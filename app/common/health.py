"""
common/health.py — รวมตรรกะอ่านสถานะระบบสำหรับหน้า `/status` (N5, CODING_BRIEF.md)

`/health` เดิมใน admin/app.py คืนแค่ `{"status":"ok"}` ไว้ให้ monitoring ภายนอก/เทสต์เดิม
อ้างอิงต่อไป — **ไม่แตะ** (ตามที่ CODING_BRIEF.md สั่ง) ไฟล์นี้คือของใหม่ที่ป้อนหน้า `/status`
(หน้าเว็บจริง อ่านง่าย ใช้สาธิตต่อหน้ากรรมการได้)

แยกตรรกะการอ่าน/คำนวณออกจาก route (admin/app.py) ตามแบบแผนเดิมของโปรเจกต์ (ดู
tools/check_disk.py::check_path ที่แยก I/O ออกจากตรรกะเปรียบเทียบเกณฑ์) เพื่อให้ทดสอบได้บน
Windows โดยไม่ต้องมี systemd/chronyd/MariaDB จริง -- ทุกจุดที่แตะไฟล์ระบบ/subprocess รับ
พารามิเตอร์ฉีด (injectable) แทนการเรียกตรง ๆ เสมอ
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger("cafe-wifi.health")

# บริการที่ install.sh สร้าง/เปิดใช้งานจริงและควร "ทำงานอยู่ตลอด" (ดู install_services()/
# setup_database()/configure_nginx()/opennds ใน install.sh) -- ตั้งใจ**ไม่รวม**
# cafe-maintenance/cafe-enforce เพราะทั้งคู่เป็น oneshot ที่ผูกกับ .timer เท่านั้น `systemctl
# is-active` ของ oneshot จะเป็น "inactive" เกือบตลอดเวลาโดยปกติ (ทำงานเสร็จก็จบ) -- ถ้าเอามา
# ปนในตารางนี้จะดูเหมือน "พัง" ทั้งที่ปกติดี ให้ไปดูผลงานจริงของมันผ่าน log_manifest/alert.log
# แทน (ดู db_status()/latest_alert() ด้านล่าง)
#
# หมายเหตุชื่อ unit ของ MariaDB: install.sh เองก็เจอปัญหาเดียวกัน (มี fallback mariadb/mysqld
# ใน setup_database()) แต่เป้าหมายจริงของโปรเจกต์นี้คือ Raspberry Pi OS (Debian-based) เสมอ
# ซึ่งใช้ "mariadb" แน่นอน — ไม่ probe ทั้งสองชื่อเพื่อความง่าย ตรงกับ default ของ install.sh เอง
DEFAULT_SERVICES: tuple[str, ...] = (
    "cafe-admin", "cafe-fas", "cafe-logger", "mariadb", "nginx", "opennds",
)

CHRONY_OK_MS = 10.0  # ต้อง < 10ms ตาม พ.ร.บ.คอมพิวเตอร์ ม.26 (เกณฑ์เดียวกับที่ check_time.sh ใช้แจ้งเตือน)


# ---------------------------------------------------------------- ดิสก์
def disk_statuses(log_dir: str | os.PathLike, warn_pct: float | None = None,
                  crit_pct: float | None = None, disk_usage_fn=shutil.disk_usage) -> list:
    """% ใช้งานดิสก์สด ๆ ของ LOG_DIR และ / -- ใช้ตรรกะเดียวกับ tools/check_disk.py (N1)
    ตรง ๆ ไม่เขียนซ้ำ (เกณฑ์ DISK_WARN_PCT/DISK_CRIT_PCT ต้องเป็นค่าเดียวกับที่ N1 ใช้จริง)"""
    from tools.check_disk import DEFAULT_CRIT_PCT, DEFAULT_WARN_PCT, check_all

    warn_pct = warn_pct if warn_pct is not None else float(os.environ.get("DISK_WARN_PCT", DEFAULT_WARN_PCT))
    crit_pct = crit_pct if crit_pct is not None else float(os.environ.get("DISK_CRIT_PCT", DEFAULT_CRIT_PCT))
    return check_all([str(log_dir), "/"], warn_pct, crit_pct, disk_usage_fn)


# ---------------------------------------------------------------- นาฬิกา (T13)
@dataclass(frozen=True)
class ChronyStatus:
    available: bool          # เคยรัน check_time.sh มาก่อนไหม (ไฟล์ time-accuracy.log มีอยู่ไหม)
    checked_at: str | None   # timestamp ของบรรทัดล่าสุดในไฟล์ (ตามที่บันทึกไว้ ไม่ parse เป็น datetime เพราะแค่โชว์)
    offset_ms: float | None  # None = อ่านค่า chronyc ไม่ได้ครั้งล่าสุด
    raw: str                 # ข้อความดิบจาก chronyc (ไว้โชว์เผื่อ debug)
    ok: bool                 # offset_ms is not None and < CHRONY_OK_MS


def _parse_chrony_line(line: str) -> tuple[str | None, float | None, str]:
    """แยกบรรทัดของ time-accuracy.log ที่ check_time.sh (install.sh) เขียนไว้ -- รูปแบบ
    `<timestamp ISO>␠␠<off>` (คั่นด้วยสองช่องว่าง — ดู `printf '%s  %s\\n'` ใน install.sh)
    โดย off เป็น 'unknown' หรือ '<วินาที> seconds slow/fast of NTP time' (chronyc ไม่ใส่
    เครื่องหมาย +/- เอง ใช้คำว่า slow/fast แทน — เอาแค่ค่าสัมบูรณ์คูณ 1000 หาหน่วย ms
    เหมือนที่ check_time.sh เองทำ)"""
    ts, sep, rest = line.strip().partition("  ")
    rest = rest.strip()
    if not sep or not rest:
        return None, None, ""
    if rest == "unknown":
        return ts, None, rest
    secs_token = rest.split(" ", 1)[0]
    try:
        ms = abs(float(secs_token)) * 1000
    except ValueError:
        return ts, None, rest
    return ts, ms, rest


def chrony_status(log_dir: str | os.PathLike) -> ChronyStatus:
    path = Path(log_dir) / "time-accuracy.log"
    if not path.exists():
        return ChronyStatus(available=False, checked_at=None, offset_ms=None, raw="", ok=False)
    try:
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError as exc:
        log.error("อ่าน %s ไม่สำเร็จ: %s", path, exc)
        return ChronyStatus(available=True, checked_at=None, offset_ms=None, raw="", ok=False)
    if not lines:
        return ChronyStatus(available=True, checked_at=None, offset_ms=None, raw="", ok=False)
    ts, ms, raw = _parse_chrony_line(lines[-1])
    return ChronyStatus(available=True, checked_at=ts, offset_ms=ms, raw=raw,
                        ok=(ms is not None and ms < CHRONY_OK_MS))


# ---------------------------------------------------------------- systemd services
def _systemctl_is_active(name: str) -> str:  # pragma: no cover -- เรียก binary จริง เทสต์ inject runner แทน
    try:
        r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr or "unknown").strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("ตรวจสถานะ service %s ไม่ได้: %s", name, exc)
        return "unknown"


def service_statuses(names: tuple[str, ...] = DEFAULT_SERVICES, runner=_systemctl_is_active) -> dict[str, str]:
    return {name: runner(name) for name in names}


# ---------------------------------------------------------------- ฐานข้อมูล (session/log rows/seal ล่าสุด)
def db_status() -> dict:
    """รวม 3 อย่างในคิวรี่เดียว (ตามแบบ dashboard() ใน admin/app.py ที่รวมสถิติเป็นคิวรี่เดียว
    ด้วย correlated subquery) -- คืน error message แยกถ้า DB ต่อไม่ได้ แทนที่จะปล่อยให้
    หน้า /status ทั้งหน้าล่มไปด้วย (นี่คือหน้าที่ควรบอกว่า "DB ล่ม" ได้ ไม่ใช่ล่มไปพร้อมกัน)"""
    from common.db import query_one

    try:
        row = query_one("""
            SELECT
              (SELECT COUNT(*) FROM portal_session WHERE state='authenticated' AND ended_at IS NULL) AS active_sessions,
              (SELECT COUNT(*) FROM portal_session WHERE state='pending') AS pending_sessions,
              (SELECT COUNT(*) FROM conn_log WHERE DATE(ts) = CURDATE())   AS conn_log_today,
              (SELECT COUNT(*) FROM dns_log  WHERE DATE(ts) = CURDATE())   AS dns_log_today,
              (SELECT MAX(sealed_at) FROM log_manifest)                    AS last_sealed_at
        """) or {}
        conn_today = int(row.get("conn_log_today") or 0)
        dns_today = int(row.get("dns_log_today") or 0)
        return dict(
            active_sessions=row.get("active_sessions"),
            pending_sessions=row.get("pending_sessions"),
            conn_log_today=conn_today,
            dns_log_today=dns_today,
            log_rows_today=conn_today + dns_today,
            last_sealed_at=row.get("last_sealed_at"),
            error=None,
        )
    except Exception as exc:  # noqa: BLE001
        log.error("อ่านสถิติจาก DB ไม่สำเร็จ: %s", exc)
        return dict(active_sessions=None, pending_sessions=None, conn_log_today=None, dns_log_today=None,
                    log_rows_today=None, last_sealed_at=None, error=str(exc))


# ---------------------------------------------------------------- alert ล่าสุดจาก N1
def latest_alert(log_dir: str | os.PathLike) -> str | None:
    path = Path(log_dir) / "alert.log"
    if not path.exists():
        return None
    try:
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError as exc:
        log.error("อ่าน %s ไม่สำเร็จ: %s", path, exc)
        return None
    return lines[-1] if lines else None


# ---------------------------------------------------------------- ประกอบทั้งหมด
def build_status(log_dir: str | os.PathLike | None = None, *,
                 disk_usage_fn=shutil.disk_usage,
                 service_runner=_systemctl_is_active) -> dict:
    log_dir = log_dir or os.environ.get("LOG_DIR", "/var/log/cafe-wifi")
    from logger.telemetry import read_collector_status
    return dict(
        generated_at=datetime.now(),
        disks=disk_statuses(log_dir, disk_usage_fn=disk_usage_fn),
        chrony=chrony_status(log_dir),
        services=service_statuses(runner=service_runner),
        collectors=read_collector_status(log_dir),
        db=db_status(),
        latest_alert=latest_alert(log_dir),
    )
