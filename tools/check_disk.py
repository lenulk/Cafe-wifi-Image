"""
tools/check_disk.py — แจ้งเตือนดิสก์ใกล้เต็ม (N1, CODING_BRIEF.md)

ปัญหาเดิม: Risk Register R5 ใน PROJECT_PLAN.md เขียนแผนรับมือไว้ว่า "alert เมื่อ disk > 80%"
แต่ไม่มีโค้ดจริงสักบรรทัดในโปรเจกต์ทำสิ่งนี้ (`grep -ic "disk" install.sh` = 0) — ดิสก์เต็ม =
log หยุดเขียน (conn_log/dns_log/audit_log insert ไม่ได้) = ผิด พ.ร.บ.คอมพิวเตอร์ ม.26 ทันที
โดยไม่มีใครรู้ตัว เพราะไม่มีสัญญาณเตือนอะไรเลยก่อนถึงจุดนั้น

รันทุกวันผ่าน cafe-maintenance.timer (ตั้งโดย install.sh) ต่อจาก tools.backup_db

ตรวจ 2 mount point: LOG_DIR (ที่เก็บ log ตามกฎหมาย) และ / (root filesystem ที่ทุกอย่างอื่น
รวมถึง MariaDB data directory และ venv อยู่) -- บนเครื่องเล็กแบบ Pi ที่ใช้ SD card ใบเดียว
สอง path นี้มักอยู่ mount เดียวกันจริง ๆ (ผลจะซ้ำกัน) แต่ยังเช็คแยกกันเสมอเผื่อวันหนึ่งมีคน
ย้าย LOG_DIR ไปมีพาร์ทิชัน/ดิสก์แยกต่างหาก (เช่น ต่อ SSD ตาม D14) จะได้ไม่ต้องแก้โค้ดตรงนี้
"""
from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger("cafe-wifi.check_disk")

DEFAULT_WARN_PCT = 80.0
DEFAULT_CRIT_PCT = 90.0


@dataclass(frozen=True)
class DiskStatus:
    path: str
    total: int
    used: int
    free: int
    percent_used: float
    level: str  # 'ok' | 'warn' | 'crit'


def check_path(path: str, warn_pct: float, crit_pct: float, disk_usage_fn=shutil.disk_usage) -> DiskStatus:
    """
    คำนวณสถานะดิสก์ของ path เดียว -- แยกออกจาก I/O (เขียน alert.log/audit_log) เพื่อทดสอบ
    ตรรกะได้โดยไม่ต้องมีดิสก์จริงที่เต็มจริง (inject disk_usage_fn แทน shutil.disk_usage ตรง ๆ)
    """
    usage = disk_usage_fn(path)
    total, used, free = usage.total, usage.used, usage.free
    percent_used = (used / total * 100) if total else 0.0
    if percent_used >= crit_pct:
        level = "crit"
    elif percent_used >= warn_pct:
        level = "warn"
    else:
        level = "ok"
    return DiskStatus(path=path, total=total, used=used, free=free,
                      percent_used=percent_used, level=level)


def check_all(paths: list[str], warn_pct: float, crit_pct: float,
             disk_usage_fn=shutil.disk_usage) -> list[DiskStatus]:
    return [check_path(p, warn_pct, crit_pct, disk_usage_fn) for p in paths]


def format_alert_line(status: DiskStatus, now: datetime | None = None) -> str:
    now = now or datetime.now()
    label = "CRITICAL" if status.level == "crit" else "WARNING"
    free_mb = status.free / (1024 * 1024)
    return (f"{now.isoformat()}  {label}  {status.path}  "
           f"{status.percent_used:.1f}% used, {free_mb:.0f} MB เหลือ")


def write_alert(alert_log_path: Path, line: str) -> None:
    alert_log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(alert_log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run(log_dir: str | None = None, warn_pct: float | None = None,
       crit_pct: float | None = None, disk_usage_fn=shutil.disk_usage) -> list[DiskStatus]:
    from common import audit

    log_dir = log_dir or os.environ.get("LOG_DIR", "/var/log/cafe-wifi")
    warn_pct = warn_pct if warn_pct is not None else float(os.environ.get("DISK_WARN_PCT", DEFAULT_WARN_PCT))
    crit_pct = crit_pct if crit_pct is not None else float(os.environ.get("DISK_CRIT_PCT", DEFAULT_CRIT_PCT))

    statuses = check_all([log_dir, "/"], warn_pct, crit_pct, disk_usage_fn)
    alert_log_path = Path(log_dir) / "alert.log"

    for status in statuses:
        if status.level == "ok":
            continue
        line = format_alert_line(status)
        write_alert(alert_log_path, line)
        log.warning(line)
        audit.log(
            audit.DISK_ALERT,
            target=status.path,
            detail=f"{status.level} {status.percent_used:.1f}% used, "
                   f"{status.free / (1024 * 1024):.0f} MB free",
        )
    return statuses


def main() -> int:  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    statuses = run()
    return 1 if any(s.level == "crit" for s in statuses) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
