"""
setup/apply.py -- ฝั่ง root ของ setup wizard (รันโดย cafe-wifi-apply.service ซึ่ง .path ปลุกเมื่อมี apply.json)

  /opt/cafe-wifi/venv/bin/python -m setup.apply      (cwd /opt/cafe-wifi)

1. ย้าย /run/cafe-wifi-setup/apply.json ออกก่อน (path unit จะไม่ปลุกซ้ำ) แล้ว validate ทุกค่าเอง
   ไม่เชื่อ wizard -- ไฟล์นี้ผู้ใช้ cafewifi เขียนได้
2. หยุด wizard (มันถือพอร์ต 80 ที่ nginx ของ --stage site ต้องใช้)
3. ตรวจเราเตอร์ซ้ำอีกรอบในฐานะ root -- ตัดสินใจจริงที่นี่ ไม่ใช่ที่หน้าเว็บ
4. install.sh --stage site ... -> สำเร็จ: ปักธง .site-done, ลบ setup code, ปิด wizard ถาวร
                              -> ล้ม: เขียนสาเหตุลง status.json แล้วเปิด wizard กลับให้ช่างเห็น
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from setup import netinfo

ETC_DIR = Path(os.environ.get("ETC_DIR", "/etc/cafe-wifi"))
RUN_DIR = Path(os.environ.get("SETUP_RUN_DIR", "/run/cafe-wifi-setup"))      # ของ cafewifi (wizard เขียนคำขอ)
STATE_DIR = Path(os.environ.get("APPLY_STATE_DIR", "/run/cafe-wifi-apply"))  # ของ root (สถานะ + log)
OPT_DIR = Path(os.environ.get("OPT_DIR", "/opt/cafe-wifi"))
REQUEST_FILE = RUN_DIR / "apply.json"
# สถานะ/log อยู่ในไดเรกทอรีของ root เท่านั้น: ถ้าเขียนลง RUN_DIR ผู้ใช้ cafewifi วาง symlink ชื่อ
# status.tmp ชี้ /etc/shadow ไว้ก่อนได้ แล้ว root จะเขียนทับไฟล์นั้นให้
STATUS_FILE = STATE_DIR / "status.json"
LOG_FILE = STATE_DIR / "apply.log"
SITE_DONE = ETC_DIR / ".site-done"
CODE_FILE = ETC_DIR / "setup-code"
WIZARD_UNITS = ["cafe-wifi-setup.service", "cafe-wifi-apply.path"]
LED_DIR = Path("/sys/class/leds/ACT")


def write_status(state: str, message: str = "", log_tail: str = "") -> None:
    tmp = STATUS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"state": state, "message": message, "log_tail": log_tail,
                               "time": time.strftime("%Y-%m-%dT%H:%M:%S")}, ensure_ascii=False),
                   encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATUS_FILE)


def systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], check=False, timeout=60)


def led(trigger: str) -> None:
    try:
        (LED_DIR / "trigger").write_text(trigger)
    except OSError:
        pass


def tail(path: Path, n: int = 25) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
    except OSError:
        return ""


def fail(msg: str, log: bool = False) -> int:
    write_status("failed", msg, tail(LOG_FILE) if log else "")
    led("heartbeat")
    systemctl("start", "cafe-wifi-setup.service")   # ให้ช่างกลับมาเห็นสาเหตุที่ http://cafewifi.local
    print(f"apply: ล้มเหลว -- {msg}", file=sys.stderr)
    return 1


def finish_success() -> None:
    tmp = SITE_DONE.with_suffix(".tmp")
    tmp.write_text(time.strftime("%Y-%m-%dT%H:%M:%S%z") + "\n")
    os.replace(tmp, SITE_DONE)
    getattr(os, "sync", lambda: None)()   # ไม่มีบน Windows (เทสต์)
    for p in (CODE_FILE, ETC_DIR / "setup-code.new"):
        p.unlink(missing_ok=True)
    for boot in (Path("/boot/firmware"), Path("/boot")):
        (boot / "SETUP-CODE.txt").unlink(missing_ok=True)
    systemctl("disable", *WIZARD_UNITS)
    led("mmc0")                                      # กลับเป็นไฟปกติของ Pi (กะพริบตามการอ่านการ์ด)
    write_status("done", "ตั้งค่าเสร็จ")


def main() -> int:
    STATE_DIR.mkdir(mode=0o755, exist_ok=True)
    if SITE_DONE.exists():
        REQUEST_FILE.unlink(missing_ok=True)
        return 0
    processing = RUN_DIR / "apply.processing.json"
    try:
        os.replace(REQUEST_FILE, processing)
    except FileNotFoundError:
        return 0
    try:
        # O_NOFOLLOW + จำกัดขนาด: ไฟล์นี้มาจากผู้ใช้ cafewifi (symlink ไปไฟล์ลับ/อุปกรณ์ไม่จบ = ปฏิเสธ)
        fd = os.open(processing, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))  # 0 = Windows (เทสต์เท่านั้น)
        with os.fdopen(fd, "rb") as f:
            raw = json.loads(f.read(65536).decode("utf-8"))
        if not isinstance(raw, dict):
            raise ValueError
    except (OSError, ValueError, UnicodeDecodeError):
        return fail("ไฟล์คำขอเสีย")
    vals, errors = netinfo.validate(raw)
    if errors:
        return fail("ค่าที่ส่งมาไม่ผ่านการตรวจ: " + "; ".join(errors))

    write_status("running", "กำลังบันทึก")
    led("timer")
    systemctl("stop", "cafe-wifi-setup.service")

    sys.path.insert(0, str(OPT_DIR))
    from tools import check_router
    res = check_router.check(vals["nic"])
    if not res.get("ok"):
        why = []
        if not res["dhcp"]["ok"]:
            why.append("DHCP ของเราเตอร์ยังเปิดอยู่" if res["dhcp"].get("servers") else
                       f"ตรวจ DHCP ไม่ได้ ({res['dhcp'].get('error', '')})")
        if not res["ipv6"]["ok"]:
            why.append("IPv6 ของเราเตอร์ยังเปิดอยู่" if res["ipv6"].get("routers") else
                       f"ตรวจ IPv6 ไม่ได้ ({res['ipv6'].get('error', '')})")
        return fail(" / ".join(why) + " -- ปิดที่เราเตอร์แล้วตรวจใหม่")

    cmd = ["bash", str(OPT_DIR / "install.sh"), *netinfo.install_args(vals)]
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            check=False, timeout=1800).returncode
    if rc != 0:
        return fail(f"install.sh --stage site ล้มเหลว (rc={rc})", log=True)
    finish_success()
    processing.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
