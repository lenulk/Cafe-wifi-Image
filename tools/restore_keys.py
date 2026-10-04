#!/usr/bin/env python3
"""
tools/restore_keys.py — กู้กุญแจเข้ารหัส (secrets.env) จากไฟล์สำรอง .cwkey ที่ดาวน์โหลดจากหน้า "สำรองกุญแจ"

ใช้เมื่อ SD card เสีย/ติดตั้งเครื่องใหม่ แล้วต้องการถอดเลขบัตรจากข้อมูลเดิม (DB ที่กู้จาก USB):
  sudo /opt/cafe-wifi/venv/bin/python -m tools.restore_keys /path/to/cafe-wifi-keys-....cwkey
  sudo ... -m tools.restore_keys <ไฟล์> --check     # แค่ตรวจรหัสผ่าน/ไฟล์ ไม่เขียนอะไร

ขั้นตอน (docs/install-from-image.md ขั้น "การ์ดเสีย"):
  1. ติดตั้งเครื่องใหม่ตามปกติ (image + wizard) -> เครื่องใหม่มีกุญแจชุดใหม่ของตัวเอง
  2. รันคำสั่งนี้ -> secrets.env เดิมถูกเก็บเป็น secrets.env.before-restore-<เวลา> แล้วแทนด้วยของในไฟล์สำรอง
     **ยกเว้นค่าเครือข่าย/พอร์ตของเครื่องใหม่** (UPLINK_*, GATEWAY_*, CLIENT_CIDR, SSH_ALT_PORT) ที่คงไว้
  3. ตั้งรหัสผู้ใช้ MariaDB ให้ตรง DB_PASS ที่กู้มาให้อัตโนมัติ (--no-db = ข้าม)
  4. คืนค่า DB จาก USB แล้วรีสตาร์ท service (คำสั่งพิมพ์ให้ท้ายสุด)
"""
from __future__ import annotations

import argparse
import getpass
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))          # รันจาก /opt/cafe-wifi
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))  # รันจาก repo
from common import keybackup  # noqa: E402

ETC_DIR = Path(os.environ.get("ETC_DIR", "/etc/cafe-wifi"))
# ค่าที่ผูกกับเครื่อง/เครือข่ายปัจจุบัน -- ต้องเป็นของเครื่องใหม่ ไม่ใช่ของร้านเดิมเมื่อหลายเดือนก่อน
KEEP_LOCAL = ("UPLINK_IP", "UPLINK_GW", "UPLINK_NETWORK", "GATEWAY_IP", "GATEWAY_NAME", "CLIENT_CIDR",
              "SSH_ALT_PORT", "OFFSITE_BACKUP_DIR")


def merge(restored: str, current: str | None) -> str:
    """ใช้ของในไฟล์สำรองเป็นหลัก แต่คงค่าเครือข่ายของเครื่องปัจจุบัน"""
    if not current:
        return restored
    local = {k: v for k, v in keybackup.parse_env(current).items() if k in KEEP_LOCAL}
    out, seen = [], set()
    for line in restored.splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key in local:
            out.append(f"{key}={local[key]}")
            seen.add(key)
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in local.items() if k not in seen]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="กู้ secrets.env จากไฟล์สำรองกุญแจ (.cwkey)")
    ap.add_argument("file")
    ap.add_argument("--check", action="store_true", help="ตรวจไฟล์+รหัสผ่านเท่านั้น ไม่เขียน")
    ap.add_argument("--no-db", action="store_true", help="ไม่ตั้งรหัสผู้ใช้ MariaDB ให้ตรง DB_PASS ที่กู้มา")
    a = ap.parse_args(argv)

    blob = Path(a.file).read_bytes()
    try:
        head = keybackup.read_header(blob)
    except keybackup.BackupError as e:
        print(f"ผิดพลาด: {e}", file=sys.stderr)
        return 2
    print(f"ไฟล์สำรองจากเครื่อง {head.get('host') or '?'} สร้างเมื่อ {head.get('created')} "
          f"ลายนิ้วมือกุญแจ {head.get('dek_fp')}")
    pw = os.environ.get("CAFEWIFI_RESTORE_PASSPHRASE") or getpass.getpass("รหัสผ่านของไฟล์สำรอง: ")
    try:
        text = keybackup.unpack(blob, pw)
    except keybackup.BackupError as e:
        print(f"ผิดพลาด: {e}", file=sys.stderr)
        return 3
    print("✓ รหัสผ่านถูกต้อง ไฟล์สมบูรณ์")
    if a.check:
        return 0
    if not os.environ.get("ETC_DIR") and os.geteuid() != 0:
        print("ต้องรันด้วย sudo", file=sys.stderr)
        return 1

    target = ETC_DIR / "secrets.env"
    current = target.read_text(encoding="utf-8") if target.exists() else None
    if current and keybackup.dek_fingerprint(current) == head.get("dek_fp"):
        print("เครื่องนี้ใช้กุญแจชุดเดียวกับไฟล์สำรองอยู่แล้ว -- ไม่ต้องกู้")
        return 0
    new = merge(text, current)
    if current is not None:
        keep = target.with_name(f"secrets.env.before-restore-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(target, keep)
        print(f"เก็บกุญแจชุดเดิมของเครื่องนี้ไว้ที่ {keep}")
    tmp = target.with_name("secrets.env.new")
    tmp.write_text(new, encoding="utf-8")
    if current is not None:
        shutil.copystat(target, tmp)
        try:
            st = target.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
        except (AttributeError, PermissionError):
            pass
    else:
        os.chmod(tmp, 0o640)
    os.replace(tmp, target)
    print(f"✓ กู้ {target} แล้ว (ลายนิ้วมือ {keybackup.dek_fingerprint(new)})")

    # แอปต่อ DB ด้วย DB_PASS ที่เพิ่งกู้มา -- ตั้งรหัสผู้ใช้ MariaDB ให้ตรง (root ต่อผ่าน unix socket)
    # ไม่ใช้ install.sh --stage firstboot: มันเขียนค่าเครือข่ายค่าปริยายทับใน secrets.env
    env = keybackup.parse_env(new)
    user, pw_db, dbname = env.get("DB_USER", "cafewifi"), env.get("DB_PASS", ""), env.get("DB_NAME", "cafewifi")
    if a.no_db:
        print("ข้ามการตั้งรหัส MariaDB (--no-db)")
    elif not (pw_db.isalnum() and user.replace("_", "").isalnum()) or not shutil.which("mysql"):
        print("ตั้งรหัส MariaDB เองให้ตรง DB_PASS ใน secrets.env (ALTER USER ...)", file=sys.stderr)
    else:
        import subprocess
        sql = "".join(f"ALTER USER '{user}'@'{h}' IDENTIFIED BY '{pw_db}';" for h in ("127.0.0.1", "localhost"))
        r = subprocess.run(["mysql", "-e", sql + "FLUSH PRIVILEGES;"], capture_output=True, text=True)
        print("✓ ตั้งรหัส MariaDB ให้ตรงกุญแจที่กู้แล้ว" if r.returncode == 0
              else f"ตั้งรหัส MariaDB ไม่สำเร็จ: {r.stderr.strip()[:200]}")
    print(f"ขั้นต่อไป: คืนค่า DB {dbname} จาก USB (ถ้ามี) แล้ว\n"
          "  sudo systemctl restart cafe-admin cafe-fas cafe-logger")
    return 0


if __name__ == "__main__":
    sys.exit(main())
