#!/usr/bin/env python3
"""
tools/restore_keys.py — กู้กุญแจเข้ารหัส (secrets.env) จากไฟล์สำรอง .cwkey ที่ดาวน์โหลดจากหน้า "สำรองกุญแจ"

ใช้เมื่อ SD card เสีย/ติดตั้งเครื่องใหม่ แล้วต้องการถอดเลขบัตรจากข้อมูลเดิม (DB ที่กู้จาก USB):
  sudo /opt/cafe-wifi/venv/bin/python -m tools.restore_keys /path/to/cafe-wifi-keys-....cwkey
  sudo ... -m tools.restore_keys <ไฟล์> --check     # แค่ตรวจรหัสผ่าน/ไฟล์ ไม่เขียนอะไร

ขั้นตอน (docs/install-from-image.md ขั้น "การ์ดเสีย"):
  1. ติดตั้งเครื่องใหม่ตามปกติ (image + wizard) -> เครื่องใหม่มีกุญแจชุดใหม่ของตัวเอง
  2. รันคำสั่งนี้ -> secrets.env เดิมถูกเก็บเป็น secrets.env.before-restore-<เวลา> แล้ว**แทนเฉพาะกุญแจของข้อมูล**
     (NATID_DEK ถอดเลขบัตร, NATID_PEPPER hash ค้นหา) ด้วยของในไฟล์สำรอง -- ค่าอื่นเป็นของเครื่องใหม่ทั้งหมด
  3. คืนค่า DB จาก USB แล้วรีสตาร์ท service (คำสั่งพิมพ์ให้ท้ายสุด)

เดิม (1.0.1) กู้ทุกค่ายกเว้นค่าเครือข่าย -> FAS_KEY ของเครื่องเก่าไม่ตรงกับที่ openNDS ของเครื่องใหม่ใช้
-> หน้าลงทะเบียนขึ้น "หน้านี้หมดอายุแล้ว" ทุกเครื่อง (เจอบน Pi จริง 2026-10-05) · ความลับอื่น (FAS_KEY, SECRET_KEY,
DB_PASS) ถูกฝังใน config ของ service อื่นตอนติดตั้ง และไม่มีข้อมูลที่เก็บไว้ตัวไหนต้องใช้ -> ไม่กู้
(dump จาก USB เป็นของฐาน cafewifi อย่างเดียว ไม่มีบัญชีผู้ใช้ MariaDB -> DB_PASS ของเครื่องใหม่ยังใช้ได้)
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
# กุญแจที่ข้อมูลในฐานข้อมูลต้องใช้ -- กู้เฉพาะสองตัวนี้ (allowlist) ที่เหลือเป็นของเครื่องปัจจุบัน
RESTORE = ("NATID_DEK", "NATID_PEPPER")


def merge(restored: str, current: str | None) -> str:
    """secrets.env ของเครื่องปัจจุบัน แทนเฉพาะค่าใน RESTORE ด้วยของในไฟล์สำรอง"""
    if not current:
        return restored
    old = {k: v for k, v in keybackup.parse_env(restored).items() if k in RESTORE}
    missing = [k for k in RESTORE if k not in old]
    if missing:
        raise keybackup.BackupError(f"ไฟล์สำรองไม่มี {', '.join(missing)}")
    out, seen = [], set()
    for line in current.splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if key in old:
            out.append(f"{key}={old[key]}")
            seen.add(key)
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in old.items() if k not in seen]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="กู้ secrets.env จากไฟล์สำรองกุญแจ (.cwkey)")
    ap.add_argument("file")
    ap.add_argument("--check", action="store_true", help="ตรวจไฟล์+รหัสผ่านเท่านั้น ไม่เขียน")
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
    try:
        new = merge(text, current)
    except keybackup.BackupError as e:
        print(f"ผิดพลาด: {e}", file=sys.stderr)
        return 2
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

    dbname = keybackup.parse_env(new).get("DB_NAME", "cafewifi")
    print(f"ขั้นต่อไป: คืนค่า DB {dbname} จาก USB (ถ้ามี) แล้ว\n"
          "  sudo systemctl restart cafe-admin cafe-fas cafe-logger")
    return 0


if __name__ == "__main__":
    sys.exit(main())
