"""
setup/restore.py -- ฝั่ง root ของ "กู้คืนจากเครื่องเดิม" ใน setup wizard (การ์ดเสีย -> flash ใหม่ -> กู้ผ่านเว็บ ไม่ต้องใช้ CLI)

  /opt/cafe-wifi/venv/bin/python -m setup.restore      (cafe-wifi-restore.service ที่ .path ปลุกเมื่อมี restore.json)

wizard (ผู้ใช้ cafewifi) ถอดไฟล์ .cwkey ด้วยรหัสผ่านที่ช่างพิมพ์เอง แล้วส่งมาเฉพาะกุญแจของข้อมูล
(NATID_DEK, NATID_PEPPER) -- รหัสผ่านและไฟล์ทั้งก้อนไม่ถูกเขียนลงดิสก์
1. ย้าย restore.json ออกก่อน (path unit ไม่ปลุกซ้ำ) แล้วตรวจรูปแบบกุญแจเอง ไม่เชื่อ wizard
2. หาไฟล์สำรองล่าสุดใน USB (OFFSITE_BACKUP_DIR) -- ไม่มี = ไม่ทำอะไรเลย
3. ฐานข้อมูลต้องยังว่าง (ยังไม่มีพนักงาน) -- กันกู้ทับเครื่องที่ใช้งานอยู่
4. คืนฐานข้อมูล -> ลง migration ของรุ่นนี้ซ้ำ (ไฟล์สำรองอาจมาจากรุ่นเก่า)
5. ตรวจว่ากุญแจถอดเลขบัตรในไฟล์สำรองได้จริง -- ไม่ได้ = กุญแจไม่ใช่ของร้านนี้ -> ไม่เขียน secrets.env
6. เขียนกุญแจลง secrets.env (เก็บของเดิมไว้ .before-restore-*) -- ค่าอื่นเป็นของเครื่องนี้ (tools/restore_keys)
หลังกู้: บัญชีพนักงานเดิมกลับมา -> wizard ข้ามขั้นสร้างแอดมินไป ③ เครือข่าย
"""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ETC_DIR = Path(os.environ.get("ETC_DIR", "/etc/cafe-wifi"))
RUN_DIR = Path(os.environ.get("SETUP_RUN_DIR", "/run/cafe-wifi-setup"))
STATE_DIR = Path(os.environ.get("APPLY_STATE_DIR", "/run/cafe-wifi-apply"))
OPT_DIR = Path(os.environ.get("OPT_DIR", "/opt/cafe-wifi"))
REQUEST_FILE = RUN_DIR / "restore.json"
STATUS_FILE = STATE_DIR / "restore.json"
KEY_RE = re.compile(r"^[0-9a-f]{64}$")
BACKUP_RE = re.compile(r"^(?P<db>[A-Za-z0-9_]+)-\d{8}-\d{6}\.sql\.gz$")   # tools/backup_db: <db>-YYYYmmdd-HHMMSS
SKIP_SQL = {"003_partitions.sql"}          # optional (install.sh --enable-partitions) -- เหมือน setup_database
SAMPLE = 50                                # ตรวจถอดเลขบัตรกี่แถว


def write_status(state: str, message: str, **extra) -> None:
    STATE_DIR.mkdir(mode=0o755, exist_ok=True)
    tmp = STATUS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"state": state, "message": message, "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                               **extra}, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATUS_FILE)


def read_env(path: Path) -> dict:
    sys.path.insert(0, str(OPT_DIR))
    from common import keybackup
    return keybackup.parse_env(path.read_text(encoding="utf-8"))


def find_backup(env: dict, db: str) -> Path | None:
    """ไฟล์สำรองล่าสุดบน USB -- ชื่อไฟล์ตามรูปแบบของ tools/backup_db เท่านั้น (ไม่ตาม symlink)"""
    d = Path(env.get("OFFSITE_BACKUP_DIR") or "/mnt/cafebackup/cafe-wifi")
    try:
        files = [p for p in d.iterdir() if (m := BACKUP_RE.match(p.name)) and m["db"] == db
                 and p.is_file() and not p.is_symlink()]
    except OSError:
        return None
    return max(files, key=lambda p: p.name) if files else None


def mysql(db: str | None, sql: str | None = None, stdin=None) -> subprocess.CompletedProcess:
    cmd = ["mysql", "-N", "-B"] + ([db] if db else []) + (["-e", sql] if sql else [])
    return subprocess.run(cmd, stdin=stdin, capture_output=True, text=stdin is None, timeout=1800)


def staff_count(db: str) -> int:
    r = mysql(db, "SELECT COUNT(*) FROM staff")
    return int(r.stdout.strip() or 0) if r.returncode == 0 else -1


def import_dump(db: str, dump: Path) -> None:
    with gzip.open(dump, "rb") as src:
        p = subprocess.Popen(["mysql", db], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        shutil.copyfileobj(src, p.stdin)
        p.stdin.close()
        err = p.stderr.read().decode("utf-8", "replace")
        if p.wait(timeout=1800) != 0:
            raise RuntimeError(f"คืนฐานข้อมูลไม่สำเร็จ: {err.strip()[:300]}")


def apply_migrations(db: str) -> None:
    for f in sorted((OPT_DIR / "sql").glob("0*.sql")):
        if f.name in SKIP_SQL:
            continue
        with open(f, "rb") as fh:
            r = subprocess.run(["mysql", db], stdin=fh, capture_output=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError(f"ปรับฐานข้อมูลเป็นรุ่นปัจจุบันไม่สำเร็จ ({f.name}): "
                               f"{r.stderr.decode('utf-8', 'replace').strip()[:300]}")


def verify_keys(db: str, dek: str, pepper: str) -> tuple[int, int]:
    """(ถอดได้และ hash ตรง, ทั้งหมดที่ตรวจ) จากตาราง customer"""
    os.environ["NATID_DEK"], os.environ["NATID_PEPPER"] = dek, pepper
    sys.path.insert(0, str(OPT_DIR))
    from common import crypto
    r = mysql(db, f"SELECT HEX(natid_enc), natid_hash FROM customer ORDER BY id DESC LIMIT {SAMPLE}")
    if r.returncode != 0:
        raise RuntimeError("อ่านตาราง customer ไม่ได้")
    ok = n = 0
    for line in r.stdout.splitlines():
        enc, h = line.split("\t")
        n += 1
        try:
            ok += crypto.natid_hash(crypto.natid_decrypt(bytes.fromhex(enc))) == h
        except Exception:      # noqa: BLE001 -- กุญแจผิด = InvalidTag
            pass
    return ok, n


def write_keys(dek: str, pepper: str) -> str:
    sys.path.insert(0, str(OPT_DIR))
    from common import keybackup
    from tools import restore_keys
    target = ETC_DIR / "secrets.env"
    current = target.read_text(encoding="utf-8")
    new = restore_keys.merge(f"NATID_DEK={dek}\nNATID_PEPPER={pepper}\n", current)
    shutil.copy2(target, target.with_name(f"secrets.env.before-restore-{time.strftime('%Y%m%d-%H%M%S')}"))
    tmp = target.with_name("secrets.env.new")
    tmp.write_text(new, encoding="utf-8")
    shutil.copystat(target, tmp)
    st = target.stat()
    os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, target)
    getattr(os, "sync", lambda: None)()
    return keybackup.dek_fingerprint(new)


def main() -> int:
    STATE_DIR.mkdir(mode=0o755, exist_ok=True)
    processing = RUN_DIR / "restore.processing.json"
    try:
        os.replace(REQUEST_FILE, processing)
    except FileNotFoundError:
        return 0
    try:
        fd = os.open(processing, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            req = json.loads(f.read(4096).decode("utf-8"))
        dek, pepper = str(req.get("NATID_DEK", "")), str(req.get("NATID_PEPPER", ""))
    except (OSError, ValueError, UnicodeDecodeError, AttributeError):
        dek = pepper = ""
    finally:
        processing.unlink(missing_ok=True)          # มีกุญแจอยู่ข้างใน -- ไม่ทิ้งค้างไว้
    if not (KEY_RE.match(dek) and KEY_RE.match(pepper)):
        write_status("failed", "ไฟล์คำขอเสีย -- อัปโหลดไฟล์สำรองกุญแจใหม่อีกครั้ง")
        return 1

    env = read_env(ETC_DIR / "secrets.env")
    db = env.get("DB_NAME", "cafewifi")
    if (ETC_DIR / ".site-done").exists() or staff_count(db) != 0:
        write_status("failed", "เครื่องนี้มีข้อมูลอยู่แล้ว -- กู้คืนได้เฉพาะเครื่องที่เพิ่งติดตั้งใหม่ (ยังไม่สร้างแอดมิน)")
        return 1
    dump = find_backup(env, db)
    if not dump:
        write_status("failed", "ไม่พบไฟล์สำรองใน USB CAFEBACKUP -- เสียบ USB ที่ใช้กับเครื่องเดิมแล้วลองใหม่")
        return 1

    write_status("running", f"กำลังคืนฐานข้อมูลจาก {dump.name}")
    try:
        import_dump(db, dump)
        apply_migrations(db)
        ok, n = verify_keys(db, dek, pepper)
        if n and ok != n:
            # กุญแจไม่ใช่ของร้านนี้ -- ล้างข้อมูลที่เพิ่งคืนทิ้ง (ถอดไม่ได้อยู่ดี) กลับเป็นฐานว่างแบบหลังบูตแรก
            # ให้ลองไฟล์ .cwkey อื่น หรือสร้างแอดมินใหม่ได้ · GRANT ของผู้ใช้แอปผูกกับชื่อฐาน ไม่หายเมื่อ DROP
            mysql(None, f"DROP DATABASE `{db}`; CREATE DATABASE `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            apply_migrations(db)
            write_status("failed", f"กุญแจในไฟล์สำรองไม่ตรงกับข้อมูลใน USB (ถอดได้ {ok}/{n}) -- "
                                   "ใช้ไฟล์ .cwkey ของเครื่องเดียวกับ USB นี้")
            return 1
        fp = write_keys(dek, pepper)
        mysql(db, "INSERT INTO audit_log (action, target, detail) VALUES ('setup_restore', "
                  f"'{dump.name}', 'กู้คืนผ่าน setup wizard: ไฟล์สำรองกุญแจ + ฐานข้อมูลจาก USB (ตรวจถอดเลขบัตร {ok}/{n})')")
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        write_status("failed", str(e))
        return 1
    staff = staff_count(db)
    write_status("done", f"กู้คืนสำเร็จจาก {dump.name}", backup=dump.name, customers_checked=n,
                 staff=staff, dek_fp=fp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
