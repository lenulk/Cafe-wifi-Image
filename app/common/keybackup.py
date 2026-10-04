"""
common/keybackup.py — ไฟล์สำรองกุญแจเข้ารหัส (secrets.env) แบบเข้ารหัสด้วยรหัสผ่านของเจ้าของร้าน

ทำไมต้องมี: backup DB ไป USB (tools/backup_db.py) มี natid_enc แต่ไม่มี NATID_DEK -- กุญแจอยู่ใน
/etc/cafe-wifi/secrets.env บน SD card ใบเดียวกับระบบ การ์ดเสีย (เรื่องปกติของ Pi) = ถอดเลขบัตรที่
เก็บไว้ไม่ได้อีกเลย มีหมายศาลมาก็ส่งข้อมูลตาม ม.26 ไม่ได้ · ไฟล์นี้ให้ร้านเก็บนอกเครื่อง (ไดรฟ์/อีเมลตัวเอง)

รูปแบบ (JSON ข้อความล้วน เปิดดูได้ว่าเป็นไฟล์อะไร แต่เนื้อหาเข้ารหัส):
  {"format": "cafe-wifi-keybackup", "v": 1, "kdf": "scrypt", "n": 32768, "r": 8, "p": 1,
   "salt": b64, "nonce": b64, "created": iso, "host": ..., "dek_fp": 16 hex, "ct": b64}
  - กุญแจ = scrypt(รหัสผ่าน, salt) -> AES-256-GCM · หัวไฟล์ทั้งหมด (ยกเว้น ct) เป็น AAD -- แก้หัวไฟล์ = ถอดไม่ได้
  - dek_fp = 8 ไบต์แรกของ SHA-256(NATID_DEK) ไว้เทียบว่าไฟล์นี้ตรงกับเครื่องไหน (ไม่พอจะเดากุญแจได้)

ใช้ cryptography (มีใน requirements อยู่แล้ว) ไม่เพิ่ม dependency ใหม่ -- image ติดตั้งหน้างานโดยไม่ออก PyPI
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT = "cafe-wifi-keybackup"
VERSION = 1
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1      # ~32 MB RAM, ~0.3 วิบน Pi 4 -- เดารหัสผ่านแบบ offline ช้า
MIN_PASSPHRASE = 12
REQUIRED_KEYS = ("NATID_DEK", "NATID_PEPPER", "SECRET_KEY", "FAS_KEY", "DB_PASS")


class BackupError(ValueError):
    """ไฟล์ไม่ใช่ไฟล์สำรองกุญแจ / รหัสผ่านผิด / ไฟล์ถูกแก้ -- ข้อความภาษาไทยแสดงผู้ใช้ได้"""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def dek_fingerprint(secrets_text: str) -> str:
    dek = parse_env(secrets_text).get("NATID_DEK", "")
    return hashlib.sha256(dek.encode()).hexdigest()[:16]


def check_passphrase(pw: str) -> list[str]:
    """นโยบายรหัสผ่านของไฟล์สำรอง: ไม่บังคับตัวพิมพ์ใหญ่/เล็ก (เจ้าของร้านต้องจำได้ในอีกหลายปี)
    แต่ต้องยาว -- ไฟล์นี้หลุดไปได้ (อีเมล/ไดรฟ์) และถูกเดาแบบ offline ได้ไม่จำกัดครั้ง"""
    errors = []
    if len(pw) < MIN_PASSPHRASE:
        errors.append(f"รหัสผ่านของไฟล์สำรองต้องยาวอย่างน้อย {MIN_PASSPHRASE} ตัว (ประโยคยาว ๆ จำง่ายกว่า)")
    elif len(set(pw)) < 5 or re.fullmatch(r"(.+?)\1+", pw):
        errors.append("รหัสผ่านซ้ำ ๆ เดาง่ายเกินไป")
    return errors


def _key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def _aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pack(secrets_text: str, passphrase: str, host: str = "") -> bytes:
    missing = [k for k in REQUIRED_KEYS if not parse_env(secrets_text).get(k)]
    if missing:
        raise BackupError("secrets.env ไม่ครบ ขาด " + ", ".join(missing) + " -- ไม่สร้างไฟล์สำรองที่กู้ไม่ได้")
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {
        "format": FORMAT, "v": VERSION, "kdf": "scrypt",
        "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "salt": _b64(salt), "nonce": _b64(nonce),
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host[:64], "dek_fp": dek_fingerprint(secrets_text),
    }
    ct = AESGCM(_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)).encrypt(
        nonce, secrets_text.encode("utf-8"), _aad(header))
    return (json.dumps({**header, "ct": _b64(ct)}, indent=1) + "\n").encode("utf-8")


def read_header(blob: bytes) -> dict:
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise BackupError("ไม่ใช่ไฟล์สำรองกุญแจของ Cafe-WiFi") from e
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise BackupError("ไม่ใช่ไฟล์สำรองกุญแจของ Cafe-WiFi")
    if doc.get("v") != VERSION or doc.get("kdf") != "scrypt":
        raise BackupError(f"ไฟล์สำรองรุ่น {doc.get('v')} -- ต้องใช้โปรแกรมรุ่นที่รองรับ")
    return doc


def unpack(blob: bytes, passphrase: str) -> str:
    doc = read_header(blob)
    header = {k: v for k, v in doc.items() if k != "ct"}
    try:
        n, r, p = int(doc["n"]), int(doc["r"]), int(doc["p"])
        if not (2 ** 10 <= n <= 2 ** 20 and 1 <= r <= 32 and 1 <= p <= 16):
            raise ValueError
        salt, nonce, ct = _unb64(doc["salt"]), _unb64(doc["nonce"]), _unb64(doc["ct"])
    except (KeyError, ValueError, TypeError) as e:
        raise BackupError("ไฟล์สำรองเสีย (หัวไฟล์ไม่ครบ)") from e
    try:
        text = AESGCM(_key(passphrase, salt, n, r, p)).decrypt(nonce, ct, _aad(header)).decode("utf-8")
    except InvalidTag as e:
        raise BackupError("รหัสผ่านไม่ถูกต้อง หรือไฟล์ถูกแก้ไข") from e
    if dek_fingerprint(text) != doc.get("dek_fp"):
        raise BackupError("กุญแจในไฟล์ไม่ตรงกับลายนิ้วมือบนหัวไฟล์ -- ไฟล์เสีย")
    return text
