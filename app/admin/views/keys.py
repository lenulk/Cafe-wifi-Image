"""
admin/views/keys.py — ดาวน์โหลดไฟล์สำรองกุญแจเข้ารหัส (M7, docs/install-from-image.md ขั้น 7)

secrets.env มี NATID_DEK -- การ์ดเสียโดยไม่มีสำเนา = ถอดเลขบัตรที่เก็บไว้ไม่ได้อีก (backup DB บน USB
ไม่มีกุญแจนี้) · หน้านี้ให้แอดมินดาวน์โหลดสำเนาที่เข้ารหัสด้วยรหัสผ่านที่ตั้งเอง (common/keybackup.py)
กู้คืนบนเครื่องใหม่ด้วย tools/restore_keys.py

ไฟล์นี้ = กุญแจของทั้งร้าน: admin เท่านั้น · ยืนยันรหัสผ่านบัญชีอีกครั้ง (session ค้างบนเครื่องพนักงาน
ไม่พอ) · จำกัดการเดา · ลง audit_log ทุกครั้ง · no-store
"""
from __future__ import annotations

import socket
from datetime import datetime

from flask import Response, g, render_template, request, session
from common import audit, crypto, keybackup

from admin import app as core
from admin.routes import Routes

routes = Routes()


def _secrets_text() -> str | None:
    try:
        return (core.ETC_DIR / "secrets.env").read_text(encoding="utf-8")
    except OSError:
        return None


def _page(status: int = 200, **ctx):
    text = _secrets_text()
    last = core.query_one(
        "SELECT ts, staff_id FROM audit_log WHERE action = %s ORDER BY id DESC LIMIT 1",
        (audit.KEY_BACKUP,))
    return render_template(
        "keys_backup.html",
        fingerprint=keybackup.dek_fingerprint(text) if text else None,
        readable=text is not None,
        last_backup=(last or {}).get("ts"),
        min_len=keybackup.MIN_PASSPHRASE, **ctx), status


@routes.get("/keys")
@core.login_required
@core.admin_required
def keys_page():
    return _page()


@routes.post("/keys/backup")
@core.login_required
@core.admin_required
def keys_backup():
    bucket = f"keybackup:{session['staff_id']}"
    if core.rate_limited(bucket):
        return _page(429, errors=["ลองผิดหลายครั้งเกินไป รอ 10 นาทีแล้วลองใหม่"])
    current = request.form.get("current_password") or ""
    pw1 = request.form.get("passphrase") or ""
    pw2 = request.form.get("passphrase_confirm") or ""

    errors: list[str] = []
    row = core.query_one("SELECT password_hash FROM staff WHERE id = %s", (session["staff_id"],))
    if not row or not crypto.verify_password(row["password_hash"], current):
        core.record_attempt(bucket)
        errors.append("รหัสผ่านบัญชีแอดมินไม่ถูกต้อง")
    if pw1 != pw2:
        errors.append("รหัสผ่านของไฟล์สำรองทั้งสองช่องไม่ตรงกัน")
    if pw1 and pw1 == current:
        errors.append("อย่าใช้รหัสผ่านเดียวกับบัญชีแอดมิน -- ถ้ารหัสบัญชีหลุด ไฟล์สำรองต้องยังปลอดภัย")
    errors.extend(keybackup.check_passphrase(pw1))
    text = _secrets_text()
    if text is None:
        errors.append("อ่าน secrets.env ไม่ได้ -- ตรวจสิทธิ์ไฟล์ (/etc/cafe-wifi/secrets.env ต้องเป็น root:cafewifi 0640)")
    if errors:
        return _page(400, errors=errors)

    host = socket.gethostname()
    try:
        blob = keybackup.pack(text, pw1, host=host)
    except keybackup.BackupError as e:
        return _page(500, errors=[str(e)])
    # ลง audit ก่อนส่งไฟล์ -- เขียน audit ไม่ได้ = ไม่ปล่อยกุญแจออกไปโดยไม่มีร่องรอย
    audit.log_required(audit.KEY_BACKUP, staff_id=session["staff_id"], target=host,
                       client_ip=g.client_ip, detail=f"dek_fp={keybackup.dek_fingerprint(text)}")
    name = f"cafe-wifi-keys-{host}-{datetime.now():%Y%m%d}.cwkey"
    return Response(blob, mimetype="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "Cache-Control": "no-store",
    })
