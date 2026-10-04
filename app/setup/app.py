"""
setup/app.py -- Setup wizard ของ image (M4, docs/install-from-image.md ขั้น 4-5)

ทำงานเฉพาะ "โหมดตั้งค่า" หลังบูตครั้งแรก: http://cafewifi.local (พอร์ต 80, ผู้ใช้ cafewifi)
  ① setup code  ② สร้างแอดมินคนแรก  ③ เครือข่าย + ชื่อร้าน + อายุ log
  ④ ให้ช่างปิด DHCP/IPv6 ที่เราเตอร์ แล้วกดตรวจ (tools/check_router.py)  ⑤ บันทึก
บันทึก = เขียนคำขอลง /run/cafe-wifi-setup/apply.json -> cafe-wifi-apply.path ปลุก setup/apply.py (root)
ซึ่งตรวจค่าซ้ำ ตรวจเราเตอร์ซ้ำ แล้วรัน install.sh --stage site · wizard ไม่มีสิทธิ์ root เอง

ความปลอดภัย: ช่วงนี้ Pi อยู่วงเดียวกับลูกค้าที่ยังใช้ Wi-Fi ร้านตามปกติ (ยังไม่มี portal)
  - ทุกหน้าต้องผ่าน setup code ก่อน · ผิด 5 ครั้ง ล็อกทั้งเครื่อง 15 นาที (ไม่ใช่ต่อ IP -- เปลี่ยน IP ได้)
  - setup code ใช้ได้จนกว่าจะบันทึกสำเร็จ แล้ว apply.py ลบทิ้ง + ปิด wizard ถาวร (.site-done)
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, session, url_for

from common import audit, crypto, keybackup
from common.db import get_conn, query_one
from setup import netinfo

ETC_DIR = Path(os.environ.get("ETC_DIR", "/etc/cafe-wifi"))
RUN_DIR = Path(os.environ.get("SETUP_RUN_DIR", "/run/cafe-wifi-setup"))
CODE_FILE = ETC_DIR / "setup-code"
SITE_DONE = ETC_DIR / ".site-done"
REQUEST_FILE = RUN_DIR / "apply.json"
STATUS_FILE = Path(os.environ.get("APPLY_STATE_DIR", "/run/cafe-wifi-apply")) / "status.json"  # เขียนโดย apply.py (root)
RESTORE_REQUEST = RUN_DIR / "restore.json"                 # -> cafe-wifi-restore.path ปลุก setup/restore.py (root)
RESTORE_STATUS = STATUS_FILE.with_name("restore.json")     # เขียนโดย restore.py
ROUTER_CHECK_TTL = 300          # ผลตรวจเราเตอร์ใช้ได้ 5 นาที (apply.py ตรวจซ้ำเองอีกรอบอยู่ดี)

MAX_FAILS = 5
LOCK_SEC = 15 * 60
RESTORE_MAX_FAILS = 10            # รหัสผ่านไฟล์สำรองผิด -- scrypt ช้าอยู่แล้ว แต่กันลองทางหน้าเว็บไม่จำกัด

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or os.urandom(32).hex(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="cafewifi_setup",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
    MAX_CONTENT_LENGTH=64 * 1024,
)

_lock = threading.Lock()
_fails: list[float] = []
_restore_fails: list[float] = []


# ------------------------------------------------------------------ helpers
def _read_code() -> str:
    try:
        return CODE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def locked_until() -> float:
    now = time.time()
    with _lock:
        _fails[:] = [t for t in _fails if now - t < LOCK_SEC]
        return _fails[0] + LOCK_SEC if len(_fails) >= MAX_FAILS else 0.0


def _record_fail() -> None:
    with _lock:
        _fails.append(time.time())


def staff_count() -> int:
    row = query_one("SELECT COUNT(*) AS n FROM staff")
    return int(row["n"]) if row else 0


def read_status(path: Path | None = None) -> dict:
    try:
        return json.loads((path or STATUS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _code_tag(code: str) -> str:
    # ผูก session กับ code ปัจจุบัน -- เตรียมการ์ดใหม่ (code ใหม่) แล้ว session เก่าใช้ไม่ได้ทันที
    return hashlib.sha256(("cafewifi-setup:" + code).encode()).hexdigest()[:32]


def verified() -> bool:
    code = _read_code()
    return bool(code) and session.get("code_ok") == _code_tag(code)


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def guard():
    if SITE_DONE.exists():
        return render_template("setup_done.html"), 410
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400)
    if request.endpoint in ("code", "static") or request.endpoint is None:
        return None
    if not verified():
        return redirect(url_for("code"))
    return None


@app.after_request
def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ------------------------------------------------------------------ routes
@app.route("/")
def index():
    st = read_status()
    if st.get("state") == "failed":
        return redirect(url_for("router"))
    if read_status(RESTORE_STATUS).get("state") == "running" or RESTORE_REQUEST.exists():
        return redirect(url_for("restore"))
    if staff_count() == 0:
        return redirect(url_for("admin"))
    if "net" not in session:
        return redirect(url_for("network"))
    return redirect(url_for("router"))


@app.route("/code", methods=["GET", "POST"])
def code():
    if request.method == "GET":
        return render_template("setup_code.html", step=1)
    until = locked_until()
    if until:
        mins = max(1, int((until - time.time()) // 60) + 1)
        return render_template("setup_code.html", step=1,
                               errors=[f"กรอกผิดหลายครั้ง ล็อกไว้ อีก {mins} นาทีลองใหม่"]), 429
    expected = _read_code()
    given = (request.form.get("code") or "").upper().replace("-", "").replace(" ", "")
    if not expected or not crypto.constant_time_eq(given, expected):
        _record_fail()
        left = max(0, MAX_FAILS - len(_fails))
        return render_template("setup_code.html", step=1,
                               errors=[f"setup code ไม่ถูกต้อง (เหลือ {left} ครั้งก่อนล็อก 15 นาที)"]), 400
    session.clear()
    session.permanent = True
    session["code_ok"] = _code_tag(expected)
    return redirect(url_for("index"))


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if staff_count() > 0:
        return redirect(url_for("network"))
    if request.method == "GET":
        return render_template("setup_admin.html", step=2)
    username = (request.form.get("username") or "").strip()
    display = (request.form.get("display_name") or "").strip() or username
    pw1 = request.form.get("password") or ""
    pw2 = request.form.get("password_confirm") or ""
    errors: list[str] = []
    # กติกาเดียวกับ /setup ของ Admin Panel (admin/app.py)
    if not (3 <= len(username) <= 64) or not username.replace("_", "").replace(".", "").isalnum():
        errors.append("ชื่อผู้ใช้ต้องยาว 3-64 ตัว ใช้ได้เฉพาะ a-z A-Z 0-9 . _")
    if pw1 != pw2:
        errors.append("รหัสผ่านทั้งสองช่องไม่ตรงกัน")
    errors.extend(crypto.check_admin_password(pw1))
    if errors:
        return render_template("setup_admin.html", step=2, errors=errors,
                               username=username, display_name=display), 400
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM staff FOR UPDATE")
        if int(cur.fetchone()["n"]) > 0:
            return redirect(url_for("network"))
        cur.execute(
            "INSERT INTO staff (username, password_hash, display_name, role, is_active) "
            "VALUES (%s, %s, %s, 'admin', 1)",
            (username, crypto.hash_password(pw1), display),
        )
        new_id = cur.lastrowid
    audit.log(audit.SETUP_ADMIN, staff_id=new_id, target=username,
              client_ip=request.remote_addr, detail="สร้างบัญชีผู้ดูแลระบบหลักผ่าน setup wizard ของ image")
    session["admin_user"] = username
    return redirect(url_for("network"))


@app.route("/restore", methods=["GET", "POST"])
def restore():
    """การ์ดเสีย -> flash ใหม่ -> กู้จากไฟล์สำรองกุญแจ (.cwkey) + ไฟล์สำรองฐานข้อมูลใน USB โดยไม่ต้องใช้ CLI

    ถอดไฟล์ที่นี่ (รหัสผ่านไม่ออกจากหน่วยความจำของโปรเซสนี้) แล้วส่งเฉพาะกุญแจของข้อมูลให้ฝั่ง root
    ใช้ได้เฉพาะเครื่องที่ยังไม่มีพนักงาน -- ฝั่ง root ตรวจซ้ำเองอีกชั้น
    """
    st = read_status(RESTORE_STATUS)
    busy = st.get("state") == "running" or RESTORE_REQUEST.exists()
    if request.method == "GET":
        if not busy and st.get("state") != "done" and staff_count() > 0:
            return redirect(url_for("network"))
        return render_template("setup_restore.html", step=2, st=st, busy=busy)
    if busy or staff_count() > 0:
        return redirect(url_for("restore"))
    now = time.time()
    with _lock:
        _restore_fails[:] = [t for t in _restore_fails if now - t < LOCK_SEC]
        if len(_restore_fails) >= RESTORE_MAX_FAILS:
            return render_template("setup_restore.html", step=2, st={}, busy=False,
                                   errors=["ใส่รหัสผ่านผิดหลายครั้ง ล็อกไว้ 15 นาที"]), 429
    f = request.files.get("cwkey")
    blob = f.read(64 * 1024) if f else b""
    try:
        env = keybackup.parse_env(keybackup.unpack(blob, request.form.get("passphrase") or ""))
    except keybackup.BackupError as e:
        with _lock:
            _restore_fails.append(now)
        return render_template("setup_restore.html", step=2, st={}, busy=False, errors=[str(e)]), 400
    keys = {k: env.get(k, "") for k in ("NATID_DEK", "NATID_PEPPER")}
    tmp = RESTORE_REQUEST.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(keys, out)
    os.replace(tmp, RESTORE_REQUEST)          # path unit เห็นไฟล์ครบทั้งก้อนเท่านั้น
    # audit เขียนโดย restore.py หลังคืนฐานข้อมูล -- เขียนตรงนี้จะถูกฐานจากไฟล์สำรองทับหาย
    return redirect(url_for("restore"))


@app.route("/network", methods=["GET", "POST"])
def network():
    uplink = netinfo.current_uplink()
    if request.method == "GET":
        # ชื่อร้านที่ช่างใส่ใน cafewifi.conf -> firstboot เขียนลง secrets.env -> มาถึงที่นี่ทาง EnvironmentFile
        # เดิมช่องว่างเปล่าให้พิมพ์ซ้ำ ถ้าลืม portal จะขึ้น Cafe-Guest แทนชื่อร้าน
        # factory reset: ค่าเดิมของร้าน (อายุ log) อยู่ใน secrets.env -- ไม่ใช้ค่าปริยายทับจนร้านเก็บ log สั้นลงโดยไม่รู้ตัว
        vals = session.get("net") or {**netinfo.suggest(uplink),
                                      "retention_days": os.environ.get("LOG_RETENTION_DAYS") or 180,
                                      "gateway_name": os.environ.get("GATEWAY_NAME", "")}
        return render_template("setup_network.html", step=3, v=vals, uplink=uplink)
    vals, errors = netinfo.validate(request.form.to_dict())
    if errors:
        return render_template("setup_network.html", step=3, v={**request.form.to_dict()},
                               uplink=uplink, errors=errors), 400
    session["net"] = vals
    session.pop("router_ok_at", None)
    return redirect(url_for("router"))


@app.route("/router", methods=["GET"])
def router():
    if "net" not in session:
        return redirect(url_for("network"))
    ok_at = session.get("router_ok_at", 0)
    fresh = time.time() - ok_at < ROUTER_CHECK_TTL
    return render_template("setup_router.html", step=4, v=session["net"],
                           result=session.get("router_result"), router_ok=fresh,
                           status=read_status(), admin_user=session.get("admin_user"))


@app.route("/router/check", methods=["POST"])
def router_check():
    if "net" not in session:
        return redirect(url_for("network"))
    from tools import check_router
    res = check_router.check(session["net"]["nic"])
    session["router_result"] = res
    session["router_ok_at"] = time.time() if res.get("ok") else 0
    return redirect(url_for("router"))


@app.route("/apply", methods=["POST"])
def apply():
    if "net" not in session:
        return redirect(url_for("network"))
    if time.time() - session.get("router_ok_at", 0) >= ROUTER_CHECK_TTL:
        return redirect(url_for("router"))
    if staff_count() == 0:
        return redirect(url_for("admin"))
    if read_status().get("state") == "running":
        return render_template("setup_applying.html", step=5, v=session["net"])
    vals, errors = netinfo.validate(session["net"])
    if errors:
        return redirect(url_for("network"))
    tmp = REQUEST_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(vals, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, REQUEST_FILE)          # path unit เห็นไฟล์ครบทั้งก้อนเท่านั้น
    return render_template("setup_applying.html", step=5, v=vals)
