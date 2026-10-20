"""
admin/views/log_suggest.py — รายการแนะนำใต้ช่องค้น log (autocomplete) · GET /logs/suggest

ค้นเฉพาะตารางเล็ก (customer / voucher / portal_session) -- ห้ามแตะ conn_log / dns_log เด็ดขาด
ผลลัพธ์ไม่มี natid_hash/natid_enc และเลขบัตรเต็มไม่เคยอยู่ใน q/cid (ซึ่งไปอยู่ใน URL):
  - role admin เห็นเลขเต็มรูปแบบ d-dddd-ddddd-dd-d ใน "label" ของรายการลูกค้าเท่านั้น (เจ้าของระบบตัดสินใจแล้ว
    ว่า admin เห็นเลขเต็ม; ทุกคำขอที่ถอดรหัสลง audit) · role staff ได้เฉพาะเลข masked
  - role admin พิมพ์เลขบัตรบางส่วน (2-13 หลัก) ค้นได้ทุกตำแหน่งตั้งแต่ต้นเลข → ต้องถอดรหัสลูกค้าทั้งร้านใน
    หน่วยความจำ จึงลง audit 1 แถวต่อคำขอ (ไม่ลงตัวเลขที่พิมพ์) และจำกัดอัตรา
  - role staff ค้นได้เฉพาะตัวเลขที่เห็นอยู่แล้วบนเลข masked (5 หลักแรก + หลักท้าย) ไม่ถอดรหัส
"""
from __future__ import annotations

import re
from datetime import datetime
from flask import g, jsonify, request, session
from common import audit, crypto
from common.sqlutil import format_natid, like_escape as _like_escape

from admin import app as core
from admin.routes import Routes

routes = Routes()

MAX_ITEMS = 8
MAX_CUSTOMERS = 5
SUGGEST_NATID_LIMIT = 120       # คำขอถอดรหัสต่อพนักงานต่อ WINDOW_SEC (600 วินาที)
_NATID_SCAN_MAX = 5000          # ลูกค้าที่อ่านต่อคำขอ (ร้านเดียว ไม่ควรถึง)


def _like_escape(s: str) -> str:
    """escape ตัวแทน LIKE (% _) และเครื่องหมาย \\ ให้เป็นตัวอักษรธรรมดา (MySQL ใช้ \\ เป็น escape ตั้งต้น)"""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _when(v) -> str:
    return v.strftime("%Y-%m-%d %H:%M") if isinstance(v, datetime) else (str(v) if v else "-")


@routes.get("/logs/suggest")
@core.login_required
def suggest_logs():
    q = (request.args.get("q") or "").strip()[:100]
    if not q:
        return jsonify(items=[])
    items: list[dict] = []

    digits = re.sub(r"[\s-]", "", q)
    if digits.isdigit() and 2 <= len(digits) <= 13:
        err = _customers(digits, items)
        if err:
            return jsonify(items=[], error=err), 429
    _vouchers(q, items)
    _devices(q, items)
    _macs(q, items)
    _ips(q, items)
    return jsonify(items=items[:MAX_ITEMS])


# ---------------------------------------------------------------- ลูกค้า (เลขบัตรบางส่วน)
def _customers(digits: str, items: list) -> str | None:
    is_admin = session.get("role") == "admin"
    if is_admin:
        sid = session["staff_id"]
        bucket = f"suggest-natid:{sid}"
        if core.rate_limited(bucket, SUGGEST_NATID_LIMIT):
            return "ค้นเลขบัตรถี่เกินไป ลองใหม่อีกสักครู่"
        core.record_attempt(bucket)

    # staff ไม่ถอดรหัส จึงไม่ดึง natid_enc ออกจากฐานข้อมูลเลย
    cols = "id, natid_enc, natid_masked" if is_admin else "id, natid_masked"
    rows = core.query_all(
        f"SELECT {cols}, last_seen, visit_count FROM customer "
        "WHERE natid_masked <> 'PURGED' ORDER BY last_seen DESC LIMIT %s", (_NATID_SCAN_MAX,))
    hits: list[dict] = []
    for r in rows:
        if len(hits) >= MAX_CUSTOMERS:
            break
        if is_admin:
            try:
                full = crypto.natid_decrypt(r["natid_enc"])
            except Exception:  # noqa: BLE001 -- ข้ามแถวที่ถอดไม่ได้ (เช่น ข้อมูลเสีย) ไม่ให้ทั้งคำขอพัง
                continue
            ok = full.startswith(digits)
            if ok:
                r = dict(r, natid_full=full)   # เก็บเลขเต็มเฉพาะแถวที่ตรง ใช้ทำ label เท่านั้น
            full = None
        else:
            ok = _masked_match(r["natid_masked"], digits)
        if ok:
            hits.append(r)
    if is_admin:
        rows = None
        audit.log_required(audit.SUGGEST_NATID, staff_id=session["staff_id"], client_ip=g.client_ip,
                           detail=f"digits={len(digits)} matched={len(hits)}")
    if not hits:
        return None

    ids = tuple(h["id"] for h in hits)
    ph = ", ".join(["%s"] * len(ids))
    vouchers: dict = {}
    for v in core.query_all(f"SELECT customer_id, username FROM voucher WHERE customer_id IN ({ph}) "
                            "ORDER BY issued_at DESC", ids):
        vouchers.setdefault(v["customer_id"], v["username"])
    hosts: dict = {}
    for p in core.query_all(
            "SELECT v.customer_id, ps.hostname FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
            f"WHERE v.customer_id IN ({ph}) AND ps.hostname IS NOT NULL ORDER BY ps.started_at DESC LIMIT 50", ids):
        hosts.setdefault(p["customer_id"], p["hostname"])
    for h in hits:
        parts = [f"มาล่าสุด {_when(h['last_seen'])}", f"{h['visit_count']} ครั้ง"]
        if vouchers.get(h["id"]):
            parts.append(vouchers[h["id"]])
        if hosts.get(h["id"]):
            parts.append(hosts[h["id"]])
        items.append(dict(group="customer", label=format_natid(h["natid_full"]) if h.get("natid_full") else h["natid_masked"],
                          detail=" · ".join(parts),
                          q=h["natid_masked"], cid=h["id"]))
    return None


def _masked_match(masked: str, digits: str) -> bool:
    """staff: เทียบเฉพาะตัวเลขที่เห็นบน masked ('d-dddd-XXXXX-XX-d') = 5 หลักแรก + หลักสุดท้าย"""
    m = re.fullmatch(r"(\d)-(\d{4})-X{5}-X{2}-(\d)", masked or "")
    if not m:
        return False
    first5, last = m.group(1) + m.group(2), m.group(3)
    if len(digits) <= 5:
        return first5.startswith(digits)
    return digits[:5] == first5 and (len(digits) < 13 or digits[12] == last)


# ---------------------------------------------------------------- เลขอ้างอิง (voucher)
def _vouchers(q: str, items: list) -> None:
    up = q.upper()
    if not re.fullmatch(r"(CAFE-?)?[A-Z0-9]{1,5}|CAFE-?", up):
        return
    rest = up[5:] if up.startswith("CAFE-") else up[4:] if up.startswith("CAFE") else up
    rows = core.query_all(
        "SELECT v.username, v.status, c.natid_masked FROM voucher v LEFT JOIN customer c ON c.id = v.customer_id "
        "WHERE v.username LIKE %s ORDER BY v.issued_at DESC LIMIT 5", (_like_escape("CAFE-" + rest) + "%",))
    for r in rows:
        items.append(dict(group="voucher", label=r["username"],
                          detail=f"{r['status']} · {r['natid_masked'] or '-'}", q=r["username"]))


# ---------------------------------------------------------------- ชื่อเครื่อง
def _devices(q: str, items: list) -> None:
    if not any(ch.isalpha() for ch in q):
        return
    rows = core.query_all(
        "SELECT mac, hostname, os_label, started_at FROM portal_session WHERE hostname LIKE %s "
        "ORDER BY started_at DESC LIMIT 30", ("%" + _like_escape(q) + "%",))
    seen = set()
    for r in rows:
        if r["mac"] in seen:
            continue
        seen.add(r["mac"])
        items.append(dict(group="device", label=r["hostname"],
                          detail=f"{r['os_label'] or '-'} · {r['mac']} · เห็นล่าสุด {_when(r['started_at'])}",
                          q=r["mac"]))
        if len(seen) >= 5:
            break


# ---------------------------------------------------------------- MAC บางส่วน
def _macs(q: str, items: list) -> None:
    if len(q) > 17 or not re.fullmatch(r"[0-9A-Fa-f:-]+", q):
        return
    hexes = re.sub(r"[:-]", "", q).upper()
    if not (2 <= len(hexes) <= 12) or not re.fullmatch(r"[0-9A-F]+", hexes):
        return
    prefix = ":".join(hexes[i:i + 2] for i in range(0, len(hexes), 2))
    rows = core.query_all(
        "SELECT mac, hostname, started_at FROM portal_session WHERE mac LIKE %s "
        "ORDER BY started_at DESC LIMIT 30", (_like_escape(prefix) + "%",))
    seen = set()
    for r in rows:
        if r["mac"] in seen:
            continue
        seen.add(r["mac"])
        items.append(dict(group="mac", label=r["mac"], detail=r["hostname"] or "-", q=r["mac"]))
        if len(seen) >= 5:
            break


# ---------------------------------------------------------------- IP บางส่วน
def _ips(q: str, items: list) -> None:
    v4 = "." in q and re.fullmatch(r"[0-9.]+", q)
    v6 = ":" in q and re.fullmatch(r"[0-9A-Fa-f:]+", q) and any(len(g) > 2 for g in q.split(":"))
    if not (v4 or v6):
        return
    rows = core.query_all(
        "SELECT ip, hostname, started_at FROM portal_session WHERE ip LIKE %s "
        "ORDER BY started_at DESC LIMIT 30", (_like_escape(q) + "%",))
    seen = set()
    for r in rows:
        if r["ip"] in seen:
            continue
        seen.add(r["ip"])
        items.append(dict(group="ip", label=r["ip"],
                          detail=f"{r['hostname'] or '-'} · {_when(r['started_at'])}", q=r["ip"]))
        if len(seen) >= 5:
            break
