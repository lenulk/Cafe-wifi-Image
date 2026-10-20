"""
admin/views/log_summary.py — สรุปการใช้งานรายเครื่อง (mac) หรือรายลูกค้า (cid) · GET /logs/summary

รวม session / เว็บที่เข้าบ่อย / ปริมาณข้อมูล ในช่วงเวลาเดียวกับหน้า /logs · ทุกครั้งที่เปิดลง audit SEARCH_LOG
(เฉพาะ masked ไม่มีเลขเต็ม) · admin เห็นเลขบัตรเต็มได้ (ลง VIEW_NATID_LOG เฉพาะจำนวน) · staff เห็น masked เท่านั้น
และไม่เคย SELECT natid_enc

การจับคู่ log -> ลูกค้า: ถ้าสรุปรายลูกค้า (cid) จำกัดแถว log ให้อยู่ในช่วง session ของลูกค้านั้นเท่านั้น
(mac + ip + เวลา ตามหลักเดียวกับ common/log_mapping.py) เพราะ MAC เดียวใช้กับหลายคนต่างเวลาได้
ใช้ EXISTS (ไม่ใช่ JOIN) เพื่อไม่ให้ session ซ้อนกันทำให้นับแถวซ้ำ
"""
from __future__ import annotations

import re
from datetime import datetime

from flask import g, render_template, request, session

from common import audit, crypto
from common.customer import PURGED_MARK

from admin import app as core
from admin.routes import Routes
from admin.views.logs import LOG_RANGES, _MAC_RE, _resolve_log_range

routes = Routes()

SESSIONS_MAX = 100
TOP_DOMAINS = 20
TOP_DST = 10
DEVICES_MAX = 200
OWNERS_MAX = 20

MAC_SCOPE = "x.mac = %s"
# เวลาเริ่มของ conn_log = started_at (ถ้ามี) ตามเหตุผล R2-02 ใน log_mapping.py
CID_SCOPE = ("x.mac IN ({macs}) AND EXISTS (SELECT 1 FROM portal_session ps "
             "JOIN voucher v ON v.id = ps.voucher_id WHERE v.customer_id = %s "
             "AND ps.mac = x.mac AND ps.ip = x.{ipfield} "
             "AND ps.authenticated_at <= {tsexpr} "
             "AND (ps.ended_at IS NULL OR {tsexpr} <= ps.ended_at))")


def _err(message: str, status: int):
    return render_template("error.html", title="สรุปการใช้งาน", message=message), status


def _full_id(blob) -> str | None:
    """ถอดรหัสเลขบัตร -- None ถ้าถูกลบ/ถอดไม่ได้ (ให้ใช้ masked แทน)"""
    if not blob:
        return None
    try:
        return crypto.natid_decrypt(bytes(blob))
    except Exception:
        return None


def _scope(kind: str, value, macs: list[str], table: str):
    """คืน (sql_where_fragment, args) สำหรับแถว log ของ table ('conn'|'dns') ที่เป็นของเป้าหมายนี้"""
    if kind == "mac":
        return MAC_SCOPE, [value]
    ipfield, tsexpr = (("src_ip", "COALESCE(x.started_at, x.ts)") if table == "conn"
                       else ("client_ip", "x.ts"))
    frag = CID_SCOPE.format(macs=", ".join(["%s"] * len(macs)), ipfield=ipfield, tsexpr=tsexpr)
    return frag, list(macs) + [value]


@routes.get("/logs/summary")
@core.login_required
def log_summary():
    mac_raw = (request.args.get("mac") or "").strip()
    cid_raw = (request.args.get("cid") or "").strip()
    rng = request.args.get("range", "today")
    if rng not in LOG_RANGES:
        rng = "today"
    start_raw = (request.args.get("start") or "").strip()
    end_raw = (request.args.get("end") or "").strip()
    is_admin = session.get("role") == "admin"

    if bool(mac_raw) == bool(cid_raw):
        return _err("ระบุ mac หรือ cid อย่างใดอย่างหนึ่งเท่านั้น", 400)
    kind = "mac" if mac_raw else "cid"
    value: object
    if kind == "mac":
        if not _MAC_RE.match(mac_raw):
            return _err("รูปแบบ MAC ไม่ถูกต้อง", 400)
        hexes = re.sub(r"[:-]", "", mac_raw).upper()
        value = ":".join(hexes[i:i + 2] for i in range(0, 12, 2))
    else:
        if not (cid_raw.isdigit() and 0 < int(cid_raw) < 2**63):
            return _err("รหัสลูกค้า (cid) ต้องเป็นจำนวนเต็มบวก", 400)
        value = int(cid_raw)

    params = dict(range=rng, start=start_raw, end=end_raw)
    ctx = dict(kind=kind, params=params, ranges=LOG_RANGES, mac=value if kind == "mac" else "",
               cid=value if kind == "cid" else "")

    start, end, error = _resolve_log_range(rng, start_raw, end_raw)
    if error:
        return render_template("error.html", title="สรุปการใช้งาน", message=error), 400

    customer = None
    if kind == "cid":
        customer = core.query_one(
            "SELECT id, natid_masked, first_seen, last_seen, visit_count FROM customer WHERE id = %s",
            (value,))
        if not customer or customer["natid_masked"] == PURGED_MARK:
            return _err("ไม่พบลูกค้ารายนี้ (หรือถูกล้างข้อมูลระบุตัวตนแล้ว)", 404)

    # ---- ส่วนหัว: เจ้าของ / อุปกรณ์
    owners: list[dict] = []     # kind=mac: ลูกค้าที่เคยใช้เครื่องนี้
    devices: list[dict] = []    # kind=cid: เครื่องของลูกค้า
    device_now = None
    full_count = 0
    if kind == "mac":
        device_now = core.query_one(
            "SELECT hostname, os_label, authenticated_at FROM portal_session WHERE mac = %s "
            "ORDER BY COALESCE(authenticated_at, started_at) DESC LIMIT 1", (value,))
        enc_col = ", c.natid_enc" if is_admin else ""
        owners = core.query_all(
            f"SELECT c.id, c.natid_masked{enc_col}, MAX(ps.authenticated_at) AS last_used "
            "FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
            "JOIN customer c ON c.id = v.customer_id WHERE ps.mac = %s "
            f"GROUP BY c.id, c.natid_masked{enc_col} ORDER BY last_used DESC LIMIT %s",
            (value, OWNERS_MAX))
        macs = [value]
        for o in owners:
            o["full"] = _full_id(o.pop("natid_enc", None)) if is_admin else None
            full_count += o["full"] is not None
    else:
        rows = core.query_all(
            "SELECT ps.mac, ps.hostname, ps.os_label, ps.authenticated_at "
            "FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
            "WHERE v.customer_id = %s AND ps.authenticated_at IS NOT NULL "
            "ORDER BY ps.authenticated_at DESC LIMIT %s", (value, DEVICES_MAX))
        seen: set[str] = set()
        for r in rows:                      # เรียงใหม่สุดก่อน -> แถวแรกของแต่ละ mac = ล่าสุด
            if r["mac"] not in seen:
                seen.add(r["mac"])
                devices.append(r)
        macs = [d["mac"] for d in devices]
        customer = dict(customer, full=None)
        if is_admin:
            enc = core.query_one("SELECT natid_enc FROM customer WHERE id = %s", (value,))
            customer["full"] = _full_id(enc and enc.get("natid_enc"))
            full_count += customer["full"] is not None

    # ---- audit (ก่อนแสดงข้อมูล) -- masked/จำนวนเท่านั้น
    target = f"mac={value}" if kind == "mac" else f"cid={value}"
    audit.log_required(audit.SEARCH_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                       detail=f"summary {target} start={start.isoformat()} end={end.isoformat()}")
    if full_count:
        audit.log_required(getattr(audit, "VIEW_NATID_LOG", "view_natid_log"),
                           staff_id=session["staff_id"], client_ip=g.client_ip,
                           detail=f"summary {target} count={full_count}")

    # ---- session ในช่วง
    sess_sql = ("SELECT ps.authenticated_at, ps.ended_at, ps.ip, ps.mac, ps.hostname, ps.os_label"
                ", c.natid_masked FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
                "LEFT JOIN customer c ON c.id = v.customer_id "
                "WHERE ps.authenticated_at IS NOT NULL AND ps.authenticated_at <= %s "
                "AND COALESCE(ps.ended_at, NOW()) >= %s AND ")
    if kind == "mac":
        sess_sql += "ps.mac = %s"
        sess_args: list = [end, start, value]
    else:
        sess_sql += "v.customer_id = %s"
        sess_args = [end, start, value]
    sessions = core.query_all(sess_sql + " ORDER BY ps.authenticated_at DESC LIMIT %s",
                              tuple(sess_args + [SESSIONS_MAX]))

    # ---- เว็บที่เข้าบ่อย + ปริมาณข้อมูล
    domains: list[dict] = []
    totals = dict(n=0, bytes_out=0, bytes_in=0)
    top_dst: list[dict] = []
    if macs:
        frag, a = _scope(kind, value, macs, "dns")
        domains = core.query_all(
            "SELECT x.qname, COUNT(*) AS n FROM dns_log x WHERE x.ts BETWEEN %s AND %s AND "
            + frag + " AND x.event_kind = 'query' GROUP BY x.qname ORDER BY n DESC LIMIT %s",
            tuple([start, end] + a + [TOP_DOMAINS]))
        frag, a = _scope(kind, value, macs, "conn")
        row = core.query_one(
            "SELECT COUNT(*) AS n, SUM(x.bytes_out) AS bytes_out, SUM(x.bytes_in) AS bytes_in "
            "FROM conn_log x WHERE x.ts BETWEEN %s AND %s AND " + frag, tuple([start, end] + a))
        if row:
            totals = dict(n=row.get("n") or 0, bytes_out=row.get("bytes_out") or 0,
                          bytes_in=row.get("bytes_in") or 0)
        top_dst = core.query_all(
            "SELECT x.dst_ip, SUM(COALESCE(x.bytes_out,0) + COALESCE(x.bytes_in,0)) AS total, "
            "COUNT(*) AS n FROM conn_log x WHERE x.ts BETWEEN %s AND %s AND " + frag +
            " GROUP BY x.dst_ip ORDER BY total DESC LIMIT %s", tuple([start, end] + a + [TOP_DST]))

    ctx.update(start_dt=start, end_dt=end, customer=customer, owners=owners, devices=devices,
               device_now=device_now, sessions=sessions, domains=domains, totals=totals,
               top_dst=top_dst, is_admin=is_admin, now=datetime.now())
    return render_template("log_summary.html", **ctx)
