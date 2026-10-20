"""
admin/views/logs.py — ค้นหา log ย้อนหลัง + CSV + ตรวจความถูกต้องของ log

แยกออกจาก admin/app.py (2026-10-03) -- ตัวช่วยกลางและการเชื่อมฐานข้อมูลเรียกผ่าน core.* ตอนรันเสมอ
(เทสต์ reload admin.app แล้วสลับฐานข้อมูลจำลอง ถ้า import query_all มาตรง ๆ จะค้างตัวเก่า)
"""
from __future__ import annotations

import ipaddress
import io
import re
from datetime import datetime, timedelta
from flask import abort, current_app, g, render_template, request, session
from common import audit, crypto
from common.customer import PURGED_MARK
from common.domain_match import domain_condition, normalize_domain
from common.log_mapping import conn_mapping_join, dns_mapping_join
from common.sqlutil import format_natid, like_escape
from logger.integrity import SqlManifestStore, verify_chain

from admin import app as core
from admin.routes import Routes

routes = Routes()


# N9 (CODING_BRIEF.md) ⭐ ช่องว่างที่ใหญ่ที่สุด -- DoD ของ Phase 4 เขียนว่า "ค้นย้อนกลับใน
# Admin เจอครบ" และ T10 ทดสอบไม่ได้เลยถ้าไม่มีหน้านี้ (เดิมมีแค่ export ผ่าน command line
# ใน tools/export_evidence.py) -- หน้านี้ค้น conn_log/dns_log ผ่านเว็บได้จริง
LOGS_PAGE_SIZE = 50


@routes.get("/logs")
@core.login_required
def search_logs():
    """ค้น log ย้อนหลัง -- ช่องค้นหาเดียวเดาชนิดให้เอง (เลขบัตร/CAFE-/MAC/IP/เว็บ) + ช่วงเวลาสำเร็จรูป

    ยังบังคับช่วงเวลาเสมอเหมือนเดิม (ตาราง log โตเร็วตาม ม.26 ห้ามกวาดทั้งตาราง) แต่ค่าเริ่มต้นคือ
    "วันนี้" -- เปิดหน้าครั้งแรกจึงไม่ค้นอะไร (ไม่ลง audit) แค่แสดงฟอร์มพร้อมใช้ แทน 400 แบบเดิม
    """
    log_type = request.args.get("log_type", "conn")
    if log_type not in ("conn", "dns"):
        log_type = "conn"
    q = (request.args.get("q") or "").strip()[:100]
    site = (request.args.get("site") or "").strip()[:100]
    port_raw = (request.args.get("port") or "").strip()[:10]
    proto_raw = (request.args.get("proto") or "").strip().lower()[:10]
    rng = request.args.get("range", "today")
    if rng not in LOG_RANGES:
        rng = "today"
    start_raw = (request.args.get("start") or "").strip()
    end_raw = (request.args.get("end") or "").strip()
    identified_only = request.args.get("identified") == "1"
    show_answers = request.args.get("answers") == "1"
    want_csv = request.args.get("format") == "csv"
    try:
        page = max(1, int(request.args.get("page") or 1))
    except ValueError:
        page = 1

    params = dict(log_type=log_type, q=q, range=rng, start=start_raw, end=end_raw,
                  identified="1" if identified_only else "", answers="1" if show_answers else "",
                  cid="", site=site, port=port_raw, proto=proto_raw)
    ctx = dict(params=params, ranges=LOG_RANGES, rows=[], page=page, has_next=False,
               has_prev=page > 1, searched=False, kind=None, note=None, kind_label=None, site_label=None,
               summary_ok='log_summary' in current_app.view_functions)

    # เปิดหน้าครั้งแรก (ยังไม่กดค้นหา) -- แสดงฟอร์ม ไม่แตะ DB
    if "range" not in request.args and not q and not site:
        return render_template("logs_search.html", error=None, **ctx)

    start, end, error = _resolve_log_range(rng, start_raw, end_raw)
    if error:
        return render_template("logs_search.html", error=error, **ctx), 400
    # cid = ผู้ใช้เลือกลูกค้าจากรายการแนะนำ (/logs/suggest) -- ช่อง q เป็นเลขบัตรแบบ masked ซึ่งค้นตรง ๆ ไม่ได้
    # ใช้ cid ก็ต่อเมื่อ q ยังตรงกับ masked ของลูกค้านั้นเป๊ะ ๆ (พนักงานแก้ข้อความแล้ว = ทิ้ง cid กลับไปเดาชนิดตามปกติ)
    kind = value = error = None
    cid_raw = (request.args.get("cid") or "").strip()
    if q and cid_raw.isdigit() and 0 < int(cid_raw) < 2**63:
        cust = core.query_one("SELECT id, natid_masked FROM customer WHERE id = %s", (int(cid_raw),))
        if cust and cust["natid_masked"] != PURGED_MARK and q == cust["natid_masked"]:
            kind, value = "customer", cust["id"]
            params["cid"] = str(cust["id"])
    if kind is None:
        kind, value, error = _classify_log_query(q)
    if error:
        return render_template("logs_search.html", error=error, **ctx), 400
    has_rev = _has_column("dns_log", "qname_rev")
    ctx.update(kind=kind, start_dt=start, end_dt=end,
               kind_label=_kind_label(kind, value, q, subdomain=has_rev))

    # ปลายทาง (site) -- AND กับ q ตอบ "คนนี้เคยเข้าเว็บ/IP นี้ไหม"
    site_kind, site_value, site_error = _classify_site(site)
    if site_error:
        return render_template("logs_search.html", error=site_error, **ctx), 400
    ctx["site_label"] = _site_label(site_kind, site_value, subdomain=has_rev)
    port = proto = None
    if log_type == "conn":
        port, error = _parse_port(port_raw)
        if not error:
            proto, error = _parse_proto(proto_raw)
        if error:
            return render_template("logs_search.html", error=error, **ctx), 400

    where: list[str] = []
    args: list = [start, end]
    a = "dl" if log_type == "dns" else "cl"
    if kind == "natid":
        cust = core.query_one("SELECT id FROM customer WHERE natid_hash = %s", (value,))
        if not cust:
            ctx.update(searched=True, note="ไม่พบลูกค้าที่ใช้เลขบัตรนี้")
            return render_template("logs_search.html", error=None, **ctx)
        where.append("c.id = %s"); args.append(cust["id"])
    elif kind == "customer":
        where.append("c.id = %s"); args.append(value)
    elif kind == "voucher":
        where.append("v.username = %s"); args.append(value)
    elif kind == "mac":
        where.append(f"{a}.mac = %s"); args.append(value)
    elif kind == "ip":
        if log_type == "dns":
            where.append("(dl.client_ip = %s OR dl.answer = %s)")
        else:
            where.append("(cl.src_ip = %s OR cl.dst_ip = %s)")
        args += [value, value]
    elif kind == "cidr":
        _net, lo, hi, ver = value
        cols = ("dl.client_ip", "dl.answer") if log_type == "dns" else ("cl.src_ip", "cl.dst_ip")
        parts = []
        for col in cols:
            parts.append(_cidr_sql(col, ver))
            args += [lo, hi]
        where.append("(" + " OR ".join(parts) + ")")
    elif kind in ("domain", "name"):
        # "name" = คำไม่มีจุด เช่น "DESKTOP-7KQ2L" หรือ "facebook" -- อาจเป็นชื่อเครื่องลูกค้าหรือชื่อเว็บก็ได้
        # จึงค้นทั้งสองอย่าง ("domain" มีจุด = ชื่อเว็บแน่นอน ไม่ต้องค้นชื่อเครื่อง)
        conds: list[str] = []
        if kind == "name":
            conds.append("ps.hostname LIKE %s")
            args.append(f"%{like_escape(value)}%")
        c, ca = _target_cond(log_type, kind, value, start, end)
        conds.append(c)
        args += ca
        if log_type == "conn":
            ctx["note"] = _conn_name_note()
        if kind == "name":
            ctx["note"] = ("ค้นทั้งชื่อเครื่องลูกค้าและชื่อเว็บ" +
                           (" · " + ctx["note"] if ctx["note"] else ""))
        where.append("(" + " OR ".join(conds) + ")")
    if site_kind:
        c, ca = _site_cond(log_type, site_kind, site_value, start, end)
        where.append(c)
        args += ca
        if site_kind in ("domain", "name") and log_type == "conn":
            ctx["note"] = ctx["note"] or _conn_name_note()
    if port is not None:
        where.append("cl.dst_port = %s")
        args.append(port)
    if proto:
        if proto == "other":
            where.append("cl.proto NOT IN ('tcp', 'udp', 'icmp')")
        else:
            where.append("cl.proto = %s")
            args.append(proto)
    if identified_only:
        where.append("v.id IS NOT NULL")
    if log_type == "dns" and not show_answers:
        where.append("dl.event_kind = 'query'")

    if log_type == "dns":
        sql = ("SELECT dl.ts, dl.client_ip, dl.mac, dl.qname, dl.qtype, dl.answer, dl.event_kind, "
               "v.username AS voucher_username, c.natid_masked, c.id AS customer_id, "
               "ps.hostname AS device_hostname, ps.os_label AS device_os "
               "FROM dns_log dl" + dns_mapping_join() + " WHERE dl.ts BETWEEN %s AND %s")
    else:
        dn = "cl.dst_name, " if _has_column("conn_log", "dst_name") else ""
        sql = ("SELECT cl.ts, cl.started_at, cl.mac, cl.src_ip, cl.src_port, cl.dst_ip, " + dn + "cl.dst_port, "
               "cl.proto, cl.bytes_out, cl.bytes_in, v.username AS voucher_username, c.natid_masked, c.id AS customer_id, "
               "ps.hostname AS device_hostname, ps.os_label AS device_os "
               "FROM conn_log cl" + conn_mapping_join() + " WHERE cl.ts BETWEEN %s AND %s")
    sql += "".join(f" AND {w}" for w in where) + f" ORDER BY {a}.ts DESC LIMIT %s OFFSET %s"

    # audit ห้ามมีเลขบัตรเต็ม -- ลงแค่ชนิดที่ค้น (เลขบัตรแทนด้วย masked)
    shown_q = crypto.mask_natid(re.sub(r"\D", "", q)) if kind == "natid" else (q or "-")
    detail = (f"log_type={log_type} start={start.isoformat()} end={end.isoformat()} "
              f"q={shown_q} kind={kind or '-'} site={site or '-'} site_kind={site_kind or '-'} "
              f"port={port if port is not None else '-'} proto={proto or '-'} "
              f"identified={int(identified_only)} page={page}")

    if want_csv:
        if session.get("role") != "admin":
            abort(403, "ดาวน์โหลด CSV ได้เฉพาะผู้ดูแลระบบ (admin)")
        rows = core.query_all(sql, tuple(args + [LOGS_CSV_MAX, 0]))
        n_full = _attach_full_natids(rows)    # admin เท่านั้น (ถึงตรงนี้ได้ = admin) -- audit ก่อนส่งไฟล์เสมอ
        audit.log_required(audit.EXPORT_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                           target="web-csv", detail=f"{detail} rows={len(rows)} natid_full={n_full}")
        return _logs_csv(log_type, rows)

    audit.log_required(audit.SEARCH_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                       detail=detail)
    rows = core.query_all(sql, tuple(args + [LOGS_PAGE_SIZE + 1, (page - 1) * LOGS_PAGE_SIZE]))
    has_next = len(rows) > LOGS_PAGE_SIZE
    rows = rows[:LOGS_PAGE_SIZE]
    _add_unidentified_hints(rows)
    if session.get("role") == "admin":
        n_full = _attach_full_natids(rows)
        if n_full:
            # audit ก่อน render -- log_required ล้มเหลว = 500 ไม่มีเลขเต็มหลุดไปหน้าจอ (ไม่ลงตัวเลขจริง ลงแค่จำนวน)
            audit.log_required(audit.VIEW_NATID_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                               detail=f"log_type={log_type} page={page} natid_full={n_full}")
    ctx.update(rows=rows, has_next=has_next, searched=True)
    return render_template("logs_search.html", error=None, **ctx)


def _add_unidentified_hints(rows) -> None:
    """แถวที่ "ยังไม่ระบุตัว" (เครื่องไม่ได้รับสิทธิ์ตอนนั้น เช่น ก่อนอนุมัติ หรือหลังถูกปิดสิทธิ์) ใส่ r["hint"]
    บอกว่าเครื่อง (MAC) นี้เคยใช้/ต่อมาได้สิทธิ์ของใคร -- **แสดงประกอบบนเว็บเท่านั้น** ไม่ผูกแถวนั้นกับ
    ลูกค้าจริง (ไม่ลง CSV/ไฟล์หลักฐาน) เพราะตอนเกิดแถวนั้นเครื่องไม่ได้ใช้สิทธิ์ของใครเลย"""
    pending = [r for r in rows if not r.get("natid_masked") and r.get("mac")]
    macs = sorted({r["mac"] for r in pending})
    if not macs:
        return
    sessions = core.query_all(
        "SELECT ps.mac, ps.authenticated_at, ps.ended_at, ps.hostname, ps.os_label, c.natid_masked, "
        "c.id AS customer_id "
        "FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
        "LEFT JOIN customer c ON c.id = v.customer_id "
        f"WHERE ps.mac IN ({', '.join(['%s'] * len(macs))}) AND ps.authenticated_at IS NOT NULL "
        "ORDER BY ps.authenticated_at DESC", tuple(macs))
    for r in pending:
        t = r.get("started_at") or r["ts"]
        mine = [s for s in sessions if s["mac"] == r["mac"]]
        if any(s["authenticated_at"] <= t and (s["ended_at"] is None or t <= s["ended_at"]) for s in mine):
            continue  # มี session ครอบเวลานี้แต่จับคู่ไม่ได้แน่ชัด (ซ้อนกัน/IP ไม่ตรง) -- ไม่ชี้นำว่าเป็นของใคร
        before = next((s for s in mine if s["authenticated_at"] <= t), None)   # ใหม่สุดก่อนแถวนี้
        after = next((s for s in reversed(mine) if s["authenticated_at"] > t), None)  # แรกสุดหลังแถวนี้
        s, when = (before, "เคยใช้สิทธิ์ของ") if before else (after, "ต่อมาได้รับสิทธิ์ของ")
        if s:
            r["hint"] = dict(hostname=s["hostname"], os_label=s["os_label"],
                             natid_masked=s["natid_masked"], customer_id=s.get("customer_id"), when=when)


def _attach_full_natids(rows) -> int:
    """admin เท่านั้น: ถอดรหัสเลขบัตรของลูกค้าที่ปรากฏในผล (และในคำใบ้) ใส่ r["natid_full"] / hint["natid_full"]
    (รูปแบบ d-dddd-ddddd-dd-d) · คืนจำนวนลูกค้าไม่ซ้ำที่ถอดได้ -- ผู้เรียกต้อง audit ก่อนส่งข้อมูลออก
    staff ไม่ผ่านฟังก์ชันนี้เลย (คืน 0 ก่อนแตะ DB): เส้นทางของ staff ต้องไม่ SELECT natid_enc · ลูกค้า PURGED ไม่ถอด"""
    if session.get("role") != "admin":
        return 0
    targets = [r for r in rows if r.get("customer_id")] + \
              [r["hint"] for r in rows if r.get("hint") and r["hint"].get("customer_id")]
    ids = sorted({t["customer_id"] for t in targets})
    if not ids:
        return 0
    recs = core.query_all(
        "SELECT natid_enc, id FROM customer WHERE id IN (" + ", ".join(["%s"] * len(ids)) +
        ") AND natid_masked <> %s", tuple(ids) + (PURGED_MARK,))
    full: dict = {}
    for rec in recs:
        try:
            full[rec["id"]] = format_natid(crypto.natid_decrypt(rec["natid_enc"]))
        except Exception:  # noqa: BLE001 -- ถอดไม่ได้ = ข้าม (หน้าจอถอยไปแสดงเลข masked)
            continue
    shown = set()
    for t in targets:
        f = full.get(t["customer_id"])
        if f:
            t["natid_full"] = f
            shown.add(t["customer_id"])
    return len(shown)


def _kind_label(kind, value, q: str, subdomain: bool = False):
    """ข้อความใต้ช่องค้นหา: ระบบตีความสิ่งที่พิมพ์เป็นอะไร (เลขบัตรแสดงแบบ masked เสมอ)"""
    if kind is None:
        return None
    if kind == "natid":
        return "เลขบัตร " + crypto.mask_natid(re.sub(r"\D", "", q))
    if kind == "customer":
        return "ลูกค้าที่เลือก"
    if kind == "voucher":
        return f"เลขอ้างอิง {value}"
    if kind == "mac":
        return f"MAC {value}"
    if kind == "ip":
        return f"IP {value}"
    if kind == "cidr":
        return f"ช่วง IP {value[0]}"
    if kind == "domain":
        return f"ชื่อเว็บ {value}" + (" (เว็บนี้และโดเมนย่อย)" if subdomain else "")
    return f"ชื่อเครื่องหรือชื่อเว็บ {value}"


def _site_label(kind, value, subdomain: bool = False):
    if kind is None:
        return None
    if kind == "ip":
        return f"IP {value}"
    if kind == "cidr":
        return f"ช่วง IP {value[0]}"
    if kind == "domain":
        return f"เว็บ {value}" + (" และโดเมนย่อย" if subdomain else "")
    return f"ชื่อเว็บ {value}"


# ---------------------------------------------------------------- ตรวจคอลัมน์ที่มาจาก migration (014/015)
# Pi บางตัวอาจยังไม่รัน migration -- ตรวจครั้งเดียวต่อ process แล้วจำ · error = ถือว่าไม่มี (ไม่จำผล)
_COLUMN_CACHE: dict = {}


def _has_column(table: str, column: str) -> bool:
    key = (table, column)
    if key in _COLUMN_CACHE:
        return _COLUMN_CACHE[key]
    try:
        row = core.query_one(
            "SELECT 1 AS ok FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
            "AND TABLE_NAME = %s AND COLUMN_NAME = %s", (table, column))
    except Exception:  # noqa: BLE001
        return False
    _COLUMN_CACHE[key] = bool(row)
    return _COLUMN_CACHE[key]


def _conn_name_note() -> str:
    if _has_column("conn_log", "dst_name"):
        return ("ค้นชื่อเว็บในตารางการเชื่อมต่อ = ใช้ชื่อที่บันทึกไว้ตอนเชื่อมต่อ · เฉพาะแถวเก่าที่ไม่มีชื่อ "
                "ประมาณจาก IP ที่ DNS ตอบสำหรับเว็บนั้น (เว็บที่ใช้ CDN ร่วมกันอาจติดมาด้วย)")
    return ("ค้นชื่อเว็บในตารางการเชื่อมต่อ = ประมาณจาก IP ที่ DNS ตอบสำหรับเว็บนั้น "
            "(เว็บที่ใช้ CDN ร่วมกันอาจติดมาด้วย)")


def _target_cond(log_type: str, kind: str, value: str, start, end):
    """เงื่อนไข "ชื่อเว็บ" (kind = domain/name) -> (sql, args)
    DNS: domain = ตรงพอดีหรือซับโดเมน (ใช้ qname_rev ถ้ามี) · name = ส่วนหนึ่งของชื่อ
    conn: ใช้ cl.dst_name ถ้ามี แถวที่ไม่มีชื่อ (เก่า) ถอยไปประมาณจาก IP ที่ DNS ตอบ"""
    pat = f"%{like_escape(value)}%"
    use_rev = kind == "domain" and _has_column("dns_log", "qname_rev")
    if log_type == "dns":
        return domain_condition("dl", value) if use_rev else ("dl.qname LIKE %s", [pat])
    if use_rev:
        sub_c, sub_a = domain_condition("d2", value)
    else:
        sub_c, sub_a = "d2.qname LIKE %s", [pat]
    sub = ("cl.dst_ip IN (SELECT d2.answer FROM dns_log d2 WHERE " + sub_c +
           " AND d2.event_kind = 'answer' AND d2.ts BETWEEN %s AND %s)")
    sub_a = list(sub_a) + [start - timedelta(hours=1), end]
    if not _has_column("conn_log", "dst_name"):
        return sub, sub_a
    if kind == "domain":
        d = normalize_domain(value)
        m, ma = "(cl.dst_name = %s OR cl.dst_name LIKE %s)", [d, "%." + like_escape(d)]
    else:
        m, ma = "cl.dst_name LIKE %s", [pat]
    return f"({m} OR (cl.dst_name IS NULL AND {sub}))", ma + sub_a


def _cidr_sql(col: str, ver: int) -> str:
    # INET6_ATON: IPv4 -> 4 ไบต์, IPv6 -> 16 ไบต์ จึงเทียบข้ามตระกูลไม่ได้อยู่แล้ว · LIKE กันซ้ำอีกชั้น
    # (%% = % ตัวจริง เพราะ driver จัดรูปแบบ SQL ด้วย args เสมอ)
    fam = "%%.%%" if ver == 4 else "%%:%%"
    return f"(INET6_ATON({col}) BETWEEN INET6_ATON(%s) AND INET6_ATON(%s) AND {col} LIKE '{fam}')"


def _site_cond(log_type: str, kind: str, value, start, end):
    if kind == "ip":
        return ("dl.answer = %s" if log_type == "dns" else "cl.dst_ip = %s"), [value]
    if kind == "cidr":
        _net, lo, hi, ver = value
        return _cidr_sql("dl.answer" if log_type == "dns" else "cl.dst_ip", ver), [lo, hi]
    return _target_cond(log_type, kind, value, start, end)


def _parse_cidr(q: str):
    """q มี "/" -> (value, error) · value = (แสดงผล, ต้น, ปลาย, ตระกูล)"""
    try:
        net = ipaddress.ip_network(q, strict=False)
    except ValueError:
        return None, "รูปแบบช่วง IP ไม่ถูกต้อง — ตัวอย่าง 192.168.50.0/24"
    if (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 48):
        return None, ("ช่วง IP กว้างเกินไป — IPv4 ต้องไม่ต่ำกว่า /16 และ IPv6 ต้องไม่ต่ำกว่า /48 "
                      "(กันค้นทั้งตาราง)")
    return (str(net), str(net.network_address), str(net.broadcast_address), net.version), None


def _classify_site(site: str):
    """ช่อง "ชื่อเว็บ / IP ปลายทาง" -> (kind, value, error) · kind: ip/cidr/domain/name หรือ None (ว่าง)"""
    if not site:
        return None, None, None
    if "/" in site:
        v, err = _parse_cidr(site)
        return ("cidr", v, None) if v else (None, None, err)
    try:
        return "ip", str(ipaddress.ip_address(site)), None
    except ValueError:
        pass
    if _DOMAIN_RE.match(site) and any(ch.isalpha() for ch in site):
        return ("domain" if "." in site.strip(".") else "name"), site.lower(), None
    return None, None, "ช่องปลายทางต้องเป็น IP, ช่วง IP (เช่น 1.2.3.0/24) หรือชื่อเว็บ"


def _parse_port(raw: str):
    if not raw:
        return None, None
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        return None, "พอร์ตต้องเป็นตัวเลข 1–65535"
    return int(raw), None


PROTOS = ("tcp", "udp", "icmp", "other")


def _parse_proto(raw: str):
    if not raw:
        return None, None
    if raw not in PROTOS:
        return None, "โปรโตคอลต้องเป็น tcp, udp, icmp หรือ other"
    return raw, None


LOGS_CSV_MAX = 5000


LOG_MAX_SPAN = timedelta(days=31)


LOG_RANGES = {"1h": "1 ชม.ล่าสุด", "today": "วันนี้", "yesterday": "เมื่อวาน",
              "7d": "7 วันล่าสุด", "custom": "กำหนดเอง"}


def _resolve_log_range(rng: str, start_raw: str, end_raw: str):
    """คืน (start, end, error) -- ช่วงสำเร็จรูปคำนวณจากเวลาปัจจุบัน, กำหนดเองไม่เกิน 31 วัน"""
    now = datetime.now().replace(microsecond=0)
    midnight = now.replace(hour=0, minute=0, second=0)
    if rng == "1h":
        return now - timedelta(hours=1), now, None
    if rng == "today":
        return midnight, now, None
    if rng == "yesterday":
        return midnight - timedelta(days=1), midnight - timedelta(seconds=1), None
    if rng == "7d":
        return now - timedelta(days=7), now, None
    if not start_raw or not end_raw:
        return None, None, "เลือก 'กำหนดเอง' แล้วต้องระบุทั้งเวลาเริ่มต้นและสิ้นสุด"
    try:
        start, end = datetime.fromisoformat(start_raw), datetime.fromisoformat(end_raw)
    except ValueError:
        return None, None, "รูปแบบวันเวลาไม่ถูกต้อง"
    if end <= start:
        return None, None, "เวลาสิ้นสุดต้องอยู่หลังเวลาเริ่มต้น"
    if end - start > LOG_MAX_SPAN:
        return None, None, "ค้นได้ครั้งละไม่เกิน 31 วัน (กันเครื่องช้า) — แบ่งค้นเป็นช่วง"
    return start, end, None


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$")


_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _classify_log_query(q: str):
    """เดาว่าพิมพ์อะไรมา -- คืน (kind, value, error) · kind: natid/voucher/mac/ip/cidr/domain/name หรือ None
    (name = คำไม่มีจุด อาจเป็นชื่อเครื่องหรือชื่อเว็บ)"""
    if not q:
        return None, None, None
    digits = re.sub(r"[\s-]", "", q)
    if digits.isdigit() and len(digits) == 13:
        if not crypto.valid_thai_id(digits):
            return None, None, "เลขบัตรประชาชนไม่ถูกต้อง (ตรวจ checksum ไม่ผ่าน)"
        return "natid", crypto.natid_hash(digits), None
    if re.fullmatch(r"(?i)CAFE-[A-Z0-9]{5}", q):
        return "voucher", q.upper(), None
    if _MAC_RE.match(q):
        hexes = re.sub(r"[:-]", "", q).upper()
        return "mac", ":".join(hexes[i:i + 2] for i in range(0, 12, 2)), None
    try:
        return "ip", str(ipaddress.ip_address(q)), None
    except ValueError:
        pass
    if "/" in q:
        v, err = _parse_cidr(q)
        return ("cidr", v, None) if v else (None, None, err)
    if _DOMAIN_RE.match(q) and any(ch.isalpha() for ch in q):
        return ("domain" if "." in q.strip(".") else "name"), q.lower(), None
    return None, None, ("ไม่รู้จักรูปแบบนี้ — พิมพ์เลขบัตร 13 หลัก, เลขอ้างอิง CAFE-xxxxx, MAC, IP, "
                        "ชื่อเครื่อง หรือชื่อเว็บ")


def _logs_csv(log_type: str, rows):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    if log_type == "dns":
        w.writerow(["ts", "client_ip", "mac", "qname", "qtype", "answer", "event_kind",
                    "voucher", "customer_masked", "customer_natid", "device_hostname", "device_os"])
        for r in rows:
            w.writerow([r["ts"], r["client_ip"], r["mac"], r["qname"], r["qtype"], r["answer"],
                        r["event_kind"], r["voucher_username"], r["natid_masked"], r.get("natid_full"),
                        r.get("device_hostname"), r.get("device_os")])
    else:
        w.writerow(["started_at", "ts", "mac", "src_ip", "src_port", "dst_ip", "dst_name", "dst_port", "proto",
                    "bytes_out", "bytes_in", "voucher", "customer_masked", "customer_natid",
                    "device_hostname", "device_os"])
        for r in rows:
            w.writerow([r["started_at"], r["ts"], r["mac"], r["src_ip"], r["src_port"], r["dst_ip"],
                        r.get("dst_name"), r["dst_port"], r["proto"], r["bytes_out"], r["bytes_in"],
                        r["voucher_username"], r["natid_masked"], r.get("natid_full"),
                        r.get("device_hostname"), r.get("device_os")])
    resp = core.app.make_response("﻿" + buf.getvalue())  # BOM ให้ Excel อ่านภาษาไทยถูก
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = (
        f"attachment; filename={log_type}_log_{datetime.now():%Y%m%d-%H%M%S}.csv")
    resp.headers["Cache-Control"] = "no-store"
    return resp


# N2 (CODING_BRIEF.md): logger/integrity.py มี verify_chain() พร้อมใช้และมีเทสต์ผ่านแล้ว
# แต่ไม่เคยมีปุ่มไหนต่อเรียกมันในหน้าเว็บเลย -- ปุ่มนี้คือ T12 ที่สาธิตสดได้ใน 20 วินาที
# (แก้ไฟล์ log ที่ผนึกแล้ว 1 ตัวอักษร -> กดปุ่ม -> เจอ hash_mismatch ทันที)
@routes.post("/logs/verify")
@core.login_required
@core.admin_required
def verify_log_integrity():
    archive_dir = core.LOG_DIR / "archive"
    issues = verify_chain(SqlManifestStore(), archive_dir)
    audit.log("verify_integrity", staff_id=session["staff_id"], client_ip=g.client_ip,
              detail=(f"พบ {len(issues)} ปัญหา" if issues else "chain สมบูรณ์ ไม่พบปัญหา"))
    return render_template("logs_verify.html", issues=issues, archive_dir=str(archive_dir))
