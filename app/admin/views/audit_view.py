"""
admin/views/audit_view.py — หน้าดู audit_log (เฉพาะ admin)

ใครทำอะไรเมื่อไหร่ในระบบ (เปิดเลขบัตร, ออกสิทธิ์, ส่งออก log, จัดการพนักงาน ฯลฯ) -- การเปิดดูหน้านี้เองก็ถูกบันทึก
เป็น action "view_audit" ทุกครั้ง (ผู้ตรวจสอบต้องถูกตรวจสอบได้ด้วย) · ตัวช่วยกลางเรียกผ่าน core.* ตอนรันเสมอ
"""
from __future__ import annotations

from flask import g, render_template, request, session

from common import audit

from admin import app as core
from admin.routes import Routes
from admin.views.logs import LOG_RANGES, _resolve_log_range

routes = Routes()

AUDIT_PAGE_SIZE = 50
VIEW_AUDIT = "view_audit"
Q_MAX = 100          # ความยาวช่องค้นข้อความ
Q_AUDIT_MAX = 50     # ส่วนของ q ที่ลงใน audit


def _known_actions() -> list[str]:
    """ค่าคงที่ใน common/audit.py (ตัวพิมพ์เล็กล้วน) + ค่าสตริงอิสระที่โค้ดอื่นเขียน"""
    consts = {v for k, v in vars(audit).items()
              if k.isupper() and isinstance(v, str) and v}
    consts.add(VIEW_AUDIT)
    return sorted(consts)


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@routes.get("/audit")
@core.login_required
@core.admin_required
def audit_log_page():
    staff_f = (request.args.get("staff") or "").strip()[:64]
    action_f = (request.args.get("action") or "").strip()[:64]
    q = (request.args.get("q") or "").strip()[:Q_MAX]
    ip_f = (request.args.get("client_ip") or "").strip()[:45]
    rng = request.args.get("range", "today")
    if rng not in LOG_RANGES:
        rng = "today"
    start_raw = (request.args.get("start") or "").strip()
    end_raw = (request.args.get("end") or "").strip()
    try:
        page = max(1, int(request.args.get("page") or 1))
    except ValueError:
        page = 1

    params = dict(staff=staff_f, action=action_f, q=q, client_ip=ip_f, range=rng,
                  start=start_raw, end=end_raw)

    staff_names = [r["username"] for r in
                   core.query_all("SELECT username FROM staff ORDER BY username LIMIT 500")]
    db_actions = [r["action"] for r in core.query_all(
        "SELECT DISTINCT action FROM audit_log ORDER BY action LIMIT 200")]
    actions = sorted(set(_known_actions()) | set(db_actions))
    ctx = dict(params=params, ranges=LOG_RANGES, staff_names=staff_names, actions=actions,
               rows=[], page=page, has_next=False, has_prev=page > 1,
               start_dt=None, end_dt=None)

    start, end, error = _resolve_log_range(rng, start_raw, end_raw)
    if error:
        return render_template("audit_log.html", error=error, **ctx), 400
    ctx.update(start_dt=start, end_dt=end)

    where = ["a.ts BETWEEN %s AND %s"]
    args: list = [start, end]
    if staff_f:
        where.append("s.username = %s"); args.append(staff_f)
    if action_f:
        where.append("a.action = %s"); args.append(action_f)
    if ip_f:
        where.append("a.client_ip = %s"); args.append(ip_f)
    if q:
        where.append("a.detail LIKE %s ESCAPE '\\\\'"); args.append(f"%{_like_escape(q)}%")

    sql = ("SELECT a.id, a.ts, s.username AS staff_username, a.staff_id, a.action, a.target, "
           "a.client_ip, a.detail FROM audit_log a LEFT JOIN staff s ON s.id = a.staff_id "
           "WHERE " + " AND ".join(where) + " ORDER BY a.ts DESC, a.id DESC LIMIT %s OFFSET %s")

    detail = (f"staff={staff_f or '-'} action={action_f or '-'} ip={ip_f or '-'} "
              f"q={q[:Q_AUDIT_MAX] or '-'} start={start.isoformat()} end={end.isoformat()} page={page}")
    audit.log_required(VIEW_AUDIT, staff_id=session["staff_id"], client_ip=g.client_ip, detail=detail)

    rows = core.query_all(sql, tuple(args + [AUDIT_PAGE_SIZE + 1, (page - 1) * AUDIT_PAGE_SIZE]))
    has_next = len(rows) > AUDIT_PAGE_SIZE
    ctx.update(rows=rows[:AUDIT_PAGE_SIZE], has_next=has_next)
    return render_template("audit_log.html", error=None, **ctx)
