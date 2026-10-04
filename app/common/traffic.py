"""
common/traffic.py — รวมยอด traffic (bytes) ต่อ MAC จาก conn_log

แยกออกมาจาก tools/enforce_voucher_expiry.py (แก้บั๊ก พบตอนตรวจทานรอบ 4): เดิม
app/fas/app.py (service ที่ลูกค้าเข้าถึงได้โดยตรง) import ฟังก์ชันนี้จาก tools.* ซึ่งเป็นชั้น
CLI/batch-job สำหรับงานบำรุงรักษาเท่านั้น -- ผิดทิศทางการพึ่งพา (dependency direction) ทำให้
service หน้าบ้านผูกติดกับโมดูล CLI งานเบื้องหลังโดยไม่จำเป็น common/ คือชั้นที่ทั้ง app/ และ
tools/ พึ่งพาได้ทั้งคู่อยู่แล้ว (เหมือน crypto.py, db.py) จึงย้ายมาไว้ตรงนี้แทน
"""
from __future__ import annotations

BYTES_PER_MB = 1_000_000


def sum_session_traffic_bytes(query_one_fn, mac: str, authenticated_at,
                              ended_at=None) -> tuple[int, int]:
    """รวมทราฟฟิกหลังเปิดสิทธิ์ถึงเวลาปิด session (ถ้ามี)

    ขอบล่างเป็นแบบไม่รวม เพื่อให้ event ที่ตรงกับเวลา reauth พอดีเป็นของ session เก่า
    ซึ่งใช้ขอบบนแบบรวม และไม่ถูกนับซ้ำใน session ใหม่
    """
    upper_bound = " AND ts <= %s" if ended_at is not None else ""
    args = (mac, authenticated_at, ended_at) if ended_at is not None else (mac, authenticated_at)
    row = query_one_fn(
        "SELECT COALESCE(SUM(bytes_out),0) AS bo, COALESCE(SUM(bytes_in),0) AS bi "
        "FROM conn_log WHERE mac=%s AND ts > %s" + upper_bound, args)
    if not row:
        return 0, 0
    return int(row["bo"]), int(row["bi"])
