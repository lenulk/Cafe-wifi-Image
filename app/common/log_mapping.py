"""
common/log_mapping.py — JOIN ย้อนกลับจากแถว conn_log/dns_log ไปหา voucher/customer

ใช้ร่วมกันระหว่างหน้า /logs (admin/app.py) และไฟล์ส่งออกหลักฐาน (tools/export_evidence.py)
-- R2-10: เดิมหน้า /logs โยงถึงตัวบุคคลได้แต่ไฟล์ส่งออกไม่ได้ ตรรกะจับคู่ต้องเป็นชุดเดียวกันเป๊ะ
ไม่เช่นนั้นสิ่งที่เจ้าหน้าที่เห็นบนเว็บกับในไฟล์หลักฐานจะไม่ตรงกัน
"""
from __future__ import annotations

# mapping ย้อนกลับ conn_log.mac / dns_log.mac -> portal_session -> voucher -> customer -- จับคู่
# ด้วย mac + ip + ช่วงเวลาที่ session เปิดสิทธิ์อยู่ (ไม่ใช่แค่ join ตาม mac เฉย ๆ) เพราะ MAC
# เดียวกันใช้กับ voucher คนละใบคนละช่วงเวลาได้จริง -- ถ้า join แค่ mac จะได้ผลลัพธ์ผิดคนเมื่อ MAC
# ถูกนำกลับมาใช้ซ้ำข้ามช่วงเวลา ถ้าเข้าได้มากกว่า 1 session จะไม่เดา (ps เป็น NULL)
# c.natid_masked มาจากคอลัมน์ที่เก็บค่า mask ไว้แล้วใน DB (ไม่เคย SELECT natid_enc/natid_hash)
# จึงไม่มีทางเห็นเลขเต็มไม่ว่า role ไหน ตรงตาม §6.2 ข้อ 5
# R2-02: conn_log.ts คือเวลาจบ connection (DESTROY) ซึ่งอาจเลยช่วง session ของเจ้าของไปแล้ว
# จึงจับคู่ด้วยเวลาเริ่ม ({tsexpr} = COALESCE(cl.started_at, cl.ts)) ส่วน dns_log ใช้ ts ตรง ๆ
MAPPING_JOIN = (
    " LEFT JOIN portal_session ps ON ps.id = ("
    " SELECT CASE WHEN COUNT(*)=1 THEN MAX(s.id) END FROM portal_session s"
    " WHERE s.mac={alias}.mac AND s.ip={alias}.{ipfield}"
    " AND s.authenticated_at <= {tsexpr}"
    " AND (s.ended_at IS NULL OR {tsexpr} <= s.ended_at))"
    " LEFT JOIN voucher v ON v.id=ps.voucher_id"
    " LEFT JOIN customer c ON c.id=v.customer_id"
)

CONN_TSEXPR = "COALESCE(cl.started_at, cl.ts)"
DNS_TSEXPR = "dl.ts"


def conn_mapping_join() -> str:
    return MAPPING_JOIN.format(alias="cl", ipfield="src_ip", tsexpr=CONN_TSEXPR)


def dns_mapping_join() -> str:
    return MAPPING_JOIN.format(alias="dl", ipfield="client_ip", tsexpr=DNS_TSEXPR)
