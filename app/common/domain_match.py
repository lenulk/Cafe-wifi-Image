"""common/domain_match.py — เงื่อนไข SQL ค้นโดเมนแบบ "ตรงกันพอดีหรือซับโดเมน" ที่ใช้ดัชนีได้

dns_log มีคอลัมน์ qname_rev = REVERSE(qname) พร้อมดัชนี (sql/014_dns_qname_rev.sql)
ค้น google.com -> qname = 'google.com' OR qname_rev LIKE 'moc.elgoog.%' (prefix match ใช้ดัชนีได้)
จะจับ www.google.com ได้ แต่ไม่จับ notgoogle.com (มีจุดคั่นนำหน้าเสมอ)
"""
from __future__ import annotations


BS = chr(92)


def _like_escape(s: str) -> str:
    """escape backslash, %, _ สำหรับ LIKE (MariaDB ใช้ backslash เป็น escape เริ่มต้น)"""
    return s.replace(BS, BS * 2).replace("%", BS + "%").replace("_", BS + "_")


def normalize_domain(domain: str) -> str:
    return (domain or "").strip().strip(".").lower()


def domain_condition(col_prefix: str, domain: str) -> tuple[str, list]:
    """คืน (SQL fragment, args) -- col_prefix เช่น "dl" (ว่าง = ไม่มี alias)

    col_prefix ต้องมาจากโค้ดเราเอง ไม่ใช่ input ผู้ใช้ (ถูกต่อเข้า SQL ตรง ๆ)
    """
    d = normalize_domain(domain)
    p = f"{col_prefix}." if col_prefix and not col_prefix.endswith(".") else (col_prefix or "")
    sql = f"({p}qname = %s OR {p}qname_rev LIKE %s)"
    return sql, [d, _like_escape(("." + d)[::-1]) + "%"]
