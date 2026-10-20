"""common/sqlutil.py — ตัวช่วยเล็ก ๆ ที่หน้า log หลายหน้าใช้ร่วมกัน"""
from __future__ import annotations

import re


def like_escape(s: str) -> str:
    """escape ตัวแทน LIKE (% _) และเครื่องหมาย \\ ให้เป็นตัวอักษรธรรมดา (MySQL ใช้ \\ เป็น escape ตั้งต้น)"""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def format_natid(nid: str) -> str:
    """1234567890123 -> '1-2345-67890-12-3' (รูปแบบเลขบัตรไทย) · ไม่ใช่ 13 หลักคืนค่าเดิม"""
    d = re.sub(r"\D", "", nid or "")
    if len(d) != 13:
        return nid
    return f"{d[0]}-{d[1:5]}-{d[5:10]}-{d[10:12]}-{d[12]}"
