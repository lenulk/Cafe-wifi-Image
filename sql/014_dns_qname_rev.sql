-- ============================================================================
--  014_dns_qname_rev.sql — คอลัมน์ qname กลับด้าน + ดัชนี สำหรับค้นโดเมน (dns_log)
--  MariaDB 10.6+ / 11.x
-- ============================================================================
-- ปัญหา: หน้าค้นหา log ใช้ `dl.qname LIKE '%x%'` -- มี % นำหน้า จึงใช้ดัชนีไม่ได้ ต้องสแกนทั้งตาราง
-- (dns_log เก็บ 180 วัน อาจเป็นล้านแถว)
--
-- วิธีแก้: เก็บ REVERSE(qname) เป็นคอลัมน์ PERSISTENT (คำนวณตอน INSERT ไม่ต้องแก้ collector)
-- แล้วค้น "โดเมนนี้หรือซับโดเมน" ด้วย
--     (qname = 'google.com' OR qname_rev LIKE 'moc.elgoog.%')
-- ซึ่งเป็น prefix match จึงใช้ idx_qname_rev ได้ (ดู app/common/domain_match.py)
--
-- เวลาที่คาด: ALTER นี้ rebuild ตารางทั้งก้อน (เพิ่มคอลัมน์ PERSISTENT + สร้างดัชนี) -- บน Pi 4B
-- ประมาณ 1-3 นาทีต่อ 1 ล้านแถว (ตารางถูกล็อกเขียนระหว่างนั้น cafe-logger จะรอ/บัฟเฟอร์ชั่วครู่)
-- ควรรันตอนร้านปิด วัดเวลาจริงด้วย tools/bench_dns_search.py ก่อน-หลัง
--
-- ใช้ได้กับตารางที่ partition รายสัปดาห์ (003) แล้ว -- คอลัมน์/ดัชนีถูกสร้างในทุก partition
-- รันซ้ำได้เสมอ: `IF NOT EXISTS` (MariaDB extension) ข้ามถ้ามีแล้ว
ALTER TABLE dns_log
  ADD COLUMN IF NOT EXISTS qname_rev VARCHAR(255) AS (REVERSE(qname)) PERSISTENT,
  ADD INDEX IF NOT EXISTS idx_qname_rev (qname_rev);
