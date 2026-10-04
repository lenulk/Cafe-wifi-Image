-- ============================================================================
--  005_bypass_alert.sql — ตาราง alert สำหรับ Bypass Detector (N10, CODING_BRIEF.md, T17)
--  MariaDB 10.6+ / 11.x
-- ============================================================================
-- PROJECT_PLAN.md §3.1.4 ชั้นที่ 4 วิเคราะห์ไว้เองว่า "ตรวจจับ + แจ้งเตือน ... ไม่ได้ป้องกัน
-- แต่มีคุณค่าเชิงวิชาการสูง" แต่ไม่เคยมีตารางรองรับผลตรวจจับเลย -- 001_schema.sql apply ไปแล้ว
-- แก้ตรง ๆ ไม่ได้ (กติกา §5 ของ CODING_BRIEF.md) จึงเพิ่มตารางใหม่ผ่าน migration นี้แทน
--
-- ไม่มี FOREIGN KEY ไปหาตารางอื่นโดยตั้งใจ -- IP/MAC ที่ตรวจพบเป็นอุปกรณ์แปลกปลอมที่ไม่เคย
-- login ผ่านระบบเลย (ไม่มี voucher/device/customer ผูกอยู่ ตามนิยามของ "bypass") จึงไม่มี
-- อะไรให้ join ถึงได้จริง
CREATE TABLE IF NOT EXISTS bypass_alert (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ip          VARCHAR(45) NOT NULL,
  mac         CHAR(17) NOT NULL,
  INDEX idx_detected_at (detected_at),
  INDEX idx_mac (mac)
) ENGINE=InnoDB;
