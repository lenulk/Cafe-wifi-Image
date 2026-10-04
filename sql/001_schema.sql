-- ============================================================================
--  Cafe Wi-Fi Gateway & Management System — schema
--  MariaDB 10.6+ / 11.x   charset utf8mb4
-- ============================================================================
SET NAMES utf8mb4;

-- ---------------------------------------------------------------- พนักงาน
CREATE TABLE IF NOT EXISTS staff (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64)  NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,                    -- argon2id
  display_name  VARCHAR(128),
  role          ENUM('admin','staff') NOT NULL DEFAULT 'staff',
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  totp_secret   VARCHAR(64) NULL,                         -- 2FA (Phase 5)
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at DATETIME NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- ลูกค้า
-- D6: ไม่เก็บเลขบัตรประชาชนแบบ plaintext เด็ดขาด
CREATE TABLE IF NOT EXISTS customer (
  id           BIGINT AUTO_INCREMENT PRIMARY KEY,
  natid_hash   CHAR(64)       NOT NULL UNIQUE,  -- HMAC-SHA256(natid, PEPPER)
  natid_enc    VARBINARY(255) NOT NULL,         -- AES-256-GCM: nonce||ct||tag
  natid_masked CHAR(20)       NOT NULL,         -- '1-2345-XXXXX-XX-3'
  first_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen    DATETIME NULL,
  visit_count  INT NOT NULL DEFAULT 0,
  is_blocked   BOOLEAN NOT NULL DEFAULT FALSE,
  INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- voucher
CREATE TABLE IF NOT EXISTS voucher (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  customer_id   BIGINT NOT NULL,
  username      VARCHAR(32)  NOT NULL UNIQUE,   -- เช่น 'CAFE-8F3K2'
  password_hash VARCHAR(255) NOT NULL,          -- argon2id (plaintext แสดงครั้งเดียว)
  issued_by     INT NOT NULL,
  issued_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  valid_from    DATETIME NOT NULL,
  valid_until   DATETIME NOT NULL,
  quota_mb      INT NULL,
  used_mb       INT NOT NULL DEFAULT 0,
  max_devices   TINYINT NOT NULL DEFAULT 2,
  status        ENUM('active','expired','revoked','used_up') NOT NULL DEFAULT 'active',
  CONSTRAINT fk_voucher_customer FOREIGN KEY (customer_id) REFERENCES customer(id),
  CONSTRAINT fk_voucher_staff    FOREIGN KEY (issued_by)   REFERENCES staff(id),
  INDEX idx_status_valid (status, valid_until)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- อุปกรณ์
CREATE TABLE IF NOT EXISTS device (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  voucher_id BIGINT NOT NULL,
  mac        CHAR(17) NOT NULL,
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_ip    VARCHAR(45),
  UNIQUE KEY uq_voucher_mac (voucher_id, mac),
  INDEX idx_mac (mac),
  CONSTRAINT fk_device_voucher FOREIGN KEY (voucher_id) REFERENCES voucher(id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- session
CREATE TABLE IF NOT EXISTS portal_session (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  voucher_id BIGINT NOT NULL,
  mac        CHAR(17) NOT NULL,
  ip         VARCHAR(45) NOT NULL,
  started_at DATETIME NOT NULL,
  authenticated_at DATETIME NULL,
  pending_until DATETIME NULL,
  state ENUM('pending','authenticated','closed') NOT NULL DEFAULT 'pending',
  ended_at   DATETIME NULL,
  bytes_in   BIGINT NOT NULL DEFAULT 0,
  bytes_out  BIGINT NOT NULL DEFAULT 0,
  terminate_cause VARCHAR(32) NULL,
  INDEX idx_time (started_at, ended_at),
  INDEX idx_mac_time (mac, started_at),
  INDEX idx_pending (state, pending_until),
  CONSTRAINT fk_session_voucher FOREIGN KEY (voucher_id) REFERENCES voucher(id)
) ENGINE=InnoDB;

-- MAC หนึ่งตัวมี pending ได้ครั้งเดียว แม้คำขอพร้อมกันใช้ voucher คนละใบ
CREATE TABLE IF NOT EXISTS pending_mac_claim (
  mac CHAR(17) PRIMARY KEY,
  portal_session_id BIGINT NULL UNIQUE,
  CONSTRAINT fk_pending_session FOREIGN KEY (portal_session_id) REFERENCES portal_session(id)
) ENGINE=InnoDB;

-- FAS context ถูกส่งจาก gateway เพียงครั้งเดียว; browser ส่งกลับแค่ nonce
CREATE TABLE IF NOT EXISTS fas_context (
  nonce_hash CHAR(64) PRIMARY KEY,
  payload TEXT NOT NULL,
  request_ip VARCHAR(45) NOT NULL,
  expires_at DATETIME NOT NULL,
  consumed_at DATETIME NULL,
  INDEX idx_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS voucher_reveal (
  token_hash CHAR(64) PRIMARY KEY,
  staff_id INT NOT NULL,
  payload BLOB NOT NULL,
  expires_at DATETIME NOT NULL,
  consumed_at DATETIME NULL,
  INDEX idx_expiry (expires_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- ข้อมูลจราจร (ม.26)
-- D5: เก็บเฉพาะ metadata ไม่เก็บ payload
CREATE TABLE IF NOT EXISTS conn_log (
  id        BIGINT AUTO_INCREMENT,
  ts        DATETIME(3) NOT NULL,
  mac       CHAR(17) NULL,
  src_ip    VARCHAR(45) NOT NULL,
  src_port  SMALLINT UNSIGNED,
  dst_ip    VARCHAR(45) NOT NULL,
  dst_port  SMALLINT UNSIGNED,
  proto     ENUM('tcp','udp','icmp','other') NOT NULL DEFAULT 'other',
  bytes_out BIGINT DEFAULT 0,
  bytes_in  BIGINT DEFAULT 0,
  PRIMARY KEY (id, ts),
  INDEX idx_ts (ts),
  INDEX idx_mac_ts (mac, ts),
  INDEX idx_dst (dst_ip)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS dns_log (
  id        BIGINT AUTO_INCREMENT,
  ts        DATETIME(3) NOT NULL,
  client_ip VARCHAR(45) NULL,
  mac       CHAR(17),
  qname     VARCHAR(255) NOT NULL,
  qtype     VARCHAR(10),
  answer    VARCHAR(255),
  event_kind ENUM('query','answer') NOT NULL DEFAULT 'query',
  PRIMARY KEY (id, ts),
  INDEX idx_ts (ts),
  INDEX idx_qname (qname),
  INDEX idx_mac_ts (mac, ts)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- audit
-- หลักฐานว่าใครเข้าถึงข้อมูลอ่อนไหวเมื่อไหร่ (PDPA)
CREATE TABLE IF NOT EXISTS audit_log (
  id        BIGINT AUTO_INCREMENT PRIMARY KEY,
  ts        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  staff_id  INT NULL,
  action    VARCHAR(64) NOT NULL,
  target    VARCHAR(128),
  client_ip VARCHAR(45),
  detail    TEXT,
  INDEX idx_ts (ts),
  INDEX idx_action (action),
  INDEX idx_staff (staff_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- integrity
-- hash chain รายวันของไฟล์ log เพื่อพิสูจน์ว่าไม่ถูกแก้ไขย้อนหลัง
CREATE TABLE IF NOT EXISTS log_manifest (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  log_date   DATE NOT NULL,
  filename   VARCHAR(255) NOT NULL,
  sha256     CHAR(64) NOT NULL,
  prev_sha256 CHAR(64) NULL,
  size_bytes BIGINT NOT NULL,
  sealed_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deletion_state ENUM('active','pending','deleted') NOT NULL DEFAULT 'active',
  deleted_at DATETIME NULL,
  UNIQUE KEY uq_date_file (log_date, filename)
) ENGINE=InnoDB;
