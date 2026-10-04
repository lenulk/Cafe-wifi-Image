"""
logger/bypass_detector.py — เฝ้าวง uplink หา IP/MAC แปลกปลอมที่ไม่ใช่ Pi/เราเตอร์ (N10, CODING_BRIEF.md)

ตอบโจทย์ T17 (ตรวจจับการ bypass) ตามที่ PROJECT_PLAN.md §3.1.4 ชั้นที่ 4 วิเคราะห์ไว้เองแล้วว่า
"ไม่ได้ป้องกัน แต่มีคุณค่าเชิงวิชาการสูง" — ก่อนหน้านี้มีแค่แผนจะ "ทดสอบ T17" ใน Task Board
โดยไม่มีไฟล์นี้อยู่จริงเลย (มีแผนจะทดสอบสิ่งที่ยังไม่มีใครสร้าง)

**ปัญหาที่ตรวจจับ (D19)**: โหมดสาย LAN เส้นเดียว (one-armed router) ทำให้ลูกค้าและเราเตอร์อยู่บน
L2 segment เดียวกัน — ถ้าใครตั้ง IP ตัวเองในวง uplink (`192.168.1.0/24` ตามค่า default) ตรง ๆ
จะคุยกับเราเตอร์ได้เลยโดยไม่ผ่าน Pi/openNDS เลย → ออกเน็ตได้โดยไม่ต้อง login และ**ไม่ถูกบันทึก
conn_log/dns_log เลย** (Pi ไม่ได้อยู่บนเส้นทางบังคับ ไม่ใช่ inline)

**ข้อจำกัดที่ตั้งใจไว้ (ต้องเขียนในเล่มรายงานด้วย ห้าม overclaim)**: นี่คือมาตรการ**ตรวจจับ**
ไม่ใช่**ป้องกัน** — อุปกรณ์ที่ bypass ไปแล้วจะยังออกเน็ตได้ปกติต่อไป สคริปต์นี้แค่ทิ้งร่องรอยไว้ให้
เจ้าหน้าที่/นักวิจัยเห็นว่าเกิดเหตุการณ์นี้ขึ้นกี่ครั้ง (ใช้เป็นตัวเลขวัดผลในบทที่ 4 ได้ เช่น
"ทดลอง bypass 20 ครั้ง ตรวจจับได้ 18 ครั้ง (90%)") การป้องกันจริงต้องพึ่ง Access Control ที่
เราเตอร์เป็นหลัก (ชั้นที่ 1-2 ใน §3.1.4) ไฟล์นี้เป็นแค่ชั้นที่ 4 (ชั้นสุดท้าย)

**บั๊กที่เจอบน Pi จริง (2026-09-16) — แก้แล้ว**: เดิม `run()` INSERT ทุกอุปกรณ์ที่เจอ *ทุกรอบ*
โดยไม่มีการกันซ้ำ พอเอาไปต่อวง uplink จริงที่มีอุปกรณ์อื่นอยู่ด้วย (แล็บมหาวิทยาลัย 9 เครื่อง)
กลายเป็น 9 แถวทุกนาที = 12,960 แถว/วัน ลงทั้ง `bypass_alert` และ `audit_log` ซึ่ง `audit_log`
เป็นหลักฐานตามกฎหมาย การถมด้วยแถวซ้ำทำให้หาเหตุการณ์จริงไม่เจอและตารางโตไม่มีที่สิ้นสุด
แก้ด้วย cooldown ต่อคู่ (ip, mac): ถ้าเพิ่งแจ้งเตือนไปภายใน `BYPASS_ALERT_COOLDOWN_MIN` นาที
(ค่าเริ่มต้น 60) จะไม่บันทึกซ้ำ แต่ยังคืนค่าใน `events` ตามเดิม — ยังนับ "ตรวจจับได้กี่ครั้ง"
ได้ครบ และยังเห็นว่าอุปกรณ์นั้นยังอยู่ต่อเนื่อง จากจำนวนแถวที่ห่างกันชั่วโมงละแถว

รันถี่ผ่าน `cafe-bypass-detect.timer` (ทุก 1 นาที ตั้งโดย install.sh) — ถี่กว่า cafe-enforce.timer
(5 นาที) เพราะ ARP cache ของเคอร์เนลหมดอายุเร็ว (โดยทั่วไป ~60-300 วินาทีขึ้นกับระบบ) การเช็คแบบ
สุ่มตัวอย่างเป็นช่วง ๆ (polling) แบบนี้**มีโอกาสพลาดอุปกรณ์ที่เชื่อมต่อสั้นมาก**ระหว่างรอบตรวจ —
เป็นข้อจำกัดของวิธีนี้ที่ต้องบันทึกไว้ตรง ๆ เช่นกัน ไม่ใช่การเฝ้าแบบ real-time

**ข้อจำกัดร้ายแรงที่พบจาก VM lab (2026-08-28) — แก้แล้ว**: เดิม `run()` อ่าน `/proc/net/arp`
แบบ passive ล้วน ๆ ซึ่งเก็บเฉพาะ IP ที่ **Pi เอง** เคยคุยด้วยตรง ๆ เท่านั้น — อุปกรณ์ bypass ที่
คุยแต่กับเราเตอร์อย่างเดียว (พฤติกรรมทั่วไปของการ bypass จริงตามที่ §3.1.4 อธิบาย) จะไม่มี
ARP entry ให้ Pi เห็นเลย ต่อให้ bypass สำเร็จอยู่จริงก็ตาม (ยืนยันจากการทดสอบจริง: จำลอง
อุปกรณ์ bypass ที่ ping ผ่านเราเตอร์ได้จริง แต่ ARP cache ของ Pi ไม่มีแถวนั้นเลย) แก้ด้วย
`netutil.active_arp_refresh()` — ยิง ping แบบขนานทุก host ในวงก่อนอ่าน ARP cache ทุกครั้ง
บังคับให้เคอร์เนลต้องทำ ARP resolution กับทุกอุปกรณ์ที่ออนไลน์อยู่จริงก่อนเสมอ
"""
from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass

log = logging.getLogger("cafe-wifi.bypass_detector")


@dataclass(frozen=True)
class BypassEvent:
    ip: str
    mac: str


def find_bypass_devices(arp_table: dict[str, str], uplink_network: str,
                        known_ips: set[str]) -> list[BypassEvent]:
    """
    ตรรกะล้วน ๆ แยกจาก I/O (ตามแบบ tools/check_disk.py::check_path) เพื่อทดสอบได้โดยไม่ต้อง
    มี /proc/net/arp จริง -- รับ arp_table ที่อ่านมาแล้ว ({ip: mac}) เทียบกับ known_ips
    (Pi เอง + เราเตอร์ -- ปกติคือ UPLINK_IP/UPLINK_GW) คืนอุปกรณ์ที่อยู่ในวง uplink แต่ไม่ใช่
    IP ที่รู้จัก เรียงตาม ip ให้ผลลัพธ์คงที่ (deterministic) ข้าม run
    """
    net = ipaddress.ip_network(uplink_network, strict=False)
    events: list[BypassEvent] = []
    for ip, mac in arp_table.items():
        if ip in known_ips:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr in net:
            events.append(BypassEvent(ip=ip, mac=mac))
    events.sort(key=lambda e: e.ip)
    return events


def run(uplink_network: str | None = None, known_ips: set[str] | None = None,
       arp_path: str = "/proc/net/arp", cooldown_minutes: int | None = None) -> list[BypassEvent]:
    """อ่าน ARP table จริง หา bypass แล้วบันทึกลงตาราง bypass_alert + audit_log ทุกรายการที่เจอ
    (ตามแบบ tools/check_disk.py::run() ที่ loop เขียน audit ทีละรายการต่อความผิดปกติ 1 ครั้ง)"""
    from common import audit
    from common.db import execute as db_execute
    from common.db import query_one as db_query_one
    from logger.netutil import active_arp_refresh, read_arp_table

    uplink_network = uplink_network or os.environ.get("UPLINK_NETWORK", "")
    if not uplink_network:
        raise RuntimeError(
            "UPLINK_NETWORK ไม่ได้ตั้งค่า -- ต้องรัน install.sh ให้เขียน secrets.env ก่อน "
            "หรือระบุพารามิเตอร์ uplink_network เอง"
        )
    if cooldown_minutes is None:
        cooldown_minutes = int(os.environ.get("BYPASS_ALERT_COOLDOWN_MIN", "60"))
    if known_ips is None:
        known_ips = {ip for ip in (os.environ.get("UPLINK_IP"), os.environ.get("UPLINK_GW")) if ip}

    # *** สำคัญ (แก้ข้อจำกัดที่พบจาก VM lab 2026-08-28) *** — ต้อง active-scan ก่อนอ่าน ARP
    # cache เสมอ ไม่งั้นจะพลาดอุปกรณ์ bypass ที่คุยแต่กับเราเตอร์อย่างเดียว (Pi ไม่เคยคุยด้วย
    # โดยตรงเลย เคอร์เนลเลยไม่มี ARP entry ให้อ่าน) ดู docstring ของ active_arp_refresh()
    active_arp_refresh(uplink_network)
    arp_table = read_arp_table(arp_path)
    events = find_bypass_devices(arp_table, uplink_network, known_ips)

    for ev in events:
        if cooldown_minutes > 0 and db_query_one(
            "SELECT id FROM bypass_alert WHERE ip=%s AND mac=%s "
            "AND detected_at > (NOW() - INTERVAL %s MINUTE) LIMIT 1",
            (ev.ip, ev.mac, cooldown_minutes),
        ):
            # เจออุปกรณ์เดิมที่ยังอยู่ — แจ้งเตือนไปแล้วในรอบ cooldown ไม่บันทึกซ้ำ
            log.info("อุปกรณ์แปลกปลอมเดิมยังอยู่ (อยู่ในช่วง cooldown %d นาที): ip=%s mac=%s",
                    cooldown_minutes, ev.ip, ev.mac)
            continue
        db_execute("INSERT INTO bypass_alert (ip, mac) VALUES (%s, %s)", (ev.ip, ev.mac))
        audit.log(audit.BYPASS_DETECTED, target=ev.ip,
                 detail=f"mac={ev.mac} network={uplink_network}")
        log.warning("ตรวจพบอุปกรณ์แปลกปลอมในวง uplink (bypass ที่เป็นไปได้): ip=%s mac=%s",
                   ev.ip, ev.mac)

    return events


def main() -> int:  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    events = run()
    if events:
        log.warning("พบอุปกรณ์แปลกปลอม %d รายการในรอบนี้", len(events))
    return 0  # ตรวจจับได้/ไม่ได้ไม่ใช่ error ของสคริปต์เอง -- ให้ exit 0 เสมอถ้ารันจบปกติ


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
