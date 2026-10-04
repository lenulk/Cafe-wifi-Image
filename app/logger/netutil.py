"""logger/netutil.py — เครื่องมือช่วยเล็ก ๆ ที่ใช้ร่วมกันในตัวเก็บ log"""
from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path

log = logging.getLogger("cafe-wifi.netutil")

_ARP_LINE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+(?P<mac>[0-9a-fA-F:]{17})\s"
)


BURST_BATCH_SIZE = 16   # N40 -- ยิง ping ทีละกี่ตัวก่อนหยุดพัก
BURST_BATCH_GAP = 0.5   # N40 -- หยุดพักกี่วินาทีระหว่างชุด (254 ตัว ≈ 8 วินาที)


def _iter_arp_entries(arp_path: str | Path):
    """แกะทุกแถวใน /proc/net/arp เป็น (ip, mac) -- ข้ามแถวที่ mac เป็น 00:00:00:00:00:00
    (incomplete entry ที่เคอร์เนลยังไม่ resolve จริง) ใช้ร่วมกันทั้ง resolve_mac() (หา MAC
    ของ IP เดียว) และ read_arp_table() (N10, CODING_BRIEF.md -- เฝ้าทั้งวงให้ bypass_detector.py)"""
    try:
        text = Path(arp_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in text.splitlines()[1:]:  # บรรทัดแรกคือหัวตาราง
        m = _ARP_LINE.match(line)
        if not m:
            continue
        mac = m.group("mac").upper()
        if mac != "00:00:00:00:00:00":
            yield m.group("ip"), mac


def resolve_mac(ip: str, arp_path: str | Path = "/proc/net/arp") -> str | None:
    """
    หา MAC address จาก IP โดยอ่านตาราง ARP ของเคอร์เนล (/proc/net/arp)
    คืน None ถ้าหาไม่เจอ (เช่นอุปกรณ์เพิ่งหลุดออกจาก ARP cache) — เรียกใหญ่ในโค้ดต้องรับมือ None ได้
    """
    for entry_ip, mac in _iter_arp_entries(arp_path):
        if entry_ip == ip:
            return mac
    return None


def read_arp_table(arp_path: str | Path = "/proc/net/arp") -> dict[str, str]:
    """คืน {ip: mac} ของทุกแถวใน ARP table ปัจจุบัน -- ต่างจาก resolve_mac() ที่หาแค่ IP เดียว
    ตัวนี้อ่านทั้งวงในครั้งเดียว (N10, CODING_BRIEF.md -- bypass_detector.py ใช้เฝ้าวง uplink ทั้งวง
    หา IP/MAC แปลกปลอมที่ไม่ใช่ Pi/เราเตอร์) ถ้า IP เดียวกันมีหลายแถว (ไม่ควรเกิดจริงในทางปฏิบัติ)
    จะเหลือแค่แถวสุดท้ายที่อ่านเจอ"""
    return dict(_iter_arp_entries(arp_path))


def active_arp_refresh(network: str, timeout: float = 1.0,
                       batch_size: int = BURST_BATCH_SIZE,
                       batch_gap: float = BURST_BATCH_GAP) -> None:
    """
    *** เพิ่มหลังพบข้อจำกัดร้ายแรงของ T17 จาก VM lab (2026-08-28) ***

    ARP cache ของเคอร์เนล (/proc/net/arp) เก็บเฉพาะ IP ที่ **ตัว Pi เอง** เคยคุยด้วยโดยตรง
    เท่านั้น -- ถ้าอุปกรณ์ bypass คุยแต่กับเราเตอร์อย่างเดียว (ซึ่งเป็นพฤติกรรมปกติของการ
    bypass จริงตามที่ §3.1.4 อธิบายไว้ Pi ไม่ได้อยู่บนเส้นทางบังคับ) Pi จะ**ไม่มีทางเห็น
    ARP entry ของอุปกรณ์นั้นเลย** ต่อให้อุปกรณ์นั้นออนไลน์อยู่จริงและ bypass สำเร็จอยู่ก็ตาม
    ยืนยันจากการทดสอบจริงบน VM lab: จำลองอุปกรณ์ bypass ที่ ping ผ่านเราเตอร์ได้จริง แต่
    `/proc/net/arp` ของ Pi ไม่มีแถวของมันเลยแม้แต่แถวเดียว -- bypass_detector.py เดิม
    (อ่าน ARP cache แบบ passive ล้วน ๆ) จะ**ตรวจจับไม่ได้เลย**ในสถานการณ์แบบนี้ ซึ่งเป็น
    สถานการณ์หลักที่ T17 ควรจะตรวจจับได้ด้วยซ้ำ

    ฟังก์ชันนี้บังคับให้ Pi ยิง ARP request ไปหาทุก IP ในวงก่อนอ่าน ARP cache จริง (ping
    แบบขนานทุก host ในวง ใช้ ping เองเพราะมีติดมากับทุก distro อยู่แล้วไม่ต้องเพิ่ม
    package ใหม่ -- ไม่สนใจว่า ping จะได้รับ reply กลับมาไหม สนใจแค่ว่า ARP request/reply
    เกิดขึ้นแล้วเคอร์เนลบันทึกไว้ใน cache) ยิงเป็นชุด ๆ ขนานกัน ไม่ใช่ทีละตัวจนจบ เพราะรอบละ
    1 นาที (cafe-bypass-detect.timer) ไม่พอให้ยิงทีละตัวแบบรอผลได้ครบ /24 ทัน (ดู N40 ด้านล่าง
    ว่าทำไมถึงไม่ยิงพรวดเดียวทั้งวงด้วย)

    🔶 หมายเหตุการทดสอบบน VM lab (2026-08-28): ยืนยันว่า active scan บังคับให้เกิด ARP
    resolution กับอุปกรณ์ภายนอกจริงได้สำเร็จ (เจอ host adapter ของเครื่อง Windows และ
    อุปกรณ์อื่นบนวงเดียวกันที่ไม่เคยอยู่ใน ARP cache มาก่อนหน้านี้เลย) แต่**ทดสอบกับอุปกรณ์
    bypass ที่จำลองด้วย macvlan บนเครื่องเดียวกับ Pi เองไม่ได้จริง** เพราะ Linux macvlan
    (โหมด bridge) มีข้อจำกัดที่รู้กันอยู่แล้วว่า parent namespace คุยกับ macvlan child ของ
    ตัวเองโดยตรงไม่ได้ทั้งสองทิศทาง (ตรงกับที่ PROJECT_PLAN.md §3.1.6 เตือนไว้ล่วงหน้าแล้ว)
    — เป็นข้อจำกัดของ "วิธีจำลอง" ใน VM lab เท่านั้น ไม่ใช่ข้อจำกัดของโค้ดนี้หรือฮาร์ดแวร์จริง
    (Raspberry Pi ที่ต่อกับอุปกรณ์ bypass จริงแยกเครื่องกันทางกายภาพจะไม่เจอข้อจำกัดนี้เลย)
    **T17 เต็มรูปแบบ ("bypass 20 ครั้ง ตรวจจับได้กี่ %") ยังต้องรอทดสอบบน Pi จริงกับอุปกรณ์
    แยกเครื่องจริงถึงจะได้ตัวเลขที่เชื่อถือได้**

    N40: ของเดิมยิง ping ทั้งวง (254 ตัว) พร้อมกันในเสี้ยววินาทีเดียว ผลข้างเคียงที่ไม่ได้
    ตั้งใจคือ **เคอร์เนลสร้างรายการ conntrack 254 รายการพร้อมกัน แล้วหมดอายุพร้อมกันอีก 30
    วินาทีต่อมา** ทำให้เกิดชุดเหตุการณ์ 250-290 รายการในวินาทีเดียวทุก ๆ นาที ซึ่งวัดแล้วว่า
    ทำให้ตัวเก็บ log หลุด (ENOBUFS) และ **หลักฐานการใช้งานของลูกค้าหายจริง ~5%** ในช่วงนั้น
    (ดู N39) · แก้ด้วยการทยอยยิงเป็นชุดเล็ก ๆ ห่างกันเล็กน้อย -- ครอบคลุมทั้งวงเท่าเดิม
    ใช้เวลารวมไม่กี่วินาที (ยังจบก่อนรอบถัดไปที่ 60 วินาทีสบาย ๆ) แต่เหตุการณ์กระจายตัว
    แทนที่จะกระจุกเป็นชุดเดียว · ผลพลอยได้: ไม่ต้องสร้างโปรเซส 254 ตัวพร้อมกันบน Pi
    """
    import subprocess
    import time as _time

    net = ipaddress.ip_network(network, strict=False)
    procs = []
    batch = 0
    for host in net.hosts():
        try:
            p = subprocess.Popen(
                ["ping", "-c", "1", "-W", "1", str(host)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            procs.append(p)
        except OSError:
            log.warning("ยิง ping ไป %s ไม่สำเร็จ (ไม่มีคำสั่ง ping?) — ข้าม active ARP refresh", host)
            return
        batch += 1
        if batch_size > 0 and batch % batch_size == 0 and batch_gap > 0:
            _time.sleep(batch_gap)
    deadline = timeout + 1.0
    for p in procs:
        try:
            p.wait(timeout=max(0.05, deadline))
        except subprocess.TimeoutExpired:
            p.kill()


class MacCache:
    """แคช IP->MAC แบบง่าย กันอ่านไฟล์ /proc/net/arp ถี่เกินไปตอนมี event เยอะ ๆ"""

    def __init__(self, ttl_seconds: float = 5.0, arp_path: str | Path = "/proc/net/arp"):
        self.ttl = ttl_seconds
        self.arp_path = arp_path
        self._cache: dict[str, tuple[float, str | None]] = {}

    def get(self, ip: str, now: float | None = None) -> str | None:
        import time
        now = now if now is not None else time.time()
        hit = self._cache.get(ip)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        mac = resolve_mac(ip, self.arp_path)
        self._cache[ip] = (now, mac)
        return mac
