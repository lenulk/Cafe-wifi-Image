"""
logger/run_all.py — entrypoint ของ cafe-logger.service (ตั้งค่าโดย install.sh)
รัน conn_collector และ dns_collector พร้อมกันเป็น thread, จับ SIGTERM ให้ปิดตัวนุ่มนวล

หมายเหตุ: ฟังก์ชันในไฟล์นี้เป็น "ตัวประกอบร่าง" ของสิ่งที่ทดสอบแยกไว้แล้วใน
conn_collector.py / dns_collector.py — ตัวไฟล์นี้เองไม่มี unit test เพราะต้องพึ่ง
conntrack binary + สิทธิ์ root + ไฟล์ log จริงบนเครื่อง (ทดสอบได้เฉพาะ Phase 4 บนฮาร์ดแวร์จริง)
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time

from . import conn_collector, dns_collector

log = logging.getLogger("cafe-wifi.logger")
_stop = threading.Event()
# R2-06: เวลาที่รอให้ collector flush ของที่ค้างก่อนออก -- ต้องน้อยกว่า TimeoutStopSec (90 วิ)
STOP_TIMEOUT = 20.0


def _handle_signal(signum, frame):  # noqa: ARG001
    log.info("ได้รับสัญญาณ %s — กำลังปิด log collector", signum)
    _stop.set()


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    log_dir = os.environ.get("LOG_DIR", "/var/log/cafe-wifi")
    dnsmasq_log = os.path.join(log_dir, "dnsmasq.log")

    # R2-06: ส่ง _stop เข้าไปให้ collector ออกจากลูปแล้ว flush เอง ยังเป็น daemon ไว้กันกรณีที่
    # ค้างจนเกิน STOP_TIMEOUT (ปล่อยให้ interpreter ปิดได้) แต่ต้อง join ก่อน main() return เสมอ
    threads = [
        threading.Thread(target=conn_collector.run_forever, kwargs=dict(stop_event=_stop),
                         name="conn_collector", daemon=True),
        threading.Thread(target=dns_collector.run_forever, args=(dnsmasq_log,),
                         kwargs=dict(stop_event=_stop), name="dns_collector", daemon=True),
    ]
    for t in threads:
        t.start()
        log.info("เริ่ม thread %s", t.name)

    status = 0
    while not _stop.wait(1):
        dead = [t for t in threads if not t.is_alive()]
        if dead:
            log.error("collector %s หยุดทำงาน", dead[0].name)
            status = 1
            _stop.set()  # ให้ตัวที่ยังรันอยู่ flush ก่อนออก systemd จะรีสตาร์ทให้
    for t in threads:
        t.join(timeout=STOP_TIMEOUT)
        if t.is_alive():
            log.error("log_gap: collector %s ไม่ยอมหยุดภายใน %.0f วินาที — ของที่ค้างอาจหาย",
                      t.name, STOP_TIMEOUT)
            status = 1
    if status == 0:
        log.info("ปิด cafe-logger เรียบร้อย")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
