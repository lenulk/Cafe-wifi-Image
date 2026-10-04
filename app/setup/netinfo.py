"""
setup/netinfo.py -- อ่านเครือข่ายปัจจุบัน (จาก DHCP ของเราเตอร์) เพื่อเสนอค่าใน wizard และตรวจค่าที่ช่างกรอก

ใช้ร่วมกันทั้ง wizard (ผู้ใช้ cafewifi) และ apply.py (root) -- apply ตรวจซ้ำทุกค่าเองเสมอ
ไม่เชื่อสิ่งที่ wizard เขียนมา เพราะไฟล์คำขออยู่ใน /run ที่ผู้ใช้ cafewifi เขียนได้
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from pathlib import Path

SYS_NET = Path("/sys/class/net")
NIC_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
# อักขระที่ install.sh ปฏิเสธ (ทำไฟล์ config พัง) -- ตรวจที่นี่ก่อนเพื่อบอกช่างได้ทันที
BAD_NAME_CHARS = set("'\"\\`$\n\r")
MIN_RETENTION_DAYS = 90       # พ.ร.บ.คอมพิวเตอร์ฯ ม.26
MAX_RETENTION_DAYS = 3650
DEFAULT_CLIENT_CIDR = "10.10.0.1/24"


def _ip_json(*args: str) -> list:
    out = subprocess.run(["ip", "-j", *args], capture_output=True, text=True, timeout=5, check=True).stdout
    return json.loads(out or "[]")


def current_uplink() -> dict:
    """{"nic", "ip", "prefix", "gw"} ของ default route ปัจจุบัน -- ว่าง {} ถ้ายังไม่ได้ IP"""
    try:
        routes = _ip_json("-4", "route", "show", "default")
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    for r in routes:
        dev, gw = r.get("dev"), r.get("gateway")
        if not dev or not gw:
            continue
        try:
            addrs = _ip_json("-4", "addr", "show", "dev", dev)
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
        for a in addrs:
            for info in a.get("addr_info", []):
                if info.get("family") == "inet" and info.get("local"):
                    return {"nic": dev, "ip": info["local"], "prefix": int(info.get("prefixlen", 24)), "gw": gw}
    return {}


def suggest(uplink: dict) -> dict:
    """ค่าที่เสนอในหน้า ③ -- IP ของ Pi = IP ที่ได้จาก DHCP อยู่ตอนนี้ (ปิด DHCP เราเตอร์แล้วไม่มีใครได้ซ้ำ
    และ wizard ยังเปิดที่อยู่เดิมได้ต่อหลังบันทึก) · วงลูกค้าเลี่ยงไปวงอื่นถ้าชนกับวงเราเตอร์"""
    s = {"nic": uplink.get("nic", "eth0"), "uplink_cidr": "", "uplink_gw": uplink.get("gw", ""),
         "client_cidr": DEFAULT_CLIENT_CIDR}
    if uplink.get("ip"):
        s["uplink_cidr"] = f"{uplink['ip']}/{uplink['prefix']}"
        up = ipaddress.ip_interface(s["uplink_cidr"]).network
        for cand in ("10.10.0.1/24", "10.20.0.1/24", "172.31.0.1/24", "192.168.250.1/24"):
            if not ipaddress.ip_interface(cand).network.overlaps(up):
                s["client_cidr"] = cand
                break
    return s


def validate(req: dict, check_nic_exists: bool = True) -> tuple[dict, list[str]]:
    """คืน (ค่าที่ทำให้เป็นรูปแบบมาตรฐานแล้ว, รายการข้อผิดพลาดภาษาไทย)"""
    errors: list[str] = []
    out: dict = {}

    nic = str(req.get("nic", "")).strip()
    if not NIC_RE.match(nic):
        errors.append("ชื่ออินเทอร์เฟซไม่ถูกต้อง")
    elif check_nic_exists and not (SYS_NET / nic).exists():
        errors.append(f"ไม่พบอินเทอร์เฟซ {nic} บนเครื่องนี้")
    out["nic"] = nic

    up = cl = gw = None
    try:
        up = ipaddress.IPv4Interface(str(req.get("uplink_cidr", "")).strip())
        if not (8 <= up.network.prefixlen <= 30) or up.ip in (up.network.network_address, up.network.broadcast_address):
            raise ValueError
        out["uplink_cidr"] = str(up)
    except ValueError:
        errors.append("IP ของ Pi ฝั่งเราเตอร์ต้องอยู่ในรูป 192.168.1.2/24")
    try:
        gw = ipaddress.IPv4Address(str(req.get("uplink_gw", "")).strip())
        out["uplink_gw"] = str(gw)
    except ValueError:
        errors.append("IP ของเราเตอร์ไม่ถูกต้อง")
    try:
        cl = ipaddress.IPv4Interface(str(req.get("client_cidr", "")).strip())
        # /24 เท่านั้น: dnsmasq ใน install.sh ใช้ netmask 255.255.255.0 ตายตัว
        if cl.network.prefixlen != 24 or not cl.ip.is_private \
                or cl.ip in (cl.network.network_address, cl.network.broadcast_address):
            raise ValueError
        out["client_cidr"] = str(cl)
    except ValueError:
        errors.append("วงลูกค้าต้องเป็น IP ภายในแบบ /24 เช่น 10.10.0.1/24")

    if up and gw:
        if gw not in up.network:
            errors.append(f"เราเตอร์ {gw} ไม่ได้อยู่ในวง {up.network}")
        elif gw == up.ip:
            errors.append("IP ของ Pi ซ้ำกับเราเตอร์")
    if up and cl and up.network.overlaps(cl.network):
        errors.append(f"วงลูกค้า {cl.network} ชนกับวงเราเตอร์ {up.network} -- ต้องเป็นคนละวง")

    name = str(req.get("gateway_name", "")).strip()
    if not name:
        name = "Cafe-Guest"
    if len(name) > 64 or any(c in BAD_NAME_CHARS for c in name):
        errors.append("ชื่อร้านยาวไม่เกิน 64 ตัว และห้ามมี ' \" \\ ` $")
    out["gateway_name"] = name

    try:
        days = int(str(req.get("retention_days", "180")).strip())
        if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
            raise ValueError
        out["retention_days"] = days
    except ValueError:
        errors.append(f"ระยะเวลาเก็บ log ต้องอยู่ระหว่าง {MIN_RETENTION_DAYS}-{MAX_RETENTION_DAYS} วัน "
                      "(กฎหมายกำหนดขั้นต่ำ 90 วัน)")
    return out, errors


def install_args(v: dict) -> list[str]:
    """อาร์กิวเมนต์ของ install.sh --stage site จากค่าที่ validate แล้วเท่านั้น"""
    iface = ipaddress.IPv4Interface(v["client_cidr"])
    base = iface.network.network_address
    # ช่วงแจก IP ลูกค้า .100-.250 ของวงที่เลือก (ค่าปริยายของ install.sh ผูกกับ 10.10.0.x)
    start, end = base + 100, base + 250
    if start <= iface.ip <= end:                   # Pi อยู่กลางช่วง -> ใช้ .10-.99 แทน
        start, end = base + 10, base + 99
    return ["--stage", "site", "--nic", v["nic"], "--uplink-cidr", v["uplink_cidr"],
            "--uplink-gw", v["uplink_gw"], "--client-cidr", v["client_cidr"],
            "--dhcp-range", f"{start},{end}",
            "--ssid", v["gateway_name"], "--retention-days", str(v["retention_days"])]
