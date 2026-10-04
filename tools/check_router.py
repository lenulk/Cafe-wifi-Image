#!/usr/bin/env python3
"""
check_router.py -- ตรวจว่าเราเตอร์ร้านปิด DHCP และ IPv6 ฝั่ง LAN แล้วจริงก่อนเปิด portal (M5, IMG-06/07)

ถ้าเราเตอร์ยังจ่าย DHCP: ลูกค้าได้ IP จากเราเตอร์แล้วออกเน็ตตรง ข้าม portal (ไม่มี log ตาม ม.26)
ถ้ายังประกาศ IPv6 (Router Advertisement): มือถือออกเน็ตทาง IPv6 ข้าม portal ทั้งหมด

  python3 check_router.py --iface eth0 [--dhcp-timeout 20] [--ra-timeout 10] [--json]

ใช้ AF_PACKET (raw) ทั้งสองอย่าง -- ต้องมี CAP_NET_RAW (root หรือ AmbientCapabilities ใน systemd)
ไม่ใช้ UDP port 68: NetworkManager/dhclient อาจถือพอร์ตนั้นอยู่ และ raw socket ส่งได้แม้ยังไม่มี IP
stdlib ล้วน (ไม่พึ่ง scapy) เพราะ image ต้องติดตั้งหน้างานได้โดยไม่ออก PyPI

DHCP: ส่ง DHCPDISCOVER (broadcast) ด้วย MAC สุ่มแบบ locally-administered -- ไม่ใช่ MAC ของ Pi เอง
จะได้ไม่ไปรบกวน lease ของ Pi กับเราเตอร์ · OFFER ที่ตอบกลับมาด้วย xid ตรงกัน = มี DHCP server อยู่
(เราเตอร์ หรือ AP ที่ตั้งเป็นโหมด router ก็นับ) · ไม่มีคำตอบภายในเวลา = ผ่าน
IPv6: ส่ง Router Solicitation 1 ครั้งแล้วฟัง RA (ICMPv6 type 134) ที่ lifetime > 0 หรือมี prefix
"""
from __future__ import annotations

import argparse
import json
import os
import select
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
BROADCAST = b"\xff" * 6


# ------------------------------------------------------------------ checksums / builders
def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def random_mac() -> bytes:
    b = bytearray(os.urandom(6))
    b[0] = (b[0] & 0xFC) | 0x02          # locally administered, unicast
    return bytes(b)


def build_dhcp_discover(mac: bytes, xid: int) -> bytes:
    """Ethernet + IPv4 + UDP + BOOTP/DHCPDISCOVER (broadcast flag) จาก 0.0.0.0:68 -> 255.255.255.255:67"""
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s",
                        1, 1, 6, 0, xid, 0, 0x8000,
                        b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                        mac + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    options = (b"\x63\x82\x53\x63"                 # magic cookie
               + b"\x35\x01\x01"                   # 53: DHCPDISCOVER
               + b"\x3d\x07\x01" + mac             # 61: client-id (ether) -- แบบเดียวกับ udhcpc/Android
               + b"\x37\x03\x01\x03\x06"           # 55: subnet, router, dns
               + b"\x0c\x0ecafewifi-probe"         # 12: hostname (เห็นใน log เราเตอร์ว่าเป็นตัวทดสอบ)
               + b"\xff")
    payload = bootp + options
    # RFC 1542: ข้อความ BOOTP ต้องยาวอย่างน้อย 300 ไบต์ -- เราเตอร์แล็บ (172.20.18.1) ทิ้งของเรา (265 ไบต์)
    # เงียบ ๆ แล้วตัวตรวจรายงานว่า "DHCP ปิดแล้ว" ทั้งที่ยังเปิด (เจอจริง 2026-10-04 เทียบกับ udhcpc ที่ได้ OFFER)
    if len(payload) < 300:
        payload += b"\0" * (300 - len(payload))
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", 68, 67, udp_len, 0) + payload   # checksum 0 = ไม่ตรวจ (ถูกต้องตาม IPv4)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 0, 0, 64, 17, 0,
                         b"\0" * 4, b"\xff" * 4)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _csum(ip_hdr)) + ip_hdr[12:]
    eth = BROADCAST + mac + struct.pack("!H", ETH_P_IP)
    return eth + ip_hdr + udp


def parse_dhcp_reply(frame: bytes, xid: int) -> dict | None:
    """คืน dict ถ้าเป็น DHCPOFFER/ACK ที่ตอบ xid ของเรา (ไม่สนว่าส่งถึง MAC ไหน)"""
    if len(frame) < 14 + 20 + 8 + 240 or frame[12:14] != struct.pack("!H", ETH_P_IP):
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17:
        return None
    udp = ip[ihl:]
    sport, dport = struct.unpack("!HH", udp[:4])
    if sport != 67 or dport != 68:
        return None
    bootp = udp[8:]
    if len(bootp) < 240 or bootp[0] != 2 or struct.unpack("!I", bootp[4:8])[0] != xid:
        return None
    if bootp[236:240] != b"\x63\x82\x53\x63":
        return None
    opts = bootp[240:]
    i, msg_type, server_id = 0, None, None
    while i < len(opts) and opts[i] != 0xFF:
        if opts[i] == 0:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        code, ln = opts[i], opts[i + 1]
        val = opts[i + 2:i + 2 + ln]
        if code == 53 and ln == 1:
            msg_type = val[0]
        elif code == 54 and ln == 4:
            server_id = socket.inet_ntoa(val)
        i += 2 + ln
    if msg_type not in (2, 5):      # OFFER, ACK
        return None
    return {
        "server_ip": server_id or socket.inet_ntoa(ip[12:16]),
        "server_mac": frame[6:12].hex(":"),
        "offered_ip": socket.inet_ntoa(bootp[16:20]),
    }


def build_router_solicit(src_mac: bytes) -> bytes:
    """ICMPv6 Router Solicitation จาก :: ไป ff02::2 (ไม่ต้องมี IPv6 address ของตัวเอง)"""
    src = b"\0" * 16
    dst = socket.inet_pton(socket.AF_INET6, "ff02::2")
    icmp = struct.pack("!BBHI", 133, 0, 0, 0)            # ไม่ใส่ SLLA option เพราะ src = ::
    pseudo = src + dst + struct.pack("!I3xB", len(icmp), 58)
    icmp = icmp[:2] + struct.pack("!H", _csum(pseudo + icmp)) + icmp[4:]
    ip6 = struct.pack("!IHBB", 0x60000000, len(icmp), 58, 255) + src + dst
    eth = b"\x33\x33\x00\x00\x00\x02" + src_mac + struct.pack("!H", ETH_P_IPV6)
    return eth + ip6 + icmp


def parse_ra(frame: bytes) -> dict | None:
    """คืน dict ถ้าเป็น Router Advertisement ที่ทำให้มือถือใช้ IPv6 ได้จริง"""
    if len(frame) < 14 + 40 + 16 or frame[12:14] != struct.pack("!H", ETH_P_IPV6):
        return None
    ip6 = frame[14:]
    if ip6[6] != 58:                                     # next header ICMPv6 (ไม่ตาม ext header)
        return None
    icmp = ip6[40:]
    if icmp[0] != 134:
        return None
    lifetime = struct.unpack("!H", icmp[6:8])[0]
    prefixes = []
    opts, i = icmp[16:], 0
    while i + 2 <= len(opts):
        otype, olen = opts[i], opts[i + 1] * 8
        if olen == 0:
            break
        if otype == 3 and olen >= 32:                    # Prefix Information
            plen = opts[i + 2]
            flags = opts[i + 3]
            valid = struct.unpack("!I", opts[i + 4:i + 8])[0]
            prefix = socket.inet_ntop(socket.AF_INET6, opts[i + 16:i + 32])
            if valid > 0 and flags & 0x40:               # A flag = SLAAC ใช้ได้
                prefixes.append(f"{prefix}/{plen}")
        i += olen
    managed = bool(icmp[5] & 0x80)                       # M flag = DHCPv6 แจก address
    if lifetime == 0 and not prefixes and not managed:
        return None                                      # RA ที่ไม่ทำให้ใครออก IPv6 ได้ (เช่นตอนเพิ่งปิด)
    return {
        "router_ip": socket.inet_ntop(socket.AF_INET6, ip6[8:24]),
        "router_mac": frame[6:12].hex(":"),
        "router_lifetime": lifetime,
        "prefixes": prefixes,
        "dhcpv6_managed": managed,
    }


# ------------------------------------------------------------------ probes
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


def _open(iface: str, proto: int, promisc: bool = False) -> socket.socket:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
    s.bind((iface, 0))
    if promisc:
        # เราเตอร์ส่วนใหญ่ไม่สน broadcast flag แล้วตอบ OFFER แบบ unicast ไปที่ MAC สุ่มของ probe --
        # การ์ดแลนทิ้งเฟรมที่ไม่ใช่ MAC ของตัวเองตั้งแต่ฮาร์ดแวร์ ถ้าไม่เปิด promiscuous จะไม่เห็นคำตอบเลย
        # แล้วรายงานว่า "DHCP ปิดแล้ว" ทั้งที่ยังเปิด (เจอจริงกับเราเตอร์แล็บ 2026-10-04) -- membership นี้
        # หายเองเมื่อปิด socket ไม่ค้าง promisc ไว้กับอินเทอร์เฟซ
        mreq = struct.pack("iHH8s", socket.if_nametoindex(iface), PACKET_MR_PROMISC, 0, b"")
        s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
    return s


def _iface_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address", encoding="ascii") as f:
        return bytes.fromhex(f.read().strip().replace(":", ""))


def _listen(sock: socket.socket, timeout: float, parse) -> list[dict]:
    found: dict[str, dict] = {}
    deadline = time.monotonic() + timeout
    while (left := deadline - time.monotonic()) > 0:
        r, _, _ = select.select([sock], [], [], left)
        if not r:
            break
        frame = sock.recv(65535)
        hit = parse(frame)
        if hit:
            found.setdefault(next(iter(hit.values())), hit)
    return list(found.values())


def _local_macs() -> set[str]:
    """MAC ของทุกอินเทอร์เฟซในเครื่อง -- dnsmasq ของ Pi เอง (macvlan ฝั่งลูกค้า) ไม่ใช่ DHCP ของเราเตอร์"""
    macs = set()
    try:
        for name in os.listdir("/sys/class/net"):
            try:
                with open(f"/sys/class/net/{name}/address", encoding="ascii") as f:
                    macs.add(f.read().strip().lower())
            except OSError:
                pass
    except OSError:
        pass
    return macs


def probe_dhcp(iface: str, timeout: float = 20.0, tries: int = 7) -> list[dict]:
    """[] = ไม่มี DHCP server ตอบ (ผ่าน)

    ทำตัวเหมือน client จริง: MAC + xid เดียว ส่งซ้ำ tries ครั้งห่างกัน timeout/tries แต่**ฟังต่อเนื่อง
    ตลอด timeout** -- เราเตอร์แล็บตอบ OFFER ช้า ~2 วิ และบางครั้งช้ากว่านั้นมาก (ตรวจ IP ว่างก่อน OFFER)
    แบบเดิมที่รอรอบละ 2 วิแล้วเปลี่ยน xid ทิ้งคำตอบที่มาช้า -> พลาด 1 ใน 3 ครั้ง (เจอจริง 2026-10-04)
    หลังเงียบไปนาน ๆ เราเตอร์แล็บไม่ตอบ DISCOVER 3 ครั้งแรกเลย ตอบครั้งที่ 4 ที่ ~12.2 วิ (วัด 3/3 ครั้งหลังว่าง 70 วิ)
    -> กรอบ 12 วิ/ส่ง 3 ครั้งพลาดรอบแรกทุกครั้ง · จึงฟัง 20 วิ ส่งซ้ำทุก ~3 วิ (เจอแล้วหยุดทันที)
    """
    sock = _open(iface, ETH_P_IP, promisc=True)
    mine = _local_macs()
    mac, xid = random_mac(), struct.unpack("!I", os.urandom(4))[0]
    frame = build_dhcp_discover(mac, xid)
    found: dict[str, dict] = {}
    try:
        start = time.monotonic()
        interval = timeout / max(tries, 1)
        next_send, sent = start, 0
        while (now := time.monotonic()) - start < timeout:
            if sent < tries and now >= next_send:
                sock.send(frame)
                sent += 1
                next_send += interval
            wait = min(next_send if sent < tries else start + timeout, start + timeout) - now
            r, _, _ = select.select([sock], [], [], max(wait, 0.05))
            if not r:
                continue
            hit = parse_dhcp_reply(sock.recv(65535), xid)
            if hit and hit["server_mac"] not in mine:
                found.setdefault(hit["server_ip"], hit)
                break                          # เจอหนึ่งตัวก็พอสรุปได้ว่ายังเปิดอยู่
        return list(found.values())
    finally:
        sock.close()


def probe_ipv6_ra(iface: str, timeout: float = 10.0) -> list[dict]:
    """[] = ไม่มีเราเตอร์ประกาศ IPv6 (ผ่าน)"""
    sock = _open(iface, ETH_P_IPV6)
    try:
        sock.send(build_router_solicit(_iface_mac(iface)))
        return _listen(sock, timeout, parse_ra)
    finally:
        sock.close()


def check(iface: str, dhcp_timeout: float = 20.0, ra_timeout: float = 10.0) -> dict:
    result: dict = {"iface": iface, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    try:
        offers = probe_dhcp(iface, dhcp_timeout)
        result["dhcp"] = {"ok": not offers, "servers": offers}
    except OSError as e:
        result["dhcp"] = {"ok": False, "error": str(e), "servers": []}
    try:
        ras = probe_ipv6_ra(iface, ra_timeout)
        result["ipv6"] = {"ok": not ras, "routers": ras}
    except OSError as e:
        result["ipv6"] = {"ok": False, "error": str(e), "routers": []}
    result["ok"] = result["dhcp"]["ok"] and result["ipv6"]["ok"]
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--dhcp-timeout", type=float, default=20.0)
    ap.add_argument("--ra-timeout", type=float, default=10.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = check(a.iface, a.dhcp_timeout, a.ra_timeout)
    if a.json:
        print(json.dumps(r, ensure_ascii=False))
    else:
        d, v = r["dhcp"], r["ipv6"]
        print(("✅" if d["ok"] else "❌") + " DHCP ของเราเตอร์ " + ("ปิดแล้ว" if d["ok"] else
              "ยังเปิดอยู่: " + (d.get("error") or ", ".join(s["server_ip"] for s in d["servers"]))))
        print(("✅" if v["ok"] else "❌") + " IPv6 ฝั่ง LAN " + ("ปิดแล้ว" if v["ok"] else
              "ยังเปิดอยู่: " + (v.get("error") or ", ".join(x["router_ip"] for x in v["routers"]))))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
