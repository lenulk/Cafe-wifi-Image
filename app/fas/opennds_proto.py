"""
fas/opennds_proto.py — โปรโตคอลคุยกับ openNDS ที่ fas_secure_enabled = 2 (D1)

อ้างอิงจาก reference implementation ทางการของ openNDS
(forward_authentication_service/fas-aes/fas-aes.php) ในรีโป openNDS/openNDS:

  * openNDS ส่ง GET มาที่ FasPath พร้อม query string `?fas=<base64>&iv=<16 ตัวอักษร>`
  * ถอดรหัสด้วย AES-256-CBC:
        key = ascii-bytes ของ faskey ตัด/เติมให้เหลือ 32 ไบต์พอดี
        iv  = ascii-bytes ของพารามิเตอร์ iv โดยตรง (ต้องยาว 16 ไบต์พอดี ไม่ decode ใด ๆ)
        payload = base64_decode(fas)  -> AES-256-CBC decrypt (PKCS7 padding)
  * ข้อความที่ถอดได้เป็นสตริง "key=value, key=value, ..." คั่นด้วย ", "
    ประกอบด้วยอย่างน้อย: clientip, clientmac, gatewayname, client_hid (hid),
    gatewayaddress, authdir, originurl, clientif
  * เมื่อยืนยันตัวตนผ่านแล้ว ต้องพา browser ของลูกค้า (ไม่ใช่ HTTP request จาก server)
    ไปที่ virtual URL ของ openNDS:
        http://<gatewayaddress>/<authdir>/?tok=<sha256(hid+faskey)>&redir=<originurl>
    เพื่อให้ openNDS อนุญาต MAC นั้นผ่าน nftables

หมายเหตุความซื่อสัตย์ทางวิศวกรรม: ✅ ทดสอบกับ openNDS 10.1.3 binary จริงแล้วบน VM lab
(2026-08-28) — login ผ่านครบวงจรจริง (decrypt → form → auth token → "state":"Authenticated")
ระหว่างทางพบว่า reference PHP ของ openNDS เข้ารหัส 2 ชั้น (`base64_encode(openssl_encrypt(
...,0,$iv))` — options=0 ทำให้ openssl_encrypt เองก็ base64-encode มาให้แล้วในตัว) ไม่ใช่
ชั้นเดียวอย่างที่โค้ดนี้เข้าใจตอนแรก แก้แล้ว (ดู decrypt_fas_payload()/encrypt_fas_payload()
และ tests/test_opennds_proto.py::test_decrypt_real_capture_from_live_opennds ที่ใช้
payload จริงเป็น fixture) 🔶 ยังไม่เคยทดสอบบน Raspberry Pi จริง (แค่ VM) และยังไม่เคย
ทดสอบกรณี login ผิด/หมดอายุ/ถูกระงับกับ openNDS จริง — ต้องยืนยันใน Phase 2 บนฮาร์ดแวร์จริง
ก่อนเชื่อว่าคุยกันได้ 100% ในทุกกรณี (ดู PROJECT_PLAN.md §17)
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, fields
from urllib.parse import quote, unquote

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY_LEN = 32   # AES-256
AES_IV_LEN = 16    # ขนาดบล็อกของ AES


class FasProtocolError(ValueError):
    """payload จาก openNDS ผิดรูปแบบ, ถอดรหัสไม่ได้, หรือ key/iv ไม่ถูกต้อง"""


def _derive_key(faskey: str) -> bytes:
    raw = faskey.encode("utf-8")
    if len(raw) < AES_KEY_LEN:
        raise FasProtocolError(
            f"faskey สั้นเกินไป: ต้องอย่างน้อย {AES_KEY_LEN} ไบต์ (ได้ {len(raw)}) "
            "— install.sh สร้างด้วย `openssl rand -hex 16` (=32 ไบต์) ให้แล้ว ตรวจ secrets.env"
        )
    return raw[:AES_KEY_LEN]


def _coerce_iv(iv: str) -> bytes:
    raw = iv.encode("utf-8")
    if len(raw) != AES_IV_LEN:
        raise FasProtocolError(f"iv ต้องยาว {AES_IV_LEN} ไบต์พอดี (ได้ {len(raw)})")
    return raw


@dataclass(frozen=True)
class ClientContext:
    """ค่าที่ openNDS ส่งมาให้ FAS ระบุตัวลูกค้าและ session ปัจจุบัน"""
    clientip: str = ""
    clientmac: str = ""
    gatewayname: str = ""
    hid: str = ""              # เดิมชื่อ client_hid ในโปรโตคอล
    gatewayaddress: str = ""
    authdir: str = ""
    originurl: str = ""
    clientif: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "ClientContext":
        d = dict(d)
        if "client_hid" in d and "hid" not in d:
            d["hid"] = d.pop("client_hid")
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})

    def is_complete(self) -> bool:
        return bool(self.clientmac and self.hid and self.gatewayaddress and self.authdir)


def parse_kv_string(decrypted: str) -> dict:
    """'clientip=1.2.3.4, clientmac=aa:bb:.. ' -> dict — ทนช่องว่างเกิน/ค่าว่าง"""
    result: dict[str, str] = {}
    for part in decrypted.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        result[k.strip()] = v.strip()
    return result


def build_kv_string(params: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in params.items())


def decrypt_fas_payload(fas_b64: str, iv: str, faskey: str) -> ClientContext:
    """ถอดรหัส query string `fas`+`iv` ที่ openNDS ส่งมา -> ClientContext"""
    if not fas_b64 or not iv:
        raise FasProtocolError("ขาดพารามิเตอร์ fas หรือ iv")
    key_bytes = _derive_key(faskey)
    iv_bytes = _coerce_iv(iv)
    # *** พบจากทดสอบกับ openNDS binary จริงบน VM lab (2026-08-28) — เข้ารหัส 2 ชั้นจริง ***
    # reference PHP ของ openNDS (src/http_microhttpd.c) เรียก
    #   base64_encode( openssl_encrypt($string, $cipher, $key, 0, $iv) )
    # ตัวเลข "0" คือ $options ที่ไม่ได้ตั้ง OPENSSL_RAW_DATA — PHP เอกสารระบุชัดว่าถ้าไม่ตั้ง
    # flag นี้ ผลลัพธ์จาก openssl_encrypt() จะถูก base64 encode มาให้เองอยู่แล้วในตัว แล้วโค้ด
    # ยัง base64_encode() ครอบซ้ำอีกชั้นด้านนอก -- แปลว่าพารามิเตอร์ `fas` ที่ได้จริงคือ
    # base64(base64(ciphertext)) ไม่ใช่ base64(ciphertext) ชั้นเดียวอย่างที่โค้ดเดิมคิด
    # (เทสต์เดิมผ่านเพราะ encrypt_fas_payload() ของเราเองก็ encode ชั้นเดียวเหมือนกัน เลย
    # round-trip กับตัวเองได้ปกติ แต่ไม่ตรงกับ openNDS จริงเลย — ยืนยันด้วยการจับ query string
    # จริงจาก openNDS แล้วลองถอดตรงๆ เจอ "Invalid padding bytes" ทุกครั้งจนกว่าจะ decode 2 รอบ)
    try:
        outer = base64.b64decode(fas_b64, validate=True)
        ciphertext = base64.b64decode(outer, validate=True)
    except Exception:
        # เผื่อ proxy/ตัวส่งบางตัวแปลง '+' เป็นช่องว่างตอน urlencode ไม่ครบ (พบได้จริงกับ
        # query string ที่ไม่ผ่าน percent-encoding อย่างเคร่งครัด) — ลองกู้คืนก่อนยอมแพ้
        try:
            outer = base64.b64decode(fas_b64.replace(" ", "+"), validate=True)
            ciphertext = base64.b64decode(outer, validate=True)
        except Exception as exc:
            raise FasProtocolError(f"base64 ของ fas ผิดรูปแบบ: {exc}") from exc

    try:
        decryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
    except Exception as exc:
        raise FasProtocolError(f"ถอดรหัส AES-256-CBC ไม่สำเร็จ (faskey/iv ไม่ตรง?): {exc}") from exc

    return ClientContext.from_dict(parse_kv_string(plain.decode("utf-8", errors="replace")))


def encrypt_fas_payload(params: dict, faskey: str, iv: bytes | None = None) -> tuple[str, str]:
    """
    เข้ารหัสแบบเดียวกับที่ openNDS gateway ทำ — ใช้สำหรับ:
      1) เขียนชุดทดสอบ (จำลอง gateway ส่ง request มาที่ FAS ของเรา)
      2) เครื่องมือ debug บนเครื่องจริงตอน Phase 2
    คืนค่า (fas_b64, iv_str) พร้อมใส่ใน query string ได้ทันที
    """
    import secrets
    import string

    key_bytes = _derive_key(faskey)
    if iv is None:
        alphabet = string.ascii_letters + string.digits
        iv = "".join(secrets.choice(alphabet) for _ in range(AES_IV_LEN)).encode("ascii")
    if len(iv) != AES_IV_LEN:
        raise FasProtocolError(f"iv ต้องยาว {AES_IV_LEN} ไบต์พอดี")

    plain = build_kv_string(params).encode("utf-8")
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    # encode 2 ชั้นให้ตรงกับ openNDS จริง — ดูเหตุผลเต็มที่ decrypt_fas_payload() ด้านบน
    outer = base64.b64encode(ciphertext)
    double = base64.b64encode(outer)
    return double.decode("ascii"), iv.decode("ascii")


def auth_token(hid: str, faskey: str) -> str:
    """tok = sha256(hid + faskey) ตาม reference implementation ของ openNDS"""
    return hashlib.sha256((hid + faskey).encode("utf-8")).hexdigest()


def build_auth_action_url(ctx: ClientContext, faskey: str, redir: str | None = None) -> str:
    """
    URL ที่ต้องพา browser ของลูกค้า (ไม่ใช่ server-to-server) ไปเปิด
    เพื่อให้ openNDS สั่ง nftables อนุญาต MAC นี้
    """
    if not ctx.is_complete():
        raise FasProtocolError("ClientContext ไม่ครบ (ต้องมี clientmac, hid, gatewayaddress, authdir)")
    tok = auth_token(ctx.hid, faskey)
    # *** บั๊ก double-encoding (พบจากทดสอบ login จริงบน Pi จริง 2026-09-16) ***
    # openNDS ส่ง originurl มาใน payload แบบ percent-encoded อยู่แล้ว (uh_urlencode ใน
    # src/ ใช้ตัวพิมพ์เล็ก เช่น "http%3a%2f%2fneverssl.com%2f") -- เดิมเราเอามา quote() ซ้ำ
    # อีกชั้นกลายเป็น %253a%252f%252f พอ openNDS (MHD) ถอด query กลับ 1 ชั้นจึงเหลือ
    # "http%3a%2f%2f..." ซึ่งยังไม่ใช่ URL ที่ใช้ได้ (ไม่มี ://) แล้วมันเอาไปใส่ Location:
    # ตรง ๆ (authenticate_client() -> send_redirect_temp()) -- เบราว์เซอร์จึงตีความเป็น
    # path สัมพัทธ์ ต่อท้าย /opennds_auth/ กลายเป็น 404 ให้ลูกค้าเห็นทุกครั้งหลัง login สำเร็จ
    # (auth ผ่านจริงเบื้องหลัง แต่ผู้ใช้เห็นหน้า error) -- ต้อง unquote ก่อนเสมอ
    # unquote() ปลอดภัยกับ URL ที่ยังไม่ได้เข้ารหัสอยู่แล้ว (ไม่เปลี่ยนค่า)
    target = unquote(redir or ctx.originurl or "")
    authdir = ctx.authdir.strip("/")
    url = f"http://{ctx.gatewayaddress}/{authdir}/?tok={tok}"
    if target:
        url += f"&redir={quote(target, safe='')}"
    return url
