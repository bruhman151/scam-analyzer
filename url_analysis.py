"""Static URL features: never fetch links, resolve DNS or claim reputation."""
import ipaddress
import re
from urllib.parse import urlsplit

URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'\u200b]+""", re.I)
SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "t.co", "shorturl.at", "is.gd", "cutt.ly"})

def parse_url(value: str):
    value = value.strip().rstrip(".,;!?)}")
    if not value or len(value) > 2048 or re.search(r"[\s\x00-\x1f\\]", value):
        raise ValueError("URL ต้องไม่มีช่องว่างและยาวไม่เกิน 2,048 ตัวอักษร")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        host, port = parts.hostname, parts.port
        if parts.scheme not in {"https", "http"} or not host:
            raise ValueError
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                raise ValueError
        return parts, host, port
    except (ValueError, UnicodeError):
        raise ValueError("รูปแบบ URL ไม่ถูกต้อง รองรับ http และ https") from None

def inspect_url(value: str) -> dict:
    parts, host, port = parse_url(value)
    findings = []
    def add(key, weight, reason):
        findings.append({"id": key, "weight": weight, "reason": reason,
                         "layer": "url_structure", "evidence": host})
    try:
        ipaddress.ip_address(host)
        add("url_ip_host", 25, "URL ใช้หมายเลข IP แทนชื่อเว็บไซต์ อาจเป็นระบบทดสอบหรือเว็บไซต์เสี่ยง")
    except ValueError:
        pass
    if parts.username is not None or parts.password is not None:
        add("url_userinfo", 35, "URL มีข้อมูลก่อน @ ชื่อเว็บไซต์จริงอยู่หลัง @")
    if any(part.startswith("xn--") for part in host.split(".")):
        add("url_idn", 15, "ชื่อเว็บไซต์เป็นอักษรนานาชาติ ควรตรวจตัวสะกดให้รอบคอบ")
    if host in SHORTENERS:
        add("url_shortener", 15, "ลิงก์ย่อซ่อนชื่อเว็บไซต์ปลายทาง ยังไม่ได้เปิดตรวจปลายทาง")
    if len(host) > 70 or len(host.split(".")) >= 6:
        add("url_complex_host", 15, "ชื่อเว็บไซต์ยาวหรือมีส่วนย่อยหลายชั้น")
    observations = ["วิเคราะห์โครงสร้างเท่านั้น ไม่ได้เปิดเว็บไซต์หรือเช็กบัญชีดำ"]
    if parts.scheme == "http":
        observations.append("HTTP ไม่เข้ารหัสการเชื่อมต่อ แต่ไม่ใช่หลักฐาน scam โดยลำพัง")
    return {"host": host, "scheme": parts.scheme, "signals": findings, "observations": observations}

def urls_in_text(text: str) -> list[str]:
    return list(dict.fromkeys(m.group(0).rstrip(".,;!?)}") for m in URL_RE.finditer(text)))[:10]
