"""Versioned bilingual indicators. Weights are policy choices, not probabilities.
See docs/RESEARCH.md for sources. Every regex context gap is bounded.
"""
import re
from dataclasses import dataclass

RULESET_VERSION = "0.3.1"

@dataclass(frozen=True)
class Rule:
    id: str
    weight: int
    reason: str
    patterns: tuple[str, ...]
    action: str
    layer: str = "phrase_context"

RULES = (
    Rule("requests_secret", 70, "ขอ OTP รหัสยืนยัน รหัสผ่าน หรือรหัสเข้าถึงบัญชี", (
        r"(?:ส่ง|แจ้ง|บอก|กรอก|แชร์|ยืนยัน|ขอ|พิมพ์|อ่าน).{0,40}?(?:otp|รหัสยืนยัน|รหัสผ่าน|พาสเวิร์ด|รหัสใช้ครั้งเดียว|รหัสลับ|รหัส pin)",
        r"\b(?:send|share|tell|enter|provide|confirm|type|read|give|reply)\b.{0,55}?\b(?:otp|verification code|password|passcode|one[ -]time (?:code|password)|security code|pin)\b",
    ), "อย่าให้ OTP หรือรหัสเข้าถึงบัญชีแก่ผู้ติดต่อ"),
    Rule("account_threat", 25, "อ้างว่าบัญชีหรือการชำระเงินมีปัญหา", (
        r"(?:บัญชี|บัตร).{0,40}?(?:อายัด|ระงับ|ปิด|คดี|ผิดปกติ|เสี่ยง|ฟอกเงิน)",
        r"\b(?:account|payment|card)\b.{0,50}?\b(?:blocked|frozen|suspended|at risk|compromised|locked|unauthorized)\b",
    ), "ตรวจสอบสถานะบัญชีผ่านแอปหรือช่องทางทางการที่เปิดเอง"),
    Rule("requests_transfer", 20, "ชวนให้โอนหรือย้ายเงิน", (
        r"(?:โอน|ส่ง|ย้าย).{0,25}?(?:เงิน|ยอดเงิน|ยอดคงเหลือ)",
        r"\b(?:transfer|move|send|wire)\b.{0,40}?\b(?:money|funds|savings|balance|payment)\b",
    ), "ตรวจสอบชื่อผู้รับและเหตุผลก่อนโอนเงิน"),
    Rule("requests_personal_data", 35, "ขอข้อมูลส่วนตัวหรือรายละเอียดบัญชี", (
        r"(?:ส่ง|แจ้ง|กรอก|ยืนยัน|ขอ|พิมพ์).{0,40}?(?:เลขบัตรประชาชน|ข้อมูลส่วนตัว|รายละเอียดบัญชี|วันเกิด|หมายเลขบัตร|เลขหลังบัตร|cvv)",
        r"\b(?:send|provide|enter|confirm|give|type)\b.{0,50}?\b(?:id number|personal information|bank account details|date of birth|card number|cvv|social security number)\b",
    ), "ตรวจสอบความจำเป็นและตัวตนผู้รับก่อนให้ข้อมูลส่วนตัว"),
    Rule("remote_access", 55, "ขอติดตั้งเครื่องมือควบคุมเครื่องหรือไฟล์แอปจากข้อความ", (
        r"(?:ติดตั้ง|ดาวน์โหลด|เปิด|อนุญาต).{0,50}?(?:anydesk|teamviewer|rustdesk|ควบคุมหน้าจอ|ควบคุมเครื่อง|แชร์หน้าจอ|ไฟล์ apk|\.apk)",
        r"\b(?:install|download|enable|allow)\b.{0,65}?(?:\banydesk\b|\bteamviewer\b|\brustdesk\b|remote access|screen sharing|\.apk\b)",
    ), "ยืนยันตัวตนผู้ติดต่อก่อนติดตั้งแอปหรือให้สิทธิ์ควบคุมเครื่อง"),
    Rule("advance_fee", 55, "ขอจ่ายเงินก่อนรับรางวัล เงินคืน สินเชื่อ หรือพัสดุ", (
        r"(?:จ่าย|ชำระ|โอน).{0,35}?(?:ค่าธรรมเนียม|ภาษี|ค่าดำเนินการ|ค่าจัดส่ง|ค่าปลดล็อก).{0,65}?(?:รางวัล|เงินคืน|สินเชื่อ|พัสดุ|รับเงิน|เงินกู้)",
        r"\b(?:pay|send|transfer)\b.{0,35}?\b(?:fee|tax|deposit|shipping)\b.{0,65}?\b(?:prize|refund|loan|parcel|winnings|reward)\b",
    ), "ตรวจสอบเงื่อนไขผ่านองค์กรจริงก่อนจ่ายเงินล่วงหน้า"),
    Rule("task_deposit", 60, "ให้เติมเงินหรือวางเงินก่อนถอนรายได้หรือค่าคอมมิชชัน", (
        r"(?:เติมเงิน|วางเงิน|ฝากเงิน|โอนเงิน|จ่ายเงิน).{0,70}?(?:ถอนเงิน|ถอนรายได้|ปลดล็อกรายได้|ค่าคอม|รับงาน|ทำภารกิจ)",
        r"\b(?:deposit|top up|pay|send money)\b.{0,80}?\b(?:withdraw|unlock.{0,20}?earnings|commission|task|job)\b",
    ), "ตรวจสอบงานที่ต้องจ่ายเงินเพื่อรับงานหรือถอนรายได้"),
    Rule("guaranteed_returns", 45, "สัญญาผลตอบแทนแน่นอนหรือไม่มีความเสี่ยงในการลงทุน", (
        r"(?:การันตี|รับประกัน).{0,40}?(?:กำไร|ผลตอบแทน)|(?:ลงทุน).{0,40}?(?:ไร้ความเสี่ยง|ไม่มีความเสี่ยง|กำไรแน่นอน)",
        r"\b(?:guaranteed|risk[ -]free)\b.{0,40}?\b(?:profit|returns|investment)\b",
    ), "ตรวจสอบใบอนุญาตและคำกล่าวอ้างเรื่องผลตอบแทนกับหน่วยงานกำกับ"),
    Rule("secrecy_pressure", 20, "ขอปกปิดเรื่องจากคนใกล้ตัวหรือธนาคาร", (
        r"(?:ห้าม|อย่า).{0,12}?(?:บอก|แจ้ง|ปรึกษา).{0,25}?(?:ครอบครัว|ตำรวจ|ธนาคาร|คนอื่น)",
        r"\b(?:do not|don't|never)\b.{0,15}?\b(?:tell|contact|inform)\b.{0,30}?\b(?:family|police|bank|anyone)\b",
    ), "ปรึกษาคนที่ไว้ใจได้และตรวจสอบข้อมูลจากอีกช่องทาง", "context"),
)
COMPILED_RULES = tuple((r, tuple(re.compile(p, re.I) for p in r.patterns)) for r in RULES)
PROHIBITION = re.compile(r"(?:ห้าม|อย่า|ไม่ควร|ไม่ต้อง|ไม่ให้|ไม่เคย|ไม่ขอให้|ไม่ต้องการให้|ไม่จำเป็นต้อง|(?:do not|don't|never|should not|will not|won't)\s+(?:ever\s+)?)(?:\s|ทำการ)*$", re.I)
INTERNAL_NEGATION = re.compile(r"\b(?:not|never)\b|ไม่ได้|ไม่ถูก|ไม่เคย|ห้าม|อย่า|ไม่ควร|ไม่ต้อง", re.I)
LINK_ACTION = re.compile(r"คลิก|กด|เปิด|เข้า|\b(?:click|visit|open|enter|follow)\b", re.I)
SENSITIVE_CONTEXT = re.compile(r"ยืนยัน|ปลดล็อก|คืนเงิน|รหัสผ่าน|\b(?:password|refund|verify|confirm|log[ -]?in)\b", re.I)
URGENCY = re.compile(r"ทันที|ภายในวันนี้|ด่วน|\b(?:immediately|now|urgent|within \d+ (?:minutes|hours))\b", re.I)
AUTHORITY = re.compile(r"ตำรวจ|เจ้าหน้าที่|กรมสรรพากร|ศาล|ปปง|\b(?:police|officer|government|tax office|court)\b", re.I)
CLAUSES = re.compile(r"\n+|(?<=[.!?;])\s+|[。！？]|\bbut\b|แต่", re.I)
