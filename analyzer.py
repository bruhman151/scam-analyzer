"""Deterministic scam signals and a provisional risk score."""

import re


_REQUESTS_SECRET = (
    re.compile(r"(?:ส่ง|แจ้ง|บอก|กรอก|แชร์|ยืนยัน).{0,35}?(?:OTP|รหัสยืนยัน|รหัสผ่าน)", re.IGNORECASE),
    re.compile(r"\b(?:send|share|tell|enter|provide|confirm)\b.{0,50}?\b(?:OTP|verification code|password|passcode)\b", re.IGNORECASE),
)
_ACCOUNT_THREAT = (
    re.compile(r"บัญชี.{0,40}?(?:อายัด|ระงับ|ปิด|คดี|ผิดปกติ|เสี่ยง)", re.IGNORECASE),
    re.compile(r"\b(?:account|payment)\b.{0,50}?\b(?:blocked|frozen|suspended|at risk|compromised)\b", re.IGNORECASE),
)
_REQUESTS_TRANSFER = (
    re.compile(r"(?:โอน|ส่ง).{0,20}?(?:เงิน|ยอดเงิน)", re.IGNORECASE),
    re.compile(r"\b(?:transfer|move|send)\b.{0,40}?\b(?:money|funds)\b", re.IGNORECASE),
)
_REQUESTS_PERSONAL_DATA = (
    re.compile(r"(?:ส่ง|แจ้ง|กรอก|ยืนยัน).{0,40}?(?:เลขบัตรประชาชน|ข้อมูลส่วนตัว|รายละเอียดบัญชี|วันเกิด)", re.IGNORECASE),
    re.compile(r"\b(?:send|provide|enter|confirm)\b.{0,50}?\b(?:ID number|personal information|bank account details|date of birth)\b", re.IGNORECASE),
)
_PROHIBITION = (
    re.compile(r"(?:ห้าม|อย่า|ไม่ควร)\s*$"),
    re.compile(r"(?:do\s+not|don't|never|should\s+not)\s*$", re.IGNORECASE),
)
_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_LINK_ACTION = re.compile(r"(?:คลิก|กด|เปิด|เข้า|\bclick\b|\bvisit\b|\bopen\b|\benter\b)", re.IGNORECASE)
_ACCOUNT_ACTION = re.compile(r"(?:ยืนยัน|ปลดล็อก|คืนเงิน|รหัสผ่าน|\bpassword\b|\brefund\b|\bverify\b|\bconfirm\b|\blogin\b)", re.IGNORECASE)
_URGENCY = re.compile(r"(?:ทันที|ภายในวันนี้|ด่วน|\bimmediately\b|\bnow\b|\burgent\b)", re.IGNORECASE)

_NOTICE = "คะแนนเป็นผลรวมของสัญญาณที่ตรวจพบ ไม่ใช่ความน่าจะเป็นที่เป็น scam"


def _has_unprohibited_match(content: str, patterns: tuple[re.Pattern, ...]) -> bool:
    """Match an action unless its verb is directly preceded by a prohibition."""
    for pattern in patterns:
        for match in pattern.finditer(content):
            prefix = content[max(0, match.start() - 25) : match.start()]
            if not any(prohibition.search(prefix) for prohibition in _PROHIBITION):
                return True
    return False


def _add_signal(signals: list[dict], signal_id: str, weight: int, reason: str) -> None:
    signals.append({"id": signal_id, "weight": weight, "reason": reason})


def analyze_text(content: str) -> dict:
    """Return a risk result for one text message without storing the input."""
    signals = []
    requests_secret = _has_unprohibited_match(content, _REQUESTS_SECRET)
    account_threat = any(pattern.search(content) for pattern in _ACCOUNT_THREAT)
    requests_transfer = _has_unprohibited_match(content, _REQUESTS_TRANSFER)
    requests_personal_data = _has_unprohibited_match(content, _REQUESTS_PERSONAL_DATA)
    link_with_account_action = bool(
        _URL.search(content)
        and _has_unprohibited_match(content, (_LINK_ACTION,))
        and _ACCOUNT_ACTION.search(content)
    )
    fear_or_urgency = bool(account_threat and _URGENCY.search(content))

    if requests_secret:
        _add_signal(signals, "requests_secret", 70, "ข้อความขอ OTP รหัสยืนยัน หรือรหัสผ่าน")
    if account_threat:
        _add_signal(signals, "account_threat", 25, "อ้างว่าบัญชีหรือการชำระเงินมีปัญหา")
    if link_with_account_action:
        _add_signal(signals, "link_with_account_action", 35, "ชวนเปิดลิงก์เพื่อจัดการบัญชีหรือข้อมูลการเงิน")
    if requests_transfer:
        _add_signal(signals, "requests_transfer", 20, "ข้อความชวนให้โอนหรือย้ายเงิน")
    if requests_personal_data:
        _add_signal(signals, "requests_personal_data", 35, "ข้อความขอข้อมูลส่วนตัวหรือรายละเอียดบัญชี")
    if fear_or_urgency:
        _add_signal(signals, "fear_or_urgency", 15, "ปัญหาบัญชีถูกนำเสนออย่างเร่งด่วน")

    if not signals:
        return {
            "status": "insufficient_evidence",
            "risk": None,
            "score": None,
            "signals": [],
            "actions": [
                "ระบบยังไม่มีหลักฐานพอจะจัดระดับความเสี่ยง",
                "หากไม่แน่ใจ ให้ตรวจสอบกับองค์กรผ่านช่องทางที่ค้นหาเอง",
            ],
            "notice": _NOTICE,
        }

    score = min(100, sum(signal["weight"] for signal in signals))
    risk = "HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW"
    actions = []
    if requests_secret:
        actions.append("อย่าให้รหัส OTP รหัสยืนยัน หรือรหัสผ่านกับผู้อื่น")
    if link_with_account_action:
        actions.append("อย่ากดลิงก์ในข้อความนี้ ให้ค้นหาช่องทางขององค์กรเอง")
    if requests_transfer:
        actions.append(
            "หยุดการโอนเงินและตรวจสอบก่อน" if account_threat else "ตรวจสอบชื่อผู้รับและเหตุผลก่อนโอนเงิน"
        )
    if requests_personal_data:
        actions.append("อย่าส่งข้อมูลส่วนตัวหรือรายละเอียดบัญชีผ่านข้อความนี้")
    actions.append("ตรวจสอบกับองค์กรผ่านช่องทางที่ค้นหาเอง")
    return {
        "status": "analyzed",
        "risk": risk,
        "score": score,
        "signals": signals,
        "actions": actions,
        "notice": _NOTICE,
    }

