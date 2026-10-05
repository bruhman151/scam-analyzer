"""Explainable bounded rule ensemble. No input persistence or external calls."""
import re
from normalization import normalize
from rules import (RULES, RULESET_VERSION, COMPILED_RULES, PROHIBITION, INTERNAL_NEGATION,
                   LINK_ACTION, SENSITIVE_CONTEXT, URGENCY, AUTHORITY, CLAUSES)
from url_analysis import inspect_url, urls_in_text

MAX_TEXT_LENGTH = 5000
_NOTICE = "คะแนนเป็นผลรวมของสัญญาณที่ตรวจพบ ไม่ใช่ความน่าจะเป็นที่เป็น scam; หลักฐานไม่พอไม่ได้แปลว่าปลอดภัย"
_REDACT = re.compile(r"\d{4,}|[\w.+-]+@[\w.-]+\.[a-z]{2,}", re.I)

def _evidence(text):
    return _REDACT.sub("[ปกปิด]", text)[:120]

def _match(clause, patterns, rule_id):
    for pattern in patterns:
        for match in pattern.finditer(clause):
            if rule_id != "secrecy_pressure":
                prefix = clause[max(0, match.start() - 60):match.start()]
                if PROHIBITION.search(prefix) or INTERNAL_NEGATION.search(match.group()):
                    continue
            if rule_id == "secrecy_pressure" and re.search(r"otp|รหัส|password|verification|code", match.group(), re.I):
                continue
            return match.group()
    return None

def _result(signals, actions, changes, urls, kind):
    score = min(100, sum(s["weight"] for s in signals)) if signals else None
    risk = ("HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW") if signals else None
    if not signals:
        actions = ["ระบบยังไม่มีหลักฐานพอจะจัดระดับความเสี่ยง"]
    actions = list(dict.fromkeys(actions + ["หากไม่แน่ใจ ให้ตรวจสอบผ่านช่องทางทางการที่ค้นหาเอง"]))
    return {"status": "analyzed" if signals else "insufficient_evidence", "risk": risk,
            "score": score, "signals": signals, "actions": actions, "notice": _NOTICE,
            "version": RULESET_VERSION, "kind": kind,
            "analysis": {"normalizations": changes, "urls": urls,
                         "layers": ["normalization", "phrase_context", "negation", "url_structure", "combination"]}}

def _analyze(content: str, *, optimized=True) -> dict:
    if not isinstance(content, str) or not content.strip() or len(content) > MAX_TEXT_LENGTH:
        raise ValueError("กรุณาใส่ข้อความ 1–5,000 ตัวอักษร")
    text, changes = normalize(content)
    clauses = [c.strip() for c in CLAUSES.split(text) if c.strip()]
    signals, actions, url_details, found = [], [], [], set()
    def add(key, weight, reason, evidence, layer, action=None):
        if key not in found:
            signals.append({"id": key, "weight": weight, "reason": reason,
                            "evidence": _evidence(evidence), "layer": layer})
            found.add(key)
            if action:
                actions.append(action)
    # Reference mode repeats scans. Optimized mode uses precompiled immutable
    # patterns and stops at the first hit per rule. Neither caches user input.
    entries = COMPILED_RULES if optimized else tuple(
        (r, tuple(re.compile(p, re.I) for p in r.patterns)) for r in RULES)
    for rule, patterns in entries:
        for clause in clauses:
            evidence = _match(clause, patterns, rule.id)
            if evidence:
                add(rule.id, rule.weight, rule.reason, evidence, rule.layer, rule.action)
                if optimized:
                    break
    for value in urls_in_text(text):
        try:
            detail = inspect_url(value)
        except ValueError:
            url_details.append({"host": None, "observations": ["พบลิงก์ที่รูปแบบไม่ถูกต้อง ตรวจโครงสร้างไม่ได้"]})
            continue
        url_details.append({k: v for k, v in detail.items() if k != "signals"})
        for signal in detail["signals"]:
            add(signal["id"], signal["weight"], signal["reason"], signal["evidence"], signal["layer"])
    for clause in clauses:
        if urls_in_text(clause) and SENSITIVE_CONTEXT.search(clause):
            evidence = _match(clause, (LINK_ACTION,), "link_with_account_action")
            if evidence:
                add("link_with_account_action", 35, "ชวนเปิดลิงก์เพื่อยืนยันข้อมูลหรือจัดการบัญชี", evidence,
                    "phrase_context", "เปิดแอปหรือเว็บไซต์ทางการด้วยตนเองเพื่อทำรายการ")
    if "account_threat" in found and URGENCY.search(text):
        add("fear_or_urgency", 15, "นำปัญหาบัญชีมาเร่งให้ตัดสินใจ", URGENCY.search(text).group(), "combination")
    if "requests_transfer" in found and AUTHORITY.search(text):
        add("authority_transfer", 30, "อ้างเจ้าหน้าที่ร่วมกับการขอโอนเงิน", AUTHORITY.search(text).group(),
            "combination", "หยุดตรวจสอบคำขอโอนเงินกับหน่วยงานที่ถูกอ้างถึง")
    if "remote_access" in found and ("account_threat" in found or AUTHORITY.search(text)):
        add("remote_access_pressure", 15, "ขอควบคุมเครื่องร่วมกับการอ้างเจ้าหน้าที่หรือปัญหาบัญชี",
            "remote_access + context", "combination")
    return _result(signals, actions, changes, url_details, "text")

def analyze_text(content: str) -> dict:
    return _analyze(content, optimized=True)

def analyze_text_reference(content: str) -> dict:
    """Unoptimized oracle with identical rule and scoring policy."""
    return _analyze(content, optimized=False)

def analyze_url(content: str) -> dict:
    detail = inspect_url(content)
    return _result(detail["signals"], [], [], [{k: v for k, v in detail.items() if k != "signals"}], "url")
