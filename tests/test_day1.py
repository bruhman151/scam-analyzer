"""Small day-1 checks. Full adversarial evaluation comes later."""

import unittest

from app import app
from analyzer import analyze_text


class AnalyzerDayOneTests(unittest.TestCase):
    def test_thai_request_for_otp_is_high(self):
        result = analyze_text("เจ้าหน้าที่ขอให้ส่งรหัส OTP เพื่อปลดล็อกบัญชี")
        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["signals"][0]["id"], "requests_secret")

    def test_otp_notice_is_not_a_request(self):
        result = analyze_text("รหัส OTP 123456 สำหรับเข้าสู่ระบบ ห้ามบอกรหัสนี้กับใคร")
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertIsNone(result["risk"])
        self.assertEqual(result["signals"], [])

    def test_thai_prohibition_is_not_a_request(self):
        result = analyze_text("ห้ามส่งรหัส OTP ให้ใครเด็ดขาด")
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertIsNone(result["risk"])

    def test_english_prohibition_is_not_a_request(self):
        result = analyze_text("Do not share your verification code with anyone")
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertIsNone(result["risk"])

    def test_a_later_positive_request_is_still_detected(self):
        result = analyze_text("ห้ามบอกรหัส OTP ให้คนอื่น แต่ส่งรหัส OTP ให้เจ้าหน้าที่")
        self.assertEqual(result["risk"], "HIGH")

    def test_api_accepts_text(self):
        response = app.test_client().post(
            "/analyze", json={"kind": "text", "content": "Please share your verification code"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk"], "HIGH")

    def test_api_rejects_empty_text(self):
        response = app.test_client().post("/analyze", json={"kind": "text", "content": " "})
        self.assertEqual(response.status_code, 400)

    def test_api_returns_insufficient_evidence_without_a_score(self):
        response = app.test_client().post(
            "/analyze", json={"kind": "text", "content": "ช่วยส่งรายงานด่วนก่อนเที่ยง"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "insufficient_evidence")
        self.assertIsNone(response.json["risk"])
        self.assertIsNone(response.json["score"])


if __name__ == "__main__":
    unittest.main()

