"""Behavior checks for the second set of scam patterns."""

import unittest

from analyzer import analyze_text


def signal_ids(result):
    return {signal["id"] for signal in result["signals"]}


class AnalyzerDayTwoTests(unittest.TestCase):
    def test_fake_bank_warning_with_link_is_high(self):
        result = analyze_text(
            "บัญชีธนาคารของคุณจะถูกอายัดวันนี้ คลิก https://bank-check.example.invalid/verify เพื่อยืนยัน"
        )
        self.assertEqual(result["risk"], "HIGH")
        self.assertIn("link_with_account_action", signal_ids(result))

    def test_government_refund_asking_for_password_is_high(self):
        result = analyze_text(
            "Government refund pending. Enter your bank password at https://refund.example.invalid/claim"
        )
        self.assertEqual(result["risk"], "HIGH")
        self.assertIn("requests_secret", signal_ids(result))

    def test_account_threat_and_transfer_pressure_are_high_together(self):
        result = analyze_text("บัญชีของคุณเกี่ยวข้องกับคดี กรุณาโอนเงินทั้งหมดทันที")
        self.assertEqual(result["risk"], "HIGH")
        self.assertIn("requests_transfer", signal_ids(result))

    def test_personal_data_request_is_medium(self):
        result = analyze_text("กรุณาส่งเลขบัตรประชาชนและวันเกิดเพื่อรับเงินคืน")
        self.assertEqual(result["risk"], "MEDIUM")

    def test_ordinary_transfer_is_only_low(self):
        result = analyze_text("โอนเงินค่าอาหารให้เพื่อนตอนเย็น")
        self.assertEqual(result["risk"], "LOW")

    def test_safety_advice_does_not_count_as_link_request(self):
        result = analyze_text(
            "บัญชีคุณอาจเสี่ยง อย่ากดลิงก์ https://help.example.org ตรวจสอบกับธนาคารโดยตรง"
        )
        self.assertNotIn("link_with_account_action", signal_ids(result))
        self.assertNotEqual(result["risk"], "HIGH")

    def test_bank_seminar_link_is_not_a_financial_action(self):
        result = analyze_text(
            "ธนาคารจัดอบรมการใช้บัญชี กรุณาคลิก https://example.org/agenda เพื่อดูตารางงาน"
        )
        self.assertNotIn("link_with_account_action", signal_ids(result))


if __name__ == "__main__":
    unittest.main()

