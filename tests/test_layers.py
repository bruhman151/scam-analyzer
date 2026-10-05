"""Behavior, invariants and boundary failures that matter for this demo."""
import io
import json
from pathlib import Path
import random
import unittest
from unittest.mock import patch

from analyzer import analyze_text, analyze_text_reference, analyze_url
from app import app
from ocr import OCRError, extract_text, _SLOT

class LayerTests(unittest.TestCase):
    def test_supported_obfuscations(self):
        for text in ["Send your O T P", "Send your ＯＴＰ", "Send your O\u200bTP",
                     "Share your p@ssw0rd", "กรอกรหัสผ่าน", "ส่งร หั ส ผ่ า น"]:
            with self.subTest(text=text):
                self.assertEqual(analyze_text(text)["risk"], "HIGH")

    def test_multiple_languages_and_categories(self):
        examples = {
            "เติมเงินก่อนถอนเงินจากค่าคอมมิชชัน": "task_deposit",
            "Pay a fee to claim your prize": "advance_fee",
            "เจ้าหน้าที่ให้ติดตั้ง AnyDesk": "remote_access",
            "Guaranteed returns on your investment": "guaranteed_returns",
            "ตำรวจให้โอนเงินเพื่อตรวจสอบ": "authority_transfer",
            "Do not tell your family about this": "secrecy_pressure",
        }
        for text, expected in examples.items():
            with self.subTest(text=text):
                self.assertIn(expected, {s["id"] for s in analyze_text(text)["signals"]})

    def test_prohibition_and_later_request(self):
        for text in ["Please don't ever share your password", "ไม่ต้องส่ง OTP",
                     "ธนาคารไม่เคยขอให้ส่งรหัสผ่าน", "Your account is not suspended"]:
            with self.subTest(text=text):
                self.assertIsNone(analyze_text(text)["risk"])
        self.assertEqual(analyze_text("Never send your OTP. But give your password to me.")["risk"], "HIGH")

    def test_secret_notice_no_secrecy_pressure(self):
        self.assertIsNone(analyze_text("ห้ามบอกรหัส OTP ให้คนอื่น")["risk"])

    def test_unrelated_sentences_do_not_form_link_signal(self):
        result = analyze_text("Click https://example.org/agenda. We will discuss how to verify claims.")
        self.assertNotIn("link_with_account_action", {s["id"] for s in result["signals"]})

    def test_scores_do_not_grow_with_repetition(self):
        once = analyze_text("Send your OTP")
        repeated = analyze_text(("Send your OTP. " * 100).strip())
        self.assertEqual(once["score"], repeated["score"])
        self.assertLessEqual(repeated["score"], 100)

    def test_no_signal_is_not_low(self):
        result = analyze_text("Hello everyone")
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertIsNone(result["score"])

    def test_url_uses_actual_host(self):
        result = analyze_url("https://bank.example.org@192.0.2.10/login")
        self.assertEqual(result["analysis"]["urls"][0]["host"], "192.0.2.10")
        self.assertEqual(result["risk"], "HIGH")

    def test_url_shortener_and_idn_are_weak(self):
        for url in ["https://bit.ly/demo", "https://xn--bcher-kva.example/"]:
            self.assertEqual(analyze_url(url)["risk"], "LOW")

    def test_normal_url_is_not_declared_safe(self):
        self.assertIsNone(analyze_url("https://example.org/")["risk"])

    def test_invalid_url(self):
        for url in ["javascript:alert(1)", "https://", "https://[broken", "https://x.example:bad",
                    "https://has space.example", "file:///a", "https://a.example\\@b.example"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                analyze_url(url)

    def test_input_bounds(self):
        for value in ["", " ", "ก"*5001, None]:
            with self.assertRaises(ValueError):
                analyze_text(value)

    def test_optimization_equivalence(self):
        cases = json.loads((Path(__file__).parent/"cases.json").read_text(encoding="utf-8"))
        texts = [c["content"] for c in cases if c["kind"]=="text"]
        random.seed(17)
        pieces = ["Send OTP.", "ห้ามส่ง OTP", "โอนเงินทันที", "Hello", "https://bit.ly/demo",
                  "We never share passwords.", "ตำรวจ", "Pay a fee to get a prize."]
        texts += ["\n".join(random.choices(pieces, k=random.randint(1, 18))) for _ in range(250)]
        for text in texts:
            self.assertEqual(analyze_text(text), analyze_text_reference(text))

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.client=app.test_client()

    def test_invalid_payloads_are_json_400(self):
        for payload in [None, [], {}, {"kind":[]}, {"kind":{}}, {"kind":"text","content":123},
                        {"kind":"text","content":""}, {"kind":"url","content":"file:///test"}]:
            with self.subTest(payload=payload):
                response=self.client.post("/analyze",json=payload)
                self.assertEqual(response.status_code,400)
                self.assertIn("error",response.json)

    def test_malformed_json(self):
        response=self.client.post("/analyze",data="{",content_type="application/json")
        self.assertEqual(response.status_code,400)

    def test_long_unicode_valid_at_boundary(self):
        response=self.client.post("/analyze",json={"kind":"text","content":"ก"*5000})
        self.assertEqual(response.status_code,200)

    def test_oversized_body(self):
        response=self.client.post("/analyze",data="x"*70000,content_type="application/json")
        self.assertEqual(response.status_code,413)

    def test_foreign_origin_and_host(self):
        self.assertEqual(self.client.post("/analyze",json={"kind":"text","content":"Hello"},
                         headers={"Origin":"https://untrusted.example"}).status_code,403)
        self.assertEqual(self.client.get("/health",headers={"Host":"untrusted.example"}).status_code,400)

    def test_image_failures_return_no_risk(self):
        response=self.client.post("/analyze/image",data={"image":(io.BytesIO(b"not an image"),"x.png")})
        self.assertEqual(response.status_code,422)
        self.assertEqual(response.json["status"],"unable_to_analyze")
        self.assertIsNone(response.json["risk"])
        self.assertEqual(self.client.post("/analyze/image").status_code,400)

    def test_security_headers_and_no_cache(self):
        response=self.client.get("/")
        self.assertEqual(response.headers["Cache-Control"],"no-store")
        self.assertIn("frame-ancestors 'none'",response.headers["Content-Security-Policy"])

    def test_busy_ocr_is_bounded(self):
        _SLOT.acquire()
        try:
            with self.assertRaises(OCRError) as caught:
                extract_text(b"x")
            self.assertEqual(caught.exception.http_status,429)
        finally:
            _SLOT.release()

    def test_ocr_fault_is_not_insufficient_evidence(self):
        with patch("app.extract_text",side_effect=OCRError("ocr_timeout","Timed out",422)):
            response=self.client.post("/analyze/image",data={"image":(io.BytesIO(b"x"),"x.png")})
        self.assertEqual(response.json["status"],"unable_to_analyze")
        self.assertIsNone(response.json["score"])

if __name__=="__main__":
    unittest.main()
