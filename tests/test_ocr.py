"""Real OCR smoke checks; explicitly skipped where the engine is absent."""
from pathlib import Path
import unittest
from PIL import Image
import io
from analyzer import analyze_text
from ocr import capability, extract_text, OCRError

FIXTURES=Path(__file__).parent/"fixtures"

class ImageValidationTests(unittest.TestCase):
    def test_blank_image(self):
        buf=io.BytesIO()
        Image.new("RGB",(500,150),"white").save(buf,format="PNG")
        if not capability()["available"]:
            self.skipTest("Tesseract tha+eng unavailable")
        with self.assertRaises(OCRError) as caught:
            extract_text(buf.getvalue())
        self.assertEqual(caught.exception.code,"ocr_no_text")

    def test_unsupported_format(self):
        buf=io.BytesIO()
        Image.new("RGB",(100,100),"white").save(buf,format="GIF")
        with self.assertRaises(OCRError):
            extract_text(buf.getvalue())

    def test_pixel_limit(self):
        buf=io.BytesIO()
        Image.new("1",(3000,3000)).save(buf,format="PNG")
        with self.assertRaises(OCRError):
            extract_text(buf.getvalue())

class OCRIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(capability()["available"], "Tesseract tha+eng unavailable")
    def test_real_thai_and_english_images(self):
        for name in ["thai.png","english.png"]:
            with self.subTest(image=name):
                ocr=extract_text((FIXTURES/name).read_bytes())
                self.assertTrue(ocr["needs_review"])
                self.assertEqual(analyze_text(ocr["text"])["risk"],"HIGH")

if __name__=="__main__":
    unittest.main()
