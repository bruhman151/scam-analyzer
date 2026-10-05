"""Bounded local Tesseract adapter; image bytes stay in memory."""
import csv
import io
import os
from pathlib import Path
import shutil
import subprocess
import threading
import warnings
from functools import lru_cache

from PIL import Image, ImageOps, UnidentifiedImageError

MAX_UPLOAD = 4 * 1024 * 1024
MAX_PIXELS = 8_000_000
MAX_EDGE = 2200
TIMEOUT = 12
Image.MAX_IMAGE_PIXELS = MAX_PIXELS
_SLOT = threading.BoundedSemaphore(1)
ROOT = Path(__file__).resolve().parent

class OCRError(Exception):
    def __init__(self, code, message, http_status=422):
        super().__init__(message)
        self.code, self.http_status = code, http_status

def engine_path():
    configured = os.environ.get("TESSERACT_CMD")
    local = ROOT / ".tools" / "tesseract" / "tesseract.exe"
    return configured or (str(local) if local.is_file() else shutil.which("tesseract"))

def _env():
    env = os.environ.copy()
    env["OMP_THREAD_LIMIT"] = "1"
    local_data = ROOT / ".tools" / "tesseract" / "tessdata"
    if not os.environ.get("TESSERACT_CMD") and local_data.is_dir():
        env["TESSDATA_PREFIX"] = str(local_data)
    return env

def _run(args, **kwargs):
    return subprocess.run(args, timeout=TIMEOUT, capture_output=True, env=_env(),
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0, **kwargs)

@lru_cache(maxsize=1)
def capability():
    engine = engine_path()
    if not engine:
        return {"available": False, "languages": [], "reason": "ไม่พบ Tesseract"}
    try:
        proc = _run([engine, "--list-langs"])
        languages = set(proc.stdout.decode("utf-8", errors="replace").splitlines()[1:])
        ready = proc.returncode == 0 and {"tha", "eng"}.issubset(languages)
        return {"available": ready, "languages": sorted(languages),
                "reason": None if ready else "ต้องติดตั้งภาษา tha และ eng"}
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "languages": [], "reason": "เปิดเครื่องมือ OCR ไม่สำเร็จ"}

def extract_text(data: bytes) -> dict:
    if not data or len(data) > MAX_UPLOAD:
        raise OCRError("image_size", "ไฟล์ภาพต้องมีขนาด 1 ไบต์ถึง 4 MB", 413)
    if not _SLOT.acquire(blocking=False):
        raise OCRError("ocr_busy", "กำลังอ่านข้อความจากอีกภาพ กรุณาลองใหม่", 429)
    try:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(data)) as source:
                    if source.format not in {"PNG", "JPEG"}:
                        raise OCRError("image_format", "รองรับภาพ PNG และ JPEG เท่านั้น")
                    if source.width * source.height > MAX_PIXELS or source.width < 32 or source.height < 32:
                        raise OCRError("image_dimensions", "ภาพต้องมีขนาดอย่างน้อย 32 × 32 และไม่เกิน 8 ล้านพิกเซล")
                    source.load()
                    image = ImageOps.exif_transpose(source).convert("RGB")
            image.thumbnail((MAX_EDGE, MAX_EDGE))
            image = ImageOps.autocontrast(ImageOps.grayscale(image))
            buffer = io.BytesIO()
            image.save(buffer, format="PNG")
        except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError, Image.DecompressionBombWarning):
            raise OCRError("invalid_image", "ภาพเสียหาย รูปแบบไม่รองรับ หรือขนาดเกินกำหนด") from None
        if not capability()["available"]:
            raise OCRError("ocr_unavailable", "OCR ไทย/อังกฤษยังไม่พร้อม ดูวิธีติดตั้งใน README", 503)
        try:
            proc = _run([engine_path(), "stdin", "stdout", "-l", "tha+eng", "--psm", "6", "tsv"],
                        input=buffer.getvalue())
        except subprocess.TimeoutExpired:
            raise OCRError("ocr_timeout", "อ่านภาพเกิน 12 วินาที ลองครอปเฉพาะข้อความ") from None
        except OSError:
            raise OCRError("ocr_failed", "เปิดเครื่องมือ OCR ไม่สำเร็จ", 503) from None
        if proc.returncode:
            raise OCRError("ocr_failed", "อ่านข้อความไม่สำเร็จ ลองใช้ภาพที่ชัดขึ้น")
        rows = csv.DictReader(io.StringIO(proc.stdout.decode("utf-8", errors="replace")), delimiter="\t")
        lines, confidence = {}, []
        for row in rows:
            word = (row.get("text") or "").strip()
            if not word:
                continue
            key = (row.get("block_num"), row.get("par_num"), row.get("line_num"))
            lines.setdefault(key, []).append(word)
            try:
                value = float(row.get("conf", "-1"))
                if value >= 0:
                    confidence.append(value)
            except ValueError:
                pass
        text = "\n".join(" ".join(words) for words in lines.values())
        # Tesseract separates Thai words; keep English spacing, join Thai word gaps.
        import re
        text = re.sub(r"(?<=[\u0e00-\u0e7f]) +(?=[\u0e00-\u0e7f])", "", text)
        if not text or sum(c.isalnum() for c in text) < 3:
            raise OCRError("ocr_no_text", "ไม่พบข้อความที่อ่านได้ ลองภาพที่ชัดขึ้นหรือพิมพ์ข้อความเอง")
        if len(text) > 5000:
            raise OCRError("ocr_text_limit", "ข้อความในภาพเกิน 5,000 ตัวอักษร กรุณาครอปภาพ")
        avg = round(sum(confidence) / len(confidence), 1) if confidence else 0
        if avg < 35:
            raise OCRError("ocr_uncertain", "OCR อ่านภาพได้ไม่ชัดพอ กรุณาครอปภาพหรือพิมพ์ข้อความ")
        return {"text": text, "mean_word_confidence": avg, "needs_review": True,
                "notice": "ตรวจทานข้อความ OCR ก่อนเชื่อผล คะแนน OCR ไม่ใช่ความมั่นใจว่าเป็น scam"}
    finally:
        _SLOT.release()
