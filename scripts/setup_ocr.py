"""Install pinned Windows OCR engine and language models into .tools."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.request import urlretrieve

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / ".tools" / "tesseract"
PINNED = {
    "installer": ("https://github.com/tesseract-ocr/tesseract/releases/download/5.5.3/tesseract-ocr-w64-setup-5.5.3.20260724.exe", "bee9e3434bd94fd65387d9be28cd467a41f61b1275383b55b0f59a1331270ae4"),
    "eng": ("https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/4.1.0/eng.traineddata", "7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2"),
    "tha": ("https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/4.1.0/tha.traineddata", "294227cc2d1292b0acb28d61d4115c88252b96d466ca90b417cf4cf0c67bf07c"),
}

def checked(url, digest, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == digest:
        return
    part = path.with_name(path.name + ".download")
    try:
        urlretrieve(url, part)
        if hashlib.sha256(part.read_bytes()).hexdigest() != digest:
            raise RuntimeError("OCR download checksum mismatch")
        part.replace(path)
    finally:
        part.unlink(missing_ok=True)

def main():
    if sys.platform != "win32":
        raise SystemExit("Install Tesseract and tha+eng language data with your OS package manager.")
    seven = shutil.which("7z") or r"C:\Program Files\7-Zip\7z.exe"
    if not Path(seven).is_file():
        raise SystemExit("7-Zip is required to unpack local OCR: https://www.7-zip.org/")
    installer = ROOT / ".tools" / "tesseract-installer.exe"
    checked(*PINNED["installer"], installer)
    if not (TARGET / "tesseract.exe").is_file():
        TARGET.mkdir(parents=True, exist_ok=True)
        subprocess.run([seven, "x", str(installer), f"-o{TARGET}", "-y"],
                       check=True, stdout=subprocess.DEVNULL)
    for lang in ("eng", "tha"):
        checked(*PINNED[lang], TARGET / "tessdata" / f"{lang}.traineddata")
    sys.path.insert(0, str(ROOT))
    from ocr import capability
    if not capability()["available"]:
        raise SystemExit("OCR setup incomplete; see README.")
    print("OCR ready: tha+eng")

if __name__ == "__main__":
    main()
