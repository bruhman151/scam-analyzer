"""Local HTTP boundary: strict input, JSON errors, no content logging."""
import logging
import socket
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from analyzer import analyze_text, analyze_url, MAX_TEXT_LENGTH
from rules import RULESET_VERSION
from ocr import capability, extract_text, OCRError, MAX_UPLOAD

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD + 64 * 1024,
                  MAX_FORM_MEMORY_SIZE=64 * 1024, MAX_FORM_PARTS=4,
                  TRUSTED_HOSTS=["127.0.0.1", "localhost", "[::1]"])

@app.before_request
def local_boundary():
    if request.method == "POST":
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            return jsonify(error="อนุญาตเฉพาะหน้าเว็บในเครื่องเดียวกัน", code="origin_rejected"), 403
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            return jsonify(error="ไม่อนุญาตคำขอจากเว็บไซต์อื่น", code="origin_rejected"), 403
        if request.path == "/analyze" and request.content_length and request.content_length > 64 * 1024:
            return jsonify(error="ข้อความมีขนาดเกินกำหนด", code="payload_too_large"), 413

@app.after_request
def headers(response):
    response.headers.update({
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    })
    return response

@app.errorhandler(HTTPException)
def http_error(error):
    return jsonify(error="คำขอไม่ถูกต้องหรือขนาดเกินกำหนด", code=error.name.lower().replace(" ", "_")), error.code

@app.errorhandler(Exception)
def unexpected_error(error):
    # No traceback or raw exception: these may contain private user input.
    app.logger.error("Request failed: %s", type(error).__name__)
    return jsonify(error="ระบบวิเคราะห์ไม่สำเร็จ กรุณาลองใหม่", code="internal_error"), 500

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/health")
def health():
    return jsonify(status="ok", version=RULESET_VERSION, ocr=capability(), mode="local")

@app.post("/analyze")
def analyze():
    if not request.is_json:
        return jsonify(error="ส่งข้อมูลเป็น JSON", code="invalid_content_type"), 400
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("kind"), str) or payload["kind"] not in {"text", "url"}:
        return jsonify(error="kind ต้องเป็น text หรือ url", code="invalid_kind"), 400
    content = payload.get("content")
    if not isinstance(content, str) or not content.strip() or len(content) > MAX_TEXT_LENGTH:
        return jsonify(error="content ต้องเป็นข้อความ 1–5,000 ตัวอักษร", code="invalid_content"), 400
    try:
        result = analyze_url(content) if payload["kind"] == "url" else analyze_text(content)
    except ValueError as error:
        return jsonify(error=str(error), code="invalid_content"), 400
    return jsonify(result)

@app.post("/analyze/image")
def analyze_image():
    if "image" not in request.files:
        return jsonify(error="ส่งภาพ PNG หรือ JPEG ในช่อง image", code="missing_image"), 400
    upload = request.files["image"]
    try:
        ocr = extract_text(upload.read(MAX_UPLOAD + 1))
        result = analyze_text(ocr["text"])
        result["kind"], result["ocr"] = "image", ocr
        result["analysis"]["layers"].insert(0, "ocr")
        return jsonify(result)
    except OCRError as error:
        return jsonify(status="unable_to_analyze", risk=None, score=None, signals=[],
                       error=str(error), code=error.code), error.http_status

if __name__ == "__main__":
    from waitress import serve
    # The socket bind in Waitress remains authoritative if another process races.
    try:
        with socket.create_connection(("127.0.0.1", 5000), timeout=0.3):
            raise SystemExit("Port 5000 is in use. Close the existing service first.")
    except OSError:
        pass
    print("Scam Risk Analyzer: http://127.0.0.1:5000/  (Ctrl+C to stop)", flush=True)
    print("OCR ready:", capability()["available"], flush=True)
    serve(app, host="127.0.0.1", port=5000, threads=4, connection_limit=32,
          channel_timeout=30, cleanup_interval=5, max_request_body_size=MAX_UPLOAD + 64 * 1024,
          inbuf_overflow=8 * 1024 * 1024, outbuf_overflow=8 * 1024 * 1024)
