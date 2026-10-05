"""Local HTTP boundary for the anti-scam demo."""

import socket

from flask import Flask, jsonify, render_template, request

from analyzer import analyze_text


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or payload.get("kind") != "text":
        return jsonify({"error": "ส่ง JSON ที่มี kind='text'"}), 400

    content = payload.get("content")
    if not isinstance(content, str) or not content.strip():
        return jsonify({"error": "content ต้องเป็นข้อความที่ไม่ว่าง"}), 400
    if len(content) > 5000:
        return jsonify({"error": "content ต้องไม่เกิน 5000 ตัวอักษร"}), 400

    return jsonify(analyze_text(content))


if __name__ == "__main__":
    try:
        with socket.create_connection(("127.0.0.1", 5000), timeout=0.3):
            raise SystemExit("Port 5000 is already in use. Close the existing service first.")
    except OSError:
        pass
    app.run(host="127.0.0.1", port=5000, debug=False)

