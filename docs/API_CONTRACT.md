# Local HTTP API v0.3.1

Base: `http://127.0.0.1:5000`. Local host/origin boundary; JSON errors; no response caching. Inputs are not persisted. Links are not opened.

| Route | Input | Response |
|---|---|---|
| `GET /health` | none | status, ruleset version, OCR availability/languages |
| `POST /analyze` | JSON `{"kind":"text","content":"..."}` or `{"kind":"url","content":"https://..."}` | risk result |
| `POST /analyze/image` | multipart field `image`, PNG/JPEG | risk result plus OCR text/confidence/review notice |

Text: 1–5,000 characters. Standalone URL: HTTP(S), up to 2,048 characters. Image: 1–4 MB, 32×32 to 8 megapixels, OCR timeout 12 seconds, one OCR at a time. Image is decoded then re-encoded in memory; the filename is never used. Thai and English OCR data are required.

Result fields: `status`, `risk` (HIGH/MEDIUM/LOW or null), `score` (0–100 or null), `signals` (id, weight, reason, masked evidence, layer), `actions`, `notice`, `version`, `kind`, `analysis`; image also has `ocr`. Each signal scores once. HIGH ≥60, MEDIUM 25–59, LOW 1–24. No signals return `insufficient_evidence`, null risk and null score; this does not mean safe. OCR failures return HTTP 422/429/503 with `unable_to_analyze`, null risk/score, `error` and `code`. Invalid JSON/content returns 400; oversized input returns 413. The score is not a scam probability.
