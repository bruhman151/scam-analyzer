# Five-minute demo

1. Run `setup.cmd` once, then `run.cmd`; open http://127.0.0.1:5000/. `/health` shows OCR availability.
2. Click **ขอ OTP**: the system normalizes separated O T P and returns HIGH with a reason.
3. Click **ข้อความปกติ**: a warning that says “ห้ามบอก OTP” has insufficient evidence and no score.
4. Choose URL, enter `https://bank.example.org@192.0.2.10/login`: actual host is 192.0.2.10, before @ is userinfo. The URL is never opened.
5. Choose image, upload `tests/fixtures/thai.png`: review extracted text, then edit and analyze again.
6. Run `python scripts/provider_simulator.py --stress 100` from the virtual environment. It sends only synthetic cases to the local API.
7. Show one error in `docs/evaluation-results.json`; explain that 36 synthetic cases do not measure real-world accuracy.
