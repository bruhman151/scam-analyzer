# Research to rules

Checked 5 October 2026. Rules are our interpretations of official guidance, not official classifiers. The examples and OCR images are synthetic.

| Source | Described tactic | Rule IDs | Key limitation |
|---|---|---|---|
| [Bank of Thailand: online fraud](https://www.bot.or.th/th/satang-story/fraud/online-fraud.html) | Account problem, fake link, credentials | `account_threat`, `link_with_account_action`, `requests_secret` | Legitimate notices can mention account issues |
| [Bank of Thailand: call centre fraud](https://www.bot.or.th/th/satang-story/fraud/call-center.html) | Authority impersonation, investigation, transfer | `authority_transfer`, `requests_transfer`, `fear_or_urgency` | Authority words alone do not score |
| [FTC: phishing](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams) | Credential or personal-data requests | `requests_secret`, `requests_personal_data` | No live identity check |
| [FTC: task scams](https://consumer.ftc.gov/consumer-alerts/2024/11/task-scams-create-illusion-making-money) | Fake earnings then deposit before withdrawal | `task_deposit` | Requires fairly explicit wording |
| [FTC: job scams](https://consumer.ftc.gov/articles/job-scams) | Upfront payment for work | `advance_fee`, `task_deposit` | Legitimate job deposits exist |
| [FTC: tech support scams](https://consumer.ftc.gov/articles/how-spot-avoid-and-report-tech-support-scams) | Unexpected remote-control request | `remote_access`, `remote_access_pressure` | Legitimate IT can use remote tools |
| [FTC: investment scams](https://consumer.ftc.gov/articles/investment-scams) | Guaranteed profits / no risk | `guaranteed_returns` | Education can quote the same promise |
| [OWASP file upload guidance](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | Validate content, bounds and image decoding | OCR size/pixel/time limits | Local-only service |
| [Tesseract installation](https://tesseract-ocr.github.io/tessdoc/Installation.html) | Local engine + language data | `ocr.py` | OCR can misread Thai |

`rules.py` is the versioned indicator list. Add a source and both positive and negative synthetic examples when changing it. Urgency, bank names and URL presence alone are weak context. The score is a chosen heuristic, not a probability. No real private messages, OTPs, phone numbers or victim screenshots are included.

URL checks parse the actual hostname, userinfo, punycode, shortener and unusually long hosts. They never fetch a destination, look up DNS or prove ownership/reputation. Normalization handles Unicode and a narrow set of known obfuscations; arbitrary fuzzy matching was excluded because it can create unrelated matches.
