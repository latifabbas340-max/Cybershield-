# AI CyberShield

AI CyberShield is an educational Flask cybersecurity toolkit with three analysis tools and a session-level security report:

- **Password strength analysis** — composition scoring, entropy estimate, breach/common-password detection, keyboard-walk and sequence detection, and an educational crack-time estimate.
- **Phishing URL detection** — 13 weighted heuristics: IP-address hosts, punycode/IDN spoofing, typosquatting against major brands, `@`-obfuscation, excessive subdomains, non-standard ports, and more.
- **File threat scanning** — filename heuristics (double extensions, RTLO tricks, suspicious naming patterns) plus **real content inspection**: uploaded files are hashed (SHA-256) and checked against magic-byte signatures to catch extension/content mismatches (e.g. a `.txt` that's actually a Windows executable). Files are read for inspection only — **never executed, parsed as code, or persisted to disk**.
- **Session security report** — aggregates whatever checks you've actually run into one composite score. No fabricated data.

## What's new in v2

- Fixed the original double-extension detector, which incorrectly flagged any filename with 2+ dots (e.g. `report.final.docx`).
- Real file-content scanning via magic-byte signatures, not just filename guessing.
- The "generate report" endpoint now reflects real scan results instead of a hardcoded score.
- Hardened Flask config: no default secret key, debug mode off by default, localhost-only binding by default, security headers (CSP, X-Frame-Options, etc.), basic per-IP rate limiting, and request size/length limits on every input.
- Wired up the password module's crack-time estimator, which existed in v1 but was never called.
- Full automated test suite (`tests/`) covering all three modules and every API route.

## Project structure

```text
AI-CyberShield/
├── app.py
├── modules/
│   ├── __init__.py
│   ├── password_checker.py
│   ├── phishing_detector.py
│   ├── file_scanner.py
│   └── report_generator.py
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── script.js
├── tests/
│   ├── test_password_checker.py
│   ├── test_phishing_detector.py
│   ├── test_file_scanner.py
│   └── test_app.py
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Setup

Python 3.10+ recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Then open `http://127.0.0.1:5000`.

### Configuration (`.env`)

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | *(none)* | Required in production. Auto-generated per run in development if left blank. |
| `FLASK_ENV` | `development` | Set to `production` to require `SECRET_KEY` and fail fast without it. |
| `FLASK_DEBUG` | `false` | Never enable in production — Flask's debugger allows remote code execution if exposed. |
| `HOST` | `127.0.0.1` | Bind address. Only set to `0.0.0.0` behind a firewall/reverse proxy. |
| `PORT` | `5000` | |

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

## Deploying

The built-in `app.run()` server is for local development only. For production, run behind a real WSGI server:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

Put it behind a reverse proxy (nginx, Caddy) that terminates TLS, and set `FLASK_ENV=production` with an explicit `SECRET_KEY`.

## Important

This is a heuristic educational project. It does not prove that a file or URL is safe, and heuristic scores are illustrative, not guarantees. It does not replace antivirus software, malware sandboxes, domain reputation services, or professional threat intelligence. The crack-time estimate is a simplified educational model, not a precise prediction — real-world crack time depends on the hashing algorithm, salting, and attacker resources.

