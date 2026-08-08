"""
AI CyberShield — Flask application entry point.

Educational cybersecurity toolkit: password strength analysis,
phishing URL heuristics, and file/filename threat scanning.
"""

import os
import re
import secrets
import time
from collections import defaultdict, deque

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from modules.file_scanner import scan_file
from modules.password_checker import check_password_strength
from modules.phishing_detector import detect_phishing
from modules.report_generator import generate_report

load_dotenv()

APP_VERSION = "2.0.0"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_PASSWORD_LENGTH = 256
MAX_URL_LENGTH = 2048
MAX_FILENAME_LENGTH = 512

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 30


def _require_secret_key() -> str:
    """
    Load SECRET_KEY from the environment. Refuses to silently fall back to
    a shared/guessable default — in development it auto-generates a random
    per-process key (with a warning) so the app still runs, but production
    deployments must set SECRET_KEY explicitly via .env or the environment.
    """
    key = os.getenv("SECRET_KEY", "").strip()
    if key and key != "your-secret-key-here":
        return key

    flask_env = os.getenv("FLASK_ENV", "development")
    if flask_env == "production":
        raise RuntimeError(
            "SECRET_KEY is not set. Refusing to start in production without "
            "an explicit secret key. Set SECRET_KEY in your environment or .env file."
        )

    generated = secrets.token_hex(32)
    print(
        "[AI CyberShield] WARNING: SECRET_KEY not set — using a randomly "
        "generated key for this process only. Set SECRET_KEY in .env for "
        "persistent sessions and before deploying to production."
    )
    return generated


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = _require_secret_key()
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.config["JSON_SORT_KEYS"] = False

    _register_security_headers(app)
    _register_routes(app)
    _register_error_handlers(app)

    return app


def _register_security_headers(app: Flask) -> None:
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; img-src 'self' data:;"
        )
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        return response


# ---- very small in-memory rate limiter (per-process, per-IP) ----
# Not a substitute for a real rate limiter (e.g. Flask-Limiter + Redis) in
# a multi-worker production deployment, but prevents trivial local abuse
# of the analysis endpoints without adding an external dependency.
_request_log: dict = defaultdict(deque)


def _rate_limited(key: str) -> bool:
    now = time.time()
    log = _request_log[key]
    while log and now - log[0] > RATE_LIMIT_WINDOW_SECONDS:
        log.popleft()
    if len(log) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    log.append(now)
    return False


def _client_key() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _register_routes(app: Flask) -> None:
    @app.before_request
    def apply_rate_limit():
        if request.path.startswith("/api/"):
            if _rate_limited(_client_key()):
                return jsonify({"error": "Too many requests. Please slow down and try again shortly."}), 429

    @app.route("/")
    def index():
        return render_template("index.html", app_version=APP_VERSION)

    @app.route("/api/check-password", methods=["POST"])
    def api_check_password():
        data = request.get_json(silent=True) or {}
        password = data.get("password", "")

        if not isinstance(password, str) or not password:
            return jsonify({"error": "Password is required"}), 400
        if len(password) > MAX_PASSWORD_LENGTH:
            return jsonify({"error": f"Password must be {MAX_PASSWORD_LENGTH} characters or fewer"}), 400

        result = check_password_strength(password)
        return jsonify(result), 200

    @app.route("/api/check-phishing", methods=["POST"])
    def api_check_phishing():
        data = request.get_json(silent=True) or {}
        url = data.get("url", "")

        if not isinstance(url, str) or not url.strip():
            return jsonify({"error": "URL is required"}), 400
        if len(url) > MAX_URL_LENGTH:
            return jsonify({"error": f"URL must be {MAX_URL_LENGTH} characters or fewer"}), 400

        result = detect_phishing(url)
        return jsonify(result), 200

    @app.route("/api/scan-file", methods=["POST"])
    def api_scan_file():
        """
        Accepts either:
          - JSON: {"file": "filename.exe"}  -> filename-only heuristic scan
          - multipart/form-data with a 'file' field -> filename + content scan
        Uploaded bytes are read for hashing/signature checks only. They are
        never executed, imported, written to a predictable path, or served
        back to any client.
        """
        if request.content_type and "multipart/form-data" in request.content_type:
            uploaded = request.files.get("file")
            if uploaded is None or uploaded.filename == "":
                return jsonify({"error": "No file was uploaded"}), 400
            if len(uploaded.filename) > MAX_FILENAME_LENGTH:
                return jsonify({"error": f"Filename must be {MAX_FILENAME_LENGTH} characters or fewer"}), 400

            file_bytes = uploaded.read(MAX_UPLOAD_BYTES + 1)
            if len(file_bytes) > MAX_UPLOAD_BYTES:
                return jsonify({"error": "File exceeds the 10 MB analysis limit"}), 413

            result = scan_file(uploaded.filename, file_bytes=file_bytes)
            return jsonify(result), 200

        data = request.get_json(silent=True) or {}
        filename = data.get("file", "")

        if not isinstance(filename, str) or not filename.strip():
            return jsonify({"error": "Filename is required"}), 400
        if len(filename) > MAX_FILENAME_LENGTH:
            return jsonify({"error": f"Filename must be {MAX_FILENAME_LENGTH} characters or fewer"}), 400

        result = scan_file(filename)
        return jsonify(result), 200

    @app.route("/api/security-tips", methods=["GET"])
    def api_security_tips():
        tips = {
            "tips": [
                "Use strong, unique passwords for each account",
                "Enable two-factor authentication (2FA) whenever possible",
                "Be cautious of suspicious emails and links from unknown senders",
                "Keep your software, OS, and applications updated regularly",
                "Use a reliable antivirus/anti-malware solution",
                "Regularly back up important data to secure locations",
                "Never share personal information online unless necessary",
                "Use a password manager to store complex passwords securely",
                "Only use HTTPS websites (look for the padlock icon)",
                "Verify sender identity before clicking email links",
                "Never leave devices unattended without locking them",
                "Be skeptical of urgent requests for sensitive information",
                "Use a VPN on public WiFi networks",
                "Educate yourself about current cyber threats",
                "Contact IT support if you suspect a security breach",
            ],
            "count": 15,
            "generated_at": "AI CyberShield Platform",
            "version": APP_VERSION,
        }
        return jsonify(tips), 200

    @app.route("/api/generate-report", methods=["POST"])
    def api_generate_report():
        """
        Expected JSON: {"password_result": {...}, "phishing_result": {...}, "file_result": {...}}
        Any of the three may be omitted; the report reflects only what's provided.
        """
        data = request.get_json(silent=True) or {}
        report = generate_report(
            password_result=data.get("password_result"),
            phishing_result=data.get("phishing_result"),
            file_result=data.get("file_result"),
        )
        return jsonify(report), 200

    @app.route("/api/health", methods=["GET"])
    def api_health():
        return jsonify({"status": "ok", "version": APP_VERSION}), 200


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(_error):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"error": "Upload too large"}), 413

    @app.errorhandler(429)
    def too_many_requests(_error):
        return jsonify({"error": "Too many requests. Please slow down and try again shortly."}), 429

    @app.errorhandler(500)
    def server_error(_error):
        return jsonify({"error": "Internal server error"}), 500


app = create_app()


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").strip().lower() in ("1", "true", "yes")
    host = os.getenv("HOST", "127.0.0.1")  # localhost by default; set HOST=0.0.0.0 explicitly if needed
    port = int(os.getenv("PORT", "5000"))

    app.run(debug=debug_mode, host=host, port=port, threaded=True)
