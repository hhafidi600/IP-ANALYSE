"""
Lightweight security helpers — deliberately dependency-free so the app
stays a single `pip install flask` away from running anywhere.
"""

import time
import secrets
from functools import wraps
from flask import session, request, jsonify, abort

# ---------------------------------------------------------------- rate limiting
# In-memory sliding window: {(ip, bucket): [timestamps]}
# Fine for a single-process app; swap for Redis-backed limiting if you
# ever run multiple worker processes behind a load balancer.
_hits = {}


def rate_limit(bucket, max_requests=20, window_seconds=60):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
            key = (ip, bucket)
            now = time.time()
            timestamps = [t for t in _hits.get(key, []) if now - t < window_seconds]
            if len(timestamps) >= max_requests:
                return jsonify({"ok": False, "error": "Too many requests — slow down and try again shortly."}), 429
            timestamps.append(now)
            _hits[key] = timestamps
            return fn(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------- auth guard
def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Not authenticated"}), 401
            from flask import redirect, url_for
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------- CSRF
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)
    return session["csrf_token"]


def csrf_protect(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        validate_csrf_or_abort()
        return fn(*args, **kwargs)
    return wrapped


def validate_csrf_or_abort():
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or token != session.get("csrf_token"):
        abort(400, "Invalid or missing CSRF token")


# ---------------------------------------------------------------- security headers
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
        "font-src fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "connect-src 'self'"
    )
    return response