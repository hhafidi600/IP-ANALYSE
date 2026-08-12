#!/usr/bin/env python3
"""
NETKIT — Network & IP Analyzer, with accounts, history, and a dashboard.

Run:
    python app.py
Then open http://127.0.0.1:5000
"""

import os
import secrets

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

import db
import net_tools
from security import rate_limit, login_required, get_csrf_token, validate_csrf_or_abort, apply_security_headers

app = Flask(__name__)

# ---------------------------------------------------------------- secret key
# A stable secret key so sessions survive restarts. Set FLASK_SECRET_KEY
# yourself in production; otherwise one is generated and cached locally.
SECRET_KEY_PATH = os.path.join(os.path.dirname(__file__), "instance", "secret.key")
if os.environ.get("FLASK_SECRET_KEY"):
    app.secret_key = os.environ["FLASK_SECRET_KEY"]
else:
    os.makedirs(os.path.dirname(SECRET_KEY_PATH), exist_ok=True)
    if os.path.exists(SECRET_KEY_PATH):
        app.secret_key = open(SECRET_KEY_PATH).read().strip()
    else:
        key = secrets.token_hex(32)
        with open(SECRET_KEY_PATH, "w") as f:
            f.write(key)
        app.secret_key = key

PRODUCTION = os.environ.get("PRODUCTION", "0") == "1"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=PRODUCTION,  # requires HTTPS when True
)

db.init_db()
app.after_request(apply_security_headers)


# ================================================================== AUTH
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", csrf_token=get_csrf_token())

    validate_csrf_or_abort()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if len(username) < 3 or len(password) < 8:
        return render_template(
            "register.html", csrf_token=get_csrf_token(),
            error="Username must be 3+ characters and password 8+ characters.",
        )

    if db.get_user_by_username(username):
        return render_template("register.html", csrf_token=get_csrf_token(), error="That username is taken.")

    db.create_user(username, generate_password_hash(password))
    user = db.get_user_by_username(username)
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", csrf_token=get_csrf_token())

    validate_csrf_or_abort()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

    if db.recent_failed_attempts(ip) >= 8:
        return render_template(
            "login.html", csrf_token=get_csrf_token(),
            error="Too many failed attempts. Wait a few minutes and try again.",
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    user = db.get_user_by_username(username)

    if not user or not check_password_hash(user["password_hash"], password):
        db.record_login_attempt(ip)
        return render_template("login.html", csrf_token=get_csrf_token(), error="Invalid username or password.")

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ================================================================== PAGES
@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get("username"))


@app.route("/dashboard")
@login_required
def dashboard():
    stats = db.get_dashboard_stats(session["user_id"])
    return render_template("dashboard.html", username=session.get("username"), stats=stats)


# ================================================================== API — existing tools
@app.route("/api/subnet", methods=["POST"])
@login_required
@rate_limit("subnet", max_requests=40)
def api_subnet():
    cidr = request.get_json(force=True).get("cidr", "").strip()
    try:
        result = net_tools.subnet_info(cidr)
        db.log_scan(session["user_id"], "subnet", cidr, f"{result['network']}/{result['total']} addrs")
        return jsonify({"ok": True, **result})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/ip-check", methods=["POST"])
@login_required
@rate_limit("ipcheck", max_requests=40)
def api_ip_check():
    ip_input = request.get_json(force=True).get("ip", "").strip()
    try:
        result = net_tools.ip_classify(ip_input)
        db.log_scan(session["user_id"], "ipcheck", ip_input, result["category"])
        return jsonify({"ok": True, **result})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/port-scan", methods=["POST"])
@login_required
@rate_limit("portscan", max_requests=10, window_seconds=60)
def api_port_scan():
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    mode = data.get("mode", "quick")
    try:
        result = net_tools.port_scan(target, mode, data.get("start", 1), data.get("end", 1024))
        db.log_scan(session["user_id"], "portscan", target, f"{len(result['open_ports'])} open ({mode})")
        return jsonify({"ok": True, **result})
    except socket_error_types() as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/ping-sweep", methods=["POST"])
@login_required
@rate_limit("pingsweep", max_requests=10, window_seconds=60)
def api_ping_sweep():
    network_input = request.get_json(force=True).get("network", "").strip()
    try:
        result = net_tools.ping_sweep(network_input)
        db.log_scan(session["user_id"], "pingsweep", network_input, f"{len(result['alive'])} up")
        return jsonify({"ok": True, **result})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)})


# ================================================================== API — new tools
@app.route("/api/traceroute", methods=["POST"])
@login_required
@rate_limit("traceroute", max_requests=8, window_seconds=60)
def api_traceroute():
    target = request.get_json(force=True).get("target", "").strip()
    try:
        result = net_tools.traceroute(target)
        db.log_scan(session["user_id"], "traceroute", target, "completed")
        return jsonify({"ok": True, **result})
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/dns-lookup", methods=["POST"])
@login_required
@rate_limit("dns", max_requests=30)
def api_dns_lookup():
    domain = request.get_json(force=True).get("domain", "").strip()
    try:
        result = net_tools.dns_lookup(domain)
        db.log_scan(session["user_id"], "dns", domain, f"{len(result['a_records'])} A record(s)")
        return jsonify({"ok": True, **result})
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/whois", methods=["POST"])
@login_required
@rate_limit("whois", max_requests=15)
def api_whois():
    domain = request.get_json(force=True).get("domain", "").strip()
    try:
        result = net_tools.whois_lookup(domain)
        db.log_scan(session["user_id"], "whois", domain, f"via {result['server']}")
        return jsonify({"ok": True, **result})
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)})


# ================================================================== API — history
@app.route("/api/history", methods=["GET"])
@login_required
def api_history():
    rows = db.get_recent_scans(session["user_id"])
    return jsonify({"ok": True, "history": [dict(r) for r in rows]})


@app.route("/api/history/clear", methods=["POST"])
@login_required
def api_history_clear():
    db.clear_history(session["user_id"])
    return jsonify({"ok": True})


@app.route("/api/dashboard-data", methods=["GET"])
@login_required
def api_dashboard_data():
    return jsonify({"ok": True, "stats": db.get_dashboard_stats(session["user_id"])})


def socket_error_types():
    import socket
    return (socket.gaierror, OSError)


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)