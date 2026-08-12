"""
Database layer — plain sqlite3, no ORM needed for this scope.
Two tables: users (auth) and scan_history (per-user tool run log).
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "netkit.db")


def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tool TEXT NOT NULL,
            target TEXT,
            summary TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def create_user(username, password_hash):
    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, password_hash, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def log_scan(user_id, tool, target, summary):
    conn = get_db()
    conn.execute(
        "INSERT INTO scan_history (user_id, tool, target, summary, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, tool, target, summary, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_recent_scans(user_id, limit=30):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scan_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    conn.close()
    return rows


def clear_history(user_id):
    conn = get_db()
    conn.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_dashboard_stats(user_id):
    conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) c FROM scan_history WHERE user_id = ?", (user_id,)
    ).fetchone()["c"]

    by_tool = conn.execute(
        "SELECT tool, COUNT(*) c FROM scan_history WHERE user_id = ? GROUP BY tool ORDER BY c DESC",
        (user_id,),
    ).fetchall()

    by_day = conn.execute(
        """SELECT substr(created_at, 1, 10) day, COUNT(*) c
           FROM scan_history WHERE user_id = ?
           GROUP BY day ORDER BY day DESC LIMIT 14""",
        (user_id,),
    ).fetchall()

    top_targets = conn.execute(
        """SELECT target, COUNT(*) c FROM scan_history
           WHERE user_id = ? AND target IS NOT NULL AND target != ''
           GROUP BY target ORDER BY c DESC LIMIT 5""",
        (user_id,),
    ).fetchall()

    conn.close()
    return {
        "total": total,
        "by_tool": [dict(r) for r in by_tool],
        "by_day": [dict(r) for r in by_day],
        "top_targets": [dict(r) for r in top_targets],
    }


# ---- brute-force login protection ----
def record_login_attempt(ip):
    conn = get_db()
    conn.execute(
        "INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)",
        (ip, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def recent_failed_attempts(ip, minutes=10):
    conn = get_db()
    since = datetime.utcnow().timestamp() - minutes * 60
    rows = conn.execute(
        "SELECT attempted_at FROM login_attempts WHERE ip = ?", (ip,)
    ).fetchall()
    conn.close()
    count = 0
    for r in rows:
        try:
            ts = datetime.fromisoformat(r["attempted_at"]).timestamp()
            if ts > since:
                count += 1
        except ValueError:
            continue
    return count