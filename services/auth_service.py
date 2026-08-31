"""
Authentication and User Management Service for IntelAssist AI.
Implements secure local SQLite-based authentication, salted SHA-256 password hashing,
session validation, and built-in Demo Analyst access for hackathons.
"""

import os
import sqlite3
import hashlib
import secrets
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from contextlib import contextmanager
from utils.config import USERS_DIR

logger = logging.getLogger(__name__)

DB_PATH = USERS_DIR / "users.db"

class AuthService:
    """Manages user registration, authentication, roles, and session persistence."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Initialize database schema if not present."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'Security Analyst',
                    created_at TEXT NOT NULL,
                    last_login TEXT
                )
                """)
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT,
                    details TEXT,
                    timestamp TEXT
                )
                """)
                conn.commit()
            
            # Ensure default demo user exists
            self._ensure_demo_user()
        except Exception as e:
            logger.error("Failed to initialize authentication database: %s", e)

    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with PBKDF2 HMAC-SHA256 for cryptographic security."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000
        ).hex()

    def _ensure_demo_user(self):
        """Create a default Demo Security Analyst account if not exists."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = 'analyst'")
                row = cursor.fetchone()
                if not row:
                    salt = secrets.token_hex(16)
                    p_hash = self._hash_password("intelassist2026", salt)
                    now = time.strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute("""
                    INSERT INTO users (username, email, password_hash, salt, full_name, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, ("analyst", "analyst@intelassist.ai", p_hash, salt, "Lead SOC Investigator", "Senior Threat Analyst", now))
                    conn.commit()
        except Exception as e:
            logger.debug("Demo user ensure notice: %s", e)

    def register(
        self,
        username: str,
        password: str,
        email: str = "",
        full_name: str = "",
        role: str = "Security Analyst"
    ) -> Tuple[bool, str]:
        """Register a new user in the platform."""
        uname = username.strip().lower()
        if not uname or len(uname) < 3:
            return False, "Username must be at least 3 characters long."
        if not password or len(password) < 6:
            return False, "Password must be at least 6 characters long."

        display_name = full_name.strip() or uname.capitalize()
        salt = secrets.token_hex(16)
        p_hash = self._hash_password(password, salt)
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO users (username, email, password_hash, salt, full_name, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (uname, email.strip(), p_hash, salt, display_name, role, now))
                conn.commit()
            return True, "User registered successfully! You can now log in."
        except sqlite3.IntegrityError:
            return False, f"Username '{uname}' is already registered."
        except Exception as e:
            return False, f"Registration error: {str(e)}"

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user credentials and return user session dict."""
        uname = username.strip().lower()
        if not uname or not password:
            return None

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (uname,))
                row = cursor.fetchone()
                if not row:
                    return None

                salt = row["salt"]
                expected_hash = row["password_hash"]
                computed_hash = self._hash_password(password, salt)

                if secrets.compare_digest(expected_hash, computed_hash):
                    now = time.strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, row["id"]))
                    conn.commit()

                    return {
                        "user_id": row["id"],
                        "username": row["username"],
                        "email": row["email"],
                        "full_name": row["full_name"],
                        "role": row["role"],
                        "created_at": row["created_at"],
                        "authenticated": True
                    }
        except Exception as e:
            logger.error("Authentication error: %s", e)

        return None

    def get_demo_account(self) -> Dict[str, Any]:
        """Convenience method to return authenticated demo analyst session."""
        return {
            "user_id": 1,
            "username": "analyst",
            "email": "analyst@intelassist.ai",
            "full_name": "Lead SOC Investigator",
            "role": "Senior Threat Analyst",
            "created_at": time.strftime("%Y-%m-%d"),
            "authenticated": True
        }
