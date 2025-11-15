import os
import sqlite3
import hashlib
import base64
import time 
from typing import Optional, Tuple

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

DATA_DIR = "data"
DB_PATH = os.path.join(DATA_DIR, "marschain.db")

def get_fernet() -> Fernet:
    secret = os.environ.get("MARSCHAIN_MASTER_KEY", "dev-secret-change-me")
    digest = hashlib.sha256(secret.encode("UTF-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)

def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            enc_seed TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )"""
    )
    conn.commit()
    conn.close()

def encrypt_seed(seed: str) -> str:
    f = get_fernet()
    return f.encrypt(seed.encode("utf-8")).decode("utf-8")

def decrypt_seed(enc: str) -> str:
    f = get_fernet()
    return f.decrypt(enc.encode("utf-8")).decode("utf-8")

def create_user(username: str, password: str, seed_phrase: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    enc = encrypt_seed(seed_phrase)
    pw_hash = generate_password_hash(password)
    cur.execute(
        "INSERT INTO users (username, password_hash, enc_seed, created_at) VALUES (?,?,?,?)",
        (username, pw_hash, enc, int(time.time())),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id

def get_user_by_username(username: str) -> Optional[Tuple[int, str, str, str]]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, enc_seed FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def get_user_by_id(user_id: int) -> Optional[Tuple[int, str, str]]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username, enc_seed FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row

def verify_password(pw_hash: str, password: str) -> bool:
    return check_password_hash(pw_hash, password)
