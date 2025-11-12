# app.py
import streamlit as st
from pymongo import MongoClient
from datetime import datetime
import hashlib
import base64
import secrets as pysecrets
import pandas as pd
from bson import ObjectId
import sys
import traceback

# === IMPORTANT: set_page_config MUST be the first Streamlit command ===
st.set_page_config(page_title="City Service Tracker", layout="wide")

# --------------------
# Password helpers
# --------------------
def gen_salt(length: int = 16) -> str:
    return base64.b64encode(pysecrets.token_bytes(length)).decode("utf-8")

def hash_password(password: str, salt: str) -> str:
    """Return a base64-encoded digest for password + salt using PBKDF2-HMAC-SHA256"""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return base64.b64encode(dk).decode("utf-8")

# --------------------
# DB connection using st.secrets
# --------------------
# Now it's safe to use Streamlit decorators / calls
@st.cache_resource(ttl=600)
def get_db():
    try:
        mongo_uri = st.secrets["mongo_uri"]
    except Exception:
        st.error("Mongo URI not found in st.secrets. Please add it to .streamlit/secrets.toml (key: mongo_uri).")
        st.stop()
    try:
        client = MongoClient(mongo_uri)
        try:
            db = client.get_database()
        except Exception:
            db = client["citytracker"]
        return db
    except Exception as e:
        st.error(f"Could not connect to MongoDB: {e}")
        st.stop()

# Connect
db = get_db()
users_col = db["users"]
issues_col = db["issues"]

# --------------------
# Auto-seed default accounts (vansh user + vansh admin)
# --------------------
def seed_default_accounts():
    """
    Create two accounts if they don't exist:
      - admin: username=vansh, password=vansh, role=admin
      - user:  username=vansh, password=vansh, role=user
    This will NOT overwrite existing accounts.
    """
    accounts = [
        {"user_id": "A_VANSH", "name": "Admin Vansh", "username": "vansh", "password": "vansh", "role": "admin"},
        {"user_id": "U_VANSH", "name": "User Vansh",  "username": "vansh", "password": "vansh", "role": "user"},
    ]
    created = []
    for acc in accounts:
        try:
            exists = users_col.find_one({"username": acc["username"], "role": acc["role"]})
        except Exception:
