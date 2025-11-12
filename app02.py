# app.py
import streamlit as st
from pymongo import MongoClient
from datetime import datetime
import hashlib
import base64
import secrets as pysecrets
import pandas as pd

# For ObjectId parsing
from bson import ObjectId

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
@st.cache_resource(ttl=600)
def get_db():
    try:
        mongo_uri = st.secrets["mongo_uri"]
    except Exception:
        st.error("Mongo URI not found in st.secrets. Please add it to .streamlit/secrets.toml (key: mongo_uri).")
        st.stop()
    client = MongoClient(mongo_uri)
    # Use the database specified in the URI (if any) otherwise default to 'citytracker'
    db_name = None
    try:
        # If URI contains a default authSource/db, get_database() will use it; otherwise fallback
        db = client.get_database()
    except Exception:
        db = client["citytracker"]
    return db

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
        exists = users_col.find_one({"username": acc["username"], "role": acc["role"]})
        if exists:
            continue
        salt = gen_salt()
        pwd_hash = hash_password(acc["password"], salt)
        users_col.insert_one({
            "user_id": acc["user_id"],
            "name": acc["name"],
            "username": acc["username"],
            "password_hash": pwd_hash,
            "salt": salt,
            "role": acc["role"],
            "created_at": datetime.utcnow()
        })
        created.append(f"{acc['role']}:{acc['username']}")
    return created

# Seed on startup (safe: skips existing)
_created = seed_default_accounts()
if _created:
    st.experimental_set_query_params(_seeded=",".join(_created))  # harmless, shows seeding happened in URL params

# --------------------
# User management functions
# --------------------
def create_user(user_id: str, name: str, username: str, password: str, role: str):
    """Create a new user if username+role combo doesn't exist."""
    if users_col.find_one({"username": username, "role": role}):
        return False, "Username already exists for this role."
    salt = gen_salt()
    pwd_hash = hash_password(password, salt)
    users_col.insert_one({
        "user_id": user_id,
        "name": name,
        "username": username,
        "password_hash": pwd_hash,
        "salt": salt,
        "role": role,
        "created_at": datetime.utcnow()
    })
    return True, "User created."

def authenticate_user(username: str, password: str, role_expected: str):
    user = users_col.find_one({"username": username, "role": role_expected})
    if not user:
        return False, "No such user with this role."
    salt = user.get("salt")
    pwd_hash = hash_password(password, salt)
    if pwd_hash != user.get("password_hash"):
        return False, "Incorrect password."
    return True, user

# --------------------
# Streamlit UI
# --------------------
st.set_page_config(page_title="City Service Tracker", layout="wide")
st.title("🏙️ City Service Tracker (Streamlit + MongoDB)")

# Session state defaults
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None

# Sidebar: Authentication (Register / Login)
with st.sidebar:
    st.header("Authentication")
    mode = st.radio("Choose mode", ("Login", "Register"))
    role_choice = st.selectbox("Role", ("user", "admin"))

    if mode == "Register":
        st.subheader("Register new account")
        reg_id = st.text_input("ID", key="reg_id")
        reg_name = st.text_input("Name", key="reg_name")
        reg_username = st.text_input("Username", key="reg_username")
        reg_password = st.text_input("Password", type="password", key="reg_password")
        if st.button("Create account"):
            if not (reg_id and reg_name and reg_username and reg_password):
                st.warning("Fill all fields to register.")
            else:
                ok, msg = create_user(reg_id.strip(), reg_name.strip(), reg_username.strip(), reg_password, role_choice)
                if ok:
                    st.success(msg + " You can now login.")
                else:
                    st.error(msg)
    else:
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            if not (login_username and login_password):
                st.warning("Enter both username and password.")
            else:
                ok, result = authenticate_user(login_username.strip(), login_password, role_choice)
                if ok:
                    st.success(f"Logged in as {result['name']} ({result['role']})")
                    st.session_state.logged_in = True
                    st.session_state.user = {
                        "user_id": result.get("user_id"),
                        "name": result.get("name"),
                        "username": result.get("username"),
                        "role": result.get("role")
                    }
                else:
                    st.error(result)

    if st.session_state.logged_in:
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.experimental_rerun()

# If not logged in, show prompt and stop
if not st.session_state.logged_in:
    st.info("Please register or log in from the sidebar (choose role: user or admin).")
    # helpful hint showing seeded creds (if created on this run or already exist)
    st.write("Tip: This app auto-seeds demo accounts. You can log in with:")
    st.write("- Admin → username: `vansh`, password: `vansh`, role: `admin`")
    st.write("- User  → username: `vansh`, password: `vansh`, role: `user`")
    st.stop()

# --------------------
# Main app after login
# --------------------
user = st.session_state.user
st.markdown(f"**Logged in:** {user['name']} — Role: `{user['role']}`")

# Layout: left input, right output
col1, col2 = st.columns([1, 2])

with col1:
    st.header("Report an Issue (Input)")
    with st.form("report_form", clear_on_submit=True):
        title = st.text_input("Issue title")
        description = st.text_area("Description")
        location = st.text_input("Location (address or area)")
        priority = st.selectbox("Priority", ("Low", "Medium", "High"))
        submit_btn = st.form_submit_button("Submit Issue")

    if submit_btn:
        if not (title and description and location):
            st.warning("Please fill title, description and location.")
        else:
            doc = {
                "reporter_id": user["user_id"],
                "reporter_name": user["name"],
                "reporter_username": user["username"],
                "role": user["role"],
                "title": title.strip(),
                "description": description.strip(),
                "location": location.strip(),
                "priority": priority,
                "status": "open",
                "notes": [],
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            res = issues_col.insert_one(doc)
            st.success(f"Issue submitted (id: {res.inserted_id}).")

    st.markdown("---")
    st.write("Quick actions:")
    if user["role"] == "admin":
        if st.button("Refresh all issues"):
            st.experimental_rerun()
    else:
        if st.button("Refresh my issues"):
            st.experimental_rerun()

with col2:
    st.header("Reported Issues (Output)")

    # Admin sees all, user sees only their own
    if user["role"] == "admin":
        base_query = {}
    else:
        base_query = {"reporter_username": user["username"]}

    # Filters
    st.write("Filters:")
    fcols = st.columns(3)
    with fcols[0]:
        f_status = st.selectbox("Status", ("All", "open", "in-progress", "closed"), key="f_status")
    with fcols[1]:
        f_priority = st.selectbox("Priority", ("All", "Low", "Medium", "High"), key="f_priority")
    with fcols[2]:
        f_search = st.text_input("Search title / location", key="f_search")

    query = base_query.copy()
    if f_status != "All":
        query["status"] = f_status
    if f_priority != "All":
        query["priority"] = f_priority
    if f_search:
        query["$or"] = [
            {"title": {"$regex": f_search, "$options": "i"}},
            {"location": {"$regex": f_search, "$options": "i"}},
            {"description": {"$regex": f_search, "$options": "i"}}
        ]

    # Fetch issues
    cursor = issues_col.find(query).sort("created_at", -1).limit(500)
    issues = list(cursor)

    if not issues:
        st.info("No issues found for these filters.")
    else:
        def doc_to_row(d):
            return {
                "id": str(d.get("_id")),
                "title": d.get("title"),
                "location": d.get("location"),
                "priority": d.get("priority"),
                "status": d.get("status"),
                "reporter": d.get("reporter_name"),
                "created_at": d.get("created_at"),
                "updated_at": d.get("updated_at")
            }
        df = pd.DataFrame([doc_to_row(d) for d in issues])
        st.dataframe(df[["id", "title", "location", "priority", "status", "reporter", "created_at"]])

        st.markdown("---")
        st.subheader("Manage / View Issue")
        sel_id = st.text_input("Enter issue id to view/manage (copy from table above)")
        if st.button("Load issue"):
            try:
                oid = ObjectId(sel_id.strip())
                issue_doc = issues_col.find_one({"_id": oid})
                if not issue_doc:
                    st.error("Issue not found. Check the id.")
                else:
                    st.markdown(f"**Title:** {issue_doc.get('title')}")
                    st.markdown(f"**Description:**\n\n{issue_doc.get('description')}")
                    st.markdown(f"**Location:** {issue_doc.get('location')}")
                    st.markdown(f"**Priority:** {issue_doc.get('priority')}")
                    st.markdown(f"**Status:** {issue_doc.get('status')}")
                    st.markdown(f"**Reporter:** {issue_doc.get('reporter_name')} ({issue_doc.get('reporter_username')})")
                    st.markdown(f"**Created at:** {issue_doc.get('created_at')}")
                    st.markdown(f"**Updated at:** {issue_doc.get('updated_at')}")
                    if issue_doc.get("notes"):
                        st.markdown("**Notes:**")
                        for n in issue_doc.get("notes", []):
                            t = n.get("time")
                            author = n.get("author")
                            text = n.get("text")
                            st.write(f"- {t} — {author}: {text}")

                    # Manage / add note / change status
                    st.markdown("### Add note / Change status")
                    with st.form("manage_form"):
                        note = st.text_area("Add note (optional)")
                        try:
                            current_status = issue_doc.get("status", "open")
                            status_index = ("open", "in-progress", "closed").index(current_status)
                        except Exception:
                            status_index = 0
                        new_status = st.selectbox("Set status", ("open", "in-progress", "closed"), index=status_index)
                        submit_manage = st.form_submit_button("Save updates")
                    if submit_manage:
                        update_ops = {"$set": {"status": new_status, "updated_at": datetime.utcnow()}}
                        if note:
                            update_ops["$push"] = {"notes": {"author": user["username"], "text": note, "time": datetime.utcnow()}}
                        issues_col.update_one({"_id": issue_doc["_id"]}, update_ops)
                        st.success("Issue updated.")
                        st.experimental_rerun()

st.markdown("---")
st.caption("Demo app: uses Streamlit for UI and MongoDB for storage. Make sure to add your connection string to `.streamlit/secrets.toml`.")
