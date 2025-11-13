# app.py
import streamlit as st
from pymongo import MongoClient
from datetime import datetime, timedelta
import hashlib
import base64
import secrets as pysecrets
import pandas as pd
from bson import ObjectId
import random

# ------------------------------------------------------------------
# IMPORTANT: set_page_config must be the first Streamlit command
# ------------------------------------------------------------------
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
@st.cache_resource(ttl=600)
def get_db():
    # Read URI from Streamlit secrets
    try:
        mongo_uri = st.secrets["mongo_uri"]
    except Exception:
        st.error("Mongo URI not found in st.secrets. Please add it to .streamlit/secrets.toml (key: mongo_uri).")
        st.stop()

    # Connect to MongoDB
    try:
        client = MongoClient(mongo_uri)
    except Exception as e:
        st.error(f"Could not create MongoDB client: {e}")
        st.stop()

    # Choose DB: use DB in URI when provided, otherwise fallback
    try:
        try:
            db = client.get_database()
        except Exception:
            db = client["citytracker"]
    except Exception as e:
        st.error(f"Could not get database object: {e}")
        st.stop()

    return db

# Connect
db = get_db()
users_col = db["users"]
issues_col = db["issues"]

# --------------------
# Auto-seed default accounts (vansh admin + vansh user + new demo accounts)
# --------------------
def seed_default_accounts():
    """
    Create default accounts if they don't exist:
      - admin: username=vansh, password=vansh, role=admin
      - user:  username=vansh, password=vansh, role=user
      - admin demo: username=admin1, password=admin1, role=admin
      - user demo: username=user1, password=user1, role=user
    This will NOT overwrite existing accounts.
    """
    accounts = [
        {"user_id": "A_VANSH", "name": "Admin Vansh", "username": "vansh", "password": "vansh", "role": "admin"},
        {"user_id": "U_VANSH", "name": "User Vansh",  "username": "vansh", "password": "vansh", "role": "user"},
        {"user_id": "A_DEMO1", "name": "Admin Demo", "username": "admin1", "password": "admin1", "role": "admin"},
        {"user_id": "U_DEMO1", "name": "User Demo",  "username": "user1", "password": "user1", "role": "user"},
    ]
    created = []
    for acc in accounts:
        try:
            exists = users_col.find_one({"username": acc["username"], "role": acc["role"]})
        except Exception:
            exists = None
        if exists:
            continue
        salt = gen_salt()
        pwd_hash = hash_password(acc["password"], salt)
        try:
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
        except Exception:
            # ignore individual insertion failures
            continue
    return created

# Seed (safe to call; failures are non-fatal)
try:
    seeded_accounts = seed_default_accounts()
except Exception:
    seeded_accounts = []

# --------------------
# Seed sample issues (20 records) — idempotent
# --------------------
def seed_sample_issues(num_samples: int = 20):
    """
    Insert sample issue documents into issues_col if collection is empty.
    This function is idempotent: it only seeds when there are no documents.
    """
    try:
        count = issues_col.count_documents({})
    except Exception:
        count = 0

    if count > 0:
        return 0  # nothing seeded

    # Prepare sample content lists
    titles = [
        "Pothole on main road", "Streetlight not working", "Garbage overflow", "Blocked storm drain",
        "Graffiti on wall", "Broken park bench", "Illegal dumping", "Noisy construction at night",
        "Water leakage from hydrant", "Overgrown roadside vegetation", "Bus stop shelter damaged",
        "Traffic signal malfunction", "Flooded underpass", "Missing manhole cover", "Broken sidewalk",
        "Public toilet needs cleaning", "Road markings faded", "Abandoned vehicle", "Park fountain broken",
        "Bird nest hazard on lamp"
    ]
    descriptions = [
        "Large pothole causing danger to two-wheelers.",
        "Lamp hasn't been on for several nights near the market.",
        "Bins overflowing for more than a week at this location.",
        "Storm drain blocked causing local flooding after rain.",
        "Offensive graffiti on the east wall of community center.",
        "Bench slats are broken and unsafe for use.",
        "Someone dumped construction waste near the alley.",
        "Construction site working after 10 PM with loud noise.",
        "Water spraying continuously from hydrant, wasting water.",
        "Shrubs and grass blocking pedestrian footpath.",
        "Glass and debris inside bus shelter, risky for passengers.",
        "Signal remains green for one side causing collisions.",
        "Underpass fills with water during rains making it unusable.",
        "Manhole cover missing near the corner shop.",
        "Sidewalk lifted causing trip hazard.",
        "Public toilet stinks and lacks soap and water.",
        "Zebra crossings faded, need repainting urgently.",
        "Car abandoned here for months, blocking parking space.",
        "Fountain motor stopped; pool is stagnant.",
        "Large nest on streetlamp causing droppings on sidewalk."
    ]
    locations = [
        "Downtown Market", "5th Ave & Baker St", "Riverside Park", "Northside Underpass",
        "Old Town Square", "Greenview Colony", "Industrial Area Gate 3", "Lakeside Promenade",
        "City Bus Depot", "Central Library Entrance", "Community Center Lane", "Harbor Road",
        "Elm Street", "Pine Apartments", "Sunset Boulevard", "Hilltop Park", "Metro Station East",
        "Junction 14", "Oakwood Park", "Civic Plaza"
    ]
    priorities = ["Low", "Medium", "High"]
    statuses = ["open", "in-progress", "closed"]

    # Try to find existing users to attribute as reporters. Fallback to named strings.
    admin_user = users_col.find_one({"role": "admin"})
    normal_user = users_col.find_one({"role": "user"})
    reporter_candidates = []
    if admin_user:
        reporter_candidates.append({
            "user_id": admin_user.get("user_id", "A_ADMIN"),
            "name": admin_user.get("name", "Admin"),
            "username": admin_user.get("username", "admin"),
            "role": admin_user.get("role", "admin")
        })
    if normal_user:
        reporter_candidates.append({
            "user_id": normal_user.get("user_id", "U_USER"),
            "name": normal_user.get("name", "User"),
            "username": normal_user.get("username", "user"),
            "role": normal_user.get("role", "user")
        })
    # If none found, create fallback reporters
    if not reporter_candidates:
        reporter_candidates = [
            {"user_id": "A_SAMPLE", "name": "Sample Admin", "username": "sample_admin", "role": "admin"},
            {"user_id": "U_SAMPLE", "name": "Sample User", "username": "sample_user", "role": "user"}
        ]

    # Build sample documents
    docs = []
    now = datetime.utcnow()
    for i in range(num_samples):
        idx = i % len(titles)
        reporter = random.choice(reporter_candidates)
        created_at = now - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0,59))
        status = random.choices(statuses, weights=[0.6, 0.3, 0.1])[0]  # mostly open
        priority = random.choices(priorities, weights=[0.5, 0.35, 0.15])[0]
        doc = {
            "reporter_id": reporter["user_id"],
            "reporter_name": reporter["name"],
            "reporter_username": reporter["username"],
            "role": reporter["role"],
            "title": titles[idx],
            "description": descriptions[idx],
            "location": locations[idx],
            "priority": priority,
            "status": status,
            "notes": [],
            "created_at": created_at,
            "updated_at": created_at + timedelta(hours=random.randint(0,72))
        }
        # For some items, add a sample note or two
        if random.random() < 0.4:
            doc["notes"].append({
                "author": reporter["username"],
                "text": "Initial report added to the system.",
                "time": doc["created_at"] + timedelta(minutes=10)
            })
        if random.random() < 0.15:
            doc["notes"].append({
                "author": "city_officer",
                "text": "Assigned to maintenance team.",
                "time": doc["created_at"] + timedelta(hours=5)
            })
        docs.append(doc)

    # Insert to DB
    try:
        res = issues_col.insert_many(docs)
        return len(res.inserted_ids)
    except Exception:
        # If bulk insert fails, try inserting one-by-one
        seeded = 0
        for d in docs:
            try:
                issues_col.insert_one(d)
                seeded += 1
            except Exception:
                continue
        return seeded

# Attempt seeding; show message in UI later
try:
    seeded_count = seed_sample_issues(20)
except Exception:
    seeded_count = 0

# --------------------
# User management functions
# --------------------
def create_user(user_id: str, name: str, username: str, password: str, role: str):
    """Create a new user if username+role combo doesn't exist."""
    try:
        if users_col.find_one({"username": username, "role": role}):
            return False, "Username already exists for this role."
    except Exception as e:
        return False, f"DB error checking username: {e}"

    salt = gen_salt()
    pwd_hash = hash_password(password, salt)
    try:
        users_col.insert_one({
            "user_id": user_id,
            "name": name,
            "username": username,
            "password_hash": pwd_hash,
            "salt": salt,
            "role": role,
            "created_at": datetime.utcnow()
        })
    except Exception as e:
        return False, f"DB error creating user: {e}"
    return True, "User created."

def authenticate_user(username: str, password: str, role_expected: str):
    try:
        user = users_col.find_one({"username": username, "role": role_expected})
    except Exception as e:
        return False, f"DB error during authentication: {e}"
    if not user:
        return False, "No such user with this role."
    salt = user.get("salt")
    if not salt or not user.get("password_hash"):
        return False, "User record incomplete (no password hash)."
    pwd_hash = hash_password(password, salt)
    if pwd_hash != user.get("password_hash"):
        return False, "Incorrect password."
    return True, user

# --------------------
# Streamlit UI
# --------------------
st.title("🏙️ City Service Tracker (Streamlit + MongoDB)")

# If seeding happened, show a small note
if seeded_count:
    st.success(f"Seeded {seeded_count} sample issues into the database for demo/testing.")

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

    # Logout button (visible only when logged in)
    if st.session_state.logged_in:
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.experimental_rerun()

# If not logged in, show prompt and stop
if not st.session_state.logged_in:
    st.info("Please register or log in from the sidebar (choose role: user or admin).")
    # show seeded info if seeding created accounts
    if seeded_accounts:
        st.write("Auto-seeded accounts (if missing):")
        for s in seeded_accounts:
            st.write(f"- {s}  (username: see table in code)")

    else:
        st.write("Tip: You can register a new user or admin from the sidebar.")
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
            try:
                res = issues_col.insert_one(doc)
                st.success(f"Issue submitted (id: {res.inserted_id}).")
            except Exception as e:
                st.error(f"Failed to submit issue: {e}")

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
    try:
        cursor = issues_col.find(query).sort("created_at", -1).limit(500)
        issues = list(cursor)
    except Exception as e:
        st.error(f"Failed to read issues: {e}")
        issues = []

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
            if not sel_id.strip():
                st.error("Enter an issue id first.")
            else:
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
                            try:
                                issues_col.update_one({"_id": issue_doc["_id"]}, update_ops)
                                st.success("Issue updated.")
                                st.experimental_rerun()
                            except Exception as e:
                                st.error(f"Failed to update issue: {e}")
                except Exception as e:
                    st.error(f"❌ Error loading issue: {e}")

st.markdown("---")
st.caption("Demo app: uses Streamlit for UI and MongoDB for storage. Make sure to add your connection string to `.streamlit/secrets.toml`.")
