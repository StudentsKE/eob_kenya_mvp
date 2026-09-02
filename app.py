from flask import Flask, request, redirect, url_for, render_template, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
import sqlite3, os, hmac, hashlib, base64
from datetime import datetime, timezone

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(APP_DIR, "eob.db")
app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("EOB_SECRET_KEY", "DEV-ONLY-CHANGE-ME")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("EOB_SECURE_COOKIES", "0") == "1"

# Passwords are not encrypted (encryption would be reversible). They use two independent
# protections: a per-password salted password hash plus a server-side pepper.
PASSWORD_PEPPER = os.environ.get("EOB_PASSWORD_PEPPER", "DEV-ONLY-CHANGE-THIS-PEPPER").encode()
FIELD_KEY = os.environ.get("EOB_FIELD_ENCRYPTION_KEY", "")
if not FIELD_KEY:
    seed = os.environ.get("EOB_FIELD_ENCRYPTION_SEED", "")
    if seed:
        FIELD_KEY = base64.urlsafe_b64encode(hashlib.sha256(seed.encode()).digest()).decode()
    else:
        key_file = os.path.join(APP_DIR, ".field_key")
        if os.path.exists(key_file):
            FIELD_KEY = open(key_file, "r", encoding="utf-8").read().strip()
        else:
            FIELD_KEY = Fernet.generate_key().decode()
            with open(key_file, "w", encoding="utf-8") as fh:
                fh.write(FIELD_KEY)
            try: os.chmod(key_file, 0o600)
            except OSError: pass
FIELD_FERNET = Fernet(FIELD_KEY.encode())

def password_material(password):
    return hmac.new(PASSWORD_PEPPER, password.encode(), hashlib.sha256).hexdigest()

def make_password_hash(password):
    return generate_password_hash(password_material(password), method="scrypt")

def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password_material(password))

def encrypt_field(value):
    return FIELD_FERNET.encrypt(value.encode()).decode() if value else ""

def decrypt_field(value):
    if not value: return ""
    try: return FIELD_FERNET.decrypt(value.encode()).decode()
    except InvalidToken: return "[encrypted value unavailable]"

def mask_identifier(value):
    if not value: return "—"
    clean=value.strip()
    return "•" * max(0, len(clean)-4) + clean[-4:]


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL, station_id INTEGER, active INTEGER NOT NULL DEFAULT 1, force_password_change INTEGER NOT NULL DEFAULT 1,
 FOREIGN KEY(station_id) REFERENCES stations(id)
);
CREATE TABLE IF NOT EXISTS stations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, county TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS occurrences (
 id INTEGER PRIMARY KEY AUTOINCREMENT, station_id INTEGER NOT NULL, ob_number INTEGER NOT NULL,
 occurrence_date TEXT NOT NULL, occurrence_time TEXT NOT NULL, category TEXT NOT NULL, location TEXT NOT NULL,
 reporter_name TEXT NOT NULL, identification_type TEXT, identification_reference_enc TEXT, identification_reference_last4 TEXT, narrative TEXT NOT NULL, action_taken TEXT, status TEXT NOT NULL DEFAULT 'OPEN',
 assigned_officer_id INTEGER, created_by INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(station_id) REFERENCES stations(id), FOREIGN KEY(created_by) REFERENCES users(id),
 FOREIGN KEY(assigned_officer_id) REFERENCES users(id), UNIQUE(station_id, ob_number)
);
CREATE TABLE IF NOT EXISTS occurrence_versions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, occurrence_id INTEGER NOT NULL, version_no INTEGER NOT NULL,
 occurrence_date TEXT NOT NULL, occurrence_time TEXT NOT NULL, category TEXT NOT NULL, location TEXT NOT NULL,
 reporter_name TEXT NOT NULL, identification_type TEXT, identification_reference_enc TEXT, identification_reference_last4 TEXT, narrative TEXT NOT NULL, action_taken TEXT, status TEXT NOT NULL,
 changed_by INTEGER NOT NULL, changed_at TEXT NOT NULL, reason TEXT NOT NULL,
 FOREIGN KEY(occurrence_id) REFERENCES occurrences(id), FOREIGN KEY(changed_by) REFERENCES users(id),
 UNIQUE(occurrence_id, version_no)
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL, entity_type TEXT NOT NULL,
 entity_id INTEGER, created_at TEXT NOT NULL, details TEXT
);
"""

CATEGORIES = ["General Report", "Crime Report", "Traffic Incident", "Missing Person", "Arrest", "Police Action", "Other"]
STATUSES = ["OPEN", "UNDER REVIEW", "ASSIGNED", "CLOSED"]
ROLES = ["ADMIN", "OB_OFFICER", "SUPERVISOR"]

ROLE_LABELS = {"ADMIN": "Administrator", "OB_OFFICER": "OB Officer", "SUPERVISOR": "Supervisor"}

def db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def column_exists(conn, table, column):
    return any(r[1] == column for r in conn.execute(f"PRAGMA table_info({table})").fetchall())

def init_db():
    conn = db()
    conn.executescript(SCHEMA)
    # Upgrade databases created by the original MVP.
    for col, definition in [("assigned_officer_id", "INTEGER"), ("updated_at", "TEXT"), ("force_password_change", "INTEGER NOT NULL DEFAULT 1"), ("identification_type", "TEXT"), ("identification_reference_enc", "TEXT"), ("identification_reference_last4", "TEXT")]:
        if not column_exists(conn, "occurrences", col):
            conn.execute(f"ALTER TABLE occurrences ADD COLUMN {col} {definition}")
    conn.execute("UPDATE occurrences SET updated_at=COALESCE(updated_at,created_at)")
    for col, definition in [("identification_type", "TEXT"), ("identification_reference_enc", "TEXT"), ("identification_reference_last4", "TEXT")]:
        if not column_exists(conn, "occurrence_versions", col):
            conn.execute(f"ALTER TABLE occurrence_versions ADD COLUMN {col} {definition}")
    if conn.execute("SELECT COUNT(*) FROM stations").fetchone()[0] == 0:
        conn.execute("INSERT INTO stations(code,name,county) VALUES(?,?,?)", ("DEMO-001", "Demo Police Station", "Demo County"))
    station_id = conn.execute("SELECT id FROM stations ORDER BY id LIMIT 1").fetchone()["id"]
    users = [("admin", "ChangeMe123!", "ADMIN", station_id), ("obofficer", "ChangeMe123!", "OB_OFFICER", station_id), ("supervisor", "ChangeMe123!", "SUPERVISOR", station_id)]
    for username, password, role, sid in users:
        if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            conn.execute("INSERT INTO users(username,password_hash,role,station_id) VALUES(?,?,?,?)", (username, make_password_hash(password), role, sid))
    conn.commit()
    seed_demo_occurrences(conn, station_id, conn.execute("SELECT id FROM users WHERE username=?", ("obofficer",)).fetchone()[0])
    conn.commit(); conn.close()

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    conn = db(); user = conn.execute("""SELECT u.*,s.name station_name,s.code station_code FROM users u LEFT JOIN stations s ON s.id=u.station_id WHERE u.id=? AND u.active=1""", (uid,)).fetchone(); conn.close()
    return user

def audit(action, entity_type, entity_id=None, details=""):
    user = current_user(); conn = db()
    conn.execute("INSERT INTO audit_log(user_id,action,entity_type,entity_id,created_at,details) VALUES(?,?,?,?,?,?)", (user["id"] if user else None, action, entity_type, entity_id, now(), details))
    conn.commit(); conn.close()

def require_login():
    user = current_user()
    if not user: return redirect(url_for("login"))
    if user["force_password_change"] and request.endpoint not in ("change_password", "logout", "static"):
        return redirect(url_for("change_password"))
    return user

def can_access(user, occurrence):
    return user["role"] == "ADMIN" or occurrence["station_id"] == user["station_id"]

def can_edit(user): return user["role"] in ("ADMIN", "OB_OFFICER", "SUPERVISOR")

@app.context_processor
def globals_for_templates():
    return {"current_user": current_user(), "categories": CATEGORIES, "statuses": STATUSES, "role_labels": ROLE_LABELS}

@app.get("/health")
def health():
    return {"status": "ok", "service": "e-OB Kenya"}, 200

@app.route("/")
def index():
    user = require_login()
    if not isinstance(user, sqlite3.Row): return user
    conn=db(); where="" if user["role"]=="ADMIN" else " WHERE o.station_id=?"; params=[] if not where else [user["station_id"]]
    total=conn.execute(f"SELECT COUNT(*) FROM occurrences o{where}",params).fetchone()[0]
    open_count=conn.execute(f"SELECT COUNT(*) FROM occurrences o{where}{' AND' if where else ' WHERE'} o.status='OPEN'",params).fetchone()[0]
    review_count=conn.execute(f"SELECT COUNT(*) FROM occurrences o{where}{' AND' if where else ' WHERE'} o.status='UNDER REVIEW'",params).fetchone()[0]
    recent=conn.execute(f"SELECT o.*,s.name station_name,u.username officer FROM occurrences o JOIN stations s ON s.id=o.station_id JOIN users u ON u.id=o.created_by{where} ORDER BY o.id DESC LIMIT 10",params).fetchall(); conn.close()
    return render_template("dashboard.html", total=total, open_count=open_count, review_count=review_count, recent=recent)

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user(): return redirect(url_for("index"))
    if request.method=="POST":
        username=request.form.get("username","").strip(); password=request.form.get("password","")
        conn=db(); u=conn.execute("SELECT * FROM users WHERE username=? AND active=1",(username,)).fetchone(); conn.close()
        if u and (verify_password(u["password_hash"], password) or check_password_hash(u["password_hash"], password)):
            session.clear(); session["user_id"]=u["id"]; audit("LOGIN","USER",u["id"],"Successful login")
            if u["force_password_change"]:
                return redirect(url_for("change_password"))
            return redirect(url_for("index"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    user = current_user()
    if not user: return redirect(url_for("login"))
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not verify_password(user["password_hash"], current):
            flash("Current password is incorrect.", "error")
        elif len(new) < 12:
            flash("New password must be at least 12 characters.", "error")
        elif new != confirm:
            flash("New passwords do not match.", "error")
        elif new == current:
            flash("New password must be different from the current password.", "error")
        else:
            conn=db(); conn.execute("UPDATE users SET password_hash=?, force_password_change=0 WHERE id=?", (make_password_hash(new), user["id"])); conn.commit(); conn.close()
            audit("PASSWORD_CHANGE", "USER", user["id"], "Password changed")
            flash("Password changed successfully.", "success")
            return redirect(url_for("index"))
    return render_template("change_password.html", forced=bool(user["force_password_change"]))

@app.route("/logout")
def logout():
    uid=session.get("user_id")
    if uid: audit("LOGOUT","USER",uid)
    session.clear(); return redirect(url_for("login"))

@app.route("/users", methods=["GET", "POST"])
def users():
    user = require_login()
    if not isinstance(user, sqlite3.Row): return user
    if user["role"] != "ADMIN": abort(403)
    conn = db()
    stations = conn.execute("SELECT * FROM stations ORDER BY name").fetchall()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        station_id = request.form.get("station_id", type=int)
        if not username or len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
        elif not password or len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif role not in ROLES:
            flash("Select a valid role.", "error")
        elif role != "ADMIN" and not station_id:
            flash("A station is required for OB Officers and Supervisors.", "error")
        elif station_id and not conn.execute("SELECT 1 FROM stations WHERE id=?", (station_id,)).fetchone():
            flash("Selected station does not exist.", "error")
        elif conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            flash("That username already exists.", "error")
        else:
            conn.execute("INSERT INTO users(username,password_hash,role,station_id,active,force_password_change) VALUES(?,?,?,?,1,1)",
                         (username, make_password_hash(password), role, station_id if role != "ADMIN" else None))
            uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()
            conn.close()
            audit("CREATE", "USER", uid, f"Created user {username} with role {role}")
            flash(f"User {username} created successfully.", "success")
            return redirect(url_for("users"))
    rows = conn.execute("""SELECT u.id,u.username,u.role,u.station_id,u.active,s.name station_name
                          FROM users u LEFT JOIN stations s ON s.id=u.station_id ORDER BY u.username""").fetchall()
    conn.close()
    return render_template("users.html", users=rows, stations=stations, roles=ROLES, role_labels=ROLE_LABELS)

@app.post("/users/<int:uid>/update")
def update_user(uid):
    user = require_login()
    if not isinstance(user, sqlite3.Row): return user
    if user["role"] != "ADMIN": abort(403)
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "")
    station_id = request.form.get("station_id", type=int)
    password = request.form.get("password", "")
    active = 1 if request.form.get("active") == "1" else 0
    if not username or len(username) < 3 or role not in ROLES:
        flash("Enter a valid username and role.", "error"); return redirect(url_for("users"))
    if role != "ADMIN" and not station_id:
        flash("A station is required for OB Officers and Supervisors.", "error"); return redirect(url_for("users"))
    conn = db()
    other = conn.execute("SELECT id FROM users WHERE username=? AND id<>?", (username, uid)).fetchone()
    target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        conn.close(); abort(404)
    if other:
        conn.close(); flash("That username already exists.", "error"); return redirect(url_for("users"))
    if uid == user["id"] and active == 0:
        conn.close(); flash("You cannot deactivate your own account.", "error"); return redirect(url_for("users"))
    if password and len(password) < 8:
        conn.close(); flash("New password must be at least 8 characters.", "error"); return redirect(url_for("users"))
    conn.execute("UPDATE users SET username=?,role=?,station_id=?,active=? WHERE id=?",
                 (username, role, station_id if role != "ADMIN" else None, active, uid))
    if password:
        conn.execute("UPDATE users SET password_hash=?, force_password_change=1 WHERE id=?", (make_password_hash(password), uid))
    conn.commit(); conn.close()
    audit("UPDATE", "USER", uid, f"Updated user {username}; role={role}; active={active}")
    flash(f"User {username} updated.", "success")
    return redirect(url_for("users"))

@app.route("/occurrences")
def occurrences():
    user=require_login()
    if not isinstance(user, sqlite3.Row): return user
    q=request.args.get("q","").strip(); category=request.args.get("category",""); status=request.args.get("status",""); date=request.args.get("date","")
    conn=db(); clauses=["1=1"]; params=[]
    if user["role"]!="ADMIN": clauses.append("o.station_id=?"); params.append(user["station_id"])
    if q: clauses.append("(CAST(o.ob_number AS TEXT) LIKE ? OR o.reporter_name LIKE ? OR o.location LIKE ? OR o.narrative LIKE ? OR o.identification_reference_last4 LIKE ? OR s.code LIKE ?)"); params += [f"%{q}%"]*6
    if category: clauses.append("o.category=?"); params.append(category)
    if status: clauses.append("o.status=?"); params.append(status)
    if date: clauses.append("o.occurrence_date=?"); params.append(date)
    rows=conn.execute(f"""SELECT o.*,s.name station_name,s.code station_code,COALESCE(u.username,'—') officer FROM occurrences o JOIN stations s ON s.id=o.station_id LEFT JOIN users u ON u.id=o.assigned_officer_id WHERE {' AND '.join(clauses)} ORDER BY o.id DESC LIMIT 500""",params).fetchall(); conn.close()
    return render_template("ob_register.html", rows=rows, q=q, category=category, status=status, date=date)

@app.route("/occurrences/new", methods=["GET","POST"])
def new_occurrence():
    user=require_login()
    if not isinstance(user, sqlite3.Row): return user
    if not can_edit(user): abort(403)
    conn=db(); stations=conn.execute("SELECT * FROM stations ORDER BY name").fetchall(); officers=conn.execute("SELECT id,username,role,station_id FROM users WHERE active=1 AND role IN ('OB_OFFICER','SUPERVISOR') ORDER BY username").fetchall(); conn.close()
    if request.method=="POST":
        data={k:request.form.get(k,"").strip() for k in ["occurrence_date","occurrence_time","category","location","reporter_name","identification_type","identification_reference","narrative","action_taken"]}
        station_id=user["station_id"] if user["role"]!="ADMIN" else request.form.get("station_id", type=int)
        if not station_id or not all([data["occurrence_date"],data["occurrence_time"],data["category"],data["location"],data["reporter_name"],data["narrative"]]) or (data["identification_type"] and not data["identification_reference"]) or data["category"] not in CATEGORIES:
            flash("Please complete all required fields.","error"); return render_template("new_occurrence.html", stations=stations, officers=officers, form=request.form)
        conn=db()
        # Atomic enough for the local SQLite MVP: transaction locks the writer before choosing the next number.
        conn.execute("BEGIN IMMEDIATE")
        ob=conn.execute("SELECT COALESCE(MAX(ob_number),0)+1 FROM occurrences WHERE station_id=?",(station_id,)).fetchone()[0]
        created=now()
        id_last4=data["identification_reference"][-4:] if data["identification_reference"] else ""
        id_enc=encrypt_field(data["identification_reference"])
        conn.execute("""INSERT INTO occurrences(station_id,ob_number,occurrence_date,occurrence_time,category,location,reporter_name,identification_type,identification_reference_enc,identification_reference_last4,narrative,action_taken,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(station_id,ob,data["occurrence_date"],data["occurrence_time"],data["category"],data["location"],data["reporter_name"],data["identification_type"] or None,id_enc,id_last4,data["narrative"],data["action_taken"],"OPEN",user["id"],created,created))
        oid=conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("""INSERT INTO occurrence_versions(occurrence_id,version_no,occurrence_date,occurrence_time,category,location,reporter_name,identification_type,identification_reference_enc,identification_reference_last4,narrative,action_taken,status,changed_by,changed_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(oid,1,data["occurrence_date"],data["occurrence_time"],data["category"],data["location"],data["reporter_name"],data["identification_type"] or None,id_enc,id_last4,data["narrative"],data["action_taken"],"OPEN",user["id"],created,"Initial entry"))
        conn.commit(); conn.close(); audit("CREATE","OCCURRENCE",oid,f"Created OB {ob}"); flash(f"Occurrence OB {ob} created.","success"); return redirect(url_for("occurrence",oid=oid))
    return render_template("new_occurrence.html", stations=stations, officers=officers, form={})

@app.route("/occurrences/<int:oid>")
def occurrence(oid):
    user=require_login()
    if not isinstance(user, sqlite3.Row): return user
    conn=db(); o=conn.execute("""SELECT o.*,s.name station_name,s.code station_code,c.username created_by_name,a.username assigned_officer FROM occurrences o JOIN stations s ON s.id=o.station_id JOIN users c ON c.id=o.created_by LEFT JOIN users a ON a.id=o.assigned_officer_id WHERE o.id=?""",(oid,)).fetchone()
    if not o: abort(404)
    if not can_access(user,o): abort(403)
    logs=conn.execute("SELECT l.*,u.username FROM audit_log l LEFT JOIN users u ON u.id=l.user_id WHERE l.entity_type='OCCURRENCE' AND l.entity_id=? ORDER BY l.id",(oid,)).fetchall()
    versions=conn.execute("SELECT v.*,u.username FROM occurrence_versions v JOIN users u ON u.id=v.changed_by WHERE v.occurrence_id=? ORDER BY v.version_no DESC",(oid,)).fetchall()
    officers=conn.execute("SELECT id,username,role FROM users WHERE active=1 AND role IN ('OB_OFFICER','SUPERVISOR') AND station_id=? ORDER BY username",(o['station_id'],)).fetchall()
    o = dict(o); o["identification_reference"] = decrypt_field(o.get("identification_reference_enc")); o["identification_masked"] = mask_identifier(o["identification_reference"])
    conn.close(); return render_template("ob_details.html",o=o,logs=logs,versions=versions,officers=officers)

@app.route("/occurrences/<int:oid>/amend", methods=["GET","POST"])
def amend_occurrence(oid):
    user=require_login()
    if not isinstance(user, sqlite3.Row): return user
    if not can_edit(user): abort(403)
    conn=db(); o=conn.execute("SELECT * FROM occurrences WHERE id=?",(oid,)).fetchone(); conn.close()
    if not o: abort(404)
    if not can_access(user,o): abort(403)
    if request.method=="POST":
        reason=request.form.get("reason","").strip()
        data={k:request.form.get(k,"").strip() for k in ["occurrence_date","occurrence_time","category","location","reporter_name","identification_type","identification_reference","narrative","action_taken","status"]}
        if not reason or not all(data[k] for k in ["occurrence_date","occurrence_time","category","location","reporter_name","narrative","status"]) or (data["identification_type"] and not data["identification_reference"]) or data["category"] not in CATEGORIES or data["status"] not in STATUSES:
            flash("A reason and all required amended fields are required.","error")
            return render_template("amend_occurrence.html",o={**dict(o),**data},reason=reason)
        conn=db(); conn.execute("BEGIN IMMEDIATE")
        version=conn.execute("SELECT COALESCE(MAX(version_no),0)+1 FROM occurrence_versions WHERE occurrence_id=?",(oid,)).fetchone()[0]; changed=now()
        id_last4=data["identification_reference"][-4:] if data["identification_reference"] else ""
        id_enc=encrypt_field(data["identification_reference"])
        conn.execute("""UPDATE occurrences SET occurrence_date=?,occurrence_time=?,category=?,location=?,reporter_name=?,identification_type=?,identification_reference_enc=?,identification_reference_last4=?,narrative=?,action_taken=?,status=?,updated_at=? WHERE id=?""",(data["occurrence_date"],data["occurrence_time"],data["category"],data["location"],data["reporter_name"],data["identification_type"] or None,id_enc,id_last4,data["narrative"],data["action_taken"],data["status"],changed,oid))
        conn.execute("""INSERT INTO occurrence_versions(occurrence_id,version_no,occurrence_date,occurrence_time,category,location,reporter_name,identification_type,identification_reference_enc,identification_reference_last4,narrative,action_taken,status,changed_by,changed_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(oid,version,data["occurrence_date"],data["occurrence_time"],data["category"],data["location"],data["reporter_name"],data["identification_type"] or None,id_enc,id_last4,data["narrative"],data["action_taken"],data["status"],user["id"],changed,reason))
        conn.commit(); conn.close(); audit("AMEND","OCCURRENCE",oid,f"Version {version}: {reason}"); flash(f"OB {o['ob_number']} amended as version {version}.","success"); return redirect(url_for("occurrence",oid=oid))
    return render_template("amend_occurrence.html",o=o,reason="")

@app.route("/ui/register")
def ui_register():
    return redirect(url_for("occurrences"))

@app.route("/ui/ob/<int:oid>")
def ui_ob_details(oid):
    return redirect(url_for("occurrence", oid=oid))

@app.route("/ui/ob/<int:oid>/amend", methods=["GET", "POST"])
def ui_amend(oid):
    return amend_occurrence(oid)

@app.post("/occurrences/<int:oid>/assign")
def assign_officer(oid):
    user=require_login()
    if not isinstance(user, sqlite3.Row): return user
    if user["role"] not in ("ADMIN","SUPERVISOR"): abort(403)
    officer_id=request.form.get("officer_id", type=int)
    conn=db(); o=conn.execute("SELECT * FROM occurrences WHERE id=?",(oid,)).fetchone(); officer=conn.execute("SELECT * FROM users WHERE id=? AND active=1 AND role IN ('OB_OFFICER','SUPERVISOR')",(officer_id,)).fetchone() if officer_id else None
    if not o or not can_access(user,o) or not officer or (user["role"]!="ADMIN" and officer["station_id"]!=user["station_id"]): conn.close(); abort(400)
    conn.execute("UPDATE occurrences SET assigned_officer_id=?,status='ASSIGNED',updated_at=? WHERE id=?",(officer_id,now(),oid)); conn.commit(); conn.close(); audit("ASSIGN","OCCURRENCE",oid,f"Assigned to {officer['username']}"); flash("Officer assigned.","success"); return redirect(url_for("occurrence",oid=oid))

@app.post("/occurrences/<int:oid>/action")
def record_action(oid):
    user=require_login()
    if not isinstance(user, sqlite3.Row): return user
    if not can_edit(user): abort(403)
    text=request.form.get("action_taken","").strip()
    if not text: flash("Action text is required.","error"); return redirect(url_for("occurrence",oid=oid))
    conn=db(); o=conn.execute("SELECT * FROM occurrences WHERE id=?",(oid,)).fetchone()
    if not o or not can_access(user,o): conn.close(); abort(403)
    new_status=request.form.get("status",o["status"])
    if new_status not in STATUSES: new_status=o["status"]
    # Actions are appended through a new version, preserving the prior version.
    version=conn.execute("SELECT COALESCE(MAX(version_no),0)+1 FROM occurrence_versions WHERE occurrence_id=?",(oid,)).fetchone()[0]; changed=now()
    combined=(o["action_taken"] + "\n" if o["action_taken"] else "") + f"[{changed}] {text}"
    conn.execute("UPDATE occurrences SET action_taken=?,status=?,updated_at=? WHERE id=?",(combined,new_status,changed,oid))
    conn.execute("INSERT INTO occurrence_versions(occurrence_id,version_no,occurrence_date,occurrence_time,category,location,reporter_name,narrative,action_taken,status,changed_by,changed_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(oid,version,o["occurrence_date"],o["occurrence_time"],o["category"],o["location"],o["reporter_name"],o["narrative"],combined,new_status,user["id"],changed,"Recorded action"))
    conn.commit(); conn.close(); audit("ACTION","OCCURRENCE",oid,text); flash("Action recorded.","success"); return redirect(url_for("occurrence",oid=oid))

@app.post("/occurrences/<int:oid>/review")
def review_occurrence(oid):
    user=require_login()
    if not isinstance(user, sqlite3.Row): return user
    if user["role"] not in ("ADMIN","SUPERVISOR"): abort(403)
    decision=request.form.get("decision","")
    if decision not in ("UNDER REVIEW","CLOSED"): abort(400)
    conn=db(); o=conn.execute("SELECT * FROM occurrences WHERE id=?",(oid,)).fetchone()
    if not o or not can_access(user,o): conn.close(); abort(403)
    conn.execute("UPDATE occurrences SET status=?,updated_at=? WHERE id=?",(decision,now(),oid)); conn.commit(); conn.close(); audit("REVIEW","OCCURRENCE",oid,f"Status changed to {decision}"); flash(f"Occurrence marked {decision}.","success"); return redirect(url_for("occurrence",oid=oid))

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG","0")=="1", host=os.environ.get("HOST","0.0.0.0"), port=int(os.environ.get("PORT","5000")))
