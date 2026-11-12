import os, sqlite3, secrets, hmac
from pathlib import Path
from functools import wraps
from uuid import uuid4
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "modvault.sqlite3"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
CATEGORIES = [
    "Android game mods", "Skins and textures", "Graphics mods",
    "Gameplay mods", "Maps and worlds", "Minecraft mods", "Other game mods"
]
ALLOWED_EXTENSIONS = {
    "zip", "7z", "rar", "apk", "obb", "mcpack", "mcaddon",
    "mcworld", "jar", "pak", "png", "jpg", "jpeg", "webp"
}

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS mods (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            downloads INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

def check_csrf():
    supplied = request.form.get("_csrf", "")
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        abort(400, "Invalid form token. Refresh and try again.")

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    return response

@app.route("/")
def home():
    category = request.args.get("category", "All")
    search = request.args.get("q", "").strip()
    query = "SELECT * FROM mods WHERE 1=1"
    params = []
    if category in CATEGORIES:
        query += " AND category=?"
        params.append(category)
    if search:
        query += " AND (name LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    query += " ORDER BY created_at DESC"
    with db() as conn:
        mods = conn.execute(query, params).fetchall()
        total_mods = conn.execute("SELECT COUNT(*) FROM mods").fetchone()[0]
        total_downloads = conn.execute("SELECT COALESCE(SUM(downloads),0) FROM mods").fetchone()[0]
    return render_template("index.html", mods=mods, categories=CATEGORIES,
                           selected=category, search=search,
                           total_mods=total_mods, total_downloads=total_downloads)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        if not ADMIN_PASSWORD:
            flash("Admin password is not configured on the server.", "error")
        else:
            supplied = request.form.get("password", "")
            if hmac.compare_digest(supplied, ADMIN_PASSWORD):
                session.clear()
                session["is_admin"] = True
                session["_csrf"] = secrets.token_urlsafe(32)
                return redirect(url_for("admin"))
            flash("Incorrect password.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@admin_required
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("home"))

@app.route("/admin")
@admin_required
def admin():
    with db() as conn:
        mods = conn.execute("SELECT * FROM mods ORDER BY created_at DESC").fetchall()
    return render_template("admin.html", mods=mods, categories=CATEGORIES)

@app.route("/upload", methods=["POST"])
@admin_required
def upload():
    check_csrf()
    file = request.files.get("file")
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    category = request.form.get("category", "")
    if not file or not file.filename or not name:
        flash("Enter a mod name and choose a file.", "error")
        return redirect(url_for("admin"))
    original = Path(file.filename).name
    if not allowed_file(original):
        flash("That file type is not allowed.", "error")
        return redirect(url_for("admin"))
    if category not in CATEGORIES:
        flash("Choose a valid category.", "error")
        return redirect(url_for("admin"))
    ext = original.rsplit(".", 1)[1].lower()
    stored = f"{uuid4().hex}.{ext}"
    destination = UPLOAD_DIR / stored
    file.save(destination)
    try:
        with db() as conn:
            conn.execute("""INSERT INTO mods
                (id,name,description,category,filename,original_filename,size_bytes)
                VALUES (?,?,?,?,?,?,?)""",
                (uuid4().hex, name[:90], description[:700], category,
                 stored, original[:180], destination.stat().st_size))
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    flash("Mod uploaded successfully.", "success")
    return redirect(url_for("admin"))

@app.route("/download/<mod_id>")
def download(mod_id):
    with db() as conn:
        mod = conn.execute("SELECT * FROM mods WHERE id=?", (mod_id,)).fetchone()
        if not mod:
            abort(404)
        path = UPLOAD_DIR / mod["filename"]
        if not path.is_file():
            abort(404)
        conn.execute("UPDATE mods SET downloads=downloads+1 WHERE id=?", (mod_id,))
    return send_from_directory(str(UPLOAD_DIR), mod["filename"],
                               as_attachment=True,
                               download_name=mod["original_filename"])

@app.route("/delete/<mod_id>", methods=["POST"])
@admin_required
def delete(mod_id):
    check_csrf()
    with db() as conn:
        mod = conn.execute("SELECT * FROM mods WHERE id=?", (mod_id,)).fetchone()
        if not mod:
            abort(404)
        (UPLOAD_DIR / mod["filename"]).unlink(missing_ok=True)
        conn.execute("DELETE FROM mods WHERE id=?", (mod_id,))
    flash("Mod deleted.", "success")
    return redirect(url_for("admin"))

@app.errorhandler(413)
def too_large(_error):
    flash("File too large. Maximum upload size is 500 MB.", "error")
    return redirect(url_for("admin" if session.get("is_admin") else "home"))

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
