import os, sqlite3, secrets, hmac, re
from pathlib import Path
from functools import wraps
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('DATA_DIR', str(BASE_DIR / 'data')))
UPLOAD_DIR = DATA_DIR / 'uploads'
IMAGE_DIR = UPLOAD_DIR / 'images'
DB_PATH = DATA_DIR / 'modvault.sqlite3'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
IMAGE_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'local-development-only-change-this-secret'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')
CATEGORIES = ['Android game mods','Skins and textures','Graphics mods','Gameplay mods','Maps and worlds','Minecraft mods','Other game mods']
MOD_EXT = {'zip','7z','rar','apk','obb','mcpack','mcaddon','mcworld','jar','pak'}
IMAGE_EXT = {'png','jpg','jpeg','webp','gif'}


def db():
    c = sqlite3.connect(DB_PATH, timeout=20)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c


def init_db():
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS mods (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
            category TEXT NOT NULL, filename TEXT NOT NULL, original_filename TEXT NOT NULL,
            size_bytes INTEGER NOT NULL, downloads INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        # Additive migrations: never drop or recreate the existing mods table.
        cols = {r['name'] for r in c.execute('PRAGMA table_info(mods)').fetchall()}
        for name, definition in {
            'game': "TEXT NOT NULL DEFAULT ''", 'version': "TEXT NOT NULL DEFAULT ''",
            'thumbnail': 'TEXT', 'featured': 'INTEGER NOT NULL DEFAULT 0'
        }.items():
            if name not in cols:
                c.execute(f'ALTER TABLE mods ADD COLUMN {name} {definition}')
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE, password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT, mod_id TEXT NOT NULL,
            user_id INTEGER NOT NULL, rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            body TEXT NOT NULL DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(mod_id,user_id), FOREIGN KEY(mod_id) REFERENCES mods(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)''')
        c.execute('''CREATE TABLE IF NOT EXISTS screenshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT, mod_id TEXT NOT NULL, filename TEXT NOT NULL,
            FOREIGN KEY(mod_id) REFERENCES mods(id) ON DELETE CASCADE)''')


def csrf_token():
    if '_csrf' not in session: session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']
app.jinja_env.globals['csrf_token'] = csrf_token


def check_csrf():
    if not hmac.compare_digest(request.form.get('_csrf',''), session.get('_csrf','x')):
        abort(400, 'Invalid form token. Refresh and try again.')


def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get('is_admin'): return redirect(url_for('login', next=request.path))
        return fn(*a, **kw)
    return wrapped


def user_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get('user_id'):
            flash('Please sign in to continue.', 'error')
            return redirect(url_for('register_login', next=request.path))
        return fn(*a, **kw)
    return wrapped


def ext_ok(filename, allowed):
    return '.' in (filename or '') and filename.rsplit('.',1)[1].lower() in allowed


def save_image(file):
    if not file or not file.filename: return None
    if not ext_ok(file.filename, IMAGE_EXT):
        raise ValueError('Images must be PNG, JPG, WEBP or GIF.')
    ext = file.filename.rsplit('.',1)[1].lower()
    stored = f'{uuid4().hex}.{ext}'
    file.save(IMAGE_DIR / stored)
    return stored


def mod_stats(mod_id):
    with db() as c:
        row = c.execute('SELECT ROUND(AVG(rating),1) avg_rating, COUNT(*) review_count FROM reviews WHERE mod_id=?',(mod_id,)).fetchone()
    return row


def get_mod(mod_id):
    with db() as c:
        m = c.execute('SELECT * FROM mods WHERE id=?',(mod_id,)).fetchone()
        if not m: abort(404)
        shots = c.execute('SELECT * FROM screenshots WHERE mod_id=? ORDER BY id',(mod_id,)).fetchall()
        reviews = c.execute('''SELECT r.*,u.username FROM reviews r JOIN users u ON u.id=r.user_id
                              WHERE r.mod_id=? ORDER BY r.created_at DESC''',(mod_id,)).fetchall()
        stats = c.execute('SELECT ROUND(AVG(rating),1) avg_rating,COUNT(*) review_count FROM reviews WHERE mod_id=?',(mod_id,)).fetchone()
    return m, shots, reviews, stats


@app.after_request
def headers(resp):
    resp.headers['X-Content-Type-Options']='nosniff'
    resp.headers['X-Frame-Options']='DENY'
    resp.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    return resp


@app.route('/')
def home():
    category=request.args.get('category','All'); q=request.args.get('q','').strip()[:100]
    sort=request.args.get('sort','new')
    sql='''SELECT m.*, ROUND((SELECT AVG(rating) FROM reviews WHERE mod_id=m.id),1) avg_rating,
           (SELECT COUNT(*) FROM reviews WHERE mod_id=m.id) review_count FROM mods m WHERE 1=1'''
    args=[]
    if category in CATEGORIES: sql+=' AND m.category=?'; args.append(category)
    if q:
        sql+=' AND (m.name LIKE ? OR m.description LIKE ? OR m.game LIKE ?)'; args += [f'%{q}%']*3
    order={'trending':'m.downloads DESC, m.created_at DESC','rated':'avg_rating DESC, review_count DESC','old':'m.created_at ASC'}.get(sort,'m.created_at DESC')
    sql+=' ORDER BY m.featured DESC, '+order
    with db() as c:
        mods=c.execute(sql,args).fetchall()
        trending=c.execute('SELECT * FROM mods ORDER BY downloads DESC,created_at DESC LIMIT 4').fetchall()
        totals=c.execute('SELECT COUNT(*),COALESCE(SUM(downloads),0) FROM mods').fetchone()
    return render_template('index.html',mods=mods,trending=trending,categories=CATEGORIES,selected=category,search=q,sort=sort,total_mods=totals[0],total_downloads=totals[1],user=session.get('username'))


@app.route('/mod/<mod_id>')
def mod_detail(mod_id):
    m,shots,reviews,stats=get_mod(mod_id)
    return render_template('detail.html',m=m,shots=shots,reviews=reviews,stats=stats,user=session.get('username'))


@app.route('/register',methods=['GET','POST'])
def register_login():
    if request.method=='POST':
        check_csrf(); action=request.form.get('action')
        if action=='register':
            username=request.form.get('username','').strip(); email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
            if not re.fullmatch(r'[A-Za-z0-9_]{3,24}',username): flash('Username must be 3–24 letters, numbers or underscores.','error')
            elif len(password)<10: flash('Use a password with at least 10 characters.','error')
            elif '@' not in email or len(email)>160: flash('Enter a valid email address.','error')
            else:
                try:
                    with db() as c: cur=c.execute('INSERT INTO users(username,email,password_hash) VALUES(?,?,?)',(username,email,generate_password_hash(password)))
                    session.clear(); session['user_id']=cur.lastrowid; session['username']=username; session['_csrf']=secrets.token_urlsafe(32)
                    return redirect(request.args.get('next') or url_for('home'))
                except sqlite3.IntegrityError: flash('That username or email is already registered.','error')
        elif action=='login':
            identity=request.form.get('identity','').strip(); password=request.form.get('password','')
            with db() as c: u=c.execute('SELECT * FROM users WHERE username=? OR email=?',(identity,identity)).fetchone()
            if u and check_password_hash(u['password_hash'],password):
                session.clear(); session['user_id']=u['id']; session['username']=u['username']; session['_csrf']=secrets.token_urlsafe(32)
                return redirect(request.args.get('next') or url_for('home'))
            flash('Incorrect username/email or password.','error')
    return render_template('account.html',user=session.get('username'))


@app.route('/account/logout',methods=['POST'])
@user_required
def user_logout():
    check_csrf(); session.clear(); return redirect(url_for('home'))


@app.route('/review/<mod_id>',methods=['POST'])
@user_required
def review(mod_id):
    check_csrf(); rating=request.form.get('rating',''); body=request.form.get('body','').strip()[:1000]
    if rating not in {'1','2','3','4','5'}: abort(400)
    with db() as c:
        if not c.execute('SELECT 1 FROM mods WHERE id=?',(mod_id,)).fetchone(): abort(404)
        c.execute('''INSERT INTO reviews(mod_id,user_id,rating,body) VALUES(?,?,?,?)
                     ON CONFLICT(mod_id,user_id) DO UPDATE SET rating=excluded.rating,body=excluded.body,created_at=CURRENT_TIMESTAMP''',(mod_id,session['user_id'],int(rating),body))
    flash('Your review has been saved.','success'); return redirect(url_for('mod_detail',mod_id=mod_id)+'#reviews')


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        check_csrf()
        if not ADMIN_PASSWORD: flash('Admin password is not configured on the server.','error')
        elif hmac.compare_digest(request.form.get('password',''),ADMIN_PASSWORD):
            session.clear(); session['is_admin']=True; session['_csrf']=secrets.token_urlsafe(32); return redirect(url_for('admin'))
        else: flash('Incorrect password.','error')
    return render_template('login.html')


@app.route('/logout',methods=['POST'])
@admin_required
def logout(): check_csrf(); session.clear(); return redirect(url_for('home'))


@app.route('/admin')
@admin_required
def admin():
    with db() as c:
        mods=c.execute('''SELECT m.*,ROUND((SELECT AVG(rating) FROM reviews WHERE mod_id=m.id),1) avg_rating,
                         (SELECT COUNT(*) FROM reviews WHERE mod_id=m.id) review_count FROM mods m ORDER BY m.created_at DESC''').fetchall()
        users=c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        reviews=c.execute('SELECT COUNT(*) FROM reviews').fetchone()[0]
        downloads=c.execute('SELECT COALESCE(SUM(downloads),0) FROM mods').fetchone()[0]
    return render_template('admin.html',mods=mods,categories=CATEGORIES,user_count=users,review_count=reviews,total_downloads=downloads)


def handle_upload(mod_id=None):
    file=request.files.get('file'); name=request.form.get('name','').strip(); desc=request.form.get('description','').strip(); category=request.form.get('category','')
    if not name or (not file or not file.filename) and not mod_id: raise ValueError('Enter a mod name and choose a mod file.')
    if category not in CATEGORIES: raise ValueError('Choose a valid category.')
    stored=None; thumb=None; saved_shots=[]
    try:
        if file and file.filename:
            if not ext_ok(file.filename,MOD_EXT): raise ValueError('Unsupported mod file type.')
            ext=file.filename.rsplit('.',1)[1].lower(); stored=f'{uuid4().hex}.{ext}'; file.save(UPLOAD_DIR/stored)
        thumb=save_image(request.files.get('thumbnail'))
        for image_file in request.files.getlist('screenshots')[:6]:
            saved=save_image(image_file)
            if saved: saved_shots.append(saved)
        with db() as c:
            if mod_id:
                old=c.execute('SELECT * FROM mods WHERE id=?',(mod_id,)).fetchone()
                if not old: abort(404)
                c.execute('''UPDATE mods SET name=?,description=?,category=?,game=?,version=?,
                    filename=?,original_filename=?,size_bytes=?,thumbnail=COALESCE(?,thumbnail) WHERE id=?''',
                    (name[:90],desc[:1500],category,request.form.get('game','')[:80],request.form.get('version','')[:40],stored or old['filename'],Path(file.filename).name[:180] if stored else old['original_filename'],(UPLOAD_DIR/stored).stat().st_size if stored else old['size_bytes'],thumb,mod_id))
                for s in saved_shots: c.execute('INSERT INTO screenshots(mod_id,filename) VALUES(?,?)',(mod_id,s))
            else:
                mod_id=uuid4().hex
                c.execute('''INSERT INTO mods(id,name,description,category,filename,original_filename,size_bytes,game,version,thumbnail)
                    VALUES(?,?,?,?,?,?,?,?,?,?)''',(mod_id,name[:90],desc[:1500],category,stored,Path(file.filename).name[:180],(UPLOAD_DIR/stored).stat().st_size,request.form.get('game','')[:80],request.form.get('version','')[:40],thumb))
                for s in saved_shots: c.execute('INSERT INTO screenshots(mod_id,filename) VALUES(?,?)',(mod_id,s))
    except Exception:
        if stored: (UPLOAD_DIR/stored).unlink(missing_ok=True)
        if thumb: (IMAGE_DIR/thumb).unlink(missing_ok=True)
        for s in saved_shots: (IMAGE_DIR/s).unlink(missing_ok=True)
        raise


@app.route('/upload',methods=['POST'])
@admin_required
def upload():
    check_csrf()
    try: handle_upload(); flash('Mod uploaded successfully.','success')
    except ValueError as e: flash(str(e),'error')
    return redirect(url_for('admin'))


@app.route('/edit/<mod_id>',methods=['POST'])
@admin_required
def edit_mod(mod_id):
    check_csrf()
    try: handle_upload(mod_id); flash('Mod details updated.','success')
    except ValueError as e: flash(str(e),'error')
    return redirect(url_for('admin'))


@app.route('/feature/<mod_id>',methods=['POST'])
@admin_required
def feature(mod_id):
    check_csrf()
    with db() as c: c.execute('UPDATE mods SET featured=CASE WHEN featured=1 THEN 0 ELSE 1 END WHERE id=?',(mod_id,))
    return redirect(url_for('admin'))


@app.route('/delete/<mod_id>',methods=['POST'])
@admin_required
def delete(mod_id):
    check_csrf()
    with db() as c:
        m=c.execute('SELECT * FROM mods WHERE id=?',(mod_id,)).fetchone()
        if not m: abort(404)
        shot_rows=c.execute('SELECT filename FROM screenshots WHERE mod_id=?',(mod_id,)).fetchall()
        c.execute('DELETE FROM mods WHERE id=?',(mod_id,))
    (UPLOAD_DIR/m['filename']).unlink(missing_ok=True)
    if m['thumbnail']: (IMAGE_DIR/m['thumbnail']).unlink(missing_ok=True)
    for s in shot_rows: (IMAGE_DIR/s['filename']).unlink(missing_ok=True)
    flash('Mod and its related images deleted.','success'); return redirect(url_for('admin'))


@app.route('/download/<mod_id>')
def download(mod_id):
    with db() as c:
        m=c.execute('SELECT * FROM mods WHERE id=?',(mod_id,)).fetchone()
        if not m: abort(404)
        path=UPLOAD_DIR/m['filename']
        if not path.is_file(): abort(404)
        c.execute('UPDATE mods SET downloads=downloads+1 WHERE id=?',(mod_id,))
    return send_from_directory(str(UPLOAD_DIR),m['filename'],as_attachment=True,download_name=m['original_filename'])


@app.route('/media/<filename>')
def media(filename):
    if not re.fullmatch(r'[a-f0-9]{32}\.(png|jpg|jpeg|webp|gif)',filename): abort(404)
    return send_from_directory(str(IMAGE_DIR),filename)


@app.errorhandler(413)
def too_large(_):
    flash('File too large. Maximum upload size is 500 MB.','error')
    return redirect(url_for('admin' if session.get('is_admin') else 'home'))

init_db()
if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=False)
