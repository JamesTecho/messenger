import os
import json
import re
import uuid
import shutil
from datetime import date

from flask import Flask, render_template, request, redirect, flash, url_for, jsonify, Response
from flask_socketio import SocketIO, emit, join_room
from flask_login import login_user, logout_user, current_user, login_required
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

from utils import load_users, verify_password, encrypt_message, decrypt_message, is_admin, save_users
from unread import get_last_read, set_last_read, get_unread_counts
from database import db, Message
from login import login_manager, User
from keys import SECRET_KEY, ENCRYPTION_KEY, fernet

# ================== CONFIG ==================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_FILE = os.path.join(BASE_DIR, "users.json")
DB_FILE = os.path.join(BASE_DIR, "instance", "chat_storage.db")
BACKUP_DIR = os.path.join(BASE_DIR, "db_backups")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
GLOBAL_CHAT_ROOM = "global_chat"
ANNOUNCEMENTS_ROOM = "announcements"

MAX_IMAGE_BYTES = 8 * 1024 * 1024   # 8 MB
MAX_FILE_BYTES  = 20 * 1024 * 1024  # 20 MB
MAX_MSG_CHARS   = 1000
ALLOWED_IMAGE_MIMES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
ALLOWED_IMAGE_EXTS  = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
ONLINE_USERS = {}
CURRENT_OPEN = {}  # tracks which conversation each user currently has open
unread = {}


# ================== SECRETS ==================
# ================== BACKUPS ==================
def backup_database():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    today = date.today().isoformat()
    backup_path = os.path.join(BACKUP_DIR, f"chat_backup_{today}.db")
    if not os.path.exists(backup_path) and os.path.exists(DB_FILE):
        shutil.copy(DB_FILE, backup_path)

# ================== UTILS ==================
# rest in utils.py

# ================== UNREAD TRACKING ==================
# ================== APP ==================
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_FILE}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


login_manager.init_app(app)
login_manager.login_view = "login"
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=True)

# ================== DATABASE ==================
# ================== LOGIN ==================
# ================== HTML ==================
# in /templates
# ================== ROUTES ==================
@app.route("/test_global")
def test_global():
    msgs = Message.query.filter(Message.is_global == 1).order_by(Message.timestamp.asc()).all()
    output = []
    for m in msgs:
        try:
            output.append(f"{m.id}: {m.sender} -> {decrypt_message(m.content)}")
        except Exception as e:
            output.append(f"{m.id}: {m.sender} (decrypt failed)")
    return "<br>".join(output)


@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated:
        return redirect("/")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        users = load_users()
        matched_username = None
        user_data = None
        for uname in users:
            if uname.lower() == username.lower():
                matched_username = uname
                break

        if matched_username:
            user_data = users[matched_username]
            if verify_password(password, user_data.get("password", "")):
                login_user(User(matched_username))
                return redirect("/")

        if user_data and isinstance(user_data, dict):
            banned = user_data.get("banned")
            if banned:
                if isinstance(banned, dict) and banned.get("status"):
                    reason = banned.get("reason", "No reason provided.")
                    flash(f"You have been banned for violating our terms of service. Reason: {reason}")
                    return render_template("login.html")
                elif banned is True:
                    flash("You have been banned for violating our terms of service.")
                    return render_template("login.html")

            if verify_password(password, user_data.get("password", "")):
                login_user(User(username))
                return redirect("/")

        flash("Invalid login")
    return render_template("login.html")

@app.route("/")
@login_required
def index():
    return render_template("chat.html", current_user=current_user, is_user_admin=is_admin())

@app.route("/admin/reset_user/<username>", methods=["POST"])
@login_required
def reset_user(username):
    if not is_admin():
        return "Forbidden", 403

    users = load_users()

    if username not in users:
        return "User not found", 404

    token = str(uuid.uuid4())
    users[username]["password"] = ""
    users[username]["banned"] = {"status": False, "reason": ""}
    users[username]["invite"] = token
    users[username]["role"] = "user"  

    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

    return f"/invite/{token}", 200

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

@app.route("/admin/create_invite", methods=["POST"])
@login_required
def create_invite():
    if not is_admin():
        return "Forbidden", 403

    username = request.form.get("username")

    if not username:
        return "Username is required", 400

    users = load_users()

    if username in users:
        return "User already exists", 400

    token = str(uuid.uuid4())

    users[username] = {
        "password": "",
        "banned": {
            "status": False,
            "reason": ""
        },
        "role": "user",
        "invite": token
    }

    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

    return f"/invite/{token}", 200

@app.route("/invite/<token>", methods=["GET", "POST"])
def accept_invite(token):
    users = load_users()
    matched_user = None

    for username, data in users.items():
        if data.get("invite") == token:
            matched_user = username
            break

    if not matched_user:
        return "Invalid or expired invite."

    if request.method == "POST":
        password = request.form.get("password")

        if not password:
            return "Password required"

        users[matched_user]["password"] = pwd_context.hash(password)
        users[matched_user].pop("invite", None)

        with open(USER_FILE, "w") as f:
            json.dump(users, f, indent=4)

        return redirect("/login")

    return render_template("invite.html", user=matched_user)

@app.route("/admin")
@login_required
def admin_panel():
    if not is_admin():
        return "Forbidden", 403

    users = load_users()
    return render_template("admin.html", users=users)


@app.route("/admin/add_user", methods=["POST"])
def add_user():
    if not is_admin():
        return redirect(url_for("login"))

    users = load_users()
    username = request.form["username"].strip()
    password = request.form.get("password", "").strip()

    if username in users:
        flash("User already exists!")
        return redirect(url_for("admin_panel"))

    users[username] = {
        "password": password, 
        "banned": False
    }
    save_users(users)
    flash(f"User {username} added!")
    return redirect(url_for("admin_panel"))

@app.route("/admin/toggle_ban/<username>", methods=["POST"])
def toggle_ban(username):
    if not is_admin():
        return redirect(url_for("login"))

    users = load_users()

    if username in users and username != "admin":
        ban_reason = request.form.get("reason", "").strip()

        current_ban = users[username].get("banned")


        if isinstance(current_ban, dict) and current_ban.get("status"):
            users[username]["banned"] = {
                "status": False,
                "reason": ""
            }
            flash(f"User {username} has been unbanned.")


        else:
            users[username]["banned"] = {
                "status": True,
                "reason": ban_reason or "No reason provided"
            }
            flash(f"User {username} has been banned.")

        save_users(users)

    return redirect(url_for("admin_panel"))


@app.route("/admin/set_contact/<username>", methods=["POST"])
@login_required
def set_contact(username):
    if not is_admin():
        return "Forbidden", 403
    users = load_users()
    if username not in users:
        return "User not found", 404
    users[username]["contact_name"] = request.form.get("contact_name", "").strip()
    save_users(users)
    return "OK", 200


# ================== FILE UPLOAD / SERVE ==================
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected"}), 400

    safe_name = secure_filename(f.filename) or "file"
    ext = os.path.splitext(safe_name)[1].lower()
    mime = (f.content_type or "").split(";")[0].strip()
    is_image = mime in ALLOWED_IMAGE_MIMES and ext in ALLOWED_IMAGE_EXTS

    data = f.read()
    max_bytes = MAX_IMAGE_BYTES if is_image else MAX_FILE_BYTES
    if len(data) > max_bytes:
        limit_mb = max_bytes // (1024 * 1024)
        return jsonify({"error": f"File too large (max {limit_mb} MB)"}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_id = str(uuid.uuid4())

    # Encrypt and save file
    encrypted = fernet.encrypt(data)
    with open(os.path.join(UPLOAD_DIR, file_id), "wb") as fp:
        fp.write(encrypted)

    # Save metadata
    meta = {"filename": safe_name, "content_type": mime, "uploader": current_user.username}
    with open(os.path.join(UPLOAD_DIR, file_id + ".meta"), "w") as mf:
        json.dump(meta, mf)

    return jsonify({"file_id": file_id, "filename": safe_name,
                    "type": "image" if is_image else "file"})


@app.route("/file/<file_id>")
@login_required
def serve_file(file_id):
    if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', file_id):
        return "Not found", 404

    file_path = os.path.join(UPLOAD_DIR, file_id)
    meta_path = os.path.join(UPLOAD_DIR, file_id + ".meta")
    if not os.path.exists(file_path):
        return "Not found", 404

    filename = file_id
    content_type = "application/octet-stream"
    if os.path.exists(meta_path):
        with open(meta_path) as mf:
            meta = json.load(mf)
        filename = meta.get("filename", file_id)
        content_type = meta.get("content_type", "application/octet-stream")

    with open(file_path, "rb") as fp:
        decrypted = fernet.decrypt(fp.read())

    is_inline = content_type in ALLOWED_IMAGE_MIMES
    disposition = f'inline; filename="{filename}"' if is_inline else f'attachment; filename="{filename}"'
    return Response(decrypted, content_type=content_type,
                    headers={"Content-Disposition": disposition})


# ================== SOCKET HANDLERS ==================
@socketio.on("connect")
def connect(auth=None):  # <-- Accepts optional auth argument
    if not current_user.is_authenticated:
        return
    ONLINE_USERS[current_user.username] = request.sid
    join_room(GLOBAL_CHAT_ROOM)
    join_room(ANNOUNCEMENTS_ROOM)
    users = load_users()
    user_list = [{"username": u, "contact_name": d.get("contact_name", "")} for u, d in users.items()]
    emit("registered_users", user_list, room=request.sid)
    emit("unread_counts", get_unread_counts(current_user.username), room=request.sid)

@socketio.on("request_history")
def request_history(data):
    target = data.get("target")
    user = current_user.username
    before_id = data.get("before_id")
    limit = 20

    if target == GLOBAL_CHAT_ROOM:
        query = Message.query.filter_by(is_global=True)

        if before_id:
            query = query.filter(Message.id < before_id)

        msgs = query.order_by(Message.id.desc()).limit(limit).all()
        msgs.reverse()

        if not before_id:
            last_from_others = max((m.id for m in msgs if m.sender != user), default=0)
            set_last_read(user, "global", last_from_others)
            CURRENT_OPEN[user] = target

    elif target == ANNOUNCEMENTS_ROOM:
        query = Message.query.filter_by(is_global=False, recipient=ANNOUNCEMENTS_ROOM)

        if before_id:
            query = query.filter(Message.id < before_id)

        msgs = query.order_by(Message.id.desc()).limit(limit).all()
        msgs.reverse()

        if not before_id:
            last_from_others = max((m.id for m in msgs if m.sender != user), default=0)
            set_last_read(user, "announcements", last_from_others)
            CURRENT_OPEN[user] = target

    else:
        query = Message.query.filter(
            ((Message.sender == user) & (Message.recipient == target)) |
            ((Message.sender == target) & (Message.recipient == user))
        ).filter_by(is_global=False)

        if before_id:
            query = query.filter(Message.id < before_id)

        msgs = query.order_by(Message.id.desc()).limit(limit).all()
        msgs.reverse()

        if not before_id:
            last_from_target = max((m.id for m in msgs if m.sender == target), default=0)
            set_last_read(user, target, last_from_target)
            CURRENT_OPEN[user] = target

    history = []
    for m in msgs:
        try:
            decrypted = decrypt_message(m.content, fernet)
            attachment = None
            display_text = f"{m.sender}: {decrypted}"
            try:
                md = json.loads(decrypted)
                if isinstance(md, dict) and "__attach" in md:
                    attachment = {"type": md["__attach"], "file_id": md["file_id"], "filename": md["filename"]}
                    display_text = f"{m.sender}: "
            except (json.JSONDecodeError, KeyError, TypeError):
                pass
            history.append({
                "id": m.id,
                "msg": display_text,
                "is_global": m.is_global,
                "timestamp": m.timestamp.isoformat() if m.timestamp else None,
                "attachment": attachment
            })
        except Exception as e:
            print("Decrypt error:", e)

    emit("history", {
        "messages": history,
        "target": target,
        "has_more": len(msgs) == limit
    }, room=request.sid)

    emit("unread_counts", get_unread_counts(user, current_open=target), room=request.sid)



@socketio.on("store_and_send")
def store(data):
    msg = data.get("msg", "")
    target = data.get("target")
    sender = current_user.username
    is_global = target == GLOBAL_CHAT_ROOM

    # Parse attachment before length check (attachments bypass char limit)
    attachment = None
    try:
        md = json.loads(msg)
        if isinstance(md, dict) and "__attach" in md:
            attachment = {"type": md["__attach"], "file_id": md["file_id"], "filename": md["filename"]}
    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    is_announcement = target == ANNOUNCEMENTS_ROOM

    # Only admins can post announcements
    if is_announcement and not is_admin():
        emit("error", {"msg": "Only admins can post announcements"}, room=request.sid)
        return

    # Enforce message length limit for non-admins and non-attachments
    if attachment is None and not is_admin() and len(msg) > MAX_MSG_CHARS:
        emit("error", {"msg": f"Message too long (max {MAX_MSG_CHARS} characters)"}, room=request.sid)
        return

    display_text = f"{sender}: " if attachment else f"{sender}: {msg}"

    encrypted = encrypt_message(msg)
    new_message = Message(sender=sender, recipient=target, content=encrypted, is_global=is_global)
    db.session.add(new_message)
    db.session.commit()
    new_msg_id = new_message.id
    live = {"msg": display_text, "sender": sender, "recipient": target, "is_global": is_global,
            "timestamp": new_message.timestamp.isoformat() if new_message.timestamp else None,
            "attachment": attachment}

    if is_global:
        emit("live_message", live, room=GLOBAL_CHAT_ROOM)
        for u, sid in ONLINE_USERS.items():
            if u != sender:
                if CURRENT_OPEN.get(u) == GLOBAL_CHAT_ROOM:
                    set_last_read(u, "global", new_msg_id)
                socketio.emit("unread_counts", get_unread_counts(u, current_open=CURRENT_OPEN.get(u)), room=sid)

    elif is_announcement:
        emit("live_message", live, room=ANNOUNCEMENTS_ROOM)
        for u, sid in ONLINE_USERS.items():
            if u != sender:
                if CURRENT_OPEN.get(u) == ANNOUNCEMENTS_ROOM:
                    set_last_read(u, "announcements", new_msg_id)
                socketio.emit("unread_counts", get_unread_counts(u, current_open=CURRENT_OPEN.get(u)), room=sid)
        socketio.emit("unread_counts", get_unread_counts(sender, current_open=CURRENT_OPEN.get(sender)), room=request.sid)

    else:
        recipient_sid = ONLINE_USERS.get(target)
        emit("live_message", live, room=request.sid)
        set_last_read(sender, target, new_msg_id)
        if recipient_sid:
            emit("live_message", live, room=recipient_sid)
            if CURRENT_OPEN.get(target) == sender:
                set_last_read(target, sender, new_msg_id)
            socketio.emit("unread_counts", get_unread_counts(target, current_open=CURRENT_OPEN.get(target)), room=recipient_sid)
        socketio.emit("unread_counts", get_unread_counts(sender, current_open=CURRENT_OPEN.get(sender)), room=request.sid)

@socketio.on("get_users")
def get_users():
    users = load_users()
    user_list = [{"username": u, "contact_name": d.get("contact_name", "")} for u, d in users.items()]
    emit("registered_users", user_list, room=request.sid)
    emit("unread_counts", get_unread_counts(current_user.username), room=request.sid)

with app.app_context():
    db.create_all()

# ================== RUN ==================  
if __name__ == "__main__":
    try:

        print("Starting server on https://m.ju-s.uk")
        socketio.run(app, host="0.0.0.0", port=1102)
    except KeyboardInterrupt:
        print("Server stopped by user.")
    except:
        print("Something else failed on startup")