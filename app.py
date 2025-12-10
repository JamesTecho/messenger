import os
import json
import uuid
import shutil
from datetime import date

from flask import Flask, render_template, request, redirect, flash, url_for
from flask_socketio import SocketIO, emit, join_room
from flask_login import login_user, logout_user, current_user, login_required
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy

from utils import load_users, verify_password, encrypt_message, decrypt_message, is_admin, save_users
from unread import get_last_read, set_last_read, get_unread_counts
from database import db, Message
from login import login_manager, User
from keys import SECRET_KEY, ENCRYPTION_KEY, fernet

# ================== CONFIG ==================
USER_FILE = "users.json"
DB_FILE = r"C:\messenger\instance\chat_storage.db"
BACKUP_DIR = "db_backups"
GLOBAL_CHAT_ROOM = "global_chat"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
ONLINE_USERS = {}
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


# ================== SOCKET HANDLERS ==================
@socketio.on("connect")
def connect():
    if not current_user.is_authenticated:
        return
    ONLINE_USERS[current_user.username] = request.sid
    join_room(GLOBAL_CHAT_ROOM)
    emit("registered_users", list(load_users().keys()), room=request.sid)
    emit("unread_counts", get_unread_counts(current_user.username), room=request.sid)

@socketio.on("request_history")
def request_history(data):
    target = data.get("target")
    user = current_user.username

    if target == GLOBAL_CHAT_ROOM:
        msgs = Message.query.filter_by(is_global=True).order_by(Message.timestamp.asc()).all()

        for m in msgs:
            
            text = decrypt_message(m.content, fernet)

        last_from_others = max((m.id for m in msgs if m.sender != user), default=0)
        set_last_read(user, "global", last_from_others)

    else:
        msgs = Message.query.filter(
            ((Message.sender==user) & (Message.recipient==target)) |
            ((Message.sender==target) & (Message.recipient==user))
        ).filter_by(is_global=False).order_by(Message.timestamp.asc()).all()

        last_from_target = max((m.id for m in msgs if m.sender == target), default=0)
        set_last_read(user, target, last_from_target)


        for m in msgs:

            text = decrypt_message(m.content, fernet)



    try:

        history = [{"msg": f"{m.sender}: {decrypt_message(m.content, fernet)}", "is_global": m.is_global} for m in msgs]
    except Exception as e:
        print(f"Error preparing message history: {e}")
        history = []

    emit("history", {"messages": history, "target": target}, room=request.sid)
    emit("unread_counts", get_unread_counts(user, current_open=target), room=request.sid)


@socketio.on("store_and_send")
def store(data):
    msg = data.get("msg")
    target = data.get("target")
    sender = current_user.username
    is_global = target == GLOBAL_CHAT_ROOM
    encrypted = encrypt_message(msg)
    db.session.add(Message(sender=sender, recipient=target, content=encrypted, is_global=is_global))
    db.session.commit()
    live = {"msg": f"{sender}: {msg}", "sender": sender, "recipient": target, "is_global": is_global}

    if is_global:
        emit("live_message", live, room=GLOBAL_CHAT_ROOM)
        for u, sid in ONLINE_USERS.items():
            if u != sender:
                socketio.emit("unread_counts", get_unread_counts(u, current_open=None), room=sid)
    else:
        recipient_sid = ONLINE_USERS.get(target)
        emit("live_message", live, room=request.sid)
        if recipient_sid:
            emit("live_message", live, room=recipient_sid)
            socketio.emit("unread_counts", get_unread_counts(target, current_open=target), room=recipient_sid)
        socketio.emit("unread_counts", get_unread_counts(sender, current_open=target), room=request.sid)

@socketio.on("get_users")
def get_users():
    emit("registered_users", list(load_users().keys()), room=request.sid)
    emit("unread_counts", get_unread_counts(current_user.username), room=request.sid)

# ================== RUN ==================  
if __name__ == "__main__":
    try:

        print("Starting server on https://m.ju-s.uk")
        socketio.run(app, host="0.0.0.0", port=5000)
    except KeyboardInterrupt:
        print("Server stopped by user.")
    except:
        print("Something else failed on startup")