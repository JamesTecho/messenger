# login.py

from flask import redirect
from flask_login import LoginManager, UserMixin
from utils import load_users  

login_manager = LoginManager()
login_manager.login_view = "login"  

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect("/login")

class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username

@login_manager.user_loader
def load_user(user_id):
    users = load_users()

    for uname, data in users.items():
        if uname.lower() == user_id.lower():
            return User(uname)
    return None

