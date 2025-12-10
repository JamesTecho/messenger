# unread.py

from database import Message
from utils import load_users
from config import GLOBAL_CHAT_ROOM

LAST_READ = {} 

def get_last_read(user, target):
    return LAST_READ.get(user, {}).get(target, 0)

def set_last_read(user, target, msg_id):
    if user not in LAST_READ:
        LAST_READ[user] = {}
    LAST_READ[user][target] = msg_id

def get_unread_counts(user, current_open=None):
    counts = {}

    if current_open != GLOBAL_CHAT_ROOM:
        counts["global"] = Message.query.filter_by(is_global=True).filter(
            Message.sender != user,
            Message.id > get_last_read(user, "global")
        ).count()
    else:
        counts["global"] = 0

    for u in load_users():
        if u == user:
            continue
        if current_open == u:
            counts[u] = 0
        else:
            last_read = get_last_read(user, u)
            counts[u] = Message.query.filter(
                Message.sender == u,
                Message.recipient == user,
                Message.id > last_read
            ).count()
    return counts
