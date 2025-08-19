import uuid
from datetime import datetime, UTC

def make_id(prefix):
    """Return unique ID like prefix_uuid"""
    return f"{prefix}_{uuid.uuid4()}"

def time_now():
    """Return current UTC time in ISO format"""
    return datetime.now(UTC).replace(microsecond=0).isoformat()

class Note:
    def __init__(self, id, user_id, title, body, created_time, updated_time):
        self.id = id
        self.user_id = user_id
        self.title = title
        self.body = body
        self.created_time = created_time
        self.updated_time = updated_time

class AuthError(Exception): pass

class AuthService:
    def __init__(self):
        self.users = {}
        self.active = {}

    def add_user(self, email, password):
        if email in self.users:
            raise AuthError("Email already exists")
        uid = make_id("usr")
        self.users[email] = {"id": uid, "password": password}
        return uid
    
    def login(self, email, password):
        u = self.users.get(email)
        if not u or u["password"] != password:
            raise AuthError("Invalid login")
        token = make_id("sess")
        self.active[token] = u["id"]
        return token
    
    def validate(self, token):
        if token not in self.active:
            raise AuthError("Invalid session")
        return self.active[token]

class storage:
    def __init__(self):
        self.notes = {}

    def add_note(self, note):
        self.notes.setdefault(note.user_id, {})[note.id] = note
        return note
    
    def list_notes(self, user_id):
        return list(self.notes.get(user_id, {}).values())

class PIM:
    def __init__(self, store, auth):
        self.store = store
        self.auth = auth

    def register_user(self, email, password):
        return self.auth.add_user(email, password)
    
    def login(self, email, password):
        return self.auth.login(email, password)
    
    def add_note(self, token, title, body=""):
        user_id = self.auth.validate(token)
        now = time_now()
        note = Note(make_id("note"), user_id, title, body, now, now)
        return self.store.add_note(note)
    
    def list_notes(self, token):
        user_id = self.auth.validate(token)
        return self.store.list_notes(user_id)

if __name__ == "__main__":
    auth = AuthService()
    store = storage()
    pim = PIM(store, auth)

    uid = pim.register_user("me@example.com", "pass")
    token = pim.login("me@example.com", "pass")
    pim.add_note(token, "My first note", "Hello world")
    for note in pim.list_notes(token):
        print(note.id, note.title, note.body)
