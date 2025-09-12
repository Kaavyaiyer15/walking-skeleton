from typing import Dict, List
from .domain import Note, AuthError
from .utils import make_id, time_now

class AuthService:
    """Handles user registration, login, and session validation."""
    def __init__(self):
        self.users: Dict[str, Dict[str, str]] = {}
        self.active: Dict[str, str] = {}

    def add_user(self, email: str, password: str) -> str:
        if email in self.users:
            raise AuthError("Email already exists")
        uid = make_id("usr")
        self.users[email] = {"id": uid, "password": password}
        return uid

    def login(self, email: str, password: str) -> str:
        user = self.users.get(email)
        if not user or user["password"] != password:
            raise AuthError("Invalid login credentials")
        token = make_id("sess")
        self.active[token] = user["id"]
        return token

    def validate(self, token: str) -> str:
        if token not in self.active:
            raise AuthError("Invalid or expired session")
        return self.active[token]

class Storage:
    """Stores and retrieves notes in memory."""
    def __init__(self):
        self.notes: Dict[str, Dict[str, Note]] = {}

    def add_note(self, note: Note) -> Note:
        self.notes.setdefault(note.user_id, {})[note.id] = note
        return note

    def list_notes(self, user_id: str) -> List[Note]:
        return list(self.notes.get(user_id, {}).values())

class PIM:
    """Main app logic: manages users and notes."""
    def __init__(self, store: Storage, auth: AuthService):
        self.store = store
        self.auth = auth

    def register_user(self, email: str, password: str) -> str:
        return self.auth.add_user(email, password)

    def login(self, email: str, password: str) -> str:
        return self.auth.login(email, password)

    def add_note(self, token: str, title: str, body: str = "") -> Note:
        user_id = self.auth.validate(token)
        now = time_now()
        note = Note(make_id("note"), user_id, title, body, now, now)
        return self.store.add_note(note)

    def list_notes(self, token: str):
        user_id = self.auth.validate(token)
        return self.store.list_notes(user_id)
