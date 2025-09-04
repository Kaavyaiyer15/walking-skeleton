"""
FastAPI backend for Notes App.
Provides:
- User registration and login
- Adding and listing notes
- Serving frontend HTML, CSS, and JS
"""

import uuid
import os
from datetime import datetime, UTC
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr

# -------------------------------
# Utility functions
# -------------------------------
def make_id(prefix: str) -> str:
    """Generate a unique ID with a given prefix."""
    return f"{prefix}_{uuid.uuid4()}"

def time_now() -> str:
    """Return the current time in ISO format (UTC, no microseconds)."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()

# -------------------------------
# Domain classes
# -------------------------------
class Note:
    """Represents a single note object."""
    
    def __init__(self, id: str, user_id: str, title: str, body: str, 
                 created_time: str, updated_time: str):
        self.id = id
        self.user_id = user_id
        self.title = title
        self.body = body
        self.created_time = created_time
        self.updated_time = updated_time

    def to_dict(self) -> Dict[str, str]:
        """Convert note to dictionary representation."""
        return {
            "id": self.id,
            "title": self.title,
            "body": self.body,
            "created_time": self.created_time,
            "updated_time": self.updated_time
        }

class AuthError(Exception): 
    """Custom exception for authentication errors."""
    pass

class AuthService:
    """Handles user registration, login, and session validation."""
    
    def __init__(self):
        self.users: Dict[str, Dict[str, str]] = {}
        self.active: Dict[str, str] = {}

    def add_user(self, email: str, password: str) -> str:
        """Register a new user with email and password."""
        if email in self.users:
            raise AuthError("Email already exists")
        uid = make_id("usr")
        self.users[email] = {"id": uid, "password": password}
        return uid
    
    def login(self, email: str, password: str) -> str:
        """Authenticate user and return session token."""
        user = self.users.get(email)
        if not user or user["password"] != password:
            raise AuthError("Invalid login credentials")
        token = make_id("sess")
        self.active[token] = user["id"]
        return token
    
    def validate(self, token: str) -> str:
        """Validate session token and return user ID."""
        if token not in self.active:
            raise AuthError("Invalid or expired session")
        return self.active[token]

class Storage:
    """Stores and retrieves notes in memory."""
    
    def __init__(self):
        self.notes: Dict[str, Dict[str, Note]] = {}

    def add_note(self, note: Note) -> Note:
        """Add a note to storage."""
        self.notes.setdefault(note.user_id, {})[note.id] = note
        return note
    
    def list_notes(self, user_id: str) -> List[Note]:
        """Retrieve all notes for a user."""
        return list(self.notes.get(user_id, {}).values())

class PIM:
    """Main application logic for user and notes management."""
    
    def __init__(self, store: Storage, auth: AuthService):
        self.store = store
        self.auth = auth

    def register_user(self, email: str, password: str) -> str:
        """Register a new user."""
        return self.auth.add_user(email, password)
    
    def login(self, email: str, password: str) -> str:
        """Login user and return session token."""
        return self.auth.login(email, password)
    
    def add_note(self, token: str, title: str, body: str = "") -> Note:
        """Add a new note for authenticated user."""
        user_id = self.auth.validate(token)
        now = time_now()
        note = Note(make_id("note"), user_id, title, body, now, now)
        return self.store.add_note(note)
    
    def list_notes(self, token: str) -> List[Note]:
        """List all notes for authenticated user."""
        user_id = self.auth.validate(token)
        return self.store.list_notes(user_id)

# -------------------------------
# FastAPI App Setup
# -------------------------------
app = FastAPI(
    title="Notes API",
    description="A simple notes application with user authentication",
    version="1.0.0"
)

# Setup static file serving
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEBSITE_DIR = os.path.join(BASE_DIR, "website")

if os.path.exists(WEBSITE_DIR):
    app.mount("/static", StaticFiles(directory=WEBSITE_DIR), name="static")

# Initialize core services
auth = AuthService()
store = Storage()
pim = PIM(store, auth)

# -------------------------------
# Dependency for token validation
# -------------------------------
def get_current_user(authorization: str = Header(...)) -> str:
    """Extract and validate authorization token."""
    try:
        return pim.auth.validate(authorization)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

# -------------------------------
# Pydantic Models
# -------------------------------
class UserCreds(BaseModel):
    email: EmailStr
    password: str

class NoteData(BaseModel):
    title: str
    body: str = ""

class UserResponse(BaseModel):
    success: bool
    user_id: str

class LoginResponse(BaseModel):
    success: bool
    token: str

class NoteResponse(BaseModel):
    success: bool
    note: Dict[str, str]

class NotesListResponse(BaseModel):
    success: bool
    notes: List[Dict[str, str]]

# -------------------------------
# Routes
# -------------------------------
@app.get("/")
async def read_root():
    """Serve index.html from website folder."""
    index_path = os.path.join(WEBSITE_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Notes API is running"}

@app.post("/register", response_model=UserResponse)
async def register(creds: UserCreds):
    """Register a new user account."""
    try:
        uid = pim.register_user(creds.email, creds.password)
        return UserResponse(success=True, user_id=uid)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login", response_model=LoginResponse)
async def login(creds: UserCreds):
    """Login with email and password."""
    try:
        token = pim.login(creds.email, creds.password)
        return LoginResponse(success=True, token=token)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/notes", response_model=NoteResponse)
async def add_note(note: NoteData, user_id: str = Depends(get_current_user)):
    """Add a new note for the authenticated user."""
    try:
        # Using the token directly since get_current_user validates it
        authorization = None  # We'll need to modify this approach
        new_note = pim.add_note(authorization, note.title, note.body)
        return NoteResponse(success=True, note=new_note.to_dict())
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/notes", response_model=NotesListResponse)
async def list_notes(authorization: str = Header(...)):
    """List all notes for the authenticated user."""
    try:
        notes = [n.to_dict() for n in pim.list_notes(authorization)]
        return NotesListResponse(success=True, notes=notes)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

# -------------------------------
# Health check endpoint
# -------------------------------
@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "healthy", "timestamp": time_now()}