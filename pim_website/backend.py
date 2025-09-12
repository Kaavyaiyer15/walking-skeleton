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
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import hashlib

# -------------------------------
# Utility functions
# -------------------------------
def make_id(prefix: str) -> str:
    """Generate a unique ID with a given prefix."""
    return f"{prefix}_{uuid.uuid4()}"

def time_now() -> str:
    """Return the current time in ISO format (UTC, no microseconds)."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()

def hash_password(password: str) -> str:
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

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
        # Store users by email: {email: {id, password_hash}}
        self.users: Dict[str, Dict[str, str]] = {}
        # Store active sessions: {token: user_id}
        self.active: Dict[str, str] = {}

    def add_user(self, email: str, password: str) -> str:
        """Register a new user with email and password."""
        # Check if email already exists
        if email in self.users:
            raise AuthError("Email already exists")
        
        # Validate password strength
        if len(password) < 6:
            raise AuthError("Password must be at least 6 characters long")
        
        # Create new user
        uid = make_id("usr")
        password_hash = hash_password(password)
        self.users[email] = {"id": uid, "password_hash": password_hash}
        return uid
    
    def login(self, email: str, password: str) -> str:
        """Authenticate user and return session token."""
        # Check if user exists
        if email not in self.users:
            raise AuthError("Invalid email or password")
        
        user = self.users[email]
        password_hash = hash_password(password)
        
        # Verify password
        if user["password_hash"] != password_hash:
            raise AuthError("Invalid email or password")
        
        # Generate session token
        token = make_id("sess")
        self.active[token] = user["id"]
        return token
    
    def validate(self, token: str) -> str:
        """Validate session token and return user ID."""
        if not token:
            raise AuthError("Authorization token is required")
        
        # Remove 'Bearer ' prefix if present
        if token.startswith("Bearer "):
            token = token[7:]
        
        if token not in self.active:
            raise AuthError("Invalid or expired session token")
        return self.active[token]
    
    def logout(self, token: str) -> bool:
        """Logout user by removing session token."""
        if token.startswith("Bearer "):
            token = token[7:]
        
        if token in self.active:
            del self.active[token]
            return True
        return False

class Storage:
    """Stores and retrieves notes in memory."""
    
    def __init__(self):
        # Store notes by user_id: {user_id: {note_id: Note}}
        self.notes: Dict[str, Dict[str, Note]] = {}

    def add_note(self, note: Note) -> Note:
        """Add a note to storage."""
        if note.user_id not in self.notes:
            self.notes[note.user_id] = {}
        self.notes[note.user_id][note.id] = note
        return note
    
    def list_notes(self, user_id: str) -> List[Note]:
        """Retrieve all notes for a user, sorted by creation time (newest first)."""
        user_notes = self.notes.get(user_id, {})
        notes_list = list(user_notes.values())
        # Sort by created_time in descending order (newest first)
        notes_list.sort(key=lambda x: x.created_time, reverse=True)
        return notes_list
    
    def get_note(self, user_id: str, note_id: str) -> Optional[Note]:
        """Get a specific note for a user."""
        return self.notes.get(user_id, {}).get(note_id)
    
    def delete_note(self, user_id: str, note_id: str) -> bool:
        """Delete a specific note for a user."""
        if user_id in self.notes and note_id in self.notes[user_id]:
            del self.notes[user_id][note_id]
            return True
        return False

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
    
    def logout(self, token: str) -> bool:
        """Logout user."""
        return self.auth.logout(token)
    
    def add_note(self, token: str, title: str, body: str = "") -> Note:
        """Add a new note for authenticated user."""
        user_id = self.auth.validate(token)
        
        # Validate input
        if not title.strip():
            raise ValueError("Note title cannot be empty")
        
        now = time_now()
        note = Note(make_id("note"), user_id, title.strip(), body.strip(), now, now)
        return self.store.add_note(note)
    
    def list_notes(self, token: str) -> List[Note]:
        """List all notes for authenticated user."""
        user_id = self.auth.validate(token)
        return self.store.list_notes(user_id)
    
    def delete_note(self, token: str, note_id: str) -> bool:
        """Delete a note for authenticated user."""
        user_id = self.auth.validate(token)
        return self.store.delete_note(user_id, note_id)

# -------------------------------
# FastAPI App Setup
# -------------------------------
app = FastAPI(
    title="Notes API",
    description="A simple notes application with user authentication",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    message: str = "User registered successfully"

class LoginResponse(BaseModel):
    success: bool
    token: str
    message: str = "Login successful"

class NoteResponse(BaseModel):
    success: bool
    note: Dict[str, str]
    message: str = "Note created successfully"

class NotesListResponse(BaseModel):
    success: bool
    notes: List[Dict[str, str]]
    count: int

class MessageResponse(BaseModel):
    success: bool
    message: str

# -------------------------------
# Helper function for authentication
# -------------------------------
def get_current_user(authorization: str = Header(None)) -> str:
    """Extract and validate authorization token."""
    if not authorization:
        raise HTTPException(
            status_code=401, 
            detail="Authorization header is required"
        )
    try:
        return auth.validate(authorization)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

# -------------------------------
# Routes
# -------------------------------
@app.get("/")
async def read_root():
    """Serve index.html from website folder."""
    index_path = os.path.join(WEBSITE_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Notes API is running", "version": "1.0.0"}

@app.post("/register", response_model=UserResponse)
async def register(creds: UserCreds):
    """Register a new user account."""
    try:
        uid = pim.register_user(creds.email, creds.password)
        return UserResponse(success=True, user_id=uid)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/login", response_model=LoginResponse)
async def login(creds: UserCreds):
    """Login with email and password."""
    try:
        token = pim.login(creds.email, creds.password)
        return LoginResponse(success=True, token=token)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/logout", response_model=MessageResponse)
async def logout(authorization: str = Header(...)):
    """Logout the current user."""
    try:
        success = pim.logout(authorization)
        if success:
            return MessageResponse(success=True, message="Logged out successfully")
        else:
            return MessageResponse(success=False, message="Already logged out")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/notes", response_model=NoteResponse)
async def add_note(note: NoteData):
    """Add a new note for the authenticated user."""
    # Get authorization from header manually to provide better error handling
    from fastapi import Request
    
    async def create_note_with_auth(request: Request):
        auth_header = request.headers.get("authorization")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authorization header is required")
        
        try:
            new_note = pim.add_note(auth_header, note.title, note.body)
            return NoteResponse(success=True, note=new_note.to_dict())
        except AuthError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")
    
    from fastapi import Request
    request = Request(scope={"type": "http"})
    return await create_note_with_auth(request)

# Alternative simpler approach for add_note
@app.post("/notes", response_model=NoteResponse)
async def add_note(note: NoteData, authorization: str = Header(...)):
    """Add a new note for the authenticated user."""
    try:
        new_note = pim.add_note(authorization, note.title, note.body)
        return NoteResponse(success=True, note=new_note.to_dict())
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/notes", response_model=NotesListResponse)
async def list_notes(authorization: str = Header(...)):
    """List all notes for the authenticated user."""
    try:
        notes = [n.to_dict() for n in pim.list_notes(authorization)]
        return NotesListResponse(success=True, notes=notes, count=len(notes))
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.delete("/notes/{note_id}", response_model=MessageResponse)
async def delete_note(note_id: str, authorization: str = Header(...)):
    """Delete a specific note for the authenticated user."""
    try:
        success = pim.delete_note(authorization, note_id)
        if success:
            return MessageResponse(success=True, message="Note deleted successfully")
        else:
            raise HTTPException(status_code=404, detail="Note not found")
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

# -------------------------------
# Health check endpoint
# -------------------------------
@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {
        "status": "healthy", 
        "timestamp": time_now(),
        "users_count": len(auth.users),
        "active_sessions": len(auth.active)
    }

# -------------------------------
# Debug endpoint (remove in production)
# -------------------------------
@app.get("/debug/users")
async def debug_users():
    """Debug endpoint to see registered users (remove in production)."""
    return {
        "users": list(auth.users.keys()),
        "count": len(auth.users)
    }