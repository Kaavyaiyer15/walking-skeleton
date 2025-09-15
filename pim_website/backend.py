"""
FastAPI backend for Notes App with Enhanced Persistence.
Provides:
- User registration and login
- Adding and listing notes
- Serving frontend HTML, CSS, and JS
- Reliable SQLite persistence that survives server restarts
"""

import uuid
import os
import threading
from datetime import datetime, UTC
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import hashlib
import sqlite3
import contextlib

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
    """Handles user registration, login, and session validation with SQLite persistence."""
    
    def __init__(self, db_path="users.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
        # Load existing users and sessions from database
        self.users: Dict[str, Dict[str, str]] = {}
        self.active: Dict[str, str] = {}
        self._load_from_database()

    def _init_database(self):
        """Initialize the users and sessions tables."""
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            # Users table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_time TEXT NOT NULL
            )
            """)
            # Sessions table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_time TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)
            conn.commit()

    @contextlib.contextmanager
    def _get_db_connection(self):
        """Get a database connection with proper error handling."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            yield conn
        finally:
            conn.close()

    def _load_from_database(self):
        """Load existing users and sessions from database."""
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Load users
            cursor.execute("SELECT id, email, password_hash FROM users")
            for user_id, email, password_hash in cursor.fetchall():
                self.users[email] = {"id": user_id, "password_hash": password_hash}
            
            # Load sessions
            cursor.execute("SELECT token, user_id FROM sessions")
            for token, user_id in cursor.fetchall():
                self.active[token] = user_id

    def add_user(self, email: str, password: str) -> str:
        """Register a new user with email and password."""
        with self.lock:
            # Check if email already exists
            if email in self.users:
                raise AuthError("Email already exists")
            
            # Validate password strength
            if len(password) < 6:
                raise AuthError("Password must be at least 6 characters long")
            
            # Create new user
            uid = make_id("usr")
            password_hash = hash_password(password)
            created_time = time_now()
            
            # Save to database
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (id, email, password_hash, created_time) VALUES (?, ?, ?, ?)",
                    (uid, email, password_hash, created_time)
                )
                conn.commit()
            
            # Update in-memory cache
            self.users[email] = {"id": uid, "password_hash": password_hash}
            return uid
    
    def login(self, email: str, password: str) -> str:
        """Authenticate user and return session token."""
        with self.lock:
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
            created_time = time_now()
            
            # Save session to database
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO sessions (token, user_id, created_time) VALUES (?, ?, ?)",
                    (token, user["id"], created_time)
                )
                conn.commit()
            
            # Update in-memory cache
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
        with self.lock:
            if token.startswith("Bearer "):
                token = token[7:]
            
            if token in self.active:
                # Remove from database
                with self._get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    conn.commit()
                
                # Remove from in-memory cache
                del self.active[token]
                return True
            return False

class Storage:
    """Stores and retrieves notes using SQLite database with enhanced persistence."""

    def __init__(self, db_path="notes.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._create_table()

    @contextlib.contextmanager
    def _get_db_connection(self):
        """Get a database connection with proper error handling."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        # Enable WAL mode for better concurrency and durability
        conn.execute('PRAGMA journal_mode=WAL;')
        # Enable foreign key constraints
        conn.execute('PRAGMA foreign_keys=ON;')
        # Synchronous mode for data safety
        conn.execute('PRAGMA synchronous=FULL;')
        try:
            yield conn
        finally:
            conn.close()

    def _create_table(self):
        """Create notes table if it doesn't exist."""
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT,
                created_time TEXT NOT NULL,
                updated_time TEXT NOT NULL
            )
            """)
            # Create index for better performance
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)
            """)
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notes_created_time ON notes(created_time DESC)
            """)
            conn.commit()

    def add_note(self, note: Note) -> Note:
        """Insert a note into the database with transaction safety."""
        with self.lock:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "INSERT INTO notes (id, user_id, title, body, created_time, updated_time) VALUES (?, ?, ?, ?, ?, ?)",
                        (note.id, note.user_id, note.title, note.body, note.created_time, note.updated_time)
                    )
                    conn.commit()
                    print(f"Note saved successfully: {note.id}")  # Debug logging
                    return note
                except sqlite3.Error as e:
                    conn.rollback()
                    print(f"Database error saving note: {e}")
                    raise Exception(f"Failed to save note: {e}")

    def list_notes(self, user_id: str) -> List[Note]:
        """Retrieve all notes for a user, newest first."""
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, user_id, title, body, created_time, updated_time FROM notes WHERE user_id=? ORDER BY created_time DESC",
                (user_id,)
            )
            rows = cursor.fetchall()
            return [Note(*row) for row in rows]

    def get_note(self, user_id: str, note_id: str) -> Optional[Note]:
        """Retrieve a single note."""
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, user_id, title, body, created_time, updated_time FROM notes WHERE user_id=? AND id=?",
                (user_id, note_id)
            )
            row = cursor.fetchone()
            return Note(*row) if row else None

    def update_note(self, note: Note) -> bool:
        """Update an existing note."""
        with self.lock:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "UPDATE notes SET title=?, body=?, updated_time=? WHERE id=? AND user_id=?",
                        (note.title, note.body, note.updated_time, note.id, note.user_id)
                    )
                    conn.commit()
                    return cursor.rowcount > 0
                except sqlite3.Error as e:
                    conn.rollback()
                    raise Exception(f"Failed to update note: {e}")

    def delete_note(self, user_id: str, note_id: str) -> bool:
        """Delete a note by ID."""
        with self.lock:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM notes WHERE user_id=? AND id=?", (user_id, note_id))
                conn.commit()
                return cursor.rowcount > 0

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
    
    def update_note(self, token: str, note_id: str, title: str, body: str = "") -> Note:
        """Update an existing note for authenticated user."""
        user_id = self.auth.validate(token)
        
        # Validate input
        if not title.strip():
            raise ValueError("Note title cannot be empty")
        
        # Get existing note to preserve created_time
        existing_note = self.store.get_note(user_id, note_id)
        if not existing_note:
            raise ValueError("Note not found")
        
        # Create updated note
        updated_note = Note(
            note_id, user_id, title.strip(), body.strip(), 
            existing_note.created_time, time_now()
        )
        
        if self.store.update_note(updated_note):
            return updated_note
        else:
            raise ValueError("Failed to update note")
    
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
    description="A simple notes application with user authentication and persistent storage",
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

# Initialize core services with separate databases for better organization
auth = AuthService("users.db")
store = Storage("notes.db")
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

class NoteUpdate(BaseModel):
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
    message: str = "Note operation successful"

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
        print(f"Registration error: {e}")
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
        print(f"Login error: {e}")
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
        print(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/notes", response_model=NoteResponse)
async def add_note(note: NoteData, authorization: str = Header(...)):
    """Add a new note for the authenticated user."""
    try:
        new_note = pim.add_note(authorization, note.title, note.body)
        return NoteResponse(
            success=True, 
            note=new_note.to_dict(),
            message="Note created successfully"
        )
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"Add note error: {e}")
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
        print(f"List notes error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/notes/{note_id}", response_model=NoteResponse)
async def get_note(note_id: str, authorization: str = Header(...)):
    """Get a specific note for the authenticated user."""
    try:
        user_id = auth.validate(authorization)
        note = store.get_note(user_id, note_id)
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        return NoteResponse(
            success=True,
            note=note.to_dict(),
            message="Note retrieved successfully"
        )
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        print(f"Get note error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.put("/notes/{note_id}", response_model=NoteResponse)
async def update_note(note_id: str, note: NoteUpdate, authorization: str = Header(...)):
    """Update a specific note for the authenticated user."""
    try:
        # Validate the note_id format
        if not note_id or not note_id.strip():
            raise HTTPException(status_code=400, detail="Invalid note ID")
        
        # Validate the input data
        if not note.title or not note.title.strip():
            raise HTTPException(status_code=400, detail="Note title cannot be empty")
        
        # Ensure body is not None
        body = note.body if note.body is not None else ""
        
        print(f"Updating note {note_id} with title: '{note.title}' and body: '{body}'")  # Debug log
        
        updated_note = pim.update_note(authorization, note_id, note.title, body)
        return NoteResponse(
            success=True, 
            note=updated_note.to_dict(),
            message="Note updated successfully"
        )
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except ValueError as e:
        error_msg = str(e)
        if "Note not found" in error_msg:
            raise HTTPException(status_code=404, detail=error_msg)
        elif "title cannot be empty" in error_msg:
            raise HTTPException(status_code=400, detail=error_msg)
        else:
            raise HTTPException(status_code=400, detail=error_msg)
    except HTTPException:
        raise
    except Exception as e:
        print(f"Update note error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

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
        print(f"Delete note error: {e}")
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
        "active_sessions": len(auth.active),
        "database_files": {
            "users_db": os.path.exists("users.db"),
            "notes_db": os.path.exists("notes.db")
        }
    }

# -------------------------------
# Database backup endpoints (useful for production)
# -------------------------------
@app.get("/admin/backup")
async def create_backup():
    """Create a backup of the database files."""
    import shutil
    from datetime import datetime
    
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"backup_{timestamp}"
        os.makedirs(backup_dir, exist_ok=True)
        
        # Copy database files
        if os.path.exists("users.db"):
            shutil.copy2("users.db", os.path.join(backup_dir, "users.db"))
        if os.path.exists("notes.db"):
            shutil.copy2("notes.db", os.path.join(backup_dir, "notes.db"))
        
        return {
            "success": True,
            "message": f"Backup created in {backup_dir}",
            "timestamp": timestamp
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup failed: {e}")

# -------------------------------
# Startup event
# -------------------------------
@app.on_event("startup")
async def startup_event():
    """Startup tasks."""
    print("Notes API starting up...")
    print(f"Database files:")
    print(f"  - users.db exists: {os.path.exists('users.db')}")
    print(f"  - notes.db exists: {os.path.exists('notes.db')}")
    print(f"Users loaded: {len(auth.users)}")
    print(f"Active sessions: {len(auth.active)}")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup tasks."""
    print("Notes API shutting down...")
    print("All data has been persisted to SQLite databases.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)