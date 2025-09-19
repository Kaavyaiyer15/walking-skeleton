"""
FastAPI backend for Notes App with Enhanced Persistence.

This module provides a complete web API for a notes application with:
- User registration and authentication system
- CRUD operations for personal notes
- SQLite database persistence
- Session management
- Static file serving for frontend
- Comprehensive error handling

The application follows a layered architecture:
- Domain layer: Core business logic (Note, AuthService, Storage, PIM)
- API layer: FastAPI routes and middleware
- Persistence layer: SQLite database operations

Author: Notes App Team
Version: 1.0.0
"""

# Import statements for external dependencies
import uuid  # For generating unique identifiers
import os  # For file system operations
import threading  # For thread-safe database operations
from datetime import datetime, UTC  # For timestamp management
from typing import List, Dict, Any, Optional  # For type hints
from fastapi import FastAPI, HTTPException, Header, Depends, Request  # FastAPI framework
from fastapi.staticfiles import StaticFiles  # For serving static files
from fastapi.responses import FileResponse  # For serving HTML files
from fastapi.middleware.cors import CORSMiddleware  # For cross-origin requests
from pydantic import BaseModel, EmailStr  # For data validation
import hashlib  # For password hashing
import sqlite3  # For database operations
import contextlib  # For database connection management

# -------------------------------
# Utility functions
# -------------------------------

def make_id(prefix: str) -> str:
    """
    Generate a unique identifier with a given prefix.
    
    This function creates a universally unique identifier (UUID) and prefixes it
    with a descriptive string to make IDs more readable and categorizable.
    
    Args:
        prefix (str): The prefix to prepend to the UUID (e.g., "user", "note", "sess")
        
    Returns:
        str: A unique identifier string in format "{prefix}_{uuid}"
        
    Examples:
        >>> make_id("user")
        'user_a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6'
        >>> make_id("note")  
        'note_f6e5d4c3-b2a1-0987-6543-210fedcba987'
    """
    # Generate a random UUID4 and combine with prefix
    return f"{prefix}_{uuid.uuid4()}"

def time_now() -> str:
    """
    Return the current time in ISO format (UTC, no microseconds).
    
    This function provides a standardized timestamp format for the application,
    ensuring all timestamps are in UTC and have consistent formatting without
    microseconds for cleaner storage and comparison.
    
    Returns:
        str: Current timestamp in ISO format (YYYY-MM-DDTHH:MM:SSZ)
        
    Examples:
        >>> time_now()
        '2023-12-07T15:30:45+00:00'
    """
    # Get current UTC time, remove microseconds, convert to ISO format
    return datetime.now(UTC).replace(microsecond=0).isoformat()

def hash_password(password: str) -> str:
    """
    Hash password using SHA-256 algorithm.
    
    This function provides secure password hashing using the SHA-256 cryptographic
    hash function. While SHA-256 is used here for simplicity, production applications
    should consider using bcrypt, scrypt, or Argon2 for better security against
    rainbow table attacks.
    
    Args:
        password (str): Plain text password to hash
        
    Returns:
        str: Hexadecimal representation of the SHA-256 hash
        
    Examples:
        >>> hash_password("mypassword123")
        'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
    """
    # Encode password to bytes, hash with SHA-256, return hex digest
    return hashlib.sha256(password.encode()).hexdigest()

# -------------------------------
# Domain classes
# -------------------------------

class Note:
    """
    Represents a single note object with metadata.
    
    This class encapsulates all the data and behavior for a note in the system.
    Each note belongs to a user and contains title, body content, and timestamps
    for creation and last modification.
    
    Attributes:
        id (str): Unique identifier for the note
        user_id (str): ID of the user who owns this note  
        title (str): Title/subject of the note
        body (str): Main content of the note
        created_time (str): ISO timestamp when note was created
        updated_time (str): ISO timestamp when note was last modified
    """
    
    def __init__(self, id: str, user_id: str, title: str, body: str, 
                 created_time: str, updated_time: str):
        """
        Initialize a new Note instance.
        
        Args:
            id (str): Unique identifier for the note
            user_id (str): ID of the user who owns this note
            title (str): Title/subject of the note  
            body (str): Main content of the note
            created_time (str): ISO timestamp when note was created
            updated_time (str): ISO timestamp when note was last modified
        """
        # Store all note attributes as instance variables
        self.id = id
        self.user_id = user_id
        self.title = title
        self.body = body
        self.created_time = created_time
        self.updated_time = updated_time

    def to_dict(self) -> Dict[str, str]:
        """
        Convert note to dictionary representation for API responses.
        
        This method serializes the note object into a dictionary format suitable
        for JSON responses. The user_id is excluded from the response for security
        as it's handled by the authentication system.
        
        Returns:
            Dict[str, str]: Dictionary containing note data without user_id
            
        Examples:
            >>> note = Note("note_123", "user_456", "My Title", "Content", "2023-12-07T10:00:00+00:00", "2023-12-07T10:00:00+00:00")
            >>> note.to_dict()
            {
                "id": "note_123",
                "title": "My Title", 
                "body": "Content",
                "created_time": "2023-12-07T10:00:00+00:00",
                "updated_time": "2023-12-07T10:00:00+00:00"
            }
        """
        # Return dictionary with public fields (excluding user_id for security)
        return {
            "id": self.id,
            "title": self.title,
            "body": self.body,
            "created_time": self.created_time,
            "updated_time": self.updated_time
        }

class AuthError(Exception): 
    """
    Custom exception for authentication and authorization errors.
    
    This exception is raised when authentication fails, invalid credentials
    are provided, sessions expire, or users attempt unauthorized actions.
    It extends the base Exception class to provide specific error handling
    for authentication-related issues.
    
    Usage:
        raise AuthError("Invalid credentials")
        raise AuthError("Session expired")
    """
    pass

class AuthService:
    """
    Handles user registration, login, and session validation with SQLite persistence.
    
    This service manages the complete user authentication lifecycle including:
    - User registration with email validation
    - Password hashing and verification
    - Session token generation and management
    - Database persistence for users and sessions
    - Thread-safe operations for concurrent access
    
    The service uses SQLite for persistence with two tables:
    - users: Stores user credentials and metadata
    - sessions: Stores active session tokens
    
    Attributes:
        db_path (str): Path to the SQLite database file
        lock (threading.Lock): Thread lock for safe concurrent access
        users (Dict): In-memory cache of user data
        active (Dict): In-memory cache of active sessions
    """
    
    def __init__(self, db_path="users.db"):
        """
        Initialize the AuthService with database connection and in-memory caches.
        
        Sets up the SQLite database, creates necessary tables if they don't exist,
        and loads existing users and sessions into memory for fast access.
        
        Args:
            db_path (str): Path to SQLite database file, defaults to "users.db"
        """
        # Store database path for connection management
        self.db_path = db_path
        # Thread lock to ensure database operations are thread-safe
        self.lock = threading.Lock()
        # Initialize database schema
        self._init_database()
        # In-memory cache for fast user lookup: {email: {id, password_hash}}
        self.users: Dict[str, Dict[str, str]] = {}
        # In-memory cache for active sessions: {token: user_id}
        self.active: Dict[str, str] = {}
        # Load existing data from database into memory caches
        self._load_from_database()

    def _init_database(self):
        """
        Initialize the users and sessions tables in SQLite database.
        
        Creates the database schema if it doesn't exist. Sets up:
        - users table: stores user accounts with email, password hash, timestamps
        - sessions table: stores active session tokens with foreign key to users
        
        The users table has a unique constraint on email to prevent duplicates.
        The sessions table references users via foreign key for data integrity.
        """
        # Get database connection using context manager for automatic cleanup
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            # Create users table with email uniqueness constraint
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_time TEXT NOT NULL
            )
            """)
            # Create sessions table with foreign key reference to users
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_time TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)
            # Commit the schema changes to database
            conn.commit()

    @contextlib.contextmanager
    def _get_db_connection(self):
        """
        Get a database connection with proper error handling and cleanup.
        
        This context manager ensures database connections are properly opened
        and closed, even if exceptions occur during database operations.
        Uses check_same_thread=False to allow multi-threaded access.
        
        Yields:
            sqlite3.Connection: Database connection object
            
        Usage:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users")
        """
        # Create connection with thread safety disabled (we handle with locks)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            # Yield connection to caller
            yield conn
        finally:
            # Ensure connection is always closed, even on exceptions
            conn.close()

    def _load_from_database(self):
        """
        Load existing users and sessions from database into memory caches.
        
        This method populates the in-memory dictionaries with existing data
        from the database on startup. This provides fast lookup performance
        while maintaining persistence.
        """
        # Get database connection for reading existing data
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Load all users into memory cache
            cursor.execute("SELECT id, email, password_hash FROM users")
            for user_id, email, password_hash in cursor.fetchall():
                # Store user data keyed by email for login lookup
                self.users[email] = {"id": user_id, "password_hash": password_hash}
            
            # Load all active sessions into memory cache
            cursor.execute("SELECT token, user_id FROM sessions")
            for token, user_id in cursor.fetchall():
                # Store session mapping token -> user_id
                self.active[token] = user_id

    def add_user(self, email: str, password: str) -> str:
        """
        Register a new user with email and password.
        
        Creates a new user account with the provided credentials. Validates
        that the email is unique and password meets minimum requirements.
        Hashes the password before storage for security.
        
        Args:
            email (str): User's email address (must be unique)
            password (str): Plain text password (minimum 6 characters)
            
        Returns:
            str: Unique user ID of the newly created user
            
        Raises:
            AuthError: If email already exists or password is too short
            
        Examples:
            >>> auth = AuthService()
            >>> user_id = auth.add_user("user@example.com", "securepass123")
            >>> print(user_id)
            'usr_a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6'
        """
        # Use thread lock to prevent race conditions during user creation
        with self.lock:
            # Check if email is already registered
            if email in self.users:
                raise AuthError("Email already exists")
            
            # Validate password meets minimum security requirements
            if len(password) < 6:
                raise AuthError("Password must be at least 6 characters long")
            
            # Generate unique user ID with descriptive prefix
            uid = make_id("usr")
            # Hash password using SHA-256 for secure storage
            password_hash = hash_password(password)
            # Get current timestamp for user creation time
            created_time = time_now()
            
            # Persist new user to database
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (id, email, password_hash, created_time) VALUES (?, ?, ?, ?)",
                    (uid, email, password_hash, created_time)
                )
                # Commit transaction to ensure data is saved
                conn.commit()
            
            # Update in-memory cache for fast future lookups
            self.users[email] = {"id": uid, "password_hash": password_hash}
            # Return the new user ID
            return uid
    
    def login(self, email: str, password: str) -> str:
        """
        Authenticate user and return session token.
        
        Validates user credentials and creates a new session token if
        authentication succeeds. The token can be used for subsequent
        API requests requiring authentication.
        
        Args:
            email (str): User's email address
            password (str): User's plain text password
            
        Returns:
            str: Session token for authenticated requests
            
        Raises:
            AuthError: If email doesn't exist or password is incorrect
            
        Examples:
            >>> token = auth.login("user@example.com", "securepass123")
            >>> print(token)
            'sess_f1e2d3c4-b5a6-9807-8765-4321fedcba09'
        """
        # Use thread lock to prevent race conditions during login
        with self.lock:
            # Check if user exists in our system
            if email not in self.users:
                raise AuthError("Invalid email or password")
            
            # Get user data from memory cache
            user = self.users[email]
            # Hash the provided password for comparison
            password_hash = hash_password(password)
            
            # Verify password matches stored hash
            if user["password_hash"] != password_hash:
                raise AuthError("Invalid email or password")
            
            # Generate new session token with descriptive prefix
            token = make_id("sess")
            # Get current timestamp for session creation time
            created_time = time_now()
            
            # Persist session to database for recovery after restart
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO sessions (token, user_id, created_time) VALUES (?, ?, ?)",
                    (token, user["id"], created_time)
                )
                # Commit transaction to ensure session is saved
                conn.commit()
            
            # Update in-memory cache for fast token validation
            self.active[token] = user["id"]
            # Return session token for client to use in future requests
            return token
    
    def validate(self, token: str) -> str:
        """
        Validate session token and return user ID.
        
        Checks if the provided token represents a valid, active session.
        Handles both bare tokens and "Bearer " prefixed tokens for
        compatibility with standard authorization headers.
        
        Args:
            token (str): Session token to validate (with or without "Bearer " prefix)
            
        Returns:
            str: User ID associated with the valid session
            
        Raises:
            AuthError: If token is missing, invalid, or expired
            
        Examples:
            >>> user_id = auth.validate("sess_abc123...")
            >>> print(user_id)
            'usr_def456...'
            
            >>> user_id = auth.validate("Bearer sess_abc123...")
            >>> print(user_id)  
            'usr_def456...'
        """
        # Check if token was provided
        if not token:
            raise AuthError("Authorization token is required")
        
        # Remove 'Bearer ' prefix if present (common in HTTP Authorization headers)
        if token.startswith("Bearer "):
            token = token[7:]
        
        # Check if token exists in active sessions cache
        if token not in self.active:
            raise AuthError("Invalid or expired session token")
        # Return user ID associated with this session
        return self.active[token]
    
    def logout(self, token: str) -> bool:
        """
        Logout user by removing session token.
        
        Invalidates a session by removing it from both the database and
        in-memory cache. This effectively logs out the user associated
        with the token.
        
        Args:
            token (str): Session token to invalidate (with or without "Bearer " prefix)
            
        Returns:
            bool: True if session was found and removed, False if not found
            
        Examples:
            >>> success = auth.logout("sess_abc123...")
            >>> print(success)
            True
            
            >>> success = auth.logout("invalid_token")
            >>> print(success)
            False
        """
        # Use thread lock to prevent race conditions during logout
        with self.lock:
            # Remove 'Bearer ' prefix if present
            if token.startswith("Bearer "):
                token = token[7:]
            
            # Check if session exists
            if token in self.active:
                # Remove session from database for persistence
                with self._get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    # Commit transaction to ensure removal is persisted
                    conn.commit()
                
                # Remove from in-memory cache
                del self.active[token]
                # Return True indicating successful logout
                return True
            # Return False if token was not found (already logged out)
            return False

class Storage:
    """
    Stores and retrieves notes using SQLite database with enhanced persistence.
    
    This class handles all database operations for notes including:
    - Creating and managing the notes table schema
    - CRUD operations (Create, Read, Update, Delete) for notes
    - Thread-safe database access with proper locking
    - Performance optimization with database indexes
    - Transaction safety with rollback on errors
    - WAL mode for better concurrency and durability
    
    The notes are stored in a single table with columns for:
    - id: Unique note identifier
    - user_id: Owner of the note (foreign key concept)
    - title: Note title/subject
    - body: Main note content
    - created_time: When note was created
    - updated_time: When note was last modified
    
    Attributes:
        db_path (str): Path to the SQLite database file
        lock (threading.Lock): Thread lock for safe concurrent access
    """

    def __init__(self, db_path="notes.db"):
        """
        Initialize the Storage service with SQLite database.
        
        Sets up the database connection, creates the notes table if needed,
        and configures database settings for optimal performance and safety.
        
        Args:
            db_path (str): Path to SQLite database file, defaults to "notes.db"
        """
        # Store database path for connection management
        self.db_path = db_path
        # Thread lock to ensure database operations are thread-safe
        self.lock = threading.Lock()
        # Initialize database schema and indexes
        self._create_table()

    @contextlib.contextmanager
    def _get_db_connection(self):
        """
        Get a database connection with optimized settings for performance and safety.
        
        This context manager creates a database connection with specific PRAGMA
        settings for enhanced performance and data integrity:
        - WAL mode: Better concurrency and crash recovery
        - Foreign keys: Enforce referential integrity
        - Synchronous FULL: Ensure data is written to disk
        
        Yields:
            sqlite3.Connection: Optimized database connection
        """
        # Create connection with thread safety disabled (we handle with locks)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        # Enable WAL (Write-Ahead Logging) mode for better concurrency and durability
        conn.execute('PRAGMA journal_mode=WAL;')
        # Enable foreign key constraints for data integrity
        conn.execute('PRAGMA foreign_keys=ON;')
        # Set synchronous mode to FULL for maximum data safety
        conn.execute('PRAGMA synchronous=FULL;')
        try:
            # Yield connection to caller
            yield conn
        finally:
            # Ensure connection is always closed
            conn.close()

    def _create_table(self):
        """
        Create notes table and indexes if they don't exist.
        
        Sets up the database schema for storing notes with appropriate
        indexes for query performance. Creates:
        - Main notes table with all required columns
        - Index on user_id for fast user-specific queries
        - Index on created_time (descending) for chronological ordering
        """
        # Get optimized database connection
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            # Create notes table with all required columns
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
            # Create index for fast filtering by user_id
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id)
            """)
            # Create index for fast ordering by creation time (newest first)
            cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notes_created_time ON notes(created_time DESC)
            """)
            # Commit schema changes to database
            conn.commit()

    def add_note(self, note: Note) -> Note:
        """
        Insert a note into the database with transaction safety.
        
        Adds a new note to the database within a transaction. If any error
        occurs during insertion, the transaction is rolled back to maintain
        data consistency. Uses thread locking to prevent concurrent access issues.
        
        Args:
            note (Note): Note object to insert into database
            
        Returns:
            Note: The same note object that was successfully inserted
            
        Raises:
            Exception: If database insertion fails
            
        Examples:
            >>> note = Note("note_123", "user_456", "My Title", "Content", "2023-12-07T10:00:00", "2023-12-07T10:00:00")
            >>> stored_note = storage.add_note(note)
            >>> print(f"Stored note: {stored_note.id}")
        """
        # Use thread lock to prevent race conditions during insertion
        with self.lock:
            # Get database connection with optimized settings
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                try:
                    # Insert note data into database
                    cursor.execute(
                        "INSERT INTO notes (id, user_id, title, body, created_time, updated_time) VALUES (?, ?, ?, ?, ?, ?)",
                        (note.id, note.user_id, note.title, note.body, note.created_time, note.updated_time)
                    )
                    # Commit transaction to persist changes
                    conn.commit()
                    # Log successful insertion for debugging
                    print(f"Note saved successfully: {note.id}")
                    # Return the successfully stored note
                    return note
                except sqlite3.Error as e:
                    # Rollback transaction on any database error
                    conn.rollback()
                    # Log error for debugging
                    print(f"Database error saving note: {e}")
                    # Raise exception with descriptive message
                    raise Exception(f"Failed to save note: {e}")

    def list_notes(self, user_id: str) -> List[Note]:
        """
        Retrieve all notes for a user, ordered by creation time (newest first).
        
        Fetches all notes belonging to a specific user from the database.
        Results are automatically ordered by creation time in descending order
        thanks to the database index, providing newest notes first.
        
        Args:
            user_id (str): ID of the user whose notes to retrieve
            
        Returns:
            List[Note]: List of Note objects ordered by creation time (newest first)
            
        Examples:
            >>> notes = storage.list_notes("user_456")
            >>> print(f"Found {len(notes)} notes")
            >>> for note in notes:
            ...     print(f"- {note.title} (created: {note.created_time})")
        """
        # Get database connection (no lock needed for read operations)
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            # Query notes for specific user, ordered by creation time (newest first)
            cursor.execute(
                "SELECT id, user_id, title, body, created_time, updated_time FROM notes WHERE user_id=? ORDER BY created_time DESC",
                (user_id,)
            )
            # Fetch all matching rows
            rows = cursor.fetchall()
            # Convert database rows to Note objects and return as list
            return [Note(*row) for row in rows]

    def get_note(self, user_id: str, note_id: str) -> Optional[Note]:
        """
        Retrieve a single note by ID for a specific user.
        
        Fetches a specific note if it exists and belongs to the specified user.
        The user_id check ensures users can only access their own notes.
        
        Args:
            user_id (str): ID of the user who should own the note
            note_id (str): ID of the note to retrieve
            
        Returns:
            Optional[Note]: Note object if found and owned by user, None otherwise
            
        Examples:
            >>> note = storage.get_note("user_456", "note_123")
            >>> if note:
            ...     print(f"Found note: {note.title}")
            ... else:
            ...     print("Note not found or access denied")
        """
        # Get database connection
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            # Query for specific note owned by specific user
            cursor.execute(
                "SELECT id, user_id, title, body, created_time, updated_time FROM notes WHERE user_id=? AND id=?",
                (user_id, note_id)
            )
            # Fetch single matching row
            row = cursor.fetchone()
            # Return Note object if found, None otherwise
            return Note(*row) if row else None

    def update_note(self, note: Note) -> bool:
        """
        Update an existing note in the database.
        
        Updates the title, body, and updated_time fields of an existing note.
        Uses the note's ID and user_id to ensure only the owner can update
        their notes. Operation is performed within a transaction for safety.
        
        Args:
            note (Note): Note object with updated data
            
        Returns:
            bool: True if note was updated, False if note not found
            
        Raises:
            Exception: If database update fails
            
        Examples:
            >>> note.title = "Updated Title"
            >>> note.body = "Updated content"
            >>> note.updated_time = time_now()
            >>> success = storage.update_note(note)
            >>> print(f"Update {'succeeded' if success else 'failed'}")
        """
        # Use thread lock to prevent race conditions during update
        with self.lock:
            # Get database connection with optimized settings
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                try:
                    # Update note fields where ID and user_id match
                    cursor.execute(
                        "UPDATE notes SET title=?, body=?, updated_time=? WHERE id=? AND user_id=?",
                        (note.title, note.body, note.updated_time, note.id, note.user_id)
                    )
                    # Commit transaction to persist changes
                    conn.commit()
                    # Return True if any rows were updated, False otherwise
                    return cursor.rowcount > 0
                except sqlite3.Error as e:
                    # Rollback transaction on any database error
                    conn.rollback()
                    # Raise exception with descriptive message
                    raise Exception(f"Failed to update note: {e}")

    def delete_note(self, user_id: str, note_id: str) -> bool:
        """
        Delete a note by ID for a specific user.
        
        Removes a note from the database if it exists and belongs to the
        specified user. The user_id check ensures users can only delete
        their own notes.
        
        Args:
            user_id (str): ID of the user who should own the note
            note_id (str): ID of the note to delete
            
        Returns:
            bool: True if note was deleted, False if note not found
            
        Examples:
            >>> success = storage.delete_note("user_456", "note_123")
            >>> print(f"Deletion {'succeeded' if success else 'failed'}")
        """
        # Use thread lock to prevent race conditions during deletion
        with self.lock:
            # Get database connection
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                # Delete note where both user_id and note_id match
                cursor.execute("DELETE FROM notes WHERE user_id=? AND id=?", (user_id, note_id))
                # Commit transaction to persist deletion
                conn.commit()
                # Return True if any rows were deleted, False otherwise
                return cursor.rowcount > 0

class PIM:
    """
    Personal Information Manager - Main application logic for user and notes management.
    
    This class provides the high-level business logic layer that coordinates
    between the authentication service and storage service. It implements
    the core functionality of the notes application:
    
    - User registration and login workflows
    - Authenticated note operations (CRUD)
    - Input validation and sanitization
    - Error handling and user feedback
    - Session management
    
    The PIM (Personal Information Manager) acts as a facade that simplifies
    the interaction between the API layer and the underlying services.
    
    Attributes:
        store (Storage): Database storage service for notes
        auth (AuthService): Authentication service for users and sessions
    """
    
    def __init__(self, store: Storage, auth: AuthService):
        """
        Initialize PIM with storage and authentication services.
        
        Args:
            store (Storage): Storage service instance for note persistence
            auth (AuthService): Authentication service instance for user management
        """
        # Store reference to storage service for note operations
        self.store = store
        # Store reference to auth service for user operations
        self.auth = auth

    def register_user(self, email: str, password: str) -> str:
        """
        Register a new user account.
        
        Creates a new user account using the authentication service.
        Validates input and handles any authentication errors.
        
        Args:
            email (str): User's email address for registration
            password (str): User's password (minimum 6 characters)
            
        Returns:
            str: Unique user ID of the newly registered user
            
        Raises:
            AuthError: If email already exists or password validation fails
        """
        # Delegate user registration to authentication service
        return self.auth.add_user(email, password)
    
    def login(self, email: str, password: str) -> str:
        """
        Login user and return session token.
        
        Authenticates user credentials and creates a new session token
        that can be used for subsequent API requests.
        
        Args:
            email (str): User's email address
            password (str): User's password
            
        Returns:
            str: Session token for authenticated requests
            
        Raises:
            AuthError: If credentials are invalid
        """
        # Delegate login to authentication service
        return self.auth.login(email, password)
    
    def logout(self, token: str) -> bool:
        """
        Logout user by invalidating session token.
        
        Removes the session token from active sessions, effectively
        logging out the user.
        
        Args:
            token (str): Session token to invalidate
            
        Returns:
            bool: True if logout successful, False if token not found
        """
        # Delegate logout to authentication service
        return self.auth.logout(token)
    
    def add_note(self, token: str, title: str, body: str = "") -> Note:
        """
        Add a new note for authenticated user.
        
        Creates a new note after validating the user's session token
        and input data. Automatically sets creation and update timestamps.
        
        Args:
            token (str): Session token for authentication
            title (str): Title of the note (required, cannot be empty)
            body (str): Body content of the note (optional, defaults to empty)
            
        Returns:
            Note: The newly created note object
            
        Raises:
            AuthError: If session token is invalid
            ValueError: If title is empty or whitespace only
        """
        # Validate session token and get user ID
        user_id = self.auth.validate(token)
        
        # Validate that title is not empty after stripping whitespace
        if not title.strip():
            raise ValueError("Note title cannot be empty")
        
        # Get current timestamp for both creation and update time
        now = time_now()
        # Create new Note object with generated ID and current timestamps
        note = Note(make_id("note"), user_id, title.strip(), body.strip(), now, now)
        # Store note in database and return the stored note
        return self.store.add_note(note)
    
    def update_note(self, token: str, note_id: str, title: str, body: str = "") -> Note:
        """
        Update an existing note for authenticated user.
        
        Updates an existing note's title and body while preserving the
        original creation time and updating the modification timestamp.
        
        Args:
            token (str): Session token for authentication
            note_id (str): ID of the note to update
            title (str): New title for the note (required, cannot be empty)
            body (str): New body content for the note (optional, defaults to empty)
            
        Returns:
            Note: The updated note object
            
        Raises:
            AuthError: If session token is invalid
            ValueError: If title is empty, note not found, or update fails
        """
        # Validate session token and get user ID
        user_id = self.auth.validate(token)
        
        # Validate that title is not empty after stripping whitespace
        if not title.strip():
            raise ValueError("Note title cannot be empty")
        
        # Get existing note to preserve creation time and verify ownership
        existing_note = self.store.get_note(user_id, note_id)
        if not existing_note:
            raise ValueError("Note not found")
        
        # Create updated note with new content but preserved creation time
        updated_note = Note(
            note_id, user_id, title.strip(), body.strip(), 
            existing_note.created_time, time_now()
        )
        
        # Attempt to update note in database
        if self.store.update_note(updated_note):
            # Return updated note if successful
            return updated_note
        else:
            # Raise error if update failed
            raise ValueError("Failed to update note")
    
    def list_notes(self, token: str) -> List[Note]:
        """
        List all notes for authenticated user.
        
        Retrieves all notes belonging to the authenticated user,
        ordered by creation time (newest first).
        
        Args:
            token (str): Session token for authentication
            
        Returns:
            List[Note]: List of user's notes ordered by creation time
            
        Raises:
            AuthError: If session token is invalid
        """
        # Validate session token and get user ID
        user_id = self.auth.validate(token)
        # Retrieve and return all notes for this user
        return self.store.list_notes(user_id)
    
    def delete_note(self, token: str, note_id: str) -> bool:
        """
        Delete a note for authenticated user.
        
        Removes a note from the database after verifying the user
        owns the note through authentication.
        
        Args:
            token (str): Session token for authentication
            note_id (str): ID of the note to delete
            
        Returns:
            bool: True if note was deleted, False if not found
            
        Raises:
            AuthError: If session token is invalid
        """
        # Validate session token and get user ID
        user_id = self.auth.validate(token)
        # Delete note and return success status
        return self.store.delete_note(user_id, note_id)

# -------------------------------
# FastAPI App Setup
# -------------------------------

"""
FastAPI application setup and configuration.

This section initializes the FastAPI application with middleware,
static file serving, and core services.
"""

# Create FastAPI application instance with metadata
app = FastAPI(
    title="Notes API",
    description="A simple notes application with user authentication and persistent storage",
    version="1.0.0"
)

# Add CORS middleware to allow cross-origin requests from web browsers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup static file serving for frontend HTML, CSS, JS
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Get current script directory
WEBSITE_DIR = os.path.join(BASE_DIR, "website")  # Path to website files

# Mount static files if website directory exists
if os.path.exists(WEBSITE_DIR):
    app.mount("/static", StaticFiles(directory=WEBSITE_DIR), name="static")

# Initialize core services with separate databases for better organization
auth = AuthService("users.db")  # Authentication service with users database
store = Storage("notes.db")  # Storage service with notes database
pim = PIM(store, auth)  # Main application logic coordinating services

# -------------------------------
# Pydantic Models for API validation
# -------------------------------

"""
Pydantic models for request/response validation and serialization.

These models define the structure of data exchanged between the API
and clients, providing automatic validation and documentation.
"""

class UserCreds(BaseModel):
    """
    User credentials for registration and login requests.
    
    Attributes:
        email (EmailStr): Validated email address
        password (str): Plain text password (will be hashed)
    """
    email: EmailStr  # Automatically validates email format
    password: str    # Plain text password for authentication

class NoteData(BaseModel):
    """
    Note data for creating new notes.
    
    Attributes:
        title (str): Note title/subject (required)
        body (str): Note content (optional, defaults to empty string)
    """
    title: str        # Required note title
    body: str = ""    # Optional note body with default empty value

class NoteUpdate(BaseModel):
    """
    Note data for updating existing notes.
    
    Attributes:
        title (str): Updated note title/subject (required)
        body (str): Updated note content (optional, defaults to empty string)
    """
    title: str        # Required updated title
    body: str = ""    # Optional updated body with default empty value

class UserResponse(BaseModel):
    """
    Response model for user registration.
    
    Attributes:
        success (bool): Whether the operation succeeded
        user_id (str): Unique identifier of the created user
        message (str): Human-readable success message
    """
    success: bool                                    # Operation success flag
    user_id: str                                    # Generated user ID
    message: str = "User registered successfully"   # Default success message

class LoginResponse(BaseModel):
    """
    Response model for user login.
    
    Attributes:
        success (bool): Whether login succeeded
        token (str): Session token for authenticated requests
        message (str): Human-readable success message
    """
    success: bool                          # Login success flag
    token: str                            # Generated session token
    message: str = "Login successful"     # Default success message

class NoteResponse(BaseModel):
    """
    Response model for single note operations (create, read, update).
    
    Attributes:
        success (bool): Whether the operation succeeded
        note (Dict[str, str]): Note data as dictionary
        message (str): Human-readable success message
    """
    success: bool                                      # Operation success flag
    note: Dict[str, str]                              # Note data dictionary
    message: str = "Note operation successful"        # Default success message

class NotesListResponse(BaseModel):
    """
    Response model for listing multiple notes.
    
    Attributes:
        success (bool): Whether the operation succeeded
        notes (List[Dict[str, str]]): List of note data dictionaries
        count (int): Number of notes returned
    """
    success: bool                        # Operation success flag
    notes: List[Dict[str, str]]         # List of note dictionaries
    count: int                          # Count of returned notes

class MessageResponse(BaseModel):
    """
    Generic response model for operations that return only a message.
    
    Attributes:
        success (bool): Whether the operation succeeded
        message (str): Human-readable message about the operation
    """
    success: bool    # Operation success flag
    message: str     # Descriptive message

# -------------------------------
# Helper function for authentication
# -------------------------------

def get_current_user(authorization: str = Header(None)) -> str:
    """
    Extract and validate authorization token from request headers.
    
    This dependency function extracts the Authorization header from
    incoming requests and validates the session token. It's used by
    protected endpoints to ensure only authenticated users can access them.
    
    Args:
        authorization (str): Authorization header value (automatically injected by FastAPI)
        
    Returns:
        str: User ID of the authenticated user
        
    Raises:
        HTTPException: 401 if authorization header is missing or token is invalid
    """
    # Check if authorization header was provided
    if not authorization:
        raise HTTPException(
            status_code=401, 
            detail="Authorization header is required"
        )
    try:
        # Validate token and return user ID
        return auth.validate(authorization)
    except AuthError as e:
        # Convert auth errors to HTTP 401 Unauthorized
        raise HTTPException(status_code=401, detail=str(e))

# -------------------------------
# API Routes
# -------------------------------

"""
FastAPI route definitions for all API endpoints.

Routes are organized by functionality:
- Root/static serving
- Authentication (register, login, logout)
- Note operations (CRUD)
- System endpoints (health, backup)
"""

@app.get("/")
async def read_root():
    """
    Serve index.html from website folder or return API info.
    
    This root endpoint serves the main HTML file if it exists in the
    website directory, otherwise returns basic API information.
    
    Returns:
        FileResponse or dict: HTML file or API metadata
    """
    # Construct path to index.html in website directory
    index_path = os.path.join(WEBSITE_DIR, "index.html")
    # Serve HTML file if it exists
    if os.path.exists(index_path):
        return FileResponse(index_path)
    # Otherwise return API information
    return {"message": "Notes API is running", "version": "1.0.0"}

@app.post("/register", response_model=UserResponse)
async def register(creds: UserCreds):
    """
    Register a new user account.
    
    Creates a new user account with the provided email and password.
    Email must be unique and password must meet minimum requirements.
    
    Args:
        creds (UserCreds): User credentials containing email and password
        
    Returns:
        UserResponse: Success status, user ID, and message
        
    Raises:
        HTTPException: 400 if email exists or validation fails, 500 for server errors
    """
    try:
        # Attempt to register user through PIM
        uid = pim.register_user(creds.email, creds.password)
        # Return success response with generated user ID
        return UserResponse(success=True, user_id=uid)
    except AuthError as e:
        # Convert authentication errors to HTTP 400 Bad Request
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Log unexpected errors for debugging
        print(f"Registration error: {e}")
        # Return generic error to avoid information disclosure
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/login", response_model=LoginResponse)
async def login(creds: UserCreds):
    """
    Login with email and password.
    
    Authenticates user credentials and returns a session token
    that can be used for subsequent API requests.
    
    Args:
        creds (UserCreds): User credentials containing email and password
        
    Returns:
        LoginResponse: Success status, session token, and message
        
    Raises:
        HTTPException: 401 for invalid credentials, 500 for server errors
    """
    try:
        # Attempt to login user through PIM
        token = pim.login(creds.email, creds.password)
        # Return success response with session token
        return LoginResponse(success=True, token=token)
    except AuthError as e:
        # Convert authentication errors to HTTP 401 Unauthorized
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        # Log unexpected errors for debugging
        print(f"Login error: {e}")
        # Return generic error to avoid information disclosure
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/logout", response_model=MessageResponse)
async def logout(authorization: str = Header(...)):
    """
    Logout the current user.
    
    Invalidates the session token, effectively logging out the user.
    The token will no longer be valid for authenticated requests.
    
    Args:
        authorization (str): Authorization header containing session token
        
    Returns:
        MessageResponse: Success status and logout message
        
    Raises:
        HTTPException: 500 for server errors
    """
    try:
        # Attempt to logout user through PIM
        success = pim.logout(authorization)
        if success:
            # Return success message if logout succeeded
            return MessageResponse(success=True, message="Logged out successfully")
        else:
            # Return message indicating already logged out
            return MessageResponse(success=False, message="Already logged out")
    except Exception as e:
        # Log unexpected errors for debugging
        print(f"Logout error: {e}")
        # Return generic error
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/notes", response_model=NoteResponse)
async def add_note(note: NoteData, authorization: str = Header(...)):
    """
    Add a new note for the authenticated user.
    
    Creates a new note with the provided title and body content.
    The note is automatically associated with the authenticated user.
    
    Args:
        note (NoteData): Note data containing title and optional body
        authorization (str): Authorization header containing session token
        
    Returns:
        NoteResponse: Success status, created note data, and message
        
    Raises:
        HTTPException: 401 for auth errors, 400 for validation errors, 500 for server errors
    """
    try:
        # Create new note through PIM
        new_note = pim.add_note(authorization, note.title, note.body)
        # Return success response with created note data
        return NoteResponse(
            success=True, 
            note=new_note.to_dict(),
            message="Note created successfully"
        )
    except AuthError as e:
        # Convert authentication errors to HTTP 401 Unauthorized
        raise HTTPException(status_code=401, detail=str(e))
    except ValueError as e:
        # Convert validation errors to HTTP 400 Bad Request
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Log unexpected errors for debugging
        print(f"Add note error: {e}")
        # Return generic error
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/notes", response_model=NotesListResponse)
async def list_notes(authorization: str = Header(...)):
    """
    List all notes for the authenticated user.
    
    Retrieves all notes belonging to the authenticated user,
    ordered by creation time with newest notes first.
    
    Args:
        authorization (str): Authorization header containing session token
        
    Returns:
        NotesListResponse: Success status, list of notes, and count
        
    Raises:
        HTTPException: 401 for auth errors, 500 for server errors
    """
    try:
        # Get all notes for authenticated user through PIM
        notes = [n.to_dict() for n in pim.list_notes(authorization)]
        # Return success response with notes list and count
        return NotesListResponse(success=True, notes=notes, count=len(notes))
    except AuthError as e:
        # Convert authentication errors to HTTP 401 Unauthorized
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        # Log unexpected errors for debugging
        print(f"List notes error: {e}")
        # Return generic error
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/notes/{note_id}", response_model=NoteResponse)
async def get_note(note_id: str, authorization: str = Header(...)):
    """
    Get a specific note for the authenticated user.
    
    Retrieves a single note by ID if it exists and belongs to
    the authenticated user.
    
    Args:
        note_id (str): ID of the note to retrieve
        authorization (str): Authorization header containing session token
        
    Returns:
        NoteResponse: Success status, note data, and message
        
    Raises:
        HTTPException: 401 for auth errors, 404 if note not found, 500 for server errors
    """
    try:
        # Validate session and get user ID
        user_id = auth.validate(authorization)
        # Get specific note from storage
        note = store.get_note(user_id, note_id)
        # Check if note was found
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        # Return success response with note data
        return NoteResponse(
            success=True,
            note=note.to_dict(),
            message="Note retrieved successfully"
        )
    except AuthError as e:
        # Convert authentication errors to HTTP 401 Unauthorized
        raise HTTPException(status_code=401, detail=str(e))
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # Log unexpected errors for debugging
        print(f"Get note error: {e}")
        # Return generic error
        raise HTTPException(status_code=500, detail="Internal server error")

@app.put("/notes/{note_id}", response_model=NoteResponse)
async def update_note(note_id: str, note: NoteUpdate, authorization: str = Header(...)):
    """
    Update a specific note for the authenticated user.
    
    Updates an existing note's title and body content while preserving
    the creation time and updating the modification timestamp.
    
    Args:
        note_id (str): ID of the note to update
        note (NoteUpdate): Updated note data containing title and body
        authorization (str): Authorization header containing session token
        
    Returns:
        NoteResponse: Success status, updated note data, and message
        
    Raises:
        HTTPException: 400/404 for validation/not found, 401 for auth, 500 for server errors
    """
    try:
        # Validate the note_id parameter
        if not note_id or not note_id.strip():
            raise HTTPException(status_code=400, detail="Invalid note ID")
        
        # Validate the title is not empty
        if not note.title or not note.title.strip():
            raise HTTPException(status_code=400, detail="Note title cannot be empty")
        
        # Ensure body is not None (default to empty string)
        body = note.body if note.body is not None else ""
        
        # Debug logging for troubleshooting
        print(f"Updating note {note_id} with title: '{note.title}' and body: '{body}'")
        
        # Update note through PIM
        updated_note = pim.update_note(authorization, note_id, note.title, body)
        # Return success response with updated note data
        return NoteResponse(
            success=True, 
            note=updated_note.to_dict(),
            message="Note updated successfully"
        )
    except AuthError as e:
        # Convert authentication errors to HTTP 401 Unauthorized
        raise HTTPException(status_code=401, detail=str(e))
    except ValueError as e:
        # Handle different types of validation errors
        error_msg = str(e)
        if "Note not found" in error_msg:
            raise HTTPException(status_code=404, detail=error_msg)
        elif "title cannot be empty" in error_msg:
            raise HTTPException(status_code=400, detail=error_msg)
        else:
            raise HTTPException(status_code=400, detail=error_msg)
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # Log unexpected errors for debugging
        print(f"Update note error: {e}")
        # Return detailed error for debugging (be careful in production)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.delete("/notes/{note_id}", response_model=MessageResponse)
async def delete_note(note_id: str, authorization: str = Header(...)):
    """
    Delete a specific note for the authenticated user.
    
    Removes a note from the database if it exists and belongs to
    the authenticated user.
    
    Args:
        note_id (str): ID of the note to delete
        authorization (str): Authorization header containing session token
        
    Returns:
        MessageResponse: Success status and deletion message
        
    Raises:
        HTTPException: 401 for auth errors, 404 if note not found, 500 for server errors
    """
    try:
        # Delete note through PIM
        success = pim.delete_note(authorization, note_id)
        if success:
            # Return success message if deletion succeeded
            return MessageResponse(success=True, message="Note deleted successfully")
        else:
            # Return 404 if note was not found
            raise HTTPException(status_code=404, detail="Note not found")
    except AuthError as e:
        # Convert authentication errors to HTTP 401 Unauthorized
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        # Log unexpected errors for debugging
        print(f"Delete note error: {e}")
        # Return generic error
        raise HTTPException(status_code=500, detail="Internal server error")

# -------------------------------
# System and utility endpoints
# -------------------------------

@app.get("/health")
async def health_check():
    """
    Simple health check endpoint for monitoring and diagnostics.
    
    Returns system status information including database connectivity,
    user counts, and active session information. Useful for monitoring
    tools and debugging.
    
    Returns:
        dict: System health information including status, timestamps, and counts
    """
    # Return comprehensive health information
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

@app.get("/admin/backup")
async def create_backup():
    """
    Create a backup of the database files.
    
    Creates a timestamped backup directory and copies the SQLite
    database files for data protection and recovery purposes.
    Useful for manual backups or automated backup scripts.
    
    Returns:
        dict: Backup status, directory name, and timestamp
        
    Raises:
        HTTPException: 500 if backup creation fails
    """
    # Import required modules for file operations
    import shutil
    from datetime import datetime
    
    try:
        # Generate timestamp for unique backup directory name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"backup_{timestamp}"
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)
        
        # Copy users database if it exists
        if os.path.exists("users.db"):
            shutil.copy2("users.db", os.path.join(backup_dir, "users.db"))
        # Copy notes database if it exists
        if os.path.exists("notes.db"):
            shutil.copy2("notes.db", os.path.join(backup_dir, "notes.db"))
        
        # Return success information
        return {
            "success": True,
            "message": f"Backup created in {backup_dir}",
            "timestamp": timestamp
        }
    except Exception as e:
        # Return error if backup fails
        raise HTTPException(status_code=500, detail=f"Backup failed: {e}")

# -------------------------------
# Application lifecycle events
# -------------------------------

@app.on_event("startup")
async def startup_event():
    """
    Startup tasks and system initialization logging.
    
    Performs initialization tasks when the FastAPI application starts up.
    Logs system status information for debugging and monitoring.
    """
    # Log startup information
    print("Notes API starting up...")
    print(f"Database files:")
    print(f"  - users.db exists: {os.path.exists('users.db')}")
    print(f"  - notes.db exists: {os.path.exists('notes.db')}")
    print(f"Users loaded: {len(auth.users)}")
    print(f"Active sessions: {len(auth.active)}")

@app.on_event("shutdown")
async def shutdown_event():
    """
    Cleanup tasks and graceful shutdown logging.
    
    Performs cleanup tasks when the FastAPI application shuts down.
    Logs shutdown information and confirms data persistence.
    """
    # Log shutdown information
    print("Notes API shutting down...")
    print("All data has been persisted to SQLite databases.")

# -------------------------------
# Application entry point
# -------------------------------

if __name__ == "__main__":
    """
    Main entry point for running the application directly.
    
    When this script is executed directly (not imported), it starts
    the FastAPI application using uvicorn ASGI server on all interfaces
    at port 8000.
    """
    # Import uvicorn ASGI server
    import uvicorn
    # Run the FastAPI app on all interfaces, port 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)