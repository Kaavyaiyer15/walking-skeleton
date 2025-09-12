import os
from fastapi import FastAPI, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .services import AuthService, Storage, PIM
from .domain import AuthError
from .models import UserCreds, NoteData, UserResponse, LoginResponse, NoteResponse, NotesListResponse
from .utils import time_now

# Initialize core services
auth = AuthService()
store = Storage()
pim = PIM(store, auth)

app = FastAPI(title="Notes API", description="A simple notes application with user authentication", version="1.0.0")

# Static frontend
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEBSITE_DIR = os.path.join(BASE_DIR, "..", "website")

if os.path.exists(WEBSITE_DIR):
    app.mount("/static", StaticFiles(directory=WEBSITE_DIR), name="static")

@app.get("/")
async def read_root():
    index_path = os.path.join(WEBSITE_DIR, "index.html")
    return FileResponse(index_path) if os.path.exists(index_path) else {"message": "Notes API is running"}

@app.post("/register", response_model=UserResponse)
async def register(creds: UserCreds):
    try:
        uid = pim.register_user(creds.email, creds.password)
        return UserResponse(success=True, user_id=uid)
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login", response_model=LoginResponse)
async def login(creds: UserCreds):
    try:
        token = pim.login(creds.email, creds.password)
        return LoginResponse(success=True, token=token)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/notes", response_model=NoteResponse)
async def add_note(note: NoteData, authorization: str = Header(...)):
    try:
        new_note = pim.add_note(authorization, note.title, note.body)
        return NoteResponse(success=True, note=new_note.to_dict())
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/notes", response_model=NotesListResponse)
async def list_notes(authorization: str = Header(...)):
    try:
        notes = [n.to_dict() for n in pim.list_notes(authorization)]
        return NotesListResponse(success=True, notes=notes)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time_now()}
