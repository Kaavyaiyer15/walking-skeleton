from typing import List, Dict
from pydantic import BaseModel, EmailStr

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
