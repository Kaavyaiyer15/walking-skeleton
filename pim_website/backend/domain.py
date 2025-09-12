from typing import Dict

class Note:
    """Represents a single note object."""
    
    def __init__(self, id: str, user_id: str, title: str, body: str, created_time: str, updated_time: str):
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
