import uuid
from datetime import datetime, UTC

def make_id(prefix: str) -> str:
    """Generate a unique ID with a given prefix."""
    return f"{prefix}_{uuid.uuid4()}"

def time_now() -> str:
    """Return the current time in ISO format (UTC, no microseconds)."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()
