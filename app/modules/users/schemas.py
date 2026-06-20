import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict


class UserRead(BaseModel):
    id:uuid.UUID
    email:EmailStr
    username: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None

    model_config = ConfigDict(from_attributes=True)