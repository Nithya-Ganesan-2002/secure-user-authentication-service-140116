"""
Pydantic models (schemas) for auth APIs (signup, login, token response).
"""

from pydantic import BaseModel, Field

# PUBLIC_INTERFACE
class UserCreate(BaseModel):
    """Data for user registration."""
    username: str = Field(..., min_length=3, max_length=32, description="Username (must be unique)")
    password: str = Field(..., min_length=6, description="Password (will be hashed)")

# PUBLIC_INTERFACE
class UserLogin(BaseModel):
    """Data for user login."""
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Plain password")

# PUBLIC_INTERFACE
class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type ('bearer')")

