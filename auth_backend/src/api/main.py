from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

from .schemas import UserCreate, TokenResponse
from .auth_utils import (
    get_user_by_username,
    create_user as create_user_in_db,
    verify_password,
    create_access_token,
    decode_access_token
)


app = FastAPI(
    title="Auth Backend",
    description="Authentication backend API for user signup, login, and token validation.",
    version="0.1.0",
    openapi_tags=[
        {"name": "Authentication", "description": "User registration, login, and token validation"},
        {"name": "Health", "description": "Service health check"}
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@app.get("/", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# PUBLIC_INTERFACE
@app.post("/signup", response_model=dict, summary="User Registration", tags=["Authentication"])
def signup(user: UserCreate):
    """
    Register a new user.  
    - **username**: must be unique  
    - **password**: minimum 6 characters
    """
    existing_user = get_user_by_username(user.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered"
        )
    try:
        create_user_in_db(user.username, user.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    return {"message": "User created successfully."}

# PUBLIC_INTERFACE
@app.post("/login", response_model=TokenResponse, summary="User Login (get JWT token)", tags=["Authentication"])
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate user and return JWT access token.  
    Use 'username' and 'password' fields (form-encoded).
    """
    user = get_user_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    token = create_access_token({"sub": user["username"]})
    return TokenResponse(access_token=token, token_type="bearer")

# PUBLIC_INTERFACE
@app.post("/validate-token", response_model=dict, summary="Validate JWT Token", tags=["Authentication"])
def validate_token(token: str = Depends(oauth2_scheme)):
    """
    Validate a JWT access token and return its payload.
    - Supply Authorization header of form "Bearer <token>"
    """
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    return {"username": payload.get("sub"), "token_valid": True}

