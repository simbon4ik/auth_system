from fastapi import APIRouter
from sqlalchemy.orm import Session
from user_operations import UserRegister, UserLogin
from fastapi import Response, Depends, Request
from database.create_tables import get_db
from services.auth_service import AuthService

from slowapi import Limiter
from slowapi.util import get_remote_address #for get ip from http

# Initialize limit to protect brut force
limiter = Limiter(key_func=get_remote_address)

router_auth = APIRouter()

# Register (writing to bd)
@router_auth.post("/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    return AuthService.register_user(user_data, db)

# Login (read from BD)
@router_auth.post("/login")
@limiter.limit("5/minute")
def login(request: Request, user_data: UserLogin, response: Response, db: Session = Depends(get_db)):
    return AuthService.login_user(user_data, db)

@router_auth.post("/logout")
def logout(response: Response, db: Session = Depends(get_db), request: Request = None):
    token = AuthService.get_token_from_request(request)
    return AuthService.logout_user(token, db, request)

# Protected route with check token
@router_auth.get("/protected")
def protected_route(request: Request, db: Session = Depends(get_db)):
    token = AuthService.get_token_from_request(request)
    return AuthService.protected_route(token, db)

@router_auth.get("/")
def home():
    return {"message": "Server is running with DATABASE!"}