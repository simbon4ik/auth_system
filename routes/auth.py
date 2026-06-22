from fastapi import APIRouter, Response, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from user_operations import UserRegister, UserLogin
from database.create_tables import get_db
from database.tables import User, UserRole
from services.auth_service import AuthService, security
from fastapi.security import HTTPBearer
from limits import parse
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter

# initialize the storage and rate limiter
security_bearer = HTTPBearer(auto_error=False)
storage = MemoryStorage()
strategy = MovingWindowRateLimiter(storage)

# create rate_limit dependency
def rate_limit_dependency(request: Request):
    token = AuthService.get_token_from_request(request)
    user_id = None
    role = None

    if token:
        try:
            payload = security._decode_token(token)
            user_id = payload.sub
            role = payload.get("role")
        except Exception:
            pass  # user is anon if there is no token in request

    if role == UserRole.SERVICE.name:
        limit_str = "120/minute"
        key = f"service_{user_id}"
    elif user_id:
        limit_str = "10/minute"
        key = f"user_{user_id}"
    else:
        # IP limit for anon
        limit_str = "10/minute"
        key = request.client.host if request.client else "unknown"

    # check limit
    limit_obj = parse(limit_str)
    if not strategy.hit(limit_obj, key):
        raise HTTPException(
            status_code=429, 
            detail=f"Rate limit exceeded: {limit_str}. Try again later."
        )
    
class AccessChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, token_payload = Depends(security.access_token_required)):
        if token_payload.role not in self.allowed_roles:
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return token_payload

router_auth = APIRouter(tags=["Authentication"])

@router_auth.post("/auth/register", dependencies=[Depends(rate_limit_dependency)])
def register(request: Request, user_data: UserRegister, db: Session = Depends(get_db)):
    return AuthService.register_user(user_data, db)

@router_auth.post("/auth/login", dependencies=[Depends(rate_limit_dependency)])
def login(request: Request, user_data: UserLogin, response: Response, db: Session = Depends(get_db)):
    return AuthService.login_user(user_data, db, response)

@router_auth.post("/auth/logout", dependencies=[Depends(rate_limit_dependency)])
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = AuthService.get_token_from_request(request)
    return AuthService.logout_user(token, db, request)

# protected route with check token
@router_auth.get("/audio/verify",
                dependencies=[
                    Depends(AccessChecker(["SERVICE", "ADMIN"])),
                    Depends(rate_limit_dependency),
                    Depends(security_bearer)
                ])
def protected_route(request: Request, db: Session = Depends(get_db)):
    token = AuthService.get_token_from_request(request)
    return AuthService.protected_route(token, db)

@router_auth.get("/")
def home():
    return {"message": "Server is running with DATABASE!"}

@router_auth.post("/auth/refresh")
def refresh_route(request: Request, response: Response, db: Session = Depends(get_db)):
    refresh_token = request.cookies.get("refresh_token")
    return AuthService.refresh_token_update(refresh_token, db, response)
