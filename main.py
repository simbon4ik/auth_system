from fastapi import FastAPI, HTTPException, Response, Depends
from authx import AuthX
from settings.config import AuthConfig, Settings
from pydantic import BaseModel
from database.database import get_db, create_tables, User  # import BD
from sqlalchemy.orm import Session
from datetime import datetime
from settings.config import settings

from slowapi import Limiter
from slowapi.util import get_remote_address #for get ip from http

from fastapi import Request
import jwt
from settings.config import AuthConfig

# Initialize config for check tokens
auth_config = AuthConfig()

app = FastAPI()
security = AuthX(config=auth_config)

# Initialize limit to protect brut force
limiter = Limiter(key_func=get_remote_address)

#Create tables with start app
@app.on_event("startup")
def startup():
    create_tables()

#For post requests
class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

# Register (writing to bd)
@app.post("/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    # Check for user's existance
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create new user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=user_data.password  # Add hash function
    )
    db.add(new_user)
    db.commit()
    
    return {"message": "User created", "user_id": new_user.id}

# Login (read from BD)
@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, user_data: UserLogin, response: Response, db: Session = Depends(get_db)):
    # Find user in BD
    user = db.query(User).filter(User.username == user_data.username).first()
    
    if not user or user.hashed_password != user_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create token
    token = security.create_access_token(uid=str(user.id))
    
    return {"access_token": token}

@app.post("/logout")
def logout(response: Response, db: Session = Depends(get_db), request: Request = None):
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    
    if token:
        payload = security._decode_token(token)
        user_id = payload.sub
        user = db.query(User).get(user_id)
        if user:
            user.last_logout_time = datetime.utcnow()
            db.commit()
    return {"message": "Logged out"}



# Protected route with check token

@app.get("/protected")
def protected_route(request: Request, db: Session = Depends(get_db)):
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    
    if not token:
        return {"error": "No token provided"}
    
    #Last logout time check
    payload = security._decode_token(token)
    user = db.query(User).get(payload.sub)

    if user.last_logout_time and datetime.utcfromtimestamp(payload.iat) < user.last_logout_time:
        raise HTTPException(status_code=401, detail="Token issued before last logout")

 #   payload = security._decode_token(token)
    if not payload:
        return {"error": "Invalid token"}
    
    return {
        "message": "This is REAL protected data!", 
        "user_id": payload.sub,
        "token_valid": True
    }


@app.get("/")
def home():
    return {"message": "Server is running with DATABASE!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)