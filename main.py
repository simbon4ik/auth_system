from fastapi import FastAPI, HTTPException, Response, Depends
from authx import AuthX
from config import AuthConfig, Settings
from pydantic import BaseModel
from database import get_db, create_tables, User  # ⬅️ Импортируем БД
from sqlalchemy.orm import Session
from datetime import datetime
from config import settings


from fastapi import Request
import jwt
from config import AuthConfig

# Инициализация конфига для проверки токенов
auth_config = AuthConfig()

app = FastAPI()
security = AuthX(config=auth_config)

# СОЗДАЕМ ТАБЛИЦЫ ПРИ СТАРТЕ
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

# РЕГИСТРАЦИЯ (записывает в БД)
@app.post("/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    # Проверяем нет ли пользователя
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Создаем нового пользователя
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=user_data.password  # Пока без хэширования
    )
    db.add(new_user)
    db.commit()
    
    return {"message": "User created", "user_id": new_user.id}

# ЛОГИН (читает из БД)
@app.post("/login")
def login(user_data: UserLogin, response: Response, db: Session = Depends(get_db)):
    # Ищем пользователя в БАЗЕ ДАННЫХ
    user = db.query(User).filter(User.username == user_data.username).first()
    
    if not user or user.hashed_password != user_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Создаем токен
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



# ЗАЩИЩЕННЫЙ РОУТ С ПРОВЕРКОЙ'''

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