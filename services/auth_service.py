from datetime import datetime
from sqlalchemy.orm import Session

from fastapi import HTTPException
from settings.security import hash_password, verify_password, security
from database.tables import User



class AuthService:
    # Register (writing to bd)
    @staticmethod
    def register_user(user_data, db: Session):
        # Check for user's existance with username
        existing_user = db.query(User).filter(User.username == user_data.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Check for user's existance with email
        existing_email = db.query(User).filter(User.email == user_data.email).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")

        hash_pass = hash_password(user_data.password)

        # Create new user
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hash_pass  # Add hash save
        )
        
        db.add(new_user)
        db.commit()
        
        return {"message": "User created", "user_id": new_user.id}

    # Login (read from BD)
    @staticmethod
    def login_user(user_data, db: Session):
        # Find user in BD
        user = db.query(User).filter(User.username == user_data.username).first()
        if not user or not verify_password(user_data.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Create token
        token = security.create_access_token(uid=str(user.id))
        
        return {"access_token": token}

    @staticmethod
    def logout_user(token: str, db: Session, request):
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
    @staticmethod
    def protected_route(token: str, db: Session):
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
    @staticmethod
    def get_token_from_request(request):
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        
        return token
        
