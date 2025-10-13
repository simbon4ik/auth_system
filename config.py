import os                                   #for work with env's vars
from pydantic_settings import BaseSettings  #
from authx import AuthXConfig               #for authx config

class Settings(BaseSettings):
    #Database settings
    DATABASE_URL: str = "sqlite:///./auth_system.db"

    #JWT settings
    JWT_SECRET_KEY: str = "LOMQBWRJK4JKLUH328FDFZA"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRES: int = 900         #15 minutes for access token
    JWT_REFRESH_TOKEN_EXPIRES: int = 2419200    #28 days for refresh token (keep in HTTP-only cookie)

    #Cookie settings
    JWT_ACCESS_COOKIE_NAME: str = "access_token"
    JWT_REFRESH_COOKIE_NAME: str = "refresh_token"
    JWT_TOKEN_LOCATION: list = ["cookies"]

    JWT_COOKIE_HTTPONLY: bool = True      #protect for XSS (block access from JS to cookies)
    #JWT_COOKIE_SECURE: bool = True       #https is needed (cookie only with https)
    JWT_COOKIE_SAMESITE: str = "lax"      #protect for CSRF (block post requests from other site)
    #JWT_COOKIE_CSRF_PROTECT: bool = True  #more protect

    class Config:
        env_file = ".env"           #for read environment - pydantic
        env_file_encoding = "utf-8" 

settings = Settings()

    
class AuthConfig(AuthXConfig):
    JWT_SECRET_KEY: str = settings.JWT_SECRET_KEY
    JWT_ALGORITHM: str = settings.JWT_ALGORITHM
    JWT_ACCESS_TOKEN_EXPIRES: int = settings.JWT_ACCESS_TOKEN_EXPIRES
    JWT_REFRESH_TOKEN_EXPIRES: int = settings.JWT_REFRESH_TOKEN_EXPIRES
    JWT_ACCESS_COOKIE_NAME: str = settings.JWT_ACCESS_COOKIE_NAME
    JWT_REFRESH_COOKIE_NAME: str = settings.JWT_REFRESH_COOKIE_NAME
    JWT_TOKEN_LOCATION: str = settings.JWT_TOKEN_LOCATION