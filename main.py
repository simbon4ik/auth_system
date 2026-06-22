from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from authx.exceptions import JWTDecodeError
from database.create_tables import create_tables
from settings.config import AuthConfig
from routes import router_auth
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield

app = FastAPI(lifespan=lifespan)

origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router_auth)

@app.exception_handler(JWTDecodeError)
async def authx_jwt_decode_handler(request: Request, exc: JWTDecodeError):
    return JSONResponse(
        status_code=401,
        content={"detail": "Сессия истекла. Пожалуйста, войдите снова.", "error": str(exc)}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

