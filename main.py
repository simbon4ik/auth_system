from fastapi import FastAPI
from database.create_tables import create_tables  # import BD
from settings.config import AuthConfig
from routes import router_auth
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(router_auth)

from fastapi import Request
from fastapi.responses import JSONResponse
from authx.exceptions import JWTDecodeError
@app.exception_handler(JWTDecodeError)
async def authx_jwt_decode_handler(request: Request, exc: JWTDecodeError):
    return JSONResponse(
        status_code=401,
        content={"detail": "Сессия истекла. Пожалуйста, войдите снова.", "error": str(exc)}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

