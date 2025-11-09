from fastapi import FastAPI
from database.create_tables import create_tables  # import BD
from settings.config import AuthConfig
from routes import router_auth


app = FastAPI()
app.include_router(router_auth)

#Create tables with start app
@app.on_event("startup")
def startup():
    create_tables()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)