import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .db import engine, SessionLocal, migrate
from .models import Base
from .seed import seed
from . import routes_auth, routes_devices, routes_reports

STATIC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    migrate()
    with SessionLocal() as db:
        seed(db)
    yield


app = FastAPI(title="ITMon", lifespan=lifespan)
app.include_router(routes_auth.router)
app.include_router(routes_devices.router)
app.include_router(routes_reports.router)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))
