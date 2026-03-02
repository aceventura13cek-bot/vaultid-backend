from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from auth.routes import router as auth_router

app = FastAPI(title="VaultID Auth Server")


app.include_router(auth_router)


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def health():
    return {"status": "VaultID running"}
