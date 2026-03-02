from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import secrets

router = APIRouter(prefix="/auth", tags=["auth"])

templates = Jinja2Templates(directory="templates")


# 1️⃣ AUTHORIZATION ENDPOINT (shows consent page)
@router.get("/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    state: str
):
    return templates.TemplateResponse(
        "consent.html",
        {
            "request": request,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "app_name": client_id
        }
    )


# 2️⃣ USER ALLOWS ACCESS
@router.post("/allow")
async def allow(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(...)
):
    # pseudo access token
    token = secrets.token_urlsafe(32)

    redirect_url = f"{redirect_uri}?token={token}&state={state}"
    return RedirectResponse(url=redirect_url, status_code=302)


# 3️⃣ USER DENIES ACCESS
@router.post("/deny")
async def deny(
    redirect_uri: str = Form(...),
    state: str = Form(...)
):
    redirect_url = f"{redirect_uri}?error=access_denied&state={state}"
    return RedirectResponse(url=redirect_url, status_code=302)
