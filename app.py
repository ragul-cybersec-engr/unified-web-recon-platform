from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse
import uvicorn
from auth import (
    authenticate_user,
    create_access_token,
    create_login_otp,
    get_current_user,
    has_active_login_otp,
    rate_limit,
    register_user,
    user_exists,
    verify_login_otp,
)
from recon_engine import ReconEngine
from db import Storage
from export_utils import build_export_file, build_recon_report
from notifications import send_email
from schemas import ExportEmailIn, NewReconIn, OTPRequestIn, OTPVerifyIn, RegisterIn
from datetime import datetime
from pathlib import Path
from starlette.responses import Response
import hashlib
import json

app = FastAPI(title="Unified Recon API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

storage = Storage()
engine = ReconEngine(storage)


def _normalized_email(value: str) -> str:
    return str(value or "").strip().lower()


def _is_admin(user: dict) -> bool:
    return str(user.get("role", "")).strip().lower() == "admin"


def _visible_records_for_user(user: dict):
    records = storage.load_all()
    if _is_admin(user):
        return records
    user_email = _normalized_email(user.get("email", ""))
    if not user_email:
        return []

    org_owner_cache = {}
    visible = []
    for record in records:
        initiated_by = _normalized_email(record.get("initiated_by", ""))
        if initiated_by:
            if initiated_by == user_email:
                visible.append(record)
            continue

        legacy_email = _normalized_email(record.get("email", ""))
        if legacy_email and legacy_email == user_email:
            visible.append(record)
            continue

        orgname = str(record.get("orgname", "") or "")
        org_key = str(record.get("org_key", "") or storage.normalize_orgname(orgname))
        if not orgname and not org_key:
            continue

        if org_key not in org_owner_cache:
            history = storage.load_org(orgname or org_key)
            owner = ""
            if isinstance(history, list):
                for event in reversed(history):
                    if not isinstance(event, dict):
                        continue
                    event_owner = _normalized_email(event.get("initiated_by", ""))
                    if event_owner:
                        owner = event_owner
                        break
            org_owner_cache[org_key] = owner

        if org_owner_cache.get(org_key) == user_email:
            visible.append(record)

    return visible


def _ensure_org_access(user: dict, orgname: str):
    if _is_admin(user):
        return
    org_key = storage.normalize_orgname(orgname)
    allowed = any(
        record.get("orgname") == orgname or record.get("org_key") == org_key
        for record in _visible_records_for_user(user)
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="Access denied for this organization")


def _has_active_org_job(orgname: str) -> bool:
    org_key = storage.normalize_orgname(orgname)
    for record in storage.load_all():
        status = str(record.get("status", "")).strip().lower()
        if status not in {"queued", "running"}:
            continue
        same_org = record.get("orgname") == orgname or record.get("org_key") == org_key
        if same_org:
            return True
    return False


def _normalized_domains(domains):
    cleaned = []
    for domain in domains or []:
        value = str(domain or "").strip().lower()
        if value:
            cleaned.append(value)
    return sorted(set(cleaned))


def _request_key(email: str, scan_type: str, domains) -> str:
    payload = {
        "email": _normalized_email(email),
        "scan_type": str(scan_type or "extended").strip().lower(),
        "domains": _normalized_domains(domains),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _find_active_matching_job(email: str, scan_type: str, domains):
    wanted_key = _request_key(email, scan_type, domains)
    wanted_domains = _normalized_domains(domains)
    wanted_scan_type = str(scan_type or "extended").strip().lower()
    for record in reversed(storage.load_all()):
        status = str(record.get("status", "")).strip().lower()
        if status not in {"queued", "running"}:
            continue
        if _normalized_email(record.get("initiated_by", "")) != _normalized_email(email):
            continue
        record_scan_type = str(record.get("scan_type", "extended")).strip().lower()
        if record_scan_type != wanted_scan_type:
            continue
        record_key = str(record.get("request_key", "")).strip().lower()
        if record_key:
            if record_key == wanted_key:
                return record
            continue
        if _normalized_domains(record.get("domains", [])) == wanted_domains:
            return record
    return None


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/register")
async def register(payload: RegisterIn):
    try:
        user = register_user(payload.email, payload.password, payload.name)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"email": user["email"], "name": user["name"], "role": user["role"]}


@app.post("/login-otp/request")
async def login_otp_request(payload: OTPRequestIn):
    if not user_exists(payload.email):
        raise HTTPException(status_code=404, detail="User not found")

    otp = create_login_otp(payload.email)
    subject = "Web-Recon OTP Login Code"
    body = (
        "Your OTP code is: "
        f"{otp}\n\n"
        "This code expires in 5 minutes.\n"
        "If you did not request this code, ignore this email."
    )
    try:
        send_email(payload.email, subject, body, config_path="config.yaml")
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to send OTP email: {exc}")
    return {"message": "OTP sent successfully", "expires_in_seconds": 300}


@app.post("/login-otp/verify")
async def login_otp_verify(payload: OTPVerifyIn):
    if not user_exists(payload.email):
        raise HTTPException(status_code=404, detail="User not found")
    if not has_active_login_otp(payload.email):
        raise HTTPException(status_code=400, detail="Request OTP before verification")
    if not verify_login_otp(payload.email, payload.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")

    token = create_access_token({"sub": _normalized_email(payload.email)})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/newrecon")
async def newrecon(payload: NewReconIn, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    rate_limit(user["email"])  # may raise HTTPException if rate-limited
    existing = _find_active_matching_job(user["email"], payload.scan_type, payload.domains)
    if existing:
        mode_message = (
            "Domain scan collects subdomains only."
            if payload.scan_type == "domain"
            else "Extended scan collects subdomains, open ports, and live hosts."
        )
        return {
            "job_id": existing.get("job_id"),
            "status": existing.get("status", "queued"),
            "scan_type": existing.get("scan_type", payload.scan_type),
            "mode_message": mode_message,
            "reused": True,
        }
    if _has_active_org_job(payload.orgname):
        raise HTTPException(
            status_code=409,
            detail="A scan for this organization is already queued or running. Wait until it completes.",
        )
    missing = engine.missing_tools(payload.scan_type)
    if missing:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Required tools not found for {payload.scan_type} scan: {', '.join(missing)}. "
                "Install the tools or update Engine.path in config.yaml."
            ),
        )

    now = datetime.utcnow().isoformat() + "Z"
    org_key = storage.normalize_orgname(payload.orgname)
    record = {
        "orgname": payload.orgname,
        "org_key": org_key,
        "domains": payload.domains,
        "started_at": now,
        "status": "queued",
        "scan_type": payload.scan_type,
        "initiated_by": user["email"],
        "request_key": _request_key(user["email"], payload.scan_type, payload.domains),
    }
    job_id = storage.append_global(record)
    # also persist initial record to per-org history
    storage.append_org(payload.orgname, dict(record, job_id=job_id))

    # write domains immediately to data/recon/{orgname}/all.txt so tools can read it
    org_path = engine.path_for_org(payload.orgname)
    (org_path / "all.txt").write_text("\n".join(payload.domains), encoding="utf-8")

    # schedule background recon
    background_tasks.add_task(
        engine.run_recon, payload.orgname, payload.domains, job_id, payload.scan_type
    )
    mode_message = (
        "Domain scan collects subdomains only."
        if payload.scan_type == "domain"
        else "Extended scan collects subdomains, open ports, and live hosts."
    )
    return {
        "job_id": job_id,
        "status": "queued",
        "scan_type": payload.scan_type,
        "mode_message": mode_message,
    }


@app.get("/allrecon")
async def allrecon(
    status: str = Query("", description="Comma-separated statuses, e.g. queued,running"),
    user=Depends(get_current_user),
):
    records = _visible_records_for_user(user)
    selected_statuses = {
        item.strip().lower()
        for item in str(status or "").split(",")
        if item.strip()
    }
    if selected_statuses:
        records = [
            rec
            for rec in records
            if str(rec.get("status", "")).strip().lower() in selected_statuses
        ]
    return records
 
 
@app.get("/subdomain")
async def get_subdomain(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    return engine.read_output_list(orgname, "subfinder.txt")
 
 
@app.get("/openports")
async def get_openports(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    return engine.read_output_list(orgname, "naabu.txt")
 
 
@app.get("/live")
async def get_live(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    return engine.read_output_list(orgname, "live.txt")



@app.get("/recon/{orgname}")
async def get_recon(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    return storage.load_org(orgname)


@app.get("/recon/{orgname}/download")
async def download_recon(
    orgname: str,
    format: str = Query("txt", pattern="^(txt|docx|pdf|xml)$"),
    user=Depends(get_current_user),
):
    _ensure_org_access(user, orgname)
    report = build_recon_report(orgname, storage, engine)
    try:
        content, filename, mime = build_export_file(orgname, report, format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=content, media_type=mime, headers=headers)


@app.post("/recon/{orgname}/send-email")
async def send_recon_email(orgname: str, payload: ExportEmailIn, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    report = build_recon_report(orgname, storage, engine)
    try:
        content, filename, mime = build_export_file(orgname, report, payload.format)
        send_email(
            payload.recipient_email,
            subject=f"Recon Report - {orgname}",
            body=(
                f"Attached is the reconnaissance report for organization: {orgname}\n"
                f"Generated by: {user['email']}\n"
                f"Format: {payload.format.upper()}"
            ),
            attachments=[(filename, content, mime)],
            config_path="config.yaml",
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email send failed: {exc}")

    return {
        "message": "Email sent successfully",
        "recipient_email": payload.recipient_email,
        "filename": filename,
    }


@app.delete("/recon/{orgname}")
async def delete_recon(orgname: str, user=Depends(get_current_user)):
    _ensure_org_access(user, orgname)
    storage.delete_org(orgname)
    storage.delete_org_from_global(orgname)
    engine.delete_org_files(orgname)
    return JSONResponse({"deleted": orgname})


ui_dir = Path(__file__).parent / "Team1ui"
if ui_dir.exists():
    app.mount("/", StaticFiles(directory=str(ui_dir), html=True), name="ui")


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
