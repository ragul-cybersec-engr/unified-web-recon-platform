# Unified GUI-Based Framework for Automated Web Application Reconnaissance and Attack Surface Analysis

<p align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-MIT-success?style=for-the-badge)

</p>

A Dockerized reconnaissance platform that automates the early stages of a web application security assessment through a single browser-based dashboard. It chains industry-standard recon tools (**Subfinder**, **Naabu**, **HTTPX**) behind a FastAPI backend, and wraps the whole workflow — authentication, scanning, history, and reporting — into one integrated app instead of a set of disconnected CLI tools.

> **Disclaimer**
>
> This project is intended strictly for authorized security assessments, research, and educational use. Always obtain explicit written permission before scanning any domain or system you do not own or manage.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Option A: Docker (recommended)](#option-a-docker-recommended)
  - [Option B: Local run — Linux/macOS](#option-b-local-run--linuxmacos)
  - [Option C: Local run — Windows](#option-c-local-run--windows)
- [Configuration](#configuration)
- [Usage Workflow](#usage-workflow)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [License](#license)
- [Author](#author)

---

## Features

### Authentication
- JWT-based session authentication
- Email/password registration and login
- OTP (one-time password) login flow delivered over email
- Role-aware access (admin vs. standard user)

### Reconnaissance
- **Domain scan** — subdomain enumeration only (`subfinder`)
- **Extended scan** — subdomains → open ports → live hosts (`subfinder` → `naabu` → `httpx`)
- Centralized scan queue: only one active (queued/running) scan per organization at a time
- Duplicate-job protection: an identical active request from the same user reuses the existing job instead of spawning a parallel one
- Results are published only after a job finishes successfully, so the UI never shows partial/intermediate output

### Dashboard & History
- Dedicated pages for login/registration, the scan dashboard, scan history, and detailed per-scan results
- Per-organization result views for subdomains, open ports, and live hosts

### Reporting & Notifications
- Export scan results as **PDF**, **DOCX**, **TXT**, or **XML**
- Email scan reports directly from the history page
- SMTP-based OTP delivery and report delivery

### Deployment
- Fully Dockerized (multi-stage build bundling Go-based recon tools + Python backend)
- Docker Compose for one-command startup
- Persistent scan data via a mounted volume
- Built-in container health checks

---

## Architecture

```text
                        User (Browser)
                              │
                     Team1ui (HTML/CSS/JS)
                              │
                     FastAPI Backend (app.py)
                   ┌──────────┼──────────┐
                   │          │          │
              auth.py     recon_engine   export_utils.py
              (JWT/OTP)      .py         (PDF/DOCX/TXT/XML)
                              │
                ┌─────────────┼─────────────┐
                │             │             │
            Subfinder      Naabu         HTTPX
          (subdomains)   (open ports)  (live hosts)
                └─────────────┴─────────────┘
                              │
                    data/recon (scan results)
                              │
                 Dashboard, History & Report Delivery
```

---

## Tech Stack

| Layer | Technologies |
|---|---|
| Backend | Python, FastAPI, Uvicorn |
| Frontend | HTML, CSS, JavaScript (`Team1ui/`) |
| Auth | PyJWT, Passlib/bcrypt, OTP over email |
| Recon Engine | Subfinder, Naabu, HTTPX (ProjectDiscovery tools) |
| Reporting | ReportLab (PDF), python-docx (DOCX) |
| Data | JSON-based storage (`data/`) |
| Deployment | Docker, Docker Compose |

---

## Project Structure

```text
web-recon/
├── app.py                 # FastAPI app & route definitions
├── auth.py                 # JWT auth, registration, OTP logic
├── recon_engine.py         # Scan orchestration (subfinder/naabu/httpx)
├── db.py                    # Data persistence helpers
├── export_utils.py          # PDF / DOCX / TXT / XML report generation
├── notifications.py          # SMTP email + OTP delivery
├── schemas.py                # Pydantic request/response models
├── config.yaml                # Engine paths, scan profiles, SMTP settings
├── requirements.txt
├── run_project.sh             # One-command local startup (Linux/macOS)
├── Dockerfile                  # Multi-stage build (Go tools + Python app)
├── docker-compose.yml
├── Team1ui/                    # Frontend (login, dashboard, history, details)
└── data/                       # Scan results & user store (persisted)
```

---

## Prerequisites

**For Docker (recommended):**
- Docker Engine / Docker Desktop
- Docker Compose plugin
- Linux containers mode enabled (if using Docker Desktop)

**For a local (non-Docker) run:**
- Python 3.11+
- Go 1.25+ (to build the recon tools)
- [Subfinder](https://github.com/projectdiscovery/subfinder), [Naabu](https://github.com/projectdiscovery/naabu), [HTTPX](https://github.com/projectdiscovery/httpx)

---

## Installation

### Option A: Docker (recommended)

```bash
# 1. Clone the repository
git clone https://github.com/ragul-cybersec-engr/unified-web-recon-platform.git
cd unified-web-recon-platform

# 2. Stop any old containers
docker compose down --remove-orphans

# 3. Build the image
docker compose build

# 4. Start the container
docker compose up -d

# 5. Check status and logs
docker compose ps
docker compose logs --tail=100 web-recon

# 6. Verify the recon tools are present inside the container
docker compose exec web-recon sh -lc "which subfinder && which naabu && which httpx"
```

Open the app at: **http://localhost:8000/login.html**

Quick health check:
```bash
curl -fsS http://localhost:8000/login.html >/dev/null && echo "UI OK"
curl -fsS http://localhost:8000/docs >/dev/null && echo "API OK"
```

If port `8000` is already in use, edit `docker-compose.yml`:
```yaml
ports:
  - "8080:8000"
```
then run `docker compose down && docker compose up -d --build` and open `http://localhost:8080/login.html`.

For a full clean rebuild (e.g. after a `libpcap` or Go version error):
```bash
docker compose down --remove-orphans
docker builder prune -af
docker compose build --no-cache --pull
```

### Option B: Local run — Linux/macOS

```bash
cd web-recon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

chmod +x run_project.sh
PATH="$HOME/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/go/bin:$PATH" ./run_project.sh
```

Open: **http://localhost:8000/login.html**

### Option C: Local run — Windows

Use **PowerShell**.

```powershell
cd C:\path\to\web-recon
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

```powershell
cd C:\path\to\web-recon; $env:Path="$env:USERPROFILE\go\bin;C:\Program Files\Go\bin;$env:Path"; .\.venv\Scripts\python.exe .\app.py
```

Open: **http://localhost:8000/login.html**

---

## Configuration

Scan behavior and tool paths are defined in `config.yaml`:

```yaml
Engine:
  path: "/usr/local/bin:/usr/bin:/bin:/usr/local/go/bin"
  scan-profiles:
    domain:
      cmd-recon:
        - "subfinder -dL {target}/all.txt -o {target}/subfinder.txt -all"
    extended:
      cmd-recon:
        - "subfinder -dL {target}/all.txt -o {target}/subfinder.txt -all"
        - "naabu -list {target}/subfinder.txt -o {target}/naabu.txt"
        - "httpx -list {target}/naabu.txt -o {target}/live.txt"
```

**SMTP (OTP + report email)** — set via environment variables (preferred, already wired into `docker-compose.yml`) rather than hardcoding into `config.yaml`:

```yaml
services:
  web-recon:
    environment:
      - SMTP_HOST=smtp.example.com
      - SMTP_PORT=587
      - SMTP_USERNAME=your-email@example.com
      - SMTP_PASSWORD=your-app-password
      - SMTP_SENDER=your-email@example.com
      - SMTP_USE_TLS=true
      - SMTP_USE_SSL=false
```

> ⚠️ **Never commit real SMTP credentials, JWT secrets, or any password to `config.yaml` in version control.** Use environment variables or a `.env` file excluded via `.gitignore`, and rotate any credential that has ever been committed in plaintext.

Use TLS (`587`) or SSL (`465`) — not both — and restart the app after any config change.

---

## Usage Workflow

1. Register an account or sign in (password or OTP-based login).
2. Choose a scan profile: **Domain** (subdomains only) or **Extended** (subdomains + ports + live hosts).
3. Enter the target as a plain hostname — e.g. `example.com`, not `https://example.com/`.
4. Start the scan and monitor its progress on the dashboard.
5. Review results in the detail view once the scan completes.
6. From the history page, download the report (PDF/DOCX/TXT/XML) or send it by email.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/register` | Create a new user account |
| `POST` | `/login` | Password-based login |
| `POST` | `/login-otp/request` | Request an OTP for login |
| `POST` | `/login-otp/verify` | Verify OTP and complete login |
| `POST` | `/newrecon` | Start a new reconnaissance scan |
| `GET` | `/allrecon` | List scans (user-scoped; admin sees all; supports `?status=queued,running`) |
| `GET` | `/recon/{orgname}` | Get scan details for an organization |
| `GET` | `/subdomain?orgname=...` | Get discovered subdomains |
| `GET` | `/openports?orgname=...` | Get discovered open ports |
| `GET` | `/live?orgname=...` | Get live hosts |
| `GET` | `/recon/{orgname}/download?format=txt|docx|pdf|xml` | Download a report |
| `POST` | `/recon/{orgname}/send-email` | Email the report to a given address |
| `DELETE` | `/recon/{orgname}` | Delete a scan record |

Interactive API docs are available at `http://localhost:8000/docs` once the app is running.

---

## Troubleshooting

**`Required tools not found for ... scan`**
Ensure Subfinder, Naabu, and HTTPX are installed and that `Engine.path` in `config.yaml` includes their directory.

**Scan `failed` when input was like `https://domain.com/`**
Enter plain hostnames only [example - google.com]— no protocol or trailing path.

**Extended scan shows no ports/live hosts**
Confirm the scan mode: `domain` mode intentionally returns subdomains only; use `extended` for ports and live hosts.

**Starting the same organization's scan from multiple devices gives inconsistent files**
Only one queued/running scan per organization is allowed — wait for the active scan to finish before starting another.

**Docker build error: `pcap.h: No such file or directory`**
```bash
docker compose down --remove-orphans
docker builder prune -af
docker compose build --no-cache --pull
```

**Docker build error: `httpx ... requires go >= 1.25.7`**
The Dockerfile already targets Go 1.25 — rebuild with `--no-cache --pull` to clear stale base image layers.

**OTP or report email not sending**
Double-check the `Notifications.smtp` / `SMTP_*` environment values and restart the app.

**OTP login fails on the first attempt**
1. Click **Request OTP** and wait for the "OTP Sent" confirmation.
2. Enter the code from the email.
3. Click **Login with OTP**.
An active OTP session must exist for that email before verification succeeds.

---

## Security Notes

- Store all secrets (SMTP credentials, JWT signing keys) as environment variables — never hardcode them in `config.yaml` or any file committed to the repository.
- Scan only targets you are explicitly authorized to assess.
- Keep ProjectDiscovery tools (Subfinder, Naabu, HTTPX) updated to their latest versions.
- Review generated reports before sharing or emailing them externally.

---

## License

Distributed under the MIT License.

---

## Author

**Ragul S**

Cybersecurity | Application Security | Web & API Security

