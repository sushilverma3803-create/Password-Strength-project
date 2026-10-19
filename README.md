# CyberGuard // Enterprise Password Strength Analyzer & Security Suite

[![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-00ff88.svg)](https://flask.palletsprojects.com/)
[![Render Deploy](https://img.shields.io/badge/Deploy%20to-Render-46E3B7?logo=render&logoColor=white)](https://render.com)
[![Theme](https://img.shields.io/badge/Theme-Dark%20%7C%20Light%20Mode-00f2fe.svg)](#dark--light-mode-theme)
[![Breach Detection](https://img.shields.io/badge/Breach%20API-HIBP%20k--Anonymity-ff2a6d.svg)](#breach-checking-api-hibp-k-anonymity)
[![PDF Export](https://img.shields.io/badge/Report-ReportLab%20PDF-00a8b5.svg)](#export-report-as-pdf-reportlab)
[![Tests](https://img.shields.io/badge/Tests-32%20Passing-success.svg)](#running-the-automated-test-suite)

An enterprise-grade, internship-level cybersecurity password intelligence suite featuring **Zero-Knowledge Breach Detection (HaveIBeenPwned k-Anonymity API)**, **Cryptographic PDF Audit Reports (ReportLab)**, **Heuristic Security Recommendations Engine**, **Operator Profile Governance & Vault Purge**, **SQLite Security Audit Logging**, **Cyberpunk Dark / Light Mode**, and an interactive **Chart.js Telemetry Dashboard**.

---

## Table of Contents
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Installation Guide](#installation-guide)
  - [Prerequisites](#prerequisites)
  - [Local Setup (Windows, macOS, Linux)](#local-setup-windows-macos-linux)
- [Environment Variables Setup](#environment-variables-setup)
- [Deployment Instructions for Render](#deployment-instructions-for-render)
  - [Method 1: One-Click Deploy via Render Blueprint (Recommended)](#method-1-one-click-deploy-via-render-blueprint-recommended)
  - [Method 2: Manual Web Service Setup on Render](#method-2-manual-web-service-setup-on-render)
- [Running the Automated Test Suite](#running-the-automated-test-suite)
- [API Reference](#api-reference)
- [Security & Compliance](#security--compliance)

---

## Key Features

### 🌓 Dark / Light Mode Theme
- **Bi-Directional Glassmorphism Token Architecture**: Dynamic toggle between the high-contrast Cyberpunk HUD Dark Mode and the ergonomic Arctic Cyber Light Mode.
- **Client-Side Persistence**: Preserves operator preferences in `localStorage('cyber-theme')` with zero flicker on page load across all routes (`/`, `/analytics`, `/dashboard`, `/profile`, `/audit-logs`, `/login`, `/register`).
- **Interactive HUD Elements**: Glassmorphic blur (`backdrop-filter: blur(16px)`), subtle gradients, glowing radial rings, and reactive Moon/Sun SVG toggle icons.

### 🛡️ Breach Checking API (HIBP k-Anonymity)
- **Zero-Plaintext Privacy Protocol**: Plaintext passwords never leave the machine. The application computes the SHA-1 hash, transmits only the first 5 characters (prefix) over TLS to HaveIBeenPwned (`https://api.pwnedpasswords.com/range/{prefix}`), and checks the 35-character suffix locally.
- **Padding Attack Defense**: Sends `Add-Padding: true` headers to thwart network packet size correlation attacks.
- **Hybrid Offline Threat Shield**: Automatically falls back to a local SQLite database of known compromised signatures and dictionary words if internet access is interrupted.
- **Real-Time Indicators**: Live UI badges display `PWNED (52,372,427x)` with exact leak frequencies or `CLEAN (HIBP Verified)`.

### 📄 Export Report as PDF (ReportLab)
- **Executive-Ready Audit Reports**: Compiles a comprehensive, cryptographic evaluation PDF with one click.
- **Report Elements**:
  - Formal document header, UTC timestamp, Report ID, and operator attribution.
  - Overall security score (0-100), defense tier badge, Shannon entropy in bits, and charset pool size.
  - Empirical brute-force scenarios table (High-Performance GPU Cluster, Single GPU, Throttled Web Form).
  - Complexity criteria checklist matrix.
  - Prioritized security remediation advice from the Recommendations Engine.
- **Dual Export Triggers**:
  - Instant direct export from the real-time analyzer UI (`POST /api/export-pdf`).
  - Historical report export from the operator database archive (`GET /api/export-report-pdf/<id>`).

### 👤 Operator Profile Page (`/profile`)
- **Account Governance**: View registration metadata, account email, active session status, and total saved credentials.
- **Email Update (`POST /profile/update`)**: Secure profile email modifications with uniqueness validation.
- **Bcrypt Password Change (`POST /profile/change-password`)**: Validates current password against stored bcrypt hash, checks complexity rules, and re-hashes with 12 bcrypt salt rounds.
- **Data Erasure & Purge (`POST /profile/purge-vault` & `POST /profile/purge-reports`)**: One-click GDPR/CCPA-compliant data erasure allowing operators to wipe stored passwords or historical reports.

### 🧠 Heuristic Security Recommendations Engine
- **Prioritized Advice Tiers**: Categorizes findings into `CRITICAL`, `WARNING`, `RECOMMENDED`, `OPTIMAL`, and `INFO`.
- **Intelligent Diagnostics**:
  - Critical exposure alerts on breach detection.
  - Short length warnings (<8 chars and <12 chars).
  - Entropy deficiency warnings (<36 bits and <50 bits).
  - Character diversity guidance (missing symbols, numbers, upper/lowercase).
  - Pattern vulnerability warnings (repeats, sequential letters, keyboard runs such as `qwerty` or `1qaz`).
  - High Entropy Certification for compliant, enterprise-hardened passwords.

### 📋 Security Audit Logs (`/audit-logs`)
- **Full Traceability**: Automatically captures every security event in the `AuditLog` SQLite model:
  - `AUTH_LOGIN_SUCCESS`, `AUTH_LOGIN_FAILED`, `AUTH_REGISTER`, `AUTH_LOGOUT`
  - `AUTH_PASSWORD_CHANGE`, `PROFILE_UPDATE`
  - `PASSWORD_GENERATED`, `REPORT_ARCHIVED`, `REPORT_EXPORT_PDF`
  - `VAULT_PURGE`, `REPORTS_PURGE`
- **Telemetry Ingestion**: Records Operator ID, Timestamp (UTC), Event Category, Description, Client IP address (`X-Forwarded-For` / `remote_addr`), and User-Agent.
- **Filterable Console**: Dedicated web dashboard with category dropdown filters and REST JSON API (`GET /api/audit-logs`).

### 📊 Cybersecurity Analytics Dashboard (`/analytics`)
- **Chart.js Visualizations**:
  - **Strength Distribution Chart**: Cyberpunk Doughnut Chart visualizing Weak, Medium, Strong, and Very Strong proportions.
  - **Resilience & Entropy Trendline**: Multi-axis Line Chart correlating scores and entropy bits over historical scans.
  - **Complexity Criteria Compliance**: Horizontal Bar Chart benchmarking criteria satisfaction across all scans.
- **KPI Metrics**: Real-time counters for total scans, average score, weak ratio, and strong ratio.

---

## System Architecture

```text
Password Strength Analyzer/
├── app.py                      # Flask application factory, routes, and WSGI entrypoint
├── config.py                   # Configuration with python-dotenv & postgresql:// URL normalization
├── models.py                   # SQLAlchemy models (User, SavedPassword, StrengthReport, AuditLog, etc.)
├── analyzer.py                 # Core cryptographic engine (entropy math, crack times, patterns)
├── breach_checker.py           # HIBP k-Anonymity API integration & local threat shield
├── recommendations_engine.py   # Heuristic rule-based cybersecurity recommendations engine
├── pdf_exporter.py             # Enterprise PDF audit report generator (ReportLab)
├── generator.py                # CSPRNG secure password generator (Python secrets module)
├── requirements.txt            # Python dependencies (Flask, ReportLab, requests, bcrypt, gunicorn, etc.)
├── render.yaml                 # Render Blueprint automated deployment spec
├── Procfile                    # Web process command for Render/Heroku/Railway
├── .env.example                # Documented environment variables template
├── .gitignore                  # Production git ignore configuration
├── DEPLOYMENT.md               # Detailed step-by-step Render deployment guide
│
├── templates/
│   ├── index.html              # Cyberpunk HUD analyzer with theme toggle & PDF export
│   ├── analytics.html          # Interactive cybersecurity telemetry dashboard (Chart.js)
│   ├── dashboard.html          # Operator credential vault & reports archive with PDF export
│   ├── profile.html            # Operator security profile, password change & data purge
│   ├── audit_logs.html         # Dedicated security audit logs console
│   ├── login.html              # Secure operator authentication portal
│   └── register.html           # Operator registration with live interactive strength meter
│
├── static/
│   ├── css/
│   │   └── style.css           # Glassmorphic design system with Dark & Light theme tokens
│   └── js/
│       └── main.js             # Real-time evaluation, audio synth, theme toggle & PDF export
│
└── tests/
    ├── test_analyzer.py        # Core analyzer & password generator tests
    ├── test_auth_and_vault.py  # User auth, bcrypt hashing & vault CRUD tests
    └── test_internship_features.py # 17 tests for breach check, PDF export, profile & audit logs
```

---

## Installation Guide

### Prerequisites
- Python 3.9 or higher (Python 3.10, 3.11, 3.12, 3.13, 3.14 supported)
- pip package manager
- git (for version control and cloud deployment)

---

### Local Setup (Windows, macOS, Linux)

#### 1. Clone or Navigate to the Repository
```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd "Password Strength Analyzer"
```

#### 2. Create a Virtual Environment
```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows (Command Prompt)
python -m venv venv
venv\Scripts\activate.bat

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
```

#### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### 4. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
# macOS / Linux
cp .env.example .env

# Windows
copy .env.example .env
```

Open `.env` and configure your secret key:
```bash
# Generate a secure 32-byte (64-character) hex key
python -c "import secrets; print(secrets.token_hex(32))"
```
Paste this generated key into `.env` as `SECRET_KEY`.

#### 5. Run the Application
```bash
python app.py
```

The server will initialize the SQLite database (`passwords.db`), seed top compromised passwords, and start listening on:
```text
http://127.0.0.1:5000
```

---

## Environment Variables Setup

The application reads configuration parameters from environment variables (with automatic local loading via `python-dotenv`).

| Variable | Default Value | Description |
|---|---|---|
| `FLASK_ENV` | `development` | Environment mode (`development` or `production`). |
| `FLASK_DEBUG` | `True` (dev) / `False` (prod) | Toggles detailed Flask debug stack traces. |
| `SECRET_KEY` | `cyber-guard-default-...` | Cryptographic secret key for session cookies. In production, provide a random 64-char hex string. |
| `DATABASE_URL` | `sqlite:///passwords.db` | SQLAlchemy database connection URI. Compatible with SQLite and PostgreSQL. |
| `PORT` | `5000` | Port bound by Flask / Gunicorn. |
| `PYTHONUNBUFFERED` | `1` | Forces unbuffered stdout/stderr streaming to terminal/cloud logs. |

---

## Deployment Instructions for Render

[Render](https://render.com) provides free and scalable cloud hosting for Python web applications. You can deploy this application using either the **Render Blueprint** (recommended) or the **Manual Web Service** method.

For comprehensive details, see [DEPLOYMENT.md](file:///c:/Users/sushi/Desktop/Password%20Strength%20Analyzer/DEPLOYMENT.md).

---

### Method 1: One-Click Deploy via Render Blueprint (Recommended)

This repository includes a [render.yaml](file:///c:/Users/sushi/Desktop/Password%20Strength%20Analyzer/render.yaml) blueprint specification that automatically provisions the web service, configures Gunicorn, and generates a production secret key.

1. Push your repository to **GitHub**.
2. Sign in to your [Render Dashboard](https://dashboard.render.com).
3. Click **New +** (top right) and choose **Blueprint**.
4. Select your connected GitHub repository.
5. Render detects `render.yaml` and sets:
   - **Service Name**: `cyberguard-password-analyzer`
   - **Runtime**: `Python`
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --workers 2 --threads 4 --timeout 120`
   - **SECRET_KEY**: Automatically generated cryptographic random string.
6. Click **Apply**. Render will automatically build the service and output your live HTTPS URL.

---

### Method 2: Manual Web Service Setup on Render

1. Sign in to the [Render Dashboard](https://dashboard.render.com).
2. Click **New +** -> **Web Service**.
3. Connect your GitHub repository.
4. Fill in the service configuration:
   - **Name**: `cyberguard-password-analyzer`
   - **Region**: Choose closest to you (e.g. *Oregon (US West)* or *Frankfurt (EU)*)
   - **Branch**: `main`
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install --upgrade pip && pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     gunicorn app:app --workers 2 --threads 4 --timeout 120
     ```
   - **Instance Type**: `Free`
5. In the **Environment Variables** section, add:
   - `SECRET_KEY`: *(Click "Generate" or paste a random 64-char hex key)*
   - `FLASK_DEBUG`: `False`
   - `PYTHONUNBUFFERED`: `1`
   - `PYTHON_VERSION`: `3.11.9`
6. Click **Create Web Service**.
7. Monitor the build logs. Within 1-2 minutes, your service will be live at `https://<your-service-name>.onrender.com`.

---

## Running the Automated Test Suite

The test suite validates the entire application across **32 automated unit and integration tests** using an isolated in-memory SQLite database:

```bash
# Run all 32 tests across all modules
python -m unittest discover -s . -p "test_*.py" -v

# Run internship feature tests (Breach check, PDF export, Profile, Audit logs)
python -m unittest test_internship_features.py -v

# Run user authentication and SQLite vault tests
python -m unittest test_auth_and_vault.py -v

# Run core entropy analyzer and generator tests
python -m unittest test_analyzer.py -v
```

### Test Suite Execution Output
```text
Ran 32 tests in 62.347s

OK
```

---

## API Reference

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/analyze` | Real-time cryptographic analysis, HIBP breach check & recommendations | No |
| `POST` | `/api/generate` | CSPRNG password generator with customizable character pool | No |
| `POST` | `/api/check-breach` | Standalone HIBP k-Anonymity breach verification | No |
| `POST` | `/api/export-pdf` | Stream generated ReportLab PDF audit report directly to browser | No |
| `GET`  | `/api/export-report-pdf/<id>` | Download PDF report for saved database audit record | Yes |
| `GET`  | `/api/audit-logs` | Retrieve structured audit logs with category filtering | Yes |
| `GET`  | `/api/analytics-data` | Telemetry statistics and Chart.js datasets | No |
| `POST` | `/api/save-generated` | Save generated password into SQLite vault | Yes |
| `POST` | `/api/save-report` | Save strength evaluation report into SQLite vault | Yes |
| `POST` | `/profile/change-password` | Update operator password with bcrypt re-hashing | Yes |
| `POST` | `/profile/update` | Update operator email address | Yes |
| `POST` | `/profile/purge-vault` | Purge all saved vault passwords (GDPR erasure) | Yes |
| `POST` | `/profile/purge-reports` | Purge all archived strength reports | Yes |

---

## Security & Compliance

1. **Zero-Plaintext Transmission (k-Anonymity)**: Never exposes passwords over the network. HIBP queries transmit only a 5-character SHA-1 prefix.
2. **Bcrypt 12-Rounds Salting**: Passwords stored in SQLite are protected against dictionary, rainbow table, and brute-force attacks.
3. **Comprehensive Audit Trail**: Security actions (logins, failed attempts, exports, purges) are tracked with client IP and User-Agent telemetry.
4. **Memory-Safe PDF Generation**: ReportLab compiles documents inside in-memory buffers (`io.BytesIO`) without temporary disk writes.
5. **GDPR / CCPA Data Erasure**: Operators can purge their stored credentials and audit reports on demand.
