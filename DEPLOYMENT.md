# Deployment Guide // CyberGuard on Render

This guide provides step-by-step instructions to deploy the **CyberGuard Password Strength Analyzer & Security Suite** to [Render](https://render.com).

Render provides free cloud hosting for Python web services with automated GitHub deployment, free SSL certificates, and managed environments.

---

## Table of Contents
1. [Prerequisites](#1-prerequisites)
2. [Quickstart: Deploy via Render Blueprint (Recommended)](#2-quickstart-deploy-via-render-blueprint-recommended)
3. [Alternative: Manual Web Service Setup](#3-alternative-manual-web-service-setup)
4. [Environment Variables Reference](#4-environment-variables-reference)
5. [Persistent Storage & PostgreSQL (Optional)](#5-persistent-storage--postgresql-optional)
6. [Troubleshooting & Verification](#6-troubleshooting--verification)
7. [Production Hardening Checklist](#7-production-hardening-checklist)

---

## 1. Prerequisites

Before starting, ensure you have:
- A [GitHub](https://github.com) account.
- A [Render](https://render.com) account (you can sign in with your GitHub account).
- Your project pushed to a GitHub repository (public or private).

If you haven't initialized git yet, run in your project folder:
```bash
git init
git add .
git commit -m "Initial commit: CyberGuard Password Security Suite"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo-name>.git
git push -u origin main
```

---

## 2. Quickstart: Deploy via Render Blueprint (Recommended)

This repository includes a pre-configured [render.yaml](file:///c:/Users/sushi/Desktop/Password%20Strength%20Analyzer/render.yaml) blueprint that automates all build settings, runtime parameters, and auto-generated secret keys.

### Steps:
1. Log in to your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** in the top right navigation bar and select **Blueprint**.
3. Connect your GitHub repository (`<your-repo-name>`).
4. Render will automatically read `render.yaml` and configure:
   - **Service Name**: `cyberguard-password-analyzer`
   - **Environment**: `Python`
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --workers 2 --threads 4 --timeout 120`
   - **Auto-generated Secret Key**: Automatically generated cryptographic random string.
5. Click **Apply**.
6. Render will build the container, install packages, and deploy your live URL (e.g. `https://cyberguard-password-analyzer.onrender.com`).

---

## 3. Alternative: Manual Web Service Setup

If you prefer to configure the service manually through Render's web interface:

### Steps:
1. Log in to the [Render Dashboard](https://dashboard.render.com).
2. Click **New +** -> **Web Service**.
3. Select **Build and deploy from a Git repository** and connect your repo.
4. Fill in the deployment details:

| Configuration Field | Recommended Value |
|---|---|
| **Name** | `cyberguard-password-analyzer` |
| **Region** | Choose closest to your audience (e.g., *Oregon (US West)* or *Frankfurt (EU)*) |
| **Branch** | `main` |
| **Root Directory** | Leave blank (root directory) |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install --upgrade pip && pip install -r requirements.txt` |
| **Start Command** | `gunicorn app:app --workers 2 --threads 4 --timeout 120` |
| **Instance Type** | `Free` |

5. Under **Environment Variables**, click **Add Environment Variable** and configure:

| Key | Value | Notes |
|---|---|---|
| `SECRET_KEY` | *(Click "Generate" or paste random 64-char hex)* | Session cookie cryptographic signature |
| `FLASK_DEBUG` | `False` | Disables debug mode in production |
| `PYTHONUNBUFFERED` | `1` | Real-time terminal output streaming |
| `PYTHON_VERSION` | `3.11.9` | Ensures compatible Python runtime |

6. Click **Create Web Service**.
7. Render will trigger the initial deployment. You can follow live build logs in the deployment console.

---

## 4. Environment Variables Reference

| Variable | Required | Default / Example | Purpose |
|---|---|---|---|
| `SECRET_KEY` | **Yes** (in Prod) | `secrets.token_hex(32)` | Signs session cookies and CSRF tokens. |
| `DATABASE_URL` | No | `sqlite:///passwords.db` | Database connection string. If using Render PostgreSQL, Render provides this automatically. |
| `FLASK_DEBUG` | No | `False` | Disables debug stack traces for public users. |
| `PORT` | Managed | `10000` (assigned by Render) | Port bound by Gunicorn/Flask. |
| `PYTHONUNBUFFERED` | No | `1` | Forces unbuffered binary stdout/stderr. |

> [!TIP]
> To generate a secure `SECRET_KEY` from your local terminal:
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

---

## 5. Persistent Storage & PostgreSQL (Optional)

### Free Tier SQLite Note
On Render's free tier, the local disk is ephemeral (restarts every time the service sleeps or updates). For local demos, SQLite is created automatically and pre-seeded.

### Connecting Render Managed PostgreSQL (For Persistent Data):
1. In the Render Dashboard, click **New +** -> **PostgreSQL**.
2. Give it a name (e.g., `cyberguard-db`) and select the Free tier.
3. Once created, copy the **Internal Database URL** (e.g., `postgres://user:pass@host/db`).
4. Go to your `cyberguard-password-analyzer` Web Service settings -> **Environment Variables**.
5. Add/Update `DATABASE_URL` with the copied Internal Database URL.
6. [config.py](file:///c:/Users/sushi/Desktop/Password%20Strength%20Analyzer/config.py) automatically handles translating `postgres://` to `postgresql://` as required by SQLAlchemy.
7. Render will automatically redeploy and initialize your tables!

---

## 6. Troubleshooting & Verification

### Verifying the Live Deployment
Once deployed, open your Render URL:
- Check the home page: `https://<your-app>.onrender.com/`
- Verify theme toggle (Dark / Light mode).
- Test the HaveIBeenPwned k-Anonymity API integration by testing known passwords (`password`) and strong random ones.
- Test PDF report generation (`EXPORT PDF` button).
- Test Operator registration and login (`/register` and `/login`).
- Access the telemetry dashboard (`/analytics`).

### Common Issues & Fixes

#### Issue 1: "Build failed: No matching distribution found for reportlab"
- **Cause**: Outdated pip version in build environment.
- **Fix**: Ensure your build command includes `pip install --upgrade pip`:
  ```bash
  pip install --upgrade pip && pip install -r requirements.txt
  ```

#### Issue 2: "Internal Server Error" on Database Access
- **Cause**: SQLAlchemy connection failure or invalid URL schema.
- **Fix**: Check that `config.py` translates `postgres://` to `postgresql://`. CyberGuard already includes this handler in `config.py`.

#### Issue 3: Cold Start Delays
- **Explanation**: Render's free tier spins down web services after 15 minutes of inactivity. When a request arrives, it takes ~30-50 seconds to spin back up. This is normal behavior for free tier plans.

---

## 7. Production Hardening Checklist

- [x] Gunicorn WSGI production server with worker threads enabled (`--workers 2 --threads 4`).
- [x] Secure `SECRET_KEY` injected via environment variable (not hardcoded).
- [x] Zero-Plaintext Transmission: HIBP k-Anonymity privacy model prevents plaintext credential leakage.
- [x] Memory-Safe PDF streaming via `io.BytesIO` buffer without temp disk leaks.
- [x] Bcrypt 12-round salted hashing for all registered user credentials.
- [x] SQLite database, virtual environments, and `.env` excluded in `.gitignore`.
- [x] Complete test suite passing 32/32 tests.
