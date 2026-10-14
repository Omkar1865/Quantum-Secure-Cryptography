# Render Deployment Guide: Quantum-Secure Cryptography Platform

## 1. Prerequisites
- A GitHub or GitLab repository containing this project.
- A free or paid [Render](https://render.com) account.

## 2. Deploy Using Blueprint (`render.yaml`)
1. Push your repository to GitHub.
2. In the Render Dashboard, click **New +** &rarr; **Blueprint**.
3. Select your repository `Quantum-Secure-Cryptography`.
4. Render will detect `render.yaml` and configure:
   - **Environment**: Python 3
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path**: `/health`
5. Supply the required environment variables:
   - `DEMO_ADMIN_PASSWORD`: A secure password of your choice.
   - `JWT_SECRET`: A generated 64-character secret (Render can auto-generate this).
6. Click **Apply**.

---

## 3. Manual Deployment Setup (Web Service)
If deploying without Blueprint:
1. In Render Dashboard, click **New +** &rarr; **Web Service**.
2. Connect your Git repository.
3. Configure the following:
   - **Name**: `quantum-secure-cryptography`
   - **Region**: Any (e.g., Oregon, Frankfurt)
   - **Branch**: `master`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Under **Advanced** &rarr; **Health Check Path**, enter `/health`.
5. Under **Environment Variables**, add:
   - `ENVIRONMENT` = `production`
   - `ALLOWED_ORIGINS` = `*`
   - `JWT_SECRET` = `<Generate a long random string>`
   - `DEMO_ADMIN_USER` = `admin`
   - `DEMO_ADMIN_PASSWORD` = `<Your chosen secure password>`
6. Click **Create Web Service**.

---

## 4. Operational Notes
- **Ephemeral Storage**: Render free-tier instances use ephemeral disk. Uploaded and decrypted files in `storage/` are cleaned up automatically and will not persist across service restarts or multi-instance scaling.
- **Port Binding**: The application listens dynamically on `$PORT` provided by Render.
- **Health Checks**: Render automatically monitors `/health` to verify zero-downtime deployments.
