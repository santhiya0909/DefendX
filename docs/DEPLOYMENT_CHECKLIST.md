# DefendX — Production Deployment & Operations Checklist

**Document ID**: DEFENDX-DEP-2026-V1  
**Target Architecture**: Docker Compose / Kubernetes / Linux Enterprise Server  
**Classification**: DEPLOYMENT GUIDE  

---

## 1. Pre-Deployment Verification Checklist

Before deploying DefendX into a staging or production environment, verify the following prerequisites:

- [x] **Backend Automated Tests**: All 24 Pytest unit/integration tests passing.
- [x] **Frontend Static Compilation**: `npm run build` completes with 0 errors across all 20 routes.
- [x] **Database Schema Head**: Alembic version aligned with current database models (`dd083ff9997d`).
- [ ] **PostgreSQL 15+ Provisioned**: Production database URL with TLS/SSL configured.
- [ ] **Google Cloud OAuth 2.0 Credentials**: Client ID created in Google Cloud Console.
- [ ] **ClamAV Antivirus Daemon**: Container or system service active and listening on TCP port 3310.
- [ ] **Secret Keys Rotated**: `SECRET_KEY` set to a cryptographically random 64-character hex string.

---

## 2. Environment Configuration Reference

### Backend Configuration (`backend/.env`)

```ini
# Production Environment
ENVIRONMENT=production
DEBUG=false
PROJECT_NAME="DefendX: Securing Adversarial AI"

# Security & Tokens
SECRET_KEY=generate_with_openssl_rand_hex_32
ACCESS_TOKEN_EXPIRE_MINUTES=1440
ALGORITHM=HS256

# Database (PostgreSQL with asyncpg driver)
DATABASE_URL=postgresql+asyncpg://defendx_user:DefendX_Secure_Pass_2026!@postgres:5432/defendx_db

# Google Identity Services (OpenID Connect)
GOOGLE_CLIENT_ID=your-google-oauth-client-id.apps.googleusercontent.com

# ClamAV Antivirus Daemon
CLAMAV_HOST=clamav
CLAMAV_PORT=3310
CLAMAV_TIMEOUT=15

# LLM Testing Provider (Optional - falls back to MockLLMProvider if empty)
LLM_PROVIDER=openai
LLM_API_KEY=sk-proj-your-openai-api-key
LLM_MODEL=gpt-4o-mini

# CORS Origins
BACKEND_CORS_ORIGINS=["https://defendx.yourdomain.com","http://localhost:3000"]
```

### Frontend Configuration (`frontend/.env.production`)

```ini
NEXT_PUBLIC_API_URL=https://defendx-api.yourdomain.com
NEXT_PUBLIC_GOOGLE_CLIENT_ID=your-google-oauth-client-id.apps.googleusercontent.com
```

---

## 3. Production Docker Compose Reference

Create `docker-compose.prod.yml` in the project root:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    container_name: defendx_postgres
    restart: always
    environment:
      POSTGRES_USER: defendx_user
      POSTGRES_PASSWORD: DefendX_Secure_Pass_2026!
      POSTGRES_DB: defendx_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U defendx_user -d defendx_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  clamav:
    image: clamav/clamav:latest
    container_name: defendx_clamav
    restart: always
    ports:
      - "3310:3310"
    healthcheck:
      test: ["CMD-SHELL", "clamdscan /bin/sh || exit 0"]
      interval: 30s
      timeout: 10s
      retries: 3

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: defendx_backend
    restart: always
    depends_on:
      postgres:
        condition: service_healthy
      clamav:
        condition: service_started
    environment:
      DATABASE_URL: postgresql+asyncpg://defendx_user:DefendX_Secure_Pass_2026!@postgres:5432/defendx_db
      CLAMAV_HOST: clamav
      CLAMAV_PORT: 3310
      ENVIRONMENT: production
    ports:
      - "8000:8000"
    volumes:
      - file_uploads:/app/uploads

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: defendx_frontend
    restart: always
    depends_on:
      - backend
    ports:
      - "3000:3000"
    environment:
      NEXT_PUBLIC_API_URL: http://backend:8000

volumes:
  postgres_data:
  file_uploads:
```

---

## 4. Step-by-Step Production Launch Sequence

### Step 1: Database Migration
Run Alembic database migrations against the production PostgreSQL instance:
```bash
cd backend
alembic upgrade head
```

### Step 2: Seed Initial Accounts
Seed the baseline administrative and role-specific testing accounts:
```bash
python -m app.core.seeder
```

Initial seeded accounts generated:
- `admin@defendx.ai` (Role: `ADMIN`)
- `red_team@defendx.ai` (Role: `RED_TEAM`)
- `blue_team@defendx.ai` (Role: `BLUE_TEAM`)
- `auditor@defendx.ai` (Role: `AUDITOR`)

> **IMPORTANT**: Force password reset for all seeded accounts immediately upon first login in production!

### Step 3: Launch Containers
```bash
docker-compose -f docker-compose.prod.yml up -d --build
```

### Step 4: Health Check Verification
Verify all services are responding healthy:
```bash
# Check Backend Health Endpoint
curl -i http://localhost:8000/api/v1/infrastructure/services

# Check Audit Chain Integrity
curl -i -H "Authorization: Bearer <ADMIN_TOKEN>" http://localhost:8000/api/v1/audit/verify
```

Expected response from `/api/v1/audit/verify`:
```json
{
  "chain_valid": true,
  "total_records": 12,
  "broken_index": null,
  "message": "Cryptographic audit chain integrity verified from Genesis."
}
```
