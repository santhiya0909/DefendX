# DEFENDX: Securing Adversarial AI – Safety Testing Infrastructure

[![Status: Production-Oriented](https://img.shields.io/badge/Status-Production--Oriented-06b6d4?style=flat-square)](#)
[![Python: 3.13+](https://img.shields.io/badge/Python-3.13+-3b82f6?style=flat-square&logo=python)](#)
[![Next.js: 16 (Turbopack)](https://img.shields.io/badge/Next.js-16%20Turbopack-white?style=flat-square&logo=next.js)](#)
[![Audit: SHA--256](https://img.shields.io/badge/Audit-SHA--256%20Hash--Linked-10b981?style=flat-square)](#)

DefendX is an enterprise AI safety testing platform designed to securely separate the **Red Team** (offensive test creation), **Blue Team** (defensive guardrails), and **Auditors** (evidence verification). It evaluates generative AI models for prompt injection vulnerability, confidential information leakage, and cross-team boundary violations while maintaining tamper-evident cryptographic audit logs.

---

## 🌟 Key Features

1. **Strict Server-Side RBAC & Team Separation**:
   - Backend-enforced roles: `ADMIN`, `RED_TEAM`, `BLUE_TEAM`, `AUDITOR`.
   - Cross-team access violations are blocked with HTTP 403 and automatically registered in the audit trail.
2. **Red Team Adversarial Workspace**:
   - Author, import, and manage adversarial safety test cases across 8 standardized categories.
   - Controlled execution against baseline and hardened model configurations.
3. **Blue Team Defensive Guardrails**:
   - Active input blacklists, prompt injection sensitivity thresholds, and canary exfiltration output regex.
4. **Controlled Before-and-After Testing**:
   - Side-by-side benchmarking comparing baseline model behavior with active guardrails on identical payloads.
5. **Interactive Live Isolation Proof**:
   - Live interactive demonstration proving cross-team isolation and displaying actual server-side HTTP authorization results.
6. **Canary Leakage Detection Engine**:
   - Reproducible synthetic canary tokens (`CANARY-SECRET-8A2F91C4`) detecting memory and cross-session context exfiltration.
7. **Secure File & Photo Upload Centre & Scanner**:
   - Multi-stage pipeline: extension check, magic byte format verification, canary detection, and ClamAV integration.
8. **Adversarial Dataset Import Wizard**:
   - Ingest CSV and JSON test suites with header mapping, row-level validation, and duplicate detection.
9. **Cryptographic SHA-256 Hash-Linked Audit Trail**:
   - Every security event is chained with canonical JSON serialization and previous hash linkage.
   - Built-in mathematical verification report detecting tampered or inserted records.
10. **Real Infrastructure Telemetry**:
    - Live database roundtrip latency, psutil host CPU/memory telemetry, and model provider status.
11. **Help Assistant**:
    - Embedded floating chatbot widget with AI guidance and rule-based safety FAQ fallback.

---

## 🚀 Quick Start (Windows PowerShell)

### Prerequisites
- Python 3.13+
- Node.js 20+ / 24+ and npm
- Docker & Docker Compose (optional for containerized deployment)

---

### Step 1: Backend Setup & Verification

Open a Windows PowerShell terminal in the repository root:

```powershell
# 1. Navigate to backend directory
cd backend

# 2. Virtual environment is already configured in backend/venv
# To run backend directly using the virtual environment:
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend will automatically create SQLite database tables, run seeders, and initialize default users and test suites.

- **API Documentation (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

### Step 2: Running Automated Test Suites

In PowerShell:

```powershell
cd backend
.\venv\Scripts\pytest.exe -v
```

All 7 core test suites (Authentication, RBAC Access Denial, Prompt Injection Evaluation, Before-and-After Comparisons, Cryptographic Audit Tampering, and File Scanner) will execute and verify all security properties.

---

### Step 3: Frontend Setup & Launch

Open a second Windows PowerShell terminal:

```powershell
# 1. Navigate to frontend directory
cd frontend

# 2. Start the Next.js development server
npm run dev
```

Visit the application at: [http://localhost:3000](http://localhost:3000)

---

## 🔑 Authentication Personas & Dev Auth

DefendX supports both **official Google OAuth 2.0 / OpenID Connect** and an **Instant Dev Auth Mode** for testing roles:

| Persona | Email | Role | Scope |
| :--- | :--- | :--- | :--- |
| **Alex Vance** | `admin@defendx.ai` | `ADMIN` | Full control, policy administration, audit verification |
| **Rachel Cole** | `redteam@defendx.ai` | `RED_TEAM` | Author & execute adversarial attacks, dataset uploads |
| **Ben Stone** | `blueteam@defendx.ai` | `BLUE_TEAM` | Defensive guardrails, threshold tuning, remediations |
| **Arthur Hayes** | `auditor@defendx.ai` | `AUDITOR` | Read-only compliance, hash-chain verification, export |

To test role switching without re-logging, use the **Role Switcher** in the top navigation bar.

---

## 🐳 Docker Compose Deployment

To deploy the entire multi-service stack with PostgreSQL, ClamAV, FastAPI, and Next.js:

```powershell
# In the root directory:
docker-compose up -d --build
```

---

## 🛡️ Documented Limitations & Residual Risks

1. **Keyword & Heuristic Input Filtering**: While effective against known injection patterns, heuristic filters cannot guarantee complete prevention of polyglot or token-manipulation prompt injections.
2. **Model Nondeterminism**: LLM outputs may exhibit variance across runs; sandbox findings should be benchmarked across multiple iterations.
3. **Audit Chain Boundary**: SHA-256 hash chains detect internal database tampering; for zero-trust guarantees in production, export audit logs to write-once cloud storage (e.g. S3 Object Lock).
