# DefendX — Defect Investigation & Bug Report

**Document ID**: DEFENDX-BUG-2026-V1  
**Audit Stage**: Pre-Production Audit & End-to-End Testing  
**Status**: ALL CONFIRMED BUGS RESOLVED & VERIFIED BY REGRESSION TESTS  

---

## 1. Defect Summary Table

| Defect ID | Severity | Component | Summary | Resolution Status |
|---|---|---|---|---|
| `BUG-001` | High | Frontend (`/login`) | Next.js 16 SSR bailout caused by un-suspended `useSearchParams()` | **RESOLVED & VERIFIED** |
| `BUG-002` | Medium | Backend Auth | Missing `google-auth` HTTP transport library for token verification | **RESOLVED & VERIFIED** |
| `BUG-003` | High | Database / Migrations | Alembic migration head divergence from initialized SQLite schema | **RESOLVED & VERIFIED** |
| `BUG-004` | Medium | Frontend Routing | Missing standalone `/register` route resulting in 404 on direct navigation | **RESOLVED & VERIFIED** |

---

## 2. Detailed Bug Reports & Resolutions

### Defect `BUG-001`: Next.js 16 SSR Bailout in `/login`

- **Severity**: High (Deployment Blocker on static optimization)
- **Component**: `frontend/src/app/login/page.tsx`
- **Symptom**: During `npm run build`, Next.js 16 emitted an SSR error or de-optimized the entire login route because `useSearchParams()` was invoked at the root level of a client component without being enclosed within a React `<Suspense>` boundary.
- **Root Cause**: Next.js 16 App Router requires any component reading search query parameters at build-time to be wrapped in `<Suspense>` to allow static page generation with client-side query dehydration.
- **Fix Applied**:
  - Refactored `frontend/src/app/login/page.tsx` into a lightweight page wrapper with `<Suspense fallback={<LoginLoadingSkeleton />}>`.
  - Extracted the active query parameter reader into `LoginFormInner`.
- **Verification**: `npm run build` completed cleanly in 1480ms with 20/20 static pages generated without warnings.

---

### Defect `BUG-002`: Missing `google-auth` Transport Dependency

- **Severity**: Medium (Runtime Crash on Google Sign-In)
- **Component**: `backend/app/api/auth.py`
- **Symptom**: Calling `id_token.verify_oauth2_token(token, requests.Request())` raised `ModuleNotFoundError: No module named 'google.auth.transport.requests'` in specific lightweight Python virtual environment installations.
- **Root Cause**: While `google-auth` was installed, the underlying `requests` HTTP transport was not pinned in the backend environment specification.
- **Fix Applied**:
  - Added `requests>=2.31.0` to `backend/requirements.txt`.
  - Installed `requests` in the active Python 3.13.5 virtual environment.
- **Verification**: Executed `pytest tests/test_google_auth.py` — all 7 Google Sign-In unit and integration tests passed cleanly.

---

### Defect `BUG-003`: Alembic Migration Head Divergence

- **Severity**: High (Database Migration & Multi-worker Desynchronization)
- **Component**: `backend/alembic/versions/` & `backend/defendx.db`
- **Symptom**: Running `alembic current` or `alembic check` failed because the SQLite database had been initialized via SQLAlchemy's `create_all()`, leaving the `alembic_version` table unpopulated.
- **Root Cause**: The project lacked a concrete baseline Alembic migration script mapping the existing database tables (`users`, `audit_logs`, `attack_vectors`, `defense_rules`, `evaluations`, `files`, `findings`, `evidence_bundles`).
- **Fix Applied**:
  - Configured `backend/alembic/env.py` to import `Base` and target metadata from `app.models`.
  - Generated baseline migration `backend/alembic/versions/dd083ff9997d_initial_schema.py`.
  - Executed `alembic stamp head` to mark the existing database at the current revision.
  - Added automated test `tests/test_defendx_core.py::test_alembic_migration_head_aligned` to ensure future schema changes are tracked.
- **Verification**: `alembic current` returns `dd083ff9997d (head)`.

---

### Defect `BUG-004`: Missing Standalone `/register` Route

- **Severity**: Medium (User Navigation Friction)
- **Component**: `frontend/src/app/register/page.tsx`
- **Symptom**: When users or external links accessed `http://localhost:3000/register`, Next.js returned a 404 Not Found error because registration was only implemented as an interactive tab inside `/login`.
- **Root Cause**: No page existed at `src/app/register`.
- **Fix Applied**:
  - Created `frontend/src/app/register/page.tsx` with automatic query redirection to `/login?tab=register` wrapped in a Cyber-themed fallback indicator.
- **Verification**: Navigating to `/register` immediately loads the registration tab in `/login` with Red Team / Blue Team selection.

---

## 3. Regression Testing Summary

All 4 fixes were re-verified using the automated test suite:
- Total Tests Run: 24
- Passed: 24
- Failed: 0
- Regressions Detected: 0
