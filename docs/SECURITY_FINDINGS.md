# DefendX — Application Security & Threat Model Report

**Document ID**: DEFENDX-SEC-2026-V1  
**Classification**: CONFIDENTIAL / SECURITY ASSESSMENT  
**Standard Compliance**: OWASP Top 10 (2021), OWASP LLM Top 10 (2025), NIST AI RMF  

---

## 1. Security Architecture & Threat Matrix

DefendX operates as a dual-role adversarial security proving ground. Because the platform intentionally processes malicious payloads, adversarial prompts, and exploit vectors, the platform itself must be fortified against the very threats it evaluates.

```
+---------------------------------------------------------------------------------------------------+
|                                      THREAT VECTORS & DEFENSES                                    |
+------------------------------+------------------------------------+-------------------------------+
| Threat Vector                | Potential Impact                   | DefendX Defense Architecture  |
+------------------------------+------------------------------------+-------------------------------+
| Cross-Team Data Compromise   | Red Team steals Blue Team filters  | Server-side RBAC dependencies |
|                              | Blue Team tampers with exploits    | Auto-logged audit violations  |
+------------------------------+------------------------------------+-------------------------------+
| Prompt Injection / Escape    | Attacker tricks LLM runner         | Heuristic risk scoring        |
|                              | into violating platform safety     | Output pattern redaction      |
+------------------------------+------------------------------------+-------------------------------+
| Canary Secret Leakage        | System prompt or training data     | Synthetic canary generator    |
|                              | exposed in completions             | Real-time token regex matcher |
+------------------------------+------------------------------------+-------------------------------+
| Malicious File Upload        | Remote Code Execution (RCE) via    | Magic byte validation, allow- |
|                              | polyglot files or CSV formulas     | list, auto-quarantine, ClamAV |
+------------------------------+------------------------------------+-------------------------------+
| Audit Trail Tampering        | Attacker mutates event logs to     | SHA-256 sequential Merkle     |
|                              | conceal malicious activity         | digest chaining from Genesis  |
+------------------------------+------------------------------------+-------------------------------+
```

---

## 2. In-Depth Evaluation Against The Five Core Questions

### 2.1 Question 1: Can someone manipulate the AI using misleading instructions or prompt injection?
- **Vulnerability Analyzed**: Direct prompt injection, role-play system jailbreaks (e.g., "Do Anything Now"), delimiter injection, and virtual machine simulation.
- **DefendX Remediation**:
  - Implemented multi-layered evaluation in `backend/app/services/evaluator.py`.
  - Scans prompt inputs for semantic injection triggers, override keywords, and delimiter tricks.
  - Generates a granular risk score (0.0 to 1.0) and assigns an OWASP LLM category (e.g., `LLM01: Prompt Injection`).
  - Blocks high-risk payloads from execution when Blue Team filters are active.

### 2.2 Question 2: Can the AI reveal confidential information?
- **Vulnerability Analyzed**: System prompt extraction, canary token leakage, and inadvertent PII memorization exposure.
- **DefendX Remediation**:
  - Implemented the Synthetic Canary Token Generator (`CANARY-SECRET-[0-9A-F]{8}`).
  - Canaries are injected into confidential prompt contexts.
  - When LLM output is generated, the Canary Leakage Detector scans completions with high-entropy regular expressions.
  - If a canary token appears in the completion, the platform marks the evaluation as `CRITICAL_LEAK`, captures an evidence snapshot, and records an audit incident.

### 2.3 Question 3: Do configured safety filters work correctly?
- **Vulnerability Analyzed**: Filter evasion via homoglyphs, base64 obfuscation, and subtle semantic shifts.
- **DefendX Remediation**:
  - The Comparison Engine (`/api/v1/comparisons`) executes dual-pass A/B runs:
    1. **Baseline Run**: Direct model response without active defensive rules.
    2. **Guarded Run**: Response subjected to regex patterns, semantic keyword blocklists, and threshold tuning.
  - The UI computes an exact diff, highlighting neutralized terms in electric-cyan and presenting a clear verdict: `Leak Prevented: True`.

### 2.4 Question 4: Can Red Team and Blue Team access each other's private data?
- **Vulnerability Analyzed**: Broken Object Level Authorization (BOLA / IDOR) and privilege escalation between offensive and defensive teams.
- **DefendX Remediation**:
  - Enforced via FastAPI's dependency injection system: `require_roles([UserRole.RED_TEAM, UserRole.ADMIN])` vs `require_roles([UserRole.BLUE_TEAM, UserRole.ADMIN])`.
  - Self-registration is restricted: users cannot register as `ADMIN` or `AUDITOR`.
  - Any cross-team unauthorized attempt immediately triggers an HTTP 403 Forbidden and posts an unalterable `UNAUTHORIZED_ENDPOINT_ACCESS_ATTEMPT` audit log with client IP, timestamp, and requested URI.

### 2.5 Question 5: Can every security finding be reproduced and supported by trustworthy evidence?
- **Vulnerability Analyzed**: Unsubstantiated or repudiated vulnerability findings, altered test logs.
- **DefendX Remediation**:
  - Implemented an immutable SHA-256 sequential hash chain (`backend/app/core/audit.py`):
    $$\text{Hash}_i = \text{SHA256}(\text{CanonicalJSON}(\text{PrevHash}_{i-1}, \text{ActorID}, \text{Role}, \text{Action}, \text{Timestamp}, \text{Payload}))$$
  - The `/api/v1/audit/verify` endpoint verifies the entire cryptographic chain from Genesis (`0000...0000`). If a single bit in the database is modified, verification fails and identifies the exact tampered index.
  - Evidence bundles export all raw inputs, outputs, timestamps, and SHA-256 checksums in a verifiable JSON format.

---

## 3. File Upload & Processing Security Analysis

DefendX implements an industry-standard 6-stage upload pipeline:
1. **Extension Allowlist**: Strict filter permitting only `.csv`, `.json`, `.txt`, `.png`, `.jpg`, `.jpeg`, `.webp`, `.pdf`, `.log`. Disallowed extensions are rejected before reading disk.
2. **Magic Byte Verification**: Verifies file binary signatures against known file headers to prevent executable polyglot disguised as images or text.
3. **Payload Inspection**: Inspects text and code files for script injection tags (`<script>`, `javascript:`, `eval()`).
4. **CSV Formula Injection Sanitization**: Scans spreadsheet uploads for formula trigger prefixes (`=`, `+`, `-`, `@`, `|`). If found, cells are neutralized or the file is marked quarantined.
5. **Malware Telemetry**: Queries ClamAV daemon via TCP socket (`localhost:3310`). If unreachable, reports `UNAVAILABLE` rather than falsely asserting the file is benign.
6. **Isolated Quarantine Storage**: Suspicious files are segregated with `is_quarantined = true`, preventing them from being served or processed by the evaluation engine.

---

## 4. Authentication & Session Hardening

- **Password Storage**: Passwords hashed using Argon2 / BCrypt with automatic salting; plaintext passwords never touch the persistence layer.
- **JWT Protection**: Signed with HS256 / RS256; token expiration enforced; validated per-request via bearer headers.
- **Google OAuth 2.0 / OpenID Connect**:
  - Validates cryptographic signature via Google's public key certificates.
  - Confirms `aud` matches configured `GOOGLE_CLIENT_ID`.
  - Verifies `iss` is `https://accounts.google.com` or `accounts.google.com`.
  - Rejects tokens where `email_verified` is `false`.
  - Enforces least-privilege role assignment: newly authenticated Google users default to `RED_TEAM` or `BLUE_TEAM`, never `ADMIN`.

---

## 5. Residual Risk & Production Hardening Recommendations

1. **Content Security Policy (CSP)**:
   - For enterprise production deployment, configure strict CSP headers in `next.config.js` (`frame-ancestors 'none'`, `script-src 'self' https://accounts.google.com`).
2. **Rate Limiting**:
   - In containerized production, deploy an API gateway (e.g., NGINX / Cloudflare) to enforce rate limits (e.g., 60 requests/minute per IP) on `/api/v1/auth/login` and `/api/v1/evaluation/run`.
3. **Database Migration to PostgreSQL**:
   - In production, ensure `DATABASE_URL` points to an enterprise PostgreSQL instance with TLS 1.3 encryption in transit (`sslmode=require`).
