# DefendX: Securing Adversarial AI – Architectural Blueprint

## 1. System Overview

DefendX is an enterprise AI safety testing infrastructure designed to evaluate generative models against adversarial manipulation, prompt injection, and information leakage, while enforcing strict role-based separation between the **Red Team**, **Blue Team**, and **Auditors**.

```
+---------------------------------------------------------------------------------+
|                                 DEFENDX WEB UI                                  |
|   Next.js (App Router) + TypeScript + Tailwind CSS + Recharts + Lucide Icons   |
+---------------------------------------------------------------------------------+
                                       |
                           HTTPS REST & JSON Bearer
                                       v
+---------------------------------------------------------------------------------+
|                              FASTAPI BACKEND CORE                               |
|   Role-Based Access Control (RBAC) & OAuth 2.0 / OpenID Connect Validation     |
+---------------------------------------------------------------------------------+
          |                               |                          |
          v                               v                          v
+-------------------+           +-------------------+      +-------------------+
|     RED TEAM      |           |     BLUE TEAM     |      |   EVALUATION &    |
|   OFFENSIVE HUB   |           |    DEFENSE HUB    |      |    AUDIT CORE     |
| - Test Authoring  |           | - Input Filters   |      | - LLM Runner      |
| - Dataset Wizard  |           | - Threshold Tuning|      | - Canary Engine   |
| - Exploit Storage |           | - Output Redaction|      | - SHA-256 Audit   |
+-------------------+           +-------------------+      +-------------------+
          |                               |                          |
          +-------------------------------+--------------------------+
                                          |
                                          v
                         +---------------------------------+
                         |      PERSISTENCE & STORAGE      |
                         | - PostgreSQL / AsyncIO SQLite   |
                         | - Isolated Upload Quarantine    |
                         | - ClamAV Daemon Heuristic Scan  |
                         +---------------------------------+
```

## 2. Five Core Questions Addressed

1. **Can someone manipulate the AI using misleading instructions or prompt injection?**
   - Simulated via the Red Team Workspace and evaluated against heuristic indicators.
2. **Can the AI reveal confidential information?**
   - Verified using reproducible synthetic canary tokens (`CANARY-SECRET-XXXXXXXX`).
3. **Do configured safety filters work correctly?**
   - Benchmarked using Controlled Before-and-After Testing (Baseline vs Protected).
4. **Can Red Team and Blue Team access each other's private data?**
   - Enforced server-side in every endpoint and verified in the Live Isolation Demo.
5. **Can every security finding be reproduced and supported by trustworthy evidence?**
   - Cryptographically guaranteed via SHA-256 hash-linked audit logging and checksum verification.

## 3. Cryptographic Audit Chain Specification

Every sensitive event $E_i$ is recorded with:
$$\text{Hash}_i = \text{SHA256}(\text{CanonicalJSON}(\text{PrevHash}_{i-1}, \text{EventID}_i, \text{ActorRole}_i, \text{Action}_i, \dots))$$

Where $\text{PrevHash}_0 = 0^{64}$ (Genesis Hash).
The `/api/v1/audit/verify` endpoint sequentially recomputes each node's digest, providing mathematical proof of audit trail authenticity.

## 4. Multi-Stage File Scanner Architecture

1. **Extension Check**: Restricts uploads to `.csv`, `.json`, `.txt`, `.png`, `.jpg`, `.jpeg`, `.webp`, `.pdf`, `.log`.
2. **Magic Byte Signature**: Compares binary headers against known magic numbers to prevent MIME spoofing.
3. **Size Limit Enforcement**: Rejects files exceeding configured threshold (default: 25MB).
4. **Deep Text Inspection**: Scans for embedded script tags, shell commands, CSV formula injections, and synthetic canary tokens.
5. **Malware Daemon Telemetry**: Connects to ClamAV daemon via TCP socket. If offline, reports `UNAVAILABLE` honestly rather than declaring files clean.
6. **Quarantine Containment**: Suspicious files are tagged `is_quarantined = true` and blocked from execution or unauthorized download.
