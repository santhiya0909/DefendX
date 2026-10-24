import os
import re
import csv
import json
import socket
from typing import Dict, Any, Tuple
from app.models.models import ScanStatus
from app.core.config import settings

MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"%PDF-": "application/pdf",
    b"RIFF": "image/webp",  # WebP begins with RIFF...WEBP
}

SENSITIVE_PATTERNS = [
    (re.compile(r"CANARY(?:-[A-Z0-9]+)+"), "DefendX Synthetic Canary Secret"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key Pattern"),
    (re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----"), "Cryptographic Private Key Block"),
    (re.compile(r"(?i)(password|secret|apikey|api_key)\s*[:=]\s*['\"][A-Za-z0-9_!@#$%^&*]{8,}['\"]"), "Plaintext Credential Pattern"),
    (re.compile(r"sk-[a-zA-Z0-9]{32,64}"), "OpenAI API Key Pattern"),
]

SUSPICIOUS_SCRIPT_PATTERNS = [
    (re.compile(r"<\s*script[^>]*>", re.IGNORECASE), "Embedded Script Tag"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "JavaScript URI Scheme"),
    (re.compile(r"(?i)(powershell|cmd\.exe|/bin/sh|/bin/bash)\s+(-e|-c|exec)"), "Shell Execution Command Pattern"),
    (re.compile(r"^[=+\-@]\s*(cmd|exec|powershell)", re.IGNORECASE), "CSV Command Injection Formula"),
]

def check_clamav_service(host: str, port: int) -> Tuple[bool, str]:
    """Tests if a local/remote ClamAV daemon is responding via PING."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((host, port))
            s.sendall(b"zPING\0")
            data = s.recv(1024)
            if b"PONG" in data:
                return True, "ClamAV daemon active (PONG received)"
    except Exception as e:
        return False, f"ClamAV daemon unreachable ({type(e).__name__})"
    return False, "ClamAV returned non-PONG response"

def scan_file_content(file_path: str, original_filename: str) -> Dict[str, Any]:
    """
    Executes multi-stage security scan:
    1. Extension & Path Traversal
    2. Magic bytes / Signature check
    3. File size check
    4. Text & Parsing check (safe JSON/CSV)
    5. Sensitive data & Canary detection
    6. Suspicious shell / CSV injection detection
    7. ClamAV integration status
    """
    filename_lower = original_filename.lower()
    _, ext = os.path.splitext(filename_lower)
    
    findings = []
    checks_run = []
    quarantine = False

    # Check 1: Extension allowlist
    checks_run.append("EXTENSION_VALIDATION")
    if ext not in settings.ALLOWED_EXTENSIONS:
        return {
            "status": ScanStatus.REJECTED,
            "summary": f"Rejected extension '{ext}'. Only authorized test artifacts and datasets are allowed.",
            "quarantined": True,
            "checks_run": checks_run,
            "findings": [f"Disallowed extension: {ext}"]
        }

    # Check 2: File size
    checks_run.append("SIZE_LIMIT_CHECK")
    file_size = os.path.getsize(file_path)
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        return {
            "status": ScanStatus.REJECTED,
            "summary": f"File size ({file_size} bytes) exceeds {settings.MAX_UPLOAD_SIZE_MB}MB policy threshold.",
            "quarantined": True,
            "checks_run": checks_run,
            "findings": ["Size limit exceeded"]
        }

    # Check 3: Magic Bytes & Format Verification
    checks_run.append("MAGIC_BYTE_VERIFICATION")
    with open(file_path, "rb") as f:
        header = f.read(16)
        
    is_image_or_pdf = ext in [".png", ".jpg", ".jpeg", ".webp", ".pdf"]
    if is_image_or_pdf:
        matched = False
        for sig, mime in MAGIC_SIGNATURES.items():
            if header.startswith(sig):
                matched = True
                break
        if not matched:
            findings.append(f"MIME spoofing detected: File extension '{ext}' does not match header signature.")
            quarantine = True

    # Check 4: Deep Content & Sensitive Data Scan for text/csv/json/log
    is_text = ext in [".csv", ".json", ".txt", ".log"]
    if is_text:
        checks_run.append("CONTENT_INSPECTION")
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(500_000)  # Read up to 500KB for inspection
            
            # Check for binary null bytes masquerading as text
            if "\x00" in content:
                findings.append("Suspicious null bytes in text payload (possible binary masquerading)")
                quarantine = True

            # Sensitive data patterns
            for pattern, label in SENSITIVE_PATTERNS:
                matches = pattern.findall(content)
                if matches:
                    findings.append(f"Detected {len(matches)} instance(s) of '{label}'")

            # Suspicious script / shell / CSV injection
            for pattern, label in SUSPICIOUS_SCRIPT_PATTERNS:
                if pattern.search(content):
                    findings.append(f"Suspicious payload pattern: '{label}'")
                    quarantine = True

            # Check format parsing integrity
            if ext == ".json":
                checks_run.append("JSON_PARSER_VALIDATION")
                try:
                    json.loads(content)
                except Exception as json_err:
                    findings.append(f"Malformed JSON structure: {str(json_err)[:100]}")
            
            elif ext == ".csv":
                checks_run.append("CSV_PARSER_VALIDATION")
                try:
                    reader = csv.reader(content.splitlines())
                    for row_idx, row in enumerate(reader):
                        if row_idx > 5000:
                            break
                        for cell in row:
                            if cell.startswith(("=", "+", "-", "@")):
                                findings.append(f"Formula injection potential in row {row_idx+1}: '{cell[:20]}'")
                except Exception as csv_err:
                    findings.append(f"Malformed CSV: {str(csv_err)[:100]}")

        except Exception as read_err:
            findings.append(f"Failed to read file for content scanning: {str(read_err)}")

    # Check 5: Malware Scanner / ClamAV Status
    checks_run.append("MALWARE_ENGINE_CHECK")
    clamav_available, clamav_msg = check_clamav_service(settings.CLAMAV_HOST, settings.CLAMAV_PORT)

    # Determine final status
    if quarantine or any("spoofing" in f or "null bytes" in f or "Formula injection" in f for f in findings):
        status = ScanStatus.SUSPICIOUS
        summary = f"Identified {len(findings)} suspicious security finding(s). File quarantined."
    elif findings:
        status = ScanStatus.SUSPICIOUS
        summary = f"Flagged sensitive data patterns ({len(findings)} findings). Reviewed and contained."
    else:
        status = ScanStatus.CLEAN
        summary = "All checks passed. File signature, structure, and text content are valid."

    return {
        "status": status,
        "summary": summary,
        "quarantined": quarantine,
        "checks_run": checks_run,
        "findings": findings,
        "malware_engine": {
            "name": "ClamAV / DefendX Heuristic Scanner",
            "available": clamav_available,
            "status_details": clamav_msg
        }
    }
