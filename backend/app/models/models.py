import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Float, ForeignKey, Enum as SQLEnum, JSON
)
from sqlalchemy.orm import relationship
from app.core.database import Base

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    RED_TEAM = "RED_TEAM"
    BLUE_TEAM = "BLUE_TEAM"
    AUDITOR = "AUDITOR"

class AccountStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    PENDING = "PENDING"

class TestCategory(str, enum.Enum):
    INPUT_SAFETY = "INPUT_SAFETY"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    INSTRUCTION_CONFLICTS = "INSTRUCTION_CONFLICTS"
    CONTEXT_LEAKAGE = "CONTEXT_LEAKAGE"
    CROSS_TEAM_LEAKAGE = "CROSS_TEAM_LEAKAGE"
    OUTPUT_SAFETY = "OUTPUT_SAFETY"
    ISOLATION = "ISOLATION"
    SENSITIVE_INFO = "SENSITIVE_INFO"

class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

class EvaluationStatus(str, enum.Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"

class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    REMEDIATED = "REMEDIATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    SCANNING = "SCANNING"
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    INFECTED = "INFECTED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"

class EvidenceAccess(str, enum.Enum):
    PUBLIC_AUDIT = "PUBLIC_AUDIT"
    RED_TEAM_ONLY = "RED_TEAM_ONLY"
    BLUE_TEAM_ONLY = "BLUE_TEAM_ONLY"
    ADMIN_ONLY = "ADMIN_ONLY"

class LeakageAttemptStatus(str, enum.Enum):
    ATTEMPTED = "ATTEMPTED"
    BLOCKED = "BLOCKED"
    SUSPECTED_DISCLOSURE = "SUSPECTED_DISCLOSURE"
    CONFIRMED_DISCLOSURE = "CONFIRMED_DISCLOSURE"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.RED_TEAM, nullable=False)
    picture_url = Column(String(1024), nullable=True)
    is_active = Column(Boolean, default=True)
    status = Column(SQLEnum(AccountStatus), default=AccountStatus.ACTIVE)
    auth_provider = Column(String(50), default="google")
    hashed_password = Column(String(255), nullable=True)
    reset_token = Column(String(255), nullable=True, index=True)
    reset_token_expires_at = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    test_cases = relationship("TestCase", back_populates="creator")
    executions = relationship("TestExecution", back_populates="executor")

class TestCase(Base):
    __tablename__ = "test_cases"

    id = Column(Integer, primary_key=True, index=True)
    test_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g., TC-PINJ-001
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(SQLEnum(TestCategory), nullable=False)
    severity = Column(SQLEnum(Severity), default=Severity.MEDIUM, nullable=False)
    input_prompt = Column(Text, nullable=False)
    expected_behavior = Column(Text, nullable=False)
    tags = Column(String(255), nullable=True)
    is_sandbox_only = Column(Boolean, default=True)
    team = Column(SQLEnum(UserRole), default=UserRole.RED_TEAM)
    dataset_id = Column(Integer, ForeignKey("test_datasets.id"), nullable=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    creator = relationship("User", back_populates="test_cases")
    executions = relationship("TestExecution", back_populates="test_case", cascade="all, delete-orphan")

class TestDataset(Base):
    __tablename__ = "test_datasets"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    file_format = Column(String(10), default="json")
    record_count = Column(Integer, default=0)
    valid_count = Column(Integer, default=0)
    malformed_count = Column(Integer, default=0)
    duplicate_count = Column(Integer, default=0)
    team = Column(SQLEnum(UserRole), default=UserRole.RED_TEAM)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    validation_status = Column(String(50), default="VALID")
    created_at = Column(DateTime, default=datetime.utcnow)

class DefensivePolicy(Base):
    __tablename__ = "defensive_policies"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g. POL-DEF-01
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    input_filter_enabled = Column(Boolean, default=True)
    output_filter_enabled = Column(Boolean, default=True)
    forbidden_keywords = Column(Text, default="system prompt,ignore previous,bypass,drop table,exfiltrate")
    canary_protection_enabled = Column(Boolean, default=True)
    prompt_injection_threshold = Column(Float, default=0.75)
    leak_prevention_regex = Column(Text, default=r"CANARY-[A-Z0-9]{8}|SK-[A-Z0-9]{16}")
    team = Column(SQLEnum(UserRole), default=UserRole.BLUE_TEAM)
    version = Column(String(20), default="1.0.0")
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class TestExecution(Base):
    __tablename__ = "test_executions"

    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String(50), unique=True, index=True, nullable=False)
    test_case_id = Column(Integer, ForeignKey("test_cases.id"), nullable=False)
    policy_id = Column(Integer, ForeignKey("defensive_policies.id"), nullable=True)
    model_name = Column(String(100), default="defendx-evaluator-v1")
    baseline_mode = Column(Boolean, default=False)
    execution_mode = Column(String(50), default="RULE_AND_MODEL")
    status = Column(SQLEnum(EvaluationStatus), default=EvaluationStatus.PASSED)
    input_sent = Column(Text, nullable=False)
    model_raw_response = Column(Text, nullable=True)
    evaluation_reasoning = Column(Text, nullable=True)
    policy_action = Column(String(50), default="ALLOW")  # ALLOW, BLOCK, SANITIZE
    failed_checks = Column(JSON, default=list)
    confidence_score = Column(Float, default=0.95)
    execution_time_ms = Column(Integer, default=120)
    executed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    team = Column(SQLEnum(UserRole), default=UserRole.RED_TEAM)
    created_at = Column(DateTime, default=datetime.utcnow)

    test_case = relationship("TestCase", back_populates="executions")
    executor = relationship("User", back_populates="executions")
    policy = relationship("DefensivePolicy")

class ComparisonRecord(Base):
    __tablename__ = "comparisons"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    test_case_id = Column(Integer, ForeignKey("test_cases.id"), nullable=False)
    baseline_execution_id = Column(Integer, ForeignKey("test_executions.id"), nullable=False)
    protected_execution_id = Column(Integer, ForeignKey("test_executions.id"), nullable=False)
    status_change = Column(String(100), nullable=False)  # e.g., "FAILED -> PASSED (Remediated)"
    regression_detected = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    test_case = relationship("TestCase")
    baseline_execution = relationship("TestExecution", foreign_keys=[baseline_execution_id])
    protected_execution = relationship("TestExecution", foreign_keys=[protected_execution_id])

class LeakageTest(Base):
    __tablename__ = "leakage_tests"

    id = Column(Integer, primary_key=True, index=True)
    test_code = Column(String(50), unique=True, index=True, nullable=False)
    resource_category = Column(String(100), nullable=False)  # e.g., "Synthetic API Keys", "Blue Team Policy"
    synthetic_canary = Column(String(100), nullable=False)
    attempted_action = Column(Text, nullable=False)
    actual_access_result = Column(String(50), nullable=False)  # "DENIED", "BLOCKED", "DISCLOSED"
    detection_method = Column(String(100), default="CANARY_REGEX_AND_HASH")
    evidence_ref = Column(String(100), nullable=True)
    severity = Column(SQLEnum(Severity), default=Severity.HIGH)
    confidence = Column(Float, default=0.98)
    status = Column(SQLEnum(LeakageAttemptStatus), default=LeakageAttemptStatus.BLOCKED)
    notes = Column(Text, nullable=True)
    tested_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True, index=True)
    finding_code = Column(String(50), unique=True, index=True, nullable=False)  # FIND-2026-001
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(SQLEnum(TestCategory), nullable=False)
    severity = Column(SQLEnum(Severity), default=Severity.HIGH)
    affected_component = Column(String(255), nullable=False)
    test_execution_id = Column(Integer, ForeignKey("test_executions.id"), nullable=True)
    detection_method = Column(String(100), default="Automated Safety Test")
    confidence = Column(Float, default=0.95)
    reproducibility_status = Column(String(50), default="REPRODUCIBLE")
    remediation_recommendation = Column(Text, nullable=True)
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.OPEN)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    team = Column(SQLEnum(UserRole), default=UserRole.BLUE_TEAM)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    execution = relationship("TestExecution")
    owner = relationship("User")

class UploadedFile(Base):
    __tablename__ = "uploaded_files"

    id = Column(Integer, primary_key=True, index=True)
    original_name = Column(String(255), nullable=False)
    stored_name = Column(String(255), nullable=False)
    file_path = Column(String(1024), nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False)
    file_hash_sha256 = Column(String(64), nullable=False, index=True)
    scan_status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    scan_summary = Column(Text, nullable=True)
    scanner_details = Column(JSON, default=dict)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    team = Column(SQLEnum(UserRole), default=UserRole.RED_TEAM)
    is_quarantined = Column(Boolean, default=False)
    retention_days = Column(Integer, default=90)
    created_at = Column(DateTime, default=datetime.utcnow)

class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(Integer, primary_key=True, index=True)
    evidence_code = Column(String(50), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    evidence_type = Column(String(50), default="SCREENSHOT")  # SCREENSHOT, LOG, REPORT, CANARY_PROOF
    file_id = Column(Integer, ForeignKey("uploaded_files.id"), nullable=True)
    test_execution_id = Column(Integer, ForeignKey("test_executions.id"), nullable=True)
    finding_id = Column(Integer, ForeignKey("security_findings.id"), nullable=True)
    file_checksum = Column(String(64), nullable=False)
    access_classification = Column(SQLEnum(EvidenceAccess), default=EvidenceAccess.PUBLIC_AUDIT)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    team = Column(SQLEnum(UserRole), default=UserRole.RED_TEAM)
    created_at = Column(DateTime, default=datetime.utcnow)

    file = relationship("UploadedFile")
    execution = relationship("TestExecution")
    finding = relationship("SecurityFinding")

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    actor_id = Column(String(100), nullable=False)
    actor_role = Column(String(50), nullable=False)
    action = Column(String(100), nullable=False)  # e.g., TEST_EXECUTE, POLICY_UPDATE, ACCESS_DENIED
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(100), nullable=False)
    team_context = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    outcome = Column(String(50), nullable=False)  # SUCCESS, DENIED, ERROR
    correlation_id = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)
    details_json = Column(JSON, default=dict)

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    category = Column(String(50), default="SECURITY_ALERT")
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    role = Column(String(20), nullable=False)  # "user", "assistant", "system"
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
