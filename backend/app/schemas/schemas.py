from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from app.models.models import (
    UserRole, AccountStatus, TestCategory, Severity,
    EvaluationStatus, FindingStatus, ScanStatus, EvidenceAccess,
    LeakageAttemptStatus
)

# User & Auth
class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    role: UserRole = UserRole.RED_TEAM

class UserCreate(UserBase):
    picture_url: Optional[str] = None

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[AccountStatus] = None

class UserResponse(UserBase):
    id: int
    picture_url: Optional[str] = None
    is_active: bool
    status: AccountStatus
    auth_provider: str
    last_login_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class GoogleAuthRequest(BaseModel):
    credential: Optional[str] = None
    code: Optional[str] = None

class DevLoginRequest(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.RED_TEAM
    full_name: Optional[str] = None

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=2, max_length=100)
    role: UserRole = UserRole.RED_TEAM
    terms_accepted: bool = True

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)

class AuthMessageResponse(BaseModel):
    message: str
    reset_token: Optional[str] = None

# Test Cases
class TestCaseBase(BaseModel):
    name: str
    description: Optional[str] = None
    category: TestCategory
    severity: Severity = Severity.MEDIUM
    input_prompt: str
    expected_behavior: str
    tags: Optional[str] = None
    is_sandbox_only: bool = True

class TestCaseCreate(TestCaseBase):
    test_id: Optional[str] = None

class TestCaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[TestCategory] = None
    severity: Optional[Severity] = None
    input_prompt: Optional[str] = None
    expected_behavior: Optional[str] = None
    tags: Optional[str] = None
    is_sandbox_only: Optional[bool] = None

class TestCaseResponse(TestCaseBase):
    id: int
    test_id: str
    team: UserRole
    created_by_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Datasets
class TestDatasetResponse(BaseModel):
    id: int
    dataset_id: str
    name: str
    description: Optional[str] = None
    file_format: str
    record_count: int
    valid_count: int
    malformed_count: int
    duplicate_count: int
    team: UserRole
    uploader_id: Optional[int] = None
    validation_status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class DatasetImportPreview(BaseModel):
    filename: str
    total_rows: int
    sample_records: List[Dict[str, Any]]
    detected_columns: List[str]
    suggested_mapping: Dict[str, str]

class DatasetImportCommit(BaseModel):
    name: str
    description: Optional[str] = None
    column_mapping: Dict[str, str]  # e.g., {"input": "prompt_text", "expected": "ground_truth"}
    records: List[Dict[str, Any]]

# Defensive Policies
class DefensivePolicyBase(BaseModel):
    name: str
    description: Optional[str] = None
    is_active: bool = True
    is_default: bool = False
    input_filter_enabled: bool = True
    output_filter_enabled: bool = True
    forbidden_keywords: str = "system prompt,ignore previous,bypass,drop table,exfiltrate"
    canary_protection_enabled: bool = True
    prompt_injection_threshold: float = 0.75
    leak_prevention_regex: str = r"CANARY-[A-Z0-9]{8}|SK-[A-Z0-9]{16}"

class DefensivePolicyCreate(DefensivePolicyBase):
    policy_id: Optional[str] = None
    version: str = "1.0.0"

class DefensivePolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None
    input_filter_enabled: Optional[bool] = None
    output_filter_enabled: Optional[bool] = None
    forbidden_keywords: Optional[str] = None
    canary_protection_enabled: Optional[bool] = None
    prompt_injection_threshold: Optional[float] = None
    leak_prevention_regex: Optional[str] = None
    version: Optional[str] = None

class DefensivePolicyResponse(DefensivePolicyBase):
    id: int
    policy_id: str
    team: UserRole
    version: str
    created_by_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Test Execution & Evaluation
class ExecutionRequest(BaseModel):
    test_case_id: int
    policy_id: Optional[int] = None
    baseline_mode: bool = False
    model_override: Optional[str] = None
    execution_mode: str = "RULE_AND_MODEL"

class TestExecutionResponse(BaseModel):
    id: int
    execution_id: str
    test_case_id: int
    policy_id: Optional[int] = None
    model_name: str
    baseline_mode: bool
    execution_mode: str
    status: EvaluationStatus
    input_sent: str
    model_raw_response: Optional[str] = None
    evaluation_reasoning: Optional[str] = None
    policy_action: str
    failed_checks: List[str] = []
    confidence_score: float
    execution_time_ms: int
    executed_by_id: Optional[int] = None
    team: UserRole
    created_at: datetime
    test_case: Optional[TestCaseResponse] = None

    model_config = ConfigDict(from_attributes=True)

# Comparisons
class ComparisonRequest(BaseModel):
    name: str
    test_case_id: int
    policy_id: Optional[int] = None

class ComparisonResponse(BaseModel):
    id: int
    name: str
    test_case_id: int
    baseline_execution_id: int
    protected_execution_id: int
    status_change: str
    regression_detected: bool
    notes: Optional[str] = None
    created_by_id: Optional[int] = None
    created_at: datetime
    baseline_execution: Optional[TestExecutionResponse] = None
    protected_execution: Optional[TestExecutionResponse] = None

    model_config = ConfigDict(from_attributes=True)

# Leakage Tests
class LeakageTestCreate(BaseModel):
    resource_category: str
    synthetic_canary: str
    attempted_action: str
    notes: Optional[str] = None

class LeakageTestResponse(BaseModel):
    id: int
    test_code: str
    resource_category: str
    synthetic_canary: str
    attempted_action: str
    actual_access_result: str
    detection_method: str
    evidence_ref: Optional[str] = None
    severity: Severity
    confidence: float
    status: LeakageAttemptStatus
    notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Findings
class FindingCreate(BaseModel):
    title: str
    description: str
    category: TestCategory
    severity: Severity
    affected_component: str
    test_execution_id: Optional[int] = None
    remediation_recommendation: Optional[str] = None

class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    remediation_recommendation: Optional[str] = None
    owner_id: Optional[int] = None

class FindingResponse(BaseModel):
    id: int
    finding_code: str
    title: str
    description: str
    category: TestCategory
    severity: Severity
    affected_component: str
    test_execution_id: Optional[int] = None
    detection_method: str
    confidence: float
    reproducibility_status: str
    remediation_recommendation: Optional[str] = None
    status: FindingStatus
    owner_id: Optional[int] = None
    team: UserRole
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

# File & Scan
class FileUploadResponse(BaseModel):
    id: int
    original_name: str
    file_size: int
    mime_type: str
    file_hash_sha256: str
    scan_status: ScanStatus
    scan_summary: Optional[str] = None
    scanner_details: Dict[str, Any] = {}
    is_quarantined: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Evidence
class EvidenceCreate(BaseModel):
    title: str
    description: Optional[str] = None
    evidence_type: str = "SCREENSHOT"
    file_id: Optional[int] = None
    test_execution_id: Optional[int] = None
    finding_id: Optional[int] = None
    access_classification: EvidenceAccess = EvidenceAccess.PUBLIC_AUDIT

class EvidenceResponse(BaseModel):
    id: int
    evidence_code: str
    title: str
    description: Optional[str] = None
    evidence_type: str
    file_id: Optional[int] = None
    test_execution_id: Optional[int] = None
    finding_id: Optional[int] = None
    file_checksum: str
    access_classification: EvidenceAccess
    uploader_id: Optional[int] = None
    team: UserRole
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# Audit
class AuditEventResponse(BaseModel):
    id: int
    event_id: str
    actor_id: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: str
    team_context: str
    timestamp: datetime
    outcome: str
    correlation_id: str
    prev_hash: str
    current_hash: str
    details_json: Dict[str, Any] = {}

    model_config = ConfigDict(from_attributes=True)

class AuditChainVerificationResponse(BaseModel):
    verified: bool
    total_events: int
    broken_at_event_id: Optional[str] = None
    status: str
    latest_hash: Optional[str] = None
    message: str

# Isolation Demo
class IsolationCheckRequest(BaseModel):
    actor_role: UserRole
    target_resource_type: str  # "RED_PAYLOAD", "BLUE_POLICY", "EVIDENCE", "CANARY_SECRET"
    target_resource_id: str

class IsolationCheckResponse(BaseModel):
    allowed: bool
    status_code: int
    message: str
    audit_event_id: Optional[str] = None
    evidence_canary: Optional[str] = None

# Chat
class ChatMessageRequest(BaseModel):
    session_id: Optional[str] = "default-session"
    message: str

class ChatMessageResponse(BaseModel):
    role: str
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# Dashboard
class DashboardMetricsResponse(BaseModel):
    total_evaluations: int
    passed_evaluations: int
    failed_evaluations: int
    inconclusive_evaluations: int
    prompt_injection_findings: int
    potential_leakage_events: int
    cross_team_violations: int
    files_scanned: int
    files_quarantined: int
    audit_chain_verified: bool
    audit_total_events: int
    risk_distribution: Dict[str, int]
    evaluation_trends: List[Dict[str, Any]]
    recent_events: List[AuditEventResponse]
