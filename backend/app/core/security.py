from datetime import datetime, timedelta
from typing import Optional, List
import jwt
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import settings
from app.core.database import get_db
from app.models.models import User, UserRole
from app.core.audit import record_audit_event

security_scheme = HTTPBearer(auto_error=False)

def get_password_hash(password: str) -> str:
    """Hashes a plaintext password using bcrypt with random salt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    """Safely verifies a plaintext password against a stored bcrypt hash."""
    if not hashed_password or not plain_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

async def get_current_user(
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Extracts and verifies user from Bearer token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not auth_header or not auth_header.credentials:
        raise credentials_exception

    payload = decode_access_token(auth_header.credentials)
    if not payload:
        raise credentials_exception

    email: Optional[str] = payload.get("sub")
    if not email:
        raise credentials_exception

    stmt = select(User).where(User.email == email)
    res = await db.execute(stmt)
    user = res.scalars().first()

    if not user:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is suspended or deactivated.")

    return user

def require_roles(allowed_roles: List[UserRole]):
    """Enforces server-side RBAC on endpoints and logs unauthorized violations to audit trail."""
    async def role_checker(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        if current_user.role not in allowed_roles and current_user.role != UserRole.ADMIN:
            # Record unauthorized access violation into immutable audit trail
            await record_audit_event(
                db=db,
                actor_id=str(current_user.id),
                actor_role=current_user.role.value,
                action="UNAUTHORIZED_ENDPOINT_ACCESS_ATTEMPT",
                resource_type="RBAC_PROTECTED_ENDPOINT",
                resource_id="API_ROUTE",
                team_context=current_user.role.value,
                outcome="DENIED",
                details={
                    "user_email": current_user.email,
                    "attempted_role": current_user.role.value,
                    "required_roles": [r.value for r in allowed_roles]
                }
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Team/Role '{current_user.role.value}' is not authorized for this resource."
            )
        return current_user
    return role_checker
