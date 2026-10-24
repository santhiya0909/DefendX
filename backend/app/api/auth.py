import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, get_current_user, get_password_hash, verify_password
from app.core.audit import record_audit_event
from app.models.models import User, UserRole, AccountStatus
from app.schemas.schemas import (
    TokenResponse, UserResponse, DevLoginRequest, GoogleAuthRequest,
    RegisterRequest, LoginRequest, ForgotPasswordRequest, ResetPasswordRequest,
    AuthMessageResponse
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.get("/config")
async def get_auth_config():
    """Returns public authentication capabilities and status."""
    return {
        "google_oauth_configured": bool(settings.GOOGLE_CLIENT_ID),
        "google_client_id_configured": bool(settings.GOOGLE_CLIENT_ID),
        "dev_auth_enabled": bool(settings.DEV_AUTH_ENABLED and settings.ENVIRONMENT != "production"),
        "environment": settings.ENVIRONMENT
    }

@router.post("/register", response_model=TokenResponse)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    User registration endpoint.
    Enforces password hashing, email uniqueness, terms acceptance, and role selection restrictions.
    Security Rule: Public registration CANNOT grant ADMIN or AUDITOR roles.
    """
    if not req.terms_accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must accept the Terms of Service and Privacy Policy to register."
        )

    # Server-side validation: Role escalation prevention
    if req.role in [UserRole.ADMIN, UserRole.AUDITOR]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration cannot self-assign Administrator or Auditor roles. Only Red Team or Blue Team can be selected."
        )

    clean_email = req.email.lower().strip()

    # Check for duplicate email
    stmt = select(User).where(User.email == clean_email)
    res = await db.execute(stmt)
    if res.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists. Please sign in instead."
        )

    # Password complexity check (minimum 8 chars, at least one letter and one number)
    if len(req.password) < 8 or not any(c.isalpha() for c in req.password) or not any(c.isdigit() for c in req.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long and contain both letters and numbers."
        )

    hashed_pw = get_password_hash(req.password)

    new_user = User(
        email=clean_email,
        full_name=req.full_name.strip(),
        role=req.role,
        hashed_password=hashed_pw,
        is_active=True,
        status=AccountStatus.ACTIVE,
        auth_provider="local",
        last_login_at=datetime.utcnow()
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Audit logging
    await record_audit_event(
        db=db,
        actor_id=str(new_user.id),
        actor_role=new_user.role.value,
        action="USER_REGISTRATION_SUCCESS",
        resource_type="ACCOUNT",
        resource_id=str(new_user.id),
        team_context=new_user.role.value,
        outcome="SUCCESS",
        details={"email": clean_email, "role": new_user.role.value, "auth_provider": "local"}
    )

    access_token = create_access_token(data={"sub": new_user.email, "role": new_user.role.value, "user_id": new_user.id})
    return TokenResponse(access_token=access_token, user=UserResponse.model_validate(new_user))

@router.post("/login-password", response_model=TokenResponse)
async def login_password(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Standard email and password login endpoint.
    Verifies salted bcrypt password hash, account active state, and issues JWT access token.
    """
    clean_email = req.email.lower().strip()

    stmt = select(User).where(User.email == clean_email)
    res = await db.execute(stmt)
    user = res.scalars().first()

    if not user:
        await record_audit_event(
            db=db,
            actor_id="anonymous",
            actor_role="ANONYMOUS",
            action="USER_LOGIN_FAILED",
            resource_type="SESSION",
            resource_id="auth",
            team_context="NONE",
            outcome="FAILURE",
            details={"email": clean_email, "reason": "USER_NOT_FOUND"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active or user.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended or deactivated. Contact platform administrator."
        )

    if not user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This account was registered via Google Sign-In or another provider. Please sign in with Google or use password recovery."
        )

    if not verify_password(req.password, user.hashed_password):
        await record_audit_event(
            db=db,
            actor_id=str(user.id),
            actor_role=user.role.value,
            action="USER_LOGIN_FAILED",
            resource_type="SESSION",
            resource_id=str(user.id),
            team_context=user.role.value,
            outcome="FAILURE",
            details={"email": clean_email, "reason": "INVALID_PASSWORD"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    user.last_login_at = datetime.utcnow()
    await db.commit()
    await db.refresh(user)

    await record_audit_event(
        db=db,
        actor_id=str(user.id),
        actor_role=user.role.value,
        action="USER_LOGIN_SUCCESS",
        resource_type="SESSION",
        resource_id=str(user.id),
        team_context=user.role.value,
        outcome="SUCCESS",
        details={"auth_provider": "local", "email": user.email}
    )

    access_token = create_access_token(data={"sub": user.email, "role": user.role.value, "user_id": user.id})
    return TokenResponse(access_token=access_token, user=UserResponse.model_validate(user))

@router.post("/forgot-password", response_model=AuthMessageResponse)
async def forgot_password(req: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    """
    Initiates secure password recovery.
    Generates a cryptographically strong reset token valid for 1 hour.
    """
    clean_email = req.email.lower().strip()
    stmt = select(User).where(User.email == clean_email)
    res = await db.execute(stmt)
    user = res.scalars().first()

    reset_token = None
    if user and user.is_active:
        reset_token = secrets.token_urlsafe(32)
        user.reset_token = reset_token
        user.reset_token_expires_at = datetime.utcnow() + timedelta(hours=1)
        await db.commit()

        await record_audit_event(
            db=db,
            actor_id=str(user.id),
            actor_role=user.role.value,
            action="PASSWORD_RESET_REQUESTED",
            resource_type="ACCOUNT",
            resource_id=str(user.id),
            team_context=user.role.value,
            outcome="SUCCESS",
            details={"email": clean_email}
        )

    # In dev/testing mode, return the token directly so automated tests and local users can reset without SMTP
    return AuthMessageResponse(
        message="If an account with that email address exists, a secure password recovery token has been issued.",
        reset_token=reset_token if (settings.ENVIRONMENT != "production" or settings.DEV_AUTH_ENABLED) else None
    )

@router.post("/reset-password", response_model=AuthMessageResponse)
async def reset_password(req: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    """
    Applies a new password using a verified recovery token.
    """
    if not req.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing password reset token."
        )

    if len(req.new_password) < 8 or not any(c.isalpha() for c in req.new_password) or not any(c.isdigit() for c in req.new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long and contain both letters and numbers."
        )

    stmt = select(User).where(User.reset_token == req.token)
    res = await db.execute(stmt)
    user = res.scalars().first()

    if not user or not user.reset_token_expires_at or user.reset_token_expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token. Please request a new recovery link."
        )

    user.hashed_password = get_password_hash(req.new_password)
    user.reset_token = None
    user.reset_token_expires_at = None
    await db.commit()

    await record_audit_event(
        db=db,
        actor_id=str(user.id),
        actor_role=user.role.value,
        action="PASSWORD_RESET_SUCCESS",
        resource_type="ACCOUNT",
        resource_id=str(user.id),
        team_context=user.role.value,
        outcome="SUCCESS",
        details={"email": user.email}
    )

    return AuthMessageResponse(message="Password successfully reset. You can now log in with your new credentials.")

@router.post("/login", response_model=TokenResponse)
async def dev_login(req: DevLoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Development & Testing identity launcher endpoint.
    Strictly blocked in production environments or when DEV_AUTH_ENABLED is False.
    """
    if settings.ENVIRONMENT == "production" or not settings.DEV_AUTH_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development login is strictly disabled in production environment."
        )

    # Lookup or create user
    stmt = select(User).where(User.email == req.email)
    res = await db.execute(stmt)
    user = res.scalars().first()

    if not user:
        user = User(
            email=req.email,
            full_name=req.full_name or req.email.split("@")[0].title(),
            role=req.role,
            is_active=True,
            status=AccountStatus.ACTIVE,
            auth_provider="dev_mode",
            last_login_at=datetime.utcnow()
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        user.role = req.role  # Allow switching roles for testing in dev mode
        user.last_login_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)

    # Record Audit Event
    await record_audit_event(
        db=db,
        actor_id=str(user.id),
        actor_role=user.role.value,
        action="USER_LOGIN_SUCCESS",
        resource_type="SESSION",
        resource_id=str(user.id),
        team_context=user.role.value,
        outcome="SUCCESS",
        details={"auth_provider": "dev_mode", "email": user.email}
    )

    access_token = create_access_token(data={"sub": user.email, "role": user.role.value, "user_id": user.id})
    return TokenResponse(access_token=access_token, user=UserResponse.model_validate(user))

@router.post("/google", response_model=TokenResponse)
async def google_login(req: GoogleAuthRequest, db: AsyncSession = Depends(get_db)):
    """
    Google OAuth 2.0 / OpenID Connect token verification endpoint.
    Uses official google-auth library to verify cryptographic signature, audience,
    issuer, expiry, and email verification status.
    """
    if not req.credential:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Google OAuth credential token."
        )

    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Google OAuth is not configured on this server. "
                "Please configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in backend environment variables, "
                "or use the Development Login mode."
            )
        )

    # Cryptographically verify the Google ID token
    try:
        id_info = google_id_token.verify_oauth2_token(
            req.credential,
            google_requests.Request(),
            audience=settings.GOOGLE_CLIENT_ID
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Google token verification failed: {str(ve)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to validate Google credential: {str(e)}"
        )

    # Verify issuer
    if id_info.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Untrusted Google token issuer."
        )

    # Verify audience strictly matches configured GOOGLE_CLIENT_ID
    if id_info.get("aud") != settings.GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token audience mismatch."
        )

    # Verify email is verified by Google
    email_verified = id_info.get("email_verified")
    if not email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unverified Google email address. Only verified Google accounts are permitted."
        )

    user_email = id_info.get("email")
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google token payload missing email attribute."
        )

    user_name = id_info.get("name") or user_email.split("@")[0].title()
    user_picture = id_info.get("picture", "")

    # Check or create user in database
    stmt = select(User).where(User.email == user_email)
    res = await db.execute(stmt)
    user = res.scalars().first()

    if not user:
        # Principle of Least Privilege: New Google users are ALWAYS assigned
        # default non-privileged role (RED_TEAM). Privileged roles (ADMIN) can
        # only be assigned by existing administrators in User Management.
        user = User(
            email=user_email,
            full_name=user_name,
            picture_url=user_picture,
            role=UserRole.RED_TEAM,
            is_active=True,
            status=AccountStatus.ACTIVE,
            auth_provider="google",
            last_login_at=datetime.utcnow()
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        # Existing user: preserve assigned role (NO role escalation)
        user.last_login_at = datetime.utcnow()
        if user_picture:
            user.picture_url = user_picture
        await db.commit()
        await db.refresh(user)

    await record_audit_event(
        db=db,
        actor_id=str(user.id),
        actor_role=user.role.value,
        action="GOOGLE_OAUTH_LOGIN_SUCCESS",
        resource_type="SESSION",
        resource_id=str(user.id),
        team_context=user.role.value,
        outcome="SUCCESS",
        details={"auth_provider": "google", "email": user.email, "assigned_role": user.role.value}
    )

    access_token = create_access_token(data={"sub": user.email, "role": user.role.value, "user_id": user.id})
    return TokenResponse(access_token=access_token, user=UserResponse.model_validate(user))

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns currently authenticated user profile."""
    return UserResponse.model_validate(current_user)

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Logs out user and records session termination event in audit log."""
    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="USER_LOGOUT",
        resource_type="SESSION",
        resource_id=str(current_user.id),
        team_context=current_user.role.value,
        outcome="SUCCESS"
    )
    return {"message": "Session successfully terminated."}
