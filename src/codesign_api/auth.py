"""
Authentication and authorization for the Code Signing API.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .database import get_database, APIUser, AuditLog
from .config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# API Key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

class AuthenticationError(Exception):
    """Custom authentication error."""
    pass

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError:
        raise AuthenticationError("Invalid token")

async def get_user_by_api_key(db: AsyncSession, api_key: str) -> Optional[APIUser]:
    """Get user by API key."""
    # Hash the provided API key to compare with stored hash
    result = await db.execute(select(APIUser).where(APIUser.is_active == True))
    users = result.scalars().all()

    for user in users:
        if verify_password(api_key, user.api_key_hash):
            # Update last used timestamp
            user.last_used_at = datetime.utcnow()
            await db.commit()
            return user

    return None

async def create_api_user(
    db: AsyncSession,
    user_id: str,
    api_key: str,
    name: Optional[str] = None,
    email: Optional[str] = None,
    allowed_signing_types: str = "windows,java,air,apple",
    max_operations_per_day: int = 1000
) -> APIUser:
    """Create a new API user."""

    # Check if user already exists
    result = await db.execute(select(APIUser).where(APIUser.user_id == user_id))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise ValueError(f"User {user_id} already exists")

    # Create new user
    user = APIUser(
        user_id=user_id,
        api_key_hash=get_password_hash(api_key),
        name=name,
        email=email,
        allowed_signing_types=allowed_signing_types,
        max_operations_per_day=max_operations_per_day,
        is_active=True
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user

async def authenticate_request(
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_database)
) -> APIUser:
    """Authenticate API request using API key."""

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await get_user_by_api_key(db, api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

    return user

async def log_audit_event(
    db: AsyncSession,
    user_id: str,
    operation: str,
    endpoint: str,
    method: str,
    ip_address: Optional[str] = None,
    status_code: Optional[int] = None,
    response_time_ms: Optional[int] = None,
    details: Optional[str] = None,
    request_id: Optional[str] = None
):
    """Log an audit event."""

    audit_log = AuditLog(
        operation=operation,
        user_id=user_id,
        ip_address=ip_address,
        endpoint=endpoint,
        method=method,
        request_id=request_id,
        status_code=status_code,
        response_time_ms=response_time_ms,
        details=details
    )

    db.add(audit_log)
    await db.commit()

def check_signing_permission(user: APIUser, signing_type: str) -> bool:
    """Check if user has permission for the specified signing type."""
    allowed_types = [t.strip() for t in user.allowed_signing_types.split(',')]
    return signing_type.lower() in [t.lower() for t in allowed_types]

def generate_api_key() -> str:
    """Generate a new API key."""
    import secrets
    return secrets.token_urlsafe(32)