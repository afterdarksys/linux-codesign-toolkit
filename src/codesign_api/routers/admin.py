"""
Admin routes for user and certificate management.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import json
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..auth import create_api_user, generate_api_key, get_password_hash
from ..database import get_database, APIUser, CertificateStore, AuditLog
from ..models import (
    CreateUserRequest, CreateUserResponse, UserInfo,
    CertificateInfo, SuccessResponse
)
from ..config import settings

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

# Simple admin authentication - in production, this should be more secure
ADMIN_API_KEY = settings.secret_key  # Change this to a proper admin key

async def verify_admin_key(admin_key: str) -> bool:
    """Verify admin API key."""
    if not admin_key or admin_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin key"
        )
    return True

@router.post("/users", response_model=CreateUserResponse)
async def create_user(
    user_request: CreateUserRequest,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Create a new API user."""

    # Generate API key
    api_key = generate_api_key()

    try:
        # Create user
        user = await create_api_user(
            db=db,
            user_id=user_request.user_id,
            api_key=api_key,
            name=user_request.name,
            email=user_request.email,
            allowed_signing_types=user_request.allowed_signing_types,
            max_operations_per_day=user_request.max_operations_per_day
        )

        return CreateUserResponse(
            user_id=user.user_id,
            api_key=api_key,
            name=user.name,
            email=user.email,
            allowed_signing_types=user.allowed_signing_types,
            max_operations_per_day=user.max_operations_per_day,
            created_at=user.created_at
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

@router.get("/users", response_model=List[UserInfo])
async def list_users(
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """List all API users."""

    result = await db.execute(select(APIUser).order_by(APIUser.created_at.desc()))
    users = result.scalars().all()

    return [
        UserInfo(
            user_id=user.user_id,
            name=user.name,
            email=user.email,
            allowed_signing_types=user.allowed_signing_types,
            max_operations_per_day=user.max_operations_per_day,
            is_active=user.is_active,
            created_at=user.created_at,
            last_used_at=user.last_used_at
        )
        for user in users
    ]

@router.get("/users/{user_id}", response_model=UserInfo)
async def get_user(
    user_id: str,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Get details of a specific user."""

    result = await db.execute(select(APIUser).where(APIUser.user_id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserInfo(
        user_id=user.user_id,
        name=user.name,
        email=user.email,
        allowed_signing_types=user.allowed_signing_types,
        max_operations_per_day=user.max_operations_per_day,
        is_active=user.is_active,
        created_at=user.created_at,
        last_used_at=user.last_used_at
    )

@router.put("/users/{user_id}/activate", response_model=SuccessResponse)
async def activate_user(
    user_id: str,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Activate a user account."""

    result = await db.execute(select(APIUser).where(APIUser.user_id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = True
    await db.commit()

    return SuccessResponse(message=f"User {user_id} activated successfully")

@router.put("/users/{user_id}/deactivate", response_model=SuccessResponse)
async def deactivate_user(
    user_id: str,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Deactivate a user account."""

    result = await db.execute(select(APIUser).where(APIUser.user_id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await db.commit()

    return SuccessResponse(message=f"User {user_id} deactivated successfully")

@router.delete("/users/{user_id}", response_model=SuccessResponse)
async def delete_user(
    user_id: str,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Delete a user account."""

    result = await db.execute(select(APIUser).where(APIUser.user_id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.delete(user)
    await db.commit()

    return SuccessResponse(message=f"User {user_id} deleted successfully")

@router.get("/certificates", response_model=List[CertificateInfo])
async def list_certificates(
    signing_type: Optional[str] = None,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """List all certificates in the certificate store."""

    query = select(CertificateStore).where(CertificateStore.is_active == True)

    if signing_type:
        query = query.where(CertificateStore.signing_type == signing_type)

    result = await db.execute(query.order_by(CertificateStore.created_at.desc()))
    certificates = result.scalars().all()

    return [
        CertificateInfo(
            key_id=cert.key_id,
            name=cert.name,
            signing_type=cert.signing_type,
            description=cert.description,
            issuer=cert.issuer,
            subject=cert.subject,
            valid_from=cert.valid_from,
            valid_until=cert.valid_until,
            is_active=cert.is_active,
            created_at=cert.created_at
        )
        for cert in certificates
    ]

@router.get("/audit-log")
async def get_audit_log(
    limit: int = 100,
    offset: int = 0,
    user_id: Optional[str] = None,
    operation: Optional[str] = None,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Get audit log entries."""

    if limit > 1000:
        limit = 1000

    query = select(AuditLog)

    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if operation:
        query = query.where(AuditLog.operation == operation)

    query = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    entries = result.scalars().all()

    return [
        {
            "id": entry.id,
            "operation": entry.operation,
            "user_id": entry.user_id,
            "ip_address": entry.ip_address,
            "endpoint": entry.endpoint,
            "method": entry.method,
            "request_id": entry.request_id,
            "status_code": entry.status_code,
            "response_time_ms": entry.response_time_ms,
            "details": json.loads(entry.details) if entry.details else None,
            "timestamp": entry.timestamp
        }
        for entry in entries
    ]