"""
Pydantic models for request/response validation.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class SigningType(str, Enum):
    """Supported signing types."""
    WINDOWS = "windows"
    JAVA = "java"
    AIR = "air"
    APPLE = "apple"

class OperationType(str, Enum):
    """Supported operation types."""
    SIGN = "sign"
    VERIFY = "verify"
    UNSIGN = "unsign"
    RESIGN = "resign"

class OperationStatus(str, Enum):
    """Operation status values."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

# Request Models
class SignRequest(BaseModel):
    """Request model for signing operations."""
    signing_type: SigningType = Field(..., description="Type of signing to perform")
    key_id: str = Field(..., description="ID of the certificate/key to use for signing")
    timestamp_url: Optional[str] = Field(None, description="URL for timestamping service")
    app_name: Optional[str] = Field(None, description="Application name (for Windows signing)")
    app_url: Optional[str] = Field(None, description="Application URL (for Windows signing)")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class VerifyRequest(BaseModel):
    """Request model for verification operations."""
    signing_type: SigningType = Field(..., description="Type of signing to verify")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class UnsignRequest(BaseModel):
    """Request model for unsigning operations."""
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

class ResignRequest(BaseModel):
    """Request model for resigning operations."""
    signing_type: SigningType = Field(..., description="Type of signing to perform")
    key_id: str = Field(..., description="ID of the certificate/key to use for resigning")
    timestamp_url: Optional[str] = Field(None, description="URL for timestamping service")
    app_name: Optional[str] = Field(None, description="Application name (for Windows signing)")
    app_url: Optional[str] = Field(None, description="Application URL (for Windows signing)")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

# Response Models
class OperationResponse(BaseModel):
    """Response model for signing operations."""
    operation_id: int = Field(..., description="Unique operation ID")
    operation_type: OperationType = Field(..., description="Type of operation")
    signing_type: SigningType = Field(..., description="Type of signing performed")
    status: OperationStatus = Field(..., description="Current status of the operation")
    original_filename: str = Field(..., description="Original filename")
    file_hash: str = Field(..., description="SHA-256 hash of the original file")
    signed_filename: Optional[str] = Field(None, description="Filename of signed file")
    signed_file_hash: Optional[str] = Field(None, description="SHA-256 hash of signed file")
    download_link: Optional[str] = Field(None, description="Download link for original file")
    signed_download_link: Optional[str] = Field(None, description="Download link for signed file")
    key_id: Optional[str] = Field(None, description="ID of certificate/key used")
    who_signed_the_file: str = Field(..., description="User who performed the operation")
    created_at: datetime = Field(..., description="Operation creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Operation completion timestamp")
    error_message: Optional[str] = Field(None, description="Error message if operation failed")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

    class Config:
        from_attributes = True

class OperationStatus(BaseModel):
    """Response model for operation status queries."""
    operation_id: int = Field(..., description="Unique operation ID")
    status: OperationStatus = Field(..., description="Current status of the operation")
    progress: Optional[str] = Field(None, description="Progress description")
    error_message: Optional[str] = Field(None, description="Error message if operation failed")
    updated_at: datetime = Field(..., description="Last update timestamp")

class ListOperationsResponse(BaseModel):
    """Response model for listing operations."""
    operations: List[OperationResponse] = Field(..., description="List of operations")
    total: int = Field(..., description="Total number of operations")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")

# User Management Models
class CreateUserRequest(BaseModel):
    """Request model for creating API users."""
    user_id: str = Field(..., description="Unique user identifier", min_length=3, max_length=50)
    name: Optional[str] = Field(None, description="User's full name", max_length=100)
    email: Optional[str] = Field(None, description="User's email address", max_length=255)
    allowed_signing_types: str = Field(
        "windows,java,air,apple",
        description="Comma-separated list of allowed signing types"
    )
    max_operations_per_day: int = Field(1000, description="Maximum operations per day", ge=1)

    @validator('user_id')
    def validate_user_id(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('User ID must contain only alphanumeric characters, hyphens, and underscores')
        return v

    @validator('allowed_signing_types')
    def validate_signing_types(cls, v):
        valid_types = {'windows', 'java', 'air', 'apple'}
        types = [t.strip().lower() for t in v.split(',')]
        invalid_types = set(types) - valid_types
        if invalid_types:
            raise ValueError(f'Invalid signing types: {invalid_types}')
        return ','.join(types)

class CreateUserResponse(BaseModel):
    """Response model for user creation."""
    user_id: str = Field(..., description="Unique user identifier")
    api_key: str = Field(..., description="Generated API key")
    name: Optional[str] = Field(None, description="User's full name")
    email: Optional[str] = Field(None, description="User's email address")
    allowed_signing_types: str = Field(..., description="Allowed signing types")
    max_operations_per_day: int = Field(..., description="Maximum operations per day")
    created_at: datetime = Field(..., description="User creation timestamp")

class UserInfo(BaseModel):
    """Response model for user information."""
    user_id: str = Field(..., description="Unique user identifier")
    name: Optional[str] = Field(None, description="User's full name")
    email: Optional[str] = Field(None, description="User's email address")
    allowed_signing_types: str = Field(..., description="Allowed signing types")
    max_operations_per_day: int = Field(..., description="Maximum operations per day")
    is_active: bool = Field(..., description="Whether the user account is active")
    created_at: datetime = Field(..., description="User creation timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last API usage timestamp")

    class Config:
        from_attributes = True

# Certificate Management Models
class CertificateInfo(BaseModel):
    """Response model for certificate information."""
    key_id: str = Field(..., description="Certificate key ID")
    name: str = Field(..., description="Certificate name")
    signing_type: SigningType = Field(..., description="Supported signing type")
    description: Optional[str] = Field(None, description="Certificate description")
    issuer: Optional[str] = Field(None, description="Certificate issuer")
    subject: Optional[str] = Field(None, description="Certificate subject")
    valid_from: Optional[datetime] = Field(None, description="Certificate validity start")
    valid_until: Optional[datetime] = Field(None, description="Certificate validity end")
    is_active: bool = Field(..., description="Whether the certificate is active")
    created_at: datetime = Field(..., description="Certificate creation timestamp")

    class Config:
        from_attributes = True

# General Response Models
class ErrorResponse(BaseModel):
    """Standard error response model."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")

class SuccessResponse(BaseModel):
    """Standard success response model."""
    success: bool = Field(True, description="Operation success status")
    message: str = Field(..., description="Success message")
    data: Optional[Dict[str, Any]] = Field(None, description="Additional response data")

class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    timestamp: datetime = Field(..., description="Current timestamp")
    database_status: str = Field(..., description="Database connection status")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")