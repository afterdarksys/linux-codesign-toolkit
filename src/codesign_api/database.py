"""
Database models and configuration for the Code Signing API.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.sql import func
from datetime import datetime
from typing import AsyncGenerator
import os

Base = declarative_base()

class SigningOperation(Base):
    """Table to track all signing operations and their metadata."""
    __tablename__ = "signing_operations"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Core operation data
    operation_type = Column(String(20), nullable=False)  # sign, verify, unsign, resign
    signing_type = Column(String(20), nullable=False)    # windows, java, air, apple
    status = Column(String(20), nullable=False, default="pending")  # pending, processing, completed, failed

    # File information
    original_filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA-256 hash
    file_size = Column(Integer, nullable=False)
    path_to_file_on_disk = Column(String(500), nullable=False)

    # Signed file information (for sign/resign operations)
    signed_filename = Column(String(255), nullable=True)
    signed_file_hash = Column(String(64), nullable=True)
    signed_path_on_disk = Column(String(500), nullable=True)

    # Download links
    download_link = Column(String(500), nullable=True)
    signed_download_link = Column(String(500), nullable=True)

    # Metadata
    key_id = Column(String(100), nullable=True)  # ID of the key/cert used
    timestamp_url = Column(String(255), nullable=True)
    who_signed_the_file = Column(String(100), nullable=False)  # API user ID

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    completed_at = Column(DateTime, nullable=True)

    # Additional metadata as JSON
    metadata = Column(Text, nullable=True)  # JSON string for additional data
    error_message = Column(Text, nullable=True)

class APIUser(Base):
    """Table to store API users and their authentication information."""
    __tablename__ = "api_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), unique=True, nullable=False)
    api_key_hash = Column(String(255), nullable=False)  # Hashed API key

    # User metadata
    name = Column(String(100), nullable=True)
    email = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Permissions
    allowed_signing_types = Column(String(255), nullable=False, default="windows,java,air,apple")
    max_operations_per_day = Column(Integer, default=1000, nullable=False)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=func.now())
    last_used_at = Column(DateTime, nullable=True)

class CertificateStore(Base):
    """Table to store certificates and keys for signing operations."""
    __tablename__ = "certificate_store"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(String(100), unique=True, nullable=False)

    # Certificate metadata
    name = Column(String(100), nullable=False)
    signing_type = Column(String(20), nullable=False)  # windows, java, air, apple
    description = Column(Text, nullable=True)

    # Certificate data (encrypted)
    certificate_data = Column(LargeBinary, nullable=True)
    private_key_data = Column(LargeBinary, nullable=True)
    keystore_data = Column(LargeBinary, nullable=True)  # For Java keystores

    # Certificate paths (if stored on filesystem)
    certificate_path = Column(String(500), nullable=True)
    private_key_path = Column(String(500), nullable=True)
    keystore_path = Column(String(500), nullable=True)

    # Security
    is_encrypted = Column(Boolean, default=True, nullable=False)
    password_hash = Column(String(255), nullable=True)  # For keystores/p12 files

    # Metadata
    issuer = Column(String(255), nullable=True)
    subject = Column(String(255), nullable=True)
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True, nullable=False)

class AuditLog(Base):
    """Table to track all API operations for auditing and compliance."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Operation details
    operation = Column(String(50), nullable=False)
    user_id = Column(String(50), nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible

    # Request details
    endpoint = Column(String(100), nullable=False)
    method = Column(String(10), nullable=False)
    request_id = Column(String(100), nullable=True)

    # Response details
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)

    # Additional data
    details = Column(Text, nullable=True)  # JSON string for additional data

    # Timestamp
    timestamp = Column(DateTime, nullable=False, default=func.now())

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./codesign_api.db")

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL debugging
    future=True,
)

# Create async session maker
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def create_tables():
    """Create all database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_database() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()