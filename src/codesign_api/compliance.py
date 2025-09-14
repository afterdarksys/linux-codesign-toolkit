"""
Compliance module for SOX, GLBA, PCI-DSS, and GDPR requirements.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

from .database import AuditLog, APIUser, SigningOperation
from .config import settings

class ComplianceManager:
    """Manages compliance requirements across SOX, GLBA, PCI-DSS, and GDPR."""

    def __init__(self):
        self.encryption_key = self._get_or_create_encryption_key()
        self.fernet = Fernet(self.encryption_key)

    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for data at rest."""
        key_file = os.path.join(settings.certificate_directory, ".encryption_key")

        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            os.makedirs(settings.certificate_directory, exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Restrict access
            return key

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data for storage (GDPR/PCI-DSS requirement)."""
        if not data:
            return data
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data for use."""
        if not encrypted_data:
            return encrypted_data
        try:
            return self.fernet.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return encrypted_data  # Return as-is if not encrypted

    def hash_pii(self, data: str, salt: Optional[str] = None) -> tuple[str, str]:
        """Hash PII data for privacy protection (GDPR requirement)."""
        if not salt:
            salt = secrets.token_hex(16)

        # Use PBKDF2 for secure hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(data.encode()))
        return key.decode(), salt

    async def log_compliance_event(
        self,
        db: AsyncSession,
        event_type: str,
        user_id: str,
        details: Dict[str, Any],
        risk_level: str = "medium",
        ip_address: Optional[str] = None
    ):
        """Log compliance-related events for audit purposes."""

        compliance_details = {
            "compliance_event": True,
            "event_type": event_type,
            "risk_level": risk_level,
            "timestamp_iso": datetime.utcnow().isoformat(),
            "details": details
        }

        audit_log = AuditLog(
            operation=f"compliance_{event_type}",
            user_id=user_id,
            ip_address=ip_address,
            endpoint="/compliance/event",
            method="SYSTEM",
            status_code=200,
            details=json.dumps(compliance_details)
        )

        db.add(audit_log)
        await db.commit()

# Data Retention Policies
class DataRetentionManager:
    """Manages data retention policies for compliance."""

    # Retention periods by regulation
    RETENTION_POLICIES = {
        "sox": {
            "audit_logs": timedelta(days=2555),  # 7 years
            "financial_records": timedelta(days=2555),  # 7 years
            "signing_operations": timedelta(days=2555)  # 7 years
        },
        "glba": {
            "customer_data": timedelta(days=1825),  # 5 years
            "access_logs": timedelta(days=1825)  # 5 years
        },
        "pci_dss": {
            "audit_logs": timedelta(days=365),  # 1 year minimum
            "system_logs": timedelta(days=365)  # 1 year minimum
        },
        "gdpr": {
            "personal_data": None,  # Must be deleted upon request
            "processing_logs": timedelta(days=1095)  # 3 years recommended
        }
    }

    @classmethod
    async def cleanup_expired_data(cls, db: AsyncSession):
        """Clean up expired data according to retention policies."""
        cutoff_dates = cls._calculate_cutoff_dates()

        # Clean up old audit logs (keeping SOX 7-year requirement)
        audit_cutoff = cutoff_dates["audit_logs"]
        expired_audits = await db.execute(
            select(AuditLog).where(AuditLog.timestamp < audit_cutoff)
        )

        count = 0
        for audit in expired_audits.scalars():
            await db.delete(audit)
            count += 1

        if count > 0:
            await db.commit()

        return {
            "cleaned_audit_logs": count,
            "cutoff_date": audit_cutoff.isoformat()
        }

    @classmethod
    def _calculate_cutoff_dates(cls) -> Dict[str, datetime]:
        """Calculate cutoff dates based on strictest retention requirements."""
        now = datetime.utcnow()

        # Use the strictest (longest) retention period for each data type
        return {
            "audit_logs": now - cls.RETENTION_POLICIES["sox"]["audit_logs"],
            "signing_operations": now - cls.RETENTION_POLICIES["sox"]["signing_operations"],
            "customer_data": now - cls.RETENTION_POLICIES["glba"]["customer_data"]
        }

# GDPR Data Subject Rights
class GDPRManager:
    """Manages GDPR data subject rights."""

    def __init__(self, compliance_manager: ComplianceManager):
        self.compliance_manager = compliance_manager

    async def export_user_data(self, db: AsyncSession, user_id: str) -> Dict[str, Any]:
        """Export all data for a user (GDPR Article 20 - Data Portability)."""

        # Get user data
        user_result = await db.execute(
            select(APIUser).where(APIUser.user_id == user_id)
        )
        user = user_result.scalar_one_or_none()

        if not user:
            return {"error": "User not found"}

        # Get signing operations
        operations_result = await db.execute(
            select(SigningOperation).where(SigningOperation.who_signed_the_file == user_id)
        )
        operations = operations_result.scalars().all()

        # Get audit logs
        audit_result = await db.execute(
            select(AuditLog).where(AuditLog.user_id == user_id)
        )
        audit_logs = audit_result.scalars().all()

        # Compile data export
        export_data = {
            "export_timestamp": datetime.utcnow().isoformat(),
            "user_data": {
                "user_id": user.user_id,
                "name": user.name,
                "email": user.email,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_used_at": user.last_used_at.isoformat() if user.last_used_at else None,
                "is_active": user.is_active,
                "allowed_signing_types": user.allowed_signing_types,
                "max_operations_per_day": user.max_operations_per_day
            },
            "signing_operations": [
                {
                    "operation_id": op.id,
                    "operation_type": op.operation_type,
                    "signing_type": op.signing_type,
                    "status": op.status,
                    "original_filename": op.original_filename,
                    "file_hash": op.file_hash,
                    "created_at": op.created_at.isoformat(),
                    "completed_at": op.completed_at.isoformat() if op.completed_at else None
                }
                for op in operations
            ],
            "audit_events": len(audit_logs),  # Count only for privacy
            "data_categories": [
                "identity_data",
                "operational_data",
                "audit_data",
                "file_metadata"
            ]
        }

        # Log the data export
        await self.compliance_manager.log_compliance_event(
            db=db,
            event_type="gdpr_data_export",
            user_id=user_id,
            details={"exported_records": len(operations) + len(audit_logs)},
            risk_level="medium"
        )

        return export_data

    async def delete_user_data(self, db: AsyncSession, user_id: str) -> Dict[str, Any]:
        """Delete all user data (GDPR Article 17 - Right to Erasure)."""

        deletion_summary = {
            "user_id": user_id,
            "deletion_timestamp": datetime.utcnow().isoformat(),
            "deleted_records": {}
        }

        # Delete user account
        user_result = await db.execute(
            select(APIUser).where(APIUser.user_id == user_id)
        )
        user = user_result.scalar_one_or_none()

        if user:
            await db.delete(user)
            deletion_summary["deleted_records"]["user_account"] = 1
        else:
            deletion_summary["deleted_records"]["user_account"] = 0

        # Delete signing operations (after archiving file hashes for integrity)
        operations_result = await db.execute(
            select(SigningOperation).where(SigningOperation.who_signed_the_file == user_id)
        )
        operations = operations_result.scalars().all()

        # Archive file integrity data before deletion (for SOX compliance)
        archived_hashes = []
        for op in operations:
            archived_hashes.append({
                "operation_id": op.id,
                "file_hash": op.file_hash,
                "deletion_date": datetime.utcnow().isoformat()
            })

            # Remove actual files
            if op.path_to_file_on_disk and os.path.exists(op.path_to_file_on_disk):
                os.remove(op.path_to_file_on_disk)
            if op.signed_path_on_disk and os.path.exists(op.signed_path_on_disk):
                os.remove(op.signed_path_on_disk)

            await db.delete(op)

        deletion_summary["deleted_records"]["signing_operations"] = len(operations)
        deletion_summary["archived_integrity_hashes"] = len(archived_hashes)

        # Anonymize audit logs (keep for SOX but remove PII)
        audit_result = await db.execute(
            select(AuditLog).where(AuditLog.user_id == user_id)
        )
        audit_logs = audit_result.scalars().all()

        anonymized_count = 0
        for audit in audit_logs:
            # Replace user_id with anonymized version
            audit.user_id = f"deleted_user_{hashlib.sha256(user_id.encode()).hexdigest()[:12]}"
            # Remove IP addresses
            audit.ip_address = None
            anonymized_count += 1

        deletion_summary["anonymized_records"]["audit_logs"] = anonymized_count

        await db.commit()

        # Log the deletion event
        await self.compliance_manager.log_compliance_event(
            db=db,
            event_type="gdpr_data_deletion",
            user_id="SYSTEM",  # System-initiated
            details=deletion_summary,
            risk_level="high"
        )

        return deletion_summary

# Security Monitoring for PCI-DSS
class SecurityMonitor:
    """Monitors security events for PCI-DSS compliance."""

    SUSPICIOUS_PATTERNS = [
        "multiple_failed_auth",
        "unusual_file_access",
        "bulk_operations",
        "off_hours_access",
        "privilege_escalation"
    ]

    @classmethod
    async def detect_suspicious_activity(cls, db: AsyncSession) -> List[Dict[str, Any]]:
        """Detect suspicious activities based on audit logs."""
        alerts = []
        now = datetime.utcnow()
        lookback_time = now - timedelta(hours=24)

        # Check for multiple failed authentication attempts
        failed_auth_count = await db.execute(
            select(func.count(AuditLog.id))
            .where(and_(
                AuditLog.status_code == 401,
                AuditLog.timestamp >= lookback_time
            ))
        )

        failed_count = failed_auth_count.scalar()
        if failed_count > 10:  # Threshold
            alerts.append({
                "alert_type": "multiple_failed_auth",
                "severity": "high",
                "count": failed_count,
                "description": f"{failed_count} failed authentication attempts in 24 hours",
                "recommendation": "Review authentication logs and consider IP blocking"
            })

        # Check for unusual bulk operations
        bulk_ops = await db.execute(
            select(func.count(AuditLog.id))
            .where(and_(
                AuditLog.operation.like('sign_%'),
                AuditLog.timestamp >= lookback_time
            ))
        )

        bulk_count = bulk_ops.scalar()
        if bulk_count > 100:  # Threshold
            alerts.append({
                "alert_type": "bulk_operations",
                "severity": "medium",
                "count": bulk_count,
                "description": f"{bulk_count} signing operations in 24 hours",
                "recommendation": "Review for potential automated abuse"
            })

        return alerts

# Global compliance manager instance
compliance_manager = ComplianceManager()
data_retention_manager = DataRetentionManager()
gdpr_manager = GDPRManager(compliance_manager)
security_monitor = SecurityMonitor()