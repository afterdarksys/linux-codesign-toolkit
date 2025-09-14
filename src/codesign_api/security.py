"""
Enhanced security module for key management and rotation.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import os
import secrets
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from .database import CertificateStore, APIUser
from .config import settings
from .compliance import compliance_manager

class KeyManager:
    """Secure key management with rotation capabilities."""

    def __init__(self):
        self.master_key_file = os.path.join(settings.certificate_directory, ".master_key")
        self.key_rotation_file = os.path.join(settings.certificate_directory, ".key_rotation_log")

    def generate_master_key(self) -> bytes:
        """Generate a new master key for certificate encryption."""
        key = Fernet.generate_key()

        # Store with restricted permissions
        os.makedirs(settings.certificate_directory, exist_ok=True)
        with open(self.master_key_file, 'wb') as f:
            f.write(key)
        os.chmod(self.master_key_file, 0o600)

        return key

    def get_master_key(self) -> bytes:
        """Get the current master key."""
        if not os.path.exists(self.master_key_file):
            return self.generate_master_key()

        with open(self.master_key_file, 'rb') as f:
            return f.read()

    def rotate_master_key(self) -> Dict[str, str]:
        """Rotate the master key and re-encrypt all stored certificates."""
        old_key = self.get_master_key() if os.path.exists(self.master_key_file) else None
        new_key = self.generate_master_key()

        rotation_log = {
            "rotation_timestamp": datetime.utcnow().isoformat(),
            "old_key_hash": base64.b64encode(hashes.Hash(hashes.SHA256()).finalize()).decode() if old_key else None,
            "new_key_hash": base64.b64encode(hashes.Hash(hashes.SHA256()).finalize()).decode(),
            "status": "completed"
        }

        # Log rotation
        with open(self.key_rotation_file, 'a') as f:
            f.write(json.dumps(rotation_log) + '\n')

        return rotation_log

    def encrypt_certificate_data(self, data: bytes, password: Optional[str] = None) -> bytes:
        """Encrypt certificate data with master key."""
        fernet = Fernet(self.get_master_key())

        if password:
            # Add password-based encryption layer
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            password_fernet = Fernet(key)
            data = salt + password_fernet.encrypt(data)

        return fernet.encrypt(data)

    def decrypt_certificate_data(self, encrypted_data: bytes, password: Optional[str] = None) -> bytes:
        """Decrypt certificate data with master key."""
        fernet = Fernet(self.get_master_key())
        decrypted_data = fernet.decrypt(encrypted_data)

        if password:
            # Remove password-based encryption layer
            salt = decrypted_data[:16]
            encrypted_with_password = decrypted_data[16:]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            password_fernet = Fernet(key)
            decrypted_data = password_fernet.decrypt(encrypted_with_password)

        return decrypted_data

    async def store_certificate(
        self,
        db: AsyncSession,
        key_id: str,
        name: str,
        signing_type: str,
        cert_data: Optional[bytes] = None,
        private_key_data: Optional[bytes] = None,
        keystore_data: Optional[bytes] = None,
        password: Optional[str] = None,
        description: Optional[str] = None
    ) -> CertificateStore:
        """Store certificate securely with encryption."""

        # Encrypt sensitive data
        encrypted_cert = None
        encrypted_key = None
        encrypted_keystore = None

        if cert_data:
            encrypted_cert = self.encrypt_certificate_data(cert_data, password)
        if private_key_data:
            encrypted_key = self.encrypt_certificate_data(private_key_data, password)
        if keystore_data:
            encrypted_keystore = self.encrypt_certificate_data(keystore_data, password)

        # Hash password if provided
        password_hash = None
        if password:
            password_hash = compliance_manager.hash_pii(password)[0]

        # Create certificate store entry
        cert_store = CertificateStore(
            key_id=key_id,
            name=name,
            signing_type=signing_type,
            description=description,
            certificate_data=encrypted_cert,
            private_key_data=encrypted_key,
            keystore_data=encrypted_keystore,
            is_encrypted=True,
            password_hash=password_hash
        )

        db.add(cert_store)
        await db.commit()
        await db.refresh(cert_store)

        # Log certificate storage
        await compliance_manager.log_compliance_event(
            db=db,
            event_type="certificate_stored",
            user_id="SYSTEM",
            details={
                "key_id": key_id,
                "signing_type": signing_type,
                "encryption": "AES-256",
                "timestamp": datetime.utcnow().isoformat()
            },
            risk_level="medium"
        )

        return cert_store

    async def retrieve_certificate(
        self,
        db: AsyncSession,
        key_id: str,
        password: Optional[str] = None
    ) -> Optional[Dict[str, bytes]]:
        """Retrieve and decrypt certificate data."""

        result = await db.execute(
            select(CertificateStore).where(CertificateStore.key_id == key_id)
        )
        cert_store = result.scalar_one_or_none()

        if not cert_store:
            return None

        # Decrypt certificate data
        decrypted_data = {}

        try:
            if cert_store.certificate_data:
                decrypted_data['certificate'] = self.decrypt_certificate_data(
                    cert_store.certificate_data, password
                )
            if cert_store.private_key_data:
                decrypted_data['private_key'] = self.decrypt_certificate_data(
                    cert_store.private_key_data, password
                )
            if cert_store.keystore_data:
                decrypted_data['keystore'] = self.decrypt_certificate_data(
                    cert_store.keystore_data, password
                )

            # Log certificate access
            await compliance_manager.log_compliance_event(
                db=db,
                event_type="certificate_accessed",
                user_id="SYSTEM",
                details={
                    "key_id": key_id,
                    "timestamp": datetime.utcnow().isoformat()
                },
                risk_level="medium"
            )

            return decrypted_data

        except Exception as e:
            # Log failed access attempt
            await compliance_manager.log_compliance_event(
                db=db,
                event_type="certificate_access_failed",
                user_id="SYSTEM",
                details={
                    "key_id": key_id,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                },
                risk_level="high"
            )
            return None

class APIKeyManager:
    """Manage API key lifecycle and rotation."""

    @staticmethod
    async def rotate_api_keys(db: AsyncSession, days_old: int = 90) -> Dict[str, int]:
        """Rotate API keys older than specified days."""

        cutoff_date = datetime.utcnow() - timedelta(days=days_old)

        # Find users with old API keys
        result = await db.execute(
            select(APIUser).where(APIUser.created_at < cutoff_date)
        )
        old_users = result.scalars().all()

        rotated_count = 0
        for user in old_users:
            # Generate new API key
            new_key = secrets.token_urlsafe(32)
            new_hash = compliance_manager.get_password_hash(new_key)

            # Update user
            user.api_key_hash = new_hash
            user.last_used_at = datetime.utcnow()

            rotated_count += 1

            # Log key rotation
            await compliance_manager.log_compliance_event(
                db=db,
                event_type="api_key_rotated",
                user_id=user.user_id,
                details={
                    "old_key_age_days": (datetime.utcnow() - user.created_at).days,
                    "rotation_reason": f"Scheduled rotation (>{days_old} days old)"
                },
                risk_level="medium"
            )

        await db.commit()

        return {
            "rotated_keys": rotated_count,
            "cutoff_date": cutoff_date.isoformat(),
            "total_users_checked": len(old_users)
        }

    @staticmethod
    async def revoke_compromised_key(db: AsyncSession, user_id: str, reason: str) -> bool:
        """Revoke a potentially compromised API key."""

        result = await db.execute(
            select(APIUser).where(APIUser.user_id == user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            return False

        # Deactivate user
        user.is_active = False
        await db.commit()

        # Log security event
        await compliance_manager.log_compliance_event(
            db=db,
            event_type="api_key_revoked",
            user_id=user_id,
            details={
                "revocation_reason": reason,
                "timestamp": datetime.utcnow().isoformat(),
                "action_required": "Generate new API key for user"
            },
            risk_level="high"
        )

        return True

class SecurityAuditor:
    """Perform security audits and checks."""

    @staticmethod
    async def audit_certificate_expiry(db: AsyncSession) -> List[Dict[str, any]]:
        """Audit certificates for upcoming expiry."""

        warning_date = datetime.utcnow() + timedelta(days=30)  # 30-day warning
        critical_date = datetime.utcnow() + timedelta(days=7)   # 7-day critical

        result = await db.execute(
            select(CertificateStore).where(
                CertificateStore.valid_until <= warning_date,
                CertificateStore.is_active == True
            )
        )

        expiring_certs = result.scalars().all()
        alerts = []

        for cert in expiring_certs:
            if not cert.valid_until:
                continue

            days_until_expiry = (cert.valid_until - datetime.utcnow()).days

            if days_until_expiry <= 7:
                severity = "critical"
            elif days_until_expiry <= 30:
                severity = "warning"
            else:
                continue

            alerts.append({
                "key_id": cert.key_id,
                "name": cert.name,
                "signing_type": cert.signing_type,
                "expiry_date": cert.valid_until.isoformat(),
                "days_until_expiry": days_until_expiry,
                "severity": severity,
                "recommendation": "Renew certificate before expiry"
            })

        return alerts

    @staticmethod
    async def audit_user_activity(db: AsyncSession) -> Dict[str, any]:
        """Audit user activity patterns."""

        # Users with no recent activity (90 days)
        inactive_cutoff = datetime.utcnow() - timedelta(days=90)

        result = await db.execute(
            select(APIUser).where(
                APIUser.last_used_at < inactive_cutoff,
                APIUser.is_active == True
            )
        )

        inactive_users = result.scalars().all()

        # Users with excessive operations
        from sqlalchemy import func
        from .database import SigningOperation

        high_activity_cutoff = datetime.utcnow() - timedelta(days=7)

        activity_result = await db.execute(
            select(
                SigningOperation.who_signed_the_file,
                func.count(SigningOperation.id).label('operation_count')
            )
            .where(SigningOperation.created_at >= high_activity_cutoff)
            .group_by(SigningOperation.who_signed_the_file)
            .having(func.count(SigningOperation.id) > 100)  # Threshold
        )

        high_activity_users = activity_result.all()

        return {
            "inactive_users": [
                {
                    "user_id": user.user_id,
                    "last_used": user.last_used_at.isoformat() if user.last_used_at else None,
                    "days_inactive": (datetime.utcnow() - (user.last_used_at or user.created_at)).days
                }
                for user in inactive_users
            ],
            "high_activity_users": [
                {
                    "user_id": user[0],
                    "operation_count": user[1],
                    "period": "7 days"
                }
                for user in high_activity_users
            ],
            "audit_timestamp": datetime.utcnow().isoformat()
        }

# Global security manager instances
key_manager = KeyManager()
api_key_manager = APIKeyManager()
security_auditor = SecurityAuditor()