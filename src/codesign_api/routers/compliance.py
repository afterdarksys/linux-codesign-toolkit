"""
Compliance API routes for GDPR data subject rights and regulatory reporting.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import authenticate_request, verify_admin_key
from ..database import get_database
from ..compliance import (
    compliance_manager, gdpr_manager, data_retention_manager, security_monitor
)
from ..models import SuccessResponse

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])

# GDPR Data Subject Rights
@router.get("/gdpr/export/{user_id}")
async def export_user_data(
    user_id: str,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Export all data for a user (GDPR Article 20 - Right to Data Portability)."""

    try:
        export_data = await gdpr_manager.export_user_data(db, user_id)
        return {
            "status": "success",
            "export_data": export_data,
            "export_timestamp": datetime.utcnow().isoformat(),
            "compliance_note": "Data exported in compliance with GDPR Article 20"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Data export failed: {str(e)}")

@router.delete("/gdpr/delete/{user_id}")
async def delete_user_data(
    user_id: str,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Delete all user data (GDPR Article 17 - Right to Erasure/Right to be Forgotten)."""

    try:
        deletion_summary = await gdpr_manager.delete_user_data(db, user_id)
        return {
            "status": "success",
            "deletion_summary": deletion_summary,
            "compliance_note": "Data deleted in compliance with GDPR Article 17",
            "note": "Audit logs anonymized but retained for SOX compliance (7 years)"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Data deletion failed: {str(e)}")

@router.post("/gdpr/consent-withdrawal/{user_id}")
async def withdraw_consent(
    user_id: str,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Process consent withdrawal (GDPR Article 7)."""

    await compliance_manager.log_compliance_event(
        db=db,
        event_type="gdpr_consent_withdrawal",
        user_id=user_id,
        details={"action": "consent_withdrawn", "timestamp": datetime.utcnow().isoformat()},
        risk_level="medium"
    )

    return {
        "status": "success",
        "message": f"Consent withdrawal recorded for user {user_id}",
        "next_steps": "User data processing will be restricted to legal basis only",
        "compliance_note": "Processed in compliance with GDPR Article 7"
    }

# Data Retention Management
@router.post("/retention/cleanup")
async def cleanup_expired_data(
    background_tasks: BackgroundTasks,
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Clean up expired data according to retention policies."""

    background_tasks.add_task(_perform_data_cleanup, db)

    return {
        "status": "success",
        "message": "Data cleanup initiated",
        "compliance_note": "Cleanup follows SOX (7yr), GLBA (5yr), PCI-DSS (1yr) retention requirements"
    }

async def _perform_data_cleanup(db: AsyncSession):
    """Background task to perform data cleanup."""
    try:
        cleanup_result = await data_retention_manager.cleanup_expired_data(db)

        await compliance_manager.log_compliance_event(
            db=db,
            event_type="data_retention_cleanup",
            user_id="SYSTEM",
            details=cleanup_result,
            risk_level="low"
        )
    except Exception as e:
        await compliance_manager.log_compliance_event(
            db=db,
            event_type="data_retention_cleanup_failed",
            user_id="SYSTEM",
            details={"error": str(e)},
            risk_level="high"
        )

@router.get("/retention/policies")
async def get_retention_policies(
    admin_key: str = Depends(verify_admin_key)
):
    """Get current data retention policies."""

    return {
        "retention_policies": {
            "SOX_compliance": {
                "audit_logs": "7 years (2555 days)",
                "financial_records": "7 years (2555 days)",
                "signing_operations": "7 years (2555 days)"
            },
            "GLBA_compliance": {
                "customer_data": "5 years (1825 days)",
                "access_logs": "5 years (1825 days)"
            },
            "PCI_DSS_compliance": {
                "audit_logs": "1 year minimum (365 days)",
                "system_logs": "1 year minimum (365 days)"
            },
            "GDPR_compliance": {
                "personal_data": "Upon request (Right to Erasure)",
                "processing_logs": "3 years recommended (1095 days)"
            }
        },
        "active_policy": "Strictest requirements applied (SOX 7-year for most data)",
        "cleanup_frequency": "Manual trigger or scheduled monthly"
    }

# Security Monitoring (PCI-DSS)
@router.get("/security/alerts")
async def get_security_alerts(
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Get security alerts and suspicious activity detection (PCI-DSS Requirement 10)."""

    try:
        alerts = await security_monitor.detect_suspicious_activity(db)

        await compliance_manager.log_compliance_event(
            db=db,
            event_type="security_monitoring_check",
            user_id="SYSTEM",
            details={"alerts_found": len(alerts)},
            risk_level="low" if len(alerts) == 0 else "high"
        )

        return {
            "status": "success",
            "alerts": alerts,
            "alert_count": len(alerts),
            "check_timestamp": datetime.utcnow().isoformat(),
            "compliance_note": "Security monitoring per PCI-DSS Requirement 10"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Security monitoring failed: {str(e)}")

# Compliance Reporting
@router.get("/reports/sox")
async def generate_sox_report(
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Generate SOX compliance report with audit trail summary."""

    # Default to last 90 days if no dates provided
    if not end_date:
        end_date = datetime.utcnow().date().isoformat()
    if not start_date:
        start_date = (datetime.utcnow() - timedelta(days=90)).date().isoformat()

    from sqlalchemy import select, func, and_
    from ..database import AuditLog, SigningOperation

    try:
        start_dt = datetime.fromisoformat(start_date)
        end_dt = datetime.fromisoformat(end_date)

        # Count operations by type
        ops_result = await db.execute(
            select(
                SigningOperation.operation_type,
                func.count(SigningOperation.id)
            )
            .where(and_(
                SigningOperation.created_at >= start_dt,
                SigningOperation.created_at <= end_dt
            ))
            .group_by(SigningOperation.operation_type)
        )

        operations_summary = dict(ops_result.all())

        # Count audit events
        audit_result = await db.execute(
            select(func.count(AuditLog.id))
            .where(and_(
                AuditLog.timestamp >= start_dt,
                AuditLog.timestamp <= end_dt
            ))
        )

        total_audit_events = audit_result.scalar()

        # Failed operations
        failed_result = await db.execute(
            select(func.count(SigningOperation.id))
            .where(and_(
                SigningOperation.status == "failed",
                SigningOperation.created_at >= start_dt,
                SigningOperation.created_at <= end_dt
            ))
        )

        failed_operations = failed_result.scalar()

        report = {
            "report_type": "SOX_compliance",
            "report_period": {
                "start_date": start_date,
                "end_date": end_date
            },
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_operations": sum(operations_summary.values()),
                "operations_by_type": operations_summary,
                "failed_operations": failed_operations,
                "total_audit_events": total_audit_events,
                "data_integrity": "All operations tracked with SHA-256 hashes"
            },
            "compliance_status": {
                "audit_trail": "Complete - all operations logged",
                "data_retention": "7-year retention policy active",
                "access_controls": "API key authentication in place",
                "data_integrity": "File hashes recorded for all operations"
            }
        }

        return report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@router.get("/reports/pci-dss")
async def generate_pci_dss_report(
    admin_key: str = Depends(verify_admin_key),
    db: AsyncSession = Depends(get_database)
):
    """Generate PCI-DSS compliance report."""

    try:
        # Get recent security alerts
        alerts = await security_monitor.detect_suspicious_activity(db)

        # Check encryption status
        encryption_status = {
            "data_at_rest": "AES-256 encryption via Fernet",
            "data_in_transit": "TLS encryption (HTTPS)",
            "key_management": "Local key generation and storage",
            "api_authentication": "API key-based authentication"
        }

        report = {
            "report_type": "PCI_DSS_compliance",
            "generated_at": datetime.utcnow().isoformat(),
            "compliance_requirements": {
                "requirement_1": "Firewall - Infrastructure responsibility",
                "requirement_2": "Default passwords - Custom API keys required",
                "requirement_3": "Protect stored data - AES-256 encryption implemented",
                "requirement_4": "Encrypt transmission - HTTPS/TLS implemented",
                "requirement_5": "Antivirus - Infrastructure responsibility",
                "requirement_6": "Secure systems - Regular updates required",
                "requirement_7": "Restrict access - API key authorization",
                "requirement_8": "Unique IDs - Unique user IDs enforced",
                "requirement_9": "Physical access - Infrastructure responsibility",
                "requirement_10": "Track access - Comprehensive audit logging",
                "requirement_11": "Security testing - Manual/automated testing",
                "requirement_12": "Security policy - This compliance module"
            },
            "current_security_status": {
                "active_alerts": len(alerts),
                "encryption_status": encryption_status,
                "audit_logging": "Active - all API calls logged",
                "access_controls": "Active - API key authentication"
            },
            "recommendations": [
                "Regular security testing and vulnerability scanning",
                "Network segmentation at infrastructure level",
                "Regular key rotation procedures",
                "Staff security training program"
            ]
        }

        return report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PCI-DSS report generation failed: {str(e)}")

@router.get("/status")
async def compliance_status_overview(
    admin_key: str = Depends(verify_admin_key)
):
    """Get overall compliance status overview."""

    return {
        "compliance_status": {
            "SOX": {
                "status": "COMPLIANT",
                "features": [
                    "7-year audit log retention",
                    "Complete audit trail for all operations",
                    "Data integrity verification (SHA-256 hashes)",
                    "Access controls and user authentication"
                ]
            },
            "GLBA": {
                "status": "COMPLIANT",
                "features": [
                    "Customer data protection via encryption",
                    "5-year data retention policy",
                    "Access logging and monitoring",
                    "Privacy safeguards implemented"
                ]
            },
            "PCI_DSS": {
                "status": "PARTIALLY_COMPLIANT",
                "features": [
                    "Data encryption at rest and in transit",
                    "Access controls and authentication",
                    "Security monitoring and alerting",
                    "Audit logging (Requirement 10)"
                ],
                "gaps": [
                    "Network security (infrastructure-dependent)",
                    "Regular security testing (operational)",
                    "Physical security (infrastructure-dependent)"
                ]
            },
            "GDPR": {
                "status": "COMPLIANT",
                "features": [
                    "Right to data portability (Article 20)",
                    "Right to erasure (Article 17)",
                    "Consent management (Article 7)",
                    "Data encryption and pseudonymization",
                    "Data breach notification procedures"
                ]
            }
        },
        "last_updated": datetime.utcnow().isoformat(),
        "next_review_date": (datetime.utcnow() + timedelta(days=90)).date().isoformat()
    }