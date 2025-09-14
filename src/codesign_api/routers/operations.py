"""
Additional operation routes (unsign, resign, download).
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import os
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..auth import authenticate_request, check_signing_permission, log_audit_event
from ..database import get_database, SigningOperation, APIUser
from ..models import (
    UnsignRequest, ResignRequest, OperationResponse,
    SigningType, OperationType
)
from ..config import settings
from ..signing import signing_engine, calculate_file_hash, SigningError
from .signing import save_uploaded_file, generate_download_link, process_signing_operation

router = APIRouter(prefix="/api/v1", tags=["operations"])

@router.post("/unsign", response_model=OperationResponse)
async def unsign_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    metadata: Optional[str] = Form(None),
    current_user: APIUser = Depends(authenticate_request),
    db: AsyncSession = Depends(get_database)
):
    """Remove signatures from a file (currently supports Windows files only)."""

    # For now, only Windows files support unsigning
    signing_type_enum = SigningType.WINDOWS

    # Check user permissions
    if not check_signing_permission(current_user, "windows"):
        raise HTTPException(status_code=403, detail="User not authorized for Windows unsigning")

    # Validate file extension for Windows files
    file_extension = os.path.splitext(file.filename)[1].lower()
    windows_extensions = [".exe", ".dll", ".sys", ".msi", ".cab", ".cat", ".appx", ".msix"]
    if file_extension not in windows_extensions:
        raise HTTPException(status_code=400, detail=f"Unsigning not supported for {file_extension} files")

    # Check file size
    if file.size > settings.max_file_size:
        raise HTTPException(status_code=413, detail="File too large")

    # Save uploaded file
    file_path = await save_uploaded_file(file, current_user.user_id)

    try:
        # Calculate file hash
        file_hash = await calculate_file_hash(file_path)

        # Parse metadata if provided
        metadata_dict = None
        if metadata:
            try:
                metadata_dict = json.loads(metadata)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid metadata JSON")

        # Generate output file path
        file_extension = os.path.splitext(file_path)[1]
        output_path = file_path.replace(file_extension, f"-unsigned{file_extension}")

        # Create operation record
        operation = SigningOperation(
            operation_type="unsign",
            signing_type=signing_type_enum.value,
            status="processing",
            original_filename=file.filename,
            file_hash=file_hash,
            file_size=file.size,
            path_to_file_on_disk=file_path,
            download_link=await generate_download_link(0),
            who_signed_the_file=current_user.user_id,
            metadata=json.dumps(metadata_dict) if metadata_dict else None
        )

        db.add(operation)
        await db.commit()
        await db.refresh(operation)

        # Update download link
        operation.download_link = await generate_download_link(operation.id, is_signed=False)

        # Perform unsigning
        try:
            success = await signing_engine.unsign_file(
                operation=operation,
                input_file=file_path,
                output_file=output_path
            )

            if success:
                # Calculate hash of unsigned file
                unsigned_hash = await calculate_file_hash(output_path)

                # Update operation with results
                operation.status = "completed"
                operation.signed_filename = os.path.basename(output_path)
                operation.signed_file_hash = unsigned_hash
                operation.signed_path_on_disk = output_path
                operation.signed_download_link = await generate_download_link(operation.id, is_signed=True)
                operation.completed_at = datetime.utcnow()
            else:
                operation.status = "failed"
                if not operation.error_message:
                    operation.error_message = "Unsigning operation failed"

        except SigningError as e:
            operation.status = "failed"
            operation.error_message = str(e)

        await db.commit()

        # Log audit event
        await log_audit_event(
            db=db,
            user_id=current_user.user_id,
            operation="unsign_windows",
            endpoint="/api/v1/unsign",
            method="POST",
            details=json.dumps({
                "operation_id": operation.id,
                "status": operation.status
            })
        )

        return OperationResponse(
            operation_id=operation.id,
            operation_type=OperationType.UNSIGN,
            signing_type=signing_type_enum,
            status=operation.status,
            original_filename=operation.original_filename,
            file_hash=operation.file_hash,
            signed_filename=operation.signed_filename,
            signed_file_hash=operation.signed_file_hash,
            download_link=operation.download_link,
            signed_download_link=operation.signed_download_link,
            key_id=operation.key_id,
            who_signed_the_file=operation.who_signed_the_file,
            created_at=operation.created_at,
            completed_at=operation.completed_at,
            error_message=operation.error_message,
            metadata=json.loads(operation.metadata) if operation.metadata else None
        )

    except Exception as e:
        # Clean up uploaded file on error
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Unsigning operation failed: {str(e)}")

@router.post("/resign", response_model=OperationResponse)
async def resign_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    signing_type: str = Form(...),
    key_id: str = Form(...),
    timestamp_url: Optional[str] = Form(None),
    app_name: Optional[str] = Form(None),
    app_url: Optional[str] = Form(None),
    metadata: Optional[str] = Form(None),
    current_user: APIUser = Depends(authenticate_request),
    db: AsyncSession = Depends(get_database)
):
    """Remove existing signatures and sign with a new certificate (resign operation)."""

    # Validate signing type
    try:
        signing_type_enum = SigningType(signing_type.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid signing type: {signing_type}")

    # Check user permissions
    if not check_signing_permission(current_user, signing_type):
        raise HTTPException(status_code=403, detail=f"User not authorized for {signing_type} signing")

    # Validate file extension
    file_extension = os.path.splitext(file.filename)[1].lower()
    if file_extension not in settings.allowed_extensions:
        raise HTTPException(status_code=400, detail=f"File type {file_extension} not supported")

    # Check file size
    if file.size > settings.max_file_size:
        raise HTTPException(status_code=413, detail="File too large")

    # Save uploaded file
    file_path = await save_uploaded_file(file, current_user.user_id)

    try:
        # Calculate file hash
        file_hash = await calculate_file_hash(file_path)

        # Parse metadata if provided
        metadata_dict = None
        if metadata:
            try:
                metadata_dict = json.loads(metadata)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid metadata JSON")

        # For resign operations, we first unsign (if supported) then sign
        # For now, we'll just perform a regular signing operation
        # In a full implementation, you might want to:
        # 1. Check if file is already signed
        # 2. Remove existing signature if supported
        # 3. Apply new signature

        # Create operation record
        operation = SigningOperation(
            operation_type="resign",
            signing_type=signing_type_enum.value,
            status="pending",
            original_filename=file.filename,
            file_hash=file_hash,
            file_size=file.size,
            path_to_file_on_disk=file_path,
            download_link=await generate_download_link(0),
            key_id=key_id,
            timestamp_url=timestamp_url or settings.default_timestamp_url,
            who_signed_the_file=current_user.user_id,
            metadata=json.dumps(metadata_dict) if metadata_dict else None
        )

        db.add(operation)
        await db.commit()
        await db.refresh(operation)

        # Update download link with actual operation ID
        operation.download_link = await generate_download_link(operation.id, is_signed=False)
        await db.commit()

        # Start background resigning task (similar to signing)
        background_tasks.add_task(
            process_signing_operation,
            operation.id,
            db,
            signing_type_enum,
            file_path,
            key_id,
            current_user.user_id,
            timestamp_url,
            app_name=app_name,
            app_url=app_url
        )

        # Return operation response
        return OperationResponse(
            operation_id=operation.id,
            operation_type=OperationType.RESIGN,
            signing_type=signing_type_enum,
            status=operation.status,
            original_filename=operation.original_filename,
            file_hash=operation.file_hash,
            signed_filename=operation.signed_filename,
            signed_file_hash=operation.signed_file_hash,
            download_link=operation.download_link,
            signed_download_link=operation.signed_download_link,
            key_id=operation.key_id,
            who_signed_the_file=operation.who_signed_the_file,
            created_at=operation.created_at,
            completed_at=operation.completed_at,
            error_message=operation.error_message,
            metadata=json.loads(operation.metadata) if operation.metadata else None
        )

    except Exception as e:
        # Clean up uploaded file on error
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Resigning operation failed: {str(e)}")

@router.get("/download/{operation_id}/{file_type}")
async def download_file(
    operation_id: int,
    file_type: str,  # "original" or "signed"
    token: str,
    current_user: APIUser = Depends(authenticate_request),
    db: AsyncSession = Depends(get_database)
):
    """Download a file from a completed operation."""

    # Validate file type
    if file_type not in ["original", "signed"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Must be 'original' or 'signed'")

    # Get operation
    result = await db.execute(
        select(SigningOperation).where(
            and_(
                SigningOperation.id == operation_id,
                SigningOperation.who_signed_the_file == current_user.user_id
            )
        )
    )
    operation = result.scalar_one_or_none()

    if not operation:
        raise HTTPException(status_code=404, detail="Operation not found")

    # Determine file path and filename
    if file_type == "original":
        file_path = operation.path_to_file_on_disk
        filename = operation.original_filename
    else:  # signed
        if not operation.signed_path_on_disk:
            raise HTTPException(status_code=404, detail="Signed file not available")
        file_path = operation.signed_path_on_disk
        filename = operation.signed_filename or f"signed-{operation.original_filename}"

    # Check if file exists
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")

    # Log download event
    await log_audit_event(
        db=db,
        user_id=current_user.user_id,
        operation=f"download_{file_type}",
        endpoint=f"/api/v1/download/{operation_id}/{file_type}",
        method="GET",
        details=json.dumps({
            "operation_id": operation_id,
            "file_type": file_type,
            "filename": filename
        })
    )

    # Return file
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type='application/octet-stream'
    )