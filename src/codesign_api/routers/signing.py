"""
API routes for signing operations.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import os
import uuid
import json
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
import aiofiles

from ..auth import authenticate_request, check_signing_permission, log_audit_event
from ..database import get_database, SigningOperation, APIUser
from ..models import (
    SignRequest, VerifyRequest, UnsignRequest, ResignRequest,
    OperationResponse, OperationStatus, ListOperationsResponse,
    SigningType, OperationType
)
from ..config import settings
from ..signing import signing_engine, calculate_file_hash, SigningError

router = APIRouter(prefix="/api/v1/signing", tags=["signing"])

async def save_uploaded_file(upload_file: UploadFile, user_id: str) -> str:
    """Save uploaded file to disk and return the path."""
    # Create user-specific directory
    user_dir = os.path.join(settings.upload_directory, user_id)
    os.makedirs(user_dir, exist_ok=True)

    # Generate unique filename
    file_extension = os.path.splitext(upload_file.filename)[1]
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = os.path.join(user_dir, unique_filename)

    # Save file
    async with aiofiles.open(file_path, 'wb') as f:
        content = await upload_file.read()
        await f.write(content)

    return file_path

async def generate_download_link(operation_id: int, is_signed: bool = False) -> str:
    """Generate download link for a file."""
    link_type = "signed" if is_signed else "original"
    token = uuid.uuid4().hex
    return f"{settings.base_download_url}/{operation_id}/{link_type}?token={token}"

async def process_signing_operation(
    operation_id: int,
    db: AsyncSession,
    signing_type: SigningType,
    input_file: str,
    key_id: str,
    user_id: str,
    timestamp_url: Optional[str] = None,
    **kwargs
):
    """Background task to process signing operation."""
    try:
        # Get operation from database
        result = await db.execute(select(SigningOperation).where(SigningOperation.id == operation_id))
        operation = result.scalar_one_or_none()

        if not operation:
            return

        # Update status to processing
        operation.status = "processing"
        await db.commit()

        # Generate output file path
        input_path = input_file
        file_extension = os.path.splitext(input_path)[1]
        output_path = input_path.replace(file_extension, f"-signed{file_extension}")

        # Perform signing
        success = await signing_engine.sign_file(
            operation=operation,
            signing_type=signing_type,
            input_file=input_path,
            output_file=output_path,
            key_id=key_id,
            timestamp_url=timestamp_url,
            **kwargs
        )

        if success:
            # Calculate hash of signed file
            signed_hash = await calculate_file_hash(output_path)

            # Update operation with results
            operation.status = "completed"
            operation.signed_filename = os.path.basename(output_path)
            operation.signed_file_hash = signed_hash
            operation.signed_path_on_disk = output_path
            operation.signed_download_link = await generate_download_link(operation_id, is_signed=True)
            operation.completed_at = datetime.utcnow()
        else:
            operation.status = "failed"

        await db.commit()

        # Log audit event
        await log_audit_event(
            db=db,
            user_id=user_id,
            operation=f"sign_{signing_type.value}",
            endpoint="/api/v1/signing/sign",
            method="POST",
            details=json.dumps({
                "operation_id": operation_id,
                "status": operation.status,
                "key_id": key_id
            })
        )

    except Exception as e:
        # Update operation with error
        if operation:
            operation.status = "failed"
            operation.error_message = str(e)
            await db.commit()

@router.post("/sign", response_model=OperationResponse)
async def sign_file(
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
    """Sign a file with the specified signing type and certificate."""

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

        # Create operation record
        operation = SigningOperation(
            operation_type="sign",
            signing_type=signing_type_enum.value,
            status="pending",
            original_filename=file.filename,
            file_hash=file_hash,
            file_size=file.size,
            path_to_file_on_disk=file_path,
            download_link=await generate_download_link(0),  # Will update after getting ID
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

        # Start background signing task
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
            operation_type=OperationType.SIGN,
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
        raise HTTPException(status_code=500, detail=f"Signing operation failed: {str(e)}")

@router.post("/verify", response_model=OperationResponse)
async def verify_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    signing_type: str = Form(...),
    metadata: Optional[str] = Form(None),
    current_user: APIUser = Depends(authenticate_request),
    db: AsyncSession = Depends(get_database)
):
    """Verify a signed file."""

    # Validate signing type
    try:
        signing_type_enum = SigningType(signing_type.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid signing type: {signing_type}")

    # Check user permissions
    if not check_signing_permission(current_user, signing_type):
        raise HTTPException(status_code=403, detail=f"User not authorized for {signing_type} verification")

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

        # Create operation record
        operation = SigningOperation(
            operation_type="verify",
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

        # Perform verification
        try:
            success = await signing_engine.verify_file(
                operation=operation,
                signing_type=signing_type_enum,
                input_file=file_path
            )

            operation.status = "completed" if success else "failed"
            if not success and not operation.error_message:
                operation.error_message = "Signature verification failed"

        except SigningError as e:
            operation.status = "failed"
            operation.error_message = str(e)

        operation.completed_at = datetime.utcnow()
        await db.commit()

        # Log audit event
        await log_audit_event(
            db=db,
            user_id=current_user.user_id,
            operation=f"verify_{signing_type.value}",
            endpoint="/api/v1/signing/verify",
            method="POST",
            details=json.dumps({
                "operation_id": operation.id,
                "status": operation.status
            })
        )

        return OperationResponse(
            operation_id=operation.id,
            operation_type=OperationType.VERIFY,
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
        raise HTTPException(status_code=500, detail=f"Verification operation failed: {str(e)}")

@router.get("/operations", response_model=ListOperationsResponse)
async def list_operations(
    page: int = 1,
    per_page: int = 50,
    operation_type: Optional[str] = None,
    signing_type: Optional[str] = None,
    status: Optional[str] = None,
    current_user: APIUser = Depends(authenticate_request),
    db: AsyncSession = Depends(get_database)
):
    """List signing operations for the current user."""

    if per_page > 100:
        per_page = 100

    offset = (page - 1) * per_page

    # Build query
    query = select(SigningOperation).where(SigningOperation.who_signed_the_file == current_user.user_id)

    if operation_type:
        query = query.where(SigningOperation.operation_type == operation_type)
    if signing_type:
        query = query.where(SigningOperation.signing_type == signing_type)
    if status:
        query = query.where(SigningOperation.status == status)

    # Get total count
    count_query = select(func.count(SigningOperation.id)).where(SigningOperation.who_signed_the_file == current_user.user_id)
    if operation_type:
        count_query = count_query.where(SigningOperation.operation_type == operation_type)
    if signing_type:
        count_query = count_query.where(SigningOperation.signing_type == signing_type)
    if status:
        count_query = count_query.where(SigningOperation.status == status)

    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Get operations
    query = query.order_by(SigningOperation.created_at.desc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    operations = result.scalars().all()

    # Convert to response models
    operation_responses = []
    for op in operations:
        operation_responses.append(OperationResponse(
            operation_id=op.id,
            operation_type=OperationType(op.operation_type),
            signing_type=SigningType(op.signing_type),
            status=op.status,
            original_filename=op.original_filename,
            file_hash=op.file_hash,
            signed_filename=op.signed_filename,
            signed_file_hash=op.signed_file_hash,
            download_link=op.download_link,
            signed_download_link=op.signed_download_link,
            key_id=op.key_id,
            who_signed_the_file=op.who_signed_the_file,
            created_at=op.created_at,
            completed_at=op.completed_at,
            error_message=op.error_message,
            metadata=json.loads(op.metadata) if op.metadata else None
        ))

    return ListOperationsResponse(
        operations=operation_responses,
        total=total,
        page=page,
        per_page=per_page
    )

@router.get("/operations/{operation_id}", response_model=OperationResponse)
async def get_operation(
    operation_id: int,
    current_user: APIUser = Depends(authenticate_request),
    db: AsyncSession = Depends(get_database)
):
    """Get details of a specific operation."""

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

    return OperationResponse(
        operation_id=operation.id,
        operation_type=OperationType(operation.operation_type),
        signing_type=SigningType(operation.signing_type),
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