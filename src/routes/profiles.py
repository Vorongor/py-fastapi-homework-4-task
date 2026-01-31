from datetime import date

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    File,
    UploadFile,
    Form
)
from typing import Annotated
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db, UserModel, UserProfileModel
from config import get_jwt_auth_manager, get_s3_storage_client
from schemas import ProfileRequestSchema, ProfileResponseSchema
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface
from validation import validate_image
from exceptions import TokenExpiredError

router = APIRouter()

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def create_user_profile(
        user_id: int,
        db: Annotated[AsyncSession, Depends(get_db)],
        auth: Annotated[HTTPAuthorizationCredentials, Depends(security)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
        storage_client: Annotated[
            S3StorageInterface, Depends(get_s3_storage_client)],
        first_name: str = Form(...),
        last_name: str = Form(...),
        gender: str = Form(...),
        date_of_birth: date = Form(...),
        info: str = Form(...),
        avatar: UploadFile = File(...)
):
    token = auth.credentials
    try:
        payload = jwt_manager.decode_access_token(token)
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'"
        )

    current_user_id = int(payload.get("sub") or payload.get("user_id"))

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == current_user_id)
    )
    current_user = user_result.scalar_one_or_none()

    if not current_user or not current_user.is_active:
        raise HTTPException(
            status_code=401,
                            detail="User not found or not active."
        )

    if current_user_id != user_id and not current_user.has_group("admin"):
        raise HTTPException(
            status_code=403,
            detail="You don't have permission to edit this profile."
        )

    target_user_result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    target_user = target_user_result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(
            status_code=401,
                            detail="User not found or not active."
        )

    existing_profile_check = await db.execute(
        select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    )
    if existing_profile_check.scalar_one_or_none():
        raise HTTPException(status_code=400,
                            detail="User already has a profile.")

    try:
        profile_fields = ProfileRequestSchema(
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            info=info
        )
        validate_image(avatar)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    filename = f"avatars/{user_id}_avatar.jpg"
    try:
        file_content = await avatar.read()
        await storage_client.upload_file(
            filename=filename,
            file_data=file_content,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Failed to upload avatar. Please try again later."
        )

    avatar_url = await storage_client.get_file_url(filename=filename)

    new_profile = UserProfileModel(
        user_id=user_id,
        first_name=profile_fields.first_name,
        last_name=profile_fields.last_name,
        gender=profile_fields.gender,
        date_of_birth=profile_fields.date_of_birth,
        info=profile_fields.info,
        avatar=avatar_url
    )

    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)

    return new_profile
