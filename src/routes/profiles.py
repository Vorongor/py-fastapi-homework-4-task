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
from fastapi.security import (
    HTTPAuthorizationCredentials,
    OAuth2PasswordBearer
)

from database import get_db, UserModel, UserProfileModel
from config import get_jwt_auth_manager, get_s3_storage_client
from schemas import ProfileRequestSchema, ProfileResponseSchema
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface
from validation import validate_image
from exceptions import TokenExpiredError, InvalidTokenError

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/users/{user_id}/profile/"
)


async def _get_user(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_id: int
) -> UserModel:
    user = await db.get(UserModel, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or not active.",
        )


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def create_user_profile(
        user_id: int,
        profile_data: ProfileRequestSchema,
        token: Annotated[str, Depends(oauth2_scheme)],
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
        storage_client: Annotated[
            S3StorageInterface, Depends(get_s3_storage_client)],
):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing",
        )
    try:
        payload = jwt_manager.decode_access_token(token)
        user_auth_id: int = payload.get("user_id") or payload.get("sub")
        if user_auth_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'",
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
        )

    user = await _get_user(db=db, user_id=user_auth_id)

    if user_auth_id != user_id and not user.has_group("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this profile.",
        )

    target_user_result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    target_user = target_user_result.scalar_one_or_none()

    if not target_user or not target_user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User not found or not active."
        )

    existing_profile_check = await db.execute(
        select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    )
    if existing_profile_check.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail="User already has a profile."
        )

    profile_data = profile_data.model_dump()
    avatar = profile_data.pop("avatar")

    filename = f"avatars/{user_id}_avatar.jpg"
    try:
        file_content = await avatar.read()
        await storage_client.upload_file(
            filename=filename,
            file_data=file_content,
        )
        avatar_url = await storage_client.get_file_url(filename=filename)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Failed to upload avatar. Please try again later."
        )

    new_profile = UserProfileModel(
        first_name=profile_data.pop("first_name"),
        last_name=profile_data.pop("last_name"),
        gender=profile_data.pop("gender"),
        date_of_birth=profile_data.pop("date_of_birth"),
        info=profile_data.pop("info"),
        avatar=avatar_url,
    )
    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)

    return new_profile
