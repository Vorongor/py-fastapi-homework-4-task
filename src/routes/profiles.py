from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Request
)
from typing import Annotated
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi.security import (
    OAuth2PasswordBearer
)

from database import get_db, UserModel, UserProfileModel
from config import get_jwt_auth_manager, get_s3_storage_client
from schemas import ProfileRequestSchema, ProfileResponseSchema
from security.interfaces import JWTAuthManagerInterface
from sqlalchemy.orm import selectinload
from storages import S3StorageInterface
from validation import validate_image
from exceptions import TokenExpiredError, InvalidTokenError

from src.database.models.accounts import UserGroupEnum, GenderEnum

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/users/{user_id}/profile/",
    auto_error=False
)


async def get_current_user_from_token(
        request: Request,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
) -> UserModel:
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing",
        )

    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=("Invalid Authorization header format. "
                    "Expected 'Bearer <token>'"),
        )

    token = auth_header.removeprefix("Bearer ").strip()

    try:
        payload = jwt_manager.decode_access_token(token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=("Invalid Authorization header format. "
                    "Expected 'Bearer <token>'"),
        )

    user_id = payload.get("user_id") or payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401,
                            detail="Could not validate credentials")

    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.group))
        .where(UserModel.id == user_id)
    )
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active.",
        )

    return user


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_user_profile(
    user_id: int,
    profile_data: Annotated[ProfileRequestSchema, Depends()],
    current_user: Annotated[
        UserModel, Depends(get_current_user_from_token)
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    storage_client: Annotated[
        S3StorageInterface, Depends(get_s3_storage_client)
    ],
):
    if current_user.id != user_id and not current_user.has_group(
            UserGroupEnum.ADMIN
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this profile.",
        )

    result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    target_user = result.scalar_one_or_none()

    if not target_user or not target_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active.",
        )

    result = await db.execute(
        select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a profile.",
        )

    # 🖼 Avatar upload
    filename = f"avatars/{user_id}_avatar.jpg"
    try:
        file_bytes = await profile_data.avatar.read()
        await storage_client.upload_file(
            filename=filename,
            file_data=file_bytes,
        )
        avatar_url = await storage_client.get_file_url(filename)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar. Please try again later.",
        )

    profile = UserProfileModel(
        user_id=user_id,
        first_name=profile_data.first_name,
        last_name=profile_data.last_name,
        gender=GenderEnum(profile_data.gender),
        date_of_birth=profile_data.date_of_birth,
        info=profile_data.info,
        avatar=avatar_url,
    )

    db.add(profile)
    await db.commit()
    await db.refresh(profile)

    return profile
