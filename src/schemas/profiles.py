import enum
from datetime import date

from fastapi import UploadFile, Form, File, HTTPException
from fastapi.openapi.models import Schema
from pydantic import BaseModel, field_validator, HttpUrl, ConfigDict

from validation import (
    validate_name,
    validate_image,
    validate_gender,
    validate_birth_date
)
class GenderEnum(str, enum.Enum):
    MAN = "man"
    WOMAN = "woman"


class ProfileRequestSchema(BaseModel):
    first_name: str
    last_name: str
    gender: str
    date_of_birth: date
    info: str
    avatar: UploadFile = File(...)

    @field_validator("first_name")
    @classmethod
    def validate_first_name(cls, value: str) -> str:
        validate_name(value)
        return value

    @field_validator("last_name")
    @classmethod
    def validate_last_name(cls, value: str) -> str:
        validate_name(value)
        return value

    @field_validator("gender")
    @classmethod
    def validate_gender(cls, value: str) -> str:
        validate_gender(value)
        return value

    @field_validator("date_of_birth")
    @classmethod
    def validate_date_of_birth(cls, value: date) -> date:
        validate_birth_date(value)
        return value

    @field_validator("info")
    @classmethod
    def validate_info(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Cannot be empty or consist only of spaces.")
        return value

    @field_validator("avatar")
    @classmethod
    def validate_avatar(cls, value: str) -> type[File]:
        validate_image(value)
        return value


class ProfileResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    first_name: str
    last_name: str
    gender: GenderEnum
    date_of_birth: date
    info: str
    avatar: str