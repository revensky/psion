from enum import Enum

from tortoise import Model, fields

from psion.oauth2.mixins import UserMixin


class Genders(str, Enum):
    male = "male"
    female = "female"


class User(Model, UserMixin):
    id = fields.UUIDField(pk=True)
    password = fields.CharField(80)
    given_name = fields.CharField(24)
    middle_name = fields.CharField(64, null=True)
    family_name = fields.CharField(64)
    nickname = fields.CharField(16, null=True)
    preferred_username = fields.CharField(16, null=True)
    profile = fields.CharField(128, null=True)
    picture = fields.CharField(256, null=True)
    website = fields.CharField(128, null=True)
    email = fields.CharField(64)
    email_verified = fields.BooleanField(default=False)
    gender = fields.CharEnumField(Genders, max_length=6, null=True)
    birthdate = fields.DateField(null=True)
    zoneinfo = fields.CharField(32, null=True)
    locale = fields.CharField(16, null=True)
    phone_number = fields.CharField(32, null=True)
    phone_number_verified = fields.BooleanField(default=False)
    address = fields.JSONField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "users"

    def get_user_id(self) -> str:
        return str(self.id)
