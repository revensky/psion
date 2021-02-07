from tortoise import Model, fields

from example.models.users import User


class Session(Model):
    id = fields.CharField(32, pk=True)
    user: fields.OneToOneRelation[User] = fields.ForeignKeyField("models.User")
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "sessions"
        unique_together = ("id", "user_id")
