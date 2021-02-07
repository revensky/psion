from starlette_wtf import StarletteForm
from wtforms import fields, validators, widgets


class LoginForm(StarletteForm):
    email = fields.StringField(
        label="Email",
        validators=[
            validators.DataRequired("Please provide a valid email."),
            validators.Email("Please provide a valid email."),
        ],
        id="email",
        render_kw={"aria-describedby": "email-help"},
    )
    password = fields.PasswordField(
        label="Password",
        validators=[
            validators.DataRequired("Please provide your password."),
            validators.Length(8, 64, "The password must be 8-64 characteres."),
        ],
        id="password",
        widget=widgets.PasswordInput(),
        render_kw={"aria-describedby": "password-help"},
    )
