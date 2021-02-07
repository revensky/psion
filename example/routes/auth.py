from starlette.routing import Route

from example.views.auth import LoginView, LogoutView


routes = [
    Route("/login", LoginView, name="login"),
    Route("/logout", LogoutView, name="logout"),
]
