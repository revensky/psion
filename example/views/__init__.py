from starlette.templating import Jinja2Templates

from example.settings import BASEDIR


templates = Jinja2Templates(BASEDIR / "templates")


async def home(request):
    return templates.TemplateResponse("index.j2", {"request": request, "title": "Home"})
