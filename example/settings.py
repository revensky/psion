import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv(override=True)

# Defines the base directory of the application.
BASEDIR = Path(__file__).resolve(strict=True).parent

# Defines the URL of the database of the application.
DATABASE_URL = os.environ["DATABASE_URL"]

# Defines the secret key of the application for session and CSRF.
SECRET_KEY = "~this_is_a_super_secret_passphrase_that_must_not_be_made_public~"
