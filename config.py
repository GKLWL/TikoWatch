import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Existing config values …
SECRET_KEY = os.getenv("SECRET_KEY")
SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI")

SQLALCHEMY_TRACK_MODIFICATIONS = False

# --- File Upload Configuration ---
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB max
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# --- Cookies and Session Management ---
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
