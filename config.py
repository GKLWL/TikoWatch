import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Existing config values …
SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret_key_change_me")

SQLALCHEMY_DATABASE_URI = os.environ.get(
    "DATABASE_URL",
    "mysql+pymysql://tikoadmin:Tiko123!@localhost/tikowatch"
)
SQLALCHEMY_TRACK_MODIFICATIONS = False

# --- File Upload Configuration ---
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB max
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
