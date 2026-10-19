import os

# Automatically load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Production and Development Configuration."""
    # Secret key for session management and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'cyber-guard-default-dev-secret-key-change-in-prod'

    # Database URI configuration:
    # Render and Heroku provision PostgreSQL with `postgres://`, but SQLAlchemy 1.4+
    # requires the dialect identifier `postgresql://`
    raw_db_url = os.environ.get('DATABASE_URL')
    if raw_db_url and raw_db_url.startswith("postgres://"):
        raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

    _sqlite_file = os.path.join(BASE_DIR, 'passwords.db').replace('\\', '/')
    SQLALCHEMY_DATABASE_URI = raw_db_url or f"sqlite:///{_sqlite_file}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
