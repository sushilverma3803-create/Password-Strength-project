from datetime import datetime, timezone
import json
import bcrypt
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    """
    User account model with secure bcrypt password hashing.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    saved_passwords = db.relationship('SavedPassword', backref='user', cascade='all, delete-orphan', lazy='dynamic')
    strength_reports = db.relationship('StrengthReport', backref='user', cascade='all, delete-orphan', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', cascade='all, delete-orphan', lazy='dynamic')

    def set_password(self, password: str) -> None:
        """Hash password securely using bcrypt with a random salt."""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        self.password_hash = hashed.decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Verify candidate plaintext password against stored bcrypt hash."""
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except Exception:
            return False

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'saved_passwords_count': self.saved_passwords.count(),
            'strength_reports_count': self.strength_reports.count()
        }


class SavedPassword(db.Model):
    """
    Stores generated passwords securely in SQLite with metadata (label, length, timestamp).
    """
    __tablename__ = 'saved_passwords'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True)
    label = db.Column(db.String(100), default='Generated Password', nullable=False)
    password = db.Column(db.String(255), nullable=False)
    length = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'label': self.label,
            'password': self.password,
            'length': self.length,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
        }


class StrengthReport(db.Model):
    """
    Stores comprehensive strength audit reports in SQLite for authenticated users.
    Includes score, entropy, crack time, criteria matrix, and security warnings.
    """
    __tablename__ = 'strength_reports'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True)
    password_preview = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), nullable=False)
    entropy = db.Column(db.Float, nullable=False)
    crack_time = db.Column(db.String(100), nullable=False)
    pool_size = db.Column(db.Integer, default=0)
    warnings_count = db.Column(db.Integer, default=0)
    is_breached = db.Column(db.Boolean, default=False)
    details_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        details = {}
        if self.details_json:
            try:
                details = json.loads(self.details_json)
            except Exception:
                details = {}

        return {
            'id': self.id,
            'user_id': self.user_id,
            'password_preview': self.password_preview,
            'score': self.score,
            'status': self.status,
            'entropy': round(self.entropy, 2),
            'crack_time': self.crack_time,
            'pool_size': self.pool_size,
            'warnings_count': self.warnings_count,
            'is_breached': self.is_breached,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'details': details
        }


class AnalysisAudit(db.Model):
    """
    Stores anonymous metrics about analyzed passwords for audit & dashboard statistics.
    Never stores plaintext passwords to adhere to strict cybersecurity best practices.
    """
    __tablename__ = 'analysis_audits'

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    password_length = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False)  # Weak, Medium, Strong, Very Strong
    entropy = db.Column(db.Float, nullable=False)
    crack_time_display = db.Column(db.String(50), nullable=False)
    has_upper = db.Column(db.Boolean, default=False)
    has_lower = db.Column(db.Boolean, default=False)
    has_digit = db.Column(db.Boolean, default=False)
    has_symbol = db.Column(db.Boolean, default=False)
    is_breached = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'length': self.password_length,
            'score': self.score,
            'status': self.status,
            'entropy': round(self.entropy, 2),
            'crack_time': self.crack_time_display,
            'flags': {
                'upper': self.has_upper,
                'lower': self.has_lower,
                'digit': self.has_digit,
                'symbol': self.has_symbol,
            },
            'is_breached': self.is_breached
        }


class CompromisedPassword(db.Model):
    """
    Lookup table of known breached / commonly used passwords (e.g. from rockyou, haveibeenpwned).
    """
    __tablename__ = 'compromised_passwords'

    id = db.Column(db.Integer, primary_key=True)
    plain_text = db.Column(db.String(100), unique=True, index=True, nullable=False)
    sha256_hash = db.Column(db.String(64), index=True, nullable=False)
    category = db.Column(db.String(50), default='Common Dictionary')


class AuditLog(db.Model):
    """
    Security event audit log recording key actions (login, password analysis, vault saves, password changes, etc.).
    """
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50), default='127.0.0.1')
    user_agent = db.Column(db.String(255), default='Browser')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'description': self.description,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
        }

