from app import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    ecc_public_key = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(25), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Attachment(db.Model):
    __tablename__ = 'attachments'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True, nullable=False)
    file_path = db.Column(db.String(255), unique=True, nullable=False)
    owned_by = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Prekey(db.Model):
    __tablename__ = 'prekeys'
    id = db.Column(db.Integer, primary_key=True)
    secret_key_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    public_key_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    prekey_value = db.Column(db.Text, nullable=False)

class Request(db.Model):
    __tablename__ = 'request'
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('attachments.id'), nullable=False)
    requested_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    request_status = db.Column(db.Enum('pending','approved','rejected'), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
