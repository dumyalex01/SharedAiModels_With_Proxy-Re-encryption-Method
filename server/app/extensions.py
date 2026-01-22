from flask_sqlalchemy import SQLAlchemy
from minio import Minio

db = SQLAlchemy()
minio_client = Minio(
    "localhost:9000",
    "minioadmin",
    "minioadmin",
    secure=False
)