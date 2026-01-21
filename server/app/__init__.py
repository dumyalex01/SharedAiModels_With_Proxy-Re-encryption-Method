from flask import Flask
from app.extensions import db
from app.routes.auth import bp as auth_bp
from app.routes.request import bp as request_bp
from app.routes.attachment import bp as attachement_bp
from app.routes.keys import bp as keys_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object("app.config.Config")

    db.init_app(app)

    app.register_blueprint(auth_bp, url_prefix="/v1/api/auth")
    app.register_blueprint(request_bp, url_prefix="/v1/api/request")
    app.register_blueprint(attachement_bp,url_prefix = "/v1/api/attachment")
    app.register_blueprint(keys_bp,url_prefix="/v1/api/keys")

    return app
