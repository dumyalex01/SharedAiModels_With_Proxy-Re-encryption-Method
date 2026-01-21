from flask import Flask
from server.extensions import db
from server.routes.auth import bp as auth_bp
from server.routes.request import bp as request_bp
from server.routes.attachment import bp as attachement_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object("server.config.Config")

    db.init_app(app)

    app.register_blueprint(auth_bp, url_prefix="/v1/api/auth")
    app.register_blueprint(request_bp, url_prefix="/v1/api/request")
    app.register_blueprint(attachement_bp,url_prefix = "/v1/api/attachment")

    return app
