from flask import Blueprint, request, jsonify
from app.models import Prekey
from app.extensions import db 

bp = Blueprint("prekeys",__name__)

@bp.route("/add", methods=["POST"])
def addKey():
    data = request.get_json()

    secret_key_user_id = data.get("secret_key_user_id")
    public_key_user_id = data.get("public_key_user_id")
    prekey_value = data.get("prekey_value")

    if not secret_key_user_id or not public_key_user_id or not prekey_value:
        return jsonify({"error": "Crucial details missing..."}), 400

    prekey = Prekey.query.filter_by(
        secret_key_user_id=secret_key_user_id,
        public_key_user_id=public_key_user_id
    ).first()

    try:
        if prekey:
            prekey.prekey_value = prekey_value
            db.session.commit()
            return jsonify({"message": "Proxy re-encryption key updated!"}), 200
        else:
            prekey = Prekey(
                secret_key_user_id=secret_key_user_id,
                public_key_user_id=public_key_user_id,
                prekey_value=prekey_value
            )
            db.session.add(prekey)
            db.session.commit()
            return jsonify({"message": "Proxy re-encryption key added!"}), 200

    except Exception as ex:
        db.session.rollback()
        return jsonify({
            "error": "Unexpected error",
            "details": str(ex)
        }), 500
