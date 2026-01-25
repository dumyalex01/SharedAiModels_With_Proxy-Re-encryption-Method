from flask import Blueprint, request, jsonify, send_file
from app.models import Attachment, Prekey,User
from app.extensions import db, minio_client
from datetime import timedelta
from io import BytesIO
from umbral import pre,keys
from umbral.key_frag import KeyFrag
import base64

bp = Blueprint("attachment", __name__)

@bp.route("/add", methods=["POST"])
def add():
    data = request.get_json()

    filename = data.get("filename")
    owner_id = data.get("owner_id")
    encrypted_key = data.get("encrypted_aes_key")
    iv = data.get("iv")
    capsule = data.get("capsule")

    if not filename or not owner_id or not encrypted_key or not iv or not capsule:
        return jsonify({"error": "Missing required fields"}), 400

    if Attachment.query.filter_by(filename=filename).first():
        return jsonify({"error": "Filename already exists"}), 400

    file_path = f"encryptedFiles/{filename}/{filename}"

    attachment = Attachment(
        filename=filename,
        file_path=file_path,
        owned_by=owner_id,
        encrypted_aes_key=encrypted_key,
        iv=iv,
        capsule=capsule
    )

    try:
        db.session.add(attachment)
        db.session.commit()
        return jsonify({"message": "Attachment added successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@bp.route("/get", methods=["GET"])
def getAttachments():
    attachments = Attachment.query.all()
    return jsonify([
        {
            "id": a.id,
            "filename": a.filename,
            "file_path": a.file_path,
            "owned_by": a.owned_by,
            "iv": a.iv,
            "uploaded_at": a.uploaded_at
        }
        for a in attachments
    ]), 200


@bp.route("/presignedUrl", methods=["GET"])
def getPresignedUrl():
    object_name = request.args.get("object_name")
    if not object_name:
        return jsonify({"error": "object_name missing"}), 400

    bucket_name = "models"
    object_path = f"encryptedFiles/{object_name}/{object_name}"

    try:
        minio_client.stat_object(bucket_name, object_path)
        return jsonify({"error": "Object already exists"}), 400
    except Exception:
        url = minio_client.presigned_put_object(
            bucket_name=bucket_name,
            object_name=object_path,
            expires=timedelta(minutes=5)
        )
        return jsonify({"url": url}), 200



@bp.route("/getAESKey", methods=["GET"])
def getAESKey():
    filename = request.args.get("filename")
    user_id = request.args.get("user_id")

    if not filename or not user_id:
        return jsonify({"error": "Missing parameters"}), 400

    attachment = Attachment.query.filter_by(filename=filename).first()
    if not attachment:
        return jsonify({"error": "Attachment not found"}), 404

    owner_id = attachment.owned_by

    prekey = Prekey.query.filter_by(
        secret_key_user_id=owner_id,  
        public_key_user_id=user_id     
    ).first()

    if not prekey:
        return jsonify({"error": "No access / no prekey"}), 403

    try:
        capsule = pre.Capsule.from_bytes(
            base64.b64decode(attachment.capsule)
        )
    except Exception as e:
        return jsonify({
            "error": "Invalid capsule",
            "details": str(e)
        }), 500


    try:
        kfrag = KeyFrag.from_bytes(
            base64.b64decode(prekey.prekey_value)
        )
    except Exception as e:
        return jsonify({
            "error": "Invalid KeyFrag bytes",
            "details": str(e)
        }), 500

    owner = User.query.filter_by(id=owner_id).first()
    if not owner:
        return jsonify({"error": "Owner not found"}), 500

    if not owner.signing_public_key or not owner.ecc_public_key:
        return jsonify({
            "error": "Owner keys missing (signing or encryption)"
        }), 500


    try:
        owner_verifying_pk = keys.PublicKey.from_bytes(
            base64.b64decode(owner.signing_public_key)
        )

        owner_delegating_pk = keys.PublicKey.from_bytes(
            base64.b64decode(owner.ecc_public_key)
        )

        receiver = User.query.filter_by(id=user_id).first()
        receiver_pk = keys.PublicKey.from_bytes(
            base64.b64decode(receiver.ecc_public_key)   
        )       

        print("BACKEND VERIFY PK:", owner.signing_public_key)
        print("BACKEND DELEGATE PK:", owner.ecc_public_key)

    except Exception as e:
        return jsonify({
            "error": "Invalid owner public keys",
            "details": str(e)
        }), 500

    try:
        verified_kfrag = kfrag.verify(
            delegating_pk=owner_delegating_pk,
            receiving_pk=receiver_pk,
            verifying_pk=owner_verifying_pk
        )
    except Exception as e:
        return jsonify({
            "error": "KeyFrag verification failed",
            "details": str(e)
        }), 403

    try:
        cfrag = pre.reencrypt(capsule, verified_kfrag)
    except Exception as e:
        return jsonify({
            "error": "Re-encryption failed",
            "details": str(e)
        }), 500


    return jsonify({
        "encrypted_aes_key": attachment.encrypted_aes_key,
        "capsule": attachment.capsule,
        "cfrags": [
            base64.b64encode(bytes(cfrag)).decode()
        ],
        "iv": attachment.iv,
        "owner_id": owner_id
    }), 200



@bp.route("/getModel", methods=["GET"])
def getModel():
    source_model = request.args.get("source_model")
    user_id = request.args.get("user_id")

    if not source_model or not user_id:
        return jsonify({"error": "Missing parameters"}), 400

    attachment = Attachment.query.filter_by(filename=source_model).first()
    if not attachment:
        return jsonify({"error": "Attachment not found"}), 404

    owner_id = attachment.owned_by

    if int(user_id) != int(owner_id):
        prekey = Prekey.query.filter_by(
            secret_key_user_id=owner_id,
            public_key_user_id=user_id
        ).first()
        if not prekey:
            return jsonify({"error": "No access to this file"}), 403

    bucket_name = "models"
    object_path = f"encryptedFiles/{source_model}/{source_model}"

    try:
        obj = minio_client.get_object(bucket_name, object_path)
        file_bytes = obj.read()
        obj.close()
        obj.release_conn()
    except Exception:
        return jsonify({"error": "File not found in storage"}), 404

    return send_file(
        BytesIO(file_bytes),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=source_model
    )


@bp.route("/getById", methods=["GET"])
def getById():
    attachment_id = request.args.get("id")
    if not attachment_id:
        return jsonify({"error": "Missing id"}), 400

    attachment = Attachment.query.filter_by(id=attachment_id).first()
    if not attachment:
        return jsonify({"error": "Not found"}), 404

    return jsonify({
        "id": attachment.id,
        "filename": attachment.filename
    }), 200
