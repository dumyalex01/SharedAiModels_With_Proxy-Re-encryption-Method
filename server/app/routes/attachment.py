from flask import Blueprint, request, jsonify,send_file
from app.models import Attachment,Prekey
from app.extensions import db,minio_client 
from datetime import timedelta
from io import BytesIO
from app.utils import reencrypt

bp = Blueprint("attachment",__name__)

@bp.route("/add",methods = ["POST"])
def add():
    
    data = request.get_json()

    filename = data.get("filename")
    owner_id = data.get("owner_id")
    encrypted_key = data.get("encrypted_aes_key")
    iv = data.get("iv")
    capsule = data.get("capsule")

    if not filename:
        return jsonify({"error":"Not filename in request"}),400
    
    if Attachment.query.filter_by(filename = filename).first():
        return jsonify({"error":"This filename already exists in drive!"}),400
    file_path = f"encryptedFiles/{filename}"

    attachment = Attachment(
        filename = filename,
        file_path = file_path,
        owned_by = owner_id,
        encrypted_aes_key = encrypted_key,
        iv = iv,
        capsule = capsule
    )

    try:
        db.session.add(attachment)
        db.session.commit()
        return jsonify({"message":"Attachment added successfully!"}),200
    except Exception as ex:
        return jsonify("error",str(ex)),500
    
@bp.route("/get",methods = ["GET"])
def getAttachments():

    attachments = Attachment.query.all()
    results = []

    for attachment in attachments:
        results.append({
            "id": attachment.id,
            "filename": attachment.filename,
            "file_path": attachment.file_path,
            "encrypted_aes_key": attachment.encrypted_aes_key,
            "iv": attachment.iv,
            "uploaded_at": attachment.uploaded_at
        })
    
    return jsonify(results),200


@bp.route("/getById", methods = ["GET"])
def getResourceById():
    
    resource_id = request.args.get("id")
    
    resource = Attachment.query.filter_by(id = resource_id).first()

    return jsonify({
        "id": resource.id,
        "filename": resource.filename,
        "file_path": resource.file_path,
        "uploaded_at": resource.uploaded_at,
        "owned_by": resource.owned_by
    })

@bp.route("/presignedUrl", methods=["GET"])
def getPresignedUrl():

    object_name = request.args.get("object_name")
    bucket_name = "models"
    object_name = "encryptedFiles/" + object_name + "/" + object_name

    try:
        existing_product = minio_client.stat_object(
            bucket_name = bucket_name,
            object_name = object_name
        )
        if existing_product:
            return jsonify({"error":"Object already existing in minio!"}),400
        
    except Exception as e:
        presigned_url = minio_client.presigned_put_object(
            bucket_name = bucket_name,
            object_name = object_name,
            expires = timedelta(minutes=5)
        )

        return jsonify({"url":presigned_url})

@bp.route("/presignedUrlDeltas", methods=["GET"])
def getPresignedUrlDeltas():

    source_model = request.args.get("source_model")
    delta_name = request.args.get("delta_name")

    bucket_name = "models"
    source_model_path = "encryptedFiles/" + source_model + "/" + source_model
    object_name = "encryptedFiles/" + source_model + "/" + delta_name

    try:
        minio_client.stat_object(
            bucket_name = bucket_name,
            object_name = source_model_path
        )
    except Exception as e:
        return jsonify({"error":"Source Model doesn't exist!"}),400

    try:
        existing_product = minio_client.stat_object(
            bucket_name = bucket_name,
            object_name = object_name
        )
        if existing_product:
            return jsonify({"error":"Delta Name already existing in minio!"}), 400
    except Exception as e:
        presigned_url = minio_client.presigned_put_object(
            bucket_name = bucket_name,
            object_name = object_name,
            expires = timedelta(minutes = 5)
        )

        return presigned_url


@bp.route("/getAESKey", methods = ["GET"])
def getAESKey():

    filename = request.args.get("filename")
    user_id = request.args.get("user_id")

    attachement_metadata = Attachment.query.filter_by(filename = filename).first()
    encrypted_aes_key = attachement_metadata.encrypted_key

    secret_key_user_id = attachement_metadata.owned_by
    public_key_user_id = user_id

    prekey_infos = Prekey.query.filter_by(secret_key_user_id = secret_key_user_id, public_key_user_id = public_key_user_id).first()
    reencrypt_key = prekey_infos.prekey_value

    reencrypted_aes_key = reencrypt(encrypted_aes_key,reencrypt_key)

    return jsonify({
        "reencrypted_aes_key": reencrypted_aes_key,
        "iv":attachement_metadata.iv
    })




@bp.route("/getModel",methods = ["GET"])
def getModel():

    source_model = request.args.get("source_model")
    delta_name = request.args.get("delta_name")
    user_id = request.args.get("user_id")

    if not source_model or not user_id:
        return jsonify({"error":"Source model or user id doesn't exist"}),400
    
    bucket_name = "models"

    if delta_name:
        object_name = f"encryptedFiles/{source_model}/{delta_name}"
    else:
        object_name = f"encryptedFiles/{source_model}/{source_model}"

    try:
        minio_client.stat_object(bucket_name,object_name)
    except Exception as ex:
        return jsonify({"error":"File doesn't exist!"}),404
    
 
    obj = minio_client.get_object(bucket_name, object_name)
    file_bytes = obj.read()
    obj.close()
    obj.release_conn()

    return send_file(
        BytesIO(file_bytes),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=source_model
    )


@bp.route("/getById", methods = ["GET"])
def getById():

    id = request.args.get("id")

    attachment = Attachment.query.filter_by(id = id).first()

    return jsonify({
        "id" : id,
        "filename": attachment.filename
    })
