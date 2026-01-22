from flask import Blueprint, request, jsonify
from app.models import Attachment
from app.extensions import db,minio_client 

bp = Blueprint("attachment",__name__)

@bp.route("/add",methods = ["POST"])
def add():
    
    data = request.get_json()

    filename = data.get("filename")

    if not filename:
        return jsonify({"error":"Not filename in request"}),400
    
    if Attachment.query.filter_by(filename = filename).first():
        return jsonify({"error":"This filename already exists in drive!"}),400
    file_path = f"encryptedFiles/{filename}"

    attachment = Attachment(
        filename = filename,
        file_path = file_path,
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
            "uploaded_at": attachment.uploaded_at
        })
    
    return jsonify(results),200

@bp.route("/presignedUrl", methods=["GET"])
def getPresignedUrl():

    filename = request.args.get("filename")
#MINIO PRESIGNED URL PENTRU A INCARCA CRIPTAT UN FISIER - 1 endpoint
#MINIO PENTRU A TRAGE UN ANUMIT FISIER(IL GASESC IN BAZA DE DATE CE PATH ARE IN MINIO) si ma folosesc de
# id-ul user-ului curent(il trimit ca parametru) pentru a face reencryption la invel de server
# FLUX:
# OBTIN CHEIA PE BAZA ID-ULUI LA DESCARCARE - endpoint-ul din keys
# O TRIMIT CA PARAMETRU PENTRU DESCARCAREA DIN MINIO
# IN ENDPOINTUL ACESTA CU MINIO FAC RECRIPTARE CU CHEIA DIN PARAMETRU
# TRAG FISIERUL DORIT PE ENDPOINT 