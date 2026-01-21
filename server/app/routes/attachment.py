from flask import Blueprint, request, jsonify
from app.models import Attachment
from app.extensions import db 

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