from flask import Blueprint, request, jsonify
from app.models import Request,Attachment
from werkzeug.security import generate_password_hash,check_password_hash
from app.extensions import db 

bp = Blueprint("request",__name__)

@bp.route("/create", methods = ["POST"])
def create():

    data = request.get_json()

    resource_id = data.get("resource_id")
    requested_by = data.get("requested_by")
    request_status = "pending"

    if not resource_id or not requested_by:
        return jsonify({"error":"Resource or requester not selected"}),400
    
    if Request.query.filter_by(resource_id = resource_id, requested_by = requested_by).first():
        return jsonify({"error":"You already requested access for this resource"}),400
    
    myRequest = Request(
        resource_id = resource_id,
        requested_by = requested_by,
        request_status = request_status
    )

    try:
        db.session.add(myRequest)
        db.session.commit()
        return jsonify({"message":"Request has been added!"}),200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error":str(e)}),500

@bp.route("/get", methods=["GET"])
def getAll():
    status = request.args.get("status")
    user_id = request.args.get("user_id")

    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    result = []

    if status == "approved":
        approved_requests = Request.query.filter_by(
            request_status="approved",
            requested_by=user_id
        ).all()

        for req in approved_requests:
            result.append({
                "id": req.id,
                "resource_id": req.resource_id,
                "requested_by": req.requested_by,
                "request_status": req.request_status,
                "created_at": req.created_at
            })

    elif status == "pending":
        user_attachments = Attachment.query.filter_by(owned_by=user_id).all()
        attachment_ids = [att.id for att in user_attachments]

        if attachment_ids:
            pending_requests = Request.query.filter(
                Request.request_status == "pending",
                Request.resource_id.in_(attachment_ids)
            ).all()

            for req in pending_requests:
                result.append({
                    "id": req.id,
                    "resource_id": req.resource_id,
                    "requested_by": req.requested_by,
                    "request_status": req.request_status,
                    "created_at": req.created_at
                })

    return jsonify(result), 200


@bp.route("/changeStatus", methods = ["POST"])
def changeStatus():

    data = request.get_json()

    id = data.get("id")
    new_status = data.get("new_status")
    print(new_status)

    if new_status != "approved" and new_status != "rejected":
        return jsonify({"error":"Status unavailable"}),400

    req = Request.query.filter_by(id = id).first()
    if not req:
        return jsonify({"error":"Request not found!"}),404
    
    req.request_status = new_status
    db.session.commit()
    


    if new_status == "approved":

        return jsonify({
            "message": "Request approved!",
            "downloader_id": req.requested_by
        })
        
    return jsonify({"message":"Request approved!"}),200

    