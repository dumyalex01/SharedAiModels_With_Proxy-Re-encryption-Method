from flask import Blueprint, request, jsonify
from app.models import Request
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
    allRequests = Request.query.filter_by(request_status = status)
    result = []

    for myRequest in allRequests:
        result.append({
            "id":myRequest.id,
            "resource_id": myRequest.resource_id,
            "requested_by": myRequest.requested_by,
            "request_status": myRequest.request_status,
            "created_at": myRequest.created_at
        })
    
    return jsonify(result),200

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

    return jsonify({"message":"Request approved!"}),200

    