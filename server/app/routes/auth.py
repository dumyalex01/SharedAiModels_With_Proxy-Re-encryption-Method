from flask import Blueprint, request, jsonify
from app.models import User
from werkzeug.security import generate_password_hash,check_password_hash
from app.extensions import db 

bp = Blueprint("auth", __name__)

@bp.route("/login", methods = ["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}),400
    
    user = User.query.filter_by(username = username).first()
    if not user:
        return jsonify({"error":"User not found"}),404
    
    if not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Password didn't match"}), 401
    
    return jsonify({
        "message":"Login successfull!",
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "ecc_public_key": user.ecc_public_key
    }),200




@bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")
    ecc_public_key = data.get("ecc_public_key")

    if not username or not password or not ecc_public_key:
        return jsonify({"error": "Missing required fields"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already existing"}), 409
    
    password_hash = generate_password_hash(password)

    user = User(
        username=username,
        password_hash=password_hash,
        ecc_public_key=ecc_public_key,
        role=role
    )

    try:
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User registered successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@bp.route("/getKey", methods = ["GET"])
def getKey():

     user_id = request.args.get("user_id")
     
     if not user_id:
         return jsonify({"error":"User id is missing!"}),400
     
     user = User.query.filter_by(id = user_id).first()
  
     if not user:
         return jsonify({"error":"User doesn't exist!"}),404

     return jsonify({"ecc_public_key": user.ecc_public_key}),200
