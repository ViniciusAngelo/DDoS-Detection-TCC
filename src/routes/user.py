from flask import Blueprint, jsonify # type: ignore

user_bp = Blueprint("user", __name__)

@user_bp.route("/user", methods=["GET"])
def get_user():
    return jsonify({"message": "User route working"})
