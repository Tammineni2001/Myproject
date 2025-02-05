from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from functools import wraps
import json

def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            identity = json.loads(get_jwt_identity())
            if not identity or identity.get("role") != required_role:
                return jsonify({"success": False, "message": "Access forbidden"}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator
