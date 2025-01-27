from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from functools import wraps
import json

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "Mysecretkey123"

jwt = JWTManager(app)
bcrypt = Bcrypt(app)


def load_users():
    try:
        with open('sample_db.json', 'r') as f:
            data = json.load(f)
            users_dict = {}
            if "users" in data:
                for user in data["users"]:
                    users_dict[user["username"]] = {
                        "password_hash": bcrypt.generate_password_hash(user["password"]).decode("utf-8"),
                        "role": "user"  
                    }
            for key, value in data.items():
                if key != "users":
                    users_dict[key] = value
            return users_dict
    except FileNotFoundError:
        return {}


def save_users(users):
    with open('sample_db.json', 'w') as f:
        json.dump(users, f, indent=4)

users = load_users()

@app.route("/", methods=["GET"])
def home():
    return format_response(True, "Welcome to the Flask JWT Authentication API!"), 200

class User:
    def __init__(self, username, password, role="user"):
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        self.role = role

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            identity = json.loads(get_jwt_identity())
            if not identity or identity.get("role") != required_role:
                return format_response(False, "Access forbidden"), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator

def format_response(success, message, data=None):
    response = {
        "success": success,
        "message": message
    }
    if data:
        response["data"] = data
    return jsonify(response)

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    if not username or not password:
        return format_response(False, "Username and password are required"), 400

    if username in users:
        return format_response(False, "User already exists"), 400

    users[username] = {
        "password_hash": bcrypt.generate_password_hash(password).decode("utf-8"),
        "role": role
    }
    save_users(users)
    return format_response(True, "User registered successfully"), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return format_response(False, "Username and password are required"), 400

    user_data = users.get(username)
    if not user_data or not bcrypt.check_password_hash(user_data["password_hash"], password):
        return format_response(False, "Invalid username or password"), 401

    access_token = create_access_token(identity=json.dumps({"username": username, "role": user_data["role"]}))
    return format_response(True, "Login successful", {"access_token": access_token}), 200

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return format_response(True, "You have accessed a protected route"), 200

@app.route("/admin/dashboard", methods=["GET"])
@jwt_required()
@role_required("admin")
def admin_dashboard():
    return format_response(True, "Welcome to the Admin Dashboard!"), 200

@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    try:
        users_data = [{"username": username, "role": user_data["role"]} for username, user_data in users.items()]
        return format_response(True, "Users fetched successfully", users_data), 200
    except Exception as e:
        return format_response(False, str(e)), 500

@app.errorhandler(Exception)
def handle_exception(e):
    return format_response(False, str(e)), 500

if __name__ == "__main__":
    app.run(debug=True)