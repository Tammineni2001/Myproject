from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from auth import auth_bp
from csv_formatter import csv_formatter_bp
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

jwt = JWTManager(app)
bcrypt = Bcrypt(app)

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(csv_formatter_bp, url_prefix='/csv')

@app.route("/", methods=["GET"])
def home():
    return jsonify({"success": True, "message": "Welcome to the Flask JWT Authentication API!"}), 200

if __name__ == "__main__":
    app.run(debug=True)
