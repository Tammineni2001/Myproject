from flask import Blueprint
from flask_bcrypt import Bcrypt

auth_bp = Blueprint('auth_bp', __name__)
bcrypt = Bcrypt()

from auth import routes