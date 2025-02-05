from flask import request, jsonify
from flask_jwt_extended import jwt_required, create_access_token
from auth.utils import role_required
from auth.views import RegisterView, LoginView, AdminDashboardView
from auth.forms import LoginForm
from db import initialize_connection
from sqlalchemy import text
from auth import auth_bp
from auth import bcrypt

auth_bp.add_url_rule('/register', view_func=RegisterView.as_view('register'))
auth_bp.add_url_rule('/login', view_func=LoginView.as_view('login'))
auth_bp.add_url_rule('/admin/dashboard', view_func=AdminDashboardView.as_view('admin_dashboard'))
