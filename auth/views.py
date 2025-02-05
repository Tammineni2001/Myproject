from flask import request, jsonify
from flask.views import MethodView
from flask_jwt_extended import create_access_token, jwt_required
from auth.forms import RegistrationForm, LoginForm
from db import initialize_connection
from sqlalchemy import text
from auth import bcrypt
from auth.utils import role_required

class RegisterView(MethodView):
    def post(self):
        form = RegistrationForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            email = request.json.get("email")
            confirm_password = request.json.get("confirm_password")
            role = request.json.get("role")

            if password != confirm_password:
                return jsonify({"success": False, "message": "Passwords do not match"}), 400

            if not role or role not in ["user", "admin"]:
                return jsonify({"success": False, "message": "Invalid role. Role must be 'user' or 'admin'."}), 400

            engine, session, Base = initialize_connection("JR_TRAINING_DB")
            
            try:
                query = text("SELECT * FROM public.users WHERE name = :username OR mail = :email")
                result = session.execute(query, {"username": username, "email": email})
                res = result.fetchall()
              
                for user_data in res:
                    if user_data["name"] == username or user_data["mail"] == email:
                        return jsonify({"success": False, "message": "User already exists"}), 400

                password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

                insert_query = text("""
                    INSERT INTO public.users (name, mail, password, role)
                    VALUES (:username, :email, :password_hash, :role)
                """)
                session.execute(insert_query, {"username": username, "email": email, "password_hash": password_hash, "role": role})
                session.commit()

                return jsonify({"success": True, "message": "User registered successfully"}), 201

            except Exception as e:
                session.rollback()
                return jsonify({"success": False, "message": "An error occurred during registration", "error": str(e)}), 500

            finally:
                session.close()

        else:
            errors = form.errors
            return jsonify({"success": False, "message": "Validation failed", "errors": errors}), 400

class LoginView(MethodView):
    def post(self):
        form = LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            mail = request.json.get("mail")

            engine, session, Base = initialize_connection("JR_TRAINING_DB")
            
            try:
                query = f"""
                SELECT * FROM public.users WHERE name = '{username}' AND mail = '{mail}'
                """
                result = session.execute(text(query))
                res = result.fetchall()

                if not res:
                    return jsonify({"success": False, "message": "Invalid Username or Email"}), 400

                for user_data in res:
           
                    if bcrypt.check_password_hash(user_data["password_hash"], password):
                        access_token = create_access_token(identity={"username": username, "role": user_data["role"]})
                        return jsonify({"success": True, "message": "Login successful", "access_token": access_token}), 200
                    else:
                        return jsonify({"success": False, "message": "Invalid Password"}), 400

            except Exception as e:
                return jsonify({"success": False, "message": "An error occurred during login", "error": str(e)}), 500

            finally:
                session.close()

        else:
            errors = form.errors
            return jsonify({"success": False, "message": "Validation failed", "errors": errors}), 400

class AdminDashboardView(MethodView):
    @jwt_required()
    @role_required("admin")
    def get(self):
        return jsonify({"success": True, "message": "Welcome to the Admin Dashboard!"}), 200
