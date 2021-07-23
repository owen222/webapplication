from flask import Blueprint, render_template, make_response, request, flash, jsonify
from . import db
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
auth = Blueprint('auth', __name__)


@auth.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user_email = data.get('email')
    user_password = data.get('password')

    user = db.session.execute(f"SELECT * FROM User WHERE email = '{user_email}' AND password = '{user_password}'").first()

    if user:
        return make_response(jsonify({'message': 'Login succesful'}), 200)

    else:
        if User.query.filter_by(email=user_email).first():
            return make_response(jsonify({'message': 'Password incorrect.'}), 401)

        elif User.query.filter_by(password=user_password).first():
            return make_response(jsonify({'message': 'No user with that email.'}), 401)

        else:
            return make_response(jsonify({'message': 'No user with that email and password'}), 401)


@auth.route('/api/sign-up', methods=['POST'])
def api_sign_up():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user or len(email) < 4:
        return make_response(jsonify({'message': 'Sign up form invalid.'}), 401)
    else:
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return make_response(jsonify({'message': 'New user created.'}), 201)


@auth.route('/login')
def login():
    return render_template("login.html")


@auth.route('/sign-up')
def sign_up():
    return render_template("sign_up.html")




