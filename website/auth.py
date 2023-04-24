from flask import Blueprint, render_template, request , flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash 
from . import db
from flask_login import login_user, login_required, logout_user, current_user

import re

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'  
regexPassword ='^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'

def check(email):
    if(re.search(regex,email)):
        return True
    else:
        return False
    
def check(password):
    if(re.search(regexPassword, password)):
        return True
    else:
        return False

auth = Blueprint('auth',__name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in Successfully!!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password, try again',  category='error')
        else:
                flash('User does not exists',  category='error')
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first() 
   
        if user:
            flash('Email already exists', category='error')
        elif len(email) < 4:
            isEmail = check(email)
            if(isEmail):
                flash("Valid Email.", category="success") 
            else:
                flash("Email must have more than four characters.", category="error")
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 9:
            isPassword = check(password1)
            if(isPassword):
                flash("Valid Password.", category="success") 
            else:
                flash('Password must be at least 8 characters with one number and one special character ', category='error')
        else:
            new_User = User(email = email, first_name= first_name, password= generate_password_hash(password1, method="sha256"))
            db.session.add(new_User)
            db.session.commit()
            flash("Account Created", category="success")
            return redirect(url_for('views.home'))    

    return render_template("sign-up.html", user=current_user)