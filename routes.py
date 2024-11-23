from flask import render_template,request,redirect,url_for,flash,session
from app import app
from models import  db,User,Product,Category,Cart,Order,Transaction
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps



@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email=request.form.get('email')
    password=request.form.get('password')
    user=User.query.filter_by(username=email).first()
    if not email or not password:
        flash('All fields are required')
        return redirect(url_for('login'))
    if not user:
        flash('User does not exist')
        return redirect(url_for('register'))
    if not check_password_hash(user.passhash,password):
        flash('Incorrect password')
        return redirect(url_for('login'))
    # return redirect(url_for('index'))
    session['user_id'] = user.id
    flash('Logged in successfully')
    return redirect(url_for('index'))
@app.route('/register')
def register():
    return render_template('register.html')
@app.route('/register', methods=['POST'])
def register_post():
    email=request.form.get('email')
    password=request.form.get('password')
    confirmpassword=request.form.get('confirmpassword')
    name=request.form.get('name')

    if not email or not password or not confirmpassword:
        flash('All fields are required')    
        return redirect(url_for('register'))

    if password != confirmpassword:
        flash('Passwords do not match')
        return redirect(url_for('register'))
    
    user=User.query.filter_by(username=email).first()

    if user:
        flash('User already exists')
        return redirect(url_for('login'))
    password_hash=generate_password_hash(password)
    
    new_user=User(username=email,passhash=password_hash,name=name)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))

def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else:
            flash('You are not logged in')
            return redirect(url_for('login'))
    return inner
@app.route('/')
@auth_required
def index():
    #user_id in session
   return render_template('index.html')


@app.route('/profile')
@auth_required
def profile():
    user=User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/profile', methods=['POST'])
@auth_required
def profile_post():
    email=request.form.get('email')
    cpassword=request.form.get('cpassword')
    password=request.form.get('password')
    name=request.form.get('name')

    if not email or not cpassword or not password or not name:
        flash('All fields are required')
        return redirect(url_for('profile'))
    user=User.query.get(session['user_id'])

    if not check_password_hash(user.passhash,cpassword):
        flash('Incorrect password')
    if user.username != email:
        new_email=User.query.filter_by(username=email).first()
        if new_email:
            flash('Email already exists')
            return redirect(url_for('profile'))
        user.username=email

    new_password_hash=generate_password_hash(password)
    user.passhash=new_password_hash
    user.name=name
    # if password:
    #     user.passhash=generate_password_hash(password)
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('profile'))
@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

