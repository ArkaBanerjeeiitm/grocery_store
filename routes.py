from flask import render_template,request,redirect,url_for,flash
from app import app
from models import  db,User,Product,Category,Cart,Order,Transaction
from werkzeug.security import generate_password_hash,check_password_hash

@app.route('/')
def index():
    return render_template('index.html')

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

