from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_login import current_user
from flask_bcrypt import Bcrypt
import httpx
# import requests 

from icecream import ic 
from datetime import datetime 

import os 
app = Flask(__name__)
app.secret_key = os.urandom(32)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user database
users = {'jesse@cassill.work': {'password': 'fubar999!!!'}}

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    # Your logic to return a user object given the user_id
    return getUserById(user_id)  # Replace with your user retrieval logic


@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return

    user = User()
    user.id = email
    return user

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST','GET'])
def register():
    MSG = request.args.get('message',None) if request.method == 'GET' else request.form.get('message',None)

    if request.method == 'GET':
        ic(MSG)
        if MSG is not None:
            return render_template('register.html',message=MSG)
        else:
            return render_template('register.html', message=MSG)
        
    user_id = request.form['email']
    plain_password = request.form['password']

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(plain_password).decode('utf-8')

    # Store user_id and hashed_password in your Xano database
    store_user_url = "https://x8ki-letl-twmt.n7.xano.io/api:KPiD297b/simple_login"
    # ...
    HEADERS = {}
    BODY = {"user_id": user_id, "password":hashed_password}
    response  = httpx.post(store_user_url, headers=HEADERS, json=BODY)
    data = response.json()
    ic(data)
    if response.status_code == 200 and data.get('user_created',None) is not None:
        # return 'User registered successfully', response.status_code
        return redirect(url_for('login', message="User Registered Successfully. Please Log In."))
    else:
        return redirect(url_for('register', message="User Already Exists"))

@app.route('/login', methods=['POST','GET'])
def login():
    try:
        if request.method == 'GET':
            return render_template('login.html')
        
        login_id = request.form['email']
        plain_password = request.form['password']
        # Retrieve the hashed password from your Xano database based on user_id
        # https://x8ki-letl-twmt.n7.xano.io/api:KPiD297b/simple_login/{simple_login_id}
        get_user_url = f"https://x8ki-letl-twmt.n7.xano.io/api:KPiD297b/simple_login_by_id?login_id={login_id}"
        HEADERS={}
        BODY={}
        response = httpx.get(get_user_url,headers=HEADERS)
        ic(response.status_code)
        stored_hashed_password = ""
        if (response.status_code == 200):
            response_records = response.json()
            if len(response_records) == 1:
                user_record = response_records[0]
                stored_hashed_password = user_record.get('password',"")
        # Let's assume you get it in a variable `stored_hashed_password`
        # ...

        # Verify the password
        if bcrypt.check_password_hash(stored_hashed_password, plain_password):
            ic('Login successful')
            return render_template('protected.html',user=user_record.get('user_id',""))
        else:
            ic('Invalid user ID or password')
            return render_template('login.html', message="Invalid Login")
    except Exception as e:
        ic(e)
    # finally:
        # return render_template('login.html', message=None)

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
#         if email in users and users[email]['password'] == password:
#             user = User()
#             user.id = email
#             login_user(user)
#             return redirect(url_for('protected'))

#         return 'Invalid credentials'

#     return render_template('login.html')

# this is some stupid shit replit does for some reason. make it go away.
@app.route('/srcdoc')
def srcdoc():
  return redirect(url_for('index'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/protected')
@login_required
def protected():
    ic(current_user.id)
    now = datetime.now()
    ic(now.timestamp())
    return render_template('protected.html')
    # return 'Logged in as: ' + current_user.get_id()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=81)