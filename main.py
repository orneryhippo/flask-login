from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_login import current_user
from icecream import ic 
from datetime import datetime 

import os 
app = Flask(__name__)
app.secret_key = os.urandom(24)

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email in users and users[email]['password'] == password:
            user = User()
            user.id = email
            login_user(user)
            return redirect(url_for('protected'))

        return 'Invalid credentials'

    return render_template('login.html')
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