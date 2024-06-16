from flask import Flask, render_template,url_for, request, session, redirect, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required



app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к данной странице необходимо пройти аутентификацию'
login_manager.login_message_category = "warning" 

application = app


app.config.from_pyfile('config.py')

class User(UserMixin):
    def __init__(self, user_id, login):
        self.id = user_id
        self.login = login

    
def list_of_users():
    return [{'id': 1, 'login': 'user', 'password': '123'}]

@login_manager.user_loader
def load_user(user_id):
    for user in list_of_users():
        if int(user_id) == user['id']:
            return User(user['id'], user['login'])
    return None
        

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/counter')
def counter():
    if 'visits' in session:
        session['visits'] += 1   
    else:
        session['visits'] = 1
    return render_template('counter.html')

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        for user in list_of_users():
            if login == user['login'] and password == user['password']:
                login_user(User(user['id'], user['login']),remember = remember)
                param = request.args.get('next')
                flash('Успешный вход','success')
                return redirect(param or url_for('index'))
        flash('Логин или пароль введены неверно','danger')
    return render_template('login.html')
    

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))