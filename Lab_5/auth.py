from flask import render_template,url_for, request, redirect, flash, Blueprint, g, redirect
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from functools import wraps
from app import db
from check_rights import CheckRights


bp_auth = Blueprint('auth', __name__, url_prefix='/auth')


def check_perm(rule):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = load_user(kwargs.get('user_id', None))
            if current_user.can(rule, user):
                return f(*args, **kwargs)
            flash(f'Permission denied','warning')
            return redirect(url_for('userlist'))
        return decorated_function
    return decorator


ADMIN_ROLE_ID = 1

def init_login_manager(app):
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Для доступа к данной странице необходимо пройти аутентификацию'
    login_manager.login_message_category = "warning"
    login_manager.user_loader(load_user)


class User(UserMixin):
    def __init__(self, user_id, login, role_id):
        self.id = user_id
        self.login = login
        self.role_id = role_id
    
    def is_admin(self):
        return self.role_id == ADMIN_ROLE_ID
    
    def can(self, action, record=None):
        check = CheckRights(record)
        method = getattr(check, action, None)
        if method:
            return method()
        return False

        

def load_user(user_id):
    cursor = db.connection().cursor(named_tuple=True)
    query = 'SELECT id, login, role_id FROM users3 WHERE users3.id = %s'
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    if user:
        return User(user.id, user.login, user.role_id)
    return None


@bp_auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        cursor = db.connection().cursor(named_tuple=True)
        query = 'SELECT * FROM users3 WHERE users3.login = %s and users3.password_hash = SHA2(%s, 256)'
        cursor.execute(query, (login,password))
        user = cursor.fetchone()
        cursor.close()
        if user:
                login_user(User(user.id, user.login, user.role_id),remember = remember)
                param = request.args.get('next')
                flash('Успешный вход','success')
                return redirect(param or url_for('index'))
        flash('Логин или пароль введены неверно','danger')
    return render_template('login.html')
    

@bp_auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

