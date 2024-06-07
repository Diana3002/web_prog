from flask import Flask, render_template,url_for, request, redirect, flash
from flask_login import login_required, current_user
from mysql_db import MySQL

app = Flask(__name__)
application = app

db = MySQL(app)

from auth import bp_auth, init_login_manager, check_perm
from eventlist import bp_eventlist

app.register_blueprint(bp_auth)
app.register_blueprint(bp_eventlist)

init_login_manager(app)

app.config.from_pyfile('config.py')

@app.before_request
def loger():
    path = request.path
    # Пропустить вставку, если запрос касается статических файлов или пользователь не аутентифицирован
    if request.endpoint == "static" or not current_user.is_authenticated:
        return
    
    user_id = getattr(current_user, "id", None)
    
    # Отладочное сообщение
    if user_id is None:
        print(f"Skipping event logging for unauthenticated user. Path: {path}")
        return
    
    try:
        cursor = db.connection().cursor(named_tuple=True)
        query = '''INSERT INTO eventlist (path, user_id, created_at) VALUES(%s, %s, NOW())'''
        cursor.execute(query, (path, user_id))
        db.connection().commit()
        cursor.close()
    except Exception as e:
        print(f"Error logging event: {e}")

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/userlist')
@login_required
def userlist():
    cursor = db.connection().cursor(named_tuple=True)
    query = '''SELECT users3.id, users3.login, users3.first_name, users3.last_name,
    roles3.name AS role_name FROM users3 LEFT JOIN roles3 ON users3.role_id = roles3.id'''
    cursor.execute(query)
    users = cursor.fetchall()
    cursor.close()
    return render_template('userlist.html', users=users)

def get_roles():
    cursor = db.connection().cursor(named_tuple=True)
    query = 'SELECT * FROM roles3'
    cursor.execute(query)
    roles = cursor.fetchall()
    cursor.close()
    return roles


@app.route('/createuser', methods=["GET", "POST"])
@login_required
@check_perm('create')
def createuser():
    if request.method == 'GET':
        roles = get_roles()
        return render_template('createuser.html', roles = roles)

    elif request.method == "POST":
        login = request.form['login']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        role = request.form['role']
        cursor = db.connection().cursor(named_tuple=True)
        query = '''INSERT INTO users3 (login, password_hash, first_name, last_name, role_id)
        VALUES (%s, SHA2(%s, 256), %s, %s, %s)'''
        values = (login, password, first_name, last_name, role)
        cursor.execute(query, values)
        db.connection().commit()
        cursor.close()
        flash('Пользователь успешно создан','success')
        return redirect(url_for('userlist'))

@app.route('/user/show/<int:user_id>')
@login_required
@check_perm('show')
def show_user(user_id):
    cursor = db.connection().cursor(named_tuple=True)
    query = '''SELECT users3.id, users3.login, users3.first_name, users3.last_name,
    roles3.name AS role_name FROM users3 LEFT JOIN roles3 ON users3.role_id = roles3.id WHERE users3.id=%s'''
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('show_user.html', user=user)



@app.route('/user/edit/<int:user_id>', methods=["GET", "POST"])
@login_required
@check_perm('edit')
def edit_user(user_id):
    if request.method == 'POST':
        cursor = db.connection().cursor(named_tuple=True)
        login = request.form['login']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        middle_name = request.form['middle_name']
        query = 'UPDATE users3 SET first_name=%s, last_name=%s, middle_name=%s WHERE id=%s'
        cursor.execute(query, (first_name, last_name, middle_name, user_id))
        db.connection().commit()
        cursor.close()
        flash(f'Данные пользователя {login} изменены','success')
        return redirect(url_for('userlist'))

    cursor = db.connection().cursor(named_tuple=True)
    query = '''SELECT users3.id, users3.login, users3.first_name, users3.last_name,
    roles3.name AS role_name FROM users3 LEFT JOIN roles3 ON users3.role_id = roles3.id WHERE users3.id=%s'''
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('edit_user.html', user=user)

@app.route('/user/delete/<int:user_id>', methods=["GET", "POST"])
@login_required
@check_perm('delete')
def delete_user(user_id):
    if request.method == 'POST':
        cursor = db.connection().cursor(named_tuple=True)
        login = request.form['login']
        query = 'DELETE FROM users3 WHERE id=%s'
        cursor.execute(query, (user_id,))
        db.connection().commit()
        cursor.close()
        flash(f'Пользователь {login} удалены','success')
        return redirect(url_for('userlist'))

    cursor = db.connection().cursor(named_tuple=True)
    query = 'SELECT id, login, first_name, last_name FROM users3 WHERE id=%s'
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('delete_user.html', user=user)
