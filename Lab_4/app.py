from flask import Flask, render_template, url_for, request, session, redirect, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from mysql_db import MySQL
import re
import hashlib


app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

db = MySQL(app)

login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к данной странице необходимо пройти аутентификацию'
login_manager.login_message_category = "warning" 

application = app


app.config.from_pyfile('config.py')

class User(UserMixin):
    def __init__(self, user_id, login, password_hash=None, first_name=None, last_name=None):
        self.id = user_id
        self.login = login
        self.password_hash = password_hash
        self.first_name = first_name
        self.last_name = last_name

    

@login_manager.user_loader
def load_user(user_id):
    # Создаем курсор для выполнения SQL-запросов к базе данных
    cursor = db.connection().cursor(named_tuple=True)
    
    # Определяем SQL-запрос для выбора пользователя по его ID
    query = 'SELECT id, login, password_hash, first_name, last_name FROM users3 WHERE users3.id = %s'
    
    # Выполняем SQL-запрос, подставляя значение user_id вместо плейсхолдера %s
    cursor.execute(query, (user_id,))
    
    # Извлекаем первую строку результата запроса (ожидаем, что ID уникален и будет только одна строка)
    user = cursor.fetchone()
    
    # Закрываем курсор, так как он больше не нужен
    cursor.close()
    
    # Если пользователь найден (не None), создаем и возвращаем объект User
    if user:
        return User(user.id, user.login, user.password_hash, user.first_name, user.last_name)
    
    # Если пользователь не найден, возвращаем None
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Проверка метода запроса
    if request.method == 'POST':
        # Получение данных из формы
        login = request.form['login']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        
        # Создание курсора и выполнение запроса к базе данных
        cursor = db.connection().cursor(named_tuple=True)
        query = 'SELECT * FROM users3 WHERE users3.login = %s'
        cursor.execute(query, (login,))
        user = cursor.fetchone()
        cursor.close()
        
        # Проверка наличия пользователя и соответствия пароля
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Аутентификация пользователя
            login_user(User(user.id, user.login), remember=remember)
            
            # Получение параметра 'next' из URL (для перенаправления)
            param = request.args.get('next')
            
            # Отправка флеш-сообщения об успешном входе
            flash('Успешный вход', 'success')
            
            # Перенаправление пользователя
            return redirect(param or url_for('index'))
        
        # Если логин или пароль неверны, отправка флеш-сообщения
        flash('Логин или пароль введены неверно', 'danger')
    
    # Возврат страницы логина (для GET-запросов или при ошибке)
    return render_template('login.html')
    

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/userlist')
@login_required
def userlist():
    # Создаем курсор для выполнения SQL-запросов к базе данных
    cursor = db.connection().cursor(named_tuple=True)
    
    # Определяем SQL-запрос для выбора всех пользователей с их ID, логином, именем и фамилией
    query = 'SELECT id, login, first_name, last_name FROM users3'
    
    # Выполняем SQL-запрос
    cursor.execute(query)
    
    # Извлекаем все строки результата запроса
    users = cursor.fetchall()
    
    # Закрываем курсор, так как он больше не нужен
    cursor.close()
    
    # Передаем полученные данные пользователей в шаблон 'userlist.html' и отображаем его
    return render_template('userlist.html', users=users)


@app.route('/createuser', methods=["GET", "POST"])
@login_required
def createuser():
    # Если метод запроса GET, отображаем форму для создания пользователя
    if request.method == 'GET':
        return render_template('createuser.html')
    
    # Если метод запроса POST, обрабатываем данные формы
    elif request.method == "POST":
        # Получаем данные формы
        login = request.form['login']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        
        # Валидируем данные пользователя
        errors = validate_user_data(login, password, first_name, last_name)
        
        # Если есть ошибки в данных, отображаем их
        if errors:
            for error in errors.values():
                flash(f'{error}', 'danger')
            return render_template('createuser.html', login=login, first_name=first_name, last_name=last_name)
        
        # Создаем курсор для выполнения SQL-запросов к базе данных
        cursor = db.connection().cursor(named_tuple=True)
        
        # Определяем SQL-запрос для вставки нового пользователя
        query = 'INSERT INTO users3 (login, password_hash, first_name, last_name) VALUES (%s, %s, %s, %s)'
        
        # Хэшируем пароль для безопасного хранения
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Значения для вставки в таблицу
        values = (login, password_hash, first_name, last_name)
        
        # Выполняем SQL-запрос
        cursor.execute(query, values)
        
        # Фиксируем изменения в базе данных
        db.connection().commit()
        
        # Закрываем курсор
        cursor.close()
        
        # Отображаем сообщение об успешном создании пользователя
        flash('Пользователь успешно создан', 'success')
        
        # Перенаправляем на страницу со списком пользователей
        return redirect(url_for('userlist'))


@app.route('/user/show/<int:user_id>')
@login_required
def show_user(user_id):
    # Создаем курсор для выполнения SQL-запросов
    cursor = db.connection().cursor(named_tuple=True)
    
    # Определяем SQL-запрос для выбора информации о пользователе на основе user_id
    query = 'SELECT id, login, first_name, last_name, middle_name FROM users3 WHERE id=%s'
    
    # Выполняем SQL-запрос, передавая user_id в качестве параметра
    cursor.execute(query, (user_id,))
    
    # Получаем первую строку результата запроса
    user = cursor.fetchone()
    
    # Закрываем курсор для освобождения ресурсов
    cursor.close()
    
    # Отображаем шаблон 'show_user.html' с информацией о пользователе
    return render_template('show_user.html', user=user)





@app.route('/user/edit/<int:user_id>', methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    # Если метод запроса POST, это означает, что данные формы отправлены для редактирования
    if request.method == 'POST':
        cursor = db.connection().cursor(named_tuple=True)
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        middle_name = request.form['middle_name']
        # Определяем SQL-запрос для обновления информации о пользователе
        query = 'UPDATE users3 SET first_name=%s, last_name=%s, middle_name=%s WHERE id=%s'
        
        # Выполняем SQL-запрос, передавая обновленную информацию о пользователе и его ID в качестве параметров
        cursor.execute(query, (first_name, last_name, middle_name, user_id))
        
        # Фиксируем изменения в базе данных
        db.connection().commit()
        cursor.close()
        
        # Выводим сообщение об успешном редактировании данных пользователя
        flash(f'Данные пользователя изменены', 'success')
        
        # Перенаправляем пользователя на страницу со списком пользователей после успешного редактирования
        return redirect(url_for('userlist'))
    
    # Если метод запроса GET, это означает, что пользователь хочет просмотреть форму для редактирования
    else:
        cursor = db.connection().cursor(named_tuple=True)
        # Определяем SQL-запрос для выбора информации о пользователе на основе его ID
        query = 'SELECT id, login, first_name, last_name FROM users3 WHERE id=%s'
        
        # Выполняем SQL-запрос, передавая ID пользователя в качестве параметра
        cursor.execute(query, (user_id,))
        
        # Получаем информацию о пользователе из результата запроса
        user = cursor.fetchone()
        cursor.close()
        
        # Отображаем шаблон 'edit_user.html' с информацией о пользователе для редактирования
        return render_template('edit_user.html', user=user)


@app.route('/user/delete/<int:user_id>', methods=["GET", "POST"])
@login_required
def delete_user(user_id):
    # Если метод запроса POST, это означает, что данные формы отправляются для удаления пользователя
    if request.method == 'POST':
        cursor = db.connection().cursor(named_tuple=True)
        
        # Получаем логин из данных формы
        login = request.form['login']
        
        # Определяем SQL-запрос для удаления пользователя на основе user_id
        query = 'DELETE FROM users3 WHERE id=%s'
        
        # Выполняем SQL-запрос, передавая user_id в качестве параметра
        cursor.execute(query, (user_id,))
        
        # Фиксируем изменения в базе данных
        db.connection().commit()
        cursor.close()
        
        # Выводим сообщение об успешном удалении пользователя
        flash(f'Пользователь {login} удален', 'success')
        
        # Перенаправляем пользователя на страницу со списком пользователей после успешного удаления
        return redirect(url_for('userlist'))
    
    # Если метод запроса GET, это означает, что пользователь хочет подтвердить удаление
    else:
        cursor = db.connection().cursor(named_tuple=True)
        # Определяем SQL-запрос для выбора информации о пользователе на основе user_id
        query = 'SELECT id, login, first_name, last_name FROM users3 WHERE id=%s'
        
        # Выполняем SQL-запрос, передавая user_id в качестве параметра
        cursor.execute(query, (user_id,))
        
        # Получаем информацию о пользователе из результата запроса


def validate_user_data(login, password, first_name, last_name):
    errors = {}
    # Проверка на наличие пустых значений
    if not login:
        errors['login'] = "Логин не может быть пустым"
    if not password:
        errors['password'] = "Пароль не может быть пустым"
    if not first_name:
        errors['first_name'] = "Имя не может быть пустым"
    if not last_name:
        errors['last_name'] = "Фамилия не может быть пустой"

    # Проверка логина
    if login and (len(login) < 5 or not re.match("^[a-zA-Z0-9]+$", login)):
        errors['login'] = "Логин должен состоять только из латинских букв и цифр и иметь длину не менее 5 символов"

    # Проверка пароля
    if password:
        if ' ' in password:
            errors['password'] = "Пароль не должен содержать пробелы"
        elif len(password) < 8:
            errors['password'] = "Пароль должен содержать не менее 8 символов"
        elif len(password) > 128:
            errors['password'] = "Пароль не должен превышать 128 символов"
        elif not re.search(r"[A-ZА-Я]", password) or not re.search(r"[a-zа-я]", password):
            errors['password'] = "Пароль должен содержать как минимум одну заглавную и одну строчную букву"
        elif not re.search(r"[0-9]", password):
            errors['password'] = "Пароль должен содержать минимум одну цифру"
        elif not re.match(r"^[a-zA-Zа-яА-Я0-9~!?@#$%^&*()_\-\+\[\]{}><\\|\"',.:;/]+$", password):
            errors['password'] = "Пароль содержит недопустимые символы"
        
    return errors

@app.route('/change_password/<int:user_id>', methods=["GET", "POST"])
@login_required
def change_password(user_id):
    # Словарь для хранения сообщений об ошибках
    error_messages = {}
    
    # Если метод запроса POST, значит данные формы отправляются для изменения пароля
    if request.method == 'POST':
        # Получаем старый, новый и подтвержденный пароли из данных формы
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Загружаем информацию о пользователе по его ID
        user = load_user(user_id)
        
        # Проверяем, совпадает ли указанный старый пароль с хэшем в базе данных
        if not user or not check_password_hash(user.password_hash, old_password):
            error_messages['old_password'] = 'Старый пароль указан неверно'
        
        # Проверяем, совпадают ли новый пароль и его подтверждение
        if new_password != confirm_password:
            error_messages['confirm_password'] = 'Пароли не совпадают'

        # Проверяем новый пароль на соответствие требованиям безопасности
        password_errors = validate_user_data(user.login, new_password, user.first_name, user.last_name).get('password', None)
        if password_errors:
            error_messages['password'] = password_errors
        
        # Если нет сообщений об ошибках, обновляем пароль в базе данных
        if not error_messages:
            try:
                cursor = db.connection().cursor(named_tuple=True)
                # Определяем SQL-запрос для обновления хэша пароля в базе данных
                query = 'UPDATE users3 SET password_hash=SHA2(%s, 256) WHERE id=%s'
                
                # Выполняем SQL-запрос, передавая новый пароль и ID пользователя в качестве параметров
                cursor.execute(query, (new_password, user.id))
                
                # Фиксируем изменения в базе данных
                db.connection().commit()
            except Exception as e:
                # В случае ошибки выводим сообщение об ошибке
                print("Ошибка обновления пароля:", e)
                flash('Произошла ошибка при смене пароля', 'danger')
            finally:
                cursor.close()
            
            flash('Пароль успешно изменен', 'success')
            return redirect(url_for('index'))

    # Отображаем страницу изменения пароля с сообщениями об ошибках
    return render_template('change_password.html', error_messages=error_messages)


def check_password_hash(stored_password_hash, provided_password):
    # Хэшируем предоставленный пароль с помощью SHA-256
    provided_password_hash = hashlib.sha256(provided_password.encode()).hexdigest()
    
    # Сравниваем полученный хэш с хранимым хэшем пароля
    # Если хэши совпадают, то пароль верный
    return provided_password_hash == stored_password_hash