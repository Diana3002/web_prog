from flask import Flask, render_template, make_response, request

app = Flask(__name__)

application = app

@app.route('/') 
def index():
    return render_template('index.html') 

@app.route('/url')
def url():
    return render_template('url.html')
    
@app.route('/headers')
def headers():
    return render_template('headers.html')

@app.route('/cookies')
def cookies():
    resp = make_response(render_template('cookies.html'))
    if 'user' in request.cookies:
        resp.delete_cookie('user')
    else:    
        resp.set_cookie('user','admin')
    return resp

@app.route('/forms', methods=['GET', 'POST'])
def forms():
    # if request.method == "POST"
    return render_template('forms.html')


@app.route('/calc')
def calc():
    a = float(request.args.get('a',0))
    b = float(request.args.get('b',0))
    operator = request.args.get('operator')


    result = 0
    if operator == "+":
        result = a+b
    elif operator == "-":
        result = a-b
    elif operator == "*":
        result = a*b
    elif operator == "/":
        result = a/b

    return render_template('calc.html', result=result)

@app.route('/phone', methods=['POST', 'GET'])
def phone():
    error = None
    format_phone = ''
    if request.method == "POST":
        additional_symvols = [' ', '(', ')', '-', '.', '+']

        phone_num = request.form['phone']

        digits = [i for i in phone_num if i.isdigit()]

        for i in phone_num:
            if i.isdigit() == False and i not in additional_symvols:
                error = 'Недопустимый ввод. В номере телефона встречаются недопустимые символы.'
                return render_template('phone.html', error=error)

        if len(digits) not in [10, 11] or (len(digits) == 11 and digits[0] not in ['7', '8']):
            error = 'Недопустимый ввод. Неверное количество цифр.'
            return render_template('phone.html', error=error)
        
        if len(digits) == 10:
            digits.insert(0, 8)
        
        format_phone = f"{8}-{''.join(digits[1:4])}-{''.join(digits[4:7])}-{''.join(digits[7:9])}-{''.join(digits[9:])}"

    return render_template('phone.html', error=error, format_phone=format_phone)