from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, send, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime


app = Flask(__name__)
app.secret_key = 'jhjsakhdjkahjdkhaksjd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Log_Pas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)


class Messages(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(300), nullable=False)
    recipient = db.Column(db.String(300), nullable=True)
    message = db.Column(db.String(300), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(300), nullable=False)
    password = db.Column(db.String(300), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()

        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main'))
        else:
            return render_template('error_password.html')
    else:
        return render_template('login.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main'))


@app.route('/')
def main():
    try:
        print(current_user.login)
        return render_template('main.html', friends=db.session.query(User.login).all())
    except:
        return render_template('user_anonim.html')


@app.route('/register', methods=['POST', 'GET'])
def reg():
    if request.method == "POST":
        if (request.form['password'] == request.form['password2']) and len(request.form['password']) > 5:
            if User.query.filter_by(login=request.form['login']).first():
                return "Произошла ошибка"
            else:
                print('1')
                login = request.form['login']
                password = generate_password_hash(request.form['password'])

                reg = User(login=login, password=password)
                try:
                    db.session.add(reg)
                    db.session.commit()
                    return redirect(url_for('login'))
                except:
                    return "Произошла ошибка"
        else:
            return render_template("error_password.html")
    else:
        return render_template("register.html")


@app.route('/message/<string:name>', methods=['POST', 'GET'])
@login_required
def data(name):
    if request.method == "POST":
        print(request.form['mes'])
        print(name)
        print(current_user.login)
    return render_template('message.html', name=name, friends=db.session.query(User.login).all())


@socketio.on('message')
def handleMessage(msg):
    print('message: ' + msg)
    send(msg, broadcast=True)


if __name__ == '__main__':
    #app.run()
    socketio.run(app)
