from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from UserLogin import UserLogin
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = 'jhjsakhdjkahjdkhaksjd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Log_Pas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)


class Messages(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(300), nullable=False)
    recipient = db.Column(db.String(300), nullable=False)
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
            return redirect(url_for('data'))
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
        return render_template('main.html')
    except:
        return render_template('user_anonim.html')


@app.route('/register', methods=['POST', 'GET'])
def reg():
    if request.method == "POST":
        if (request.form['password'] == request.form['password2']) and len(request.form['password']) > 5:
            res = User.query.all()
            for i in range(len(res)):
                if res[i].login == request.form['login']:
                    return render_template("error_login.html")
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


@app.route('/main')
@login_required
def data():
    return render_template('main.html')


if __name__ == '__main__':
    app.run()
