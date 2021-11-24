from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, send, emit, namespace, join_room, leave_room
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


class messages(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(300), nullable=False)
    room = db.Column(db.String(300), nullable=False)
    message = db.Column(db.String(300), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(300), nullable=False)
    password = db.Column(db.String(300), nullable=False)


class rooms(db.Model, UserMixin):
    room = db.Column(db.Integer, primary_key=True)
    user_one = db.Column(db.String(300), nullable=False)
    user_two = db.Column(db.String(300), nullable=False)


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
            return render_template('login.html')
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
        return render_template('main.html', friends=db.session.query(User.login).all(), user=current_user.login)
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
    room = 'global'
    user = current_user.login
    if rooms.query.filter_by(user_one=user, user_two=name).first():
        room = rooms.query.filter_by(user_one=user, user_two=name).first()
    elif rooms.query.filter_by(user_one=name, user_two=user).first():
        room = rooms.query.filter_by(user_one=name, user_two=user).first()
    else:
        res = rooms(user_one=user, user_two=name)
        try:
            db.session.add(res)
            db.session.commit()
            room = db.session.query(rooms).order_by(rooms.room)[-1]
        except:
            pass

    messages_list = messages.query.filter_by(room=room.room).all()
    return render_template('message.html', friend=name, friends=db.session.query(User.login).all(), user=current_user.login, room=room.room, messages=messages_list)


@socketio.on('message')
def handleMessage(data):
    username = data['username']
    print(data)
    room = data['room']
    msg = data['message']
    res = messages(sender=username, room=room, message=msg)
    try:
        db.session.add(res)
        db.session.commit()
    except:
        pass
    send({'message': msg, 'user': username}, to=room)


@socketio.on('join')
def on_join(data):
    username = data['username']
    room = data['room']
    friend = data['friend']
    print(username, friend)
    print(room)
    msg = username + ' has entered the room.'
    join_room(room)
    #send({'message': msg, 'user': username}, to=room)


@socketio.on('leave')
def on_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    send(username + ' has left the room.', to=room)


if __name__ == '__main__':
    #app.run()
    socketio.run(app)
