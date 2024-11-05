from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '123456'
login_manager = LoginManager(app)
login_manager.login_view = 'login'


users_db = {}


class User(UserMixin):
    def __init__(self, id, email, password, name):
        self.id = id
        self.email = email
        self.password = password
        self.name = name


@login_manager.user_loader
def load_user(user_id):
    return users_db.get(user_id)


@app.route('/')
@login_required
def index():
    return render_template('index.html', name=current_user.name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = next((u for u in users_db.values() if u.email == email), None)

        if user is None:
            flash('Пользователь не найден.')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            flash('Неверный пароль.')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if email in (user.email for user in users_db.values()):
            flash('Пользователь уже существует.')
            return redirect(url_for('signup'))

        new_user = User(id=email, email=email, password=generate_password_hash(password), name=name)
        users_db[email] = new_user

        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)