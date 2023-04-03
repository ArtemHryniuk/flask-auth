from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_dance.contrib.github import make_github_blueprint, github
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Створення Flask додатку
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'

# Ініціалізація Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Github авторизація
github_blueprint = make_github_blueprint(client_id='00a02028f1b5a90ecc10', client_secret='b6d1fdee7faced13ac4176553e9b5fc5fed0d204')
app.register_blueprint(github_blueprint, url_prefix='/github_login')

# Клас користувача
class User(UserMixin):
    def __init__(self, id, username, password, is_admin=False):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin

# Список користувачів
users = [
    User(1, 'admin', 'password', is_admin=True),
    User(2, 'user1', 'password'),
    User(3, 'user2', 'password'),
    User(4, 'ArtemHryniuk', '^Artm0n$uk10o', is_admin=True),
]

# Функція для знаходження користувача за ідентифікатором
@login_manager.user_loader
def load_user(user_id):
    for user in users:
        if user.id == int(user_id):
            return user
    return None

def load_user_by_name(username):
    for user in users:
        if user.username == username:
            return user
    return None

# Головна сторінка
@app.route('/')
def index():
    return redirect(url_for('login'))

# Сторінка авторизації
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = None
        for u in users:
            if u.username == username and u.password == password:
                user = u
                break

        if not user:
            return render_template('login/login.html', error='Invalid Credentials. Please try again.')

        login_user(user)
        return redirect(request.args.get('next') or url_for('dashboard'))

    return render_template('login/login.html', error=error)

# Сторінка виходу
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Сторінка для адміністратора
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    return render_template('admin/admin.html')

# Сторінка для користувача
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin'))
        
    return render_template('dashboard/dashboard.html')

@app.route('/github-login')
def github_login():
    resp = github.get("/user")
    print(resp)
    
    if resp.ok:
        print('Authorized on Github')
        user_data = resp.json()
        print(user_data['login'])
        user = load_user_by_name(user_data['login'])
        print(user_data)
        if user and not current_user.is_authenticated:
            print('You are not authenticated')
            login_user(user)
            return redirect(url_for('dashboard'))
        elif not user:
            # Якщо користувач не знайдений, ви можете створити нового користувача
            # і додати його до списку користувачів або відобразити повідомлення про помилку
            return redirect(url_for('login'))
    else:
        print('Not authorized')
        return redirect(url_for("github.login"))

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)
