import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.secret_key = os.environ.get('SECRET_KEY', 'your-fixed-secret-key-change-this')

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

db = SQLAlchemy(app)

# ── Model ─────────────────────────────────────────────────
class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80),  unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

# ── Login Required Decorator ──────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Home ──────────────────────────────────────────────────
@app.route('/')
@app.route('/index')
def home():
    return render_template('index.html')

# ── Register ──────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template('register.html', error='All fields are required')
        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters')
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')

        db.session.add(User(username=username, password=generate_password_hash(password)))
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

# ── Login ─────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user'] = username
            return redirect(url_for('home'))
        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

# ── User Logout ───────────────────────────────────────────
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# ── Admin Login ───────────────────────────────────────────
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect('/admin')

    if request.method == 'POST':
        if (request.form['username'] == ADMIN_USERNAME and
                request.form['password'] == ADMIN_PASSWORD):
            session['is_admin'] = True
            return redirect('/admin')
        return render_template('adminlogin.html', error='Wrong username or password')

    return render_template('adminlogin.html')

# ── Admin Panel ───────────────────────────────────────────
@app.route('/admin')
def admin_panel():
    if not session.get('is_admin'):
        return redirect('/admin/login')
    users = User.query.all()
    return render_template('admin.html', users=users)

# ── Admin Delete ──────────────────────────────────────────
@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def admin_delete(user_id):
    if not session.get('is_admin'):
        return redirect('/admin/login')
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.", "success")
    return redirect('/admin')

# ── Admin Edit ────────────────────────────────────────────
@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit(user_id):
    if not session.get('is_admin'):
        return redirect('/admin/login')

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_username = request.form['username'].strip()
        new_password = request.form.get('password', '').strip()

        existing = User.query.filter_by(username=new_username).first()
        if existing and existing.id != user.id:
            return render_template('user.html', user=user,
                                   error='Username already taken.')

        user.username = new_username
        if new_password:
            user.password = generate_password_hash(new_password)

        db.session.commit()
        flash(f"User '{user.username}' updated successfully.", "success")
        return redirect('/admin')

    return render_template('user.html', user=user)

# ── Admin Logout ──────────────────────────────────────────
@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect('/admin/login')
# ── Admin Add User ────────────────────────────────────────
@app.route('/admin/adduser', methods=['GET', 'POST'])
def admin_add_user():
    if not session.get('is_admin'):
        return redirect('/admin/login')

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Validation
        if not username or not password:
            return render_template('adduser.html', error='Both fields are required.')
        if len(password) < 8:
            return render_template('adduser.html', error='Password must be at least 8 characters.')
        if User.query.filter_by(username=username).first():
            return render_template('adduser.html', error='Username already exists.')

        # Save new user
        new_user = User(
            username=username,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{username}' created successfully.", "success")
        return redirect('/admin')

    return render_template('adduser.html')
if __name__ == '__main__':
    app.run(debug=True)