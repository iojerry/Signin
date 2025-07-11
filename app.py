from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from sqlalchemy import func

load_dotenv()

def nocache(view_func):
    def wrapper(*args, **kwargs):
        response = make_response(view_func(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    wrapper.__name__ = view_func.__name__
    return wrapper

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'jerry_chhoti')

UPLOAD_FOLDER = os.path.join('static', 'uploads')
DB_FILE_PATH = os.path.join('users.db')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_FILE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=30)

# Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='password-reset')

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='password-reset', max_age=expiration)
        return email
    except Exception:
        return None

db = SQLAlchemy(app)

# ----------------- Models -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    image_filename = db.Column(db.String(200))

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# ----------------- Routes -----------------
@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        city = request.form.get('city')
        mobile = request.form.get('mobile')
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')
        photo = request.files.get('photo')

        if not all([name, city, mobile, email, password]):
            flash('All fields are required.', 'error')
            return render_template('index.html', name=name, city=city, mobile=mobile, email=email)

        if User.query.filter(func.lower(User.email) == email).first():
            flash('Email already registered.', 'error')
            return render_template('index.html', name=name, city=city, mobile=mobile, email=email)

        filename = None
        if photo and photo.filename:
            filename = secure_filename(photo.filename)
            try:
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            except Exception:
                flash('Failed to save image.', 'error')
                return render_template('index.html', name=name, city=city, mobile=mobile, email=email)

        hashed_pw = generate_password_hash(password)
        new_user = User(
            name=name,
            city=city,
            mobile=mobile,
            email=email,
            password=hashed_pw,
            image_filename=f'uploads/{filename}' if filename else None
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registered successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception:
            db.session.rollback()
            flash('An error occurred while saving your data.', 'error')

    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password')
        remember = request.form.get('remember')

        user = User.query.filter(func.lower(User.email) == email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            if remember:
                session.permanent = True
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/dashboard')
@nocache
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            flash('Admin logged in successfully.', 'success')
            return redirect(url_for('admin_dashboard'))

        flash('Invalid admin credentials.', 'error')
    return render_template('admin_login.html')

@app.route('/admin')
@nocache
def admin_dashboard():
    if not session.get('admin_id'):
        flash('Please log in as admin.', 'error')
        return redirect(url_for('admin_login'))

    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin-settings', methods=['GET', 'POST'])
@nocache
def admin_settings():
    if not session.get('admin_id'):
        flash('Login as admin to access settings.', 'error')
        return redirect(url_for('admin_login'))

    admin = Admin.query.get(session['admin_id'])

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        current_password = request.form.get('current_password')

        if not new_username or not current_password:
            flash('Username and current password are required.', 'error')
            return redirect(url_for('admin_settings'))

        if not check_password_hash(admin.password, current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('admin_settings'))

        admin.username = new_username

        if new_password:
            admin.password = generate_password_hash(new_password)

        try:
            db.session.commit()
            flash('Admin credentials updated. Please log in again.', 'success')
            session.clear()
            return redirect(url_for('admin_login'))
        except:
            db.session.rollback()
            flash('Update failed. Try again.', 'error')
            return redirect(url_for('admin_settings'))

    return render_template('admin_settings.html', admin=admin)

@app.route('/logout-admin')
def logout_admin():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        if user.image_filename:
            image_path = os.path.join(app.static_folder, user.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    except Exception:
        db.session.rollback()
        flash('Error deleting user.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter(func.lower(User.email) == email).first()
        if user:
            token = generate_reset_token(email)
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_link}\n\nIf you didn't request this, ignore this email."
            mail.send(msg)
            flash('Password reset link sent to your email.', 'success')
        else:
            flash('Email not found.', 'error')
    return render_template('forgot_password.html')
    
    
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if not password or not confirm:
            flash('Both fields are required.', 'error')
            return render_template('reset_password.html')

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Password reset successful. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'error')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html')    
# ----------------- Main -----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8000)
