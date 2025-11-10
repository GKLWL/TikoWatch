from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
from sqlalchemy import event
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from flask_login import UserMixin



pymysql.install_as_MySQLdb()

# --- Initialize app ---
app = Flask(__name__)
app.config.from_pyfile('config.py')

# --- Initialize database ---
db = SQLAlchemy(app)

# --- Rate Limiter ---
limiter = Limiter(
    get_remote_address,
    storage_uri="redis://localhost:6379",
    app=app,
)

# --- File Helper Functions ---
def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    )

def delete_file_safely(filename):
    """Delete a file from uploads folder safely (if it exists)."""
    if not filename:
        return
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        app.logger.warning(f"Failed to delete file {filename}: {e}")

# ------------------ DATABASE MODELS ------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='member')  # member / moderator / admin

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    photo = db.Column(db.String(120), nullable=True)
    datetime = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    confirmations = db.relationship('Confirmation', backref='report', lazy=True)

class Confirmation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    area = db.Column(db.String(120), nullable=False)


@app.route('/moderator')
@login_required
def moderator_dashboard():
    if current_user.role not in ['moderator', 'admin']:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
    reports = Report.query.filter_by(status='Pending').all()
    return render_template('moderator.html', reports=reports)

@app.route('/approve/<int:report_id>', methods=['POST'])
@login_required
def approve_report(report_id):
    if current_user.role not in ['moderator', 'admin']:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('index'))

    report = Report.query.get_or_404(report_id)
    report.status = "Approved"
    db.session.commit()
    flash(f'Report "{report.title}" approved successfully.', "success")
    return redirect(url_for('moderator_dashboard'))


@app.route('/reject/<int:report_id>', methods=['POST'])
@login_required
def reject_report(report_id):
    if current_user.role not in ['moderator', 'admin']:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('index'))

    report = Report.query.get_or_404(report_id)
    report.status = "Rejected"
    db.session.commit()
    flash(f'Report "{report.title}" rejected.', "warning")
    return redirect(url_for('moderator_dashboard'))


# ===================== ADMIN PAGE =====================

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/reports')
@login_required
def admin_reports():
    if current_user.role != 'admin':
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for('index'))
    reports = Report.query.all()
    return render_template('admin_reports.html', reports=reports)


@app.route('/admin/delete_report/<int:report_id>', methods=['POST'])
@login_required
def admin_delete_report(report_id):
    # Only admins can delete reports
    if current_user.role != 'admin':
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for('index'))

    report = Report.query.get_or_404(report_id)

    # --- Step 1: Delete associated image file (if exists) ---
    delete_file_safely(report.photo)

    # --- Step 2: Delete all related confirmations to avoid orphaned entries ---
    Confirmation.query.filter_by(report_id=report.id).delete()

    # --- Step 3: Delete the report itself ---
    db.session.delete(report)
    db.session.commit()

    flash(f'Report "{report.title}" and all related data have been deleted.', "info")
    return redirect(url_for('admin_reports'))


@app.route('/promote/<username>', methods=['POST'])
@login_required
def promote_user(username):
    # Only admins can promote
    if current_user.role != 'admin':
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for('index'))

    # Find the user in the database
    user = User.query.filter_by(username=username).first()

    if user:
        if user.role == 'moderator':
            flash(f"{username} is already a moderator.", "info")
        else:
            user.role = 'moderator'
            db.session.commit()
            flash(f"{username} has been promoted to Moderator.", "success")
    else:
        flash("User not found.", "danger")

    return redirect(url_for('admin_dashboard'))


@app.route('/demote/<username>', methods=['POST'])
@login_required
def demote_user(username):
    # Only admins can demote
    if current_user.role != 'admin':
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for('index'))

    user = User.query.filter_by(username=username).first()

    if user:
        if user.username == 'admin':
            flash("You cannot demote the admin account.", "warning")
        elif user.role == 'member':
            flash(f"{username} is already a regular member.", "info")
        else:
            user.role = 'member'
            db.session.commit()
            flash(f"{username} has been demoted to Member.", "warning")
    else:
        flash("User not found.", "danger")

    return redirect(url_for('admin_dashboard'))


@app.route('/delete_user/<username>', methods=['POST'])
@login_required
def delete_user(username):
    # Only admins can delete
    if current_user.role != 'admin':
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for('index'))

    user = User.query.filter_by(username=username).first()

    if user:
        if user.username == 'admin':
            flash("You cannot delete the main admin account.", "warning")
        else:
            db.session.delete(user)
            db.session.commit()
            flash(f"User '{username}' has been deleted.", "danger")
    else:
        flash("User not found.", "danger")

    return redirect(url_for('admin_dashboard'))



# Track which user has confirmed which report
# Structure: { "username": {report_id1, report_id2, ...} }

@app.route('/report/<int:report_id>')
def report_detail(report_id):
    report = Report.query.get_or_404(report_id)

    # Restrict access if not approved
    if report.status != 'Approved' and (
        not current_user.is_authenticated or current_user.role not in ['moderator', 'admin']
    ):
        flash("This report is not available for public viewing.", "warning")
        return redirect(url_for('view_reports'))

    user_has_confirmed = False
    if current_user.is_authenticated:
        existing = Confirmation.query.filter_by(
            user_id=current_user.id, report_id=report_id
        ).first()
        user_has_confirmed = existing is not None

    return render_template('report_detail.html', report=report, user_has_confirmed=user_has_confirmed)




@app.route('/confirm/<int:report_id>', methods=['POST'])
@login_required
def confirm_sighting(report_id):
    report = Report.query.get_or_404(report_id)
    existing = Confirmation.query.filter_by(
        user_id=current_user.id, report_id=report_id
    ).first()

    if existing:
        flash("You’ve already confirmed this sighting.", "info")
    else:
        new_conf = Confirmation(user_id=current_user.id, report_id=report_id)
        db.session.add(new_conf)
        db.session.commit()
        flash("Your confirmation has been recorded. Thank you for helping the community!", "success")

    return redirect(url_for('report_detail', report_id=report_id))

@app.route('/reports')
def view_reports():
    query = request.args.get('q', '').lower()

    if current_user.is_authenticated and current_user.role in ['moderator', 'admin']:
        base_query = Report.query
    else:
        base_query = Report.query.filter_by(status='Approved')

    if query:
        reports = base_query.filter(
            (Report.title.ilike(f"%{query}%")) |
            (Report.location.ilike(f"%{query}%"))
        ).all()
    else:
        reports = base_query.all()

    return render_template('view_reports.html', reports=reports, query=query)




@app.route('/')
def index():
    reports = Report.query.filter_by(status='Approved').order_by(Report.id.desc()).limit(3).all()
    if current_user.is_authenticated and current_user.role in ['moderator', 'admin']:
        pending_count = Report.query.filter_by(status='Pending').count()
        if pending_count > 0:
            flash(f"There are {pending_count} report(s) awaiting review.", "info")
    return render_template('index.html', reports=reports)




login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@limiter.limit("5 per minute") 
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Capture where the user came from (default: home)
    next_page = request.args.get('next', url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Demo login
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

@limiter.limit("3 per minute")
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_report():
    if request.method == 'POST':
        file = request.files.get('photo')
        filename = None

        if file and allowed_file(file.filename):
            original_name = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4().hex}_{original_name}"
            filename = unique_name
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        elif file and file.filename != '':
            flash("Invalid file type. Only PNG, JPG, JPEG, or GIF allowed.", "danger")
            return redirect(url_for('submit_report'))

        new_report = Report(
            title=request.form['title'],
            location=request.form['location'],
            details=request.form['details'],
            datetime=datetime.now().strftime("%Y-%m-%d %H:%M"),
            user_id=current_user.id,
            photo=filename
        )
        db.session.add(new_report)
        db.session.commit()
        flash("Report submitted successfully!", "success")
        return redirect(url_for('index'))

    return render_template('submit_report.html')

@app.route('/profile')
@login_required
def profile():
    user_reports = Report.query.filter_by(user_id=current_user.id).all()
    subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
    return render_template(
        'profile.html',
        username=current_user.username,
        reports=user_reports,
        subscriptions=subscriptions
    )

@app.route('/add_subscription', methods=['POST'])
@login_required
def add_subscription():
    area = request.form.get('area')
    if not area:
        flash('Please enter an area name.', 'warning')
        return redirect(url_for('profile'))

    existing = Subscription.query.filter_by(user_id=current_user.id, area=area).first()
    if existing:
        flash(f'You are already subscribed to "{area}".', 'info')
        return redirect(url_for('profile'))

    new_sub = Subscription(user_id=current_user.id, area=area)
    db.session.add(new_sub)
    db.session.commit()
    flash(f'Subscribed to "{area}" successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/unsubscribe/<int:sub_id>', methods=['POST'])
@login_required
def unsubscribe(sub_id):
    sub = Subscription.query.get_or_404(sub_id)
    if sub.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('profile'))

    db.session.delete(sub)
    db.session.commit()
    flash(f'Unsubscribed from "{sub.area}".', 'info')
    return redirect(url_for('profile'))

@limiter.limit("3 per hour")
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash('Username or email already registered.', 'warning')
            return redirect(url_for('register'))
        # basic validation
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        # TODO: Save user to database later
        hashed_pw = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# --- Security Headers (CSP & other protections) ---
@app.after_request
def apply_security_headers(response):
    # Content Security Policy (CSP) - limits where resources can be loaded from
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net;"
    )

    # Prevent browsers from MIME-type sniffing a response away from declared type
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent the app from being embedded in iframes (clickjacking defense)
    response.headers["X-Frame-Options"] = "DENY"

    # Control how much referrer information should be sent
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Optional: Tell browsers to prefer HTTPS when possible
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Too many requests — please slow down and try again later.", "warning")
    return redirect(request.referrer or url_for('index'))

@event.listens_for(Report, 'after_delete')
def delete_report_image(mapper, connection, target):
    if target.photo:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], target.photo)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            app.logger.warning(f"Could not delete file {target.photo}: {e}")
        
if __name__ == '__main__':
    app.run(debug=False)

