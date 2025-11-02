import os
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort, send_file, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from config import Config
from models import Base, User, Ticket
from forms import RegisterForm, LoginForm, TicketForm, TicketUpdateForm
from flask_mail import Mail, Message
import io, csv, jwt, uuid
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

mail = Mail(app)

# DB setup
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], connect_args={"check_same_thread": False})
Base.metadata.create_all(engine)
SessionLocal = scoped_session(sessionmaker(bind=engine))
db = SessionLocal

# ensure uploads dir exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return db.query(User).get(int(user_id))

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.remove()

def generate_jwt(user):
    payload = {
        'sub': user.id,
        'exp': datetime.utcnow() + timedelta(seconds=app.config['JWT_EXP_SECONDS'])
    }
    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
    return token

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth:
            return jsonify({'error': 'authorization required'}), 401
        parts = auth.split()
        if parts[0].lower() != 'bearer' or len(parts) != 2:
            return jsonify({'error': 'invalid auth header'}), 401
        token = parts[1]
        try:
            payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            user = db.query(User).get(int(payload['sub']))
            if not user:
                return jsonify({'error':'user not found'}), 401
            request.current_user = user
        except Exception as e:
            return jsonify({'error': 'invalid token', 'msg': str(e)}), 401
        return f(*args, **kwargs)
    return decorated

# --- Routes for web UI (same as before) ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        existing = db.query(User).filter_by(email=form.email.data.lower()).first()
        if existing:
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        user = User(
            name=form.name.data,
            email=form.email.data.lower(),
            password_hash=generate_password_hash(form.password.data),
            role='user'
        )
        db.add(user)
        db.commit()
        flash('Registered. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.query(User).filter_by(email=form.email.data.lower()).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Logged in', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        tickets = db.query(Ticket).order_by(Ticket.date_created.desc()).all()
        users = db.query(User).all()
        return render_template('dashboard_admin.html', tickets=tickets, users=users)
    else:
        tickets = db.query(Ticket).filter_by(created_by=current_user.id).order_by(Ticket.date_created.desc()).all()
        return render_template('dashboard_user.html', tickets=tickets)

@app.route('/ticket/new', methods=['GET','POST'])
@login_required
def ticket_new():
    form = TicketForm()
    if form.validate_on_submit():
        # handle optional file upload (from web form)
        file = request.files.get('attachment')
        filename = None
        if file and file.filename:
            ext = os.path.splitext(file.filename)[1]
            filename = f"{uuid.uuid4().hex}{ext}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        t = Ticket(
            type=form.type.data,
            description=form.description.data,
            date_created=datetime.utcnow(),
            status='open',
            created_by=current_user.id,
            attachment=filename
        )
        db.add(t)
        db.commit()
        # Notify admins by email (if configured)
        try:
            admins = db.query(User).filter_by(role='admin').all()
            recipients = [a.email for a in admins if a.email]
            if recipients:
                msg = Message(subject=f'New ticket #{t.id}: {t.type}',
                              recipients=recipients,
                              body=f'New ticket submitted by {current_user.name} ({current_user.email})\n\nType: {t.type}\n\nDescription:\n{t.description}')
                mail.send(msg)
        except Exception as e:
            app.logger.debug('Mail send failed: %s', e)
        flash('Ticket submitted', 'success')
        return redirect(url_for('dashboard'))
    return render_template('ticket_edit.html', form=form, new=True)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # serve attachment if user is allowed (admin or owner)
    t = db.query(Ticket).filter_by(attachment=filename).first()
    if not t:
        abort(404)
    if current_user.role != 'admin' and t.created_by != current_user.id:
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/ticket/<int:ticket_id>')
@login_required
def ticket_view(ticket_id):
    t = db.query(Ticket).get(ticket_id)
    if not t:
        abort(404)
    if current_user.role != 'admin' and t.created_by != current_user.id:
        abort(403)
    return render_template('ticket_view.html', ticket=t)

@app.route('/ticket/<int:ticket_id>/edit', methods=['GET','POST'])
@login_required
def ticket_edit(ticket_id):
    if current_user.role != 'admin':
        abort(403)
    t = db.query(Ticket).get(ticket_id)
    if not t:
        abort(404)
    users = db.query(User).all()
    form = TicketUpdateForm()
    form.managed_by.choices = [(0, 'Unassigned')] + [(u.id, f"{u.name} ({u.email})") for u in users]
    if request.method == 'GET':
        form.status.data = t.status
        form.action_done.data = t.action_done or ''
        form.managed_by.data = t.managed_by or 0
    if form.validate_on_submit():
        t.status = form.status.data
        t.action_done = form.action_done.data
        t.managed_by = form.managed_by.data if form.managed_by.data != 0 else None
        db.add(t)
        db.commit()
        # Notify reporter about status change (if configured)
        try:
            reporter = db.query(User).get(t.created_by)
            if reporter and reporter.email:
                msg = Message(subject=f'Ticket #{t.id} updated: {t.status}',
                              recipients=[reporter.email],
                              body=f'Your ticket #{t.id} status has been changed to {t.status}.\n\nAction taken:\n{t.action_done or "(none)"}')
                mail.send(msg)
        except Exception as e:
            app.logger.debug('Mail send failed: %s', e)
        flash('Ticket updated', 'success')
        return redirect(url_for('ticket_view', ticket_id=t.id))
    return render_template('ticket_edit.html', form=form, ticket=t, new=False)

# CSV export (admin only)
@app.route('/admin/export_csv')
@login_required
def export_csv():
    if current_user.role != 'admin':
        abort(403)
    tickets = db.query(Ticket).order_by(Ticket.date_created.desc()).all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['id','date_created','type','description','action_done','status','created_by','managed_by','attachment'])
    for t in tickets:
        cw.writerow([t.id, t.date_created.isoformat(), t.type, (t.description or ''), (t.action_done or ''), t.status, t.created_by, t.managed_by or '', t.attachment or ''])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='tickets.csv')

# --- REST API (JSON) with JWT support ---
@app.route('/api/token', methods=['POST'])
def api_token():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error':'missing credentials'}), 400
    user = db.query(User).filter_by(email=email.lower()).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error':'invalid credentials'}), 401
    token = generate_jwt(user)
    return jsonify({'token': token})

@app.route('/api/tickets', methods=['GET'])
@jwt_required
def api_list_tickets():
    user = request.current_user
    if user.role == 'admin':
        tickets = db.query(Ticket).order_by(Ticket.date_created.desc()).all()
    else:
        tickets = db.query(Ticket).filter_by(created_by=user.id).order_by(Ticket.date_created.desc()).all()
    out = []
    for t in tickets:
        out.append({
            'id': t.id,
            'date_created': t.date_created.isoformat(),
            'type': t.type,
            'description': t.description,
            'action_done': t.action_done,
            'status': t.status,
            'created_by': t.created_by,
            'managed_by': t.managed_by,
            'attachment': t.attachment
        })
    return jsonify(out)

@app.route('/api/tickets', methods=['POST'])
@jwt_required
def api_create_ticket():
    user = request.current_user
    # accept form-data with optional file
    if request.content_type and 'multipart/form-data' in request.content_type:
        typ = request.form.get('type', 'other')
        description = request.form.get('description', '')
        file = request.files.get('attachment')
    else:
        data = request.get_json() or {}
        typ = data.get('type', 'other')
        description = data.get('description', '')
        file = None
    filename = None
    if file and getattr(file, 'filename', None):
        ext = os.path.splitext(file.filename)[1]
        filename = f"{uuid.uuid4().hex}{ext}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    t = Ticket(
        type=typ,
        description=description,
        date_created=datetime.utcnow(),
        status='open',
        created_by=user.id,
        attachment=filename
    )
    db.add(t)
    db.commit()
    return jsonify({'id': t.id}), 201

@app.route('/api/tickets/<int:ticket_id>', methods=['GET','PUT'])
@jwt_required
def api_ticket(ticket_id):
    user = request.current_user
    t = db.query(Ticket).get(ticket_id)
    if not t:
        return jsonify({'error':'not found'}), 404
    if request.method == 'GET':
        if user.role != 'admin' and t.created_by != user.id:
            return jsonify({'error':'forbidden'}), 403
        return jsonify({
            'id': t.id,
            'date_created': t.date_created.isoformat(),
            'type': t.type,
            'description': t.description,
            'action_done': t.action_done,
            'status': t.status,
            'created_by': t.created_by,
            'managed_by': t.managed_by,
            'attachment': t.attachment
        })
    else:
        if user.role != 'admin':
            return jsonify({'error':'forbidden'}), 403
        data = request.get_json() or {}
        t.type = data.get('type', t.type)
        t.description = data.get('description', t.description)
        t.action_done = data.get('action_done', t.action_done)
        t.status = data.get('status', t.status)
        t.managed_by = data.get('managed_by', t.managed_by)
        db.add(t)
        db.commit()
        return jsonify({'ok': True})

@app.route('/api/tickets/<int:ticket_id>/attachment', methods=['GET'])
@jwt_required
def api_get_attachment(ticket_id):
    user = request.current_user
    t = db.query(Ticket).get(ticket_id)
    if not t or not t.attachment:
        return jsonify({'error':'not found'}), 404
    if user.role != 'admin' and t.created_by != user.id:
        return jsonify({'error':'forbidden'}), 403
    return send_from_directory(app.config['UPLOAD_FOLDER'], t.attachment, as_attachment=True)

@app.route('/admin/create_user', methods=['POST'])
@login_required
def admin_create_user():
    if current_user.role != 'admin':
        return jsonify({'error':'forbidden'}), 403
    data = request.get_json() or {}
    if not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'error': 'missing fields'}), 400
    existing = db.query(User).filter_by(email=data['email'].lower()).first()
    if existing:
        return jsonify({'error': 'user exists'}), 400
    user = User(
        name=data['name'],
        email=data['email'].lower(),
        password_hash=generate_password_hash(data['password']),
        role=data.get('role','user')
    )
    db.add(user)
    db.commit()
    return jsonify({'id': user.id}), 201

@app.route('/bootstrap-admin')
def bootstrap_admin():
    admin = db.query(User).filter_by(role='admin').first()
    if admin:
        return 'Admin already exists.'
    admin_user = User(name='Admin', email='admin@example.com', password_hash=generate_password_hash('admin123'), role='admin')
    db.add(admin_user)
    db.commit()
    return 'Admin created with email admin@example.com and password admin123. Change it immediately.'

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
