from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_me_in_prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///sotay.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='member')

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    if current_user.role == 'admin':
        notes = Note.query.order_by(Note.created_at.desc()).all()
    else:
        notes = Note.query.filter_by(member_id=current_user.id).order_by(Note.created_at.desc()).all()
    return render_template('index.html', notes=notes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(username=request.form['username']).first()
        if u and bcrypt.check_password_hash(u.password_hash, request.form['password']):
            login_user(u)
            return redirect(url_for('index'))
        flash('Thông tin đăng nhập sai', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/note/new', methods=['GET', 'POST'])
@login_required
def new_note():
    if request.method == 'POST':
        t = request.form.get('title')
        c = request.form.get('content')
        note = Note(member_id=current_user.id, title=t, content=c)
        db.session.add(note); db.session.commit()
        flash('Đã lưu ghi chú', 'success')
        return redirect(url_for('index'))
    return render_template('note_form.html')

@app.route('/note/<int:nid>/delete', methods=['POST'])
@login_required
def delete_note(nid):
    note = Note.query.get_or_404(nid)
    if current_user.role != 'admin' and note.member_id != current_user.id:
        flash('Không có quyền', 'danger')
        return redirect(url_for('index'))
    db.session.delete(note); db.session.commit()
    flash('Đã xóa', 'success')
    return redirect(url_for('index'))

# CLI helper để tạo admin (chạy 1 lần)
@app.cli.command('create-admin')
def create_admin():
    username = os.environ.get('ADMIN_USERNAME', 'admin')
    password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    if User.query.filter_by(username=username).first():
        print('admin đã tồn tại')
        return
    pw = bcrypt.generate_password_hash(password).decode('utf-8')
    u = User(username=username, password_hash=pw, role='admin')
    db.session.add(u); db.session.commit()
    print('admin created')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)