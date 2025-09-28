from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
import os
from functools import wraps

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
    return render_template('note_form.html', note=None, action='create')

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


# --- helper: kiểm tra admin ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Bạn không có quyền truy cập trang này', 'danger')
            return redirect(url_for('index' if current_user.is_authenticated else 'login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------- Admin: danh sách users ----------
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.id.asc()).all()
    return render_template('users_list.html', users=users)

# ---------- Admin: tạo user mới ----------
@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_user():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        role = request.form.get('role', 'member')
        if not username or not password:
            flash('Vui lòng điền đủ tài khoản và mật khẩu', 'danger')
            return redirect(url_for('admin_create_user'))
        if User.query.filter_by(username=username).first():
            flash('Tài khoản đã tồn tại', 'danger')
            return redirect(url_for('admin_create_user'))
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        u = User(username=username, password_hash=pw_hash, role=role)
        db.session.add(u)
        db.session.commit()
        flash('Tạo tài khoản thành công', 'success')
        return redirect(url_for('admin_users'))
    return render_template('user_form.html', action='create', user=None)

# ---------- Admin: sửa user (chỉ role và reset mật khẩu) ----------
@app.route('/admin/users/<int:uid>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(uid):
    user = User.query.get_or_404(uid)
    if request.method == 'POST':
        # chỉ cho sửa role và reset password
        role = request.form.get('role', 'member')
        new_password = request.form.get('password')
        user.role = role
        if new_password:
            user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash('Cập nhật tài khoản thành công', 'success')
        return redirect(url_for('admin_users'))
    return render_template('user_form.html', action='edit', user=user)

# ---------- Admin: xóa user ----------
@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(uid):
    user = User.query.get_or_404(uid)
    # tránh xóa admin hiện tại bằng nhầm lẫn
    if user.id == current_user.id:
        flash('Không thể xóa chính bạn', 'danger')
        return redirect(url_for('admin_users'))
    db.session.delete(user); db.session.commit()
    flash('Đã xóa tài khoản', 'success')
    return redirect(url_for('admin_users'))


# Xem chi tiết 1 ghi chú
@app.route('/note/<int:nid>')
@login_required
def view_note(nid):
    note = Note.query.get_or_404(nid)
    # quyền: admin hoặc chính chủ mới xem (nếu muốn khác hãy sửa)
    if current_user.role != 'admin' and note.member_id != current_user.id:
        flash('Không có quyền xem ghi chú này', 'danger')
        return redirect(url_for('index'))
    return render_template('note_view.html', note=note)

# Chỉnh sửa 1 ghi chú
@app.route('/note/<int:nid>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(nid):
    note = Note.query.get_or_404(nid)
    # chỉ admin hoặc chủ sở hữu được chỉnh sửa
    if current_user.role != 'admin' and note.member_id != current_user.id:
        flash('Không có quyền chỉnh sửa ghi chú này', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        note.title = title
        note.content = content
        db.session.commit()
        flash('Cập nhật ghi chú thành công', 'success')
        return redirect(url_for('view_note', nid=note.id))

    # GET -> hiện form với dữ liệu hiện tại
    return render_template('note_form.html', note=note, action='edit')

with app.app_context():
    db.create_all()
    # auto tạo admin nếu chưa có
    if not User.query.filter_by(username="admin").first():
        pw = bcrypt.generate_password_hash("admin123").decode("utf-8")
        u = User(username="admin", password_hash=pw, role="admin")
        db.session.add(u)
        db.session.commit()
        print("✅ Admin account created: admin / admin123")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)