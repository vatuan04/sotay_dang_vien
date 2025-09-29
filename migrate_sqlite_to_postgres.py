# migrate_sqlite_to_postgres.py
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone, timedelta

# --- cấu hình nguồn (SQLite) ---
SQLITE_PATH = os.path.abspath(os.path.join('instance', 'sotay.db'))
SQLITE_URL = f"sqlite:///{SQLITE_PATH}"

# --- chọn URL Postgres ---
PG_URL = os.environ.get("DATABASE_URL_INTERNAL") or os.environ.get("DATABASE_URL")
if not PG_URL:
    raise SystemExit(
        "❌ Không tìm thấy DATABASE_URL_INTERNAL hoặc DATABASE_URL trong biến môi trường.\n"
        "Hãy set biến env trước khi chạy."
    )

print(f"✅ Sử dụng Postgres URL: {('INTERNAL' if os.environ.get('DATABASE_URL_INTERNAL') else 'EXTERNAL')}")

# --- tạo engine + session ---
src_engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
dst_engine = create_engine(PG_URL)

SrcSession = sessionmaker(bind=src_engine)
DstSession = sessionmaker(bind=dst_engine)

src_sess = SrcSession()
dst_sess = DstSession()

# --- import metadata/models từ app ---
from app import db
from app import User as AppUser, Note as AppNote

# --- tạo bảng đích nếu chưa có ---
print("📦 Tạo bảng trên Postgres nếu chưa tồn tại...")
AppUser.__table__.create(bind=dst_engine, checkfirst=True)
AppNote.__table__.create(bind=dst_engine, checkfirst=True)
print("✔️ Done.")

VN_TZ = timezone(timedelta(hours=7))

def normalize_dt(dt):
    """Chuyển datetime thành aware với tz=UTC+7 nếu thiếu tzinfo"""
    if dt is None:
        return None
    if isinstance(dt, (bytes, bytearray)):
        try:
            dt = dt.decode("utf-8")
        except Exception:
            dt = str(dt)
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except Exception:
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(dt, fmt)
                    break
                except Exception:
                    continue
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=VN_TZ)
        return dt
    return None

# --- copy users ---
print("➡️ Copy users từ SQLite sang Postgres ...")
users = src_sess.execute(text("SELECT id, username, password_hash, role FROM user")).fetchall()
for u in users:
    id_, username, pw, role = u
    exists = dst_sess.execute(
        text('SELECT 1 FROM "user" WHERE username = :u'),
        {"u": username}
    ).fetchone()
    if exists:
        print(f"  ⚠️ Bỏ qua user {username} (đã tồn tại)")
        continue
    dst_sess.execute(
        AppUser.__table__.insert().values(
            id=id_,
            username=username,
            password_hash=pw,
            role=role
        )
    )
dst_sess.commit()
print("✔️ Users copied.")

# --- copy notes ---
print("➡️ Copy notes ...")
notes = src_sess.execute(text("SELECT id, author_username, title, content, created_at FROM note")).fetchall()
for n in notes:
    nid, author_username, title, content, created_at = n
    dt = normalize_dt(created_at)
    dst_sess.execute(
        AppNote.__table__.insert().values(
            id=nid,
            author_username=author_username,
            title=title,
            content=content,
            created_at=dt
        )
    )
dst_sess.commit()
print("✔️ Notes copied.")

src_sess.close()
dst_sess.close()
print("🎉 Migration finished successfully.")
