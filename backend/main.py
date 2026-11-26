import os
import sys
import sqlite3
import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import jwt
import pyotp

# Password hashing with passlib/bcrypt fallback
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    def hash_password(password: str) -> str:
        return pwd_context.hash(password)
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)
except Exception:
    import bcrypt
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

# Configuration
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "iam_pyme.db"
FRONTEND_DIR = BASE_DIR.parent / "frontend"
INDEX_HTML = FRONTEND_DIR / "index.html"

SECRET_KEY = os.getenv("IAM_SECRET_KEY", "clave-desarrollo-cambiar-en-produccion")
JWT_SECRET = SECRET_KEY
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

# Database Helpers
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        token_version INTEGER NOT NULL DEFAULT 1,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        totp_secret TEXT,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        company_name TEXT NOT NULL DEFAULT 'PymeGuard S.A.',
        enforce_2fa INTEGER NOT NULL DEFAULT 0,
        max_login_attempts INTEGER NOT NULL DEFAULT 5
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS apps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        url TEXT NOT NULL,
        allowed_roles TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        ip_address TEXT
    );
    """)

    # Seed Default Policies
    cursor.execute("SELECT COUNT(*) FROM policies WHERE id = 1;")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO policies (id, company_name, enforce_2fa, max_login_attempts)
            VALUES (1, 'Mi Pyme S.A.', 0, 5);
        """)

    # Seed Admin User
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin';")
    if cursor.fetchone()[0] == 0:
        admin_pass = hash_password("Admin123*")
        cursor.execute("""
            INSERT INTO users (username, full_name, password_hash, role, is_active, token_version, totp_enabled, failed_attempts)
            VALUES ('admin', 'Gerente General (Admin)', ?, 'ADMIN', 1, 1, 0, 0);
        """, (admin_pass,))

    # Seed Employee User
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'empleado';")
    if cursor.fetchone()[0] == 0:
        emp_pass = hash_password("User123*")
        cursor.execute("""
            INSERT INTO users (username, full_name, password_hash, role, is_active, token_version, totp_enabled, failed_attempts)
            VALUES ('empleado', 'Juan Pérez (Contabilidad)', ?, 'CONTADOR', 1, 1, 0, 0);
        """, (emp_pass,))

    # Seed SSO Apps
    cursor.execute("SELECT COUNT(*) FROM apps;")
    if cursor.fetchone()[0] == 0:
        default_apps = [
            ("Sistema Contable ERP", "Facturación, impuestos y nómina", "https://ejemplo-erp.local/sso", "ADMIN,CONTADOR"),
            ("Nube Corporativa", "Documentos compartidos y respaldos", "https://ejemplo-cloud.local/sso", "ADMIN,CONTADOR,EMPLEADO"),
            ("Panel de Infraestructura", "Servidores y respaldos críticos", "https://ejemplo-infra.local/sso", "ADMIN")
        ]
        cursor.executemany("""
            INSERT INTO apps (name, description, url, allowed_roles)
            VALUES (?, ?, ?, ?);
        """, default_apps)

    # Seed Initial Log
    cursor.execute("SELECT COUNT(*) FROM audit_logs;")
    if cursor.fetchone()[0] == 0:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, actor, action, details, ip_address)
            VALUES (?, 'SYSTEM', 'INIT_DB', 'Base de datos inicializada con cuentas operativas y apps SSO.', '127.0.0.1');
        """, (now_str,))

    conn.commit()
    conn.close()

def log_audit(actor: str, action: str, details: str, ip: str = "127.0.0.1"):
    try:
        conn = get_db()
        cursor = conn.cursor()
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, actor, action, details, ip_address)
            VALUES (?, ?, ?, ?, ?);
        """, (now_str, actor, action, details, ip))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging audit: {e}", file=sys.stderr)

# FastAPI App Setup
app = FastAPI(
    title="PymeGuard IAM",
    description="Gestor de Identidades y Accesos Ligero para Pymes con RBAC, 2FA TOTP y SSO Simulado",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# Schemas
class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

class UserCreateRequest(BaseModel):
    username: str
    full_name: str
    password: str
    role: str

class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[int] = None

class AppCreateRequest(BaseModel):
    name: str
    description: str
    url: str
    allowed_roles: str

class PolicyUpdateRequest(BaseModel):
    company_name: str
    enforce_2fa: int
    max_login_attempts: int

# Auth Dependency
def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict[str, Any]:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token de autorización requerido")
    
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado. Inicie sesión nuevamente.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token de autorización inválido.")

    username = payload.get("sub")
    token_version = payload.get("token_version")

    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token con payload inválido.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?;", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado.")

    user_dict = dict(user)

    if not user_dict["is_active"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cuenta desactivada o revocada por seguridad.")

    if user_dict["token_version"] != token_version:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión revocada. Por favor inicie sesión nuevamente.")

    return user_dict

def get_current_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acceso denegado: se requieren privilegios de Administrador.")
    return user

# Startup Event
@app.on_event("startup")
def on_startup():
    init_db()

# Healthcheck
@app.get("/api/health")
def health():
    return {"status": "ok", "system": "PymeGuard IAM"}

# Authentication Endpoints
@app.post("/api/login")
def login(req: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM policies WHERE id = 1;")
    policy = dict(cursor.fetchone() or {"company_name": "Mi Pyme S.A.", "enforce_2fa": 0, "max_login_attempts": 5})

    cursor.execute("SELECT * FROM users WHERE username = ?;", (req.username.strip(),))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        log_audit(req.username, "LOGIN_FAILED", "Intento de login con usuario inexistente.", client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario o contraseña incorrectos")

    user = dict(user_row)

    if not user["is_active"]:
        conn.close()
        log_audit(req.username, "LOGIN_BLOCKED", "Intento de acceso a cuenta revocada o bloqueada.", client_ip)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cuenta desactivada o bloqueada por seguridad.")

    # Verify Password
    if not verify_password(req.password, user["password_hash"]):
        failed = (user["failed_attempts"] or 0) + 1
        max_attempts = policy.get("max_login_attempts", 5)

        if failed >= max_attempts and user["username"] != "admin":
            cursor.execute("UPDATE users SET failed_attempts = ?, is_active = 0, token_version = token_version + 1 WHERE id = ?;", (failed, user["id"]))
            conn.commit()
            conn.close()
            log_audit(user["username"], "BRUTE_FORCE_LOCK", f"Cuenta bloqueada automáticamente tras {failed} intentos fallidos.", client_ip)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cuenta bloqueada por múltiples intentos fallidos.")
        else:
            cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?;", (failed, user["id"]))
            conn.commit()
            conn.close()
            log_audit(user["username"], "LOGIN_FAILED", f"Contraseña incorrecta ({failed}/{max_attempts}).", client_ip)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario o contraseña incorrectos")

    # Password is correct; reset failed attempts
    cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?;", (user["id"],))
    conn.commit()

    # 2FA Verification
    is_2fa_enforced = bool(policy.get("enforce_2fa", 0))
    user_has_totp = bool(user.get("totp_enabled") and user.get("totp_secret"))

    if user_has_totp or (is_2fa_enforced and user.get("totp_secret")):
        if not req.totp_code:
            conn.close()
            return {"require_2fa": True, "detail": "Se requiere código de verificación 2FA (TOTP)."}

        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(req.totp_code.strip(), valid_window=1):
            conn.close()
            log_audit(user["username"], "2FA_FAILED", "Código TOTP inválido o expirado.", client_ip)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código 2FA inválido (6 dígitos)")

    conn.close()

    # Issue JWT
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "token_version": user["token_version"],
        "iat": now,
        "exp": now + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES)
    }
    access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    log_audit(user["username"], "LOGIN_SUCCESS", f"Inicio de sesión exitoso (Rol: {user['role']}).", client_ip)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "enforce_2fa": is_2fa_enforced,
        "company_name": policy.get("company_name", "Mi Pyme S.A."),
        "user": {
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
            "totp_enabled": bool(user["totp_enabled"])
        }
    }

# Employee Portal Endpoints
@app.get("/api/portal/apps")
def get_portal_apps(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM apps ORDER BY id ASC;")
    all_apps = [dict(row) for row in cursor.fetchall()]
    conn.close()

    user_role = user["role"]
    authorized_apps = []

    now = datetime.datetime.now(datetime.timezone.utc)
    for a in all_apps:
        roles_allowed = [r.strip() for r in a["allowed_roles"].split(",") if r.strip()]
        if user_role in roles_allowed:
            # Generate short-lived SSO token (5 min)
            sso_payload = {
                "sub": user["username"],
                "role": user["role"],
                "app": a["name"],
                "iat": now,
                "exp": now + datetime.timedelta(minutes=5)
            }
            sso_token = jwt.encode(sso_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
            sso_redirect_url = f"{a['url']}?sso_token={sso_token}"

            authorized_apps.append({
                "id": a["id"],
                "name": a["name"],
                "description": a["description"],
                "sso_redirect_url": sso_redirect_url
            })

    return authorized_apps

@app.post("/api/2fa/setup")
def setup_2fa(user: Dict[str, Any] = Depends(get_current_user), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    secret = pyotp.random_base32()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users 
        SET totp_secret = ?, totp_enabled = 1 
        WHERE id = ?;
    """, (secret, user["id"]))
    conn.commit()
    conn.close()

    log_audit(user["username"], "2FA_ENABLED", "El usuario activó el segundo factor (TOTP).", client_ip)

    otpauth_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["username"],
        issuer_name="PymeGuard"
    )

    return {
        "secret": secret,
        "otpauth_uri": otpauth_uri
    }

@app.post("/api/profile/password")
def change_password(req: PasswordChangeRequest, user: Dict[str, Any] = Depends(get_current_user), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id = ?;", (user["id"],))
    row = cursor.fetchone()

    if not row or not verify_password(req.current_password, row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="La contraseña actual es incorrecta.")

    if len(req.new_password) < 6:
        conn.close()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La nueva contraseña debe tener al menos 6 caracteres.")

    new_hash = hash_password(req.new_password)
    # Increment token_version to invalidate previous sessions
    cursor.execute("""
        UPDATE users 
        SET password_hash = ?, token_version = token_version + 1 
        WHERE id = ?;
    """, (new_hash, user["id"]))
    conn.commit()
    conn.close()

    log_audit(user["username"], "PASSWORD_CHANGED", "El usuario actualizó su contraseña corporativa e invalidó sesiones previas.", client_ip)
    return {"message": "Contraseña actualizada exitosamente"}

# Admin Users Endpoints
@app.get("/api/admin/users")
def list_users(admin: Dict[str, Any] = Depends(get_current_admin)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, role, is_active, totp_enabled FROM users ORDER BY id ASC;")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return users

@app.post("/api/admin/users")
def create_user(req: UserCreateRequest, admin: Dict[str, Any] = Depends(get_current_admin), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    username = req.username.strip().lower()

    if not username or not req.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El nombre de usuario y contraseña son requeridos.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?;", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El nombre de usuario ya existe")

    hashed = hash_password(req.password)
    role_normalized = req.role.strip().upper()

    cursor.execute("""
        INSERT INTO users (username, full_name, password_hash, role, is_active, token_version, totp_enabled, failed_attempts)
        VALUES (?, ?, ?, ?, 1, 1, 0, 0);
    """, (username, req.full_name.strip(), hashed, role_normalized))
    conn.commit()
    conn.close()

    log_audit(admin["username"], "USER_CREATED", f"Creó al usuario '{username}' con rol {role_normalized}.", client_ip)
    return {"message": "Usuario creado exitosamente"}

@app.patch("/api/admin/users/{user_id}")
def update_user(user_id: int, req: UserUpdateRequest, admin: Dict[str, Any] = Depends(get_current_admin), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
    target = cursor.fetchone()

    if not target:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    target = dict(target)
    updates = []
    params = []

    if req.role is not None:
        updates.append("role = ?")
        params.append(req.role.strip().upper())

    if req.is_active is not None:
        updates.append("is_active = ?")
        params.append(req.is_active)
        # If deactivating, increment token_version for real-time revocation
        if req.is_active == 0:
            updates.append("token_version = token_version + 1")

    if updates:
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?;"
        params.append(user_id)
        cursor.execute(query, tuple(params))
        conn.commit()

    conn.close()

    log_audit(admin["username"], "ROLE_UPDATED", f"Actualizó a '{target['username']}' -> Rol: {req.role or target['role']}, Activo: {req.is_active if req.is_active is not None else target['is_active']}.", client_ip)
    return {"message": "Usuario actualizado exitosamente"}

@app.post("/api/admin/offboarding/{user_id}")
def emergency_offboarding(user_id: int, admin: Dict[str, Any] = Depends(get_current_admin), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
    target = cursor.fetchone()

    if not target:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    target = dict(target)

    # Deactivate and bump token_version immediately
    cursor.execute("UPDATE users SET is_active = 0, token_version = token_version + 1 WHERE id = ?;", (user_id,))
    conn.commit()
    conn.close()

    log_audit(admin["username"], "EMERGENCY_OFFBOARDING", f"Revocación inmediata ejecutada sobre '{target['username']}'.", client_ip)
    return {"message": "Acceso revocado y credenciales invalidadas"}

# Admin SSO Apps Endpoints
@app.get("/api/admin/apps")
def list_admin_apps(admin: Dict[str, Any] = Depends(get_current_admin)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, url, allowed_roles FROM apps ORDER BY id ASC;")
    apps = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return apps

@app.post("/api/admin/apps")
def create_app(req: AppCreateRequest, admin: Dict[str, Any] = Depends(get_current_admin), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO apps (name, description, url, allowed_roles)
        VALUES (?, ?, ?, ?);
    """, (req.name.strip(), req.description.strip(), req.url.strip(), req.allowed_roles.strip()))
    conn.commit()
    conn.close()

    log_audit(admin["username"], "APP_CREATED", f"Agregó aplicación SSO '{req.name.strip()}'.", client_ip)
    return {"message": "Aplicación SSO agregada con éxito"}

@app.delete("/api/admin/apps/{app_id}")
def delete_app(app_id: int, admin: Dict[str, Any] = Depends(get_current_admin), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM apps WHERE id = ?;", (app_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Aplicación no encontrada")

    app_name = row["name"]
    cursor.execute("DELETE FROM apps WHERE id = ?;", (app_id,))
    conn.commit()
    conn.close()

    log_audit(admin["username"], "APP_DELETED", f"Eliminó la aplicación SSO '{app_name}'.", client_ip)
    return {"message": "Aplicación eliminada exitosamente"}

# Admin Security Policies Endpoints
@app.get("/api/admin/policies")
def get_policies(admin: Dict[str, Any] = Depends(get_current_admin)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT company_name, enforce_2fa, max_login_attempts FROM policies WHERE id = 1;")
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {"company_name": "Mi Pyme S.A.", "enforce_2fa": 0, "max_login_attempts": 5}
    return dict(row)

@app.put("/api/admin/policies")
def update_policies(req: PolicyUpdateRequest, admin: Dict[str, Any] = Depends(get_current_admin), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE policies 
        SET company_name = ?, enforce_2fa = ?, max_login_attempts = ? 
        WHERE id = 1;
    """, (req.company_name.strip(), req.enforce_2fa, req.max_login_attempts))
    conn.commit()
    conn.close()

    log_audit(admin["username"], "POLICY_UPDATED", f"Políticas actualizadas (2FA Obligatorio: {bool(req.enforce_2fa)}, Intentos máx: {req.max_login_attempts}).", client_ip)
    return {"message": "Políticas actualizadas exitosamente"}

# Admin Logs Endpoint
@app.get("/api/admin/logs")
def get_audit_logs(admin: Dict[str, Any] = Depends(get_current_admin)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, actor, action, details, ip_address FROM audit_logs ORDER BY id DESC LIMIT 200;")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

# Static Frontend Serving
@app.get("/")
def serve_index():
    if INDEX_HTML.exists():
        return FileResponse(str(INDEX_HTML))
    return JSONResponse({"message": "PymeGuard IAM API activa. Frontend no encontrado."}, status_code=200)

@app.get("/index.html")
def serve_index_html():
    if INDEX_HTML.exists():
        return FileResponse(str(INDEX_HTML))
    return JSONResponse({"message": "PymeGuard IAM API activa."}, status_code=200)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "127.0.0.1")
    uvicorn.run("main:app", host=host, port=port, reload=False)
