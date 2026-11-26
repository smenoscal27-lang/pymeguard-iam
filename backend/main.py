import os
import sys
import sqlite3
import datetime
import secrets
import json
import urllib.parse
import re
import io
import csv
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
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
ERP_DEMO_HTML = FRONTEND_DIR / "erp-demo.html"

SECRET_KEY = os.getenv("IAM_SECRET_KEY", "clave-desarrollo-cambiar-en-produccion")
JWT_SECRET = SECRET_KEY
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

# Database Helpers
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def generate_recovery_codes(count: int = 5) -> List[str]:
    codes = []
    for _ in range(count):
        p1 = secrets.token_hex(2).upper()
        p2 = secrets.token_hex(1).upper()
        codes.append(f"PG-{p1}-{p2}")
    return codes

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
        recovery_codes TEXT,
        must_change_password INTEGER NOT NULL DEFAULT 0,
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

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS active_sessions (
        jti TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        is_revoked INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)

    # Safe Migrations for existing databases
    cursor.execute("PRAGMA table_info(users);")
    existing_cols = [col[1] for col in cursor.fetchall()]
    if "must_change_password" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;")
    if "recovery_codes" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN recovery_codes TEXT;")

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
            INSERT INTO users (username, full_name, password_hash, role, is_active, token_version, totp_enabled, must_change_password, failed_attempts)
            VALUES ('admin', 'Gerente General (Admin)', ?, 'ADMIN', 1, 1, 0, 0, 0);
        """, (admin_pass,))

    # Seed Employee User
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'empleado';")
    if cursor.fetchone()[0] == 0:
        emp_pass = hash_password("User123*")
        cursor.execute("""
            INSERT INTO users (username, full_name, password_hash, role, is_active, token_version, totp_enabled, must_change_password, failed_attempts)
            VALUES ('empleado', 'Juan Pérez (Contabilidad)', ?, 'CONTADOR', 1, 1, 0, 0, 0);
        """, (emp_pass,))

    # Seed SSO Apps
    cursor.execute("SELECT COUNT(*) FROM apps;")
    if cursor.fetchone()[0] == 0:
        default_apps = [
            ("Sistema Contable ERP", "Facturación, impuestos y nómina", "/erp-demo", "ADMIN,CONTADOR"),
            ("Nube Corporativa", "Documentos compartidos y respaldos", "/erp-demo", "ADMIN,CONTADOR,EMPLEADO"),
            ("Panel de Infraestructura", "Servidores y respaldos críticos", "/erp-demo", "ADMIN")
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
    version="1.1.0"
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
    new_password: str = Field(..., min_length=8)

    @validator("new_password")
    def validate_new_pass(cls, v):
        if len(v) < 8:
            raise ValueError("La nueva contraseña debe tener al menos 8 caracteres.")
        return v

class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    full_name: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=8, max_length=128)
    role: str

    @validator("username")
    def validate_username(cls, v):
        v = v.strip().lower()
        if not re.match(r"^[a-zA-Z0-9_.-]{3,30}$", v):
            raise ValueError("El nombre de usuario debe tener entre 3 y 30 caracteres alfanuméricos, guiones o puntos.")
        return v

    @validator("full_name")
    def validate_full_name(cls, v):
        v = v.strip()
        if len(v) < 2:
            raise ValueError("El nombre completo debe tener al menos 2 caracteres.")
        return v

    @validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres.")
        return v

    @validator("role")
    def validate_role(cls, v):
        v = v.strip().upper()
        if v not in {"ADMIN", "CONTADOR", "EMPLEADO"}:
            raise ValueError("Rol inválido. Debe ser ADMIN, CONTADOR o EMPLEADO.")
        return v

class UserUpdateRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[int] = None

    @validator("role")
    def validate_role(cls, v):
        if v is not None:
            v = v.strip().upper()
            if v not in {"ADMIN", "CONTADOR", "EMPLEADO"}:
                raise ValueError("Rol inválido. Debe ser ADMIN, CONTADOR o EMPLEADO.")
            return v
        return v

    @validator("is_active")
    def validate_is_active(cls, v):
        if v is not None and v not in (0, 1):
            raise ValueError("is_active debe ser 0 o 1.")
        return v

class AppCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(..., min_length=2, max_length=250)
    url: str = Field(..., min_length=1)
    allowed_roles: str = Field(..., min_length=1)

    @validator("name")
    def validate_name(cls, v):
        v = v.strip()
        if len(v) < 2:
            raise ValueError("El nombre debe tener al menos 2 caracteres.")
        return v

    @validator("url")
    def validate_url(cls, v):
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://") or v.startswith("/")):
            raise ValueError("La URL debe ser una dirección web válida (http://, https://) o una ruta relativa (/...).")
        return v

    @validator("allowed_roles")
    def validate_roles(cls, v):
        v = v.strip()
        roles = [r.strip().upper() for r in v.split(",") if r.strip()]
        valid_roles = {"ADMIN", "CONTADOR", "EMPLEADO"}
        if not roles:
            raise ValueError("Debe especificar al menos un rol permitido.")
        for r in roles:
            if r not in valid_roles:
                raise ValueError(f"Rol inválido: '{r}'. Roles válidos: {', '.join(valid_roles)}")
        return ",".join(roles)

class PolicyUpdateRequest(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=100)
    enforce_2fa: int = Field(..., ge=0, le=1)
    max_login_attempts: int = Field(..., ge=1, le=20)

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
    jti = payload.get("jti")

    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token con payload inválido.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?;", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado.")

    user_dict = dict(user)

    if not user_dict["is_active"]:
        conn.close()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cuenta desactivada o revocada por seguridad.")

    if user_dict["token_version"] != token_version:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión revocada. Por favor inicie sesión nuevamente.")

    # Validate JTI Active Session
    if jti:
        cursor.execute("SELECT is_revoked FROM active_sessions WHERE jti = ?;", (jti,))
        sess = cursor.fetchone()
        if sess and sess["is_revoked"] == 1:
            conn.close()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Esta sesión específica fue cerrada o revocada.")

    conn.close()
    user_dict["current_jti"] = jti
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
    user_agent = request.headers.get("user-agent", "Navegador Web")
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
            cursor.execute("UPDATE active_sessions SET is_revoked = 1 WHERE user_id = ?;", (user["id"],))
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

    # 2FA Verification (Supports TOTP 6 digits OR 1-time Recovery Code)
    is_2fa_enforced = bool(policy.get("enforce_2fa", 0))
    user_has_totp = bool(user.get("totp_enabled") and user.get("totp_secret"))

    if user_has_totp or (is_2fa_enforced and user.get("totp_secret")):
        if not req.totp_code:
            conn.close()
            return {"require_2fa": True, "detail": "Se requiere código de verificación 2FA (TOTP o Código de Respaldo)."}

        code_input = req.totp_code.strip().upper()
        totp_verified = False

        # 1. Test standard 6-digit TOTP
        if len(code_input) == 6 and code_input.isdigit():
            totp = pyotp.TOTP(user["totp_secret"])
            if totp.verify(code_input, valid_window=1):
                totp_verified = True

        # 2. Test Recovery Code if TOTP failed
        if not totp_verified and user.get("recovery_codes"):
            try:
                codes_list = json.loads(user["recovery_codes"])
                if code_input in [c.upper().strip() for c in codes_list]:
                    totp_verified = True
                    # Consume the recovery code
                    codes_list = [c for c in codes_list if c.upper().strip() != code_input]
                    cursor.execute("UPDATE users SET recovery_codes = ? WHERE id = ?;", (json.dumps(codes_list), user["id"]))
                    conn.commit()
                    log_audit(user["username"], "2FA_RECOVERY_CODE_USED", f"Código de respaldo utilizado. Códigos restantes: {len(codes_list)}.", client_ip)
            except Exception as e:
                print(f"Error parsing recovery codes: {e}", file=sys.stderr)

        if not totp_verified:
            conn.close()
            log_audit(user["username"], "2FA_FAILED", "Código 2FA o código de respaldo inválido.", client_ip)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Código 2FA o código de respaldo inválido.")

    # Create Session & JTI
    jti = secrets.token_hex(16)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    exp_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, created_at, expires_at, is_revoked)
        VALUES (?, ?, ?, ?, ?, ?, 0);
    """, (jti, user["id"], client_ip, user_agent, now_str, exp_str))
    conn.commit()
    conn.close()

    # Issue JWT
    must_change = bool(user.get("must_change_password", 0))
    payload = {
        "jti": jti,
        "sub": user["username"],
        "role": user["role"],
        "token_version": user["token_version"],
        "must_change_password": must_change,
        "iat": now,
        "exp": expires_at
    }
    access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    log_audit(user["username"], "LOGIN_SUCCESS", f"Inicio de sesión exitoso (Rol: {user['role']}).", client_ip)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "enforce_2fa": is_2fa_enforced,
        "company_name": policy.get("company_name", "Mi Pyme S.A."),
        "require_password_change": must_change,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
            "totp_enabled": bool(user["totp_enabled"]),
            "must_change_password": must_change
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
            # Generate short-lived SSO token (5 min) with token_version for Zero-Trust validation
            sso_payload = {
                "sub": user["username"],
                "role": user["role"],
                "full_name": user["full_name"],
                "app": a["name"],
                "token_version": user["token_version"],
                "iat": int(now.timestamp()),
                "exp": int((now + datetime.timedelta(minutes=5)).timestamp())
            }
            sso_token = jwt.encode(sso_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
            sso_redirect_url = f"/erp-demo?token={sso_token}&app={urllib.parse.quote(a['name'])}"

            authorized_apps.append({
                "id": a["id"],
                "name": a["name"],
                "description": a["description"],
                "url": a["url"],
                "sso_redirect_url": sso_redirect_url
            })

    return authorized_apps

# SSO Verification Endpoint for Connected Apps (e.g., ERP demo)
@app.get("/api/sso/verify")
def verify_sso(token: str = Query(...)):
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token SSO no proporcionado")
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token SSO expirado (vigencia máxima: 5 minutos).")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Firma criptográfica de token SSO inválida.")

    username = payload.get("sub")
    token_version = payload.get("token_version")
    app_name = payload.get("app")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?;", (username,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario SSO no encontrado en PymeGuard IAM.")

    user = dict(row)

    if not user["is_active"]:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="401 Sesión Revocada: El usuario fue desactivado en PymeGuard IAM (One-Click Offboarding).")

    if user["token_version"] != token_version:
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="401 Sesión Revocada: Las credenciales fueron invalidadas en tiempo real por el Administrador.")

    # Check RBAC permissions for requested application
    if app_name:
        cursor.execute("SELECT allowed_roles FROM apps WHERE name = ?;", (app_name,))
        app_row = cursor.fetchone()
        if app_row:
            allowed = [r.strip() for r in app_row["allowed_roles"].split(",") if r.strip()]
            if user["role"] not in allowed:
                conn.close()
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Acceso denegado: El rol {user['role']} no tiene permisos para {app_name}.")

    conn.close()

    iat_dt = datetime.datetime.fromtimestamp(payload["iat"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if "iat" in payload else "Reciente"
    exp_dt = datetime.datetime.fromtimestamp(payload["exp"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if "exp" in payload else "Válido"

    return {
        "ok": True,
        "valid": True,
        "status": "VERIFIED",
        "app": app_name or "Aplicación SSO",
        "user": {
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"]
        },
        "issued_at": iat_dt,
        "expires_at": exp_dt
    }

@app.post("/api/2fa/setup")
def setup_2fa(user: Dict[str, Any] = Depends(get_current_user), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    secret = pyotp.random_base32()
    recovery_codes = generate_recovery_codes(5)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users 
        SET totp_secret = ?, totp_enabled = 1, recovery_codes = ? 
        WHERE id = ?;
    """, (secret, json.dumps(recovery_codes), user["id"]))
    conn.commit()
    conn.close()

    log_audit(user["username"], "2FA_ENABLED", "El usuario activó el segundo factor (TOTP) y generó 5 códigos de respaldo.", client_ip)

    otpauth_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["username"],
        issuer_name="PymeGuard"
    )

    return {
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "recovery_codes": recovery_codes
    }

@app.post("/api/profile/password")
def change_password(req: PasswordChangeRequest, user: Dict[str, Any] = Depends(get_current_user), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, must_change_password FROM users WHERE id = ?;", (user["id"],))
    row = cursor.fetchone()

    if not row or not verify_password(req.current_password, row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="La contraseña actual es incorrecta.")

    if len(req.new_password) < 8:
        conn.close()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La nueva contraseña debe tener al menos 8 caracteres.")

    new_hash = hash_password(req.new_password)
    was_first_login = bool(row["must_change_password"])

    # Update password, remove must_change_password flag, increment token_version
    new_token_version = user["token_version"] + 1
    cursor.execute("""
        UPDATE users 
        SET password_hash = ?, token_version = ?, must_change_password = 0 
        WHERE id = ?;
    """, (new_hash, new_token_version, user["id"]))

    # Revoke all previous active sessions
    cursor.execute("UPDATE active_sessions SET is_revoked = 1 WHERE user_id = ?;", (user["id"],))

    # Issue a fresh new active session and token for the current user so they stay logged in
    jti = secrets.token_hex(16)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES)
    user_agent = request.headers.get("user-agent", "Navegador Web") if request else "Navegador Web"

    cursor.execute("""
        INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, created_at, expires_at, is_revoked)
        VALUES (?, ?, ?, ?, ?, ?, 0);
    """, (jti, user["id"], client_ip, user_agent, now.strftime("%Y-%m-%d %H:%M:%S"), expires_at.strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()

    action_label = "FIRST_LOGIN_PASSWORD_RESET" if was_first_login else "PASSWORD_CHANGED"
    log_audit(user["username"], action_label, "El usuario actualizó su contraseña corporativa e invalidó sesiones previas.", client_ip)

    # Issue refreshed JWT
    new_payload = {
        "jti": jti,
        "sub": user["username"],
        "role": user["role"],
        "token_version": new_token_version,
        "must_change_password": False,
        "iat": now,
        "exp": expires_at
    }
    new_access_token = jwt.encode(new_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {
        "message": "Contraseña actualizada exitosamente",
        "access_token": new_access_token,
        "must_change_password": False
    }

# Session Management Endpoints
@app.get("/api/sessions")
def get_sessions(all: bool = False, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()

    if all and user["role"] == "ADMIN":
        cursor.execute("""
            SELECT s.jti, s.user_id, s.ip_address, s.user_agent, s.created_at, s.expires_at, s.is_revoked,
                   u.username, u.full_name, u.role
            FROM active_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.is_revoked = 0
            ORDER BY s.created_at DESC
            LIMIT 100;
        """)
    else:
        cursor.execute("""
            SELECT s.jti, s.user_id, s.ip_address, s.user_agent, s.created_at, s.expires_at, s.is_revoked,
                   u.username, u.full_name, u.role
            FROM active_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.user_id = ? AND s.is_revoked = 0
            ORDER BY s.created_at DESC
            LIMIT 50;
        """, (user["id"],))

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    current_jti = user.get("current_jti")
    for r in rows:
        r["is_current"] = (r["jti"] == current_jti)

    return rows

@app.delete("/api/sessions/{jti}")
def revoke_session(jti: str, user: Dict[str, Any] = Depends(get_current_user), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM active_sessions WHERE jti = ?;", (jti,))
    sess = cursor.fetchone()

    if not sess:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sesión no encontrada.")

    sess_dict = dict(sess)
    if sess_dict["user_id"] != user["id"] and user["role"] != "ADMIN":
        conn.close()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tiene permisos para revocar esta sesión.")

    cursor.execute("UPDATE active_sessions SET is_revoked = 1 WHERE jti = ?;", (jti,))
    conn.commit()
    conn.close()

    log_audit(user["username"], "SESSION_REVOKED", f"Sesión individual ({jti[:8]}...) revocada exitosamente.", client_ip)
    return {"message": "Sesión revocada exitosamente"}

# Admin Users Endpoints
@app.get("/api/admin/users")
def list_users(admin: Dict[str, Any] = Depends(get_current_admin)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, role, is_active, totp_enabled, must_change_password FROM users ORDER BY id ASC;")
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

    # Newly created users are forced to change their password on first login
    cursor.execute("""
        INSERT INTO users (username, full_name, password_hash, role, is_active, token_version, totp_enabled, must_change_password, failed_attempts)
        VALUES (?, ?, ?, ?, 1, 1, 0, 1, 0);
    """, (username, req.full_name.strip(), hashed, role_normalized))
    conn.commit()
    conn.close()

    log_audit(admin["username"], "USER_CREATED", f"Creó al usuario '{username}' con rol {role_normalized} (Cambio de contraseña forzado requerido).", client_ip)
    return {"message": "Usuario creado exitosamente (requiere cambio de contraseña en su primer inicio de sesión)"}

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
        # If deactivating, increment token_version and revoke sessions
        if req.is_active == 0:
            updates.append("token_version = token_version + 1")
            cursor.execute("UPDATE active_sessions SET is_revoked = 1 WHERE user_id = ?;", (user_id,))
        elif req.is_active == 1:
            updates.append("failed_attempts = 0")

    if updates:
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?;"
        params.append(user_id)
        cursor.execute(query, tuple(params))
        conn.commit()

    conn.close()

    log_audit(admin["username"], "ROLE_UPDATED", f"Actualizó a '{target['username']}' -> Rol: {req.role or target['role']}, Activo: {req.is_active if req.is_active is not None else target['is_active']}.", client_ip)
    return {"message": "Usuario actualizado exitosamente"}

@app.post("/api/admin/users/{user_id}/reset-2fa")
def reset_user_2fa(user_id: int, admin: Dict[str, Any] = Depends(get_current_admin), request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
    target = cursor.fetchone()

    if not target:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    target = dict(target)
    cursor.execute("""
        UPDATE users 
        SET totp_enabled = 0, totp_secret = NULL, recovery_codes = NULL 
        WHERE id = ?;
    """, (user_id,))
    conn.commit()
    conn.close()

    log_audit(admin["username"], "2FA_RESET_BY_ADMIN", f"El Administrador restableció y desactivó el 2FA del colaborador @{target['username']}.", client_ip)
    return {"message": f"2FA restablecido exitosamente para el usuario @{target['username']}."}

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

    # Deactivate, bump token_version immediately, and revoke all active sessions
    cursor.execute("UPDATE users SET is_active = 0, token_version = token_version + 1 WHERE id = ?;", (user_id,))
    cursor.execute("UPDATE active_sessions SET is_revoked = 1 WHERE user_id = ?;", (user_id,))
    conn.commit()
    conn.close()

    log_audit(admin["username"], "EMERGENCY_OFFBOARDING", f"Revocación inmediata ejecutada sobre '{target['username']}'. Todas las sesiones activas fueron invalidadas.", client_ip)
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

@app.get("/api/admin/logs/export")
def export_audit_logs_csv(admin: Dict[str, Any] = Depends(get_current_admin)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, actor, action, details, ip_address FROM audit_logs ORDER BY id DESC;")
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Actor", "Action", "Details", "IP_Address"])
    for r in rows:
        writer.writerow([r["id"], r["timestamp"], r["actor"], r["action"], r["details"], r["ip_address"]])

    csv_data = output.getvalue()
    filename = f"auditoria_iam_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# Static Frontend & ERP Demo Serving
@app.get("/erp-demo")
def serve_erp_demo():
    if ERP_DEMO_HTML.exists():
        return FileResponse(str(ERP_DEMO_HTML))
    return JSONResponse({"message": "Simulador ERP no encontrado en frontend/erp-demo.html"}, status_code=404)

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
