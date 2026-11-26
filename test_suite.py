"""
PymeGuard IAM — Suite de Pruebas Automatizadas End-to-End (E2E)
Verifica los 6 flujos críticos de seguridad, RBAC, 2FA, Zero-Trust y Auditoría.
"""

import sys
import os
import json
import urllib.parse
from pathlib import Path
import pyotp

# Cargar app desde el backend
BACKEND_DIR = Path(__file__).resolve().parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from main import app, init_db, get_db, DB_PATH
from fastapi.testclient import TestClient

client = TestClient(app)

class TestFailedException(Exception):
    pass

def api_call(path: str, method: str = "GET", data: dict = None, token: str = None) -> tuple:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    method = method.upper()
    if method == "GET":
        resp = client.get(path, headers=headers)
    elif method == "POST":
        resp = client.post(path, json=data, headers=headers)
    elif method == "PATCH":
        resp = client.patch(path, json=data, headers=headers)
    elif method == "DELETE":
        resp = client.delete(path, headers=headers)
    elif method == "PUT":
        resp = client.put(path, json=data, headers=headers)
    else:
        raise ValueError(f"Método HTTP no soportado: {method}")

    try:
        body = resp.json()
    except Exception:
        body = resp.text

    return resp.status_code, body

def log_test(name: str, passed: bool, detail: str = ""):
    symbol = "✅ [PASÓ]" if passed else "❌ [FALLÓ]"
    print(f"{symbol} {name}")
    if detail:
        print(f"    └── {detail}")
    if not passed:
        raise TestFailedException(f"Fallo en la prueba: {name} - {detail}")

def reset_database():
    print("\n[MANTENIMIENTO] Limpiando y restaurando base de datos a estado semilla inicial...")
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS active_sessions;")
        cursor.execute("DROP TABLE IF EXISTS audit_logs;")
        cursor.execute("DROP TABLE IF EXISTS apps;")
        cursor.execute("DROP TABLE IF EXISTS policies;")
        cursor.execute("DROP TABLE IF EXISTS users;")
        conn.commit()
        conn.close()
        init_db()
        print("✅ Base de datos restaurada con éxito: usuarios 'admin' y 'empleado' operativos con contraseñas por defecto.")
    except Exception as e:
        print(f"Error restaurando base de datos: {e}", file=sys.stderr)

def run_suite():
    print("=" * 70)
    print("  PYMEGUARD IAM — EJECUTANDO SUITE DE PRUEBAS DE SEGURIDAD E2E")
    print("=" * 70)

    # Inicializar BD limpia y fresca antes de iniciar pruebas
    reset_database()

    # -------------------------------------------------------------
    # PRUEBA A: Login exitoso de admin y empleado
    # -------------------------------------------------------------
    print("\n[FASE 1] Verificación de Acceso de Usuarios Pre-cargados...")
    status, res = api_call("/api/login", "POST", {"username": "admin", "password": "Admin123*"})
    log_test("Login exitoso de Administrador (admin / Admin123*)", status == 200 and "access_token" in res and res["user"]["role"] == "ADMIN", f"Rol: {res.get('user', {}).get('role')}")
    admin_token = res["access_token"]

    status, res = api_call("/api/login", "POST", {"username": "empleado", "password": "User123*"})
    log_test("Login exitoso de Empleado (empleado / User123*)", status == 200 and "access_token" in res and res["user"]["role"] == "CONTADOR", f"Rol: {res.get('user', {}).get('role')}")

    # -------------------------------------------------------------
    # PRUEBA B: Bloqueo por Fuerza Bruta y Desbloqueo por Admin
    # -------------------------------------------------------------
    print("\n[FASE 2] Protección contra Fuerza Bruta y Desbloqueo...")
    # Crear usuario objetivo de prueba
    user_b = "victima_brute"
    api_call("/api/admin/users", "POST", {"username": user_b, "full_name": "Usuario Fuerza Bruta", "password": "Password123*", "role": "EMPLEADO"}, token=admin_token)
    
    # Obtener ID del usuario
    _, users_list = api_call("/api/admin/users", "GET", token=admin_token)
    target_id = next(u["id"] for u in users_list if u["username"] == user_b)

    # Realizar 5 intentos fallidos
    for attempt in range(1, 6):
        status, res = api_call("/api/login", "POST", {"username": user_b, "password": f"WrongPass{attempt}*"})
        if attempt < 5:
            log_test(f"Intento fallido {attempt}/5 rechazado con 401", status == 401)
        else:
            log_test(f"Intento 5/5 activa bloqueo de cuenta con 403 Forbidden", status == 403 and "bloqueada" in str(res.get("detail", "")).lower())

    # 6to intento con contraseña correcta debe seguir bloqueado
    status, res = api_call("/api/login", "POST", {"username": user_b, "password": "Password123*"})
    log_test("Intento con contraseña correcta mientras está bloqueado recibe 403", status == 403)

    # Administrador reactiva la cuenta (PATCH is_active = 1)
    status, res = api_call(f"/api/admin/users/{target_id}", "PATCH", {"is_active": 1}, token=admin_token)
    log_test("Administrador reactiva y desbloquea la cuenta con éxito", status == 200)

    # Intento de login tras desbloqueo
    status, res = api_call("/api/login", "POST", {"username": user_b, "password": "Password123*"})
    log_test("Login exitoso inmediato tras desbloqueo por el Administrador", status == 200 and "access_token" in res)

    # -------------------------------------------------------------
    # PRUEBA C: Primer Inicio de Sesión y Cambio Obligatorio de Contraseña
    # -------------------------------------------------------------
    print("\n[FASE 3] Flujo de Primer Inicio de Sesión (Cambio Obligatorio)...")
    user_c = "primer_ingreso"
    temp_pass = "Temporal123*"
    new_def_pass = "Definitiva890*"

    # Admin crea el usuario
    status, res = api_call("/api/admin/users", "POST", {"username": user_c, "full_name": "Nuevo Ingreso", "password": temp_pass, "role": "CONTADOR"}, token=admin_token)
    log_test("Admin crea colaborador con cambio de contraseña forzado requerido", status == 200)

    # Usuario inicia sesión por primera vez
    status, res = api_call("/api/login", "POST", {"username": user_c, "password": temp_pass})
    log_test("Login detecta 'require_password_change': True", status == 200 and res.get("require_password_change") is True)
    temp_token = res["access_token"]

    # Validación: Intento de cambio con contraseña débil (< 8 caracteres) debe fallar con 400/422
    status, res = api_call("/api/profile/password", "POST", {"current_password": temp_pass, "new_password": "123"}, token=temp_token)
    log_test("Rechazo 400/422 (Validación de entrada) al intentar contraseña corta (< 8 caracteres)", status in (400, 422), f"HTTP {status}")

    # Cambio exitoso de contraseña
    status, res = api_call("/api/profile/password", "POST", {"current_password": temp_pass, "new_password": new_def_pass}, token=temp_token)
    log_test("Cambio de contraseña exitoso a clave definitiva de 8+ caracteres", status == 200 and res.get("must_change_password") is False)

    # Verificación: Antigua clave temporal ya no sirve
    status, res = api_call("/api/login", "POST", {"username": user_c, "password": temp_pass})
    log_test("Contraseña temporal antigua rechazada con 401 Unauthorized", status == 401)

    # Login con nueva contraseña entra directo sin exigir cambio
    status, res = api_call("/api/login", "POST", {"username": user_c, "password": new_def_pass})
    log_test("Login con nueva clave definitiva entra directo (require_password_change: False)", status == 200 and res.get("require_password_change") is False)

    # -------------------------------------------------------------
    # PRUEBA D: 2FA TOTP y Códigos de Respaldo (Uso Único)
    # -------------------------------------------------------------
    print("\n[FASE 4] Autenticación Multifactor (TOTP + Códigos de Respaldo)...")
    user_d = "usuario_mfa"
    pass_d = "Segura123*"
    api_call("/api/admin/users", "POST", {"username": user_d, "full_name": "Usuario MFA", "password": pass_d, "role": "EMPLEADO"}, token=admin_token)
    
    # Login y cambio de clave inicial
    _, login_d = api_call("/api/login", "POST", {"username": user_d, "password": pass_d})
    api_call("/api/profile/password", "POST", {"current_password": pass_d, "new_password": "MfaDefinitiva123*"}, token=login_d["access_token"])
    _, login_d = api_call("/api/login", "POST", {"username": user_d, "password": "MfaDefinitiva123*"})
    user_d_token = login_d["access_token"]

    # Activar 2FA
    status, res_2fa = api_call("/api/2fa/setup", "POST", token=user_d_token)
    totp_secret = res_2fa["secret"]
    recovery_codes = res_2fa["recovery_codes"]
    log_test("Activación de 2FA genera secreto Base32 y 5 códigos de respaldo", status == 200 and len(recovery_codes) == 5, f"Secret: {totp_secret[:6]}..., Códigos: {len(recovery_codes)}")

    # Login sin 2FA solicita código
    status, res = api_call("/api/login", "POST", {"username": user_d, "password": "MfaDefinitiva123*"})
    log_test("Login sin código 2FA responde require_2fa: True", status == 200 and res.get("require_2fa") is True)

    # Login con código inválido
    status, res = api_call("/api/login", "POST", {"username": user_d, "password": "MfaDefinitiva123*", "totp_code": "000000"})
    log_test("Código TOTP incorrecto rechazado con 401 Unauthorized", status == 401)

    # Login con código TOTP válido
    totp_calc = pyotp.TOTP(totp_secret).now()
    status, res = api_call("/api/login", "POST", {"username": user_d, "password": "MfaDefinitiva123*", "totp_code": totp_calc})
    log_test("Login con código TOTP de 6 dígitos aceptado exitosamente", status == 200 and "access_token" in res)

    # Login con primer código de respaldo (formato PG-XXXX-YY)
    code_1 = recovery_codes[0]
    status, res = api_call("/api/login", "POST", {"username": user_d, "password": "MfaDefinitiva123*", "totp_code": code_1})
    log_test(f"Login alternativo con Código de Respaldo exitoso ({code_1})", status == 200 and "access_token" in res)

    # Intentar re-usar el mismo código de respaldo (consumo de un solo uso)
    status, res = api_call("/api/login", "POST", {"username": user_d, "password": "MfaDefinitiva123*", "totp_code": code_1})
    log_test("Intento de reutilización de código ya gastado es RECHAZADO (Un solo uso comprobado)", status == 401)

    # Login con segundo código de respaldo
    code_2 = recovery_codes[1]
    status, res = api_call("/api/login", "POST", {"username": user_d, "password": "MfaDefinitiva123*", "totp_code": code_2})
    log_test(f"Segundo código de respaldo ({code_2}) funciona correctamente", status == 200 and "access_token" in res)

    # -------------------------------------------------------------
    # PRUEBA E: SSO Token -> Verificación -> One-Click Offboarding Zero-Trust
    # -------------------------------------------------------------
    print("\n[FASE 5] Single Sign-On (SSO) y Zero-Trust One-Click Offboarding...")
    user_e = "colaborador_sso"
    pass_e = "Contable123*"
    api_call("/api/admin/users", "POST", {"username": user_e, "full_name": "Carlos Contador", "password": pass_e, "role": "CONTADOR"}, token=admin_token)
    
    # Obtener ID
    _, users_list = api_call("/api/admin/users", "GET", token=admin_token)
    user_e_id = next(u["id"] for u in users_list if u["username"] == user_e)

    # Login y cambio de clave inicial
    _, login_e = api_call("/api/login", "POST", {"username": user_e, "password": pass_e})
    api_call("/api/profile/password", "POST", {"current_password": pass_e, "new_password": "ContableDefinitiva123*"}, token=login_e["access_token"])
    _, login_e = api_call("/api/login", "POST", {"username": user_e, "password": "ContableDefinitiva123*"})
    user_e_token = login_e["access_token"]

    # Obtener aplicaciones SSO autorizadas
    status, apps = api_call("/api/portal/apps", "GET", token=user_e_token)
    log_test("Consulta de Apps SSO autorizadas para rol CONTADOR", status == 200 and len(apps) >= 1)
    
    # Extraer token SSO de la primera app
    app_sso = apps[0]
    redirect_url = app_sso["sso_redirect_url"]
    parsed_qs = urllib.parse.parse_qs(urllib.parse.urlparse(redirect_url).query)
    sso_token = parsed_qs["token"][0]

    # Validar token SSO en la aplicación externa
    status, verify_res = api_call(f"/api/sso/verify?token={urllib.parse.quote(sso_token)}", "GET")
    log_test("Verificación SSO en /api/sso/verify responde 200 OK y STATUS: VERIFIED", status == 200 and verify_res.get("status") == "VERIFIED", f"Usuario verificado: {verify_res.get('user', {}).get('username')}")

    # Ejecutar One-Click Offboarding de emergencia por el Administrador
    status, off_res = api_call(f"/api/admin/offboarding/{user_e_id}", "POST", token=admin_token)
    log_test("Administrador ejecuta 'One-Click Offboarding' de emergencia", status == 200)

    # Re-verificar el token SSO inmediatamente: debe ser RECHAZADO con 401 Unauthorized
    status, verify_after = api_call(f"/api/sso/verify?token={urllib.parse.quote(sso_token)}", "GET")
    log_test("ZERO-TRUST ACTIVO: Mismo token SSO rechazado al instante con HTTP 401", status == 401, f"Respuesta: {verify_after.get('detail')}")

    # Sesión general y nuevo login bloqueados
    status, _ = api_call("/api/login", "POST", {"username": user_e, "password": "ContableDefinitiva123*"})
    log_test("Acceso general al portal IAM bloqueado con HTTP 403 Forbidden", status == 403)

    # -------------------------------------------------------------
    # PRUEBA F: Bitácora de Auditoría y Exportación CSV
    # -------------------------------------------------------------
    print("\n[FASE 6] Bitácora de Auditoría y Exportación CSV...")
    status, logs = api_call("/api/admin/logs", "GET", token=admin_token)
    actions = [l["action"] for l in logs]
    log_test("Consulta de bitácora de auditoría retorna eventos registrados", status == 200 and len(logs) > 0, f"Total eventos recuperados: {len(logs)}")
    
    # Verificar presencia de eventos críticos
    critical_events = ["LOGIN_SUCCESS", "BRUTE_FORCE_LOCK", "USER_CREATED", "2FA_ENABLED", "2FA_RECOVERY_CODE_USED", "EMERGENCY_OFFBOARDING"]
    found_events = [ev for ev in critical_events if ev in actions]
    log_test(f"Eventos de seguridad críticos detectados en bitácora ({len(found_events)}/{len(critical_events)})", len(found_events) >= 5, f"Eventos: {', '.join(found_events)}")

    # Exportación a CSV
    status, csv_data = api_call("/api/admin/logs/export", "GET", token=admin_token)
    has_header = "Timestamp" in csv_data and "Action" in csv_data and "Actor" in csv_data
    log_test("Endpoint /api/admin/logs/export genera archivo CSV válido y no vacío", status == 200 and has_header and len(csv_data) > 100, f"Tamaño del CSV: {len(csv_data)} bytes")

    print("\n" + "=" * 70)
    print("  RESULTADO: 100% DE PRUEBAS SUPERADAS EXITOSAMENTE SIN ERRORES")
    print("=" * 70)

    # Restaurar base de datos a estado original limpio
    reset_database()

if __name__ == "__main__":
    try:
        run_suite()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ ERROR FATAL EN SUITE DE PRUEBAS: {e}", file=sys.stderr)
        sys.exit(1)
