# 🛡️ PymeGuard IAM — Gestor Ligero de Identidades y Accesos para PyMEs

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Security: TOTP & JWT](https://img.shields.io/badge/Security-JWT%20%2B%202FA%20TOTP-blue?style=flat-square)](#-características-principales)

**PymeGuard IAM** es una plataforma integral y liviana de Gestión de Identidad y Accesos (IAM) con Single Sign-On (SSO) diseñada específicamente para pequeñas y medianas empresas. Proporciona control de acceso basado en roles (RBAC), autenticación en dos factores (2FA TOTP), revocación de sesiones en tiempo real (*One-Click Offboarding*) y bitácora de auditoría inmutable.

---

## 🌟 Características Principales

- **Control de Acceso Basado en Roles (RBAC Dinámico)**: Gestión simplificada de permisos según funciones organizacionales (`ADMIN`, `CONTADOR`, `EMPLEADO`).
- **Autenticación Fuerte con 2FA TOTP**: Enrolamiento self-service mediante código QR y secreto Base32 compatible con Google Authenticator y Microsoft Authenticator.
- **Revocación Inmediata de Sesiones (*One-Click Offboarding*)**: Invalida instantáneamente los tokens de acceso activos mediante el control de versión de tokens (`token_version`) en la base de datos.
- **Protección contra Fuerza Bruta**: Bloqueo preventivo de cuentas tras alcanzar el número máximo de intentos fallidos configurado por la empresa.
- **Single Sign-On (SSO) Simulado**: Emisión de tokens efímeros firmados por aplicación para redirección segura hacia sistemas corporativos (ERP, nube, infraestructura).
- **Bitácora de Auditoría Forense**: Registro inmutable de eventos de seguridad con marcas de tiempo, direcciones IP, actores y acciones ejecutadas.

---

## 🏛️ Arquitectura del Proyecto

```text
pymeguard-iam/
├── backend/
│   ├── main.py          # API REST (FastAPI, SQLite, JWT HS256, PyOTP)
│   └── iam_pyme.db      # Base de datos relacional SQLite (auto-generada)
├── frontend/
│   └── index.html       # Interfaz responsiva moderna (Tailwind CSS, tema oscuro/claro)
├── .env.example         # Plantilla de variables de entorno (IAM_SECRET_KEY, PORT, HOST)
├── .gitignore           # Exclusiones para Git (venv, caché, bases de datos locales)
├── LICENSE              # Licencia MIT de código abierto
├── README.md            # Documentación y guía de despliegue
└── requirements.txt     # Dependencias de Python
```

---

## 🔑 Credenciales Operativas de Prueba

El sistema realiza un **sembrado automático** de cuentas y aplicaciones corporativas en el primer arranque:

| Usuario | Contraseña Inicial | Rol | Privilegios y Alcance |
| :--- | :--- | :--- | :--- |
| **`admin`** | `Admin123*` | **ADMIN** | Control total: gestión de usuarios, revocación express, políticas y auditoría forense. |
| **`empleado`** | `User123*` | **CONTADOR** | Portal del empleado, aplicaciones asignadas (ERP, Nube), activación de 2FA y cambio de contraseña. |

---

## 🚀 Instalación y Despliegue Local

### Prerrequisitos
- **Python 3.10 o superior**
- Administrador de paquetes `pip`

### 1. Clonar el repositorio y acceder a la carpeta
```bash
git clone https://github.com/tu-usuario/pymeguard-iam.git
cd pymeguard-iam
```

### 2. Crear y activar un entorno virtual

**En Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**En Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Configurar variables de entorno
Crea un archivo `.env` basado en la plantilla:
```bash
cp .env.example .env
```
*(En Windows PowerShell: `Copy-Item .env.example .env`)*

### 4. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 5. Iniciar la aplicación
```bash
python backend/main.py
```
El servidor quedará disponible en:
👉 **http://127.0.0.1:8000**

---

## 🧪 Pruebas de Funcionamiento

- **Healthcheck de la API**: Realiza una petición GET a `http://127.0.0.1:8000/api/health`.
- **Acceso Web**: Ingresa a `http://127.0.0.1:8000` y usa las credenciales de prueba predeterminadas.
- **Offboarding Express**: Desde el panel de administración, haz clic en **"Revocar"** sobre cualquier usuario y comprueba que sus sesiones activas son invalidadas inmediatamente.
- **Exportación de Auditoría**: Descarga los registros de auditoría en formato CSV desde la pestaña **"Bitácora"**.

---

## 📄 Licencia
Este proyecto está distribuido bajo la licencia [MIT](LICENSE).
