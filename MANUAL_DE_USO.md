# PymeGuard IAM — Manual Oficial de Uso & Guion de Presentación Ejecutiva

> **Sistema de Gestión de Identidades y Accesos (IAM) Ligero para Pequeñas y Medianas Empresas**  
> **Versión:** 1.2 Enterprise Edition | **Tecnología:** Python, FastAPI, SQLite, JWT (HS256), TOTP RFC 6238, Zero-Trust Architecture  
> **Repositorio:** `pymeguard-iam/` | **Servidor Local:** `http://127.0.0.1:8000`

---

## Índice General

1. [Visión General & Propósito del Sistema](#visión-general--propósito-del-sistema)
2. [Sección 1: Guía Completa del Administrador de TI](#sección-1-guía-completa-del-administrador-de-ti)
   - 1.1 Panel de Control y Métricas de Seguridad
   - 1.2 Gestión de Colaboradores y Control de Acceso Basado en Roles (RBAC)
   - 1.3 Catálogo de Aplicaciones Single Sign-On (SSO)
   - 1.4 Políticas Corporativas de Seguridad (2FA Obligatorio y Bloqueo de Fuerza Bruta)
   - 1.5 Protocolo de Desvinculación Inmediata (*One-Click Offboarding*)
   - 1.6 Bitácora de Auditoría Forense y Exportación en CSV
   - 1.7 Monitor de Dispositivos y Sesiones Activas
3. [Sección 2: Guía Operativa del Empleado / Colaborador](#sección-2-guía-operativa-del-empleado--colaborador)
   - 2.1 Primer Inicio de Sesión y Cambio Obligatorio de Contraseña
   - 2.2 Portal de Aplicaciones Corporativas (SSO con 1 Clic)
   - 2.3 Configuración de Segundo Factor (2FA TOTP) con Authenticator
   - 2.4 Resguardo y Uso de Códigos de Emergencia (*Recovery Codes*)
   - 2.5 Gestión de Sesiones Propias y Cierre Remoto de Dispositivos
4. [Sección 3: Guion de Exposición en Vivo (5 Minutos) para Demostración](#sección-3-guion-de-exposición-en-vivo-5-minutos-para-demostración)
   - 3.1 Preparación Previa al Pitch
   - 3.2 Minuto a Minuto: Paso a Paso en Pantalla con Diálogos Clave
5. [Sección 4: Tabla de Credenciales Operativas y Matriz de Cumplimiento Técnico](#sección-4-tabla-de-credenciales-operativas-y-matriz-de-cumplimiento-técnico)
   - 4.1 Cuentas Pre-cargadas de Demostración
   - 4.2 Matriz de Cumplimiento Técnico y Estándares de Ciberseguridad
   - 4.3 Comandos de Despliegue y Ejecución de Batería de Pruebas

---

## Visión General & Propósito del Sistema

Las pequeñas y medianas empresas (Pymes) enfrentan un dilema crítico: las soluciones IAM tradicionales de gran escala (como Okta, Ping Identity o Azure AD Premium) conllevan costos prohibitivos por licencia de usuario y arquitecturas excesivamente complejas. En consecuencia, las Pymes suelen recurrir a prácticas de alto riesgo: compartir contraseñas administrativas por mensajería, omitir el doble factor de autenticación y tardar días o semanas en revocar accesos tras la salida de un colaborador.

**PymeGuard IAM** resuelve este desafío entregando una plataforma ligera, autónoma, de bajo consumo y de alta seguridad que ofrece:
- **Zero-Trust Real-Time Validation:** Revocación instantánea de sesiones y tokens SSO en menos de un segundo gracias al algoritmo de `token_version` e invalidación concurrente de `active_sessions`.
- **Single Sign-On (SSO) Simulado:** Integración con sistemas de negocio (como el ERP Contable Demo) mediante tokens JWT firmados criptográficamente.
- **2FA TOTP (RFC 6238) + Códigos de Respaldo:** Compatible con Google Authenticator, Authy y Microsoft Authenticator, con 5 códigos de contingencia de un solo uso.
- **Protección contra Fuerza Bruta:** Bloqueo automático de cuentas tras 5 intentos fallidos consecutivos (configurable) con auditoría inmediata.
- **Auditoría Forense Inmutable:** Registro pormenorizado de cada inicio de sesión, cambio de rol, actualización de directivas o revocación de accesos con exportación directa a formato CSV.

---

## Sección 1: Guía Completa del Administrador de TI

El perfil de Administrador (`role: ADMIN`) cuenta con la visibilidad absoluta del sistema, privilegios de gestión de usuarios, catálogos SSO, políticas globales y capacidades de respuesta a incidentes de seguridad.

### 1.1 Panel de Control y Métricas de Seguridad
Al ingresar con la cuenta administradora (`admin` / `Admin123*`), el sistema despliega el **Panel de Administración**:
- **Tarjetas KPI en Tiempo Real:**
  - *Colaboradores Totales:* Cantidad de identidades registradas en el directorio.
  - *Cuentas Activas:* Porcentaje y conteo de cuentas habilitadas frente a suspendidas.
  - *Apps Integradas:* Número de aplicaciones corporativas federadas bajo SSO.
  - *Eventos Auditados:* Conteo acumulado de eventos registrados en la bitácora forense.

### 1.2 Gestión de Colaboradores y Control de Acceso Basado en Roles (RBAC)
PymeGuard IAM aplica el principio de menor privilegio mediante tres roles predefinidos:
1. **ADMIN (Administrador TI / Gerencia):** Acceso integral al portal, gestión de políticas, logs y revocaciones.
2. **CONTADOR (Finanzas y Operaciones):** Acceso autorizado a sistemas contables, ERP y repositorios documentales.
3. **EMPLEADO (Colaborador Estándar):** Acceso restringido únicamente a herramientas colaborativas y documentos comunes.

#### Alta de Nuevos Colaboradores:
1. En la pestaña **"Administración"**, diríjase a la sección **"Nuevo colaborador"**.
2. Complete los campos obligatorios con validación estricta:
   - **Usuario:** Nombre alfanumérico único de 3 a 30 caracteres (ej. `carlos.ramirez`).
   - **Nombre completo:** Nombre real del empleado.
   - **Contraseña inicial:** Mínimo 8 caracteres (ej. `PymeSecure2026*`).
   - **Rol asignado:** Seleccione `EMPLEADO`, `CONTADOR` o `ADMIN`.
3. Presione **"+ Registrar usuario"**.
4. *Mecanismo de Seguridad:* El usuario se registra automáticamente con la bandera `must_change_password = 1`. En su primer inicio de sesión, el sistema le impedirá el acceso a las aplicaciones hasta que reemplace esta contraseña provisional por una secreta definitiva.

#### Cambio de Roles y Desactivación Preventiva:
- En la tabla de usuarios, el Administrador puede alternar el rol de un colaborador mediante el selector en línea.
- Si un usuario olvida o bloquea su 2FA, el Administrador puede utilizar el botón **"Restablecer 2FA"** para reiniciar su segundo factor de manera segura.

### 1.3 Catálogo de Aplicaciones Single Sign-On (SSO)
1. Acceda a la subpestaña o bloque **"Catálogo de Aplicaciones"**.
2. Para integrar un nuevo aplicativo web corporativo:
   - Ingrese el **Nombre del aplicativo** (ej. *CRM Comercial*, *Plataforma de Tickets*).
   - Ingrese la **Descripción funcional**.
   - Defina la **URL de SSO**: Puede ser una ruta relativa local (como `/erp-demo`) o una URL absoluta (`https://app.empresa.com/sso`).
   - Marque los **Roles autorizados** que tendrán permiso para visualizar y solicitar tokens de acceso hacia este servicio.
3. Al guardar, las aplicaciones aparecerán inmediatamente en el portal de los colaboradores que coincidan con los roles autorizados.

### 1.4 Políticas Corporativas de Seguridad
Desde la sección de **Políticas**:
- **Nombre de la Organización:** Personaliza la razón social mostrada en toda la interfaz y encabezados del portal.
- **Segundo Factor (2FA) Obligatorio:** Si se activa, todos los colaboradores recibirán un banner de advertencia y se les exigirá configurar su autenticador TOTP antes de continuar operando.
- **Límite de Intentos Fallidos (Anti-Fuerza Bruta):** Valor por defecto: 5 intentos. Si un atacante supera este límite, la cuenta queda automáticamente bloqueada (`is_active = 0`), sus sesiones activas son destruidas y el evento queda grabado con severidad crítica en la auditoría.
- **Desbloqueo de Cuentas Bloqueadas:** El Administrador puede reactivar la cuenta bloqueada con un solo clic en la tabla de usuarios. Al reactivarse, el contador de intentos fallidos se reinicia a 0 de forma automática.

### 1.5 Protocolo de Desvinculación Inmediata (*One-Click Offboarding*)
En caso de despido, renuncia o sospecha de compromiso de credenciales:
1. Localice la fila del colaborador en la tabla de usuarios.
2. Haga clic en el botón rojo **"Revocar (Offboarding Express)"**.
3. Confirme la acción en el cuadro de diálogo.
4. **Lo que ocurre internamente en menos de 100 milisegundos:**
   - La cuenta pasa a estado inactivo (`is_active = 0`).
   - El atributo `token_version` en la base de datos se incrementa (+1).
   - Todas las sesiones registradas en la tabla `active_sessions` son marcadas como revocadas (`is_revoked = 1`).
   - Cualquier token JWT o token SSO que el usuario tuviera abierto en su navegador queda **automáticamente invalidado** (Zero-Trust). Al siguiente intento de recarga o consumo de API, el usuario es expulsado con error `HTTP 401 Unauthorized`.

### 1.6 Bitácora de Auditoría Forense y Exportación en CSV
- La pestaña **"Auditoría y Trazabilidad"** despliega la cronología exacta de eventos con: Marca de tiempo (Timestamp), Actor, Acción, Detalles e IP de origen.
- **Exportación en CSV:** Haga clic en **"↓ Exportar CSV"** para descargar de inmediato un reporte estructurado `auditoria_iam_YYYYMMDD.csv` compatible con Excel, PowerBI o sistemas SIEM corporativos.

### 1.7 Monitor de Dispositivos y Sesiones Activas
El Administrador puede auditar la lista de todos los dispositivos y navegadores conectados en la empresa, verificando:
- Identificador único de sesión (`JTI`).
- Dirección IP del cliente y agente de usuario (Chrome, Edge, Firefox).
- Fecha de inicio de sesión y fecha de caducidad.
- Posibilidad de cerrar cualquier sesión individual de manera remota sin afectar a otros colaboradores.

---

## Sección 2: Guía Operativa del Empleado / Colaborador

### 2.1 Primer Inicio de Sesión y Cambio Obligatorio de Contraseña
1. Ingrese a la URL principal del sistema (`http://127.0.0.1:8000`).
2. Introduzca su usuario corporativo y la contraseña temporal proporcionada por el Administrador.
3. Presione **"Continuar al portal"**.
4. El sistema detectará que es su primera vez e interrumpirá el flujo abriendo el modal obligatorio: **"Actualización Obligatoria de Contraseña"**.
5. Ingrese su nueva contraseña secreta (mínimo 8 caracteres) y confirme el valor idéntico.
6. Haga clic en **"Establecer Contraseña y Entrar"**.
7. La contraseña anterior quedará destruida en ese instante y su sesión se renovará de forma transparente.

### 2.2 Portal de Aplicaciones Corporativas (SSO con 1 Clic)
1. En la pestaña **"Aplicaciones"**, el colaborador observa exclusivamente las herramientas a las que su puesto tiene acceso autorizado por RBAC (ej. el rol `CONTADOR` ve el *Sistema Contable ERP* y la *Nube Corporativa*, mientras que la infraestructura de TI permanece oculta).
2. Cada tarjeta de aplicación incluye una insignia que indica el nivel de acceso concedido.
3. Al hacer clic en **"Abrir Aplicación (SSO) →"**:
   - PymeGuard IAM genera un token SSO efímero (vigencia de 5 minutos) firmado criptográficamente con los reclamos del usuario.
   - Se abre la aplicación de destino (ej. `/erp-demo`) transmitiendo la identidad federada.
   - El sistema externo valida la firma contra el IAM y da la bienvenida al usuario sin solicitar nuevamente contraseñas.

### 2.3 Configuración de Segundo Factor (2FA TOTP)
1. Diríjase a la pestaña **"Mi Seguridad"**.
2. En la tarjeta de Segundo Factor (2FA), haga clic en **"Configurar 2FA (TOTP)"**.
3. Se desplegará un código QR y una clave alfanumérica secreta Base32.
4. Abra su aplicación móvil favorita (**Google Authenticator**, **Authy** o **Microsoft Authenticator**) y escanee el código QR.
5. Inmediatamente se generarán códigos dinámicos de 6 dígitos que cambian cada 30 segundos.
6. A partir de este momento, cada vez que inicie sesión, el sistema solicitará este código tras ingresar su contraseña.

### 2.4 Resguardo y Uso de Códigos de Emergencia (*Recovery Codes*)
Junto con el código QR, PymeGuard IAM genera **5 códigos de respaldo alfanuméricos de emergencia** con el formato `PG-XXXX-YY` (por ejemplo: `PG-A8F2-3B`).

- **¿Para qué sirven?** Si el empleado extravía su teléfono celular, se queda sin batería o no tiene acceso a su aplicación de autenticación, puede escribir uno de estos códigos en el campo de código 2FA.
- **Principio de Un Solo Uso:** Cada código de respaldo funciona exactamente una vez. Una vez consumido, queda revocado de la base de datos de manera irreversible.
- **Acción recomendada:** Copie estos códigos presionando el botón **"Copiar códigos"** y guárdelos en un gestor seguro de contraseñas.

### 2.5 Gestión de Sesiones Propias y Cierre Remoto
En la sección inferior de **"Mi Seguridad"**, el colaborador puede revisar la lista de navegadores donde mantiene su sesión iniciada:
- Identifica cuál es su *Dispositivo Actual* (marcado en verde).
- Si detecta un dispositivo sospechoso o antiguo, puede presionar el botón de basura rojo para invalidar esa sesión de inmediato.

---

## Sección 3: Guion de Exposición en Vivo (5 Minutos) para Demostración

> **Propósito:** Cautivar a directores, evaluadores técnicos o inversionistas mostrando en vivo el ciclo completo de una arquitectura Zero-Trust real en una Pyme.

### 3.1 Preparación Previa al Pitch
- **Navegador:** Abra dos ventanas o pestañas independientes (idealmente una ventana normal para el Administrador y una ventana de incógnito para el Empleado).
- **Servidor:** Verifique que el servicio esté corriendo en `http://127.0.0.1:8000`.
- **Base de datos:** Base de datos restaurada en estado original con los usuarios `admin` y `empleado`.

---

### 3.2 Minuto a Minuto: Paso a Paso en Pantalla con Diálogos Clave

#### Minuto 0:00 a 1:00 — La Problemática y la Bienvenida Visual
- **Acción en pantalla:** Muestre la pantalla de inicio de sesión dividida (*Split-Screen*) en `http://127.0.0.1:8000`. Muestre la estética moderna en Modo Oscuro y alterne a Modo Claro con el interruptor en la esquina.
- **Diálogo del ponente:**
  > *"Muy buenos días. En América Latina, más del 80% de las Pymes sufren incidentes de seguridad porque sus empleados comparten contraseñas o porque los exempleados conservan acceso a los sistemas meses después de haberse ido. Hoy les presento **PymeGuard IAM**, una solución ligera, segura y sin fricción de Gestión de Identidades y Accesos con arquitectura Zero-Trust diseñada a la medida de la pequeña y mediana empresa."*

#### Minuto 1:00 a 2:00 — Inicio de Sesión de Empleado y Experiencia SSO
- **Acción en pantalla:** Haga clic en el botón de acceso rápido **"Empleado (empleado / User123*)"** y presione *"Continuar al portal"*.
- Muestre el Portal del Colaborador. Señale que el rol asignado es `CONTADOR`.
- Haga clic en el botón **"Abrir Aplicación (SSO) →"** de la tarjeta **"Sistema Contable ERP"**.
- La aplicación ERP (`/erp-demo`) se abre mostrando en vivo la verificación criptográfica: *"Identidad Verificada por PymeGuard IAM — JWT HS256 OK — Empleado: @empleado — Rol: CONTADOR"*.
- **Diálogo del ponente:**
  > *"Aquí vemos la experiencia del colaborador. Juan ingresa con sus credenciales y de inmediato ve las aplicaciones autorizadas para su rol contable. Con un solo clic, se conecta al Sistema ERP mediante un token JWT federado firmado por el IAM. Sin volver a escribir contraseñas, su identidad está autenticada y verificada."*

#### Minuto 2:00 a 3:30 — Demostración Cumbre: One-Click Offboarding Zero-Trust en Vivo
- **Acción en pantalla:**
  1. En la otra ventana (o cerrando sesión y entrando con `admin` / `Admin123*`), ingrese como Administrador y abra la pestaña **"Administración"**.
  2. Localice al usuario `empleado` (Juan Pérez) en la tabla.
  3. Comente a la audiencia: *"Imaginen que este colaborador acaba de ser desvinculado de la empresa en este preciso instante."*
  4. Haga clic en el botón rojo **"Revocar (Offboarding Express)"** y confirme. El estado de Juan cambia de inmediato a *"Inactivo"*.
  5. Vuelva a la ventana del **Sistema Contable ERP** (donde Juan estaba trabajando tranquilamente) y presione el botón **"Recargar / Verificar Sesión"** o refresque la página.
  6. **Resultado en pantalla:** La pantalla cambia inmediatamente a una alerta roja de alta seguridad: **"HTTP 401 — SESIÓN REVOCADA (One-Click Offboarding Zero-Trust)"**. El acceso al ERP quedó completamente bloqueado en tiempo real.
- **Diálogo del ponente:**
  > *"Esto es Zero-Trust real. No esperamos a que el token JWT expire en una hora. En el instante exacto en que el Administrador presionó el botón de revocación, la versión del token cambió en la base de datos y la sesión quedó destruida. Al siguiente milisegundo, cualquier sistema externo rechaza al usuario. Cero fugas de información, cero accesos residuales."*

#### Minuto 3:30 a 4:30 — Gestión de Políticas, Fuerza Bruta y Auditoría Forense
- **Acción en pantalla:** 
  1. En el panel de Administrador, diríjase a la sección de **"Políticas"** y muestre el control de límite de intentos fallidos.
  2. Vaya a **"Auditoría y Trazabilidad"**. Muestre cómo el evento `EMERGENCY_OFFBOARDING` quedó registrado con fecha, hora exacta, usuario ejecutor e IP.
  3. Haga clic en el botón **"↓ Exportar CSV"**. Muestre cómo se descarga el reporte listo para entregar al comité de auditoría o a la aseguradora contra riesgos cibernéticos.
- **Diálogo del ponente:**
  > *"Además, cada acción está protegida contra ataques de fuerza bruta y queda registrada en una bitácora inmutable. Con un clic podemos exportar este informe forense en CSV cumpliendo con las regulaciones de protección de datos y auditorías de seguridad."*

#### Minuto 4:30 a 5:00 — Cierre Contundente & Preguntas
- **Diálogo del ponente:**
  > *"PymeGuard IAM demuestra que una empresa pequeña no necesita gastar miles de dólares al mes para tener la misma seguridad y experiencia de acceso que un banco o una corporación global. Es rápido, es privado, es Zero-Trust y está listo para producción. Muchas gracias, quedo a su disposición para cualquier pregunta."*

---

## Sección 4: Tabla de Credenciales Operativas y Matriz de Cumplimiento Técnico

### 4.1 Cuentas Pre-cargadas de Demostración

| Usuario | Contraseña | Rol RBAC | Estado Inicial | Propósito en la Demostración |
| :--- | :--- | :--- | :--- | :--- |
| **`admin`** | `Admin123*` | `ADMIN` | Activo / 2FA Opcional | Control maestro, creación de usuarios, políticas, revocaciones y descarga de logs. |
| **`empleado`** | `User123*` | `CONTADOR` | Activo / 2FA Opcional | Demostración de acceso SSO al ERP Contable y prueba de revocación Zero-Trust. |

*(Nota: Al crear usuarios adicionales desde el panel de administración, el sistema los creará con cambio forzado de contraseña en su primer inicio).*

---

### 4.2 Matriz de Cumplimiento Técnico y Estándares de Ciberseguridad

| Requisito / Estándar de Seguridad | Mecanismo Implementado en PymeGuard IAM | Estado de Verificación |
| :--- | :--- | :---: |
| **Hashing Criptográfico de Contraseñas** | Algoritmo **bcrypt** con salting dinámico por usuario (passlib fallback). | **100% Cumplido** |
| **Tokens de Sesión Seguros** | Tokens JWT firmados con algoritmo criptográfico **HS256** y reclamo `jti` único. | **100% Cumplido** |
| **Revocación Instantánea (Zero-Trust)** | Validación concurrente de `token_version` e `is_active` en cada petición y endpoint SSO. | **100% Cumplido** |
| **Autenticación Multifactor (2FA)** | Estándar **TOTP RFC 6238** (códigos de 6 dígitos con ventana de deriva de ±30 segundos). | **100% Cumplido** |
| **Códigos de Respaldo de Emergencia** | Generación de 5 códigos alfanuméricos `PG-XXXX-YY` consumibles en modo **un solo uso**. | **100% Cumplido** |
| **Protección Anti-Fuerza Bruta** | Bloqueo automático de cuenta tras 5 intentos fallidos continuos (`is_active = 0`). | **100% Cumplido** |
| **Restablecimiento Limpio de Desbloqueo** | Al reactivar un usuario, `failed_attempts` se restablece a 0 para permitir login inmediato. | **100% Cumplido** |
| **Validaciones Estrictas de Entrada** | Esquemas Pydantic con validación regex para nombres, contraseñas (mín. 8 caracteres) y roles. | **100% Cumplido** |
| **Trazabilidad y Exportación Forense** | Tabla `audit_logs` con endpoints de consulta y descarga directa de archivos **CSV**. | **100% Cumplido** |
| **Interfaz Responsiva & Accesible** | Single Page Application con Tailwind CSS, modo Claro/Oscuro y cero errores de consola. | **100% Cumplido** |

---

### 4.3 Comandos de Despliegue y Ejecución de Batería de Pruebas

#### 1. Iniciar el Servidor de Aplicación:
```bash
# Desde la carpeta raíz del proyecto
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --app-dir pymeguard-iam/backend
```
*Abrir navegador en:* `http://127.0.0.1:8000`

#### 2. Ejecutar la Batería Completa de Pruebas Automatizadas (E2E):
```bash
python pymeguard-iam/test_suite.py
```
*El script ejecuta los 6 flujos de punta a punta, valida el 100% de las pruebas y restaura automáticamente la base de datos a su estado semilla inicial.*
