# Sistema de Automatización de Pruebas de Penetración

## Descripción General

Este sistema automatiza las pruebas de penetración en redes internas, implementando un enfoque modular que cubre todas las fases del ciclo de vida de un ataque: desde el reconocimiento inicial hasta la exfiltración de datos.

## ⚠️ ADVERTENCIA IMPORTANTE

**ESTE SISTEMA ES EXCLUSIVAMENTE PARA PRUEBAS DE PENETRACIÓN AUTORIZADAS Y EDUCACIÓN EN SEGURIDAD.**

- Solo use este sistema en redes que posea o tenga autorización explícita para probar
- El uso no autorizado de este sistema es ilegal y puede resultar en consecuencias legales graves
- Los desarrolladores no se hacen responsables del uso indebido de este software
- Siempre obtenga autorización por escrito antes de realizar pruebas de penetración

## Características Principales

### 🎯 Fases de Ataque Implementadas

1. **Reconocimiento Interno**
   - Escaneo de red con nmap y masscan
   - Descubrimiento de hosts con arp-scan
   - Traceroute para mapeo de rutas
   - Enumeración de servicios

1.5. **Reconocimiento Avanzado** (Nuevo)
   - Detección de arquitectura de sistemas
   - Identificación de sistemas operativos
   - Mapeo de topología de red
   - Detección de dispositivos específicos (IoT, impresoras, etc.)
   - Generación de mapa visual de red

2. **Recolección de Credenciales**
   - LLMNR/NBT-NS spoofing con Responder
   - Sniffing de tráfico con tcpdump
   - Ataques de fuerza bruta con Hydra
   - Verificación de credenciales por defecto

3. **Movimiento Lateral**
   - Acceso a recursos compartidos SMB
   - Explotación de vulnerabilidades conocidas (EternalBlue, SMBGhost, BlueKeep)
   - Exploits de servicios web (Tomcat, Struts, Jenkins)
   - Establecimiento de acceso lateral

4. **Persistencia y Ocultación (Modo Sigiloso)**
   - Instalación de backdoors disfrazados (netcat, PowerShell, Python)
   - Creación de tareas programadas con nombres legítimos
   - Modificación del registro de Windows con entradas discretas
   - Instalación de servicios maliciosos disfrazados
   - **Conexiones persistentes** para acceso remoto continuo
   - **Usuarios sigilosos** con nombres y contraseñas realistas

5. **Escalada de Privilegios**
   - Dump de hashes con Mimikatz
   - Enumeración con CrackMapExec
   - Acceso de Domain Admin
   - Técnicas de escalada de privilegios

6. **Exfiltración de Datos**
   - Recopilación de datos sensibles
   - Compresión de datos (con permisos)
   - Encriptación de datos (con permisos)
   - Corrupción de datos (con permisos críticos)
   - Transferencia a servidor remoto
   - Gestión de exploits persistentes
   - Limpieza selectiva (solo evidencia o backdoors completos)

7. **Explotación de Dispositivos IoT**
   - Explotación de cámaras IP (Ezviz, Hikvision, Dahua)
   - Ataques a routers (TP-Link, D-Link, Netgear)
   - Explotación de dispositivos IoT (Intelbras, Axis, Bosch)
   - Acceso remoto a cámaras de seguridad
   - Explotación de vulnerabilidades IoT conocidas
   - Establecimiento de acceso visual a la red

8. **Exfiltración de Bases de Datos SQL**
   - Descubrimiento de bases de datos (MySQL, MSSQL, PostgreSQL, Oracle, MongoDB, Redis)
   - Prueba de credenciales por defecto
   - Ataques de SQL injection (UNION, Boolean, Time-based, Error-based)
   - Exfiltración de datos de bases de datos
   - Establecimiento de conexiones remotas
   - Extracción de esquemas y datos sensibles

9. **Gestión de Backdoors y Accesos Remotos**
   - Descubrimiento automático de backdoors existentes
   - Prueba de conexiones de backdoors activos
   - Ejecución de escaneos remotos desde backdoors
   - Gestión de accesos remotos (modificar IPs, puertos, credenciales)

10. **Tareas Post-Ejecución** (Nuevo)
    - Escaneo profundo de red desde backdoors
    - Extracción avanzada de credenciales (Kerberoasting, ASREPRoasting, DCSync)
    - Escalada de privilegios avanzada (kernel exploits, UAC bypass)
    - Movimiento lateral avanzado (Pass-the-hash, WMI, DCOM)
    - Exfiltración comprehensiva de datos
    - Persistencia avanzada (WMI events, COM hijacking)
    - Mapeo completo de red

### 📁 **Gestión de Escaneos por Carpetas**

#### **Organización Automática**
- **Carpeta por escaneo**: Cada escaneo se organiza en su propia carpeta con mote
- **Estructura organizada**: 
  - `logs/` - Logs de cada fase
  - `evidence/` - Evidencia de cada fase
  - `exfiltration/` - Datos exfiltrados
  - `console/` - Salida de consola completa
  - `reports/` - Reportes generados
  - `backdoors/` - Información de backdoors
  - `config/` - Configuración del escaneo

#### **Funcionalidades de Gestión**
- **📋 Listar escaneos**: Ver todos los escaneos disponibles
- **🔍 Ver detalles**: Información completa de cada escaneo
- **📊 Ver resumen**: Estadísticas y fases completadas
- **🗂️ Explorar archivos**: Navegar por la estructura de archivos
- **🔄 Continuar escaneos**: Retomar escaneos desde cualquier punto
- **🔐 Cargar backdoors**: Usar escaneos como fuente de backdoors

### 🧊 **Pentest Frío**

#### **Características del Pentest Frío**
- **Ejecución completa**: Ejecuta todas las fases del pentest
- **Limpieza automática**: Elimina todos los backdoors, credenciales y persistencia al final
- **Datos de referencia**: Guarda solo los datos para análisis, sin accesos activos
- **Identificación clara**: Marcado como "🧊 FRÍO" en todos los menús
- **Advertencias**: Avisos claros de que los datos son solo de referencia

#### **Proceso de Limpieza**
- **Backdoors**: Elimina todos los backdoors establecidos
- **Credenciales**: Remueve usuarios creados
- **Persistencia**: Limpia tareas programadas, servicios y modificaciones de registro
- **Conexiones**: Cierra conexiones persistentes (SSH, RDP, Web)
- **Archivos**: Limpia archivos temporales y evidencia
- **Reporte de limpieza**: Genera reporte detallado de lo que fue eliminado

#### **Casos de Uso**
- **Pruebas de concepto**: Verificar capacidades sin dejar rastros
- **Evaluaciones**: Probar vulnerabilidades sin comprometer sistemas
- **Demostraciones**: Mostrar capacidades sin riesgo
- **Análisis**: Obtener datos de referencia para reportes

### 🌐 **Frontend Web para Reportes**

#### **Características del Frontend**
- **Interfaz elegante**: Diseño moderno y profesional
- **Visualización interactiva**: Navegación intuitiva por resultados
- **Secciones organizadas**: Información estructurada y fácil de entender
- **Instrucciones de uso**: Comandos y acciones para cada backdoor
- **Soporte completo**: Pentest normal y pentest frío

#### **Funcionalidades**
- **📊 Estadísticas**: Resumen numérico de resultados
- **🔐 Persistencia**: Lista detallada de backdoors con instrucciones
- **🖥️ Sistemas comprometidos**: Hosts accesibles con credenciales
- **📹 Dispositivos IoT**: Cámaras y dispositivos accesibles
- **🗄️ Bases de datos**: Conexiones establecidas
- **📥 Datos exfiltrados**: Archivos y tamaños
- **🗺️ Mapa de red**: Topología descubierta

#### **Uso del Frontend**
```bash
# Iniciar servidor web
python start_web_frontend.py

# Acceder en navegador
http://localhost:8080
```

#### **Instrucciones de Backdoors**
- **Netcat**: `nc IP PUERTO` - Conexión directa
- **PowerShell**: Comandos para ejecutar payloads
- **Cámaras**: `ffplay rtsp://usuario:password@IP:puerto/stream`
- **Bases de datos**: `mysql -h IP -P PUERTO -u usuario -ppassword`
- **SSH**: `ssh usuario@IP` - Acceso al sistema

### ⚡ **Exfiltración Inteligente**

#### **Configuración de Opciones Delicadas**
- **Al inicio del script** se pregunta si habilitar opciones delicadas
- **Si se dice NO** → Solo exfiltración rápida de archivos pequeños
- **Si se dice SÍ** → Se configuran opciones específicas:
  - ✅ Compresión de archivos del sistema
  - ✅ Encriptación de datos sensibles  
  - ✅ Corrupción de archivos críticos

#### **Modos de Exfiltración**
- **⚡ Exfiltración Rápida**: Solo archivos pequeños (< 10MB)
  - Excluye: fotos, videos, audio, archivos comprimidos
  - Incluye: configuraciones, logs, documentos pequeños, scripts
  - Límite total: 100MB máximo
- **🆕 Exfiltración Completa**: Todos los archivos del sistema
  - Sin límites de tamaño
  - Incluye todos los tipos de archivos
  - Opciones delicadas aplicables

#### **Gestión desde Backdoors**
- **🔓 Sin límites**: Todas las opciones delicadas disponibles
- **📤 Exfiltración completa** desde backdoors establecidos
- **🔧 Gestión avanzada** de accesos remotos
   - Actualización automática de logs con cambios
   - Escaneo completo desde conexiones establecidas

### 🔧 Características Técnicas

- **Arquitectura Modular**: Cada fase es un módulo independiente
- **Sistema de Logging Avanzado**: Registro detallado de todas las actividades
- **Configuración Flexible**: Parámetros adaptables via JSON
- **Evidencia Automática**: Captura y almacenamiento de evidencia
- **Reportes Detallados**: Generación automática de reportes
- **Manejo de Errores**: Recuperación robusta ante fallos
- **🕵️ Modo Sigiloso**: Técnicas de persistencia disfrazadas y realistas
- **🔗 Conexiones Persistentes**: Acceso remoto continuo y automático
- **👤 Usuarios Sigilosos**: Nombres y contraseñas que pasan desapercibidos
- **🔍 Reconocimiento Avanzado**: Detección de arquitectura, SO y topología de red
- **🔧 Tareas Post-Ejecución**: Procedimientos extensos desde backdoors establecidos
- **📁 Gestión de Escaneos**: Organización por carpetas con mote, evidencia y logs
- **🧊 Pentest Frío**: Ejecuta todo pero limpia al final, solo datos de referencia
- **🌐 Frontend Web**: Visualizador elegante de reportes con interfaz web

## Requisitos del Sistema

### Sistema Operativo
- Kali Linux (recomendado)
- Ubuntu/Debian con herramientas de pentesting
- Otras distribuciones Linux compatibles

### Herramientas Requeridas
```bash
# Herramientas de escaneo
sudo apt install nmap masscan arp-scan traceroute

# Herramientas de ataque
sudo apt install responder tcpdump hydra smbclient

# Metasploit Framework
sudo apt install metasploit-framework

# Herramientas adicionales
sudo apt install netcat-openbsd mimikatz crackmapexec
sudo apt install whatweb dirb sshpass rdesktop
```

### Dependencias de Python
```bash
pip install -r requirements.txt
```

## Instalación

### 1. Clonar el Repositorio
```bash
git clone <repository-url>
cd pentest-automation
```

### 2. Instalar Dependencias
```bash
# Instalar herramientas del sistema
sudo apt update
sudo apt install nmap masscan arp-scan traceroute responder tcpdump hydra smbclient metasploit-framework netcat-openbsd crackmapexec whatweb dirb sshpass rdesktop

# Instalar dependencias de Python
pip install -r requirements.txt
```

### 3. Configurar Permisos
```bash
chmod +x pentest_automation.py
chmod +x modules/*.py
```

### 4. Configurar el Sistema
```bash
# Copiar y editar configuración
cp config.json.example config.json
nano config.json
```

## Configuración

### Configuración Automática (RECOMENDADO)

El sistema puede configurarse automáticamente detectando:
- ✅ **Interfaz de red activa** (prioriza WiFi)
- ✅ **IP local** de la interfaz
- ✅ **Red objetivo** basada en la IP local
- ✅ **Router/Gateway** por defecto

```bash
# Configurar automáticamente
python3 pentest_automation.py --auto-config

# Ver información de red
python3 network_info.py
```

### Archivo de Configuración (config.json)

```json
{
  "network_config": {
    "target_network": "192.168.1.0/24",
    "interface": "eth0",
    "router_ip": "192.168.1.1",
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "scan_rate": 10000,
    "timeout": 30
  },
  "credentials": {
    "wifi_password": "",
    "default_users": ["admin", "administrator", "root", "guest", "user"],
    "default_passwords": ["admin", "password", "123456", "root", "guest", ""],
    "password_lists": [
      "/usr/share/wordlists/rockyou.txt",
      "/usr/share/wordlists/metasploit/unix_passwords.txt"
    ]
  },
  "targets": {
    "common_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900, 8080],
    "vulnerable_services": {
      "smb": {"port": 445, "version": "1"},
      "rdp": {"port": 3389},
      "ftp": {"port": 21},
      "ssh": {"port": 22},
      "http": {"port": 80},
      "https": {"port": 443}
    }
  },
  "exploitation": {
    "metasploit_path": "/usr/share/metasploit-framework",
    "payloads": {
      "windows": "windows/meterpreter/reverse_tcp",
      "linux": "linux/x86/meterpreter/reverse_tcp"
    },
    "lhost": "192.168.1.50",
    "lport": 4444
  },
  "persistence": {
    "backdoor_ports": [4444, 5555, 6666],
    "scheduled_tasks": true,
    "registry_modifications": true
  },
  "exfiltration": {
    "remote_server": "192.168.1.200",
    "remote_user": "pentest",
    "remote_path": "/tmp/exfiltrated_data",
    "compression": true,
    "encryption": false,
    "max_data_size": 1073741824
  },
  "logging": {
    "log_level": "INFO",
    "log_file": "pentest_automation.log",
    "detailed_logs": true,
    "save_screenshots": true,
    "save_evidence": true
  },
  "safety": {
    "dry_run": false,
    "confirm_actions": true,
    "backup_before_changes": true,
    "max_concurrent_scans": 5
  }
}
```

### Parámetros de Configuración

#### network_config
- `target_network`: Red objetivo para el escaneo
- `interface`: Interfaz de red a utilizar
- `router_ip`: IP del router (se detecta automáticamente si está vacío)
- `dns_servers`: Servidores DNS a utilizar
- `scan_rate`: Velocidad de escaneo para masscan
- `timeout`: Timeout para comandos

#### credentials
- `wifi_password`: Contraseña de WiFi (si es necesaria)
- `default_users`: Lista de usuarios por defecto para probar
- `default_passwords`: Lista de contraseñas por defecto
- `password_lists`: Rutas a listas de contraseñas

#### targets
- `common_ports`: Puertos comunes a escanear
- `vulnerable_services`: Configuración de servicios vulnerables

#### exploitation
- `metasploit_path`: Ruta al framework Metasploit
- `payloads`: Payloads por defecto para diferentes sistemas
- `lhost`: IP local para reverse shells
- `lport`: Puerto local para reverse shells

#### persistence
- `backdoor_ports`: Puertos para backdoors
- `scheduled_tasks`: Habilitar tareas programadas
- `registry_modifications`: Habilitar modificaciones de registro

#### exfiltration
- `remote_server`: Servidor remoto para exfiltración
- `remote_user`: Usuario para conexión remota
- `remote_path`: Ruta remota para datos exfiltrados
- `compression`: Habilitar compresión de datos (requiere permisos)
- `encryption`: Habilitar encriptación de datos (requiere permisos)
- `max_data_size`: Límite de tamaño de datos en bytes (default: 1GB)

#### logging
- `log_level`: Nivel de logging (DEBUG, INFO, WARNING, ERROR)
- `log_file`: Archivo de log principal
- `detailed_logs`: Habilitar logs detallados
- `save_screenshots`: Guardar capturas de pantalla
- `save_evidence`: Guardar evidencia

#### safety
- `dry_run`: Modo de prueba (no ejecuta comandos reales)
- `confirm_actions`: Solicitar confirmación antes de acciones críticas
- `backup_before_changes`: Crear respaldos antes de cambios
- `max_concurrent_scans`: Máximo número de escaneos concurrentes

#### stealth_mode (Nuevo)
- `stealth_mode`: Habilitar modo sigiloso para persistencia
- `stealth_users`: Usuarios con nombres realistas por sistema operativo
- `stealth_passwords`: Contraseñas creíbles y difíciles de detectar
- `persistent_connections`: Configuración de conexiones persistentes
- `stealth_names`: Nombres disfrazados para servicios y tareas

## 🕵️ Características Sigilosas

### Modo Sigiloso Avanzado

El sistema ahora incluye un **modo sigiloso** que hace que las técnicas de persistencia sean mucho más difíciles de detectar por equipos de seguridad:

#### 👤 Usuarios Sigilosos
- **Windows**: `svc_windowsupdate`, `svc_systemmaintenance`, `svc_networkmonitor`
- **Linux**: `svc_loganalyzer`, `svc_systemmonitor`, `svc_networkcheck`
- **Contraseñas realistas**: `W1nd0ws_Upd@te_2024!`, `Syst3m_M@int3n@nce_2024!`

#### 🔧 Servicios Disfrazados
- **Windows**: `WindowsUpdateService` (usa `wuauclt.exe`)
- **Linux**: `system-monitor` (monitoreo del sistema)
- **Tareas programadas**: `WindowsUpdateService` (ejecuta a las 3:00 AM)

#### 🔗 Conexiones Persistentes
- **SSH**: Conexión reversa cada 60 segundos
- **RDP**: Verificación de conectividad cada 5 minutos
- **Web**: Heartbeat HTTP cada 5 minutos
- **Reconexión automática** si se pierde la conexión

#### 📁 Archivos y Rutas Sigilosas
- **Windows**: `C:\Windows\System32\WindowsUpdate.ps1`
- **Linux**: `/usr/local/bin/system-monitor.sh`
- **Logs**: `/tmp/.network_monitor.pid`
- **Cron**: Tareas de mantenimiento del sistema

### 🎯 Desafío para Equipos de Seguridad

Estas características están diseñadas para crear un **desafío realista** donde los equipos de seguridad deben:

1. **Detectar usuarios sospechosos** entre cuentas legítimas
2. **Identificar servicios maliciosos** disfrazados como legítimos
3. **Encontrar conexiones persistentes** ocultas en el tráfico normal
4. **Localizar archivos maliciosos** en rutas del sistema
5. **Analizar logs del sistema** para encontrar actividad sospechosa

## 📹 Explotación de Cámaras IP y Dispositivos IoT

### Cámaras Detectadas en el Reporte

El sistema ha identificado una **cámara Ezviz** en la red:
- **IP**: 192.168.1.218
- **Vendor**: Hangzhou Ezviz Software
- **MAC**: 34:C6:DD:B4:97:4F

### Exploits Implementados

#### 🎥 Cámaras Ezviz
- **Credenciales por defecto**: admin/admin, admin/12345, admin/password
- **Path Traversal**: Acceso a archivos del sistema
- **RCE**: Ejecución remota de comandos
- **Stream RTSP**: Acceso directo al video en vivo

#### 🔧 Routers TP-Link
- **Command Injection**: Inyección de comandos en formularios
- **Backdoor**: Acceso a backdoors conocidos
- **Credenciales por defecto**: admin/admin, admin/password

#### 📡 Dispositivos Intelbras
- **RCE**: Ejecución remota de comandos
- **Path Traversal**: Acceso a archivos del sistema
- **Credenciales por defecto**: admin/admin, admin/123456

### Acceso Remoto Configurado

Una vez comprometida una cámara, el sistema genera:

1. **Script de acceso web**: `camera_access_192.168.1.218.sh`
2. **URL de interfaz web**: `http://192.168.1.218:80`
3. **Stream RTSP**: `rtsp://admin:admin@192.168.1.218:554/stream1`
4. **Stream alternativo**: `rtsp://admin:admin@192.168.1.218:8554/stream1`

### Comandos de Acceso

```bash
# Acceder a la interfaz web
xdg-open http://192.168.1.218:80

# Reproducir stream con VLC
vlc rtsp://admin:admin@192.168.1.218:554/stream1

# Usar ffmpeg para grabar
ffmpeg -i rtsp://admin:admin@192.168.1.218:554/stream1 -t 60 output.mp4
```

## 🗄️ Exfiltración de Bases de Datos SQL

### Bases de Datos Soportadas

El sistema puede detectar y explotar las siguientes bases de datos:

#### 🐬 MySQL
- **Puerto**: 3306
- **Credenciales por defecto**: root/root, admin/admin, mysql/mysql
- **Comandos de conexión**: `mysql -h IP -u usuario -p`

#### 🏢 MSSQL (Microsoft SQL Server)
- **Puerto**: 1433
- **Credenciales por defecto**: sa/sa, admin/admin, administrator/admin
- **Comandos de conexión**: `sqlcmd -S IP,1433 -U usuario -P contraseña`

#### 🐘 PostgreSQL
- **Puerto**: 5432
- **Credenciales por defecto**: postgres/postgres, admin/admin, root/root
- **Comandos de conexión**: `psql -h IP -U usuario -d postgres`

#### 🏛️ Oracle
- **Puerto**: 1521
- **Credenciales por defecto**: system/system, sys/sys, admin/admin
- **Comandos de conexión**: `sqlplus usuario/contraseña@IP:1521/XE`

#### 🍃 MongoDB
- **Puerto**: 27017
- **Credenciales por defecto**: admin/admin, root/root, user/user
- **Comandos de conexión**: `mongo mongodb://usuario:contraseña@IP:27017/admin`

#### 🔴 Redis
- **Puerto**: 6379
- **Credenciales por defecto**: default/, admin/admin
- **Comandos de conexión**: `redis-cli -h IP -p 6379 -a contraseña`

### Técnicas de SQL Injection

#### 💉 UNION-based
```sql
' UNION SELECT 1,2,3,4,5--
' UNION SELECT user(),database(),version(),4,5--
' UNION SELECT table_name,column_name,3,4,5 FROM information_schema.columns--
```

#### 🔍 Boolean-based
```sql
' OR '1'='1
' OR 1=1--
' AND 1=1--
' AND 1=2--
```

#### ⏰ Time-based
```sql
'; WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--
'; SELECT SLEEP(5)--
```

#### ❌ Error-based
```sql
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--
```

### Conexiones Remotas Configuradas

Una vez comprometida una base de datos, el sistema genera:

1. **Script de conexión**: `db_connection_IP_tipo.sh`
2. **Credenciales válidas**: Usuario y contraseña
3. **Comandos de acceso**: Comandos específicos por tipo de BD
4. **Datos exfiltrados**: Esquemas, tablas, usuarios

### Comandos de Acceso

```bash
# Conectar a MySQL
mysql -h 192.168.1.5 -P 3306 -u root -p

# Conectar a MSSQL
sqlcmd -S 192.168.1.7,1433 -U sa -P admin

# Conectar a PostgreSQL
psql -h 192.168.1.12 -p 5432 -U postgres -d postgres

# Conectar a MongoDB
mongo mongodb://admin:admin@192.168.1.17:27017/admin

# Conectar a Redis
redis-cli -h 192.168.1.18 -p 6379 -a admin
```

## 🔐 Gestión de Backdoors y Accesos Remotos

### Funcionalidades Principales

El sistema de gestión de backdoors permite:

#### 📂 **Carga desde Logs Específicos**
- **Selecciona log específico** como punto de partida
- **Carga backdoors** desde evidencia guardada
- **Usa como referencia** logs de pentesting anteriores
- **Mantiene contexto** de escaneos previos

#### 🔍 **Descubrimiento Automático**
- Busca backdoors en logs de persistencia
- Identifica accesos remotos de cámaras IoT
- Detecta conexiones de bases de datos
- Carga automáticamente desde evidencia existente

#### 🔗 **Prueba de Conexiones**
- Verifica estado de backdoors netcat
- Prueba accesos a cámaras IP
- Valida conexiones a bases de datos
- Mide tiempos de respuesta

#### 🚀 **Escaneo Remoto**
- Ejecuta reconocimiento desde backdoors
- Realiza movimiento lateral remoto
- Verifica persistencia desde conexiones establecidas
- Escanea red desde dispositivos comprometidos

#### 🔧 **Gestión de Accesos**
- Modifica direcciones IP de backdoors
- Cambia puertos de conexión
- Actualiza credenciales de acceso
- Modifica scripts de conexión

### Tipos de Backdoors Soportados

#### 🖥️ **Backdoors de Sistema**
- **Netcat**: Conexiones TCP reversas
- **PowerShell**: Scripts de PowerShell persistentes
- **Python**: Backdoors en Python

#### 📹 **Accesos de Cámaras**
- **Ezviz**: Cámaras de seguridad
- **Hikvision**: Sistemas de videovigilancia
- **Dahua**: Cámaras IP

#### 🗄️ **Conexiones de Bases de Datos**
- **MySQL**: Conexiones a bases de datos MySQL
- **MSSQL**: Acceso a SQL Server
- **PostgreSQL**: Conexiones PostgreSQL
- **MongoDB**: Acceso a MongoDB
- **Redis**: Conexiones Redis

### Comandos de Gestión

```bash
# Ejecutar gestión de backdoors
python3 pentest_automation.py -p backdoor

# Desde menú interactivo
python3 pentest_automation.py
# Seleccionar opción 7: Gestión de backdoors

# Flujo recomendado:
# 1. Seleccionar "Cargar backdoors desde log específico"
# 2. Elegir log de pentesting anterior
# 3. Probar conexiones de backdoors
# 4. Ejecutar escaneos remotos desde backdoors
# 5. Gestionar accesos remotos según necesidad
```

### Flujo de Trabajo con Logs

1. **📂 Seleccionar Log**: Elige un log de pentesting anterior como punto de partida
2. **🔍 Cargar Backdoors**: El sistema extrae automáticamente todos los backdoors del log
3. **🔗 Probar Conexiones**: Verifica qué backdoors siguen activos
4. **🚀 Ejecutar Escaneos**: Usa backdoors activos para escaneos remotos
5. **🔧 Gestionar Accesos**: Modifica configuraciones según necesidad

### Actualización Automática de Logs

El sistema actualiza automáticamente los logs cuando se modifican accesos:

```json
{
  "timestamp": 1757184150.567725,
  "action": "ACCESS_MODIFIED",
  "access_id": "backdoor_192.168.1.5",
  "original": {
    "ip": "192.168.1.5",
    "port": "4444",
    "username": "admin"
  },
  "modified": {
    "ip": "192.168.1.10",
    "port": "5555",
    "username": "svc_windowsupdate"
  },
  "changes": {
    "ip": "192.168.1.10",
    "port": "5555",
    "username": "svc_windowsupdate"
  }
}
```

### Demo de Exfiltración SQL

Para probar el módulo de exfiltración SQL:

```bash
# Ejecutar demo de exfiltración SQL
python3 examples/sql_exfiltration_demo.py

# El demo incluye:
# - Descubrimiento de bases de datos
# - Ataques de SQL injection
# - Exfiltración de datos
# - Establecimiento de conexiones remotas
```

### Demo de Gestión de Backdoors

Para probar el módulo de gestión de backdoors:

```bash
# Ejecutar demo de gestión de backdoors
python3 examples/backdoor_management_demo.py

# El demo incluye:
# - Descubrimiento de backdoors existentes
# - Prueba de conexiones
# - Ejecución de escaneos remotos
# - Gestión de accesos remotos
# - Modificación de configuraciones
```

### Demo de Carga desde Logs

Para probar la carga de backdoors desde logs específicos:

```bash
# Ejecutar demo de carga desde logs
python3 examples/backdoor_from_log_demo.py

# El demo incluye:
# - Creación de logs de ejemplo
# - Carga desde log específico
# - Carga desde evidencia de persistencia
# - Carga desde evidencia de IoT
# - Carga desde evidencia de SQL
# - Descubrimiento desde todos los logs
```

### Demo de Opciones Delicadas

Para probar la configuración de opciones delicadas:

```bash
# Ejecutar demo de opciones delicadas
python3 examples/delicate_options_demo.py

# El demo incluye:
# - Configuración de opciones delicadas
# - Comparación entre escaneo normal y gestión de backdoors
# - Demostración de modos de exfiltración
# - Ejemplos de archivos incluidos/excluidos
```

## Uso

### 🎯 Modo Interactivo (Recomendado)

El sistema ahora incluye un menú interactivo que se ejecuta por defecto:

```bash
# Ejecutar con menú interactivo (por defecto)
python3 pentest_automation.py

# Usar modo legacy con argumentos de línea de comandos
python3 pentest_automation.py --legacy --dry-run
```

**⚠️ Configuración de Opciones Delicadas (al inicio):**
- El sistema pregunta si habilitar opciones delicadas
- **Si dice NO** → Solo exfiltración rápida de archivos pequeños
- **Si dice SÍ** → Configuración específica de compresión, encriptación y corrupción

**Menú Principal:**
1. ⚙️ **Configuración automática de red**
2. 🚀 **Escaneo completo (todas las fases)**
3. 🧪 **Modo de prueba (dry-run)**
4. 📋 **Escaneo por módulos específicos**
5. 📂 **Continuar escaneo desde log existente**
6. 📊 **Ver logs y reportes existentes**
7. 🔍 **Reconocimiento avanzado**
8. 📁 **Gestión de escaneos** (Nuevo)
9. 🔐 **Gestión de backdoors y accesos remotos**
10. ❌ **Salir del sistema**

**Características del modo interactivo:**
- 🏷️ **Motes personalizados**: Asigne nombres personalizados a sus escaneos
- 📋 **Selección de módulos**: Elija exactamente qué fases ejecutar
- 📂 **Gestión de logs**: Vea y continúe escaneos anteriores
- 🎨 **Interfaz colorizada**: Mensajes claros con códigos de color
- ⚡ **Logging en tiempo real**: No pierda progreso si se interrumpe

### 🔐 Sistema de Permisos y Confirmaciones

El sistema incluye un sistema robusto de permisos para acciones que pueden modificar o dañar el sistema objetivo:

**Niveles de Riesgo:**
- 🟢 **BAJO**: Acciones seguras (limpieza de evidencia)
- 🟡 **MEDIO**: Acciones que modifican archivos (compresión, creación)
- 🟠 **ALTO**: Acciones que modifican el sistema (encriptación, backdoors)
- 🔴 **CRÍTICO**: Acciones irreversibles (corrupción de datos)

**Sistema de Confirmación:**
1. **Primera confirmación**: Pregunta básica de proceder
2. **Doble confirmación**: Para acciones irreversibles
3. **PIN de aprobación**: `0443` para acciones críticas

**Acciones Protegidas:**
- 🔒 **Encriptación de datos**: Requiere permiso del usuario
- 💥 **Corrupción de datos**: Requiere PIN de aprobación
- 🗜️ **Compresión de archivos**: Requiere confirmación
- 🧹 **Limpieza de backdoors**: Requiere doble confirmación
- 🧽 **Limpieza de evidencia**: Opción segura (mantiene accesos)

### 🏷️ Sistema de Motes Personalizados

Cada escaneo puede tener un "mote" (nombre personalizado) para facilitar la identificación:

**Ejemplos de motes:**
- `Red_Principal_2024`
- `Auditoria_Cliente_X`
- `Prueba_Desarrollo`
- `Penetration_Test_Office`

**Características:**
- 📝 **Identificación fácil**: Encuentre rápidamente sus escaneos
- 📅 **Fechas automáticas**: Se sugiere fecha/hora si no especifica
- 🔍 **Búsqueda rápida**: Filtre logs por mote personalizado
- 📊 **Historial organizado**: Vea todos sus escaneos con nombres descriptivos

### Modo Gestión de Exploits Persistentes

El sistema ahora incluye un modo especial para gestionar exploits persistentes existentes sin necesidad de re-escanear la red:

```bash
# Gestionar exploits persistentes desde logs existentes
python3 pentest_automation.py --manage-exploits -p exfil

# Con archivo de log específico
python3 pentest_automation.py --manage-exploits --log-file pentest_automation.log -p exfil
```

**Características del modo gestión:**
- 📋 Carga exploits persistentes desde logs existentes
- 🔧 Opciones de gestión: exfiltrar, limpiar, modificar, probar conectividad
- 🧹 Limpieza automática de backdoors y evidencia
- 🔍 Pruebas de conectividad de firewalls
- 📊 Reportes detallados de estado de exploits

**Opciones disponibles:**
1. **Exfiltrar datos** desde exploits activos
2. **Limpiar todos** los exploits persistentes
3. **Modificar configuración** de exploits (IPs, puertos)
4. **Probar conectividad** de backdoors
5. **Continuar sin cambios**

### Configuración Automática
```bash
# Configurar automáticamente datos de red
python3 pentest_automation.py --auto-config

# Ver información de red del sistema
python3 network_info.py
```

### Ejecución Completa
```bash
# Ejecutar prueba de penetración completa (con auto-configuración)
python3 pentest_automation.py

# Ejecutar con configuración personalizada
python3 pentest_automation.py -c mi_config.json

# Ejecutar en modo dry-run
python3 pentest_automation.py --dry-run
```

### Ejecución por Fases
```bash
# Solo reconocimiento
python3 pentest_automation.py -p recon

# Solo recolección de credenciales
python3 pentest_automation.py -p creds

# Solo movimiento lateral
python3 pentest_automation.py -p lateral

# Solo persistencia
python3 pentest_automation.py -p persist

# Solo escalada de privilegios
python3 pentest_automation.py -p priv

# Solo exfiltración
python3 pentest_automation.py -p exfil

# Solo explotación IoT
python3 pentest_automation.py -p iot

# Solo exfiltración SQL
python3 pentest_automation.py -p sql

# Solo gestión de backdoors
python3 pentest_automation.py -p backdoor

# Gestión de exploits persistentes existentes
python3 pentest_automation.py --manage-exploits -p exfil

# Gestión con archivo de log específico
python3 pentest_automation.py --manage-exploits --log-file mi_log.log -p exfil
```

### Opciones de Línea de Comandos

**Modo Interactivo (por defecto):**
```bash
python3 pentest_automation.py                    # Menú interactivo
python3 pentest_automation.py -c mi_config.json  # Con configuración personalizada
```

**Modo Legacy (argumentos de línea de comandos):**
```bash
python3 pentest_automation.py --legacy [opciones]

Opciones:
  -c, --config CONFIG    Archivo de configuración (default: config.json)
  --legacy              Usar modo legacy con argumentos de línea de comandos
  -p, --phase PHASE      Fase específica a ejecutar (solo en modo legacy)
  --dry-run             Ejecutar en modo de prueba (solo en modo legacy)
  --auto-config         Solo ejecutar configuración automática (solo en modo legacy)
  --manage-exploits     Modo gestión de exploits persistentes (solo en modo legacy)
  --log-file FILE       Archivo de log para cargar exploits (solo en modo legacy)
  -h, --help            Mostrar ayuda
```

## Estructura del Proyecto

```
pentest-automation/
├── pentest_automation.py          # Script principal
├── config.json                    # Configuración
├── requirements.txt               # Dependencias de Python
├── README.md                      # Este archivo
├── MANUAL.md                      # Manual detallado
├── modules/                       # Módulos del sistema
│   ├── __init__.py
│   ├── logging_system.py          # Sistema de logging
│   ├── reconnaissance.py          # Módulo de reconocimiento
│   ├── credential_harvesting.py   # Módulo de credenciales
│   ├── lateral_movement.py        # Módulo de movimiento lateral
│   ├── persistence.py             # Módulo de persistencia
│   ├── privilege_escalation.py    # Módulo de escalada de privilegios
│   └── exfiltration.py            # Módulo de exfiltración
├── evidence/                      # Evidencia recopilada
│   ├── logs/                      # Logs estructurados
│   ├── screenshots/               # Capturas de pantalla
│   ├── data/                      # Datos recopilados
│   ├── credentials/               # Credenciales encontradas
│   ├── lateral_movement/          # Evidencia de movimiento lateral
│   ├── persistence/               # Evidencia de persistencia
│   ├── privilege_escalation/      # Evidencia de escalada
│   └── exfiltration/              # Evidencia de exfiltración
└── reports/                       # Reportes generados
    ├── pentest_report_YYYYMMDD_HHMMSS.json
    └── phase_reports/
```

## Logging y Evidencia

### Sistema de Logging
El sistema genera múltiples tipos de logs:

1. **Log Principal**: `pentest_automation.log`
2. **Logs Estructurados**: `evidence/logs/structured_events.jsonl`
3. **Logs por Fase**: `evidence/logs/[fase]_events.jsonl`

### Tipos de Evidencia
- **Datos de Red**: Información de hosts y servicios
- **Credenciales**: Usuarios y contraseñas encontradas
- **Scripts**: Scripts generados para exploits
- **Capturas**: Screenshots de interfaces
- **Archivos**: Datos exfiltrados y comprimidos

### Formato de Logs Estructurados
```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "event_id": 1,
  "event_type": "DISCOVERY",
  "phase": "RECONNAISSANCE",
  "severity": "INFO",
  "description": "Host descubierto: 192.168.1.100",
  "data": {
    "host": "192.168.1.100",
    "mac": "00:11:22:33:44:55",
    "vendor": "Intel Corporate"
  }
}
```

## Reportes

### Reporte Principal
Al finalizar la ejecución, se genera un reporte JSON con:
- Metadatos de la prueba
- Resumen de resultados por fase
- Estadísticas generales
- Tiempo de ejecución

### Reportes por Fase
Cada módulo genera su propio reporte detallado con:
- Resultados específicos de la fase
- Evidencia recopilada
- Métricas de éxito/fallo
- Recomendaciones

## Seguridad y Consideraciones Éticas

### Uso Ético
- Solo use este sistema en redes autorizadas
- Obtenga permiso por escrito antes de cualquier prueba
- Documente todos los hallazgos apropiadamente
- Siga las leyes locales e internacionales

### Consideraciones de Seguridad
- El sistema genera evidencia que debe protegerse
- Los logs contienen información sensible
- Limpie todos los artefactos después de las pruebas
- Use conexiones seguras para exfiltración

### Mejores Prácticas
- Realice pruebas en entornos aislados primero
- Mantenga backups de sistemas antes de las pruebas
- Documente todos los cambios realizados
- Reporte vulnerabilidades encontradas apropiadamente

## Solución de Problemas

### Problemas Comunes

#### Error: "Herramienta no encontrada"
```bash
# Verificar instalación de herramientas
which nmap masscan arp-scan responder hydra

# Instalar herramientas faltantes
sudo apt install <herramienta>
```

#### Error: "Permisos insuficientes"
```bash
# Ejecutar con permisos de administrador
sudo python3 pentest_automation.py

# O configurar sudo sin contraseña para herramientas específicas
```

#### Error: "Interfaz de red no encontrada"
```bash
# Listar interfaces disponibles
ip link show

# Actualizar configuración con interfaz correcta
```

#### Error: "Metasploit no funciona"
```bash
# Inicializar base de datos de Metasploit
sudo msfdb init

# Verificar estado
sudo msfconsole -q -x "db_status; exit"
```

### Logs de Depuración
```bash
# Ejecutar con nivel de debug
python3 pentest_automation.py --log-level DEBUG

# Revisar logs detallados
tail -f pentest_automation.log
```

## Contribuciones

### Cómo Contribuir
1. Fork del repositorio
2. Crear rama para nueva funcionalidad
3. Implementar cambios con tests
4. Documentar nuevas funcionalidades
5. Enviar pull request

### Estándares de Código
- Seguir PEP 8 para Python
- Documentar todas las funciones
- Incluir tests unitarios
- Mantener compatibilidad hacia atrás

## Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo LICENSE para más detalles.

## Contacto y Soporte

- **Issues**: Reportar problemas en GitHub Issues
- **Documentación**: Ver MANUAL.md para detalles técnicos
- **Seguridad**: Reportar vulnerabilidades de forma responsable

## Changelog

### Versión 1.1.0 (Actual)
- **🕵️ Modo Sigiloso**: Técnicas de persistencia disfrazadas y realistas
- **🔗 Conexiones Persistentes**: Acceso remoto continuo y automático
- **👤 Usuarios Sigilosos**: Nombres y contraseñas que pasan desapercibidos
- **🔧 Servicios Disfrazados**: Servicios maliciosos con nombres legítimos
- **📁 Rutas Sigilosas**: Archivos en ubicaciones del sistema operativo
- **🎯 Desafío Realista**: Mayor dificultad para equipos de seguridad

### Versión 1.0.0
- Implementación inicial del sistema
- Módulos básicos de todas las fases
- Sistema de logging avanzado
- Configuración flexible
- Documentación completa

## Agradecimientos

- Comunidad de seguridad de Kali Linux
- Desarrolladores de herramientas de pentesting
- Contribuidores del proyecto
- Comunidad de seguridad en general

---

**Recuerde: Use este sistema de manera responsable y ética. La seguridad es responsabilidad de todos.**
