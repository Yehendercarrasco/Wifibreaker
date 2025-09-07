"""
Módulo de Consola Limpia
Mantiene la consola limpia con mensajes cortos pero guarda detalles técnicos en logs
"""

import subprocess
import time
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
from modules.logging_system import LoggingSystem, Colors

class CleanConsole:
    """Sistema de consola limpia con logging detallado"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        
        # Buffer para detalles técnicos
        self.technical_details = []
        self.current_operation = None
        
    def start_operation(self, operation_name: str, description: str = ""):
        """Iniciar una operación con mensaje limpio"""
        self.current_operation = {
            'name': operation_name,
            'description': description,
            'start_time': time.time(),
            'details': [],
            'status': 'running'
        }
        
        # Mensaje limpio en consola
        if description:
            print(f"{Colors.BLUE}🔄 {operation_name}: {description}{Colors.END}")
        else:
            print(f"{Colors.BLUE}🔄 {operation_name}...{Colors.END}")
    
    def log_technical_detail(self, detail: str, level: str = "info"):
        """Registrar detalle técnico (solo en log, no en consola)"""
        if self.current_operation:
            self.current_operation['details'].append({
                'timestamp': time.time(),
                'level': level,
                'detail': detail
            })
        
        # Log detallado
        if level == "error":
            self.logger.error(detail)
        elif level == "warning":
            self.logger.warning(detail)
        else:
            self.logger.info(detail)
    
    def complete_operation(self, success: bool, result_message: str = "", error_message: str = ""):
        """Completar operación con resultado limpio"""
        if not self.current_operation:
            return
        
        self.current_operation['status'] = 'completed' if success else 'failed'
        self.current_operation['end_time'] = time.time()
        self.current_operation['duration'] = self.current_operation['end_time'] - self.current_operation['start_time']
        
        # Mensaje limpio en consola
        if success:
            if result_message:
                print(f"{Colors.GREEN}✅ {self.current_operation['name']}: {result_message}{Colors.END}")
            else:
                print(f"{Colors.GREEN}✅ {self.current_operation['name']}: Completado{Colors.END}")
        else:
            if error_message:
                print(f"{Colors.RED}❌ {self.current_operation['name']}: {error_message}{Colors.END}")
            else:
                print(f"{Colors.RED}❌ {self.current_operation['name']}: Falló{Colors.END}")
        
        # Guardar detalles técnicos
        self.technical_details.append(self.current_operation.copy())
        
        # Log detallado
        if success:
            self.logger.info(f"Operación completada: {self.current_operation['name']}")
        else:
            self.logger.error(f"Operación falló: {self.current_operation['name']}")
        
        self.current_operation = None
    
    def run_command_clean(self, command: List[str], operation_name: str, 
                         success_message: str = "", error_message: str = "",
                         timeout: int = 300) -> Dict[str, Any]:
        """Ejecutar comando con salida limpia"""
        self.start_operation(operation_name)
        
        try:
            # Ejecutar comando
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Log detallado
            self.log_technical_detail(f"Comando ejecutado: {' '.join(command)}")
            self.log_technical_detail(f"Código de salida: {result.returncode}")
            self.log_technical_detail(f"STDOUT: {result.stdout}")
            if result.stderr:
                self.log_technical_detail(f"STDERR: {result.stderr}", "warning")
            
            # Determinar éxito
            success = result.returncode == 0
            
            # Mensaje de resultado
            if success:
                final_message = success_message or "Completado exitosamente"
            else:
                final_message = error_message or f"Falló con código {result.returncode}"
            
            self.complete_operation(success, final_message)
            
            return {
                'success': success,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(command)
            }
            
        except subprocess.TimeoutExpired:
            self.log_technical_detail(f"Comando expiró después de {timeout} segundos", "error")
            self.complete_operation(False, error_message or "Tiempo de espera agotado")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Timeout',
                'command': ' '.join(command)
            }
        except Exception as e:
            self.log_technical_detail(f"Error ejecutando comando: {str(e)}", "error")
            self.complete_operation(False, error_message or f"Error: {str(e)}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'command': ' '.join(command)
            }
    
    def run_metasploit_clean(self, resource_script: str, operation_name: str,
                           success_message: str = "", error_message: str = "") -> Dict[str, Any]:
        """Ejecutar Metasploit con salida limpia"""
        self.start_operation(operation_name)
        
        try:
            # Ejecutar msfconsole
            command = ['msfconsole', '-q', '-r', resource_script]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutos para Metasploit
            )
            
            # Log detallado
            self.log_technical_detail(f"Metasploit ejecutado: {resource_script}")
            self.log_technical_detail(f"Código de salida: {result.returncode}")
            self.log_technical_detail(f"Salida completa: {result.stdout}")
            if result.stderr:
                self.log_technical_detail(f"Errores: {result.stderr}", "warning")
            
            # Analizar salida para determinar éxito
            success = self._analyze_metasploit_output(result.stdout, result.stderr)
            
            # Mensaje de resultado
            if success:
                final_message = success_message or "Exploit ejecutado exitosamente"
            else:
                final_message = error_message or "Exploit falló"
            
            self.complete_operation(success, final_message)
            
            return {
                'success': success,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'resource_script': resource_script
            }
            
        except subprocess.TimeoutExpired:
            self.log_technical_detail("Metasploit expiró después de 10 minutos", "error")
            self.complete_operation(False, error_message or "Tiempo de espera agotado")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': 'Timeout',
                'resource_script': resource_script
            }
        except Exception as e:
            self.log_technical_detail(f"Error ejecutando Metasploit: {str(e)}", "error")
            self.complete_operation(False, error_message or f"Error: {str(e)}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'resource_script': resource_script
            }
    
    def run_nmap_clean(self, target: str, operation_name: str, 
                      success_message: str = "", error_message: str = "") -> Dict[str, Any]:
        """Ejecutar nmap con salida limpia"""
        self.start_operation(operation_name)
        
        try:
            # Comando nmap básico
            command = ['nmap', '-sS', '-O', '-sV', target]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Log detallado
            self.log_technical_detail(f"Nmap ejecutado en: {target}")
            self.log_technical_detail(f"Código de salida: {result.returncode}")
            self.log_technical_detail(f"Salida completa: {result.stdout}")
            if result.stderr:
                self.log_technical_detail(f"Errores: {result.stderr}", "warning")
            
            # Analizar salida
            success = result.returncode == 0
            hosts_found = self._count_nmap_hosts(result.stdout)
            
            # Mensaje de resultado
            if success:
                final_message = success_message or f"Escaneo completado, {hosts_found} hosts encontrados"
            else:
                final_message = error_message or "Escaneo falló"
            
            self.complete_operation(success, final_message)
            
            return {
                'success': success,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'target': target,
                'hosts_found': hosts_found
            }
            
        except Exception as e:
            self.log_technical_detail(f"Error ejecutando nmap: {str(e)}", "error")
            self.complete_operation(False, error_message or f"Error: {str(e)}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'target': target
            }
    
    def run_hydra_clean(self, target: str, service: str, operation_name: str,
                       success_message: str = "", error_message: str = "") -> Dict[str, Any]:
        """Ejecutar Hydra con salida limpia"""
        self.start_operation(operation_name)
        
        try:
            # Comando Hydra básico
            command = ['hydra', '-L', 'users.txt', '-P', 'passwords.txt', f'{service}://{target}']
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Log detallado
            self.log_technical_detail(f"Hydra ejecutado en: {target} para servicio {service}")
            self.log_technical_detail(f"Código de salida: {result.returncode}")
            self.log_technical_detail(f"Salida completa: {result.stdout}")
            if result.stderr:
                self.log_technical_detail(f"Errores: {result.stderr}", "warning")
            
            # Analizar salida
            success = result.returncode == 0
            credentials_found = self._count_hydra_credentials(result.stdout)
            
            # Mensaje de resultado
            if success:
                final_message = success_message or f"Fuerza bruta completada, {credentials_found} credenciales encontradas"
            else:
                final_message = error_message or "Fuerza bruta falló"
            
            self.complete_operation(success, final_message)
            
            return {
                'success': success,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'target': target,
                'service': service,
                'credentials_found': credentials_found
            }
            
        except Exception as e:
            self.log_technical_detail(f"Error ejecutando Hydra: {str(e)}", "error")
            self.complete_operation(False, error_message or f"Error: {str(e)}")
            return {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'target': target,
                'service': service
            }
    
    def _analyze_metasploit_output(self, stdout: str, stderr: str) -> bool:
        """Analizar salida de Metasploit para determinar éxito"""
        # Buscar indicadores de éxito
        success_indicators = [
            'session opened',
            'meterpreter session',
            'command shell session',
            'exploit completed successfully',
            'payload delivered'
        ]
        
        # Buscar indicadores de fallo
        failure_indicators = [
            'exploit failed',
            'connection refused',
            'timeout',
            'incompatible payload',
            'exploit aborted'
        ]
        
        output_lower = stdout.lower() + stderr.lower()
        
        # Verificar fallos primero
        for indicator in failure_indicators:
            if indicator in output_lower:
                return False
        
        # Verificar éxitos
        for indicator in success_indicators:
            if indicator in output_lower:
                return True
        
        # Si no hay indicadores claros, asumir fallo
        return False
    
    def _count_nmap_hosts(self, output: str) -> int:
        """Contar hosts encontrados en salida de nmap"""
        lines = output.split('\n')
        hosts = 0
        for line in lines:
            if 'Nmap scan report for' in line:
                hosts += 1
        return hosts
    
    def _count_hydra_credentials(self, output: str) -> int:
        """Contar credenciales encontradas en salida de Hydra"""
        lines = output.split('\n')
        credentials = 0
        for line in lines:
            if 'login:' in line and 'password:' in line:
                credentials += 1
        return credentials
    
    def get_technical_summary(self) -> Dict[str, Any]:
        """Obtener resumen de detalles técnicos"""
        return {
            'total_operations': len(self.technical_details),
            'successful_operations': len([op for op in self.technical_details if op['status'] == 'completed']),
            'failed_operations': len([op for op in self.technical_details if op['status'] == 'failed']),
            'operations': self.technical_details
        }
    
    def save_technical_details(self, file_path: str):
        """Guardar detalles técnicos en archivo"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.get_technical_summary(), f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Error guardando detalles técnicos: {e}")
    
    def clear_technical_details(self):
        """Limpiar buffer de detalles técnicos"""
        self.technical_details = []
        self.current_operation = None
