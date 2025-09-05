"""
Sistema de Logging Avanzado para Automatización de Pentesting
"""

import logging
import json
import os
import time
from datetime import datetime
from pathlib import Path
import threading
from typing import Dict, Any, Optional

# Códigos de colores ANSI
class Colors:
    GREEN = '\033[92m'      # Éxito
    ORANGE = '\033[93m'     # No explotable/Advertencia
    RED = '\033[91m'        # Error/Problema
    BLUE = '\033[94m'       # Información
    PURPLE = '\033[95m'     # Progreso
    CYAN = '\033[96m'       # Datos importantes
    YELLOW = '\033[93m'     # Advertencia
    BOLD = '\033[1m'        # Negrita
    UNDERLINE = '\033[4m'   # Subrayado
    END = '\033[0m'         # Reset

class LoggingSystem:
    """Sistema de logging avanzado con múltiples niveles y formatos"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.log_config = config.get('logging', {})
        self.evidence_dir = Path("evidence")
        self.screenshots_dir = self.evidence_dir / "screenshots"
        self.logs_dir = self.evidence_dir / "logs"
        self.data_dir = self.evidence_dir / "data"
        
        # Crear directorios de evidencia
        self._create_directories()
        
        # Configurar logging estructurado
        self.structured_logger = self._setup_structured_logging()
        
        # Contador de eventos
        self.event_counter = 0
        self.lock = threading.Lock()
        
        # Configurar logging en tiempo real
        self.realtime_log_file = self.logs_dir / "realtime_progress.log"
        self.realtime_handler = None
        self._setup_realtime_logging()
    
    def _create_directories(self):
        """Crear directorios necesarios para evidencia"""
        directories = [self.evidence_dir, self.screenshots_dir, self.logs_dir, self.data_dir]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Directorio creado/verificado: {directory}")
    
    def _setup_structured_logging(self):
        """Configurar logging estructurado para análisis posterior"""
        structured_logger = logging.getLogger('StructuredLogging')
        structured_logger.setLevel(logging.INFO)
        
        # Handler para logs estructurados
        structured_handler = logging.FileHandler(
            self.logs_dir / "structured_events.jsonl",
            mode='a',
            encoding='utf-8'
        )
        
        # Formatter personalizado para JSON
        json_formatter = logging.Formatter('%(message)s')
        structured_handler.setFormatter(json_formatter)
        structured_logger.addHandler(structured_handler)
        
        return structured_logger
    
    def _setup_realtime_logging(self):
        """Configurar logging en tiempo real para evitar pérdida de progreso"""
        try:
            self.realtime_handler = logging.FileHandler(
                self.realtime_log_file,
                mode='a',
                encoding='utf-8'
            )
            self.realtime_handler.setLevel(logging.INFO)
            
            # Formatter para tiempo real
            realtime_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            self.realtime_handler.setFormatter(realtime_formatter)
            
        except Exception as e:
            print(f"Error configurando logging en tiempo real: {e}")
    
    def log_success(self, message: str, phase: str = "UNKNOWN"):
        """Log de éxito en verde"""
        colored_message = f"{Colors.GREEN}✅ {message}{Colors.END}"
        self.logger.info(colored_message)
        self._log_realtime(f"SUCCESS: {message}", phase)
        self.log_event("SUCCESS", message, severity="SUCCESS", phase=phase)
    
    def log_warning(self, message: str, phase: str = "UNKNOWN"):
        """Log de advertencia en naranja"""
        colored_message = f"{Colors.ORANGE}⚠️ {message}{Colors.END}"
        self.logger.warning(colored_message)
        self._log_realtime(f"WARNING: {message}", phase)
        self.log_event("WARNING", message, severity="WARNING", phase=phase)
    
    def log_error(self, message: str, phase: str = "UNKNOWN"):
        """Log de error en rojo"""
        colored_message = f"{Colors.RED}❌ {message}{Colors.END}"
        self.logger.error(colored_message)
        self._log_realtime(f"ERROR: {message}", phase)
        self.log_event("ERROR", message, severity="ERROR", phase=phase)
    
    def log_info(self, message: str, phase: str = "UNKNOWN"):
        """Log de información en azul"""
        colored_message = f"{Colors.BLUE}ℹ️ {message}{Colors.END}"
        self.logger.info(colored_message)
        self._log_realtime(f"INFO: {message}", phase)
        self.log_event("INFO", message, severity="INFO", phase=phase)
    
    def log_progress(self, message: str, phase: str = "UNKNOWN"):
        """Log de progreso en púrpura"""
        colored_message = f"{Colors.PURPLE}🔄 {message}{Colors.END}"
        self.logger.info(colored_message)
        self._log_realtime(f"PROGRESS: {message}", phase)
        self.log_event("PROGRESS", message, severity="INFO", phase=phase)
    
    def log_important(self, message: str, phase: str = "UNKNOWN"):
        """Log de datos importantes en cyan"""
        colored_message = f"{Colors.CYAN}📊 {message}{Colors.END}"
        self.logger.info(colored_message)
        self._log_realtime(f"IMPORTANT: {message}", phase)
        self.log_event("IMPORTANT", message, severity="INFO", phase=phase)
    
    def _log_realtime(self, message: str, phase: str):
        """Log en tiempo real para evitar pérdida de progreso"""
        if self.realtime_handler:
            try:
                realtime_logger = logging.getLogger('RealtimeLogger')
                realtime_logger.setLevel(logging.INFO)
                realtime_logger.addHandler(self.realtime_handler)
                realtime_logger.info(f"[{phase}] {message}")
                realtime_logger.removeHandler(self.realtime_handler)
            except Exception as e:
                # Fallback a print si hay problemas con logging
                print(f"Realtime log error: {e}")
    
    def log_event(self, event_type: str, description: str, data: Optional[Dict] = None, 
                  severity: str = "INFO", phase: str = "UNKNOWN"):
        """Registrar evento estructurado"""
        with self.lock:
            self.event_counter += 1
            
            event = {
                "timestamp": datetime.now().isoformat(),
                "event_id": self.event_counter,
                "event_type": event_type,
                "phase": phase,
                "severity": severity,
                "description": description,
                "data": data or {}
            }
            
            # Log estructurado
            self.structured_logger.info(json.dumps(event, ensure_ascii=False))
            
            # Log normal
            log_message = f"[{phase}] {event_type}: {description}"
            if data:
                log_message += f" | Datos: {json.dumps(data, ensure_ascii=False)}"
            
            if severity == "ERROR":
                self.logger.error(log_message)
            elif severity == "WARNING":
                self.logger.warning(log_message)
            elif severity == "DEBUG":
                self.logger.debug(log_message)
            else:
                self.logger.info(log_message)
    
    def log_command(self, command: str, output: str, return_code: int, phase: str = "UNKNOWN"):
        """Registrar ejecución de comando"""
        self.log_event(
            event_type="COMMAND_EXECUTION",
            description=f"Comando ejecutado: {command}",
            data={
                "command": command,
                "output": output,
                "return_code": return_code,
                "output_length": len(output)
            },
            severity="INFO" if return_code == 0 else "WARNING",
            phase=phase
        )
    
    def log_discovery(self, discovery_type: str, target: str, details: Dict, phase: str = "RECONNAISSANCE"):
        """Registrar descubrimiento de información"""
        self.log_event(
            event_type="DISCOVERY",
            description=f"{discovery_type} descubierto: {target}",
            data={
                "discovery_type": discovery_type,
                "target": target,
                "details": details
            },
            phase=phase
        )
    
    def log_vulnerability(self, target: str, vulnerability: str, severity: str, 
                         details: Dict, phase: str = "VULNERABILITY_ASSESSMENT"):
        """Registrar vulnerabilidad encontrada"""
        self.log_event(
            event_type="VULNERABILITY",
            description=f"Vulnerabilidad {severity} en {target}: {vulnerability}",
            data={
                "target": target,
                "vulnerability": vulnerability,
                "severity": severity,
                "details": details
            },
            severity=severity.upper(),
            phase=phase
        )
    
    def log_credential(self, target: str, credential_type: str, username: str, 
                      success: bool, phase: str = "CREDENTIAL_HARVESTING"):
        """Registrar intento de credencial"""
        self.log_event(
            event_type="CREDENTIAL_ATTEMPT",
            description=f"Credencial {credential_type} para {username}@{target}: {'ÉXITO' if success else 'FALLO'}",
            data={
                "target": target,
                "credential_type": credential_type,
                "username": username,
                "success": success
            },
            severity="INFO" if success else "WARNING",
            phase=phase
        )
    
    def log_compromise(self, target: str, method: str, details: Dict, phase: str = "LATERAL_MOVEMENT"):
        """Registrar compromiso de sistema"""
        self.log_event(
            event_type="SYSTEM_COMPROMISE",
            description=f"Sistema comprometido: {target} via {method}",
            data={
                "target": target,
                "method": method,
                "details": details
            },
            severity="WARNING",
            phase=phase
        )
    
    def log_persistence(self, target: str, method: str, details: Dict, phase: str = "PERSISTENCE"):
        """Registrar establecimiento de persistencia"""
        self.log_event(
            event_type="PERSISTENCE_ESTABLISHED",
            description=f"Persistencia establecida en {target}: {method}",
            data={
                "target": target,
                "method": method,
                "details": details
            },
            phase=phase
        )
    
    def log_exfiltration(self, target: str, data_type: str, size: int, 
                        destination: str, phase: str = "EXFILTRATION"):
        """Registrar exfiltración de datos"""
        self.log_event(
            event_type="DATA_EXFILTRATION",
            description=f"Datos exfiltrados de {target}: {data_type} ({size} bytes) -> {destination}",
            data={
                "target": target,
                "data_type": data_type,
                "size": size,
                "destination": destination
            },
            phase=phase
        )
    
    def save_evidence(self, filename: str, content: str, evidence_type: str = "data"):
        """Guardar evidencia en archivo"""
        try:
            if evidence_type == "screenshot":
                file_path = self.screenshots_dir / filename
            elif evidence_type == "log":
                file_path = self.logs_dir / filename
            else:
                file_path = self.data_dir / filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.log_event(
                event_type="EVIDENCE_SAVED",
                description=f"Evidencia guardada: {filename}",
                data={
                    "filename": filename,
                    "evidence_type": evidence_type,
                    "file_path": str(file_path),
                    "size": len(content)
                }
            )
            
            return str(file_path)
        except Exception as e:
            self.logger.error(f"Error al guardar evidencia {filename}: {e}")
            return None
    
    def save_json_evidence(self, filename: str, data: Dict, evidence_type: str = "data"):
        """Guardar evidencia en formato JSON"""
        try:
            if evidence_type == "screenshot":
                file_path = self.screenshots_dir / filename
            elif evidence_type == "log":
                file_path = self.logs_dir / filename
            else:
                file_path = self.data_dir / filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.log_event(
                event_type="EVIDENCE_SAVED",
                description=f"Evidencia JSON guardada: {filename}",
                data={
                    "filename": filename,
                    "evidence_type": evidence_type,
                    "file_path": str(file_path),
                    "size": len(json.dumps(data))
                }
            )
            
            return str(file_path)
        except Exception as e:
            self.logger.error(f"Error al guardar evidencia JSON {filename}: {e}")
            return None
    
    def get_phase_summary(self, phase: str) -> Dict:
        """Obtener resumen de una fase específica"""
        # Leer logs estructurados y filtrar por fase
        log_file = self.logs_dir / "structured_events.jsonl"
        phase_events = []
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if event.get('phase') == phase:
                            phase_events.append(event)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            return {}
        
        # Generar resumen
        summary = {
            "total_events": len(phase_events),
            "event_types": {},
            "severity_counts": {"INFO": 0, "WARNING": 0, "ERROR": 0},
            "discoveries": [],
            "vulnerabilities": [],
            "compromises": []
        }
        
        for event in phase_events:
            # Contar tipos de eventos
            event_type = event.get('event_type', 'UNKNOWN')
            summary["event_types"][event_type] = summary["event_types"].get(event_type, 0) + 1
            
            # Contar severidades
            severity = event.get('severity', 'INFO')
            if severity in summary["severity_counts"]:
                summary["severity_counts"][severity] += 1
            
            # Recopilar descubrimientos importantes
            if event_type == "DISCOVERY":
                summary["discoveries"].append(event)
            elif event_type == "VULNERABILITY":
                summary["vulnerabilities"].append(event)
            elif event_type == "SYSTEM_COMPROMISE":
                summary["compromises"].append(event)
        
        return summary
    
    def generate_phase_report(self, phase: str) -> str:
        """Generar reporte detallado de una fase"""
        summary = self.get_phase_summary(phase)
        
        report = f"""
=== REPORTE DE FASE: {phase} ===
Timestamp: {datetime.now().isoformat()}

RESUMEN GENERAL:
- Total de eventos: {summary.get('total_events', 0)}
- Eventos por severidad: {summary.get('severity_counts', {})}

TIPOS DE EVENTOS:
"""
        
        for event_type, count in summary.get('event_types', {}).items():
            report += f"- {event_type}: {count}\n"
        
        # Agregar descubrimientos
        if summary.get('discoveries'):
            report += "\nDESCUBRIMIENTOS:\n"
            for discovery in summary['discoveries']:
                report += f"- {discovery.get('description', 'N/A')}\n"
        
        # Agregar vulnerabilidades
        if summary.get('vulnerabilities'):
            report += "\nVULNERABILIDADES:\n"
            for vuln in summary['vulnerabilities']:
                report += f"- {vuln.get('description', 'N/A')}\n"
        
        # Agregar compromisos
        if summary.get('compromises'):
            report += "\nSISTEMAS COMPROMETIDOS:\n"
            for compromise in summary['compromises']:
                report += f"- {compromise.get('description', 'N/A')}\n"
        
        return report
    
    def cleanup(self):
        """Limpiar recursos del sistema de logging"""
        self.log_event(
            event_type="SYSTEM_SHUTDOWN",
            description="Sistema de logging finalizando",
            phase="CLEANUP"
        )
        
        # Cerrar handlers
        for handler in self.structured_logger.handlers:
            handler.close()
            self.structured_logger.removeHandler(handler)
    
    def generate_phase_summary(self, phase: str, phase_data: Dict[str, Any]) -> str:
        """Generar resumen breve de fase con datos prioritarios"""
        summary_lines = []
        summary_lines.append(f"{Colors.BOLD}{Colors.CYAN}📋 RESUMEN DE FASE: {phase.upper()}{Colors.END}")
        summary_lines.append("=" * 50)
        
        if phase.upper() == "RECONNAISSANCE":
            # Datos prioritarios para reconocimiento
            hosts_found = phase_data.get('hosts_discovered', 0)
            services_found = phase_data.get('services_discovered', 0)
            public_ip = phase_data.get('public_ip', 'No detectada')
            network_range = phase_data.get('target_network', 'No configurada')
            
            summary_lines.append(f"🌐 Red objetivo: {network_range}")
            summary_lines.append(f"🌍 IP pública: {public_ip}")
            summary_lines.append(f"🖥️ Hosts descubiertos: {hosts_found}")
            summary_lines.append(f"🔌 Servicios encontrados: {services_found}")
            
        elif phase.upper() == "CREDENTIAL_HARVESTING":
            # Datos prioritarios para credenciales
            credentials_found = phase_data.get('credentials_found', 0)
            successful_attacks = phase_data.get('successful_attacks', 0)
            failed_attacks = phase_data.get('failed_attacks', 0)
            
            summary_lines.append(f"🔑 Credenciales encontradas: {credentials_found}")
            summary_lines.append(f"✅ Ataques exitosos: {successful_attacks}")
            summary_lines.append(f"❌ Ataques fallidos: {failed_attacks}")
            
        elif phase.upper() == "LATERAL_MOVEMENT":
            # Datos prioritarios para movimiento lateral
            compromised_systems = phase_data.get('compromised_systems', 0)
            lateral_access = phase_data.get('lateral_access_achieved', 0)
            exploits_used = phase_data.get('exploits_used', 0)
            
            summary_lines.append(f"🎯 Sistemas comprometidos: {compromised_systems}")
            summary_lines.append(f"🔄 Accesos laterales: {lateral_access}")
            summary_lines.append(f"💥 Exploits utilizados: {exploits_used}")
            
        elif phase.upper() == "PERSISTENCE":
            # Datos prioritarios para persistencia
            backdoors_installed = phase_data.get('backdoors_installed', 0)
            scheduled_tasks = phase_data.get('scheduled_tasks', 0)
            registry_modifications = phase_data.get('registry_modifications', 0)
            
            summary_lines.append(f"🚪 Backdoors instalados: {backdoors_installed}")
            summary_lines.append(f"⏰ Tareas programadas: {scheduled_tasks}")
            summary_lines.append(f"📝 Modificaciones de registro: {registry_modifications}")
            
        elif phase.upper() == "PRIVILEGE_ESCALATION":
            # Datos prioritarios para escalada de privilegios
            privilege_escalations = phase_data.get('privilege_escalations', 0)
            domain_admin_access = phase_data.get('domain_admin_access', 0)
            hashes_dumped = phase_data.get('hashes_dumped', 0)
            
            summary_lines.append(f"⬆️ Escaladas de privilegios: {privilege_escalations}")
            summary_lines.append(f"👑 Acceso Domain Admin: {domain_admin_access}")
            summary_lines.append(f"🔐 Hashes extraídos: {hashes_dumped}")
            
        elif phase.upper() == "EXFILTRATION":
            # Datos prioritarios para exfiltración
            data_size = phase_data.get('data_size', 0)
            files_exfiltrated = phase_data.get('files_exfiltrated', 0)
            exploits_managed = phase_data.get('exploits_managed', 0)
            
            summary_lines.append(f"📦 Datos exfiltrados: {data_size:,} bytes ({data_size / (1024*1024):.2f} MB)")
            summary_lines.append(f"📄 Archivos transferidos: {files_exfiltrated}")
            summary_lines.append(f"🔧 Exploits gestionados: {exploits_managed}")
        
        # Agregar tiempo de ejecución si está disponible
        execution_time = phase_data.get('execution_time', 0)
        if execution_time > 0:
            summary_lines.append(f"⏱️ Tiempo de ejecución: {execution_time:.2f} segundos")
        
        summary_lines.append("=" * 50)
        return "\n".join(summary_lines)
