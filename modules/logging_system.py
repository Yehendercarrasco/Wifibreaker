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
