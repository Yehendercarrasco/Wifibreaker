"""
Módulo de Gestión de Escaneos
Organiza datos por escaneo en carpetas individuales
"""

import os
import json
import time
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from modules.logging_system import LoggingSystem, Colors

class ScanManager:
    """Gestor de escaneos con organización por carpetas"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        
        # Directorio base de escaneos
        self.scans_base_dir = Path("scans")
        self.scans_base_dir.mkdir(exist_ok=True)
        
        # Escaneo actual
        self.current_scan = None
        self.current_scan_dir = None
        
        # Estructura de carpetas por escaneo
        self.scan_folders = {
            'logs': 'logs',
            'evidence': 'evidence',
            'exfiltration': 'exfiltration',
            'console': 'console',
            'reports': 'reports',
            'backdoors': 'backdoors',
            'config': 'config'
        }
    
    def create_new_scan(self, mote: str, description: str = "") -> str:
        """Crear nuevo escaneo con mote"""
        # Generar ID único para el escaneo
        scan_id = self._generate_scan_id(mote)
        
        # Crear directorio del escaneo
        scan_dir = self.scans_base_dir / scan_id
        scan_dir.mkdir(exist_ok=True)
        
        # Crear subdirectorios
        for folder_name, folder_path in self.scan_folders.items():
            (scan_dir / folder_path).mkdir(exist_ok=True)
        
        # Crear archivo de información del escaneo
        scan_info = {
            'scan_id': scan_id,
            'mote': mote,
            'description': description,
            'created_at': datetime.now().isoformat(),
            'status': 'active',
            'folders': self.scan_folders,
            'results': {}
        }
        
        info_file = scan_dir / 'scan_info.json'
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(scan_info, f, indent=2, ensure_ascii=False)
        
        # Configurar escaneo actual
        self.current_scan = scan_info
        self.current_scan_dir = scan_dir
        
        self.logger.info(f"✅ Nuevo escaneo creado: {mote} (ID: {scan_id})")
        self.logger.info(f"📁 Directorio: {scan_dir}")
        
        return scan_id
    
    def load_scan(self, scan_id: str) -> bool:
        """Cargar escaneo existente"""
        scan_dir = self.scans_base_dir / scan_id
        
        if not scan_dir.exists():
            self.logger.error(f"❌ Escaneo {scan_id} no encontrado")
            return False
        
        info_file = scan_dir / 'scan_info.json'
        if not info_file.exists():
            self.logger.error(f"❌ Información del escaneo {scan_id} no encontrada")
            return False
        
        try:
            with open(info_file, 'r', encoding='utf-8') as f:
                self.current_scan = json.load(f)
            
            self.current_scan_dir = scan_dir
            
            self.logger.info(f"✅ Escaneo cargado: {self.current_scan['mote']} (ID: {scan_id})")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error cargando escaneo {scan_id}: {e}")
            return False
    
    def get_scan_path(self, folder: str) -> Path:
        """Obtener ruta de carpeta específica del escaneo actual"""
        if not self.current_scan_dir:
            raise ValueError("No hay escaneo activo")
        
        return self.current_scan_dir / self.scan_folders.get(folder, folder)
    
    def save_evidence(self, phase: str, data: Dict[str, Any]) -> str:
        """Guardar evidencia de fase específica"""
        if not self.current_scan_dir:
            raise ValueError("No hay escaneo activo")
        
        evidence_dir = self.get_scan_path('evidence')
        phase_dir = evidence_dir / phase
        phase_dir.mkdir(exist_ok=True)
        
        # Guardar evidencia
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_file = phase_dir / f"{phase}_evidence_{timestamp}.json"
        
        with open(evidence_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        # Actualizar información del escaneo
        if 'results' not in self.current_scan:
            self.current_scan['results'] = {}
        
        self.current_scan['results'][phase] = {
            'evidence_file': str(evidence_file),
            'timestamp': timestamp,
            'status': 'completed'
        }
        
        self._update_scan_info()
        
        self.logger.info(f"✅ Evidencia guardada: {evidence_file}")
        return str(evidence_file)
    
    def save_log(self, phase: str, log_data: str) -> str:
        """Guardar log de fase específica"""
        if not self.current_scan_dir:
            raise ValueError("No hay escaneo activo")
        
        logs_dir = self.get_scan_path('logs')
        phase_dir = logs_dir / phase
        phase_dir.mkdir(exist_ok=True)
        
        # Guardar log
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = phase_dir / f"{phase}_log_{timestamp}.log"
        
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(log_data)
        
        self.logger.info(f"✅ Log guardado: {log_file}")
        return str(log_file)
    
    def save_console_output(self, output: str) -> str:
        """Guardar salida de consola"""
        if not self.current_scan_dir:
            raise ValueError("No hay escaneo activo")
        
        console_dir = self.get_scan_path('console')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        console_file = console_dir / f"console_output_{timestamp}.txt"
        
        with open(console_file, 'w', encoding='utf-8') as f:
            f.write(output)
        
        self.logger.info(f"✅ Salida de consola guardada: {console_file}")
        return str(console_file)
    
    def save_exfiltration_data(self, data: Dict[str, Any]) -> str:
        """Guardar datos exfiltrados"""
        if not self.current_scan_dir:
            raise ValueError("No hay escaneo activo")
        
        exfiltration_dir = self.get_scan_path('exfiltration')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exfiltration_file = exfiltration_dir / f"exfiltration_data_{timestamp}.json"
        
        with open(exfiltration_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f"✅ Datos exfiltrados guardados: {exfiltration_file}")
        return str(exfiltration_file)
    
    def save_backdoor_info(self, backdoor_data: Dict[str, Any]) -> str:
        """Guardar información de backdoors"""
        if not self.current_scan_dir:
            raise ValueError("No hay escaneo activo")
        
        backdoors_dir = self.get_scan_path('backdoors')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backdoor_file = backdoors_dir / f"backdoors_{timestamp}.json"
        
        with open(backdoor_file, 'w', encoding='utf-8') as f:
            json.dump(backdoor_data, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f"✅ Información de backdoors guardada: {backdoor_file}")
        return str(backdoor_file)
    
    def save_report(self, report_data: Dict[str, Any]) -> str:
        """Guardar reporte del escaneo"""
        if not self.current_scan_dir:
            raise ValueError("No hay escaneo activo")
        
        reports_dir = self.get_scan_path('reports')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = reports_dir / f"scan_report_{timestamp}.json"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        # Actualizar información del escaneo
        self.current_scan['report_file'] = str(report_file)
        self._update_scan_info()
        
        self.logger.info(f"✅ Reporte guardado: {report_file}")
        return str(report_file)
    
    def list_scans(self) -> List[Dict[str, Any]]:
        """Listar todos los escaneos disponibles"""
        scans = []
        
        for scan_dir in self.scans_base_dir.iterdir():
            if scan_dir.is_dir():
                info_file = scan_dir / 'scan_info.json'
                if info_file.exists():
                    try:
                        with open(info_file, 'r', encoding='utf-8') as f:
                            scan_info = json.load(f)
                        scans.append(scan_info)
                    except:
                        continue
        
        # Ordenar por fecha de creación
        scans.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return scans
    
    def get_scan_data(self, phase: str) -> Optional[Dict[str, Any]]:
        """Obtener datos de fase específica del escaneo actual"""
        if not self.current_scan_dir:
            return None
        
        evidence_dir = self.get_scan_path('evidence')
        phase_dir = evidence_dir / phase
        
        if not phase_dir.exists():
            return None
        
        # Buscar el archivo de evidencia más reciente
        evidence_files = list(phase_dir.glob("*.json"))
        if not evidence_files:
            return None
        
        latest_file = max(evidence_files, key=os.path.getctime)
        
        try:
            with open(latest_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return None
    
    def get_all_scan_data(self) -> Dict[str, Any]:
        """Obtener todos los datos del escaneo actual"""
        if not self.current_scan_dir:
            return {}
        
        all_data = {}
        evidence_dir = self.get_scan_path('evidence')
        
        for phase_dir in evidence_dir.iterdir():
            if phase_dir.is_dir():
                phase_name = phase_dir.name
                phase_data = self.get_scan_data(phase_name)
                if phase_data:
                    all_data[phase_name] = phase_data
        
        return all_data
    
    def copy_file_to_scan(self, source_file: str, destination_folder: str, new_name: str = None) -> str:
        """Copiar archivo al escaneo actual"""
        if not self.current_scan_dir:
            raise ValueError("No hay escaneo activo")
        
        source_path = Path(source_file)
        if not source_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {source_file}")
        
        dest_dir = self.get_scan_path(destination_folder)
        dest_dir.mkdir(exist_ok=True)
        
        if new_name:
            dest_file = dest_dir / new_name
        else:
            dest_file = dest_dir / source_path.name
        
        shutil.copy2(source_path, dest_file)
        
        self.logger.info(f"✅ Archivo copiado: {source_file} -> {dest_file}")
        return str(dest_file)
    
    def finalize_scan(self, status: str = "completed") -> None:
        """Finalizar escaneo"""
        if not self.current_scan:
            return
        
        self.current_scan['status'] = status
        self.current_scan['completed_at'] = datetime.now().isoformat()
        
        self._update_scan_info()
        
        self.logger.info(f"✅ Escaneo finalizado: {self.current_scan['mote']} - Estado: {status}")
        
        # Limpiar escaneo actual
        self.current_scan = None
        self.current_scan_dir = None
    
    def _generate_scan_id(self, mote: str) -> str:
        """Generar ID único para el escaneo"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_mote = "".join(c for c in mote if c.isalnum() or c in ('-', '_')).rstrip()
        return f"{safe_mote}_{timestamp}"
    
    def _update_scan_info(self) -> None:
        """Actualizar archivo de información del escaneo"""
        if not self.current_scan or not self.current_scan_dir:
            return
        
        info_file = self.current_scan_dir / 'scan_info.json'
        with open(info_file, 'w', encoding='utf-8') as f:
            json.dump(self.current_scan, f, indent=2, ensure_ascii=False, default=str)
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Obtener resumen del escaneo actual"""
        if not self.current_scan:
            return {}
        
        summary = {
            'scan_id': self.current_scan.get('scan_id'),
            'mote': self.current_scan.get('mote'),
            'description': self.current_scan.get('description'),
            'status': self.current_scan.get('status'),
            'created_at': self.current_scan.get('created_at'),
            'completed_at': self.current_scan.get('completed_at'),
            'phases_completed': list(self.current_scan.get('results', {}).keys()),
            'total_phases': len(self.current_scan.get('results', {})),
            'scan_directory': str(self.current_scan_dir) if self.current_scan_dir else None
        }
        
        return summary
