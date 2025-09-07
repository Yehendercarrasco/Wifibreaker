#!/usr/bin/env python3
"""
Servidor HTTP simple para el frontend de reportes de pentesting
"""

import os
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import mimetypes

class PentestReportHandler(BaseHTTPRequestHandler):
    """Manejador HTTP para el frontend de reportes"""
    
    def __init__(self, *args, **kwargs):
        # Directorio base del proyecto
        self.base_dir = Path(__file__).parent.parent
        self.scans_dir = self.base_dir / "scans"
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Manejar peticiones GET"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        try:
            if path == '/':
                self.serve_file('index.html')
            elif path.startswith('/api/'):
                self.handle_api_request(path)
            elif path.startswith('/static/'):
                self.serve_static_file(path)
            else:
                self.send_error(404, "Archivo no encontrado")
        except Exception as e:
            print(f"Error manejando petición {path}: {e}")
            self.send_error(500, f"Error interno: {str(e)}")
    
    def handle_api_request(self, path):
        """Manejar peticiones de API"""
        if path == '/api/scans':
            self.get_scans_list()
        elif path.startswith('/api/scan/'):
            scan_id = path.split('/')[-1]
            self.get_scan_details(scan_id)
        else:
            self.send_error(404, "Endpoint de API no encontrado")
    
    def get_scans_list(self):
        """Obtener lista de escaneos disponibles"""
        try:
            scans = []
            
            if not self.scans_dir.exists():
                self.send_json_response([])
                return
            
            # Buscar directorios de escaneos
            for scan_dir in self.scans_dir.iterdir():
                if scan_dir.is_dir():
                    scan_info_file = scan_dir / "scan_info.json"
                    if scan_info_file.exists():
                        try:
                            with open(scan_info_file, 'r', encoding='utf-8') as f:
                                scan_info = json.load(f)
                                scans.append(scan_info)
                        except Exception as e:
                            print(f"Error leyendo {scan_info_file}: {e}")
                            continue
            
            # Ordenar por fecha de creación (más recientes primero)
            scans.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            
            self.send_json_response(scans)
            
        except Exception as e:
            print(f"Error obteniendo lista de escaneos: {e}")
            self.send_error(500, f"Error obteniendo escaneos: {str(e)}")
    
    def get_scan_details(self, scan_id):
        """Obtener detalles de un escaneo específico"""
        try:
            scan_dir = self.scans_dir / scan_id
            
            if not scan_dir.exists():
                self.send_error(404, "Escaneo no encontrado")
                return
            
            # Cargar información básica del escaneo
            scan_info_file = scan_dir / "scan_info.json"
            if not scan_info_file.exists():
                self.send_error(404, "Información del escaneo no encontrada")
                return
            
            with open(scan_info_file, 'r', encoding='utf-8') as f:
                scan_info = json.load(f)
            
            # Cargar reporte final si existe
            report_file = scan_dir / "reports" / "final_report.json"
            if report_file.exists():
                try:
                    with open(report_file, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                        scan_info['results'] = report_data
                except Exception as e:
                    print(f"Error leyendo reporte final: {e}")
            
            # Cargar evidencia de fases específicas
            evidence_dir = scan_dir / "evidence"
            if evidence_dir.exists():
                for phase_file in evidence_dir.glob("*.json"):
                    try:
                        phase_name = phase_file.stem
                        with open(phase_file, 'r', encoding='utf-8') as f:
                            phase_data = json.load(f)
                            if 'results' not in scan_info:
                                scan_info['results'] = {}
                            scan_info['results'][phase_name] = phase_data
                    except Exception as e:
                        print(f"Error leyendo evidencia {phase_file}: {e}")
            
            self.send_json_response(scan_info)
            
        except Exception as e:
            print(f"Error obteniendo detalles del escaneo {scan_id}: {e}")
            self.send_error(500, f"Error obteniendo detalles: {str(e)}")
    
    def serve_file(self, filename):
        """Servir archivo HTML"""
        file_path = Path(__file__).parent / filename
        
        if not file_path.exists():
            self.send_error(404, "Archivo no encontrado")
            return
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            print(f"Error sirviendo archivo {filename}: {e}")
            self.send_error(500, f"Error sirviendo archivo: {str(e)}")
    
    def serve_static_file(self, path):
        """Servir archivos estáticos (CSS, JS, imágenes)"""
        # Remover /static/ del path
        file_path = Path(__file__).parent / path[1:]  # Remover el / inicial
        
        if not file_path.exists():
            self.send_error(404, "Archivo estático no encontrado")
            return
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Determinar tipo MIME
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if not mime_type:
                mime_type = 'application/octet-stream'
            
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            print(f"Error sirviendo archivo estático {path}: {e}")
            self.send_error(500, f"Error sirviendo archivo estático: {str(e)}")
    
    def send_json_response(self, data):
        """Enviar respuesta JSON"""
        try:
            json_data = json.dumps(data, ensure_ascii=False, indent=2)
            json_bytes = json_data.encode('utf-8')
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(json_bytes)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json_bytes)
            
        except Exception as e:
            print(f"Error enviando respuesta JSON: {e}")
            self.send_error(500, f"Error enviando respuesta: {str(e)}")
    
    def log_message(self, format, *args):
        """Personalizar mensajes de log"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {format % args}")

def run_server(port=8080, host='localhost'):
    """Ejecutar el servidor HTTP"""
    server_address = (host, port)
    httpd = HTTPServer(server_address, PentestReportHandler)
    
    print(f"🌐 Servidor de reportes iniciado en http://{host}:{port}")
    print(f"📁 Directorio de escaneos: {Path(__file__).parent.parent / 'scans'}")
    print(f"🔍 Buscando escaneos en: {Path(__file__).parent.parent / 'scans'}")
    print(f"⏹️  Presiona Ctrl+C para detener el servidor")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n🛑 Servidor detenido")
        httpd.shutdown()

if __name__ == '__main__':
    import sys
    
    # Configuración por defecto
    port = 8080
    host = 'localhost'
    
    # Procesar argumentos de línea de comandos
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("Error: Puerto debe ser un número entero")
            sys.exit(1)
    
    if len(sys.argv) > 2:
        host = sys.argv[2]
    
    # Verificar que el directorio de escaneos existe
    scans_dir = Path(__file__).parent.parent / "scans"
    if not scans_dir.exists():
        print(f"⚠️  Advertencia: Directorio de escaneos no encontrado: {scans_dir}")
        print(f"   El servidor funcionará pero no mostrará escaneos hasta que se ejecuten")
    
    run_server(port, host)
