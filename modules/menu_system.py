"""
Sistema de Menús Interactivos para Automatización de Pentesting
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from modules.logging_system import LoggingSystem, Colors

class MenuSystem:
    """Sistema de menús interactivos para el pentesting"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        
        # Directorio de logs
        self.logs_dir = Path("evidence/logs")
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Archivo de metadatos de logs
        self.log_metadata_file = self.logs_dir / "log_metadata.json"
        self.log_metadata = self._load_log_metadata()
    
    def _load_log_metadata(self) -> Dict[str, Any]:
        """Cargar metadatos de logs existentes"""
        if self.log_metadata_file.exists():
            try:
                with open(self.log_metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error cargando metadatos de logs: {e}")
        return {"logs": {}, "next_id": 1}
    
    def _save_log_metadata(self):
        """Guardar metadatos de logs"""
        try:
            with open(self.log_metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.log_metadata, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Error guardando metadatos de logs: {e}")
    
    def clear_screen(self):
        """Limpiar pantalla"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_header(self, title: str):
        """Imprimir encabezado del menú"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{title.center(60)}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}\n")
    
    def print_menu_option(self, number: int, description: str, emoji: str = "🔹"):
        """Imprimir opción de menú"""
        print(f"{Colors.BLUE}{emoji} {number}.{Colors.END} {description}")
    
    def get_user_choice(self, max_options: int, prompt: str = "Seleccione una opción") -> int:
        """Obtener selección del usuario"""
        while True:
            try:
                choice = input(f"\n{Colors.YELLOW}{prompt} (1-{max_options}): {Colors.END}")
                choice_num = int(choice)
                if 1 <= choice_num <= max_options:
                    return choice_num
                else:
                    print(f"{Colors.RED}❌ Opción inválida. Seleccione entre 1 y {max_options}{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}❌ Por favor ingrese un número válido{Colors.END}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}⚠️ Operación cancelada por el usuario{Colors.END}")
                return 0
    
    def main_menu(self) -> str:
        """Menú principal del sistema"""
        self.clear_screen()
        self.print_header("🔐 SISTEMA DE AUTOMATIZACIÓN DE PENTESTING")
        
        print(f"{Colors.GREEN}¡Bienvenido al sistema de automatización de pruebas de penetración!{Colors.END}\n")
        
        self.print_menu_option(1, "🔧 Configuración automática de red", "⚙️")
        self.print_menu_option(2, "🚀 Escaneo completo (todas las fases)", "🎯")
        self.print_menu_option(3, "🧊 Pentest frío (ejecuta y limpia)", "🧊")
        self.print_menu_option(4, "🧪 Modo de prueba (dry-run)", "🔍")
        self.print_menu_option(5, "📋 Escaneo por módulos específicos", "🔧")
        self.print_menu_option(6, "📂 Continuar escaneo desde log existente", "📁")
        self.print_menu_option(7, "📊 Ver logs y reportes existentes", "📈")
        self.print_menu_option(8, "🔍 Reconocimiento avanzado", "🔍")
        self.print_menu_option(9, "📁 Gestión de escaneos", "📁")
        self.print_menu_option(10, "🔐 Gestión de backdoors y accesos remotos", "🔐")
        self.print_menu_option(11, "❌ Salir del sistema", "🚪")
        
        choice = self.get_user_choice(11, "Seleccione una opción del menú principal")
        
        if choice == 0:  # Cancelado
            return "exit"
        
        menu_options = {
            1: "autoconfig",
            2: "full_scan",
            3: "cold_pentest",
            4: "dry_run",
            5: "module_scan",
            6: "continue_scan",
            7: "view_logs",
            8: "advanced_reconnaissance",
            9: "scan_management",
            10: "backdoor_management",
            11: "exit"
        }
        
        return menu_options.get(choice, "exit")
    
    def module_selection_menu(self) -> List[str]:
        """Menú de selección de módulos específicos"""
        self.clear_screen()
        self.print_header("📋 SELECCIÓN DE MÓDULOS")
        
        print(f"{Colors.BLUE}Seleccione los módulos que desea ejecutar:{Colors.END}\n")
        
        modules = [
            ("recon", "🔍 Reconocimiento de red", "Escaneo de hosts y servicios"),
            ("advanced_recon", "🔍 Reconocimiento Avanzado", "Detección de arquitectura, SO y topología"),
            ("creds", "🔑 Recolección de credenciales", "Ataques de fuerza bruta y spoofing"),
            ("lateral", "🔄 Movimiento lateral", "Explotación y acceso lateral"),
            ("persist", "🚪 Persistencia", "Instalación de backdoors"),
            ("priv", "⬆️ Escalada de privilegios", "Acceso de administrador"),
            ("exfil", "📤 Exfiltración de datos", "Transferencia y gestión de datos")
        ]
        
        selected_modules = []
        
        for i, (module_id, name, description) in enumerate(modules, 1):
            print(f"{Colors.CYAN}{i}. {name}{Colors.END}")
            print(f"   {Colors.WHITE}{description}{Colors.END}")
        
        print(f"\n{Colors.YELLOW}Instrucciones:{Colors.END}")
        print(f"• Ingrese los números de los módulos separados por comas (ej: 1,3,5)")
        print(f"• Presione Enter para seleccionar todos")
        print(f"• Escriba 'back' para volver al menú principal")
        
        while True:
            try:
                choice = input(f"\n{Colors.YELLOW}Seleccione módulos: {Colors.END}")
                
                if choice.lower() == 'back':
                    return []
                
                if choice.strip() == "":
                    # Seleccionar todos
                    return [module[0] for module in modules]
                
                # Parsear selección
                selected_numbers = [int(x.strip()) for x in choice.split(',')]
                selected_modules = []
                
                for num in selected_numbers:
                    if 1 <= num <= len(modules):
                        selected_modules.append(modules[num-1][0])
                    else:
                        print(f"{Colors.RED}❌ Número inválido: {num}{Colors.END}")
                        break
                else:
                    # Si no hubo errores, retornar selección
                    return selected_modules
                    
            except ValueError:
                print(f"{Colors.RED}❌ Formato inválido. Use números separados por comas{Colors.END}")
            except KeyboardInterrupt:
                return []
    
    def log_selection_menu(self) -> Optional[str]:
        """Menú de selección de logs existentes"""
        self.clear_screen()
        self.print_header("📂 SELECCIÓN DE LOG EXISTENTE")
        
        # Obtener logs disponibles
        available_logs = self._get_available_logs()
        
        if not available_logs:
            print(f"{Colors.ORANGE}⚠️ No se encontraron logs existentes{Colors.END}")
            print(f"{Colors.BLUE}💡 Ejecute primero un escaneo para generar logs{Colors.END}")
            input(f"\n{Colors.YELLOW}Presione Enter para continuar...{Colors.END}")
            return None
        
        print(f"{Colors.BLUE}Logs disponibles para continuar:{Colors.END}\n")
        
        for i, log_info in enumerate(available_logs, 1):
            mote = log_info.get('mote', 'Sin mote')
            date = log_info.get('date', 'Fecha desconocida')
            status = log_info.get('status', 'Desconocido')
            phases = log_info.get('phases_completed', [])
            
            print(f"{Colors.CYAN}{i}. {mote}{Colors.END}")
            print(f"   {Colors.WHITE}📅 Fecha: {date}{Colors.END}")
            print(f"   {Colors.WHITE}📊 Estado: {status}{Colors.END}")
            print(f"   {Colors.WHITE}🔧 Fases completadas: {', '.join(phases) if phases else 'Ninguna'}{Colors.END}")
            print(f"   {Colors.WHITE}📁 Archivo: {log_info.get('filename', 'N/A')}{Colors.END}")
            print()
        
        print(f"{Colors.YELLOW}0. Volver al menú principal{Colors.END}")
        
        choice = self.get_user_choice(len(available_logs), "Seleccione un log para continuar")
        
        if choice == 0:
            return None
        
        selected_log = available_logs[choice - 1]
        return selected_log.get('filename')
    
    def _get_available_logs(self) -> List[Dict[str, Any]]:
        """Obtener lista de logs disponibles"""
        logs = []
        
        # Buscar logs en el directorio
        for log_file in self.logs_dir.glob("*.log"):
            if log_file.name == "log_metadata.json":
                continue
                
            # Obtener metadatos del log
            log_id = log_file.stem
            metadata = self.log_metadata.get("logs", {}).get(log_id, {})
            
            # Obtener información del archivo
            stat = log_file.stat()
            date = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            
            log_info = {
                'filename': str(log_file),
                'mote': metadata.get('mote', f'Log_{log_id}'),
                'date': date,
                'status': metadata.get('status', 'Incompleto'),
                'phases_completed': metadata.get('phases_completed', []),
                'size': stat.st_size
            }
            
            logs.append(log_info)
        
        # Ordenar por fecha (más reciente primero)
        logs.sort(key=lambda x: x['date'], reverse=True)
        return logs
    
    def get_log_mote(self, default_mote: str = None) -> str:
        """Obtener mote personalizado para el log"""
        self.clear_screen()
        self.print_header("🏷️ PERSONALIZAR LOG")
        
        if default_mote:
            print(f"{Colors.BLUE}Mote sugerido: {Colors.CYAN}{default_mote}{Colors.END}\n")
        
        print(f"{Colors.YELLOW}Ingrese un mote personalizado para este escaneo:{Colors.END}")
        print(f"• El mote es un identificador personalizado para el log")
        print(f"• Ayuda a identificar fácilmente el escaneo")
        print(f"• Ejemplos: 'Red_Principal', 'Prueba_Cliente_X', 'Auditoria_2024'")
        
        while True:
            try:
                mote = input(f"\n{Colors.YELLOW}Mote (o Enter para usar el sugerido): {Colors.END}")
                
                if mote.strip() == "":
                    return default_mote or f"Escaneo_{datetime.now().strftime('%Y%m%d_%H%M')}"
                
                # Validar mote
                if len(mote.strip()) < 3:
                    print(f"{Colors.RED}❌ El mote debe tener al menos 3 caracteres{Colors.END}")
                    continue
                
                if len(mote.strip()) > 50:
                    print(f"{Colors.RED}❌ El mote no puede exceder 50 caracteres{Colors.END}")
                    continue
                
                return mote.strip()
                
            except KeyboardInterrupt:
                return default_mote or f"Escaneo_{datetime.now().strftime('%Y%m%d_%H%M')}"
    
    def save_log_metadata(self, log_id: str, mote: str, status: str = "En progreso", phases_completed: List[str] = None):
        """Guardar metadatos del log"""
        if phases_completed is None:
            phases_completed = []
        
        self.log_metadata["logs"][log_id] = {
            "mote": mote,
            "status": status,
            "phases_completed": phases_completed,
            "created": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat()
        }
        
        self._save_log_metadata()
    
    def update_log_status(self, log_id: str, status: str, phases_completed: List[str] = None):
        """Actualizar estado del log"""
        if log_id in self.log_metadata.get("logs", {}):
            self.log_metadata["logs"][log_id]["status"] = status
            self.log_metadata["logs"][log_id]["last_updated"] = datetime.now().isoformat()
            
            if phases_completed is not None:
                self.log_metadata["logs"][log_id]["phases_completed"] = phases_completed
            
            self._save_log_metadata()
    
    def view_logs_menu(self):
        """Menú para ver logs y reportes existentes"""
        self.clear_screen()
        self.print_header("📊 LOGS Y REPORTES EXISTENTES")
        
        logs = self._get_available_logs()
        
        if not logs:
            print(f"{Colors.ORANGE}⚠️ No se encontraron logs existentes{Colors.END}")
            input(f"\n{Colors.YELLOW}Presione Enter para continuar...{Colors.END}")
            return
        
        print(f"{Colors.BLUE}Logs disponibles:{Colors.END}\n")
        
        for i, log_info in enumerate(logs, 1):
            mote = log_info.get('mote', 'Sin mote')
            date = log_info.get('date', 'Fecha desconocida')
            status = log_info.get('status', 'Desconocido')
            phases = log_info.get('phases_completed', [])
            size = log_info.get('size', 0)
            
            # Determinar color según estado
            status_color = Colors.GREEN if status == "Completado" else Colors.ORANGE if status == "En progreso" else Colors.RED
            
            print(f"{Colors.CYAN}{i}. {mote}{Colors.END}")
            print(f"   {Colors.WHITE}📅 Fecha: {date}{Colors.END}")
            print(f"   {Colors.WHITE}📊 Estado: {status_color}{status}{Colors.END}")
            print(f"   {Colors.WHITE}🔧 Fases: {', '.join(phases) if phases else 'Ninguna'}{Colors.END}")
            print(f"   {Colors.WHITE}📁 Tamaño: {size:,} bytes{Colors.END}")
            print()
        
        input(f"\n{Colors.YELLOW}Presione Enter para continuar...{Colors.END}")
    
    def confirm_exit(self) -> bool:
        """Confirmar salida del sistema"""
        print(f"\n{Colors.YELLOW}¿Está seguro que desea salir del sistema?{Colors.END}")
        print(f"{Colors.BLUE}1. Sí, salir{Colors.END}")
        print(f"{Colors.BLUE}2. No, continuar{Colors.END}")
        
        choice = self.get_user_choice(2, "Confirmar salida")
        return choice == 1
