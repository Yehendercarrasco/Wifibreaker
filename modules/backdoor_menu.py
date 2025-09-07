"""
Menú específico para gestión de backdoors y accesos remotos
"""

import os
import json
import time
from typing import Dict, List, Any, Optional
from modules.logging_system import Colors

class BackdoorMenu:
    """Menú específico para gestión de backdoors"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
    
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
    
    def backdoor_management_menu(self) -> str:
        """Menú principal de gestión de backdoors"""
        self.clear_screen()
        self.print_header("🔐 GESTIÓN DE BACKDOORS Y ACCESOS REMOTOS")
        
        print(f"{Colors.GREEN}Gestiona backdoors establecidos y ejecuta escaneos remotos{Colors.END}\n")
        
        self.print_menu_option(1, "📂 Cargar backdoors desde log específico", "📂")
        self.print_menu_option(2, "🔍 Descubrir backdoors existentes (todos los logs)", "🔍")
        self.print_menu_option(3, "🔗 Probar conexiones de backdoors", "🔗")
        self.print_menu_option(4, "🚀 Ejecutar escaneo completo desde backdoors", "🚀")
        self.print_menu_option(5, "📋 Ejecutar escaneo específico desde backdoor", "📋")
        self.print_menu_option(6, "🔧 Gestionar accesos remotos", "🔧")
        self.print_menu_option(7, "📊 Ver backdoors y accesos activos", "📊")
        self.print_menu_option(8, "🔄 Actualizar configuración de backdoors", "🔄")
        self.print_menu_option(9, "❌ Volver al menú principal", "🚪")
        
        choice = self.get_user_choice(9, "Seleccione una opción de gestión de backdoors")
        
        if choice == 0:  # Cancelado
            return "back"
        
        menu_options = {
            1: "load_from_log",
            2: "discover_backdoors",
            3: "test_connections",
            4: "full_remote_scan",
            5: "specific_remote_scan",
            6: "manage_access",
            7: "view_active",
            8: "update_config",
            9: "back"
        }
        
        return menu_options.get(choice, "back")
    
    def log_selection_menu(self) -> Optional[str]:
        """Menú para seleccionar log específico"""
        self.clear_screen()
        self.print_header("📂 SELECCIÓN DE LOG")
        
        print(f"{Colors.BLUE}Seleccione el log desde el cual cargar backdoors:{Colors.END}\n")
        
        # Buscar escaneos disponibles
        logs = []
        
        # Buscar en directorios de escaneos
        scans_dir = Path("scans")
        if scans_dir.exists():
            for scan_dir in scans_dir.iterdir():
                if not scan_dir.is_dir():
                    continue
                    
                # Agregar el directorio del escaneo
                logs.append(f"scan:{scan_dir.name}")
                
                # Buscar evidencia específica en cada escaneo
                persistence_evidence = scan_dir / "evidence" / "persistence.json"
                if persistence_evidence.exists():
                    logs.append(str(persistence_evidence))
                
                iot_evidence = scan_dir / "evidence" / "iot_exploitation.json"
                if iot_evidence.exists():
                    logs.append(str(iot_evidence))
                
                sql_evidence = scan_dir / "evidence" / "sql_exfiltration.json"
                if sql_evidence.exists():
                    logs.append(str(sql_evidence))
        
        if not logs:
            print(f"{Colors.RED}❌ No se encontraron logs disponibles{Colors.END}")
            print(f"{Colors.YELLOW}💡 Asegúrate de haber ejecutado al menos una fase de pentesting{Colors.END}")
            input(f"\n{Colors.YELLOW}Presione Enter para continuar...{Colors.END}")
            return None
        
        # Mostrar logs disponibles
        for i, log_file in enumerate(logs, 1):
            log_name = Path(log_file).name
            log_size = Path(log_file).stat().st_size
            log_time = Path(log_file).stat().st_mtime
            
            print(f"{Colors.CYAN}{i}. {log_name}{Colors.END}")
            print(f"   {Colors.WHITE}Tamaño: {log_size} bytes{Colors.END}")
            print(f"   {Colors.WHITE}Modificado: {time.ctime(log_time)}{Colors.END}")
            print()
        
        choice = self.get_user_choice(len(logs), "Seleccione un log")
        
        if choice == 0:
            return None
        
        return logs[choice - 1]
    
    def backdoor_selection_menu(self, backdoors: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Menú para seleccionar backdoor específico"""
        if not backdoors:
            print(f"{Colors.RED}❌ No hay backdoors disponibles{Colors.END}")
            return None
        
        self.clear_screen()
        self.print_header("📋 SELECCIÓN DE BACKDOOR")
        
        print(f"{Colors.BLUE}Seleccione el backdoor desde el cual ejecutar el escaneo:{Colors.END}\n")
        
        for i, backdoor in enumerate(backdoors, 1):
            backdoor_type = backdoor.get('type', 'unknown')
            ip = backdoor.get('ip', 'unknown')
            port = backdoor.get('port', 'unknown')
            status = "🟢 Activo" if backdoor.get('status') == 'active' else "🔴 Inactivo"
            
            print(f"{Colors.CYAN}{i}. {backdoor_type.upper()} en {ip}:{port} {status}{Colors.END}")
            if 'username' in backdoor:
                print(f"   {Colors.WHITE}Usuario: {backdoor['username']}{Colors.END}")
            if 'access_script' in backdoor:
                print(f"   {Colors.WHITE}Script: {backdoor['access_script']}{Colors.END}")
            print()
        
        choice = self.get_user_choice(len(backdoors), "Seleccione un backdoor")
        
        if choice == 0:
            return None
        
        return backdoors[choice - 1]
    
    def scan_type_selection_menu(self) -> str:
        """Menú para seleccionar tipo de escaneo"""
        self.clear_screen()
        self.print_header("📋 TIPO DE ESCANEO REMOTO")
        
        print(f"{Colors.BLUE}Seleccione el tipo de escaneo a ejecutar:{Colors.END}\n")
        
        scan_types = [
            ("reconnaissance", "🔍 Reconocimiento", "Escaneo de red y servicios"),
            ("advanced_reconnaissance", "🔍 Reconocimiento Avanzado", "Detección de arquitectura, SO y topología"),
            ("lateral_movement", "🔄 Movimiento lateral", "Exploración de la red interna"),
            ("persistence", "🚪 Persistencia", "Verificación de backdoors existentes"),
            ("privilege_escalation", "⬆️ Escalada de privilegios", "Búsqueda de vulnerabilidades"),
            ("exfiltration", "📤 Exfiltración", "Búsqueda de datos sensibles"),
            ("iot_exploitation", "📹 Explotación IoT", "Escaneo de dispositivos IoT"),
            ("sql_exfiltration", "🗄️ Exfiltración SQL", "Búsqueda de bases de datos"),
            ("post_execution_tasks", "🔧 Tareas Post-Ejecución", "Procedimientos extensos desde backdoors")
        ]
        
        for i, (scan_id, name, description) in enumerate(scan_types, 1):
            print(f"{Colors.CYAN}{i}. {name}{Colors.END}")
            print(f"   {Colors.WHITE}{description}{Colors.END}")
            print()
        
        choice = self.get_user_choice(len(scan_types), "Seleccione el tipo de escaneo")
        
        if choice == 0:
            return "back"
        
        return scan_types[choice - 1][0]
    
    def access_management_menu(self, remote_access: List[Dict[str, Any]]) -> str:
        """Menú de gestión de accesos remotos"""
        if not remote_access:
            print(f"{Colors.RED}❌ No hay accesos remotos disponibles{Colors.END}")
            return "back"
        
        self.clear_screen()
        self.print_header("🔧 GESTIÓN DE ACCESOS REMOTOS")
        
        print(f"{Colors.BLUE}Accesos remotos disponibles:{Colors.END}\n")
        
        for i, access in enumerate(remote_access, 1):
            access_type = access.get('type', 'unknown')
            ip = access.get('ip', 'unknown')
            port = access.get('port', 'unknown')
            
            print(f"{Colors.CYAN}{i}. {access_type.upper()} en {ip}:{port}{Colors.END}")
            if 'username' in access:
                print(f"   {Colors.WHITE}Usuario: {access['username']}{Colors.END}")
            if 'connection_script' in access:
                print(f"   {Colors.WHITE}Script: {access['connection_script']}{Colors.END}")
            print()
        
        print(f"{Colors.YELLOW}Opciones de gestión:{Colors.END}")
        self.print_menu_option(len(remote_access) + 1, "🔧 Modificar acceso específico", "🔧")
        self.print_menu_option(len(remote_access) + 2, "🔄 Actualizar credenciales", "🔄")
        self.print_menu_option(len(remote_access) + 3, "🌐 Cambiar dirección IP", "🌐")
        self.print_menu_option(len(remote_access) + 4, "🔌 Cambiar puerto", "🔌")
        self.print_menu_option(len(remote_access) + 5, "❌ Volver", "🚪")
        
        choice = self.get_user_choice(len(remote_access) + 5, "Seleccione una opción")
        
        if choice == 0:
            return "back"
        elif choice <= len(remote_access):
            return f"modify_access_{choice - 1}"
        elif choice == len(remote_access) + 1:
            return "modify_specific"
        elif choice == len(remote_access) + 2:
            return "update_credentials"
        elif choice == len(remote_access) + 3:
            return "change_ip"
        elif choice == len(remote_access) + 4:
            return "change_port"
        else:
            return "back"
    
    def modification_input_menu(self, access: Dict[str, Any]) -> Dict[str, Any]:
        """Menú para entrada de modificaciones"""
        self.clear_screen()
        self.print_header("🔧 MODIFICACIÓN DE ACCESO REMOTO")
        
        print(f"{Colors.BLUE}Modificando acceso: {access.get('type', 'unknown')} en {access.get('ip', 'unknown')}:{access.get('port', 'unknown')}{Colors.END}\n")
        
        modifications = {}
        
        # Modificar IP
        print(f"{Colors.YELLOW}Dirección IP actual: {access.get('ip', 'N/A')}{Colors.END}")
        new_ip = input(f"{Colors.CYAN}Nueva IP (Enter para mantener): {Colors.END}").strip()
        if new_ip:
            modifications['ip'] = new_ip
        
        # Modificar puerto
        print(f"{Colors.YELLOW}Puerto actual: {access.get('port', 'N/A')}{Colors.END}")
        new_port = input(f"{Colors.CYAN}Nuevo puerto (Enter para mantener): {Colors.END}").strip()
        if new_port:
            modifications['port'] = new_port
        
        # Modificar usuario
        if 'username' in access:
            print(f"{Colors.YELLOW}Usuario actual: {access['username']}{Colors.END}")
            new_user = input(f"{Colors.CYAN}Nuevo usuario (Enter para mantener): {Colors.END}").strip()
            if new_user:
                modifications['username'] = new_user
        
        # Modificar contraseña
        if 'password' in access:
            print(f"{Colors.YELLOW}Contraseña actual: {access['password']}{Colors.END}")
            new_pass = input(f"{Colors.CYAN}Nueva contraseña (Enter para mantener): {Colors.END}").strip()
            if new_pass:
                modifications['password'] = new_pass
        
        return modifications
    
    def show_backdoors_summary(self, backdoors: List[Dict[str, Any]], connections: List[Dict[str, Any]]):
        """Mostrar resumen de backdoors y conexiones"""
        self.clear_screen()
        self.print_header("📊 RESUMEN DE BACKDOORS Y ACCESOS")
        
        print(f"{Colors.GREEN}Backdoors descubiertos: {len(backdoors)}{Colors.END}")
        print(f"{Colors.GREEN}Conexiones activas: {len(connections)}{Colors.END}\n")
        
        if backdoors:
            print(f"{Colors.BLUE}📋 BACKDOORS DISPONIBLES:{Colors.END}")
            for i, backdoor in enumerate(backdoors, 1):
                backdoor_type = backdoor.get('type', 'unknown')
                ip = backdoor.get('ip', 'unknown')
                port = backdoor.get('port', 'unknown')
                status = "🟢" if any(conn['backdoor']['ip'] == ip for conn in connections) else "🔴"
                
                print(f"{Colors.CYAN}  {i}. {status} {backdoor_type.upper()} en {ip}:{port}{Colors.END}")
                if 'username' in backdoor:
                    print(f"     {Colors.WHITE}Usuario: {backdoor['username']}{Colors.END}")
                if 'access_script' in backdoor:
                    print(f"     {Colors.WHITE}Script: {backdoor['access_script']}{Colors.END}")
                print()
        
        if connections:
            print(f"{Colors.BLUE}🔗 CONEXIONES ACTIVAS:{Colors.END}")
            for i, connection in enumerate(connections, 1):
                backdoor = connection['backdoor']
                response_time = connection.get('response_time', 0)
                
                print(f"{Colors.CYAN}  {i}. {backdoor['type'].upper()} en {backdoor['ip']}:{backdoor['port']}{Colors.END}")
                print(f"     {Colors.WHITE}Tiempo de respuesta: {response_time:.2f}s{Colors.END}")
                print()
        
        input(f"\n{Colors.YELLOW}Presione Enter para continuar...{Colors.END}")
    
    def show_scan_results(self, scan_results: Dict[str, Any]):
        """Mostrar resultados de escaneo remoto"""
        self.clear_screen()
        self.print_header("📊 RESULTADOS DE ESCANEO REMOTO")
        
        backdoor = scan_results.get('backdoor', {})
        scan_type = scan_results.get('scan_type', 'unknown')
        success = scan_results.get('success', False)
        
        print(f"{Colors.BLUE}Backdoor: {backdoor.get('type', 'unknown')} en {backdoor.get('ip', 'unknown')}:{backdoor.get('port', 'unknown')}{Colors.END}")
        print(f"{Colors.BLUE}Tipo de escaneo: {scan_type}{Colors.END}")
        print(f"{Colors.BLUE}Estado: {'✅ Exitoso' if success else '❌ Fallido'}{Colors.END}\n")
        
        if success and 'results' in scan_results:
            results = scan_results['results']
            
            if 'commands' in results:
                print(f"{Colors.GREEN}Comandos ejecutados:{Colors.END}")
                for i, command in enumerate(results['commands'], 1):
                    print(f"{Colors.CYAN}  {i}. {command}{Colors.END}")
                print()
            
            if 'output' in results:
                print(f"{Colors.GREEN}Salida de comandos:{Colors.END}")
                for i, output in enumerate(results['output'], 1):
                    if output.strip():
                        print(f"{Colors.WHITE}  Comando {i}:{Colors.END}")
                        print(f"{Colors.WHITE}{output[:500]}{'...' if len(output) > 500 else ''}{Colors.END}")
                        print()
            
            if 'urls' in results:
                print(f"{Colors.GREEN}URLs probadas:{Colors.END}")
                for i, url in enumerate(results['urls'], 1):
                    print(f"{Colors.CYAN}  {i}. {url}{Colors.END}")
                print()
            
            if 'responses' in results:
                print(f"{Colors.GREEN}Respuestas:{Colors.END}")
                for i, response in enumerate(results['responses'], 1):
                    if isinstance(response, dict):
                        if 'status_code' in response:
                            print(f"{Colors.CYAN}  {i}. Status: {response['status_code']}{Colors.END}")
                        if 'content_preview' in response:
                            print(f"{Colors.WHITE}     Contenido: {response['content_preview'][:200]}...{Colors.END}")
                        print()
        
        if 'error' in scan_results:
            print(f"{Colors.RED}Error: {scan_results['error']}{Colors.END}")
        
        input(f"\n{Colors.YELLOW}Presione Enter para continuar...{Colors.END}")
    
    def _scan_selection_menu(self) -> Optional[str]:
        """Menú de selección de escaneo específico"""
        self.clear_screen()
        self.print_header("📁 SELECCIÓN DE ESCANEO")
        
        print(f"{Colors.BLUE}Seleccione el escaneo desde el cual cargar backdoors:{Colors.END}\n")
        
        try:
            from modules.scan_manager import ScanManager
            scan_manager = ScanManager(self.config, self.logger)
            available_scans = scan_manager.list_scans()
            
            if not available_scans:
                print(f"{Colors.RED}❌ No se encontraron escaneos disponibles{Colors.END}")
                input(f"\n{Colors.YELLOW}Presione Enter para continuar...{Colors.END}")
                return None
            
            # Mostrar escaneos disponibles
            for i, scan in enumerate(available_scans, 1):
                status_icon = "✅" if scan.get('status') == 'completed' else "🔄" if scan.get('status') == 'active' else "❌"
                scan_type = "🧊 FRÍO" if scan.get('is_cold_pentest') else "🔥 NORMAL"
                print(f"{Colors.CYAN}{i}. {status_icon} {scan['mote']} {scan_type}{Colors.END}")
                print(f"   {Colors.WHITE}ID: {scan['scan_id']}{Colors.END}")
                print(f"   {Colors.WHITE}Estado: {scan.get('status', 'unknown')}{Colors.END}")
                print(f"   {Colors.WHITE}Creado: {scan.get('created_at', 'unknown')}{Colors.END}")
                if scan.get('description'):
                    print(f"   {Colors.WHITE}Descripción: {scan['description']}{Colors.END}")
                if scan.get('is_cold_pentest'):
                    print(f"   {Colors.YELLOW}⚠️  PENTEST FRÍO: Backdoors eliminados, solo datos de referencia{Colors.END}")
                print()
            
            print(f"{Colors.CYAN}{len(available_scans) + 1}. 🔙 Volver{Colors.END}")
            
            choice = int(input(f"\n{Colors.YELLOW}Seleccione un escaneo (1-{len(available_scans) + 1}): {Colors.END}"))
            
            if choice == len(available_scans) + 1:
                return None
            elif 1 <= choice <= len(available_scans):
                selected_scan = available_scans[choice - 1]
                print(f"\n{Colors.GREEN}✅ Escaneo seleccionado: {selected_scan['mote']}{Colors.END}")
                return f"scan:{selected_scan['scan_id']}"
            else:
                print(f"{Colors.RED}❌ Opción inválida{Colors.END}")
                return None
                
        except Exception as e:
            print(f"{Colors.RED}❌ Error cargando escaneos: {e}{Colors.END}")
            return None
