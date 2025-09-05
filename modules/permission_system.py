"""
Sistema de Permisos y Confirmaciones para Acciones de Riesgo
"""

import os
import getpass
from typing import Dict, List, Any, Optional
from modules.logging_system import Colors

class PermissionSystem:
    """Sistema de permisos para acciones que pueden modificar o dañar sistemas"""
    
    def __init__(self, logger):
        self.logger = logger
        self.approval_pin = "0443"
        self.risk_actions = {
            'encrypt_data': {
                'description': 'Encriptar datos del sistema objetivo',
                'risk_level': 'HIGH',
                'irreversible': True
            },
            'corrupt_data': {
                'description': 'Corromper datos del sistema objetivo',
                'risk_level': 'CRITICAL',
                'irreversible': True
            },
            'compress_data': {
                'description': 'Comprimir archivos del sistema objetivo',
                'risk_level': 'MEDIUM',
                'irreversible': False
            },
            'create_files': {
                'description': 'Crear archivos en el sistema objetivo',
                'risk_level': 'MEDIUM',
                'irreversible': False
            },
            'modify_system': {
                'description': 'Modificar configuraciones del sistema',
                'risk_level': 'HIGH',
                'irreversible': True
            },
            'cleanup_evidence': {
                'description': 'Limpiar evidencia de rastros',
                'risk_level': 'LOW',
                'irreversible': False
            },
            'cleanup_backdoors': {
                'description': 'Limpiar backdoors y accesos persistentes',
                'risk_level': 'HIGH',
                'irreversible': True
            }
        }
    
    def clear_screen(self):
        """Limpiar pantalla"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_risk_warning(self, action: str, description: str):
        """Imprimir advertencia de riesgo"""
        print(f"\n{Colors.RED}{'='*80}{Colors.END}")
        print(f"{Colors.RED}{Colors.BOLD}⚠️  OPCIÓN DE RIESGO ⚠️{Colors.END}")
        print(f"{Colors.RED}{'='*80}{Colors.END}")
        print(f"{Colors.YELLOW}ACCIÓN: {action.upper()}{Colors.END}")
        print(f"{Colors.WHITE}DESCRIPCIÓN: {description}{Colors.END}")
        print(f"{Colors.RED}⚠️  ESTA ACCIÓN PUEDE MODIFICAR O DAÑAR EL SISTEMA OBJETIVO{Colors.END}")
        print(f"{Colors.RED}⚠️  SOLO PROCEDA SI SABE EXACTAMENTE LO QUE ESTÁ HACIENDO{Colors.END}")
        print(f"{Colors.RED}{'='*80}{Colors.END}\n")
    
    def get_user_confirmation(self, action: str, description: str, risk_level: str) -> bool:
        """Obtener confirmación del usuario para acción de riesgo"""
        self.print_risk_warning(action, description)
        
        # Mostrar nivel de riesgo
        risk_colors = {
            'LOW': Colors.GREEN,
            'MEDIUM': Colors.YELLOW,
            'HIGH': Colors.ORANGE,
            'CRITICAL': Colors.RED
        }
        
        risk_color = risk_colors.get(risk_level, Colors.WHITE)
        print(f"{Colors.BLUE}Nivel de riesgo: {risk_color}{risk_level}{Colors.END}")
        
        # Primera confirmación
        print(f"\n{Colors.YELLOW}¿Está seguro que desea proceder con esta acción?{Colors.END}")
        print(f"{Colors.BLUE}1. Sí, proceder{Colors.END}")
        print(f"{Colors.BLUE}2. No, cancelar{Colors.END}")
        
        try:
            choice = input(f"\n{Colors.YELLOW}Seleccione una opción (1-2): {Colors.END}")
            
            if choice != '1':
                print(f"{Colors.GREEN}✅ Acción cancelada por el usuario{Colors.END}")
                return False
            
            # Segunda confirmación para acciones irreversibles
            action_info = self.risk_actions.get(action, {})
            if action_info.get('irreversible', False):
                return self._get_double_confirmation(action, description)
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}✅ Acción cancelada por el usuario{Colors.END}")
            return False
    
    def _get_double_confirmation(self, action: str, description: str) -> bool:
        """Obtener doble confirmación para acciones irreversibles"""
        print(f"\n{Colors.RED}{'='*60}{Colors.END}")
        print(f"{Colors.RED}⚠️  ACCIÓN IRREVERSIBLE ⚠️{Colors.END}")
        print(f"{Colors.RED}{'='*60}{Colors.END}")
        print(f"{Colors.WHITE}Esta acción NO se puede deshacer{Colors.END}")
        print(f"{Colors.WHITE}Descripción: {description}{Colors.END}")
        print(f"{Colors.RED}⚠️  Confirme nuevamente que desea proceder{Colors.END}")
        print(f"{Colors.RED}{'='*60}{Colors.END}")
        
        # Segunda confirmación
        print(f"\n{Colors.YELLOW}¿Confirma que desea proceder con esta acción irreversible?{Colors.END}")
        print(f"{Colors.BLUE}1. Sí, confirmo que quiero proceder{Colors.END}")
        print(f"{Colors.BLUE}2. No, cancelar{Colors.END}")
        
        try:
            choice = input(f"\n{Colors.YELLOW}Seleccione una opción (1-2): {Colors.END}")
            
            if choice != '1':
                print(f"{Colors.GREEN}✅ Acción irreversible cancelada por el usuario{Colors.END}")
                return False
            
            # Tercera confirmación con PIN
            return self._get_pin_confirmation(action)
            
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}✅ Acción irreversible cancelada por el usuario{Colors.END}")
            return False
    
    def _get_pin_confirmation(self, action: str) -> bool:
        """Obtener confirmación con PIN para acciones críticas"""
        print(f"\n{Colors.RED}{'='*60}{Colors.END}")
        print(f"{Colors.RED}🔐 CONFIRMACIÓN FINAL CON PIN{Colors.END}")
        print(f"{Colors.RED}{'='*60}{Colors.END}")
        print(f"{Colors.WHITE}Para proceder con esta acción crítica,{Colors.END}")
        print(f"{Colors.WHITE}debe ingresar el PIN de aprobación.{Colors.END}")
        print(f"{Colors.RED}⚠️  Esta es la confirmación final{Colors.END}")
        print(f"{Colors.RED}{'='*60}{Colors.END}")
        
        try:
            pin = getpass.getpass(f"\n{Colors.YELLOW}Ingrese el PIN de aprobación: {Colors.END}")
            
            if pin == self.approval_pin:
                print(f"{Colors.GREEN}✅ PIN correcto. Procediendo con la acción...{Colors.END}")
                return True
            else:
                print(f"{Colors.RED}❌ PIN incorrecto. Acción cancelada por seguridad.{Colors.END}")
                return False
                
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}✅ Acción cancelada por el usuario{Colors.END}")
            return False
    
    def request_permission(self, action: str, description: str = None) -> bool:
        """Solicitar permiso para una acción específica"""
        if action not in self.risk_actions:
            # Acción no catalogada como de riesgo, permitir
            return True
        
        action_info = self.risk_actions[action]
        risk_level = action_info['risk_level']
        action_description = description or action_info['description']
        
        return self.get_user_confirmation(action, action_description, risk_level)
    
    def log_permission_granted(self, action: str, user_decision: str):
        """Registrar que se otorgó permiso para una acción"""
        self.logger.info(f"🔐 Permiso otorgado para acción: {action} - Decisión: {user_decision}")
    
    def log_permission_denied(self, action: str, reason: str = "Usuario canceló"):
        """Registrar que se denegó permiso para una acción"""
        self.logger.info(f"🚫 Permiso denegado para acción: {action} - Razón: {reason}")
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Obtener resumen de acciones de riesgo disponibles"""
        summary = {
            'total_actions': len(self.risk_actions),
            'by_risk_level': {},
            'irreversible_actions': []
        }
        
        for action, info in self.risk_actions.items():
            risk_level = info['risk_level']
            if risk_level not in summary['by_risk_level']:
                summary['by_risk_level'][risk_level] = []
            summary['by_risk_level'][risk_level].append(action)
            
            if info.get('irreversible', False):
                summary['irreversible_actions'].append(action)
        
        return summary
    
    def show_risk_summary(self):
        """Mostrar resumen de acciones de riesgo"""
        summary = self.get_risk_summary()
        
        print(f"\n{Colors.CYAN}📊 RESUMEN DE ACCIONES DE RIESGO{Colors.END}")
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")
        
        for risk_level, actions in summary['by_risk_level'].items():
            risk_colors = {
                'LOW': Colors.GREEN,
                'MEDIUM': Colors.YELLOW,
                'HIGH': Colors.ORANGE,
                'CRITICAL': Colors.RED
            }
            
            risk_color = risk_colors.get(risk_level, Colors.WHITE)
            print(f"\n{risk_color}{risk_level}:{Colors.END}")
            
            for action in actions:
                action_info = self.risk_actions[action]
                irreversible = " (IRREVERSIBLE)" if action_info.get('irreversible', False) else ""
                print(f"  • {action}: {action_info['description']}{irreversible}")
        
        print(f"\n{Colors.RED}⚠️  Total de acciones irreversibles: {len(summary['irreversible_actions'])}{Colors.END}")
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")
    
    def validate_action_safety(self, action: str, target_system: str = None) -> Dict[str, Any]:
        """Validar la seguridad de una acción antes de ejecutarla"""
        if action not in self.risk_actions:
            return {
                'safe': True,
                'requires_permission': False,
                'message': 'Acción no catalogada como de riesgo'
            }
        
        action_info = self.risk_actions[action]
        
        return {
            'safe': False,
            'requires_permission': True,
            'risk_level': action_info['risk_level'],
            'irreversible': action_info.get('irreversible', False),
            'description': action_info['description'],
            'message': f"Acción de riesgo nivel {action_info['risk_level']}"
        }
