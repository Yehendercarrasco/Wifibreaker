#!/usr/bin/env python3
"""
Demo de Configuración de Opciones Delicadas
Ejemplo de cómo funciona el sistema de opciones delicadas en la exfiltración
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pentest_automation import PentestAutomation
import logging

def setup_logging():
    """Configurar logging para el demo"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('delicate_options_demo.log')
        ]
    )
    return logging.getLogger(__name__)

def demo_delicate_options():
    """Demo de configuración de opciones delicadas"""
    logger = setup_logging()
    
    logger.info("🚀 DEMO DE CONFIGURACIÓN DE OPCIONES DELICADAS")
    logger.info("=" * 60)
    
    # Crear instancia del sistema
    pentest = PentestAutomation("config.json")
    
    # Simular configuración de opciones delicadas
    logger.info("📋 ESCENARIO 1: Usuario dice NO a opciones delicadas")
    pentest.delicate_options = {
        'compression_enabled': False,
        'encryption_enabled': False,
        'corruption_enabled': False,
        'user_choice_made': True
    }
    
    # Obtener configuración para escaneo normal
    normal_config = pentest.get_delicate_options(from_backdoor=False)
    logger.info("Configuración para escaneo normal:")
    logger.info(f"  • Compresión: {'✅ Habilitada' if normal_config['compression_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Encriptación: {'✅ Habilitada' if normal_config['encryption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Corrupción: {'✅ Habilitada' if normal_config['corruption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Exfiltración rápida: {'✅ Habilitada' if normal_config['fast_exfiltration'] else '❌ Deshabilitada'}")
    
    # Obtener configuración para gestión de backdoors
    backdoor_config = pentest.get_delicate_options(from_backdoor=True)
    logger.info("\nConfiguración para gestión de backdoors:")
    logger.info(f"  • Compresión: {'✅ Habilitada' if backdoor_config['compression_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Encriptación: {'✅ Habilitada' if backdoor_config['encryption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Corrupción: {'✅ Habilitada' if backdoor_config['corruption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Exfiltración rápida: {'✅ Habilitada' if backdoor_config['fast_exfiltration'] else '❌ Deshabilitada'}")
    
    logger.info("\n" + "=" * 60)
    logger.info("📋 ESCENARIO 2: Usuario dice SÍ a opciones delicadas")
    pentest.delicate_options = {
        'compression_enabled': True,
        'encryption_enabled': True,
        'corruption_enabled': False,
        'user_choice_made': True
    }
    
    # Obtener configuración para escaneo normal
    normal_config = pentest.get_delicate_options(from_backdoor=False)
    logger.info("Configuración para escaneo normal:")
    logger.info(f"  • Compresión: {'✅ Habilitada' if normal_config['compression_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Encriptación: {'✅ Habilitada' if normal_config['encryption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Corrupción: {'✅ Habilitada' if normal_config['corruption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Exfiltración rápida: {'✅ Habilitada' if normal_config['fast_exfiltration'] else '❌ Deshabilitada'}")
    
    # Obtener configuración para gestión de backdoors
    backdoor_config = pentest.get_delicate_options(from_backdoor=True)
    logger.info("\nConfiguración para gestión de backdoors:")
    logger.info(f"  • Compresión: {'✅ Habilitada' if backdoor_config['compression_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Encriptación: {'✅ Habilitada' if backdoor_config['encryption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Corrupción: {'✅ Habilitada' if backdoor_config['corruption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Exfiltración rápida: {'✅ Habilitada' if backdoor_config['fast_exfiltration'] else '❌ Deshabilitada'}")
    
    logger.info("\n" + "=" * 60)
    logger.info("📋 ESCENARIO 3: Usuario habilita todas las opciones delicadas")
    pentest.delicate_options = {
        'compression_enabled': True,
        'encryption_enabled': True,
        'corruption_enabled': True,
        'user_choice_made': True
    }
    
    # Obtener configuración para escaneo normal
    normal_config = pentest.get_delicate_options(from_backdoor=False)
    logger.info("Configuración para escaneo normal:")
    logger.info(f"  • Compresión: {'✅ Habilitada' if normal_config['compression_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Encriptación: {'✅ Habilitada' if normal_config['encryption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Corrupción: {'✅ Habilitada' if normal_config['corruption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Exfiltración rápida: {'✅ Habilitada' if normal_config['fast_exfiltration'] else '❌ Deshabilitada'}")
    
    # Obtener configuración para gestión de backdoors
    backdoor_config = pentest.get_delicate_options(from_backdoor=True)
    logger.info("\nConfiguración para gestión de backdoors:")
    logger.info(f"  • Compresión: {'✅ Habilitada' if backdoor_config['compression_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Encriptación: {'✅ Habilitada' if backdoor_config['encryption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Corrupción: {'✅ Habilitada' if backdoor_config['corruption_enabled'] else '❌ Deshabilitada'}")
    logger.info(f"  • Exfiltración rápida: {'✅ Habilitada' if backdoor_config['fast_exfiltration'] else '❌ Deshabilitada'}")
    
    logger.info("\n" + "=" * 60)
    logger.info("💡 RESUMEN DE FUNCIONAMIENTO:")
    logger.info("1. Al inicio del script se pregunta sobre opciones delicadas")
    logger.info("2. Si dice NO → Solo exfiltración rápida de archivos pequeños")
    logger.info("3. Si dice SÍ → Se configuran opciones específicas")
    logger.info("4. En gestión de backdoors → Todas las opciones disponibles")
    logger.info("5. El sistema respeta la configuración del usuario")
    
    logger.info("\n✅ DEMO COMPLETADO")

def demo_exfiltration_modes():
    """Demo de modos de exfiltración"""
    logger = setup_logging()
    
    logger.info("\n🚀 DEMO DE MODOS DE EXFILTRACIÓN")
    logger.info("=" * 60)
    
    # Simular archivos encontrados
    sample_files = [
        {'path': '/etc/passwd', 'size': 1024, 'ext': '.txt'},
        {'path': '/var/log/auth.log', 'size': 2048, 'ext': '.log'},
        {'path': '/home/user/document.pdf', 'size': 5*1024*1024, 'ext': '.pdf'},
        {'path': '/home/user/vacation.jpg', 'size': 15*1024*1024, 'ext': '.jpg'},
        {'path': '/home/user/movie.mp4', 'size': 500*1024*1024, 'ext': '.mp4'},
        {'path': '/etc/nginx/nginx.conf', 'size': 512, 'ext': '.conf'},
        {'path': '/var/lib/mysql/database.sql', 'size': 2*1024*1024, 'ext': '.sql'}
    ]
    
    logger.info("📁 ARCHIVOS ENCONTRADOS EN EL SISTEMA:")
    for file in sample_files:
        logger.info(f"  • {file['path']} ({file['size']} bytes, {file['ext']})")
    
    # Exfiltración rápida
    logger.info("\n⚡ EXFILTRACIÓN RÁPIDA (archivos pequeños):")
    excluded_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.mp4', '.avi', '.mkv', '.mp3', '.wav'}
    included_extensions = {'.txt', '.log', '.cfg', '.conf', '.pdf', '.sql'}
    max_size = 10 * 1024 * 1024  # 10MB
    
    fast_files = []
    for file in sample_files:
        if file['ext'] in excluded_extensions:
            logger.info(f"  ❌ EXCLUIDO: {file['path']} (tipo de archivo excluido)")
        elif file['size'] > max_size:
            logger.info(f"  ❌ EXCLUIDO: {file['path']} (archivo muy grande)")
        elif file['ext'] in included_extensions or file['ext'] == '':
            fast_files.append(file)
            logger.info(f"  ✅ INCLUIDO: {file['path']} (archivo pequeño)")
        else:
            logger.info(f"  ❌ EXCLUIDO: {file['path']} (tipo de archivo no incluido)")
    
    logger.info(f"\n📊 RESULTADO EXFILTRACIÓN RÁPIDA: {len(fast_files)} archivos")
    total_size = sum(f['size'] for f in fast_files)
    logger.info(f"📏 Tamaño total: {total_size} bytes ({total_size/1024/1024:.2f} MB)")
    
    # Exfiltración completa
    logger.info("\n🆕 EXFILTRACIÓN COMPLETA (todos los archivos):")
    logger.info("  ✅ TODOS LOS ARCHIVOS INCLUIDOS")
    total_size_all = sum(f['size'] for f in sample_files)
    logger.info(f"📊 Total: {len(sample_files)} archivos")
    logger.info(f"📏 Tamaño total: {total_size_all} bytes ({total_size_all/1024/1024:.2f} MB)")
    
    logger.info("\n✅ DEMO DE MODOS COMPLETADO")

if __name__ == "__main__":
    demo_delicate_options()
    demo_exfiltration_modes()
