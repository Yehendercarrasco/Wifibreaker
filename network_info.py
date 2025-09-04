#!/usr/bin/env python3
"""
Script auxiliar para mostrar información de red
Ayuda a verificar la configuración automática
Funciona en Linux y Windows
"""

import subprocess
import re
import json
import platform
import socket

def get_network_info():
    """Obtener información completa de red"""
    print("🌐 INFORMACIÓN DE RED DEL SISTEMA")
    print(f"🖥️  Sistema operativo: {platform.system()} {platform.release()}")
    print("="*50)
    
    # Detectar sistema operativo
    is_linux = platform.system().lower() == 'linux'
    is_windows = platform.system().lower() == 'windows'
    
    # 1. Interfaces de red
    print("\n📡 INTERFACES DE RED:")
    if is_linux:
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ': ' in line and 'state' in line:
                        print(f"  {line.strip()}")
            else:
                print("  ❌ Error obteniendo interfaces")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    elif is_windows:
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'adapter' in line.lower() or 'ethernet' in line.lower() or 'wireless' in line.lower():
                        print(f"  {line.strip()}")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    else:
        print("  ℹ️  Sistema operativo no soportado para detección automática")
    
    # 2. IPs asignadas
    print("\n🏠 DIRECCIONES IP:")
    if is_linux:
        try:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line and not '127.0.0.1' in line:
                        print(f"  {line.strip()}")
            else:
                print("  ❌ Error obteniendo IPs")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    elif is_windows:
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'IPv4' in line or 'Dirección IPv4' in line:
                        print(f"  {line.strip()}")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    # Información básica usando Python
    print("\n🐍 INFORMACIÓN BÁSICA (Python):")
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"  🏠 Hostname: {hostname}")
        print(f"  🌐 IP local: {local_ip}")
    except Exception as e:
        print(f"  ❌ Error obteniendo información básica: {e}")
    
    # 3. Rutas de red
    print("\n🛣️  RUTAS DE RED:")
    if is_linux:
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        print(f"  {line.strip()}")
            else:
                print("  ❌ Error obteniendo rutas")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    elif is_windows:
        try:
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and 'Gateway' in line:
                        print(f"  {line.strip()}")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    # 4. Gateway por defecto
    print("\n📡 GATEWAY POR DEFECTO:")
    if is_linux:
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"  {result.stdout.strip()}")
            else:
                print("  ❌ No se encontró gateway por defecto")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    elif is_windows:
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Gateway' in line or 'Puerta de enlace' in line:
                        print(f"  {line.strip()}")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    # 5. Información de WiFi (si está disponible)
    print("\n📶 INFORMACIÓN DE WIFI:")
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'IEEE 802.11' in line or 'ESSID:' in line or 'Access Point:' in line:
                    print(f"  {line.strip()}")
        else:
            print("  ℹ️  iwconfig no disponible (puede ser normal)")
    except Exception as e:
        print(f"  ℹ️  iwconfig no disponible: {e}")
    
    # 6. Resumen de configuración recomendada
    print("\n💡 CONFIGURACIÓN RECOMENDADA:")
    try:
        if is_linux:
            # Detectar interfaz activa
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                interfaces = []
                for line in lines:
                    if ': ' in line and 'state UP' in line:
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            interface_name = parts[1].split('@')[0].strip()
                            if interface_name and interface_name != 'lo':
                                interfaces.append(interface_name)
                
                # Priorizar WiFi
                wifi_interfaces = [iface for iface in interfaces if 'wlan' in iface or 'wifi' in iface or 'wireless' in iface]
                if wifi_interfaces:
                    recommended_interface = wifi_interfaces[0]
                elif interfaces:
                    recommended_interface = interfaces[0]
                else:
                    recommended_interface = "eth0"
                
                print(f"  🌐 Interfaz recomendada: {recommended_interface}")
                
                # Detectar IP local
                if recommended_interface:
                    result = subprocess.run(['ip', 'addr', 'show', recommended_interface], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'inet ' in line and not '127.0.0.1' in line:
                                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', line)
                                if match:
                                    local_ip = match.group(1)
                                    print(f"  🏠 IP local: {local_ip}")
                                    
                                    # Calcular red objetivo
                                    ip_parts = local_ip.split('.')
                                    if len(ip_parts) == 4:
                                        target_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                                        print(f"  🎯 Red objetivo: {target_network}")
                                    break
                
                # Detectar router
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if match:
                        router_ip = match.group(1)
                        print(f"  📡 Router: {router_ip}")
        
        elif is_windows:
            # Para Windows, usar información básica
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                print(f"  🌐 Interfaz recomendada: eth0 (configurar manualmente)")
                print(f"  🏠 IP local: {local_ip}")
                
                # Calcular red objetivo
                ip_parts = local_ip.split('.')
                if len(ip_parts) == 4:
                    target_network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                    print(f"  🎯 Red objetivo: {target_network}")
                
                # Intentar detectar router
                try:
                    result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'Gateway' in line or 'Puerta de enlace' in line:
                                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                                if match:
                                    router_ip = match.group(1)
                                    print(f"  📡 Router: {router_ip}")
                                    break
                except:
                    pass
                    
            except Exception as e:
                print(f"  ❌ Error obteniendo información básica: {e}")
        
    except Exception as e:
        print(f"  ❌ Error generando recomendaciones: {e}")
    
    print("\n" + "="*50)
    print("💡 Para configurar automáticamente, ejecuta:")
    print("   python3 pentest_automation.py --auto-config")
    print("="*50)

if __name__ == "__main__":
    get_network_info()
