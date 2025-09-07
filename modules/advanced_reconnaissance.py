"""
Módulo de Reconocimiento Avanzado para Automatización de Pentesting
Incluye detección de arquitectura, SO, topología y mapeo de red
"""

import subprocess
import json
import time
import threading
from typing import Dict, List, Any, Optional
from pathlib import Path
import ipaddress
import re
from modules.logging_system import LoggingSystem

class AdvancedReconnaissanceModule:
    """Módulo de reconocimiento avanzado de red y sistemas"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.network_config = config['network_config']
        self.targets_config = config['targets']
        self.logging_system = LoggingSystem(config, logger)
        
        # Resultados del reconocimiento avanzado
        self.results = {
            'hosts': [],
            'os_detection': [],
            'services': [],
            'topology': {},
            'devices': [],
            'network_map': {},
            'architecture_info': {},
            'timestamp': time.time()
        }
        
        # Directorio de evidencia
        self.evidence_dir = Path("evidence/advanced_reconnaissance")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Obtener IP del router automáticamente
        self.router_ip = self._discover_router()
        if self.router_ip:
            self.network_config['router_ip'] = self.router_ip
            self.logging_system.log_success(f"Router descubierto: {self.router_ip}", "ADVANCED_RECON")
        
        # Obtener IP pública
        self.public_ip = self._get_public_ip()
        if self.public_ip:
            self.results['public_ip'] = self.public_ip
            self.logging_system.log_important(f"IP pública detectada: {self.public_ip}", "ADVANCED_RECON")
    
    def run_advanced_reconnaissance(self) -> Dict[str, Any]:
        """Ejecutar reconocimiento avanzado completo"""
        self.logger.info("🚀 INICIANDO RECONOCIMIENTO AVANZADO")
        
        start_time = time.time()
        
        try:
            # 1. Descubrimiento rápido de hosts
            self.logger.info("⚡ Fase 1: Descubrimiento rápido de hosts")
            discovered_hosts = self.discover_hosts_fast()
            
            if not discovered_hosts:
                self.logger.warning("⚠️ No se descubrieron hosts")
                return self.results
            
            # 2. Detección de arquitectura y SO
            self.logger.info("🖥️ Fase 2: Detección de arquitectura y sistemas operativos")
            os_detection_results = self.detect_operating_systems(discovered_hosts)
            
            # 3. Escaneo de servicios críticos
            self.logger.info("🔍 Fase 3: Escaneo de servicios críticos")
            service_scan_results = self.scan_critical_services(discovered_hosts)
            
            # 4. Mapeo de topología de red
            self.logger.info("🗺️ Fase 4: Mapeo de topología de red")
            topology_results = self.map_network_topology(discovered_hosts)
            
            # 5. Detección de dispositivos específicos
            self.logger.info("📱 Fase 5: Detección de dispositivos específicos")
            device_detection_results = self.detect_specific_devices(discovered_hosts)
            
            # 6. Enumeración de servicios críticos
            self.logger.info("🔍 Fase 6: Enumeración de servicios críticos")
            enumeration_results = self.enumerate_critical_services(service_scan_results)
            
            # 7. Generar mapa de red visual
            self.logger.info("🗺️ Fase 7: Generando mapa de red")
            self.generate_network_map(discovered_hosts, topology_results, os_detection_results)
            
            # Guardar resultados
            self.results['hosts'] = discovered_hosts
            self.results['os_detection'] = os_detection_results
            self.results['services'] = service_scan_results
            self.results['topology'] = topology_results
            self.results['devices'] = device_detection_results
            self.results['enumeration'] = enumeration_results
            
            # Guardar evidencia
            self._save_evidence()
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ RECONOCIMIENTO AVANZADO COMPLETADO en {duration:.2f} segundos")
            self.logger.info(f"📊 Hosts descubiertos: {len(discovered_hosts)}")
            self.logger.info(f"🖥️ Sistemas operativos detectados: {len(os_detection_results)}")
            self.logger.info(f"🔍 Servicios encontrados: {len(service_scan_results)}")
            self.logger.info(f"📱 Dispositivos específicos: {len(device_detection_results)}")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en reconocimiento avanzado: {e}")
            return self.results
    
    def discover_hosts_fast(self) -> List[Dict[str, Any]]:
        """Descubrimiento rápido de hosts con detección de arquitectura"""
        self.logger.info("⚡ DESCUBRIMIENTO RÁPIDO DE HOSTS")
        
        hosts = []
        
        # 1. ARP scan rápido
        arp_hosts = self._arp_scan_fast()
        hosts.extend(arp_hosts)
        
        # 2. Ping sweep rápido
        ping_hosts = self._ping_sweep_fast()
        hosts.extend(ping_hosts)
        
        # 3. Detectar arquitectura y SO básico
        for host in hosts:
            host['architecture'] = self._detect_architecture(host['ip'])
            host['os_family'] = self._detect_os_family(host['ip'])
            host['device_type'] = self._detect_device_type(host)
        
        # Eliminar duplicados
        unique_hosts = {}
        for host in hosts:
            ip = host['ip']
            if ip not in unique_hosts:
                unique_hosts[ip] = host
            else:
                # Combinar información
                unique_hosts[ip].update(host)
        
        return list(unique_hosts.values())
    
    def detect_operating_systems(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detección rápida de sistemas operativos"""
        self.logger.info("🖥️ DETECTANDO SISTEMAS OPERATIVOS")
        
        os_results = []
        
        for host in hosts[:20]:  # Limitar a 20 hosts para velocidad
            ip = host['ip']
            
            # Detección rápida de OS
            os_info = self._quick_os_detection(ip)
            if os_info:
                os_results.append({
                    'ip': ip,
                    'os': os_info['os'],
                    'version': os_info.get('version', 'Unknown'),
                    'confidence': os_info.get('confidence', 0),
                    'timestamp': time.time()
                })
        
        return os_results
    
    def scan_critical_services(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Escaneo rápido de servicios críticos"""
        self.logger.info("🔍 ESCANEANDO SERVICIOS CRÍTICOS")
        
        # Puertos críticos a escanear
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
        
        services = []
        
        for host in hosts[:15]:  # Limitar a 15 hosts
            ip = host['ip']
            
            # Escaneo rápido de puertos críticos
            for port in critical_ports:
                if self._is_port_open(ip, port, timeout=1):
                    service_info = self._identify_service(ip, port)
                    services.append({
                        'host': ip,
                        'port': port,
                        'service': service_info.get('service', 'unknown'),
                        'version': service_info.get('version', ''),
                        'banner': service_info.get('banner', ''),
                        'timestamp': time.time()
                    })
        
        return services
    
    def map_network_topology(self, hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Mapeo rápido de topología de red"""
        self.logger.info("🗺️ MAPEANDO TOPOLOGÍA DE RED")
        
        topology = {
            'network_segments': [],
            'routing_info': [],
            'gateway_info': {},
            'dns_servers': [],
            'timestamp': time.time()
        }
        
        # Detectar segmentos de red
        network_segments = {}
        for host in hosts:
            ip = ipaddress.ip_address(host['ip'])
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            network_str = str(network)
            
            if network_str not in network_segments:
                network_segments[network_str] = {
                    'network': network_str,
                    'hosts': [],
                    'gateway': None
                }
            
            network_segments[network_str]['hosts'].append(host)
        
        topology['network_segments'] = list(network_segments.values())
        
        # Detectar gateway
        if self.router_ip:
            topology['gateway_info'] = {
                'ip': self.router_ip,
                'type': 'router',
                'timestamp': time.time()
            }
        
        return topology
    
    def detect_specific_devices(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detección de dispositivos específicos (IoT, impresoras, etc.)"""
        self.logger.info("📱 DETECTANDO DISPOSITIVOS ESPECÍFICOS")
        
        devices = []
        
        for host in hosts:
            device_type = self._detect_device_type(host)
            if device_type != 'unknown':
                devices.append({
                    'ip': host['ip'],
                    'type': device_type,
                    'vendor': host.get('vendor', 'Unknown'),
                    'mac': host.get('mac', ''),
                    'timestamp': time.time()
                })
        
        return devices
    
    def enumerate_critical_services(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enumeración rápida de servicios críticos"""
        self.logger.info("🔍 ENUMERANDO SERVICIOS CRÍTICOS")
        
        enumeration_results = []
        
        for service in services:
            if service['port'] in [80, 443, 8080]:  # HTTP/HTTPS
                web_info = self._enumerate_web_service(service['host'], service['port'])
                if web_info:
                    enumeration_results.append(web_info)
            
            elif service['port'] == 445:  # SMB
                smb_info = self._enumerate_smb_service(service['host'])
                if smb_info:
                    enumeration_results.append(smb_info)
            
            elif service['port'] == 22:  # SSH
                ssh_info = self._enumerate_ssh_service(service['host'])
                if ssh_info:
                    enumeration_results.append(ssh_info)
        
        return enumeration_results
    
    def generate_network_map(self, hosts: List[Dict[str, Any]], topology: Dict[str, Any], os_results: List[Dict[str, Any]]) -> None:
        """Generar mapa visual de la red"""
        self.logger.info("🗺️ GENERANDO MAPA DE RED")
        
        # Crear archivo de mapa de red
        map_file = self.evidence_dir / "network_map.txt"
        
        with open(map_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("MAPA DE RED - RECONOCIMIENTO AVANZADO\n")
            f.write("=" * 60 + "\n\n")
            
            # Información de red
            f.write("INFORMACIÓN DE RED:\n")
            f.write(f"Red objetivo: {self.network_config.get('target_network', 'No configurada')}\n")
            f.write(f"Router: {self.router_ip or 'No detectado'}\n")
            f.write(f"IP pública: {self.public_ip or 'No detectada'}\n\n")
            
            # Segmentos de red
            f.write("SEGMENTOS DE RED:\n")
            for segment in topology.get('network_segments', []):
                f.write(f"  {segment['network']}: {len(segment['hosts'])} hosts\n")
            f.write("\n")
            
            # Hosts por tipo
            f.write("HOSTS POR TIPO:\n")
            device_types = {}
            for host in hosts:
                device_type = host.get('device_type', 'unknown')
                if device_type not in device_types:
                    device_types[device_type] = []
                device_types[device_type].append(host['ip'])
            
            for device_type, ips in device_types.items():
                f.write(f"  {device_type.upper()}: {', '.join(ips)}\n")
            f.write("\n")
            
            # Sistemas operativos
            f.write("SISTEMAS OPERATIVOS:\n")
            for os_info in os_results:
                f.write(f"  {os_info['ip']}: {os_info['os']} {os_info.get('version', '')}\n")
            f.write("\n")
            
            # Topología
            f.write("TOPOLOGÍA:\n")
            f.write(f"  Gateway: {topology.get('gateway_info', {}).get('ip', 'No detectado')}\n")
            f.write(f"  Segmentos: {len(topology.get('network_segments', []))}\n")
        
        self.logger.info(f"✅ Mapa de red guardado en: {map_file}")
    
    def _arp_scan_fast(self) -> List[Dict[str, Any]]:
        """ARP scan rápido"""
        hosts = []
        try:
            result = self._run_command(['arp-scan', '--local', '--quiet'], timeout=10)
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            hosts.append({
                                'ip': parts[0],
                                'mac': parts[1],
                                'vendor': parts[2],
                                'discovery_method': 'arp_scan',
                                'timestamp': time.time()
                            })
        except:
            pass
        return hosts
    
    def _ping_sweep_fast(self) -> List[Dict[str, Any]]:
        """Ping sweep rápido"""
        hosts = []
        try:
            target_network = self.network_config.get('target_network', '192.168.1.0/24')
            result = self._run_command(['nmap', '-sn', target_network], timeout=30)
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if 'Nmap scan report for' in line:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            hosts.append({
                                'ip': ip_match.group(1),
                                'discovery_method': 'nmap_ping',
                                'timestamp': time.time()
                            })
        except:
            pass
        return hosts
    
    def _detect_architecture(self, ip: str) -> str:
        """Detectar arquitectura del sistema"""
        try:
            # Ping con diferentes tamaños de paquete para detectar arquitectura
            result = self._run_command(['ping', '-c', '1', '-s', '1500', ip], timeout=2)
            if result['success']:
                return 'x86_64'  # Asumir x86_64 si responde a paquetes grandes
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    def _detect_os_family(self, ip: str) -> str:
        """Detectar familia de sistema operativo"""
        try:
            # TTL analysis para detectar OS
            result = self._run_command(['ping', '-c', '1', ip], timeout=2)
            if result['success'] and 'ttl=' in result['stdout'].lower():
                ttl_match = re.search(r'ttl=(\d+)', result['stdout'].lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if ttl <= 64:
                        return 'Linux'
                    elif ttl <= 128:
                        return 'Windows'
                    elif ttl <= 255:
                        return 'Unix'
            return 'unknown'
        except:
            return 'unknown'
    
    def _detect_device_type(self, host: Dict[str, Any]) -> str:
        """Detectar tipo de dispositivo"""
        vendor = host.get('vendor', '').lower()
        mac = host.get('mac', '').lower()
        
        # Detectar por vendor
        if 'huawei' in vendor:
            return 'router'
        elif 'hewlett' in vendor or 'hp' in vendor:
            return 'server'
        elif 'ezviz' in vendor:
            return 'camera'
        elif 'intelbras' in vendor:
            return 'iot_device'
        
        # Detectar por MAC OUI
        if mac.startswith('c4:5e:5c'):
            return 'router'
        elif mac.startswith('c4:34:6b'):
            return 'server'
        elif mac.startswith('64:51:06'):
            return 'server'
        
        return 'unknown'
    
    def _quick_os_detection(self, ip: str) -> Optional[Dict[str, Any]]:
        """Detección rápida de sistema operativo"""
        try:
            # Usar nmap para detección rápida de OS
            result = self._run_command(['nmap', '-O', '--osscan-limit', ip], timeout=10)
            
            if result['success']:
                output = result['stdout']
                
                # Parsear resultado de nmap
                if 'Running:' in output:
                    os_match = re.search(r'Running: (.+)', output)
                    if os_match:
                        os_info = os_match.group(1)
                        return {
                            'os': os_info,
                            'confidence': 80,
                            'method': 'nmap'
                        }
            
            return None
        except:
            return None
    
    def _is_port_open(self, ip: str, port: int, timeout: int = 1) -> bool:
        """Verificar si un puerto está abierto"""
        try:
            result = self._run_command(['nc', '-z', '-w', str(timeout), ip, str(port)], timeout=timeout+1)
            return result['success']
        except:
            return False
    
    def _identify_service(self, ip: str, port: int) -> Dict[str, str]:
        """Identificar servicio en puerto"""
        try:
            result = self._run_command(['nmap', '-sV', '-p', str(port), ip], timeout=5)
            
            if result['success']:
                output = result['stdout']
                
                # Parsear información del servicio
                service_info = {'service': 'unknown', 'version': '', 'banner': ''}
                
                if 'open' in output:
                    # Extraer nombre del servicio
                    service_match = re.search(r'(\d+)/tcp\s+open\s+(\w+)', output)
                    if service_match:
                        service_info['service'] = service_match.group(2)
                    
                    # Extraer versión
                    version_match = re.search(r'(\d+)/tcp\s+open\s+\w+\s+(.+)', output)
                    if version_match:
                        service_info['version'] = version_match.group(2)
                
                return service_info
            
            return {'service': 'unknown', 'version': '', 'banner': ''}
        except:
            return {'service': 'unknown', 'version': '', 'banner': ''}
    
    def _enumerate_web_service(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Enumerar servicio web"""
        try:
            result = self._run_command(['curl', '-s', '-I', f'http://{ip}:{port}'], timeout=3)
            
            if result['success']:
                headers = result['stdout']
                
                web_info = {
                    'host': ip,
                    'port': port,
                    'type': 'web',
                    'server': 'unknown',
                    'technologies': [],
                    'timestamp': time.time()
                }
                
                # Extraer servidor web
                server_match = re.search(r'Server:\s*(.+)', headers, re.IGNORECASE)
                if server_match:
                    web_info['server'] = server_match.group(1).strip()
                
                return web_info
            
            return None
        except:
            return None
    
    def _enumerate_smb_service(self, ip: str) -> Optional[Dict[str, Any]]:
        """Enumerar servicio SMB"""
        try:
            result = self._run_command(['smbclient', '-L', ip, '-N'], timeout=5)
            
            if result['success']:
                smb_info = {
                    'host': ip,
                    'port': 445,
                    'type': 'smb',
                    'shares': [],
                    'timestamp': time.time()
                }
                
                # Parsear shares
                shares = []
                for line in result['stdout'].split('\n'):
                    if 'Disk' in line or 'IPC' in line:
                        share_match = re.search(r'(\w+)\s+(Disk|IPC)', line)
                        if share_match:
                            shares.append(share_match.group(1))
                
                smb_info['shares'] = shares
                return smb_info
            
            return None
        except:
            return None
    
    def _enumerate_ssh_service(self, ip: str) -> Optional[Dict[str, Any]]:
        """Enumerar servicio SSH"""
        try:
            result = self._run_command(['ssh', '-o', 'ConnectTimeout=3', '-o', 'BatchMode=yes', ip], timeout=5)
            
            ssh_info = {
                'host': ip,
                'port': 22,
                'type': 'ssh',
                'version': 'unknown',
                'timestamp': time.time()
            }
            
            # Extraer versión SSH
            if 'OpenSSH' in result['stderr']:
                version_match = re.search(r'OpenSSH_([\d.]+)', result['stderr'])
                if version_match:
                    ssh_info['version'] = f"OpenSSH {version_match.group(1)}"
            
            return ssh_info
        except:
            return None
    
    def _discover_router(self) -> Optional[str]:
        """Descubrir automáticamente la IP del router"""
        try:
            # Método 1: Usar ip route
            result = self._run_command(['ip', 'route', 'show', 'default'])
            if result['success']:
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result['stdout'])
                if match:
                    return match.group(1)
            
            # Método 2: Usar netstat
            result = self._run_command(['netstat', '-rn'])
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if '0.0.0.0' in line and 'UG' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            
            return None
        except:
            return None
    
    def _get_public_ip(self) -> Optional[str]:
        """Obtener IP pública"""
        try:
            result = self._run_command(['curl', '-s', 'ifconfig.me'], timeout=5)
            if result['success'] and result['stdout'].strip():
                return result['stdout'].strip()
            
            result = self._run_command(['curl', '-s', 'ipinfo.io/ip'], timeout=5)
            if result['success'] and result['stdout'].strip():
                return result['stdout'].strip()
            
            return None
        except:
            return None
    
    def _run_command(self, command: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Ejecutar comando y capturar salida"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'stdout': '', 'stderr': 'Timeout', 'return_code': -1}
        except Exception as e:
            return {'success': False, 'stdout': '', 'stderr': str(e), 'return_code': -1}
    
    def _save_evidence(self) -> None:
        """Guardar evidencia del reconocimiento avanzado"""
        evidence_file = self.evidence_dir / "advanced_reconnaissance_results.json"
        
        with open(evidence_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        self.logger.info(f"✅ Evidencia guardada en: {evidence_file}")
