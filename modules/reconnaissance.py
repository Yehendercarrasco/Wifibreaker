"""
Módulo de Reconocimiento para Automatización de Pentesting
Incluye escaneo de red, descubrimiento de hosts y servicios
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

class ReconnaissanceModule:
    """Módulo de reconocimiento de red y sistemas"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.network_config = config['network_config']
        self.targets_config = config['targets']
        self.logging_system = LoggingSystem(config, logger)
        
        # Resultados del reconocimiento
        self.results = {
            'hosts': [],
            'services': [],
            'network_info': {},
            'routes': [],
            'vulnerabilities': []
        }
        
        # Obtener IP del router automáticamente
        self.router_ip = self._discover_router()
        if self.router_ip:
            self.network_config['router_ip'] = self.router_ip
            self.logger.info(f"🎯 Router descubierto: {self.router_ip}")
    
    def _discover_router(self) -> Optional[str]:
        """Descubrir automáticamente la IP del router"""
        try:
            # Intentar obtener la puerta de enlace por defecto
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Buscar la IP de la puerta de enlace
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    router_ip = match.group(1)
                    self.logging_system.log_discovery(
                        "ROUTER", router_ip, {"method": "ip_route"}, "RECONNAISSANCE"
                    )
                    return router_ip
            
            # Método alternativo usando netstat
            result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and 'UG' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            router_ip = parts[1]
                            self.logging_system.log_discovery(
                                "ROUTER", router_ip, {"method": "netstat"}, "RECONNAISSANCE"
                            )
                            return router_ip
            
            self.logger.warning("⚠️  No se pudo descubrir automáticamente la IP del router")
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Error al descubrir router: {e}")
            return None
    
    def _run_command(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Ejecutar comando y capturar salida"""
        try:
            self.logger.debug(f"🔧 Ejecutando: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            # Log del comando
            self.logging_system.log_command(
                ' '.join(command),
                result.stdout + result.stderr,
                result.returncode,
                "RECONNAISSANCE"
            )
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"⏰ Timeout ejecutando: {' '.join(command)}")
            return {'stdout': '', 'stderr': 'Timeout', 'return_code': -1, 'success': False}
        except Exception as e:
            self.logger.error(f"❌ Error ejecutando comando: {e}")
            return {'stdout': '', 'stderr': str(e), 'return_code': -1, 'success': False}
    
    def discover_network_info(self) -> Dict[str, Any]:
        """Descubrir información básica de la red"""
        self.logger.info("🔍 Descubriendo información de red...")
        
        network_info = {
            'interface': self.network_config.get('interface', 'eth0'),
            'target_network': self.network_config['target_network'],
            'router_ip': self.router_ip,
            'dns_servers': self.network_config.get('dns_servers', []),
            'local_ip': None,
            'subnet_mask': None
        }
        
        # Obtener IP local
        try:
            result = self._run_command(['hostname', '-I'])
            if result['success']:
                local_ips = result['stdout'].strip().split()
                network_info['local_ip'] = local_ips[0] if local_ips else None
        except Exception as e:
            self.logger.error(f"Error obteniendo IP local: {e}")
        
        # Obtener información de la interfaz
        try:
            interface = network_info['interface']
            result = self._run_command(['ip', 'addr', 'show', interface])
            if result['success']:
                # Parsear información de la interfaz
                lines = result['stdout'].split('\n')
                for line in lines:
                    if 'inet ' in line and not '127.0.0.1' in line:
                        # Extraer IP y máscara
                        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                        if match:
                            network_info['local_ip'] = match.group(1)
                            network_info['subnet_mask'] = match.group(2)
                            break
        except Exception as e:
            self.logger.error(f"Error obteniendo info de interfaz: {e}")
        
        self.results['network_info'] = network_info
        self.logging_system.log_discovery(
            "NETWORK_INFO", network_info['target_network'], network_info, "RECONNAISSANCE"
        )
        
        return network_info
    
    def arp_scan(self) -> List[Dict[str, Any]]:
        """Realizar escaneo ARP para descubrir hosts activos"""
        self.logger.info("🔍 Ejecutando escaneo ARP...")
        
        hosts = []
        target_network = self.network_config['target_network']
        
        try:
            # Ejecutar arp-scan
            result = self._run_command(['arp-scan', '--localnet', '--quiet'], timeout=60)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    # Parsear línea de arp-scan
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].count('.') == 3:
                        ip = parts[0]
                        mac = parts[1]
                        vendor = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                        
                        host = {
                            'ip': ip,
                            'mac': mac,
                            'vendor': vendor,
                            'discovery_method': 'arp_scan',
                            'timestamp': time.time()
                        }
                        
                        hosts.append(host)
                        self.logging_system.log_discovery(
                            "HOST", ip, host, "RECONNAISSANCE"
                        )
            
            self.logger.info(f"✅ ARP scan completado: {len(hosts)} hosts descubiertos")
            
        except Exception as e:
            self.logger.error(f"❌ Error en ARP scan: {e}")
        
        return hosts
    
    def nmap_ping_scan(self) -> List[Dict[str, Any]]:
        """Realizar escaneo de ping con nmap"""
        self.logger.info("🔍 Ejecutando escaneo de ping con nmap...")
        
        hosts = []
        target_network = self.network_config['target_network']
        
        try:
            # Escaneo de ping
            result = self._run_command([
                'nmap', '-sn', target_network, '--max-retries', '1', '--host-timeout', '30s'
            ], timeout=300)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                current_host = None
                
                for line in lines:
                    line = line.strip()
                    
                    # Detectar inicio de host
                    if line.startswith('Nmap scan report for'):
                        if current_host:
                            hosts.append(current_host)
                        
                        # Extraer IP del reporte
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            ip = match.group(1)
                            current_host = {
                                'ip': ip,
                                'discovery_method': 'nmap_ping',
                                'timestamp': time.time(),
                                'hostname': None,
                                'mac': None,
                                'vendor': None
                            }
                    
                    # Detectar MAC address
                    elif 'MAC Address:' in line and current_host:
                        match = re.search(r'MAC Address: ([A-Fa-f0-9:]+) \((.+)\)', line)
                        if match:
                            current_host['mac'] = match.group(1)
                            current_host['vendor'] = match.group(2)
                
                # Agregar último host
                if current_host:
                    hosts.append(current_host)
            
            self.logger.info(f"✅ Nmap ping scan completado: {len(hosts)} hosts descubiertos")
            
        except Exception as e:
            self.logger.error(f"❌ Error en nmap ping scan: {e}")
        
        return hosts
    
    def nmap_port_scan(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """Realizar escaneo de puertos con nmap"""
        self.logger.info(f"🔍 Escaneando puertos en {len(hosts)} hosts...")
        
        services = []
        common_ports = self.targets_config.get('common_ports', [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3389, 5432, 5900, 8080])
        
        # Convertir lista de puertos a string
        ports_str = ','.join(map(str, common_ports))
        
        try:
            # Escaneo de puertos en hosts específicos
            host_list = ' '.join(hosts)
            result = self._run_command([
                'nmap', '-sS', '-p', ports_str, '--open', '--max-retries', '2',
                '--host-timeout', '60s', host_list
            ], timeout=600)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                current_host = None
                
                for line in lines:
                    line = line.strip()
                    
                    # Detectar inicio de host
                    if line.startswith('Nmap scan report for'):
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            current_host = match.group(1)
                    
                    # Detectar puertos abiertos
                    elif '/tcp' in line and 'open' in line and current_host:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_info = parts[0].split('/')
                            port = int(port_info[0])
                            protocol = port_info[1]
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            
                            service_info = {
                                'host': current_host,
                                'port': port,
                                'protocol': protocol,
                                'state': state,
                                'service': service,
                                'discovery_method': 'nmap_port_scan',
                                'timestamp': time.time()
                            }
                            
                            services.append(service_info)
                            self.logging_system.log_discovery(
                                "SERVICE", f"{current_host}:{port}", service_info, "RECONNAISSANCE"
                            )
            
            self.logger.info(f"✅ Escaneo de puertos completado: {len(services)} servicios encontrados")
            
        except Exception as e:
            self.logger.error(f"❌ Error en escaneo de puertos: {e}")
        
        return services
    
    def masscan_scan(self) -> List[Dict[str, Any]]:
        """Realizar escaneo rápido con masscan"""
        self.logger.info("🔍 Ejecutando escaneo rápido con masscan...")
        
        services = []
        target_network = self.network_config['target_network']
        scan_rate = self.network_config.get('scan_rate', 10000)
        
        try:
            # Escaneo con masscan
            result = self._run_command([
                'masscan', '-p0-65535', target_network, f'--rate={scan_rate}'
            ], timeout=300)
            
            if result['success']:
                lines = result['stdout'].split('\n')
                for line in lines:
                    line = line.strip()
                    if 'open' in line and 'tcp' in line:
                        # Parsear línea de masscan
                        parts = line.split()
                        if len(parts) >= 4:
                            timestamp = parts[0]
                            ip = parts[3]
                            port_info = parts[2].split('/')
                            port = int(port_info[0])
                            protocol = port_info[1]
                            
                            service_info = {
                                'host': ip,
                                'port': port,
                                'protocol': protocol,
                                'state': 'open',
                                'service': 'unknown',
                                'discovery_method': 'masscan',
                                'timestamp': time.time()
                            }
                            
                            services.append(service_info)
                            self.logging_system.log_discovery(
                                "SERVICE", f"{ip}:{port}", service_info, "RECONNAISSANCE"
                            )
            
            self.logger.info(f"✅ Masscan completado: {len(services)} servicios encontrados")
            
        except Exception as e:
            self.logger.error(f"❌ Error en masscan: {e}")
        
        return services
    
    def traceroute_scan(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Realizar traceroute a objetivos específicos"""
        self.logger.info(f"🔍 Ejecutando traceroute a {len(targets)} objetivos...")
        
        routes = []
        
        for target in targets:
            try:
                result = self._run_command(['traceroute', '-n', target], timeout=120)
                
                if result['success']:
                    route_info = {
                        'target': target,
                        'hops': [],
                        'discovery_method': 'traceroute',
                        'timestamp': time.time()
                    }
                    
                    lines = result['stdout'].split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('traceroute'):
                            # Parsear hop
                            parts = line.split()
                            if len(parts) >= 2:
                                hop_num = parts[0]
                                hop_ip = parts[1]
                                if hop_ip != '*':
                                    route_info['hops'].append({
                                        'hop': int(hop_num),
                                        'ip': hop_ip
                                    })
                    
                    routes.append(route_info)
                    self.logging_system.log_discovery(
                        "ROUTE", target, route_info, "RECONNAISSANCE"
                    )
                
            except Exception as e:
                self.logger.error(f"❌ Error en traceroute a {target}: {e}")
        
        return routes
    
    def service_enumeration(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enumerar servicios específicos para obtener más información"""
        self.logger.info("🔍 Enumerando servicios...")
        
        enumerated_services = []
        
        for service in services:
            host = service['host']
            port = service['port']
            service_name = service['service']
            
            # Enumeración específica por servicio
            if service_name in ['http', 'https']:
                enumerated_service = self._enumerate_web_service(host, port, service_name)
            elif service_name in ['smb', 'netbios-ssn']:
                enumerated_service = self._enumerate_smb_service(host, port)
            elif service_name == 'ssh':
                enumerated_service = self._enumerate_ssh_service(host, port)
            elif service_name == 'ftp':
                enumerated_service = self._enumerate_ftp_service(host, port)
            else:
                enumerated_service = service.copy()
            
            enumerated_services.append(enumerated_service)
        
        return enumerated_services
    
    def _enumerate_web_service(self, host: str, port: int, service: str) -> Dict[str, Any]:
        """Enumerar servicio web"""
        service_info = {
            'host': host,
            'port': port,
            'service': service,
            'discovery_method': 'nmap_port_scan',
            'timestamp': time.time(),
            'enumeration': {}
        }
        
        try:
            # Detectar tecnologías web
            result = self._run_command(['whatweb', f'{host}:{port}'], timeout=30)
            if result['success']:
                service_info['enumeration']['technologies'] = result['stdout']
            
            # Detectar directorios
            result = self._run_command(['dirb', f'http://{host}:{port}', '/usr/share/wordlists/dirb/common.txt'], timeout=60)
            if result['success']:
                service_info['enumeration']['directories'] = result['stdout']
                
        except Exception as e:
            self.logger.debug(f"Error enumerando servicio web {host}:{port}: {e}")
        
        return service_info
    
    def _enumerate_smb_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enumerar servicio SMB"""
        service_info = {
            'host': host,
            'port': port,
            'service': 'smb',
            'discovery_method': 'nmap_port_scan',
            'timestamp': time.time(),
            'enumeration': {}
        }
        
        try:
            # Enumerar shares SMB
            result = self._run_command(['smbclient', '-L', f'//{host}', '-N'], timeout=30)
            if result['success']:
                service_info['enumeration']['shares'] = result['stdout']
            
            # Detectar versión SMB
            result = self._run_command(['smbclient', '--version'], timeout=10)
            if result['success']:
                service_info['enumeration']['smb_version'] = result['stdout']
                
        except Exception as e:
            self.logger.debug(f"Error enumerando SMB {host}:{port}: {e}")
        
        return service_info
    
    def _enumerate_ssh_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enumerar servicio SSH"""
        service_info = {
            'host': host,
            'port': port,
            'service': 'ssh',
            'discovery_method': 'nmap_port_scan',
            'timestamp': time.time(),
            'enumeration': {}
        }
        
        try:
            # Detectar versión SSH
            result = self._run_command(['ssh', '-V'], timeout=10)
            if result['success']:
                service_info['enumeration']['ssh_version'] = result['stdout']
                
        except Exception as e:
            self.logger.debug(f"Error enumerando SSH {host}:{port}: {e}")
        
        return service_info
    
    def _enumerate_ftp_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enumerar servicio FTP"""
        service_info = {
            'host': host,
            'port': port,
            'service': 'ftp',
            'discovery_method': 'nmap_port_scan',
            'timestamp': time.time(),
            'enumeration': {}
        }
        
        try:
            # Intentar conexión FTP anónima
            result = self._run_command(['ftp', '-n', host], timeout=30)
            if result['success']:
                service_info['enumeration']['ftp_info'] = result['stdout']
                
        except Exception as e:
            self.logger.debug(f"Error enumerando FTP {host}:{port}: {e}")
        
        return service_info
    
    def run(self) -> Dict[str, Any]:
        """Ejecutar módulo completo de reconocimiento"""
        self.logger.info("🚀 INICIANDO MÓDULO DE RECONOCIMIENTO")
        
        start_time = time.time()
        
        try:
            # 1. Descubrir información de red
            network_info = self.discover_network_info()
            
            # 2. Descubrir hosts activos
            self.logger.info("📡 Descubriendo hosts activos...")
            arp_hosts = self.arp_scan()
            nmap_hosts = self.nmap_ping_scan()
            
            # Combinar hosts únicos
            all_hosts = {}
            for host in arp_hosts + nmap_hosts:
                ip = host['ip']
                if ip not in all_hosts:
                    all_hosts[ip] = host
                else:
                    # Combinar información
                    all_hosts[ip].update(host)
            
            hosts_list = list(all_hosts.values())
            self.results['hosts'] = hosts_list
            
            # 3. Escanear puertos en hosts descubiertos
            if hosts_list:
                host_ips = [host['ip'] for host in hosts_list]
                
                # Escaneo de puertos con nmap
                nmap_services = self.nmap_port_scan(host_ips)
                
                # Escaneo rápido con masscan
                masscan_services = self.masscan_scan()
                
                # Combinar servicios únicos
                all_services = {}
                for service in nmap_services + masscan_services:
                    key = f"{service['host']}:{service['port']}"
                    if key not in all_services:
                        all_services[key] = service
                    else:
                        all_services[key].update(service)
                
                services_list = list(all_services.values())
                
                # 4. Enumerar servicios
                enumerated_services = self.service_enumeration(services_list)
                self.results['services'] = enumerated_services
            
            # 5. Traceroute a objetivos importantes
            important_targets = [self.router_ip] if self.router_ip else []
            if important_targets:
                routes = self.traceroute_scan(important_targets)
                self.results['routes'] = routes
            
            # 6. Guardar evidencia
            self.logging_system.save_json_evidence(
                'reconnaissance_results.json',
                self.results,
                'data'
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ RECONOCIMIENTO COMPLETADO en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {len(hosts_list)} hosts, {len(self.results['services'])} servicios")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en módulo de reconocimiento: {e}")
            return self.results
