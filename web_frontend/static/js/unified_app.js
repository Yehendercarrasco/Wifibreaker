/**
 * Frontend Unificado para Pentest Report Viewer
 * Muestra datos del JSON unificado
 */

let currentScan = null;

// Inicializar aplicación
document.addEventListener('DOMContentLoaded', function() {
    loadScans();
});

// Cargar lista de escaneos
async function loadScans() {
    try {
        const response = await fetch('/api/scans');
        const scans = await response.json();
        
        displayScansList(scans);
    } catch (error) {
        console.error('Error cargando escaneos:', error);
        document.getElementById('scansList').innerHTML = '<p>Error cargando escaneos</p>';
    }
}

// Mostrar lista de escaneos
function displayScansList(scans) {
    const scansList = document.getElementById('scansList');
    
    if (!scans || scans.length === 0) {
        scansList.innerHTML = '<p>No hay escaneos disponibles</p>';
        return;
    }
    
    let html = '<div class="scans-grid">';
    
    scans.forEach(scan => {
        const statusClass = getStatusClass(scan.status);
        const statusText = getStatusText(scan.status);
        const coldIcon = scan.is_cold_pentest ? '🧊' : '🔥';
        const coldText = scan.is_cold_pentest ? 'Pentest Frío' : 'Pentest Normal';
        
        html += `
            <div class="scan-card" onclick="loadScanDetails('${scan.mote}')">
                <div class="scan-card-header">
                    <h3>${coldIcon} ${scan.mote}</h3>
                    <span class="scan-status ${statusClass}">${statusText}</span>
                </div>
                <div class="scan-card-body">
                    <div class="scan-info">
                        <div class="info-item">
                            <span class="label">📅 Fecha:</span>
                            <span class="value">${formatDate(scan.created_at)}</span>
                        </div>
                        <div class="info-item">
                            <div class="label">🎯 Red:</div>
                            <div class="value">${scan.target_network || 'No especificada'}</div>
                        </div>
                        <div class="info-item">
                            <div class="label">📊 Fases:</div>
                            <div class="value">${scan.phases_completed ? scan.phases_completed.length : 0} completadas</div>
                        </div>
                        <div class="info-item">
                            <div class="label">🏷️ Tipo:</div>
                            <div class="value">${coldText}</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    scansList.innerHTML = html;
}

// Cargar detalles de un escaneo
async function loadScanDetails(scanId) {
    try {
        const response = await fetch(`/api/scans/${scanId}`);
        const scan = await response.json();
        
        if (scan.error) {
            alert('Error: ' + scan.error);
            return;
        }
        
        currentScan = scan;
        displayScanDetails(scan);
        
        // Mostrar sección de detalles
        document.getElementById('scansList').style.display = 'none';
        document.getElementById('scanDetails').style.display = 'block';
        
    } catch (error) {
        console.error('Error cargando detalles del escaneo:', error);
        alert('Error cargando detalles del escaneo');
    }
}

// Mostrar detalles del escaneo
function displayScanDetails(scan) {
    const detailsContainer = document.getElementById('scanDetails');
    
    if (!scan || !scan.scan_info) {
        detailsContainer.innerHTML = '<p>No hay datos disponibles para este escaneo.</p>';
        return;
    }
    
    const scanInfo = scan.scan_info;
    const scanData = scan.scan_data || {};
    
    let html = `
        <div class="scan-header">
            <button class="back-button" onclick="showScansList()">← Volver a Escaneos</button>
            <h2>${scanInfo.mote || 'Escaneo sin nombre'}</h2>
            <div class="scan-meta">
                <span class="scan-date">📅 ${formatDate(scanInfo.created_at)}</span>
                <span class="scan-status status-${scanInfo.status}">${scanInfo.status}</span>
                ${scanInfo.is_cold_pentest ? '<span class="cold-pentest">🧊 Pentest Frío</span>' : ''}
            </div>
        </div>
        
        <div class="scan-summary">
            <h3>📊 Resumen del Escaneo</h3>
            <div class="summary-grid">
                <div class="summary-item">
                    <span class="label">Fases Completadas:</span>
                    <span class="value">${scanInfo.phases_completed ? scanInfo.phases_completed.length : 0}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Red Objetivo:</span>
                    <span class="value">${scanInfo.target_network || 'No especificada'}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Dispositivos Encontrados:</span>
                    <span class="value">${scanData.network_map ? scanData.network_map.devices.length : 0}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Credenciales Capturadas:</span>
                    <span class="value">${scanData.credentials ? scanData.credentials.captured_passwords.length : 0}</span>
                </div>
            </div>
        </div>
    `;
    
    // Mostrar mapa de red
    if (scanData.network_map) {
        html += displayNetworkMap(scanData.network_map);
    }
    
    // Mostrar credenciales
    if (scanData.credentials) {
        html += displayCredentials(scanData.credentials);
    }
    
    // Mostrar persistencia
    if (scanData.persistence) {
        html += displayPersistence(scanData.persistence);
    }
    
    // Mostrar conexiones
    if (scanData.connections) {
        html += displayConnections(scanData.connections);
    }
    
    // Mostrar sistemas comprometidos
    if (scanData.compromised_systems) {
        html += displayCompromisedSystems(scanData.compromised_systems);
    }
    
    // Mostrar dispositivos IoT
    if (scanData.iot_devices) {
        html += displayIoTDevices(scanData.iot_devices);
    }
    
    // Mostrar exfiltración
    if (scanData.exfiltration) {
        html += displayExfiltration(scanData.exfiltration);
    }
    
    // Mostrar configuración de servidores
    if (scanData.server_configs) {
        html += displayServerConfigs(scanData.server_configs);
    }
    
    detailsContainer.innerHTML = html;
}

// Mostrar mapa de red
function displayNetworkMap(networkMap) {
    let html = `
        <div class="section">
            <h3>🌐 Mapa de Red</h3>
            <div class="network-map">
    `;
    
    // IPs públicas
    if (networkMap.public_ips && networkMap.public_ips.length > 0) {
        html += `
            <div class="network-section">
                <h4>🌍 IPs Públicas</h4>
                <div class="ip-list">
        `;
        networkMap.public_ips.forEach(ip => {
            html += `<div class="ip-item public">${ip.ip} - ${ip.hostname || 'Sin hostname'}</div>`;
        });
        html += `</div></div>`;
    }
    
    // IPs privadas
    if (networkMap.private_ips && networkMap.private_ips.length > 0) {
        html += `
            <div class="network-section">
                <h4>🏠 IPs Privadas</h4>
                <div class="ip-list">
        `;
        networkMap.private_ips.forEach(ip => {
            html += `<div class="ip-item private">${ip.ip} - ${ip.hostname || 'Sin hostname'}</div>`;
        });
        html += `</div></div>`;
    }
    
    // Dispositivos
    if (networkMap.devices && networkMap.devices.length > 0) {
        html += `
            <div class="network-section">
                <h4>💻 Dispositivos</h4>
                <div class="devices-grid">
        `;
        networkMap.devices.forEach(device => {
            html += `
                <div class="device-card">
                    <div class="device-header">
                        <strong>${device.ip}</strong>
                        <span class="device-os">${device.os || 'OS Desconocido'}</span>
                    </div>
                    <div class="device-info">
                        <div>Hostname: ${device.hostname || 'N/A'}</div>
                        <div>Vendor: ${device.vendor || 'N/A'}</div>
                        <div>Puertos: ${device.ports ? device.ports.length : 0}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    html += `</div></div>`;
    return html;
}

// Mostrar credenciales
function displayCredentials(credentials) {
    let html = `
        <div class="section">
            <h3>🔑 Credenciales Capturadas</h3>
            <div class="credentials-grid">
    `;
    
    // Contraseñas capturadas
    if (credentials.captured_passwords && credentials.captured_passwords.length > 0) {
        html += `
            <div class="credential-section">
                <h4>🎯 Contraseñas Capturadas</h4>
                <div class="credential-list">
        `;
        credentials.captured_passwords.forEach(cred => {
            html += `
                <div class="credential-item">
                    <div class="cred-header">
                        <strong>${cred.username}</strong>
                        <span class="cred-target">${cred.target}</span>
                    </div>
                    <div class="cred-info">
                        <div>Servicio: ${cred.service || 'N/A'}</div>
                        <div>Método: ${cred.method || 'N/A'}</div>
                        <div>Capturado: ${formatDate(cred.captured_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // Credenciales por defecto
    if (credentials.default_credentials && credentials.default_credentials.length > 0) {
        html += `
            <div class="credential-section">
                <h4>🔓 Credenciales por Defecto</h4>
                <div class="credential-list">
        `;
        credentials.default_credentials.forEach(cred => {
            html += `
                <div class="credential-item default">
                    <div class="cred-header">
                        <strong>${cred.username}</strong>
                        <span class="cred-target">${cred.target}</span>
                    </div>
                    <div class="cred-info">
                        <div>Servicio: ${cred.service || 'N/A'}</div>
                        <div>Método: ${cred.method || 'N/A'}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    html += `</div></div>`;
    return html;
}

// Mostrar persistencia
function displayPersistence(persistence) {
    let html = `
        <div class="section">
            <h3>🔒 Datos de Persistencia</h3>
            <div class="persistence-grid">
    `;
    
    // Backdoors
    if (persistence.backdoors && persistence.backdoors.length > 0) {
        html += `
            <div class="persistence-section">
                <h4>🚪 Backdoors</h4>
                <div class="backdoor-list">
        `;
        persistence.backdoors.forEach(backdoor => {
            html += `
                <div class="backdoor-item">
                    <div class="backdoor-header">
                        <strong>${backdoor.type}</strong>
                        <span class="backdoor-status ${backdoor.status}">${backdoor.status}</span>
                    </div>
                    <div class="backdoor-info">
                        <div>Host: ${backdoor.host}:${backdoor.port}</div>
                        <div>Usuario: ${backdoor.username}</div>
                        <div>Script: ${backdoor.access_script || 'N/A'}</div>
                        <div>Creado: ${formatDate(backdoor.created_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // Usuarios creados
    if (persistence.users_created && persistence.users_created.length > 0) {
        html += `
            <div class="persistence-section">
                <h4>👤 Usuarios Creados</h4>
                <div class="user-list">
        `;
        persistence.users_created.forEach(user => {
            html += `
                <div class="user-item">
                    <div class="user-header">
                        <strong>${user.username}</strong>
                        <span class="user-host">${user.host}</span>
                    </div>
                    <div class="user-info">
                        <div>Grupos: ${user.groups ? user.groups.join(', ') : 'N/A'}</div>
                        <div>Creado: ${formatDate(user.created_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // Servicios instalados
    if (persistence.services_installed && persistence.services_installed.length > 0) {
        html += `
            <div class="persistence-section">
                <h4>⚙️ Servicios Instalados</h4>
                <div class="service-list">
        `;
        persistence.services_installed.forEach(service => {
            html += `
                <div class="service-item">
                    <div class="service-header">
                        <strong>${service.name}</strong>
                        <span class="service-host">${service.host}:${service.port}</span>
                    </div>
                    <div class="service-info">
                        <div>Comando: ${service.command || 'N/A'}</div>
                        <div>Instalado: ${formatDate(service.created_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    html += `</div></div>`;
    return html;
}

// Mostrar conexiones
function displayConnections(connections) {
    let html = `
        <div class="section">
            <h3>🔗 Conexiones Establecidas</h3>
            <div class="connections-grid">
    `;
    
    // SSH
    if (connections.ssh_access && connections.ssh_access.length > 0) {
        html += `
            <div class="connection-section">
                <h4>🔐 Acceso SSH</h4>
                <div class="connection-list">
        `;
        connections.ssh_access.forEach(conn => {
            html += `
                <div class="connection-item ssh">
                    <div class="conn-header">
                        <strong>SSH</strong>
                        <span class="conn-status ${conn.status}">${conn.status}</span>
                    </div>
                    <div class="conn-info">
                        <div>Host: ${conn.host}:${conn.port}</div>
                        <div>Usuario: ${conn.username}</div>
                        <div>Método: ${conn.method || 'N/A'}</div>
                        <div>Establecido: ${formatDate(conn.established_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // RDP
    if (connections.rdp_access && connections.rdp_access.length > 0) {
        html += `
            <div class="connection-section">
                <h4>🖥️ Acceso RDP</h4>
                <div class="connection-list">
        `;
        connections.rdp_access.forEach(conn => {
            html += `
                <div class="connection-item rdp">
                    <div class="conn-header">
                        <strong>RDP</strong>
                        <span class="conn-status ${conn.status}">${conn.status}</span>
                    </div>
                    <div class="conn-info">
                        <div>Host: ${conn.host}:${conn.port}</div>
                        <div>Usuario: ${conn.username}</div>
                        <div>Método: ${conn.method || 'N/A'}</div>
                        <div>Establecido: ${formatDate(conn.established_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // Bases de datos
    if (connections.database_connections && connections.database_connections.length > 0) {
        html += `
            <div class="connection-section">
                <h4>🗄️ Conexiones de Base de Datos</h4>
                <div class="connection-list">
        `;
        connections.database_connections.forEach(conn => {
            html += `
                <div class="connection-item database">
                    <div class="conn-header">
                        <strong>DB</strong>
                        <span class="conn-status ${conn.status}">${conn.status}</span>
                    </div>
                    <div class="conn-info">
                        <div>Host: ${conn.host}:${conn.port}</div>
                        <div>Usuario: ${conn.username}</div>
                        <div>Método: ${conn.method || 'N/A'}</div>
                        <div>Establecido: ${formatDate(conn.established_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    html += `</div></div>`;
    return html;
}

// Mostrar sistemas comprometidos
function displayCompromisedSystems(compromisedSystems) {
    let html = `
        <div class="section">
            <h3>💻 Sistemas Comprometidos</h3>
            <div class="compromised-grid">
    `;
    
    if (compromisedSystems.lateral_movement && compromisedSystems.lateral_movement.length > 0) {
        compromisedSystems.lateral_movement.forEach(system => {
            html += `
                <div class="compromised-item">
                    <div class="compromised-header">
                        <strong>${system.host}</strong>
                        <span class="compromised-status ${system.status}">${system.status}</span>
                    </div>
                    <div class="compromised-info">
                        <div>IP: ${system.ip}</div>
                        <div>OS: ${system.os || 'N/A'}</div>
                        <div>Usuario: ${system.username}</div>
                        <div>Privilegios: ${system.privileges || 'N/A'}</div>
                        <div>Método: ${system.compromise_method || 'N/A'}</div>
                        <div>Comprometido: ${formatDate(system.compromised_at)}</div>
                    </div>
                </div>
            `;
        });
    }
    
    html += `</div></div>`;
    return html;
}

// Mostrar dispositivos IoT
function displayIoTDevices(iotDevices) {
    let html = `
        <div class="section">
            <h3>📱 Dispositivos IoT</h3>
            <div class="iot-grid">
    `;
    
    // Cámaras
    if (iotDevices.cameras && iotDevices.cameras.length > 0) {
        html += `
            <div class="iot-section">
                <h4>📹 Cámaras</h4>
                <div class="iot-list">
        `;
        iotDevices.cameras.forEach(camera => {
            html += `
                <div class="iot-item camera">
                    <div class="iot-header">
                        <strong>📹 ${camera.vendor} ${camera.model}</strong>
                        <span class="iot-status ${camera.status}">${camera.status}</span>
                    </div>
                    <div class="iot-info">
                        <div>IP: ${camera.ip}</div>
                        <div>Usuario: ${camera.username}</div>
                        <div>Método: ${camera.access_method || 'N/A'}</div>
                        <div>Comprometido: ${formatDate(camera.compromised_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // Routers
    if (iotDevices.routers && iotDevices.routers.length > 0) {
        html += `
            <div class="iot-section">
                <h4>🌐 Routers</h4>
                <div class="iot-list">
        `;
        iotDevices.routers.forEach(router => {
            html += `
                <div class="iot-item router">
                    <div class="iot-header">
                        <strong>🌐 ${router.vendor} ${router.model}</strong>
                        <span class="iot-status ${router.status}">${router.status}</span>
                    </div>
                    <div class="iot-info">
                        <div>IP: ${router.ip}</div>
                        <div>Usuario: ${router.username}</div>
                        <div>Método: ${router.access_method || 'N/A'}</div>
                        <div>Comprometido: ${formatDate(router.compromised_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // Otros dispositivos
    if (iotDevices.other_devices && iotDevices.other_devices.length > 0) {
        html += `
            <div class="iot-section">
                <h4>🔌 Otros Dispositivos</h4>
                <div class="iot-list">
        `;
        iotDevices.other_devices.forEach(device => {
            html += `
                <div class="iot-item other">
                    <div class="iot-header">
                        <strong>🔌 ${device.vendor} ${device.model}</strong>
                        <span class="iot-status ${device.status}">${device.status}</span>
                    </div>
                    <div class="iot-info">
                        <div>IP: ${device.ip}</div>
                        <div>Usuario: ${device.username}</div>
                        <div>Método: ${device.access_method || 'N/A'}</div>
                        <div>Comprometido: ${formatDate(device.compromised_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    html += `</div></div>`;
    return html;
}

// Mostrar exfiltración
function displayExfiltration(exfiltration) {
    let html = `
        <div class="section">
            <h3>📤 Datos de Exfiltración</h3>
            <div class="exfiltration-info">
                <div class="exfil-stats">
                    <div class="stat-item">
                        <span class="stat-label">Tamaño Total:</span>
                        <span class="stat-value">${formatBytes(exfiltration.data_size || 0)}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Archivos:</span>
                        <span class="stat-value">${exfiltration.files_count || 0}</span>
                    </div>
                </div>
    `;
    
    if (exfiltration.sensitive_data && exfiltration.sensitive_data.length > 0) {
        html += `
            <div class="sensitive-data">
                <h4>🔒 Datos Sensibles</h4>
                <div class="data-list">
        `;
        exfiltration.sensitive_data.forEach(data => {
            html += `
                <div class="data-item">
                    <div class="data-header">
                        <strong>${data.type}</strong>
                        <span class="data-size">${formatBytes(data.size)}</span>
                    </div>
                    <div class="data-info">
                        <div>Ubicación: ${data.location}</div>
                        <div>Exfiltrado: ${formatDate(data.exfiltrated_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    html += `</div></div>`;
    return html;
}

// Mostrar configuración de servidores
function displayServerConfigs(serverConfigs) {
    let html = `
        <div class="section">
            <h3>🖥️ Configuración de Servidores</h3>
            <div class="server-configs">
    `;
    
    // Servidores backdoor
    if (serverConfigs.backdoor_servers && serverConfigs.backdoor_servers.length > 0) {
        html += `
            <div class="server-section">
                <h4>🚪 Servidores Backdoor</h4>
                <div class="server-list">
        `;
        serverConfigs.backdoor_servers.forEach(server => {
            html += `
                <div class="server-item backdoor">
                    <div class="server-header">
                        <strong>${server.type}</strong>
                        <span class="server-protocol">${server.protocol}</span>
                    </div>
                    <div class="server-info">
                        <div>Host: ${server.host}:${server.port}</div>
                        <div>Configurado: ${formatDate(server.configured_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // Servidores de exfiltración
    if (serverConfigs.exfiltration_servers && serverConfigs.exfiltration_servers.length > 0) {
        html += `
            <div class="server-section">
                <h4>📤 Servidores de Exfiltración</h4>
                <div class="server-list">
        `;
        serverConfigs.exfiltration_servers.forEach(server => {
            html += `
                <div class="server-item exfiltration">
                    <div class="server-header">
                        <strong>${server.type}</strong>
                        <span class="server-protocol">${server.protocol}</span>
                    </div>
                    <div class="server-info">
                        <div>Host: ${server.host}:${server.port}</div>
                        <div>Configurado: ${formatDate(server.configured_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    // Servidores C2
    if (serverConfigs.c2_servers && serverConfigs.c2_servers.length > 0) {
        html += `
            <div class="server-section">
                <h4>🎯 Servidores C2</h4>
                <div class="server-list">
        `;
        serverConfigs.c2_servers.forEach(server => {
            html += `
                <div class="server-item c2">
                    <div class="server-header">
                        <strong>${server.type}</strong>
                        <span class="server-protocol">${server.protocol}</span>
                    </div>
                    <div class="server-info">
                        <div>Host: ${server.host}:${server.port}</div>
                        <div>Configurado: ${formatDate(server.configured_at)}</div>
                    </div>
                </div>
            `;
        });
        html += `</div></div>`;
    }
    
    html += `</div></div>`;
    return html;
}

// Volver a la lista de escaneos
function showScansList() {
    document.getElementById('scansList').style.display = 'block';
    document.getElementById('scanDetails').style.display = 'none';
    currentScan = null;
}

// Funciones auxiliares
function getStatusClass(status) {
    switch (status) {
        case 'completed': return 'completed';
        case 'in_progress': return 'in-progress';
        case 'failed': return 'failed';
        default: return 'unknown';
    }
}

function getStatusText(status) {
    switch (status) {
        case 'completed': return 'Completado';
        case 'in_progress': return 'En Progreso';
        case 'failed': return 'Fallido';
        default: return 'Desconocido';
    }
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleString('es-ES');
    } catch (error) {
        return dateString;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
