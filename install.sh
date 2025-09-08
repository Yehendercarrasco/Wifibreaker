#!/bin/bash

# Script de Instalación para el Sistema de Automatización de Pruebas de Penetración
# Autor: Sistema de Automatización
# Versión: 1.0

set -e  # Salir si hay algún error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Verificar si se ejecuta como root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "No ejecute este script como root. Use un usuario normal con sudo."
        exit 1
    fi
}

# Verificar sistema operativo
check_os() {
    print_header "Verificando Sistema Operativo"
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "No se pudo determinar el sistema operativo"
        exit 1
    fi
    
    print_message "Sistema operativo detectado: $OS $VER"
    
    # Verificar si es Kali Linux o Ubuntu/Debian
    if [[ "$OS" == *"Kali"* ]] || [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        print_message "Sistema operativo compatible detectado"
    else
        print_warning "Sistema operativo no probado. Continuando de todos modos..."
    fi
}

# Actualizar sistema
update_system() {
    print_header "Actualizando Sistema"
    
    print_message "Actualizando lista de paquetes..."
    sudo apt update
    
    print_message "Actualizando paquetes instalados..."
    sudo apt upgrade -y
    
    print_message "Instalando paquetes básicos..."
    sudo apt install -y curl wget git python3 python3-pip
}

# Instalar herramientas de pentesting
install_pentest_tools() {
    print_header "Instalando Herramientas de Pentesting"
    
    print_message "Instalando herramientas de escaneo..."
    sudo apt install -y nmap masscan arp-scan traceroute
    
    print_message "Instalando herramientas de ataque..."
    sudo apt install -y responder tcpdump hydra smbclient
    
    print_message "Instalando Metasploit Framework..."
    sudo apt install -y metasploit-framework
    
    print_message "Instalando herramientas adicionales..."
    sudo apt install -y netcat-openbsd crackmapexec whatweb dirb sshpass rdesktop
    
    print_message "Instalando herramientas de desarrollo..."
    sudo apt install -y build-essential libssl-dev libffi-dev python3-dev
}

# Instalar dependencias de Python
install_python_deps() {
    print_header "Instalando Dependencias de Python"
    
    print_message "Actualizando pip..."
    python3 -m pip install --upgrade pip
    
    print_message "Instalando dependencias opcionales..."
    python3 -m pip install --user requests paramiko cryptography psutil colorama tqdm
    
    print_message "Dependencias de Python instaladas"
}

# Configurar Metasploit
setup_metasploit() {
    print_header "Configurando Metasploit Framework"
    
    print_message "Inicializando base de datos de Metasploit..."
    sudo msfdb init
    
    print_message "Verificando configuración de Metasploit..."
    sudo msfconsole -q -x "db_status; exit"
    
    print_message "Metasploit configurado correctamente"
}

# Configurar permisos
setup_permissions() {
    print_header "Configurando Permisos"
    
    print_message "Configurando permisos para herramientas de red..."
    sudo usermod -aG wireshark $USER
    
    print_message "Configurando sudo sin contraseña para herramientas específicas..."
    echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/bin/masscan, /usr/bin/arp-scan, /usr/bin/traceroute" | sudo tee /etc/sudoers.d/pentest-tools
    
    print_message "Permisos configurados"
}

# Crear directorios necesarios
create_directories() {
    print_header "Creando Directorios"
    
    print_message "Creando directorios de escaneos..."
    mkdir -p scans/{logs,screenshots,data,credentials,lateral_movement,persistence,privilege_escalation,exfiltration}
    
    print_message "Creando directorios de reportes..."
    mkdir -p reports/phase_reports
    
    print_message "Creando directorios de configuración..."
    mkdir -p config
    
    print_message "Directorios creados"
}

# Configurar archivos de configuración
setup_config() {
    print_header "Configurando Archivos de Configuración"
    
    if [[ ! -f config.json ]]; then
        print_message "Archivo de configuración no encontrado. Creando uno por defecto..."
        # El archivo config.json ya existe del desarrollo anterior
        print_message "Archivo de configuración listo"
    else
        print_message "Archivo de configuración encontrado"
    fi
    
    print_message "Configurando permisos de archivos..."
    chmod +x pentest_automation.py
    chmod +x modules/*.py
    chmod +x install.sh
    
    print_message "Configuración completada"
}

# Verificar instalación
verify_installation() {
    print_header "Verificando Instalación"
    
    print_message "Verificando herramientas instaladas..."
    
    tools=("nmap" "masscan" "arp-scan" "traceroute" "responder" "tcpdump" "hydra" "smbclient" "msfconsole" "nc" "crackmapexec" "whatweb" "dirb" "sshpass" "rdesktop")
    
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            print_message "✓ $tool instalado correctamente"
        else
            print_warning "✗ $tool no encontrado"
        fi
    done
    
    print_message "Verificando archivos del sistema..."
    
    files=("pentest_automation.py" "config.json" "modules/__init__.py" "modules/logging_system.py" "modules/reconnaissance.py" "modules/credential_harvesting.py" "modules/lateral_movement.py" "modules/persistence.py" "modules/privilege_escalation.py" "modules/exfiltration.py")
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            print_message "✓ $file encontrado"
        else
            print_warning "✗ $file no encontrado"
        fi
    done
    
    print_message "Verificación completada"
}

# Mostrar información post-instalación
show_post_install_info() {
    print_header "Información Post-Instalación"
    
    echo -e "${GREEN}Instalación completada exitosamente!${NC}"
    echo ""
    echo -e "${BLUE}Próximos pasos:${NC}"
    echo "1. Edite el archivo config.json con sus parámetros específicos"
    echo "2. Configure la red objetivo en la configuración"
    echo "3. Ejecute una prueba en modo dry-run: python3 pentest_automation.py --dry-run"
    echo "4. Revise la documentación en README.md y MANUAL.md"
    echo ""
    echo -e "${BLUE}Comandos útiles:${NC}"
    echo "• Ejecutar prueba completa: python3 pentest_automation.py"
    echo "• Solo reconocimiento: python3 pentest_automation.py -p recon"
    echo "• Modo dry-run: python3 pentest_automation.py --dry-run"
    echo "• Ver ayuda: python3 pentest_automation.py --help"
    echo ""
    echo -e "${YELLOW}IMPORTANTE:${NC}"
    echo "• Solo use este sistema en redes autorizadas"
    echo "• Obtenga permiso por escrito antes de realizar pruebas"
    echo "• Revise la documentación de seguridad"
    echo ""
    echo -e "${GREEN}¡Disfrute usando el sistema de automatización de pentesting!${NC}"
}

# Función principal
main() {
    print_header "Sistema de Automatización de Pruebas de Penetración - Instalador"
    
    check_root
    check_os
    update_system
    install_pentest_tools
    install_python_deps
    setup_metasploit
    setup_permissions
    create_directories
    setup_config
    verify_installation
    show_post_install_info
}

# Ejecutar instalación
main "$@"
