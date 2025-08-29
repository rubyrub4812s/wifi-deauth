#!/bin/bash

# WiFi Deauth SuperTool - Setup Script
# Author: Ruby Doss (@rubydoss)
# Instagram: @mr__dawxz

set -e

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
PURPLE='\\033[0;35m'
CYAN='\\033[0;36m'
NC='\\033[0m' # No Color

# Print functions
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                  WiFi Deauth SuperTool Setup                    ║"
    echo "║                  Automated Installation                          ║"
    echo "╠══════════════════════════════════════════════════════════════════╣"
    echo "║  Author: Ruby Doss (@rubydoss)                                  ║"
    echo "║  Instagram: @mr__dawxz                                           ║"
    echo "║  GitHub: https://github.com/rubydoss                            ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_success "Running with root privileges ✓"
    else
        print_error "This script requires root privileges for system package installation"
        print_status "Please run: sudo $0"
        exit 1
    fi
}

# Detect operating system
detect_os() {
    print_status "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        print_success "Detected: $PRETTY_NAME"
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        print_success "Detected: CentOS/RHEL"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        print_success "Detected: Debian-based"
    else
        print_error "Unable to detect operating system"
        exit 1
    fi
}

# Update package manager
update_packages() {
    print_status "Updating package manager..."
    
    case $OS in
        ubuntu|debian|kali)
            apt update -y > /dev/null 2>&1
            print_success "Package manager updated"
            ;;
        fedora|centos|rhel)
            if command -v dnf > /dev/null; then
                dnf update -y > /dev/null 2>&1
            else
                yum update -y > /dev/null 2>&1
            fi
            print_success "Package manager updated"
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm > /dev/null 2>&1
            print_success "Package manager updated"
            ;;
        *)
            print_warning "Unsupported OS for automatic updates: $OS"
            ;;
    esac
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian|kali)
            apt install -y python3 python3-pip aircrack-ng wireless-tools net-tools > /dev/null 2>&1
            print_success "System dependencies installed"
            ;;
        fedora|centos|rhel)
            if command -v dnf > /dev/null; then
                dnf install -y python3 python3-pip aircrack-ng wireless-tools net-tools > /dev/null 2>&1
            else
                yum install -y python3 python3-pip aircrack-ng wireless-tools net-tools > /dev/null 2>&1
            fi
            print_success "System dependencies installed"
            ;;
        arch|manjaro)
            pacman -S --noconfirm python python-pip aircrack-ng wireless_tools net-tools > /dev/null 2>&1
            print_success "System dependencies installed"
            ;;
        *)
            print_error "Unsupported OS: $OS"
            print_status "Please install manually: python3, pip3, aircrack-ng, wireless-tools"
            exit 1
            ;;
    esac
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    if [[ -f requirements.txt ]]; then
        pip3 install -r requirements.txt > /dev/null 2>&1
        print_success "Python dependencies installed"
    else
        print_status "Installing individual packages..."
        pip3 install scapy colorama psutil netifaces python-dateutil > /dev/null 2>&1
        print_success "Python packages installed"
    fi
}

# Check wireless adapter
check_wireless() {
    print_status "Checking wireless adapters..."
    
    WIRELESS_INTERFACES=$(iwconfig 2>/dev/null | grep -o '^[a-zA-Z0-9]*' | head -5)
    
    if [[ -z "$WIRELESS_INTERFACES" ]]; then
        print_warning "No wireless interfaces found"
        print_status "Please ensure you have a compatible WiFi adapter connected"
    else
        print_success "Found wireless interfaces:"
        for interface in $WIRELESS_INTERFACES; do
            echo "  ${CYAN}→${NC} $interface"
        done
    fi
}

# Test monitor mode capability
test_monitor_mode() {
    print_status "Testing monitor mode capabilities..."
    
    WIRELESS_INTERFACES=$(iwconfig 2>/dev/null | grep -o '^[a-zA-Z0-9]*' | head -1)
    
    if [[ -n "$WIRELESS_INTERFACES" ]]; then
        FIRST_INTERFACE=$(echo $WIRELESS_INTERFACES | head -1)
        
        # Test if we can set monitor mode
        iwconfig $FIRST_INTERFACE mode monitor 2>/dev/null && \\
        iwconfig $FIRST_INTERFACE mode managed 2>/dev/null
        
        if [[ $? -eq 0 ]]; then
            print_success "Monitor mode supported on $FIRST_INTERFACE"
        else
            print_warning "Monitor mode test failed - this may be normal"
            print_status "The tool will attempt to use airmon-ng for monitor mode"
        fi
    fi
}

# Set permissions
set_permissions() {
    print_status "Setting file permissions..."
    
    chmod +x wifi_deauth_supertool.py 2>/dev/null || true
    chmod +x setup.sh 2>/dev/null || true
    
    print_success "Permissions set"
}

# Final instructions
show_instructions() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════╗"
    echo -e "║                        SETUP COMPLETE! 🎉                         ║"
    echo -e "╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}📋 Next Steps:${NC}"
    echo ""
    echo -e "  ${GREEN}1.${NC} Run the tool:"
    echo -e "     ${YELLOW}sudo python3 wifi_deauth_supertool.py${NC}"
    echo ""
    echo -e "  ${GREEN}2.${NC} Follow the interactive prompts to:"
    echo -e "     • Select your wireless interface"
    echo -e "     • Scan for WiFi networks"  
    echo -e "     • Choose target and execute attack"
    echo ""
    echo -e "${RED}⚠️  IMPORTANT REMINDERS:${NC}"
    echo -e "  • Only test on networks you own or have permission to test"
    echo -e "  • Unauthorized WiFi attacks are illegal"
    echo -e "  • Use this tool responsibly for educational purposes only"
    echo ""
    echo -e "${PURPLE}👨‍💻 Author: Ruby Doss (@rubydoss) | Instagram: @mr__dawxz${NC}"
    echo ""
}

# Main installation process
main() {
    print_banner
    
    check_root
    detect_os
    update_packages
    install_system_deps
    install_python_deps
    check_wireless
    test_monitor_mode
    set_permissions
    
    show_instructions
}

# Run main function
main "$@"