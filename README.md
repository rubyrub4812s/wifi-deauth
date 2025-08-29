# WiFi Deauth SuperTool 🔒

<div align="center">

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Kali](https://img.shields.io/badge/kali-supported-success.svg)

**A unified, interactive WiFi deauthentication tool for penetration testing**

*Step-by-step network scanning and deauth attacks in a single CLI tool*

</div>
<image>source=</image>
---

## 🎯 Overview

**WiFi Deauth SuperTool** is a professional, all-in-one command-line tool that streamlines WiFi penetration testing. Unlike traditional multi-script approaches, this tool provides a **unified workflow** that guides users through interface setup, network scanning, target selection, and deauthentication attacks—all within a single, interactive CLI experience.

### ✨ Key Features

- 🔧 **All-in-One Solution**: Complete workflow in single tool - no multiple scripts needed
- 🖥️ **Interactive CLI**: Step-by-step guided interface with colored output
- 📡 **Auto Monitor Mode**: Automatically enables/disables monitor mode on selected interface  
- 🔍 **Network Scanner**: Discovers and displays all available WiFi networks with details
- ⚡ **Deauth Attacks**: Continuous deauthentication with real-time statistics
- 🛡️ **Safety Features**: Confirmation prompts and authorized-only warnings
- 📊 **Live Statistics**: Real-time attack progress and packet counts
- 🧹 **Auto Cleanup**: Graceful interface restoration on exit

### 🎮 Tool Workflow

![Tool Workflow](https://raw.githubusercontent.com/rubydoss/wifi-deauth-supertool/main/workflow.png)

1. **Interface Selection** → Choose and enable monitor mode
2. **Network Scanning** → Discover available WiFi networks  
3. **Target Selection** → Pick network from interactive list
4. **Attack Confirmation** → Safety check before proceeding
5. **Deauth Execution** → Continuous attack with live stats
6. **Clean Exit** → Restore interfaces and cleanup

---

## 🚨 Legal Notice

> ⚠️ **EDUCATIONAL USE ONLY**  
> This tool is designed exclusively for educational purposes and authorized penetration testing. Using this tool against networks you don't own or lack explicit permission to test is **illegal** and may result in criminal charges.

**By using this tool, you agree to:**
- ✅ Only test networks you own or have written permission to test
- ✅ Comply with all applicable local and international laws
- ✅ Use findings to improve security, not cause harm
- ❌ Never attack public, corporate, or unauthorized networks

---

## 📋 Requirements

### Hardware
- **Linux System** (Kali Linux, Ubuntu, Debian, etc.)
- **WiFi Adapter** with monitor mode and packet injection support
  - Recommended: Alfa AWUS036ACS, Panda PAU09, TP-Link AC600T2U Plus
- **4GB+ RAM** (8GB recommended)
- **Root Access** (sudo privileges required)

### Software
- Python 3.8 or higher
- Aircrack-ng suite
- Compatible wireless drivers

---

## 🚀 Installation

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/rubyrub4812s/wifi-deauth.git
cd wifi-deauth-supertool

# Install dependencies
pip3 install -r requirements.txt

# Make executable (optional)
chmod +x wifi_deauth_supertool.py
```

### System Dependencies

**Ubuntu/Debian/Kali:**
```bash
sudo apt update
sudo apt install python3 python3-pip aircrack-ng
```

**Fedora/RHEL:**
```bash
sudo dnf install python3 python3-pip aircrack-ng
```

---

## 🎮 Usage

### Basic Usage

```bash
# Run the tool (requires root privileges)
sudo python3 wifi_deauth_supertool.py
```

### Example Session

```
$ sudo python3 wifi_deauth_supertool.py

╔══════════════════════════════════════════════════════════════════╗
║                    WiFi Deauth SuperTool                        ║
║              Unified WiFi Penetration Framework                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Author: Ruby Doss (@rubydoss)                                  ║
║  Instagram: @mr__dawxz                                           ║
║  GitHub: https://github.com/rubydoss                            ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚠️  FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY! ⚠️           ║
╚══════════════════════════════════════════════════════════════════╝

🚀 WiFi Deauth SuperTool - Main Menu
========================================
  [1] Setup Monitor Mode & Scan Networks
  [2] Attack Selected Network
  [3] Exit & Cleanup

Choose option (1-3): 1

📡 Available Wireless Interfaces:
----------------------------------------
  [1] wlan0
  [2] wlan1

Select interface (1-2): 1

[INFO] Enabling monitor mode on wlan0...
[SUCCESS] Monitor mode enabled successfully: wlan0mon

[INFO] Scanning for WiFi networks on wlan0mon...
[SCANNING] 20/20s - Networks found: 12

📡 Discovered WiFi Networks:
================================================================================
#   SSID                     BSSID              Ch   Security     Signal    
================================================================================
1   HomeNetwork_5G           AA:BB:CC:DD:EE:FF  36   WPA2         -45 dBm   
2   CoffeeShop_Guest         11:22:33:44:55:66  6    Open         -67 dBm   
3   TestLab_Research         99:88:77:66:55:44  11   WPA3         -52 dBm   

Select target network (1-3) or 'q' to quit: 1

⚠️  WARNING: You are about to attack WiFi network:
   SSID: HomeNetwork_5G
   BSSID: AA:BB:CC:DD:EE:FF
   Security: WPA2

This will disconnect all clients from this network!
Only proceed if you have explicit permission to test this network.

Continue with deauth attack? [y/N]: y

[INFO] Starting deauthentication attack on HomeNetwork_5G
[WARNING] Press Ctrl+C to stop the attack

[ATTACKING] Packets: 150 | Rate: 15.2/sec | Duration: 10s

^C
Attack stopped by user

📊 Attack Summary:
   Target: HomeNetwork_5G (AA:BB:CC:DD:EE:FF)
   Packets sent: 150
   Duration: 10 seconds
   Average rate: 15.0 packets/sec
```

---

## 📊 Features in Detail

### Interactive Network Selection
- Automatically detects wireless interfaces
- Displays networks in organized table format
- Shows SSID, BSSID, channel, security type, and signal strength
- Numbered selection for easy targeting

### Real-time Attack Monitoring
- Live packet count and transmission rate
- Attack duration tracking
- Graceful stop with Ctrl+C
- Comprehensive attack summary

### Safety & Security Features
- Root privilege verification
- Interface conflict detection and resolution
- Confirmation prompts before attacks
- Automatic interface restoration
- Comprehensive error handling

---

## 🔧 Advanced Configuration

### Custom Packet Delay
Modify the delay between packets by editing the tool:
```python
time.sleep(0.1)  # 100ms delay (line ~380)
```

### Attack Intensity
Adjust packet burst frequency in the main attack loop for different intensity levels.

---

## 📁 Project Structure

```
wifi-deauth-supertool/
├── wifi_deauth_supertool.py    # Main tool (single file)
├── README.md                   # This documentation
├── requirements.txt            # Python dependencies
├── LICENSE                     # MIT License
├── .gitignore                 # Git ignore patterns
└── workflow.png               # Workflow diagram
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Guidelines
- Follow Python PEP 8 style guidelines
- Add appropriate error handling
- Include docstrings for new functions
- Test on multiple Linux distributions

---

## 🐛 Troubleshooting

### Common Issues

**"No wireless interfaces found"**
- Ensure WiFi adapter is connected and recognized
- Check with `iwconfig` command
- Install appropriate drivers for your adapter

**"Permission denied"**  
- Run with `sudo` - root privileges required
- Ensure user is in appropriate groups (netdev, etc.)

**"Monitor mode enable failed"**
- Kill NetworkManager: `sudo systemctl stop NetworkManager`
- Use `airmon-ng check kill` to stop interfering processes
- Try different WiFi adapter

**"No networks found during scan"**
- Ensure monitor mode is working: `iwconfig`
- Check if adapter supports packet injection
- Try scanning longer or on specific channels

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ruby Doss**
- 🌐 GitHub: [@rubydoss](https://github.com/rubydoss)
- 📷 Instagram: [@mr__dawxz](https://instagram.com/mr__dawxz)
- 💼 LinkedIn: [Ruby Doss](https://linkedin.com/in/rubydoss)
- 📧 Contact: ruby@cybersec.dev

---

## ⭐ Support

If you find this tool helpful, please consider:
- ⭐ Starring this repository
- 🍴 Forking and contributing
- 📢 Sharing with the cybersecurity community
- 🐛 Reporting bugs and issues

---

## 📚 Educational Resources

### Learning WiFi Security
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [WiFi Security Best Practices](https://www.sans.org/white-papers/)
- [802.11 Protocol Deep Dive](https://standards.ieee.org/standard/802_11-2020.html)

### Legal Resources
- [Penetration Testing Legal Guidelines](https://www.sans.org/white-papers/legal/)
- [Computer Fraud and Abuse Act (CFAA)](https://www.justice.gov/criminal-ccips/computer-fraud-and-abuse-act)
- [International Cybersecurity Laws](https://www.cisa.gov/cybersecurity-best-practices)

---

## 🔄 Version History

- **v1.0.0** - Initial release with unified workflow
- **v1.1.0** - Added colored output and improved error handling
- **v1.2.0** - Enhanced network scanning and statistics
- **v2.0.0** - Complete rewrite with professional CLI interface

---

<div align="center">

**⚠️ Remember: Use responsibly, test ethically, secure effectively ⚠️**

Made with ❤️ for the cybersecurity community

[🔝 Back to Top](#wifi-deauth-supertool-)

</div>
