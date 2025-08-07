# 🛠️ Setup Guide

Welcome to the Analyst Field Guide! This document will walk you through setting up your analysis environment so you can get the most out of the labs and handbooks.

---

## ⚙️ Recommended Environment

I recommend using a Linux virtual machine (VM) for best compatibility and isolation. You can also perform many tasks on Windows or macOS with minor adjustments.

### ✅ Linux VM Options
- **Ubuntu 22.04 LTS**
- **Kali Linux**
- **Remnux** (for malware analysis)

I recommend using [VirtualBox](https://www.virtualbox.org/) ([instructions](https://www.tomshardware.com/how-to/set-up-virtual-machines-with-virtualbox)) or [VMware Workstation](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) ([instructions](https://www.wikihow.com/Create-a-Virtual-Machine-on-Your-PC-with-VMware-Workstation)) to run your VM. 

---

## 📦 Required Tools

Install the following tools in your VM or host system.

### 📡 Network Analysis
| Tool         | Install Command (Ubuntu/Debian) |
|--------------|---------------------------------|
| Wireshark    | `sudo apt install wireshark`    |
| tshark       | `sudo apt install tshark`       |
| tcpdump      | `sudo apt install tcpdump`      |
| nmap         | `sudo apt install nmap`         |
| Zeek         | `sudo apt install zeek`         |

### 🔍 Host & Log Analysis
| Tool           | Install Command |
|----------------|-----------------|
| jq             | `sudo apt install jq`         |
| grep / awk / sed | (pre-installed)             |
| Auditd         | `sudo apt install auditd`     |
| Sysmon (for Windows logs) | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |

### 🧪 Malware Analysis
| Tool         | Notes |
|--------------|-------|
| CyberChef    | Web-based: https://gchq.github.io/CyberChef |
| Ghidra       | [Download here](https://ghidra-sre.org/) |
| Radare2      | `sudo apt install radare2` |
| Strings      | `sudo apt install binutils` (provides `strings`) |

