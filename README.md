<div align="center">

```
 ███╗   ██╗███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║       ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
```

# 📡 Basic Network Sniffer

**ARCH Technologies — Cyber Security Month 1 | Task 1**

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)](https://kernel.org)
[![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Saqib%20Raheem%20Khan-purple?style=for-the-badge)](https://github.com)

> A lightweight, terminal-based network packet sniffer built in pure Python.  
> Captures, parses, and displays live network traffic in a clean, readable format.

</div>

---

## 📖 Table of Contents

- [📡 Basic Network Sniffer](#-basic-network-sniffer)
  - [📖 Table of Contents](#-table-of-contents)
  - [🎯 Project Overview](#-project-overview)
  - [✨ Features](#-features)
  - [🔬 How It Works](#-how-it-works)
    - [Packet Capture Flow](#packet-capture-flow)
    - [Protocols Supported](#protocols-supported)
  - [🖥️ System Requirements](#️-system-requirements)
  - [⚙️ Installation](#️-installation)
    - [Step 1 — Verify Python Version](#step-1--verify-python-version)
    - [Step 2 — Clone the Repository](#step-2--clone-the-repository)
    - [Step 3 — Navigate into the Project](#step-3--navigate-into-the-project)
    - [Step 4 — (Optional) Create a Virtual Environment](#step-4--optional-create-a-virtual-environment)
    - [Step 5 — Verify No Extra Dependencies Are Needed](#step-5--verify-no-extra-dependencies-are-needed)
  - [🚀 Usage](#-usage)
    - [Basic — Capture All Traffic](#basic--capture-all-traffic)
    - [Filter by Protocol](#filter-by-protocol)
    - [Filter by IP Address](#filter-by-ip-address)
    - [Limit Number of Packets](#limit-number-of-packets)
    - [Verbose Mode (Show Payload)](#verbose-mode-show-payload)
    - [Save Output to Log File](#save-output-to-log-file)
    - [Combined Example](#combined-example)
  - [🗂️ Project Structure](#️-project-structure)
  - [📊 Output Explained](#-output-explained)
  - [🛡️ Legal & Ethical Notice](#️-legal--ethical-notice)
  - [👤 Author](#-author)

---

## 🎯 Project Overview

This project was developed as **Task 1** of the **ARCH Technologies Cyber Security Month 1** program. The goal is to build a network sniffer from scratch using Python's raw socket interface to understand how data flows across a network and how network packets are structured at each layer of the OSI model.

The sniffer captures packets at the **Data Link Layer (Layer 2)** and parses them upward through:

```
Layer 2  →  Ethernet Frame  (MAC addresses, EtherType)
Layer 3  →  IPv4 Header     (IP addresses, TTL, Protocol)
Layer 4  →  TCP / UDP / ICMP (Ports, Flags, Sequence Numbers)
Layer 7  →  Payload Data    (Optional display)
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 📦 **Packet Capture** | Captures live packets at the Ethernet frame level |
| 🌐 **IPv4 Parsing** | Decodes IP version, TTL, protocol, source/dest IPs |
| 📡 **TCP Analysis** | Ports, sequence numbers, ACK numbers, all TCP flags |
| 📡 **UDP Analysis** | Ports and payload length |
| 📶 **ICMP Analysis** | Type, code, and human-readable ICMP type names |
| 🔍 **Protocol Filter** | Filter by TCP, UDP, ICMP, or IGMP |
| 🎯 **IP Filter** | Show only packets involving a specific IP address |
| 🔢 **Packet Limit** | Stop capture after N packets |
| 📝 **Verbose Mode** | Display payload data (ASCII or hex dump) |
| 💾 **Log to File** | Save packet summary to a plain text log file |
| 📊 **Live Statistics** | Shows total packets, bytes, protocol breakdown on exit |
| 🎨 **Colored Output** | ANSI color-coded terminal output for readability |
| 🔌 **Known Ports** | Labels 30+ well-known ports (HTTP, HTTPS, DNS, SSH…) |
| ⚡ **Zero Dependencies** | Uses only Python standard library — no pip installs |

---

## 🔬 How It Works

### Packet Capture Flow

```
Network Interface Card (NIC)
          │
          ▼
 Raw Socket (AF_PACKET, SOCK_RAW)
          │
          ▼
 ┌─────────────────────────────┐
 │     Ethernet Frame Parser   │   → Src/Dst MAC, EtherType
 └────────────┬────────────────┘
              │  (EtherType = 0x0800 → IPv4)
              ▼
 ┌─────────────────────────────┐
 │     IPv4 Header Parser      │   → Src/Dst IP, TTL, Protocol
 └────────────┬────────────────┘
              │
       ┌──────┴───────┐
       ▼              ▼            ▼
  TCP Parser     UDP Parser   ICMP Parser
  (ports, flags) (ports, len)  (type, code)
       │              │            │
       └──────────────┴────────────┘
                      │
                      ▼
              Display + Log + Stats
```

### Protocols Supported

| Protocol | Number | Details Extracted |
|---|---|---|
| **TCP** | 6 | Src/Dst port, Seq, Ack, Flags (SYN/ACK/FIN/RST/PSH/URG), Window |
| **UDP** | 17 | Src/Dst port, Length, Payload |
| **ICMP** | 1 | Type, Code, Type Name (Echo Request/Reply, Unreachable…) |
| **IGMP** | 2 | Detected and labeled |
| **OSPF** | 89 | Detected and labeled |
| **Other** | — | Logged with protocol number |

---

## 🖥️ System Requirements

| Requirement | Minimum |
|---|---|
| **Operating System** | Linux (Ubuntu, Kali, Debian, Fedora, Arch…) |
| **Python Version** | Python 3.6 or higher |
| **Permissions** | Root / sudo (required for raw sockets) |
| **Dependencies** | None (standard library only) |

> ⚠️ **Windows/macOS Note:** `AF_PACKET` raw sockets are Linux-specific.  
> On Windows, use **Wireshark** or **Npcap** as alternatives.  
> On macOS, use `BPF` sockets or **tcpdump**.

---

## ⚙️ Installation

Follow these steps carefully to set up and run the sniffer on a Linux system.

### Step 1 — Verify Python Version

Open your terminal and check that Python 3.6+ is installed:

```bash
python3 --version
```

Expected output (example):
```
Python 3.10.12
```

If Python is not installed:
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install python3 -y

# Fedora / RHEL
sudo dnf install python3 -y

# Arch Linux
sudo pacman -S python
```

---

### Step 2 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/network-sniffer.git
```

> Replace `YOUR_USERNAME` with your actual GitHub username.

---

### Step 3 — Navigate into the Project

```bash
cd network-sniffer
```

---

### Step 4 — (Optional) Create a Virtual Environment

Although no external packages are needed, a virtual environment keeps your workspace clean:

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### Step 5 — Verify No Extra Dependencies Are Needed

```bash
cat requirements.txt
```

The file confirms this tool uses **only standard library modules** — no pip installs required. ✅

---

## 🚀 Usage

> 🔑 **All commands must be run with `sudo`** — raw sockets require root privileges.

### Basic — Capture All Traffic

```bash
sudo python3 sniffer.py
```

Captures all IPv4 packets on the network interface. Press `Ctrl+C` to stop.

---

### Filter by Protocol

```bash
sudo python3 sniffer.py -p TCP
sudo python3 sniffer.py -p UDP
sudo python3 sniffer.py -p ICMP
```

Only display packets matching the specified protocol.

---

### Filter by IP Address

```bash
sudo python3 sniffer.py --ip 192.168.1.1
```

Show only packets where the source **or** destination IP matches.

---

### Limit Number of Packets

```bash
sudo python3 sniffer.py -c 100
```

Stop automatically after capturing 100 packets.

---

### Verbose Mode (Show Payload)

```bash
sudo python3 sniffer.py -v
```

Display payload content. ASCII text is shown as-is; binary data is shown as a hex dump.

---

### Save Output to Log File

```bash
sudo python3 sniffer.py -o capture.log
```

Packet summaries are saved to `capture.log` in plain text (no ANSI color codes).

---

### Combined Example

```bash
sudo python3 sniffer.py -p TCP --ip 192.168.1.100 -c 50 -v -o session.log
```

Captures 50 TCP packets involving `192.168.1.100`, shows payloads, and saves to `session.log`.

---

## 📋 All Arguments

```
usage: sniffer.py [-h] [-p PROTO] [--ip IP_ADDR] [-c N] [-v] [-o FILE]

options:
  -h, --help            Show this help message and exit
  -p, --protocol PROTO  Filter: TCP, UDP, ICMP, IGMP
  --ip IP_ADDR          Filter by source or destination IP
  -c, --count N         Stop after N packets
  -v, --verbose         Show payload data (ASCII / hex)
  -o, --output FILE     Save packet log to FILE
```

---

## 🗂️ Project Structure

```
network-sniffer/
│
├── sniffer.py          ← Main script (packet capture & analysis)
├── requirements.txt    ← Dependency info (standard library only)
└── README.md           ← This file
```

---

## 📊 Output Explained

When a TCP packet is captured, the output looks like this:

```
[ PKT #0001 ]  14:23:05.412  EtherType: 0x0800
──────────────────────────────────────────────────────────────
  🔗 Ethernet
     Src MAC : A4:C3:F0:85:12:3E
     Dst MAC : FF:FF:FF:FF:FF:FF
  🌐 IPv4
     192.168.1.5 ──▶  142.250.80.46
     Protocol : TCP  |  TTL: 64  |  Len: 60B  |  Hdr: 20B
  📡 TCP
     Port  : 52341  ──▶  443 (HTTPS)
     Flags : SYN  |  Seq: 1482736123  |  Ack: 0  |  Win: 64240
```

| Field | Meaning |
|---|---|
| `PKT #0001` | Packet sequence number |
| `14:23:05.412` | Capture timestamp |
| `Src/Dst MAC` | Hardware addresses (Ethernet layer) |
| `──▶` | Direction of flow |
| `TTL` | Time To Live (how many hops remain) |
| `Flags` | TCP control flags active in this packet |
| `(HTTPS)` | Known service name for port 443 |

At exit (Ctrl+C), statistics are shown:

```
══════════════════════════════════════════════════════════════
  📊  SESSION STATISTICS
══════════════════════════════════════════════════════════════
  Duration      : 12.4s
  Total Packets : 87
  Total Bytes   : 142,320
  TCP           : 61
  UDP           : 19
  ICMP          : 7
  Other         : 0
  Avg Rate      : 7.0 pkt/s
══════════════════════════════════════════════════════════════
```

---

## 🛡️ Legal & Ethical Notice

```
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  IMPORTANT — READ BEFORE USE                             ║
╠══════════════════════════════════════════════════════════════╣
║  This tool is developed STRICTLY for:                        ║
║    • Educational purposes                                    ║
║    • Authorized network testing                              ║
║    • Cybersecurity training (ARCH Technologies M-1)         ║
║                                                              ║
║  DO NOT use this tool on networks you do not own             ║
║  or do not have explicit written permission to test.         ║
║                                                              ║
║  Unauthorized packet sniffing may violate:                   ║
║    • Local and international computer crime laws             ║
║    • The Computer Fraud and Abuse Act (CFAA)                 ║
║    • The Electronic Communications Privacy Act (ECPA)        ║
║                                                              ║
║  Always use in a controlled lab environment.                 ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 👤 Author

<div align="center">

**Saqib Raheem Khan**  
*Cyber Security Student | ARCH Technologies — Month 1*

[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/YOUR_USERNAME)

---

*ARCH Technologies — Sharpening your hidden skills for a brighter future*

</div>
