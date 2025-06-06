# CodeAlpha - Network Sniffer 🕵️‍♂️

A basic network packet sniffer built in Python using Scapy — enhanced with a simple Tkinter GUI and `.pcap` export support.

## 🚀 Features
- Live packet capture (TCP, UDP, IP)
- GUI interface with start/stop buttons
- Save captured traffic to `.pcap` (open in Wireshark)
- Displays source IP, destination IP, protocol and payloads
- Lightweight and beginner-friendly

## 🛠️ Tech Used
- Python 3
- Scapy
- Tkinter

## 📦 Installation

1. Clone this repo:
   ```bash
   git clone https://github.com/soham-baxi/CodeAlpha_NetworkSniffer.git
   cd CodeAlpha_NetworkSniffer

2. On Windows, install Npcap

## 🔍 Optional: Version Differences Explained

This project includes two versions of the network sniffer:

### 🖥️ 1. GUI Version (`network_sniffer_gui.py`)
- Built using **Tkinter**
- Real-time packet display in a GUI window
- **Auto-stops after 40 seconds** (⏱️) — but you can change this by modifying the `SCAN_DURATION` variable at the top of the script:
  ```python
  SCAN_DURATION = 60  # change to any number of seconds
- Displays **color-coded protocols** (TCP = green, UDP = blue, Others = red)
- Saves both `.pcap` and `.txt` files after timeout

### 🖥️ 2. Terminal Version (`network_sniffer.py`)
- Simple and lightweight **command-line interface**
- Does **not auto-stop** — continues capturing until you press `Ctrl + C`
- Ideal for long-term monitoring or terminal-only environments
- Also saves both `.pcap` and `.txt` files when stopped manually

---

**Why both?**  
Having both versions demonstrates flexibility — GUI for beginner users or demos, terminal version for real-world usage or scripting environments.

