import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, wrpcap
import threading
import datetime
import logging

SCAN_DURATION = 40  # Seconds (In GUI the process doesn't stop when we use `CTRL + C` so after 40 seconds it will stop autoatically & we can change seconds)
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"sniffer_log_{timestamp}.txt"
pcap_file = f"captured_packets_{timestamp}.pcap"

logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(message)s")
captured_packets = []

# GUI setup
window = tk.Tk()
window.title("CodeAlpha Network Sniffer")
window.geometry("850x550")
window.configure(bg="#1e1e2f")

header = tk.Label(window, text="🛡️ CodeAlpha Network Sniffer", font=("Segoe UI", 16, "bold"), fg="#00ffe1", bg="#1e1e2f")
header.pack(pady=10)

start_button = tk.Button(window, text="Start Sniffing (Auto 40sec)", command=lambda: threading.Thread(target=start_sniffing).start(), font=("Segoe UI", 12), bg="#00bcd4", fg="white")
start_button.pack(pady=5)

text_area = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=105, height=25, font=("Consolas", 10), bg="#f7f7f7")
text_area.pack(padx=10, pady=10)

# Packet processor with color coding
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else str(ip_layer.proto)
        msg = f"{ip_layer.src} -> {ip_layer.dst} | Protocol: {protocol}"

        if protocol == "TCP":
            color = "green"
        elif protocol == "UDP":
            color = "blue"
        else:
            color = "red"

        # Extract payload (for TCP/UDP)
        try:
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            short_payload = payload[:50].decode(errors='replace')  # Truncate for display
            msg += f"\n    Payload: {short_payload}"
        except:
            msg += "\n    Payload: [Error reading]"

        # Display and log
        text_area.insert(tk.END, msg + "\n\n", color)
        text_area.see(tk.END)
        logging.info(msg)

        captured_packets.append(packet)

# Start sniffing (auto-stop)
def start_sniffing():
    start_button.config(state=tk.DISABLED)
    text_area.insert(tk.END, f"[+] Starting capture for {SCAN_DURATION} seconds...\n\n", "bold")
    sniff(prn=process_packet, store=False, timeout=SCAN_DURATION)
    save_and_exit()

# Save to .pcap
def save_and_exit():
    wrpcap(pcap_file, captured_packets)
    text_area.insert(tk.END, f"\n[✓] Capture complete.\n", "bold")
    text_area.insert(tk.END, f"📁 Packets saved to: {pcap_file}\n", "bold")
    text_area.insert(tk.END, f"📝 Log saved to: {log_file}\n", "bold")
    text_area.see(tk.END)
    start_button.config(state=tk.NORMAL)

# Style tags
text_area.tag_config("green", foreground="green")
text_area.tag_config("blue", foreground="blue")
text_area.tag_config("red", foreground="red")
text_area.tag_config("bold", font=("Segoe UI", 10, "bold"))

window.mainloop()
