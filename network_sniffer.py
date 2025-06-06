from scapy.all import sniff, IP, TCP, UDP, wrpcap
import logging
import datetime

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file_name = f"sniffer_log_{timestamp}.txt"
pcap_file_name = f"captured_packets_{timestamp}.pcap"

logging.basicConfig(filename=log_file_name, level=logging.INFO, format='%(asctime)s - %(message)s')

captured_packets = []

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else str(ip_layer.proto)
        msg = f"{ip_layer.src} -> {ip_layer.dst} | Protocol: {protocol}"

        try:
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            short_payload = payload[:50].decode(errors='replace') 
            msg += f"\n    Payload: {short_payload}"
        except Exception:
            msg += "\n    Payload: [Error reading]"

        print(msg + "\n")
        logging.info(msg)

        captured_packets.append(packet)

def main():
    print("=" * 60)
    print("🚀 CodeAlpha - Network Sniffer (Press Ctrl+C to stop)")
    print("=" * 60)

    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Capture stopped by user.")

    wrpcap(pcap_file_name, captured_packets)
    print(f"\n✅ Capture complete!")
    print(f"📁 Packets saved to: {pcap_file_name}")
    print(f"📝 Log saved to: {log_file_name}")

if __name__ == "__main__":
    main()
