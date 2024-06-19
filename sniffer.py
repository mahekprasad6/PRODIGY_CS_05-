from scapy.all import sniff, IP, TCP, UDP
import sys

# Dictionary to map port numbers to services
services = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S"
}

def packet_callback(packet, log_file):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Protocols: 6 = TCP, 17 = UDP
        if proto == 6 and TCP in packet:
            protocol = "TCP"
            dport = packet[TCP].dport
        elif proto == 17 and UDP in packet:
            protocol = "UDP"
            dport = packet[UDP].dport
        else:
            protocol = "Other"
            dport = None

        # Get the service name from the port number
        service = services.get(dport, "Unknown")

        # Extract the payload (content) of the packet
        payload = bytes(packet)
        payload_hex = payload.hex()
        payload_ascii = ''.join(chr(int(payload_hex[i:i+2], 16)) for i in range(0, len(payload_hex), 2))

        log_file.write(f"Source IP: {ip_src}\n")
        log_file.write(f"Destination IP: {ip_dst}\n")
        log_file.write(f"Protocol: {protocol}\n")
        log_file.write(f"Destination Port: {dport}\n")
        log_file.write(f"Service: {service}\n")
        log_file.write(f"Payload (HEX): {payload_hex}\n")
        log_file.write(f"Payload (ASCII): {payload_ascii}\n")
        log_file.write("\n" + "-"*50 + "\n")

def main():
    print("Starting packet sniffer...")
    log_file = open("packet_sniffer_log.txt", "w", encoding="utf-8")
    try:
        # Start sniffing (use iface parameter to specify the interface)
        sniff(prn=lambda packet: packet_callback(packet, log_file), store=0)
    except KeyboardInterrupt:
        print("Packet sniffer stopped.")
        log_file.close()
        sys.exit(0)

if __name__ == "__main__":
    main()