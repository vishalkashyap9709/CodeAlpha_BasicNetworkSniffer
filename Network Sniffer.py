from scapy.all import sniff, IP,TCP, UDP,ICMP

def packet_sniffer(packet):
    if packet.haslayer(IP):
        src_ip =packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Unknown"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} Protocol: {protocol}")

sniff(prn=packet_sniffer , count=10)