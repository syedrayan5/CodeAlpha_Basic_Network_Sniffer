import scapy.all as scapy

# Function to process captured packets
def packet_callback(packet):
    print(f"Packet captured: {packet.summary()}")
    # Analyzing packet details (you can customize this based on the protocol you're interested in)
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}")
    
    if packet.haslayer(scapy.TCP):
        tcp_sport = packet[scapy.TCP].sport
        tcp_dport = packet[scapy.TCP].dport
        print(f"Source Port: {tcp_sport}, Destination Port: {tcp_dport}")
    
    if packet.haslayer(scapy.UDP):
        udp_sport = packet[scapy.UDP].sport
        udp_dport = packet[scapy.UDP].dport
        print(f"Source Port: {udp_sport}, Destination Port: {udp_dport}")

# Start sniffing network packets
def start_sniffing():
    print("Starting packet sniffing...")
    interfaces = scapy.get_if_list()  # Get list of available interfaces
    print("Available interfaces:", interfaces)
    
    # Choose the correct interface, e.g., "Ethernet" or "Wi-Fi" on Windows
    interface = input("Enter the interface name to sniff on: ")

    # Start sniffing
    scapy.sniff(iface=interface, prn=packet_callback, store=0)

# Run the sniffer
start_sniffing()
