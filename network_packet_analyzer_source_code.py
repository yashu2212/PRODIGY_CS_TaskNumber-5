from scapy.all import IP, sniff, Raw

# Define a callback function to process each packet
def packet_callback(packet):
    try:
        # Extract the IP layer from the packet
        ip_layer = packet.getlayer(IP)
        if ip_layer:
            # Extract IP addresses
            source_ip = ip_layer.src
            destination_ip = ip_layer.dst
            
            # Extract the protocol
            protocol = ip_layer.proto
            
            # Extract payload (if available)
            payload = packet.load.decode(errors='ignore') if packet.haslayer(Raw) else ''
            
            # Print packet information
            print(f"Source IP: {source_ip}")
            print(f"Destination IP: {destination_ip}")
            print(f"Protocol: {protocol}")
            print(f"Payload: {payload}")
            print("-" * 40)
    
    except Exception as e:
        print(f"Error: {e}")

# Start sniffing packets
def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=packet_callback, store=0)

# Entry point
if __name__ == "__main__":
    # Specify the network interface if needed, e.g., "eth0" for Ethernet, "wlan0" for Wi-Fi
    network_interface = None
    start_sniffing(network_interface)
