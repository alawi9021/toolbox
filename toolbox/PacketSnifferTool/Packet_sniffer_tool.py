import argparse
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    """Callback function to process each sniffed packet with basic details."""
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            print(f"[+] Packet: {ip_src} -> {ip_dst} (Protocol: {proto})")

            if TCP in packet or UDP in packet:
                sport = packet.sport
                dport = packet.dport
                print(f"    [+] Source Port: {sport}, Destination Port: {dport}")

        else:
            print("[+] Non-IP packet captured.")
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(interface, count):
    """Starts sniffing packets on the specified network interface."""
    try:
        print(f"Starting packet capture on interface {interface}... Press Ctrl+C to stop.")
        sniff(iface=interface, prn=packet_callback, count=count)
        print("Packet capture completed.")
    except PermissionError:
        print("Error: Permission denied. Run the script as root or with sufficient privileges.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="A simple packet sniffer using Scapy.")
    parser.add_argument("-i", "--interface", required=True, help="The network interface to sniff packets on.")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default: 0 for unlimited).")

    args = parser.parse_args()

    
    if args.count < 0:
        print("Error: The count must be a non-negative integer.")
        return

    
    start_sniffing(args.interface, args.count)

if __name__ == "__main__":
    main()


