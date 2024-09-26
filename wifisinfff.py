## WIFI SNIFFER BY UZAIR UL HAQ ##



from scapy.all import *  # Import everything from the scapy library
import os  # Import os module to interact with the operating system

def packet_handler(packet):
    """
    Handle each captured packet.
    If the packet has a Dot11 layer, extract and print relevant information.
    """
    if packet.haslayer(Dot11):
        # Get the MAC addresses
        source_mac = packet.addr2  # MAC address of the device sending the packet
        dest_mac = packet.addr1    # MAC address of the access point
        packet_type = packet.type    # Type of the packet (Data, Control, Management)

        # Print the extracted information
        print(f"Packet Type: {packet_type}, Source: {source_mac}, Destination: {dest_mac}")

def start_sniffer(interface):
    """
    Start the packet sniffing process on the specified network interface.
    """
    print(f"Starting Wi-Fi sniffer on {interface}...")
    # Sniff packets, calling packet_handler for each captured packet
    sniff(iface=interface, prn=packet_handler, store=0)

if __name__ == "__main__":
    # Specify your Wi-Fi interface name (change 'wlan0' to your interface)
    interface = 'wlan0'  # For example: wlan0, eth0, etc.

    # Ensure the interface is set to managed mode (optional based on your setup)
    os.system(f"iw dev {interface} set type managed")
    os.system(f"ifconfig {interface} up")  # Bring the interface up
    
    # Start the packet sniffer
    start_sniffer(interface)
