from tkinter import *
from tkinter.scrolledtext import ScrolledText
from scapy.all import *
import time
import threading

# Create the GUI window
root = Tk()
root.title("Packet Sniffer")
root.geometry("800x600")

# Variables for statistical analysis
start_time = 0
packet_count = 0
protocols = {}
capture_thread = None  # Variable to hold the capture thread
stop_capture_flag = False  # Flag to signal the capture thread to stop

def packet_sniffer(packet):
    global packet_count, protocols

    # Count the number of packets
    packet_count += 1

    # Extract the protocol from the captured packet
    if IP in packet:
        protocol = packet[IP].proto
        if protocol in protocols:
            protocols[protocol]["count"] += 1
        else:
            protocols[protocol] = {"count": 1, "name": packet[IP].name}

        # Extract additional information based on the protocol
        if protocol == 6:  # TCP
            protocols[protocol]["source_port"] = packet[TCP].sport
            protocols[protocol]["destination_port"] = packet[TCP].dport
        elif protocol == 17:  # UDP
            protocols[protocol]["source_port"] = packet[UDP].sport
            protocols[protocol]["destination_port"] = packet[UDP].dport

        # Update the GUI with the captured packet details
        update_gui(packet)


def update_gui(packet):
    eth_frame = packet.getlayer(Ether)
    ip_packet = packet.getlayer(IP)
    tcp_segment = packet.getlayer(TCP)

    text_area.insert(END, "----- Ethernet Frame -----\n")
    text_area.insert(
        END,
        f"- Destination: {eth_frame.dst}, Source: {eth_frame.src}, Protocol: {eth_frame.proto}\n",
    )

    text_area.insert(END, "----- IPv4 Packet -----\n")
    text_area.insert(
        END,
        f"- Version: {ip_packet.version}, Header Length: {ip_packet.ihl * 4}, TTL: {ip_packet.ttl}\n",
    )
    text_area.insert(
        END,
        f"- Protocol: {ip_packet.proto}, Source: {ip_packet.src}, Target: {ip_packet.dst}\n",
    )

    if tcp_segment:
        text_area.insert(END, "----- TCP Segment -----\n")
        text_area.insert(END, f"- Source Port: {tcp_segment.sport}, Destination Port: {tcp_segment.dport}\n")
        text_area.insert(END, f"- Sequence: {tcp_segment.seq}, Acknowledgment: {tcp_segment.ack}\n")
        text_area.insert(END, "- Flags:\n")
        flags_summary = str(tcp_segment.flags)
        text_area.insert(END, f"  - {flags_summary}\n")

    if Raw in packet:
        text_area.insert(END, f"- Data: {packet[Raw].load}\n")

    text_area.insert(END, "\n")


def get_protocol_name(packet):
    if IP in packet:
        protocol = packet[IP].proto
        if protocol in protocols:
            return protocols[protocol]["name"]
    return "Unknown"


def get_port_name(packet, port_type):
    if IP in packet:
        protocol = packet[IP].proto
        if protocol in protocols:
            port = protocols[protocol].get(f"{port_type}_port")
            if port:
                return f"{port} ({get_service_name(protocol, port)})"
    return "Unknown"


def get_service_name(protocol, port):
    try:
        if protocol == 6:  # TCP
            return socket.getservbyport(port, "tcp")
        elif protocol == 17:  # UDP
            return socket.getservbyport(port, "udp")
    except OSError:
        pass
    return "Unknown"


def start_capture():
    global start_time, packet_count, protocols, capture_thread, stop_capture_flag

    if capture_thread is None or not capture_thread.is_alive():
        # Reset variables
        start_time = time.time()
        packet_count = 0
        protocols = {}
        stop_capture_flag = False  # Reset the stop flag

        # Create a new thread for packet capture
        capture_thread = threading.Thread(target=run_capture)
        capture_thread.start()


def stop_capture():
    global stop_capture_flag

    stop_capture_flag = True  # Set the flag to stop the capture


def run_capture():
    sniff(filter="ip", prn=packet_sniffer, store=0, stop_filter=stop_capture_condition)


def stop_capture_condition(packet):
    global stop_capture_flag

    return stop_capture_flag


def display_statistics():
    global start_time, packet_count, protocols

    elapsed_time = time.time() - start_time

    text_area.insert(END, "----- Capture Statistics -----\n")
    text_area.insert(END, f"Total Packets Captured: {packet_count}\n")
    text_area.insert(END, f"Capture Duration: {elapsed_time:.2f} seconds\n")
    text_area.insert(END, "\n")

    text_area.insert(END, "----- Protocol Statistics -----\n")
    for protocol, data in protocols.items():
        text_area.insert(END, f"Protocol: {data['name']}\n")
        text_area.insert(END, f"Packets Count: {data['count']}\n")
        if "source_port" in data:
            text_area.insert(END, f"Source Port: {data['source_port']}\n")
        if "destination_port" in data:
            text_area.insert(END, f"Destination Port: {data['destination_port']}\n")
        text_area.insert(END, "\n")


# Create a text area to display the captured packets
text_area = ScrolledText(root)
text_area.pack(expand=True, fill=BOTH)

# Create a button to start packet capture
capture_button = Button(root, text="Start Capture", command=start_capture)
capture_button.pack(side=LEFT)

# Create a button to stop packet capture
stop_button = Button(root, text="Stop Capture", command=stop_capture)
stop_button.pack(side=LEFT)

# Create a button to display capture statistics
stats_button = Button(root, text="Capture Statistics", command=display_statistics)
stats_button.pack(side=LEFT)

# Start the GUI event loop
root.mainloop()