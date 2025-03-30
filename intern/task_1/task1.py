from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import pandas as pd
from IPython.display import display, clear_output
import time
import csv
import os
import threading
import ipaddress

class NetworkSniffer:
    def __init__(self, max_packets=100, output_file=None, filter_string="ip"):
        """
        Initialize the network sniffer.
        
        Args:
            max_packets (int): Maximum number of packets to capture
            output_file (str): File path to save captured data (CSV format)
            filter_string (str): Berkeley Packet Filter string
        """
        self.packet_data = []
        self.max_packets = max_packets
        self.output_file = output_file
        self.filter_string = filter_string
        self.stop_flag = threading.Event()
        self.known_services = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            23: "Telnet",
            21: "FTP",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            53: "DNS",
            67: "DHCP",
            3389: "RDP"
        }
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "unique_ips": set(),
            "start_time": None,
            "end_time": None
        }
    
    def packet_callback(self, packet):
        """Process captured packets and store relevant information."""
        if not packet.haslayer(IP):
            return
        
        # Update statistics
        self.stats["total_packets"] += 1
        
        # Extract basic information
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        
        # Add IPs to unique set
        self.stats["unique_ips"].add(src_ip)
        self.stats["unique_ips"].add(dst_ip)
        
        # Identify IP type
        try:
            src_ip_type = "Private" if ipaddress.ip_address(src_ip).is_private else "Public"
            dst_ip_type = "Private" if ipaddress.ip_address(dst_ip).is_private else "Public"
        except:
            src_ip_type = "Unknown"
            dst_ip_type = "Unknown"
        
        # Identify protocol and ports
        if packet.haslayer(TCP):
            self.stats["tcp_packets"] += 1
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto_name = "TCP"
            
            # Check for known services
            service_src = self.known_services.get(src_port, "")
            service_dst = self.known_services.get(dst_port, "")
            
            # Get TCP flags
            flags = []
            if packet[TCP].flags.S: flags.append("SYN")
            if packet[TCP].flags.A: flags.append("ACK")
            if packet[TCP].flags.F: flags.append("FIN")
            if packet[TCP].flags.R: flags.append("RST")
            if packet[TCP].flags.P: flags.append("PSH")
            tcp_flags = ",".join(flags) if flags else "None"
            
        elif packet.haslayer(UDP):
            self.stats["udp_packets"] += 1
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto_name = "UDP"
            
            # Check for known services
            service_src = self.known_services.get(src_port, "")
            service_dst = self.known_services.get(dst_port, "")
            tcp_flags = "N/A"
            
        elif packet.haslayer(ICMP):
            self.stats["icmp_packets"] += 1
            src_port = "N/A"
            dst_port = "N/A"
            proto_name = "ICMP"
            service_src = ""
            service_dst = ""
            tcp_flags = "N/A"
            
        else:
            self.stats["other_packets"] += 1
            src_port = "Unknown"
            dst_port = "Unknown"
            proto_name = f"Other ({packet[IP].proto})"
            service_src = ""
            service_dst = ""
            tcp_flags = "N/A"
        
        # Append packet data
        self.packet_data.append([
            timestamp, 
            proto_name, 
            src_ip, 
            src_ip_type,
            src_port, 
            service_src,
            dst_ip, 
            dst_ip_type,
            dst_port,
            service_dst,
            packet_size,
            tcp_flags
        ])
        
        # Update display
        self.update_display()
        
        # Save data if requested
        if self.output_file and len(self.packet_data) % 10 == 0:
            self.save_to_csv()
        
        # Check if we've reached the maximum number of packets
        if len(self.packet_data) >= self.max_packets:
            self.stop_flag.set()
    
    def update_display(self):
        """Update the display with current packet data."""
        df = pd.DataFrame(
            self.packet_data, 
            columns=[
                "Timestamp", "Protocol", 
                "Source IP", "Source IP Type", "Source Port", "Source Service",
                "Destination IP", "Destination IP Type", "Destination Port", "Destination Service",
                "Packet Size (B)", "TCP Flags"
            ]
        )
        
        clear_output(wait=True)
        
        # Display statistics
        print(f"Captured packets: {len(self.packet_data)}/{self.max_packets}")
        print(f"TCP: {self.stats['tcp_packets']} | UDP: {self.stats['udp_packets']} | "
              f"ICMP: {self.stats['icmp_packets']} | Other: {self.stats['other_packets']}")
        print(f"Unique IPs: {len(self.stats['unique_ips'])}")
        
        # Display dataframe
        display(df.tail(10))
    
    def save_to_csv(self):
        """Save captured packets to CSV file."""
        if not self.output_file:
            return
            
        try:
            df = pd.DataFrame(
                self.packet_data, 
                columns=[
                    "Timestamp", "Protocol", 
                    "Source IP", "Source IP Type", "Source Port", "Source Service",
                    "Destination IP", "Destination IP Type", "Destination Port", "Destination Service",
                    "Packet Size (B)", "TCP Flags"
                ]
            )
            df.to_csv(self.output_file, index=False)
            print(f"Data saved to {self.output_file}")
        except Exception as e:
            print(f"Error saving to CSV: {e}")
    
    def start_capture(self):
        """Start packet capture."""
        try:
            print(f"Starting network sniffer with filter: '{self.filter_string}'")
            print(f"Press Ctrl+C to stop capturing...")
            
            self.stats["start_time"] = datetime.now()
            
            # Start sniffing with stop condition
            sniff(
                filter=self.filter_string,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda p: self.stop_flag.is_set()
            )
            
        except Exception as e:
            print(f"Error during packet capture: {e}")
        finally:
            self.stats["end_time"] = datetime.now()
            self.print_summary()
            
            if self.output_file:
                self.save_to_csv()
    
    def print_summary(self):
        """Print summary of captured traffic."""
        if not self.stats["start_time"]:
            return
            
        duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()
        
        print("\n===== Capture Summary =====")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total packets: {self.stats['total_packets']}")
        print(f"Packet rate: {self.stats['total_packets']/duration:.2f} packets/sec")
        print(f"Protocol distribution:")
        print(f"  - TCP: {self.stats['tcp_packets']} ({self.stats['tcp_packets']/max(1, self.stats['total_packets'])*100:.1f}%)")
        print(f"  - UDP: {self.stats['udp_packets']} ({self.stats['udp_packets']/max(1, self.stats['total_packets'])*100:.1f}%)")
        print(f"  - ICMP: {self.stats['icmp_packets']} ({self.stats['icmp_packets']/max(1, self.stats['total_packets'])*100:.1f}%)")
        print(f"  - Other: {self.stats['other_packets']} ({self.stats['other_packets']/max(1, self.stats['total_packets'])*100:.1f}%)")
        print(f"Unique IP addresses: {len(self.stats['unique_ips'])}")
        
# Example usage
if __name__ == "__main__":
    # Create sniffer with limited packet count and output file
    sniffer = NetworkSniffer(
        max_packets=100,
        output_file="network_capture.csv",
        filter_string="ip"  # Capture all IP traffic
    )
    
    # Start capturing
    sniffer.start_capture()