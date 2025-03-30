from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import pandas as pd
from IPython.display import display, clear_output
import threading
import ipaddress
import re
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import time
import os
from collections import Counter, defaultdict

class NetworkIDS:
    def __init__(self, max_packets=1000, output_file=None, filter_string="ip", alert_log="ids_alerts.log"):
        """
        Initialize the Network Intrusion Detection System.
        
        Args:
            max_packets (int): Maximum number of packets to capture
            output_file (str): File path to save captured data (CSV format)
            filter_string (str): Berkeley Packet Filter string
            alert_log (str): File to log security alerts
        """
        # Basic configuration
        self.packet_data = []
        self.max_packets = max_packets
        self.output_file = output_file
        self.filter_string = filter_string
        self.alert_log = alert_log
        self.stop_flag = threading.Event()
        
        # Service identification
        self.known_services = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 23: "Telnet", 21: "FTP",
            25: "SMTP", 110: "POP3", 143: "IMAP", 53: "DNS", 67: "DHCP",
            3389: "RDP", 445: "SMB", 139: "NetBIOS", 8080: "HTTP-ALT",
            1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
            6379: "Redis", 11211: "Memcached", 9200: "Elasticsearch",
            161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 636: "LDAPS"
        }
        
        # Statistics and tracking
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "unique_ips": set(),
            "start_time": None,
            "end_time": None,
            "alerts": 0,
            "blocked_ips": set()
        }
        
        # Traffic patterns for anomaly detection
        self.traffic_history = {
            "timestamps": [],
            "packet_counts": [],
            "window_size": 60  # Track traffic in 60-second windows
        }
        
        # Connection tracking for port scan detection
        self.connection_tracker = defaultdict(set)  # src_ip -> set(destination_ports)
        self.scan_threshold = 15  # Number of different ports in a short time to consider a port scan
        
        # SYN flood detection
        self.syn_tracker = defaultdict(int)  # dst_ip -> count of SYN packets
        self.syn_threshold = 30  # Threshold for SYN flood detection
        
        # Setup intrusion detection rules
        self.setup_ids_rules()
        
        # Initialize alert log
        if self.alert_log:
            with open(self.alert_log, 'w') as f:
                f.write(f"=== Network IDS Alert Log - Started at {datetime.now()} ===\n\n")
    
    def setup_ids_rules(self):
        """Setup IDS detection rules."""
        # Common attack patterns (regex)
        self.attack_patterns = {
            # Web attacks
            "sql_injection": re.compile(r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR\s+1=1|\'|\-\-)', re.IGNORECASE),
            "xss": re.compile(r'(?i)(<script>|<img|onerror|javascript:|alert\(|onload=)', re.IGNORECASE),
            "path_traversal": re.compile(r'(?i)(\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/win.ini)', re.IGNORECASE),
            "command_injection": re.compile(r'(?i)(;|\||\`|\$\(|\&\&|system\()', re.IGNORECASE),
            
            # Scanning and recon
            "nmap_scan": re.compile(r'(?i)(nmap|SCAN)', re.IGNORECASE),
            
            # Malware signatures
            "known_malware": re.compile(r'(?i)(trojan|backdoor|rootkit|ransomware)', re.IGNORECASE)
        }
        
        # Blocked or suspicious IP ranges (example)
        self.blocked_ip_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),  # Example - adjust with actual threats
            ipaddress.ip_network("192.168.0.0/16")  # Example - adjust with actual threats
        ]
        
        # Service vulnerability checks
        self.vulnerable_services = {
            21: "Potentially insecure FTP",
            23: "Telnet (insecure protocol)",
            445: "SMB (potential Windows share exploits)",
            3389: "RDP (potential Windows remote access exploits)"
        }
    
    def log_alert(self, alert_type, details, severity="Medium"):
        """Log security alerts."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] ALERT-{severity}: {alert_type} - {details}\n"
        
        # Print to console
        print(f"\033[91m{alert_msg}\033[0m")  # Red color for alerts
        
        # Log to file
        if self.alert_log:
            try:
                with open(self.alert_log, 'a') as f:
                    f.write(alert_msg)
            except Exception as e:
                print(f"Error writing to alert log: {e}")
        
        # Update statistics
        self.stats["alerts"] += 1
    
    def check_payload_for_attacks(self, packet, src_ip, dst_ip):
        """Check packet payload for attack signatures."""
        if not packet.haslayer(Raw):
            return
        
        # Get the raw payload data
        payload = str(packet[Raw].load)
        
        # Check for each attack pattern
        for attack_name, pattern in self.attack_patterns.items():
            if pattern.search(payload):
                self.log_alert(
                    f"Potential {attack_name} attack", 
                    f"From {src_ip} to {dst_ip}, Matched pattern: {pattern.pattern}",
                    "High"
                )
                return True
        
        return False
    
    def check_for_port_scan(self, src_ip, dst_ip, dst_port):
        """Detect potential port scanning activity."""
        # Add the destination port to the set of ports this source has connected to
        self.connection_tracker[src_ip].add(dst_port)
        
        # If the source has connected to too many different ports, flag as a port scan
        if len(self.connection_tracker[src_ip]) >= self.scan_threshold:
            ports = sorted(list(self.connection_tracker[src_ip]))
            self.log_alert(
                "Port Scan Detected", 
                f"Source {src_ip} has connected to {len(ports)} different ports on {dst_ip}. "
                f"Sample ports: {ports[:10]}...",
                "High"
            )
            
            # Reset the tracking for this IP to avoid continuous alerts
            self.connection_tracker[src_ip] = set()
            return True
        
        return False
    
    def check_for_syn_flood(self, dst_ip, flags):
        """Detect potential SYN flood attacks."""
        if "SYN" in flags and "ACK" not in flags:
            self.syn_tracker[dst_ip] += 1
            
            if self.syn_tracker[dst_ip] >= self.syn_threshold:
                self.log_alert(
                    "Potential SYN Flood Attack", 
                    f"Target {dst_ip} has received {self.syn_tracker[dst_ip]} SYN packets "
                    f"without ACK in a short period",
                    "Critical"
                )
                
                # Reset counter to avoid continuous alerts
                self.syn_tracker[dst_ip] = 0
                return True
        
        return False
    
    def check_suspicious_ip(self, ip_addr):
        """Check if an IP is in a blocked or suspicious range."""
        try:
            ip = ipaddress.ip_address(ip_addr)
            
            # Check against blocked ranges
            for network in self.blocked_ip_ranges:
                if ip in network:
                    if ip_addr not in self.stats["blocked_ips"]:
                        self.log_alert(
                            "Connection with Blocked IP", 
                            f"IP {ip_addr} is in blocked range {network}",
                            "High"
                        )
                        self.stats["blocked_ips"].add(ip_addr)
                    return True
            
            return False
        except:
            return False
    
    def check_vulnerable_service(self, port, src_ip, dst_ip):
        """Check if the traffic involves potentially vulnerable services."""
        if port in self.vulnerable_services:
            self.log_alert(
                "Vulnerable Service", 
                f"{self.vulnerable_services[port]} detected - {src_ip}:{port} to {dst_ip}",
                "Medium"
            )
            return True
        
        return False
    
    def detect_traffic_anomalies(self):
        """Detect sudden spikes in network traffic."""
        current_time = time.time()
        self.traffic_history["timestamps"].append(current_time)
        self.traffic_history["packet_counts"].append(self.stats["total_packets"])
        
        # Only analyze if we have enough data points
        if len(self.traffic_history["timestamps"]) < 5:
            return
        
        # Remove old data points
        cutoff_time = current_time - self.traffic_history["window_size"]
        while self.traffic_history["timestamps"] and self.traffic_history["timestamps"][0] < cutoff_time:
            self.traffic_history["timestamps"].pop(0)
            self.traffic_history["packet_counts"].pop(0)
        
        # Check for sudden traffic spikes
        if len(self.traffic_history["packet_counts"]) >= 3:
            recent_avg = self.traffic_history["packet_counts"][-1] - self.traffic_history["packet_counts"][-3]
            if recent_avg > 100:  # Arbitrary threshold, adjust based on network
                self.log_alert(
                    "Traffic Anomaly", 
                    f"Unusual spike in network traffic: {recent_avg} packets in a short period",
                    "Medium"
                )
    
    def packet_callback(self, packet):
        """Process captured packets for IDS analysis."""
        if not packet.haslayer(IP):
            return
        
        # Update statistics
        self.stats["total_packets"] += 1
        
        # Extract basic information
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        
        # Detect traffic anomalies periodically
        if self.stats["total_packets"] % 50 == 0:
            self.detect_traffic_anomalies()
        
        # Add IPs to unique set
        self.stats["unique_ips"].add(src_ip)
        self.stats["unique_ips"].add(dst_ip)
        
        # Check for suspicious IPs
        is_suspicious_src = self.check_suspicious_ip(src_ip)
        is_suspicious_dst = self.check_suspicious_ip(dst_ip)
        
        # Identify IP type
        try:
            src_ip_type = "Private" if ipaddress.ip_address(src_ip).is_private else "Public"
            dst_ip_type = "Private" if ipaddress.ip_address(dst_ip).is_private else "Public"
        except:
            src_ip_type = "Unknown"
            dst_ip_type = "Unknown"
        
        threat_detected = False
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
            
            # Intrusion detection checks
            threat_detected |= self.check_for_port_scan(src_ip, dst_ip, dst_port)
            threat_detected |= self.check_for_syn_flood(dst_ip, flags)
            threat_detected |= self.check_payload_for_attacks(packet, src_ip, dst_ip)
            threat_detected |= self.check_vulnerable_service(dst_port, src_ip, dst_ip)
            
        elif packet.haslayer(UDP):
            self.stats["udp_packets"] += 1
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto_name = "UDP"
            
            # Check for known services
            service_src = self.known_services.get(src_port, "")
            service_dst = self.known_services.get(dst_port, "")
            tcp_flags = "N/A"
            
            # Intrusion detection checks
            threat_detected |= self.check_vulnerable_service(dst_port, src_ip, dst_ip)
            threat_detected |= self.check_payload_for_attacks(packet, src_ip, dst_ip)
            
        elif packet.haslayer(ICMP):
            self.stats["icmp_packets"] += 1
            src_port = "N/A"
            dst_port = "N/A"
            proto_name = "ICMP"
            service_src = ""
            service_dst = ""
            tcp_flags = "N/A"
            
            # Check for ICMP flood
            if self.stats["icmp_packets"] % 10 == 0:
                self.log_alert("ICMP Traffic", f"High volume of ICMP packets detected", "Low")
                threat_detected = True
            
        else:
            self.stats["other_packets"] += 1
            src_port = "Unknown"
            dst_port = "Unknown"
            proto_name = f"Other ({packet[IP].proto})"
            service_src = ""
            service_dst = ""
            tcp_flags = "N/A"
        
        # Threat level
        threat_level = "High" if threat_detected or is_suspicious_src or is_suspicious_dst else "None"
        
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
            tcp_flags,
            threat_level
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
        """Update the display with current packet data and IDS status."""
        df = pd.DataFrame(
            self.packet_data, 
            columns=[
                "Timestamp", "Protocol", 
                "Source IP", "Source IP Type", "Source Port", "Source Service",
                "Destination IP", "Destination IP Type", "Destination Port", "Destination Service",
                "Packet Size (B)", "TCP Flags", "Threat Level"
            ]
        )
        
        clear_output(wait=True)
        
        # Display IDS banner
        print(f"\033[94m{'='*50}\033[0m")
        print(f"\033[94m   NETWORK INTRUSION DETECTION SYSTEM\033[0m")
        print(f"\033[94m{'='*50}\033[0m")
        
        # Display statistics
        print(f"Captured packets: {len(self.packet_data)}/{self.max_packets}")
        print(f"TCP: {self.stats['tcp_packets']} | UDP: {self.stats['udp_packets']} | "
              f"ICMP: {self.stats['icmp_packets']} | Other: {self.stats['other_packets']}")
        print(f"Unique IPs: {len(self.stats['unique_ips'])}")
        print(f"Security alerts: {self.stats['alerts']}")
        print(f"Blocked IPs: {len(self.stats['blocked_ips'])}")
        
        # Highlight threats in the dataframe
        def highlight_threats(row):
            if row['Threat Level'] == 'High':
                return ['background-color: #ffcccc'] * len(row)
            return [''] * len(row)
        
        # Display dataframe
        display(df.tail(10).style.apply(highlight_threats, axis=1))
    
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
                    "Packet Size (B)", "TCP Flags", "Threat Level"
                ]
            )
            df.to_csv(self.output_file, index=False)
            print(f"Data saved to {self.output_file}")
        except Exception as e:
            print(f"Error saving to CSV: {e}")
    
    def generate_visualizations(self):
        """Generate visualizations of the network traffic and detected threats."""
        if not self.packet_data:
            print("No data to visualize.")
            return
            
        df = pd.DataFrame(
            self.packet_data, 
            columns=[
                "Timestamp", "Protocol", 
                "Source IP", "Source IP Type", "Source Port", "Source Service",
                "Destination IP", "Destination IP Type", "Destination Port", "Destination Service",
                "Packet Size (B)", "TCP Flags", "Threat Level"
            ]
        )
        
        # Convert timestamp to datetime for plotting
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Create a figure with subplots
        plt.figure(figsize=(20, 15))
        
        # 1. Protocol distribution pie chart
        plt.subplot(2, 2, 1)
        protocol_counts = df['Protocol'].value_counts()
        plt.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', startangle=90)
        plt.title('Protocol Distribution')
        
        # 2. Traffic volume over time
        plt.subplot(2, 2, 2)
        df.set_index('Timestamp').resample('10S').size().plot(marker='o')
        plt.title('Network Traffic Volume Over Time')
        plt.ylabel('Number of Packets')
        plt.grid(True)
        
        # 3. Top Source IPs
        plt.subplot(2, 3, 4)
        top_src_ips = df['Source IP'].value_counts().head(10)
        sns.barplot(x=top_src_ips.values, y=top_src_ips.index)
        plt.title('Top 10 Source IPs')
        plt.xlabel('Number of Packets')
        
        # 4. Top Destination IPs
        plt.subplot(2, 3, 5)
        top_dst_ips = df['Destination IP'].value_counts().head(10)
        sns.barplot(x=top_dst_ips.values, y=top_dst_ips.index)
        plt.title('Top 10 Destination IPs')
        plt.xlabel('Number of Packets')
        
        # 5. Threat distribution
        plt.subplot(2, 3, 6)
        threat_counts = df['Threat Level'].value_counts()
        colors = ['green' if level == 'None' else 'red' for level in threat_counts.index]
        sns.barplot(x=threat_counts.index, y=threat_counts.values, palette=colors)
        plt.title('Threat Distribution')
        plt.ylabel('Number of Packets')
        
        plt.tight_layout()
        
        # Save the visualization
        viz_file = "ids_visualization.png"
        plt.savefig(viz_file)
        plt.close()
        
        print(f"Visualizations saved to {viz_file}")
        
        # Also create a visualization of detected threats over time
        if df[df['Threat Level'] != 'None'].shape[0] > 0:
            plt.figure(figsize=(15, 6))
            
            # Group by timestamp and count threats
            threat_df = df[df['Threat Level'] != 'None'].copy()
            threat_df['timestamp_minute'] = threat_df['Timestamp'].dt.floor('T')
            threat_counts = threat_df.groupby('timestamp_minute').size()
            
            # Plot threats over time
            plt.plot(threat_counts.index, threat_counts.values, 'r-o', linewidth=2)
            plt.title('Security Alerts Over Time')
            plt.ylabel('Number of Alerts')
            plt.grid(True)
            
            # Save the threat visualization
            threat_viz_file = "ids_threats_over_time.png"
            plt.savefig(threat_viz_file)
            plt.close()
            
            print(f"Threat timeline visualization saved to {threat_viz_file}")
    
    def start_capture(self):
        """Start packet capture with intrusion detection."""
        try:
            print(f"\033[94m{'='*50}\033[0m")
            print(f"\033[94m   NETWORK INTRUSION DETECTION SYSTEM\033[0m")
            print(f"\033[94m{'='*50}\033[0m")
            print(f"Starting NIDS with filter: '{self.filter_string}'")
            print(f"Press Ctrl+C to stop capturing...\n")
            
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
            
            # Generate visualizations
            self.generate_visualizations()
    
    def print_summary(self):
        """Print summary of captured traffic and security alerts."""
        if not self.stats["start_time"]:
            return
            
        duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()
        
        print("\n===== NIDS Capture Summary =====")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total packets: {self.stats['total_packets']}")
        print(f"Packet rate: {self.stats['total_packets']/max(1, duration):.2f} packets/sec")
        print(f"Protocol distribution:")
        print(f"  - TCP: {self.stats['tcp_packets']} ({self.stats['tcp_packets']/max(1, self.stats['total_packets'])*100:.1f}%)")
        print(f"  - UDP: {self.stats['udp_packets']} ({self.stats['udp_packets']/max(1, self.stats['total_packets'])*100:.1f}%)")
        print(f"  - ICMP: {self.stats['icmp_packets']} ({self.stats['icmp_packets']/max(1, self.stats['total_packets'])*100:.1f}%)")
        print(f"  - Other: {self.stats['other_packets']} ({self.stats['other_packets']/max(1, self.stats['total_packets'])*100:.1f}%)")
        print(f"Unique IP addresses: {len(self.stats['unique_ips'])}")
        print(f"Security alerts: {self.stats['alerts']}")
        
        # Count threats by level
        if self.packet_data:
            df = pd.DataFrame(
                self.packet_data, 
                columns=[
                    "Timestamp", "Protocol", 
                    "Source IP", "Source IP Type", "Source Port", "Source Service",
                    "Destination IP", "Destination IP Type", "Destination Port", "Destination Service",
                    "Packet Size (B)", "TCP Flags", "Threat Level"
                ]
            )
            threat_counts = df['Threat Level'].value_counts()
            print("\nThreat distribution:")
            for level, count in threat_counts.items():
                print(f"  - {level}: {count} ({count/len(df)*100:.1f}%)")

# Example usage in Jupyter Notebook
if __name__ == "__main__":
    # Create and start the Network IDS
    ids = NetworkIDS(
        max_packets=200,
        output_file="ids_capture.csv",
        filter_string="ip",
        alert_log="ids_alerts.log"
    )
    
    # Start the IDS
    ids.start_capture()