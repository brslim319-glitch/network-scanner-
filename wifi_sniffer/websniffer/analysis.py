from scapy.all import (
    sniff, IP, TCP, UDP, ARP, DNS, Raw, Ether, ICMP
)
from collections import defaultdict, deque
import time
import re
import dns.resolver
from datetime import datetime, timedelta
import json
import requests
import logging
from config import Config
import os

class PacketAnalyzer:
    def __init__(self, socketio):
        self.socketio = socketio
        self.packet_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.arp_cache = {}
        self.syn_flood_detector = SYNFloodDetector()
        self.dns_tunnel_detector = DNSTunnelDetector()
        self.password_detector = PasswordDetector()
        self.suspicious_domain_detector = SuspiciousDomainDetector()
        
        # Time-based statistics
        self.time_window = 60  # seconds
        self.packet_history = deque(maxlen=1000)
        
        # Initialize logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
    def analyze_packet(self, packet):
        try:
            timestamp = datetime.now()
            self.packet_history.append((timestamp, packet))
            
            # Basic packet analysis
            packet_data = self._extract_basic_info(packet)
            if not packet_data:
                return
                
            # Update statistics
            self._update_statistics(packet_data)
            
            # Threat detection
            self._detect_threats(packet, packet_data)
            
            # Emit packet data to frontend
            self.socketio.emit('packet', packet_data)
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
        
    def _extract_basic_info(self, packet):
        try:
            data = {'timestamp': datetime.now().isoformat()}
            
            if packet.haslayer(IP):
                data['src'] = packet[IP].src
                data['dst'] = packet[IP].dst
                data['length'] = len(packet)
                
                if packet.haslayer(TCP):
                    data['proto'] = 'TCP'
                    data['sport'] = packet[TCP].sport
                    data['dport'] = packet[TCP].dport
                    data['flags'] = packet[TCP].flags
                    data['info'] = f"TCP {packet[TCP].sport} -> {packet[TCP].dport}"
                elif packet.haslayer(UDP):
                    data['proto'] = 'UDP'
                    data['sport'] = packet[UDP].sport
                    data['dport'] = packet[UDP].dport
                    data['info'] = f"UDP {packet[UDP].sport} -> {packet[UDP].dport}"
                else:
                    data['proto'] = 'IP'
                    data['info'] = 'IP'
            elif packet.haslayer(ARP):
                data['src'] = packet[ARP].psrc
                data['dst'] = packet[ARP].pdst
                data['proto'] = 'ARP'
                data['op'] = packet[ARP].op
                data['info'] = f"ARP {packet[ARP].op}"
            else:
                return None
                
            return data
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
        
    def _update_statistics(self, packet_data):
        try:
            # Update protocol statistics
            self.protocol_stats[packet_data['proto']] += 1
            
            # Update IP statistics
            if 'src' in packet_data:
                self.ip_stats[packet_data['src']] += 1
            if 'dst' in packet_data:
                self.ip_stats[packet_data['dst']] += 1
                
            # Emit updated statistics
            self.socketio.emit('stats_update', {
                'protocols': dict(self.protocol_stats),
                'top_ips': dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10])
            })
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
        
    def _detect_threats(self, packet, packet_data):
        try:
            # ARP Spoofing Detection
            if packet_data['proto'] == 'ARP':
                self._detect_arp_spoofing(packet)
                
            # SYN Flood Detection
            if packet_data['proto'] == 'TCP' and packet_data.get('flags') == 'S':
                self.syn_flood_detector.detect(packet, self.socketio)
                
            # DNS Tunneling Detection
            if packet_data['proto'] == 'UDP' and packet_data.get('dport') == 53:
                self.dns_tunnel_detector.detect(packet, self.socketio)
                
            # Password Detection
            if packet_data['proto'] in ['TCP', 'UDP']:
                self.password_detector.detect(packet, self.socketio)
                
            # Suspicious Domain Detection
            if packet_data['proto'] == 'UDP' and packet_data.get('dport') == 53:
                self.suspicious_domain_detector.detect(packet, self.socketio)
        except Exception as e:
            self.logger.error(f"Error detecting threats: {e}")

class SYNFloodDetector:
    def __init__(self):
        self.syn_counts = defaultdict(int)
        self.last_reset = time.time()
        self.logger = logging.getLogger(__name__)
        
    def detect(self, packet, socketio):
        try:
            current_time = time.time()
            if current_time - self.last_reset > 1:  # Reset every second
                self.syn_counts.clear()
                self.last_reset = current_time
                
            src_ip = packet[IP].src
            self.syn_counts[src_ip] += 1
            
            if self.syn_counts[src_ip] > Config.ALERT_THRESHOLDS['syn_flood']:
                socketio.emit('alert', {
                    'type': 'syn_flood',
                    'severity': 'high',
                    'source_ip': src_ip,
                    'description': f'SYN flood detected from {src_ip}'
                })
        except Exception as e:
            self.logger.error(f"Error in SYN flood detection: {e}")

class DNSTunnelDetector:
    def __init__(self):
        self.dns_counts = defaultdict(int)
        self.last_reset = time.time()
        self.logger = logging.getLogger(__name__)
        
    def detect(self, packet, socketio):
        try:
            if not packet.haslayer(DNS):
                return
                
            current_time = time.time()
            if current_time - self.last_reset > 1:
                self.dns_counts.clear()
                self.last_reset = current_time
                
            src_ip = packet[IP].src
            self.dns_counts[src_ip] += 1
            
            if self.dns_counts[src_ip] > Config.ALERT_THRESHOLDS['dns_tunnel']:
                socketio.emit('alert', {
                    'type': 'dns_tunnel',
                    'severity': 'medium',
                    'source_ip': src_ip,
                    'description': f'Possible DNS tunneling from {src_ip}'
                })
        except Exception as e:
            self.logger.error(f"Error in DNS tunnel detection: {e}")

class PasswordDetector:
    def __init__(self):
        self.password_patterns = [
            rb'password\s*=\s*[\w@#$%^&*]+',
            rb'passwd\s*=\s*[\w@#$%^&*]+',
            rb'pwd\s*=\s*[\w@#$%^&*]+',
            rb'pass\s*=\s*[\w@#$%^&*]+'
        ]
        self.logger = logging.getLogger(__name__)
        
    def detect(self, packet, socketio):
        try:
            if not packet.haslayer(Raw):
                return
                
            payload = bytes(packet[Raw].load)
            for pattern in self.password_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    socketio.emit('alert', {
                        'type': 'password_exposure',
                        'severity': 'high',
                        'source_ip': packet[IP].src,
                        'destination_ip': packet[IP].dst,
                        'description': 'Cleartext password detected in traffic'
                    })
                    break
        except Exception as e:
            self.logger.error(f"Error in password detection: {e}")

class SuspiciousDomainDetector:
    def __init__(self):
        self.suspicious_domains = set()
        self.logger = logging.getLogger(__name__)
        self._load_suspicious_domains()
        
    def _load_suspicious_domains(self):
        try:
            # Create a local cache file for suspicious domains
            cache_file = os.path.join(Config.DATA_DIR, 'suspicious_domains.txt')
            
            # If cache doesn't exist, try to download
            if not os.path.exists(cache_file):
                try:
                    response = requests.get('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', timeout=10)
                    if response.status_code == 200:
                        with open(cache_file, 'w') as f:
                            f.write(response.text)
                except Exception as e:
                    self.logger.error(f"Error downloading suspicious domains: {e}")
                    return
            
            # Load domains from cache
            try:
                with open(cache_file, 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            domain = line.split()[1]
                            self.suspicious_domains.add(domain)
            except Exception as e:
                self.logger.error(f"Error reading suspicious domains cache: {e}")
                
        except Exception as e:
            self.logger.error(f"Error loading suspicious domains: {e}")
            
    def detect(self, packet, socketio):
        try:
            if not packet.haslayer(DNS):
                return
                
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # DNS query
                domain = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                if domain in self.suspicious_domains:
                    socketio.emit('alert', {
                        'type': 'suspicious_domain',
                        'severity': 'medium',
                        'source_ip': packet[IP].src,
                        'description': f'Suspicious domain query: {domain}'
                    })
        except Exception as e:
            self.logger.error(f"Error in suspicious domain detection: {e}") 