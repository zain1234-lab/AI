"""
Packet sniffing module with cross-platform support
-------------------------------------------------
This module provides robust packet capture functionality
with support for Windows, Linux, and macOS.
"""

import os
import time
import socket
import struct
import threading
import logging
from datetime import datetime
from enhanced_logging import get_logger, track_performance, with_context
from platform_utils import get_platform_detector, get_network_interface_manager
from advanced_feature_engineering import get_feature_extractor

# Get logger for this module
logger = get_logger('packet_sniffing')

# Get platform utilities
platform_detector = get_platform_detector()
network_manager = get_network_interface_manager()

class PacketSniffer:
    """Class for capturing and processing network packets"""
    
    def __init__(self, callback=None, interface=None):
        """Initialize the packet sniffer"""
        self.callback = callback
        self.interface = interface
        self.running = False
        self.socket = None
        self.thread = None
        self.packet_count = 0
        self.start_time = None
        self.feature_extractor = get_feature_extractor()
        
        # Initialize platform-specific settings
        self._init_platform_settings()
    
    def _init_platform_settings(self):
        """Initialize platform-specific settings"""
        self.is_windows = platform_detector.is_windows
        self.is_linux = platform_detector.is_linux
        self.is_macos = platform_detector.is_macos
        
        # Set default interface if not specified
        if not self.interface:
            self.interface = network_manager.get_preferred_interface()
            if self.interface:
                logger.info(f"Using preferred interface: {self.interface}")
            else:
                logger.warning("No preferred interface found, will use default")
    
    def start(self, interface=None):
        """Start packet sniffing"""
        if self.running:
            logger.warning("Packet sniffer already running")
            return False
        
        # Update interface if specified
        if interface:
            self.interface = interface
        
        # If still no interface, try to find one
        if not self.interface:
            interfaces = network_manager.get_interface_names()
            if interfaces:
                self.interface = interfaces[0]
                logger.info(f"Using first available interface: {self.interface}")
            else:
                logger.error("No network interfaces found")
                return False
        
        # Start sniffing thread
        try:
            self.running = True
            self.start_time = time.time()
            self.packet_count = 0
            
            # Create and start thread
            self.thread = threading.Thread(target=self._sniff_packets)
            self.thread.daemon = True
            self.thread.start()
            
            logger.info(f"Started packet sniffing on interface {self.interface}")
            return True
        
        except Exception as e:
            logger.error(f"Error starting packet sniffer: {e}")
            self.running = False
            return False
    
    def stop(self):
        """Stop packet sniffing"""
        if not self.running:
            logger.warning("Packet sniffer not running")
            return False
        
        try:
            self.running = False
            
            # Close socket if open
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            
            # Wait for thread to terminate
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=1.0)
            
            logger.info(f"Stopped packet sniffing (captured {self.packet_count} packets)")
            return True
        
        except Exception as e:
            logger.error(f"Error stopping packet sniffer: {e}")
            return False
    
    def _sniff_packets(self):
        """Main packet sniffing loop"""
        try:
            # Create raw socket based on platform
            if self.is_windows:
                self._sniff_packets_windows()
            elif self.is_linux or self.is_macos:
                self._sniff_packets_unix()
            else:
                logger.error(f"Unsupported platform: {platform_detector.os_name}")
                self.running = False
        
        except Exception as e:
            logger.error(f"Error in packet sniffing loop: {e}")
            self.running = False
    
    def _sniff_packets_windows(self):
        """Packet sniffing implementation for Windows"""
        try:
            # Try to import winpcap/npcap libraries
            try:
                from scapy.all import sniff
                
                def packet_callback(packet):
                    if not self.running:
                        return
                    
                    try:
                        # Process packet with scapy
                        packet_dict = self._process_scapy_packet(packet)
                        
                        # Update packet count
                        self.packet_count += 1
                        
                        # Call callback if provided
                        if self.callback and packet_dict:
                            self.callback(packet_dict)
                    
                    except Exception as e:
                        logger.error(f"Error processing packet: {e}")
                
                # Start sniffing
                logger.info(f"Starting scapy sniffing on interface {self.interface}")
                sniff(iface=self.interface, prn=packet_callback, store=0, stop_filter=lambda p: not self.running)
            
            except ImportError:
                # Fallback to socket-based sniffing
                logger.warning("Scapy not available, falling back to socket-based sniffing")
                self._sniff_packets_socket_fallback()
        
        except Exception as e:
            logger.error(f"Error in Windows packet sniffing: {e}")
            self.running = False
    
    def _sniff_packets_unix(self):
        """Packet sniffing implementation for Unix-like systems"""
        try:
            # Try to use scapy first
            try:
                from scapy.all import sniff
                
                def packet_callback(packet):
                    if not self.running:
                        return
                    
                    try:
                        # Process packet with scapy
                        packet_dict = self._process_scapy_packet(packet)
                        
                        # Update packet count
                        self.packet_count += 1
                        
                        # Call callback if provided
                        if self.callback and packet_dict:
                            self.callback(packet_dict)
                    
                    except Exception as e:
                        logger.error(f"Error processing packet: {e}")
                
                # Start sniffing
                logger.info(f"Starting scapy sniffing on interface {self.interface}")
                sniff(iface=self.interface, prn=packet_callback, store=0, stop_filter=lambda p: not self.running)
            
            except ImportError:
                # Fallback to raw socket
                logger.warning("Scapy not available, falling back to raw socket sniffing")
                self._sniff_packets_raw_socket()
        
        except Exception as e:
            logger.error(f"Error in Unix packet sniffing: {e}")
            self.running = False
    
    def _sniff_packets_raw_socket(self):
        """Packet sniffing using raw sockets"""
        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            # Bind to interface if specified
            if self.interface:
                self.socket.bind((self.interface, 0))
            
            logger.info(f"Started raw socket sniffing on interface {self.interface}")
            
            # Main sniffing loop
            while self.running:
                # Receive packet
                packet_data = self.socket.recv(65535)
                
                # Process packet
                packet_dict = self._process_raw_packet(packet_data)
                
                # Update packet count
                self.packet_count += 1
                
                # Call callback if provided
                if self.callback and packet_dict:
                    self.callback(packet_dict)
        
        except Exception as e:
            logger.error(f"Error in raw socket sniffing: {e}")
            self.running = False
    
    def _sniff_packets_socket_fallback(self):
        """Fallback packet sniffing using basic sockets"""
        try:
            # Create a raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Bind to interface
            if self.interface:
                # Get IP address of interface
                interface_info = network_manager.get_interface_by_name(self.interface)
                if interface_info and interface_info.get('addresses'):
                    ip_address = interface_info['addresses'][0]
                    self.socket.bind((ip_address, 0))
            
            # Include IP headers
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Receive all packets
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            logger.info(f"Started fallback socket sniffing on interface {self.interface}")
            
            # Main sniffing loop
            while self.running:
                # Receive packet
                packet_data = self.socket.recv(65535)
                
                # Process packet
                packet_dict = self._process_ip_packet(packet_data)
                
                # Update packet count
                self.packet_count += 1
                
                # Call callback if provided
                if self.callback and packet_dict:
                    self.callback(packet_dict)
            
            # Turn off promiscuous mode
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        except Exception as e:
            logger.error(f"Error in fallback socket sniffing: {e}")
            self.running = False
    
    def _process_scapy_packet(self, packet):
        """Process a packet captured with scapy"""
        try:
            packet_dict = {}
            
            # Get current time
            packet_dict['timestamp'] = time.time()
            packet_dict['packet_time'] = packet_dict['timestamp']
            
            # Extract Ethernet layer if present
            if hasattr(packet, 'src') and hasattr(packet, 'dst'):
                packet_dict['eth_src'] = packet.src
                packet_dict['eth_dst'] = packet.dst
            
            # Extract IP layer if present
            if hasattr(packet, 'payload') and hasattr(packet.payload, 'src') and hasattr(packet.payload, 'dst'):
                packet_dict['src_ip'] = packet.payload.src
                packet_dict['dst_ip'] = packet.payload.dst
                packet_dict['protocol'] = packet.payload.proto if hasattr(packet.payload, 'proto') else 0
            
            # Extract TCP/UDP layer if present
            if hasattr(packet, 'payload') and hasattr(packet.payload, 'payload'):
                transport = packet.payload.payload
                if hasattr(transport, 'sport') and hasattr(transport, 'dport'):
                    packet_dict['src_port'] = transport.sport
                    packet_dict['dst_port'] = transport.dport
                
                # Extract TCP flags if present
                if hasattr(transport, 'flags'):
                    packet_dict['flags'] = transport.flags
            
            # Get packet size
            packet_dict['packet_size'] = len(packet) if hasattr(packet, '__len__') else 0
            
            return packet_dict
        
        except Exception as e:
            logger.error(f"Error processing scapy packet: {e}")
            return None
    
    def _process_raw_packet(self, packet_data):
        """Process a raw packet"""
        try:
            packet_dict = {}
            
            # Get current time
            packet_dict['timestamp'] = time.time()
            packet_dict['packet_time'] = packet_dict['timestamp']
            
            # Extract Ethernet header
            eth_length = 14
            eth_header = packet_data[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)
            
            # Extract source and destination MAC addresses
            packet_dict['eth_src'] = self._format_mac(packet_data[6:12])
            packet_dict['eth_dst'] = self._format_mac(packet_data[0:6])
            
            # Check if IP packet (EtherType = 0x0800)
            if eth[2] == 0x0800:
                # Extract IP header
                ip_header = packet_data[eth_length:20+eth_length]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                # Extract IP information
                version_ihl = iph[0]
                ihl = version_ihl & 0xF
                ip_header_length = ihl * 4
                
                packet_dict['protocol'] = iph[6]
                packet_dict['src_ip'] = socket.inet_ntoa(iph[8])
                packet_dict['dst_ip'] = socket.inet_ntoa(iph[9])
                
                # Extract TCP/UDP header
                if packet_dict['protocol'] == 6:  # TCP
                    t = ip_header_length + eth_length
                    tcp_header = packet_data[t:t+20]
                    
                    if len(tcp_header) >= 20:
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        
                        packet_dict['src_port'] = tcph[0]
                        packet_dict['dst_port'] = tcph[1]
                        packet_dict['flags'] = tcph[5]
                
                elif packet_dict['protocol'] == 17:  # UDP
                    u = ip_header_length + eth_length
                    udp_header = packet_data[u:u+8]
                    
                    if len(udp_header) >= 8:
                        udph = struct.unpack('!HHHH', udp_header)
                        
                        packet_dict['src_port'] = udph[0]
                        packet_dict['dst_port'] = udph[1]
            
            # Get packet size
            packet_dict['packet_size'] = len(packet_data)
            
            return packet_dict
        
        except Exception as e:
            logger.error(f"Error processing raw packet: {e}")
            return None
    
    def _process_ip_packet(self, packet_data):
        """Process an IP packet"""
        try:
            packet_dict = {}
            
            # Get current time
            packet_dict['timestamp'] = time.time()
            packet_dict['packet_time'] = packet_dict['timestamp']
            
            # Extract IP header
            ip_header = packet_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            # Extract IP information
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            ip_header_length = ihl * 4
            
            packet_dict['protocol'] = iph[6]
            packet_dict['src_ip'] = socket.inet_ntoa(iph[8])
            packet_dict['dst_ip'] = socket.inet_ntoa(iph[9])
            
            # Extract TCP/UDP header
            if packet_dict['protocol'] == 6:  # TCP
                tcp_header = packet_data[ip_header_length:ip_header_length+20]
                
                if len(tcp_header) >= 20:
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    
                    packet_dict['src_port'] = tcph[0]
                    packet_dict['dst_port'] = tcph[1]
                    packet_dict['flags'] = tcph[5]
            
            elif packet_dict['protocol'] == 17:  # UDP
                udp_header = packet_data[ip_header_length:ip_header_length+8]
                
                if len(udp_header) >= 8:
                    udph = struct.unpack('!HHHH', udp_header)
                    
                    packet_dict['src_port'] = udph[0]
                    packet_dict['dst_port'] = udph[1]
            
            # Get packet size
            packet_dict['packet_size'] = len(packet_data)
            
            return packet_dict
        
        except Exception as e:
            logger.error(f"Error processing IP packet: {e}")
            return None
    
    def _format_mac(self, mac_bytes):
        """Format MAC address bytes to string"""
        return ':'.join('{:02x}'.format(b) for b in mac_bytes)
    
    def get_stats(self):
        """Get packet sniffing statistics"""
        duration = time.time() - self.start_time if self.start_time else 0
        
        return {
            'running': self.running,
            'interface': self.interface,
            'packet_count': self.packet_count,
            'duration': duration,
            'packets_per_second': self.packet_count / duration if duration > 0 else 0
        }

class PacketProcessor:
    """Class for processing captured packets"""
    
    def __init__(self, model_integration=None):
        """Initialize the packet processor"""
        self.model_integration = model_integration
        self.feature_extractor = get_feature_extractor()
        self.processed_count = 0
        self.attack_count = 0
        self.last_packets = []
        self.max_stored_packets = 100
    
    def process_packet(self, packet_dict):
        """Process a packet and detect attacks"""
        try:
            # Extract features
            with track_performance(logger, "Feature extraction"):
                features = self.feature_extractor.extract_features(packet_dict)
            
            # Store basic packet info
            basic_info = {
                'timestamp': packet_dict.get('timestamp', time.time()),
                'src_ip': packet_dict.get('src_ip', ''),
                'dst_ip': packet_dict.get('dst_ip', ''),
                'src_port': packet_dict.get('src_port', 0),
                'dst_port': packet_dict.get('dst_port', 0),
                'protocol': packet_dict.get('protocol', 0),
                'size': packet_dict.get('packet_size', 0)
            }
            
            # Detect attacks if model integration is available
            result = {
                'is_attack': False,
                'attack_type': 'Unknown',
                'confidence': 0.0,
                'detector': 'None'
            }
            
            if self.model_integration:
                with track_performance(logger, "Attack detection"):
                    result = self.model_integration.detect(features)
            
            # Update counters
            self.processed_count += 1
            if result['is_attack']:
                self.attack_count += 1
            
            # Combine results
            packet_result = {**basic_info, **result}
            
            # Store packet
            self._store_packet(packet_result)
            
            return packet_result
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None
    
    def _store_packet(self, packet_result):
        """Store packet result in history"""
        self.last_packets.append(packet_result)
        
        # Limit the number of stored packets
        if len(self.last_packets) > self.max_stored_packets:
            self.last_packets.pop(0)
    
    def get_last_packets(self, count=None):
        """Get the last processed packets"""
        if count is None or count >= len(self.last_packets):
            return self.last_packets
        return self.last_packets[-count:]
    
    def get_stats(self):
        """Get packet processing statistics"""
        return {
            'processed_count': self.processed_count,
            'attack_count': self.attack_count,
            'attack_rate': self.attack_count / self.processed_count if self.processed_count > 0 else 0
        }

# Create singleton instances
packet_sniffer = PacketSniffer()
packet_processor = PacketProcessor()

# Functions to get singleton instances
def get_packet_sniffer():
    """Get the singleton packet sniffer instance"""
    return packet_sniffer

def get_packet_processor():
    """Get the singleton packet processor instance"""
    return packet_processor

def set_model_integration(model_integration):
    """Set the model integration for packet processing"""
    global packet_processor
    packet_processor = PacketProcessor(model_integration)
    return packet_processor
