"""
Platform-specific utilities for cross-OS compatibility
-----------------------------------------------------
This module provides platform detection and utilities for
ensuring compatibility across Windows, Linux, and macOS.
"""

import os
import sys
import time  # Added missing import
import platform
import socket
import logging
import subprocess
import re
import psutil
from pathlib import Path
from enhanced_logging import get_logger

# Get logger for this module
logger = get_logger('platform_utils')

class PlatformDetector:
    """Class for detecting platform and providing platform-specific utilities"""
    
    def __init__(self):
        """Initialize the platform detector"""
        self.os_name = platform.system().lower()
        self.os_version = platform.version()
        self.is_windows = self.os_name == 'windows'
        self.is_linux = self.os_name == 'linux'
        self.is_macos = self.os_name == 'darwin'
        self.python_version = platform.python_version()
        
        logger.info(f"Detected platform: {self.os_name} {self.os_version}")
        logger.info(f"Python version: {self.python_version}")
    
    def get_platform_info(self):
        """Get detailed platform information"""
        return {
            'os_name': self.os_name,
            'os_version': self.os_version,
            'is_windows': self.is_windows,
            'is_linux': self.is_linux,
            'is_macos': self.is_macos,
            'python_version': self.python_version,
            'processor': platform.processor(),
            'machine': platform.machine(),
            'node': platform.node(),
            'release': platform.release()
        }
    
    def is_admin(self):
        """Check if the current process has administrator privileges"""
        try:
            if self.is_windows:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def normalize_path(self, path):
        """Normalize a path for the current platform"""
        # Convert to Path object for cross-platform handling
        return str(Path(path))
    
    def get_home_dir(self):
        """Get the user's home directory"""
        return str(Path.home())
    
    def get_temp_dir(self):
        """Get the system's temporary directory"""
        import tempfile
        return tempfile.gettempdir()
    
    def get_app_data_dir(self, app_name):
        """Get the application data directory"""
        if self.is_windows:
            base_dir = os.environ.get('APPDATA', self.get_home_dir())
            return os.path.join(base_dir, app_name)
        elif self.is_macos:
            return os.path.join(self.get_home_dir(), 'Library', 'Application Support', app_name)
        else:  # Linux and others
            base_dir = os.environ.get('XDG_DATA_HOME', os.path.join(self.get_home_dir(), '.local', 'share'))
            return os.path.join(base_dir, app_name)
    
    def get_config_dir(self, app_name):
        """Get the configuration directory"""
        if self.is_windows:
            return self.get_app_data_dir(app_name)
        elif self.is_macos:
            return os.path.join(self.get_home_dir(), 'Library', 'Preferences', app_name)
        else:  # Linux and others
            base_dir = os.environ.get('XDG_CONFIG_HOME', os.path.join(self.get_home_dir(), '.config'))
            return os.path.join(base_dir, app_name)
    
    def get_log_dir(self, app_name):
        """Get the log directory"""
        if self.is_windows:
            base_dir = os.environ.get('LOCALAPPDATA', os.path.join(self.get_home_dir(), 'AppData', 'Local'))
            return os.path.join(base_dir, app_name, 'Logs')
        elif self.is_macos:
            return os.path.join(self.get_home_dir(), 'Library', 'Logs', app_name)
        else:  # Linux and others
            base_dir = os.environ.get('XDG_STATE_HOME', os.path.join(self.get_home_dir(), '.local', 'state'))
            return os.path.join(base_dir, app_name, 'logs')

class NetworkInterfaceManager:
    """Class for managing network interfaces across platforms"""
    
    def __init__(self, platform_detector=None):
        """Initialize the network interface manager"""
        self.platform_detector = platform_detector or PlatformDetector()
        self.interfaces = {}
        self.preferred_interfaces = []
        self.refresh_interfaces()
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        try:
            if self.platform_detector.is_windows:
                self._get_windows_interfaces()
            elif self.platform_detector.is_linux:
                self._get_linux_interfaces()
            elif self.platform_detector.is_macos:
                self._get_macos_interfaces()
            else:
                self._get_fallback_interfaces()
            
            logger.info(f"Detected {len(self.interfaces)} network interfaces")
            logger.debug(f"Interfaces: {list(self.interfaces.keys())}")
            
            # Set preferred interfaces
            self._set_preferred_interfaces()
        
        except Exception as e:
            logger.error(f"Error refreshing network interfaces: {e}")
            # Fall back to socket-based detection
            self._get_fallback_interfaces()
    
    def _get_windows_interfaces(self):
        """Get network interfaces on Windows"""
        self.interfaces = {}
        
        try:
            # First try using psutil (more reliable)
            if hasattr(psutil, 'net_if_addrs'):
                net_if_addrs = psutil.net_if_addrs()
                for interface_name, addresses in net_if_addrs.items():
                    ip_addresses = []
                    mac_address = None
                    
                    for addr in addresses:
                        if addr.family == socket.AF_INET:  # IPv4
                            ip_addresses.append(addr.address)
                        elif addr.family == psutil.AF_LINK:  # MAC
                            mac_address = addr.address
                    
                    if ip_addresses:  # Only add interfaces with IP addresses
                        self.interfaces[interface_name] = {
                            'name': interface_name,
                            'addresses': ip_addresses,
                            'mac': mac_address
                        }
                        
                        # Determine interface type
                        if 'wi-fi' in interface_name.lower() or 'wireless' in interface_name.lower():
                            self.interfaces[interface_name]['type'] = 'wireless'
                        elif 'ethernet' in interface_name.lower() or 'local area connection' in interface_name.lower():
                            self.interfaces[interface_name]['type'] = 'ethernet'
                        elif 'bluetooth' in interface_name.lower():
                            self.interfaces[interface_name]['type'] = 'bluetooth'
                        elif 'loopback' in interface_name.lower() or 'localhost' in interface_name.lower():
                            self.interfaces[interface_name]['type'] = 'loopback'
                        else:
                            self.interfaces[interface_name]['type'] = 'unknown'
                
                # If we found interfaces, return
                if self.interfaces:
                    return
            
            # Fallback to ipconfig
            output = subprocess.check_output('ipconfig /all', shell=True).decode('utf-8', errors='ignore')
            
            # Parse ipconfig output
            current_adapter = None
            for line in output.split('\n'):
                line = line.strip()
                
                # Check for adapter name
                if line.endswith(':') and not line.startswith('   '):
                    current_adapter = line[:-1].strip()
                    self.interfaces[current_adapter] = {'name': current_adapter, 'addresses': []}
                
                # Check for IPv4 address
                elif current_adapter and 'IPv4 Address' in line:
                    # Extract IP address
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        self.interfaces[current_adapter]['addresses'].append(ip)
                
                # Check for MAC address
                elif current_adapter and 'Physical Address' in line:
                    # Extract MAC address
                    match = re.search(r'([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})', line)
                    if match:
                        mac = match.group(1)
                        self.interfaces[current_adapter]['mac'] = mac
                
                # Check for description
                elif current_adapter and 'Description' in line:
                    # Extract description
                    match = re.search(r'Description[.\s]*:\s*(.+)', line)
                    if match:
                        description = match.group(1)
                        self.interfaces[current_adapter]['description'] = description
            
            # Filter out adapters without IP addresses
            self.interfaces = {k: v for k, v in self.interfaces.items() if v.get('addresses')}
            
            # Add interface type based on name/description
            for name, interface in self.interfaces.items():
                if 'wi-fi' in name.lower() or 'wireless' in name.lower():
                    interface['type'] = 'wireless'
                elif 'ethernet' in name.lower() or 'local area connection' in name.lower():
                    interface['type'] = 'ethernet'
                elif 'bluetooth' in name.lower():
                    interface['type'] = 'bluetooth'
                elif 'loopback' in name.lower() or 'localhost' in name.lower():
                    interface['type'] = 'loopback'
                else:
                    interface['type'] = 'unknown'
        
        except Exception as e:
            logger.error(f"Error getting Windows interfaces: {e}")
            # Fall back to socket-based detection
            self._get_fallback_interfaces()
    
    def _get_linux_interfaces(self):
        """Get network interfaces on Linux"""
        self.interfaces = {}
        
        try:
            # First try using psutil (more reliable)
            if hasattr(psutil, 'net_if_addrs'):
                net_if_addrs = psutil.net_if_addrs()
                for interface_name, addresses in net_if_addrs.items():
                    ip_addresses = []
                    mac_address = None
                    
                    for addr in addresses:
                        if addr.family == socket.AF_INET:  # IPv4
                            ip_addresses.append(addr.address)
                        elif addr.family == psutil.AF_LINK:  # MAC
                            mac_address = addr.address
                    
                    if ip_addresses:  # Only add interfaces with IP addresses
                        self.interfaces[interface_name] = {
                            'name': interface_name,
                            'addresses': ip_addresses,
                            'mac': mac_address
                        }
                        
                        # Determine interface type
                        if interface_name.startswith('wl'):
                            self.interfaces[interface_name]['type'] = 'wireless'
                        elif interface_name.startswith('en') or interface_name.startswith('eth'):
                            self.interfaces[interface_name]['type'] = 'ethernet'
                        elif interface_name.startswith('br'):
                            self.interfaces[interface_name]['type'] = 'bridge'
                        elif interface_name.startswith('lo'):
                            self.interfaces[interface_name]['type'] = 'loopback'
                        elif interface_name.startswith('tun') or interface_name.startswith('tap'):
                            self.interfaces[interface_name]['type'] = 'virtual'
                        else:
                            self.interfaces[interface_name]['type'] = 'unknown'
                
                # If we found interfaces, return
                if self.interfaces:
                    return
            
            # Fallback to ip command
            output = subprocess.check_output('ip addr show', shell=True).decode('utf-8', errors='ignore')
            
            # Parse ip addr output
            current_interface = None
            for line in output.split('\n'):
                line = line.strip()
                
                # Check for interface name
                if line.startswith(tuple(str(i) + ':' for i in range(10))):
                    parts = line.split(':', 2)
                    if len(parts) >= 2:
                        current_interface = parts[1].strip()
                        self.interfaces[current_interface] = {'name': current_interface, 'addresses': []}
                
                # Check for IPv4 address
                elif current_interface and 'inet ' in line:
                    # Extract IP address
                    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        self.interfaces[current_interface]['addresses'].append(ip)
                
                # Check for MAC address
                elif current_interface and 'link/ether' in line:
                    # Extract MAC address
                    match = re.search(r'link/ether\s+([0-9a-f:]{17})', line)
                    if match:
                        mac = match.group(1)
                        self.interfaces[current_interface]['mac'] = mac
            
            # Filter out interfaces without IP addresses
            self.interfaces = {k: v for k, v in self.interfaces.items() if v.get('addresses')}
            
            # Add interface type based on name
            for name, interface in self.interfaces.items():
                if name.startswith('wl'):
                    interface['type'] = 'wireless'
                elif name.startswith('en') or name.startswith('eth'):
                    interface['type'] = 'ethernet'
                elif name.startswith('br'):
                    interface['type'] = 'bridge'
                elif name.startswith('lo'):
                    interface['type'] = 'loopback'
                elif name.startswith('tun') or name.startswith('tap'):
                    interface['type'] = 'virtual'
                else:
                    interface['type'] = 'unknown'
        
        except Exception as e:
            logger.error(f"Error getting Linux interfaces: {e}")
            # Fall back to socket-based detection
            self._get_fallback_interfaces()
    
    def _get_macos_interfaces(self):
        """Get network interfaces on macOS"""
        self.interfaces = {}
        
        try:
            # First try using psutil (more reliable)
            if hasattr(psutil, 'net_if_addrs'):
                net_if_addrs = psutil.net_if_addrs()
                for interface_name, addresses in net_if_addrs.items():
                    ip_addresses = []
                    mac_address = None
                    
                    for addr in addresses:
                        if addr.family == socket.AF_INET:  # IPv4
                            ip_addresses.append(addr.address)
                        elif addr.family == psutil.AF_LINK:  # MAC
                            mac_address = addr.address
                    
                    if ip_addresses:  # Only add interfaces with IP addresses
                        self.interfaces[interface_name] = {
                            'name': interface_name,
                            'addresses': ip_addresses,
                            'mac': mac_address
                        }
                        
                        # Determine interface type
                        if interface_name.startswith('en0') or interface_name.startswith('en1'):
                            self.interfaces[interface_name]['type'] = 'wireless'
                        elif interface_name.startswith('en'):
                            self.interfaces[interface_name]['type'] = 'ethernet'
                        elif interface_name.startswith('bridge'):
                            self.interfaces[interface_name]['type'] = 'bridge'
                        elif interface_name.startswith('lo'):
                            self.interfaces[interface_name]['type'] = 'loopback'
                        elif interface_name.startswith('utun'):
                            self.interfaces[interface_name]['type'] = 'virtual'
                        else:
                            self.interfaces[interface_name]['type'] = 'unknown'
                
                # If we found interfaces, return
                if self.interfaces:
                    return
            
            # Fallback to ifconfig
            output = subprocess.check_output('ifconfig', shell=True).decode('utf-8', errors='ignore')
            
            # Parse ifconfig output
            current_interface = None
            for line in output.split('\n'):
                line = line.strip()
                
                # Check for interface name
                if line and not line.startswith(('\t', ' ')):
                    parts = line.split(':', 1)
                    if len(parts) >= 1:
                        current_interface = parts[0].strip()
                        self.interfaces[current_interface] = {'name': current_interface, 'addresses': []}
                
                # Check for IPv4 address
                elif current_interface and 'inet ' in line:
                    # Extract IP address
                    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        ip = match.group(1)
                        self.interfaces[current_interface]['addresses'].append(ip)
                
                # Check for MAC address
                elif current_interface and 'ether ' in line:
                    # Extract MAC address
                    match = re.search(r'ether\s+([0-9a-f:]{17})', line)
                    if match:
                        mac = match.group(1)
                        self.interfaces[current_interface]['mac'] = mac
            
            # Filter out interfaces without IP addresses
            self.interfaces = {k: v for k, v in self.interfaces.items() if v.get('addresses')}
            
            # Add interface type based on name
            for name, interface in self.interfaces.items():
                if name.startswith('en0') or name.startswith('en1'):
                    interface['type'] = 'wireless'
                elif name.startswith('en'):
                    interface['type'] = 'ethernet'
                elif name.startswith('bridge'):
                    interface['type'] = 'bridge'
                elif name.startswith('lo'):
                    interface['type'] = 'loopback'
                elif name.startswith('utun'):
                    interface['type'] = 'virtual'
                else:
                    interface['type'] = 'unknown'
        
        except Exception as e:
            logger.error(f"Error getting macOS interfaces: {e}")
            # Fall back to socket-based detection
            self._get_fallback_interfaces()
    
    def _get_fallback_interfaces(self):
        """Fallback method to get network interfaces using socket"""
        self.interfaces = {}
        
        try:
            # Get hostname and IP address
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            
            # Create a fallback interface
            self.interfaces['default'] = {
                'name': 'default',
                'addresses': [ip_address],
                'type': 'unknown'
            }
            
            # Try to get all addresses
            try:
                addresses = socket.getaddrinfo(hostname, None)
                all_ips = set()
                for addr in addresses:
                    if addr[0] == socket.AF_INET:  # IPv4
                        all_ips.add(addr[4][0])
                
                self.interfaces['default']['addresses'] = list(all_ips)
            except:
                pass
        
        except Exception as e:
            logger.error(f"Error getting fallback interfaces: {e}")
            # Create a dummy interface as last resort
            self.interfaces['dummy'] = {
                'name': 'dummy',
                'addresses': ['127.0.0.1'],
                'type': 'loopback'
            }
    
    def _set_preferred_interfaces(self):
        """Set preferred interfaces based on type and availability"""
        # Order: wireless, ethernet, others
        wireless = []
        ethernet = []
        others = []
        
        for name, interface in self.interfaces.items():
            if interface.get('type') == 'wireless':
                wireless.append(name)
            elif interface.get('type') == 'ethernet':
                ethernet.append(name)
            elif interface.get('type') != 'loopback':  # Exclude loopback
                others.append(name)
        
        # Set preferred order
        self.preferred_interfaces = wireless + ethernet + others
    
    def get_interfaces(self):
        """Get all network interfaces"""
        return self.interfaces
    
    def get_interface_names(self):
        """Get names of all network interfaces"""
        return list(self.interfaces.keys())
    
    def get_preferred_interface(self):
        """Get the preferred interface for packet capture"""
        if not self.preferred_interfaces:
            return None
        
        return self.preferred_interfaces[0]
    
    def get_interface_by_name(self, name):
        """Get interface by name"""
        # Direct match
        if name in self.interfaces:
            return self.interfaces[name]
        
        # Case-insensitive match
        for interface_name, interface in self.interfaces.items():
            if interface_name.lower() == name.lower():
                return interface
        
        # Partial match
        for interface_name, interface in self.interfaces.items():
            if name.lower() in interface_name.lower():
                return interface
        
        # Match by type
        if name.lower() == 'wifi' or name.lower() == 'wireless':
            for interface in self.interfaces.values():
                if interface.get('type') == 'wireless':
                    return interface
        
        if name.lower() == 'ethernet':
            for interface in self.interfaces.values():
                if interface.get('type') == 'ethernet':
                    return interface
        
        return None

class MemoryMonitor:
    """Class for monitoring memory usage"""
    
    def __init__(self, platform_detector=None, memory_limit_mb=None):
        """Initialize the memory monitor"""
        self.platform_detector = platform_detector or PlatformDetector()
        
        # Set memory limit (default to 70% of system memory)
        if memory_limit_mb is None:
            total_memory = psutil.virtual_memory().total / (1024 * 1024)  # MB
            self.memory_limit_mb = int(total_memory * 0.7)
        else:
            self.memory_limit_mb = memory_limit_mb
        
        logger.info(f"Memory limit set to {self.memory_limit_mb} MB")
    
    def get_memory_stats(self):
        """Get current memory statistics"""
        try:
            # Get process memory usage
            process = psutil.Process(os.getpid())
            process_memory = process.memory_info().rss / (1024 * 1024)  # MB
            
            # Get system memory usage
            system_memory = psutil.virtual_memory()
            system_used = system_memory.used / (1024 * 1024)  # MB
            system_total = system_memory.total / (1024 * 1024)  # MB
            system_percent = system_memory.percent
            
            return {
                'process_mb': process_memory,
                'system_used_mb': system_used,
                'system_total_mb': system_total,
                'system_percent': system_percent,
                'limit_mb': self.memory_limit_mb,
                'usage_percent': (process_memory / self.memory_limit_mb) * 100 if self.memory_limit_mb > 0 else 0
            }
        
        except Exception as e:
            logger.error(f"Error getting memory stats: {e}")
            return {
                'process_mb': 0,
                'system_used_mb': 0,
                'system_total_mb': 0,
                'system_percent': 0,
                'limit_mb': self.memory_limit_mb,
                'usage_percent': 0
            }
    
    def is_memory_critical(self):
        """Check if memory usage is critical"""
        stats = self.get_memory_stats()
        return stats['usage_percent'] > 90
    
    def is_memory_high(self):
        """Check if memory usage is high"""
        stats = self.get_memory_stats()
        return stats['usage_percent'] > 80

def get_platform_detector():
    """Get a platform detector instance"""
    return PlatformDetector()

def get_network_interface_manager():
    """Get a network interface manager instance"""
    return NetworkInterfaceManager()

def get_memory_monitor(memory_limit_mb=None):
    """Get a memory monitor instance"""
    return MemoryMonitor(memory_limit_mb=memory_limit_mb)
