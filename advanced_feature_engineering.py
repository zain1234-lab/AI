"""
Advanced feature extraction and mapping for intrusion detection
--------------------------------------------------------------
This module provides robust feature extraction from network packets
and mapping between training data and live packet features.
"""

import os
import re
import time
import pickle
import logging
import numpy as np
import pandas as pd
from collections import defaultdict
from enhanced_logging import get_logger

# Get logger for this module
logger = get_logger('feature_engineering')

class FeatureNormalizer:
    """Class for normalizing feature names and values"""
    
    def __init__(self):
        """Initialize the feature normalizer"""
        # Common feature name mappings - expanded to handle more variations
        self.name_mappings = {
            # IP features
            'source': 'src_ip',
            'src': 'src_ip',
            'source ip': 'src_ip',
            'src ip': 'src_ip',
            'source_ip': 'src_ip',
            'destination': 'dst_ip',
            'dst': 'dst_ip',
            'destination ip': 'dst_ip',
            'dst ip': 'dst_ip',
            'destination_ip': 'dst_ip',
            
            # Port features
            'source port': 'src_port',
            'src port': 'src_port',
            'src_port': 'src_port',
            'source.port': 'src_port',
            'destination port': 'dst_port',
            'dst port': 'dst_port',
            'dst_port': 'dst_port',
            'destination.port': 'dst_port',
            
            # Protocol features
            'protocol': 'protocol',
            'proto': 'protocol',
            'protocol type': 'protocol',
            'protocol_type': 'protocol',
            'protocol.type': 'protocol',
            
            # Flow features
            'flow duration': 'flow_duration',
            'duration': 'flow_duration',
            'flow_duration': 'flow_duration',
            'flow.duration': 'flow_duration',
            'flow_bytes': 'flow_bytes',
            'bytes': 'flow_bytes',
            'flow.bytes': 'flow_bytes',
            'flow_packets': 'flow_packets',
            'packets': 'flow_packets',
            'flow.packets': 'flow_packets',
            
            # Packet features
            'packet_size': 'packet_size',
            'size': 'packet_size',
            'packet size': 'packet_size',
            'packet.size': 'packet_size',
            'packet_time': 'packet_time',
            'time': 'packet_time',
            'packet time': 'packet_time',
            'packet.time': 'packet_time',
            
            # Flag features
            'flags': 'flags',
            'tcp_flags': 'flags',
            'tcp flags': 'flags',
            'flag': 'flags',
            'tcp.flags': 'flags',
            
            # Label features - expanded to handle more variations
            'label': 'label',
            ' label': 'label',  # With leading space
            'class': 'label',
            'target': 'label',
            'attack_type': 'label',
            'attack type': 'label',
            'attack': 'label',
            'is_attack': 'label',
            'is attack': 'label',
            'malicious': 'label',
            'is_malicious': 'label',
            'category': 'label',
            'type': 'label'
        }
        
        # Regular expressions for feature name normalization
        self.name_patterns = [
            # Convert camelCase to snake_case
            (r'([a-z0-9])([A-Z])', r'\1_\2'),
            
            # Convert spaces to underscores
            (r'\s+', r'_'),
            
            # Remove special characters
            (r'[^a-zA-Z0-9_]', r''),
            
            # Convert to lowercase
            (r'[A-Z]', lambda x: x.group(0).lower())
        ]
    
    def normalize_name(self, name):
        """Normalize a feature name"""
        # Check direct mappings first
        if name.lower() in self.name_mappings:
            return self.name_mappings[name.lower()]
        
        # Apply regex patterns
        normalized = name
        for pattern, replacement in self.name_patterns:
            normalized = re.sub(pattern, replacement, normalized)
        
        return normalized
    
    def normalize_value(self, value, feature_type=None):
        """Normalize a feature value based on its type"""
        if value is None:
            return 0
        
        if feature_type == 'ip':
            # Convert IP address to numerical value
            try:
                if isinstance(value, str) and '.' in value:
                    return sum(int(octet) * (256 ** i) for i, octet in enumerate(reversed(value.split('.'))))
                return float(value)
            except:
                return 0
        
        elif feature_type == 'port':
            # Ensure port is an integer
            try:
                return int(float(value))
            except:
                return 0
        
        elif feature_type == 'protocol':
            # Convert protocol to integer or keep as is if already numeric
            if isinstance(value, (int, float)):
                return int(value)
            
            # Map common protocol names
            protocol_map = {
                'tcp': 6,
                'udp': 17,
                'icmp': 1,
                'http': 80,
                'https': 443,
                'dns': 53
            }
            
            if isinstance(value, str):
                return protocol_map.get(value.lower(), 0)
            
            return 0
        
        elif feature_type == 'flag':
            # Convert flag string to integer
            if isinstance(value, (int, float)):
                return int(value)
            
            if isinstance(value, str):
                # Sum ASCII values as a simple hash
                return sum(ord(c) for c in value)
            
            return 0
        
        elif feature_type == 'label':
            # Keep label as is if string, otherwise convert to string
            if isinstance(value, str):
                return value
            return str(value)
        
        else:
            # Default numeric conversion
            try:
                if isinstance(value, str) and not value.strip():
                    return 0
                return float(value)
            except:
                return 0

class FeatureMapper:
    """Class for mapping between different feature sets"""
    
    def __init__(self):
        """Initialize the feature mapper"""
        self.normalizer = FeatureNormalizer()
        self.feature_types = {}
        self.cicids_to_packet = {}
        self.packet_to_cicids = {}
        self.default_values = {}
    
    def register_feature_type(self, feature_name, feature_type):
        """Register the type of a feature"""
        normalized_name = self.normalizer.normalize_name(feature_name)
        self.feature_types[normalized_name] = feature_type
    
    def register_feature_mapping(self, cicids_feature, packet_feature, default_value=0):
        """Register a mapping between CICIDS and packet features"""
        normalized_cicids = self.normalizer.normalize_name(cicids_feature)
        normalized_packet = self.normalizer.normalize_name(packet_feature)
        
        self.cicids_to_packet[normalized_cicids] = normalized_packet
        self.packet_to_cicids[normalized_packet] = normalized_cicids
        self.default_values[normalized_cicids] = default_value
    
    def get_feature_type(self, feature_name):
        """Get the type of a feature"""
        normalized_name = self.normalizer.normalize_name(feature_name)
        return self.feature_types.get(normalized_name, None)
    
    def normalize_column_names(self, df):
        """Normalize column names in a DataFrame"""
        normalized_columns = {}
        
        for col in df.columns:
            normalized_col = self.normalizer.normalize_name(col)
            normalized_columns[col] = normalized_col
        
        # Rename columns
        return df.rename(columns=normalized_columns)
    
    def normalize_packet_dict(self, packet_dict):
        """Normalize a packet dictionary"""
        normalized_dict = {}
        
        for key, value in packet_dict.items():
            normalized_key = self.normalizer.normalize_name(key)
            feature_type = self.get_feature_type(normalized_key)
            normalized_value = self.normalizer.normalize_value(value, feature_type)
            normalized_dict[normalized_key] = normalized_value
        
        return normalized_dict
    
    def map_packet_to_cicids(self, packet_dict):
        """Map packet features to CICIDS features"""
        cicids_dict = {}
        
        # Normalize the packet dictionary
        normalized_packet = self.normalize_packet_dict(packet_dict)
        
        # Map to CICIDS features
        for cicids_feature, packet_feature in self.cicids_to_packet.items():
            if packet_feature in normalized_packet:
                cicids_dict[cicids_feature] = normalized_packet[packet_feature]
            else:
                cicids_dict[cicids_feature] = self.default_values.get(cicids_feature, 0)
        
        return cicids_dict
    
    def map_cicids_to_packet(self, cicids_dict):
        """Map CICIDS features to packet features"""
        packet_dict = {}
        
        # Normalize the CICIDS dictionary
        normalized_cicids = {}
        for key, value in cicids_dict.items():
            normalized_key = self.normalizer.normalize_name(key)
            feature_type = self.get_feature_type(normalized_key)
            normalized_value = self.normalizer.normalize_value(value, feature_type)
            normalized_cicids[normalized_key] = normalized_value
        
        # Map to packet features
        for packet_feature, cicids_feature in self.packet_to_cicids.items():
            if cicids_feature in normalized_cicids:
                packet_dict[packet_feature] = normalized_cicids[cicids_feature]
        
        return packet_dict
    
    def prepare_features_for_model(self, packet_dict, selected_features):
        """Prepare packet features for model input"""
        # Map packet to CICIDS features
        cicids_dict = self.map_packet_to_cicids(packet_dict)
        
        # Create a DataFrame with the selected features
        feature_dict = {}
        for feature in selected_features:
            normalized_feature = self.normalizer.normalize_name(feature)
            feature_dict[normalized_feature] = cicids_dict.get(normalized_feature, self.default_values.get(normalized_feature, 0))
        
        return pd.DataFrame([feature_dict])

class FlowTracker:
    """Class for tracking network flows and calculating flow-level features"""
    
    def __init__(self, max_flows=1000, flow_timeout=120):
        """Initialize the flow tracker"""
        self.flows = {}
        self.max_flows = max_flows
        self.flow_timeout = flow_timeout  # seconds
        self.flow_count = 0
    
    def _get_flow_key(self, packet_dict):
        """Get a unique key for a flow"""
        src_ip = packet_dict.get('src_ip', '')
        dst_ip = packet_dict.get('dst_ip', '')
        src_port = packet_dict.get('src_port', 0)
        dst_port = packet_dict.get('dst_port', 0)
        protocol = packet_dict.get('protocol', 0)
        
        # Create a bidirectional flow key (same key regardless of direction)
        if f"{src_ip}:{src_port}" < f"{dst_ip}:{dst_port}":
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def _clean_expired_flows(self, current_time):
        """Clean expired flows"""
        expired_keys = []
        for key, flow in self.flows.items():
            if current_time - flow['last_packet_time'] > self.flow_timeout:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.flows[key]
    
    def update_flow(self, packet_dict):
        """Update flow information with a new packet"""
        current_time = time.time()
        
        # Clean expired flows if we have too many
        if len(self.flows) >= self.max_flows:
            self._clean_expired_flows(current_time)
        
        # Get flow key
        flow_key = self._get_flow_key(packet_dict)
        
        # Get packet information
        packet_size = packet_dict.get('packet_size', 0)
        packet_time = packet_dict.get('packet_time', current_time)
        
        # Update or create flow
        if flow_key in self.flows:
            flow = self.flows[flow_key]
            
            # Update flow statistics
            flow['packet_count'] += 1
            flow['byte_count'] += packet_size
            flow['last_packet_time'] = current_time
            
            # Update packet size statistics
            flow['packet_sizes'].append(packet_size)
            
            # Update inter-arrival time statistics
            if flow['packet_count'] > 1:
                inter_arrival = current_time - flow['prev_packet_time']
                flow['inter_arrival_times'].append(inter_arrival)
            
            flow['prev_packet_time'] = current_time
        else:
            # Create new flow
            self.flows[flow_key] = {
                'flow_id': self.flow_count,
                'start_time': current_time,
                'last_packet_time': current_time,
                'prev_packet_time': current_time,
                'packet_count': 1,
                'byte_count': packet_size,
                'packet_sizes': [packet_size],
                'inter_arrival_times': []
            }
            self.flow_count += 1
        
        return self.flows[flow_key]
    
    def get_flow_features(self, packet_dict):
        """Get flow-level features for a packet"""
        flow_key = self._get_flow_key(packet_dict)
        
        if flow_key not in self.flows:
            # Update flow first
            self.update_flow(packet_dict)
        
        flow = self.flows[flow_key]
        
        # Calculate flow duration
        flow_duration = flow['last_packet_time'] - flow['start_time']
        
        # Calculate packet size statistics
        if flow['packet_sizes']:
            min_packet_size = min(flow['packet_sizes'])
            max_packet_size = max(flow['packet_sizes'])
            mean_packet_size = sum(flow['packet_sizes']) / len(flow['packet_sizes'])
            std_packet_size = np.std(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        else:
            min_packet_size = max_packet_size = mean_packet_size = std_packet_size = 0
        
        # Calculate inter-arrival time statistics
        if flow['inter_arrival_times']:
            min_iat = min(flow['inter_arrival_times'])
            max_iat = max(flow['inter_arrival_times'])
            mean_iat = sum(flow['inter_arrival_times']) / len(flow['inter_arrival_times'])
            std_iat = np.std(flow['inter_arrival_times']) if len(flow['inter_arrival_times']) > 1 else 0
        else:
            min_iat = max_iat = mean_iat = std_iat = 0
        
        # Calculate packet rate and byte rate
        packet_rate = flow['packet_count'] / flow_duration if flow_duration > 0 else 0
        byte_rate = flow['byte_count'] / flow_duration if flow_duration > 0 else 0
        
        # Create feature dictionary
        flow_features = {
            'flow_duration': flow_duration,
            'flow_packets': flow['packet_count'],
            'flow_bytes': flow['byte_count'],
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'min_packet_size': min_packet_size,
            'max_packet_size': max_packet_size,
            'mean_packet_size': mean_packet_size,
            'std_packet_size': std_packet_size,
            'min_iat': min_iat,
            'max_iat': max_iat,
            'mean_iat': mean_iat,
            'std_iat': std_iat
        }
        
        return flow_features

def get_feature_extractor():
    """Get a feature extractor instance"""
    feature_mapper = FeatureMapper()
    
    # Register feature types
    feature_mapper.register_feature_type('src_ip', 'ip')
    feature_mapper.register_feature_type('dst_ip', 'ip')
    feature_mapper.register_feature_type('src_port', 'port')
    feature_mapper.register_feature_type('dst_port', 'port')
    feature_mapper.register_feature_type('protocol', 'protocol')
    feature_mapper.register_feature_type('flags', 'flag')
    feature_mapper.register_feature_type('label', 'label')
    
    # Register feature mappings
    feature_mapper.register_feature_mapping('src_ip', 'src_ip')
    feature_mapper.register_feature_mapping('dst_ip', 'dst_ip')
    feature_mapper.register_feature_mapping('src_port', 'src_port')
    feature_mapper.register_feature_mapping('dst_port', 'dst_port')
    feature_mapper.register_feature_mapping('protocol', 'protocol')
    feature_mapper.register_feature_mapping('flow_duration', 'flow_duration')
    feature_mapper.register_feature_mapping('flow_packets', 'flow_packets')
    feature_mapper.register_feature_mapping('flow_bytes', 'flow_bytes')
    feature_mapper.register_feature_mapping('packet_size', 'packet_size')
    feature_mapper.register_feature_mapping('flags', 'flags')
    
    return feature_mapper
