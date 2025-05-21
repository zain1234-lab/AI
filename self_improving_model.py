"""
Self-improving model system for intrusion detection
--------------------------------------------------
This module provides an online learning framework that adapts to
specific network traffic patterns and continuously improves detection.
"""

import os
import time
import pickle
import logging
import numpy as np
import pandas as pd
from collections import deque
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from enhanced_logging import get_logger, track_performance, with_context

# Get logger for this module
logger = get_logger('model_adaptation')

class NetworkProfile:
    """Class representing a network environment profile"""
    
    def __init__(self, name, description=None):
        """Initialize the network profile"""
        self.name = name
        self.description = description or f"Profile created on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.creation_time = datetime.now()
        self.last_updated = self.creation_time
        self.packet_count = 0
        self.traffic_stats = {
            'protocols': {},
            'ports': {},
            'ip_ranges': {}
        }
        self.adaptation_stats = {
            'adaptations': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'initial_accuracy': None,
            'current_accuracy': None
        }
        self.thresholds = {}
        
    def update_stats(self, packet_dict):
        """Update traffic statistics based on a packet"""
        self.packet_count += 1
        self.last_updated = datetime.now()
        
        # Update protocol stats
        protocol = packet_dict.get('protocol', 0)
        self.traffic_stats['protocols'][protocol] = self.traffic_stats['protocols'].get(protocol, 0) + 1
        
        # Update port stats
        src_port = packet_dict.get('src_port', 0)
        dst_port = packet_dict.get('dst_port', 0)
        self.traffic_stats['ports'][src_port] = self.traffic_stats['ports'].get(src_port, 0) + 1
        self.traffic_stats['ports'][dst_port] = self.traffic_stats['ports'].get(dst_port, 0) + 1
        
        # Update IP range stats (first octet only for simplicity)
        src_ip = packet_dict.get('src_ip', '')
        dst_ip = packet_dict.get('dst_ip', '')
        
        if src_ip:
            src_range = src_ip.split('.')[0] if '.' in src_ip else src_ip
            self.traffic_stats['ip_ranges'][src_range] = self.traffic_stats['ip_ranges'].get(src_range, 0) + 1
        
        if dst_ip:
            dst_range = dst_ip.split('.')[0] if '.' in dst_ip else dst_ip
            self.traffic_stats['ip_ranges'][dst_range] = self.traffic_stats['ip_ranges'].get(dst_range, 0) + 1
    
    def update_adaptation_stats(self, adaptation_type, metrics=None):
        """Update adaptation statistics"""
        self.adaptation_stats['adaptations'] += 1
        self.last_updated = datetime.now()
        
        if adaptation_type == 'false_positive':
            self.adaptation_stats['false_positives'] += 1
        elif adaptation_type == 'false_negative':
            self.adaptation_stats['false_negatives'] += 1
        
        if metrics:
            if self.adaptation_stats['initial_accuracy'] is None:
                self.adaptation_stats['initial_accuracy'] = metrics.get('accuracy')
            
            self.adaptation_stats['current_accuracy'] = metrics.get('accuracy')
    
    def get_profile_summary(self):
        """Get a summary of the profile"""
        return {
            'name': self.name,
            'description': self.description,
            'creation_time': self.creation_time.strftime('%Y-%m-%d %H:%M:%S'),
            'last_updated': self.last_updated.strftime('%Y-%m-%d %H:%M:%S'),
            'packet_count': self.packet_count,
            'top_protocols': dict(sorted(self.traffic_stats['protocols'].items(), 
                                        key=lambda x: x[1], reverse=True)[:5]),
            'top_ports': dict(sorted(self.traffic_stats['ports'].items(), 
                                    key=lambda x: x[1], reverse=True)[:5]),
            'top_ip_ranges': dict(sorted(self.traffic_stats['ip_ranges'].items(), 
                                        key=lambda x: x[1], reverse=True)[:5]),
            'adaptation_stats': self.adaptation_stats
        }
    
    def to_dict(self):
        """Convert profile to dictionary for serialization"""
        return {
            'name': self.name,
            'description': self.description,
            'creation_time': self.creation_time.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'packet_count': self.packet_count,
            'traffic_stats': self.traffic_stats,
            'adaptation_stats': self.adaptation_stats,
            'thresholds': self.thresholds
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create profile from dictionary"""
        profile = cls(data['name'], data['description'])
        profile.creation_time = datetime.fromisoformat(data['creation_time'])
        profile.last_updated = datetime.fromisoformat(data['last_updated'])
        profile.packet_count = data['packet_count']
        profile.traffic_stats = data['traffic_stats']
        profile.adaptation_stats = data['adaptation_stats']
        profile.thresholds = data['thresholds']
        return profile

class AdaptiveThresholdManager:
    """Class for managing adaptive thresholds"""
    
    def __init__(self, initial_threshold=0.5, min_threshold=0.1, max_threshold=0.9, 
                 adaptation_rate=0.01, window_size=100):
        """Initialize the threshold manager"""
        self.threshold = initial_threshold
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.adaptation_rate = adaptation_rate
        self.window_size = window_size
        self.history = deque(maxlen=window_size)
        self.false_positives = 0
        self.false_negatives = 0
    
    def update(self, confidence, is_attack, feedback=None):
        """Update threshold based on prediction and feedback"""
        # Record prediction result
        self.history.append((confidence, is_attack))
        
        # If feedback is provided, update false positive/negative counts
        if feedback is not None:
            if is_attack and not feedback:  # False positive
                self.false_positives += 1
            elif not is_attack and feedback:  # False negative
                self.false_negatives += 1
        
        # Only adapt threshold after collecting enough samples
        if len(self.history) >= self.window_size:
            self._adapt_threshold()
    
    def _adapt_threshold(self):
        """Adapt threshold based on recent history"""
        # Calculate false positive and false negative rates
        fp_rate = self.false_positives / len(self.history) if self.history else 0
        fn_rate = self.false_negatives / len(self.history) if self.history else 0
        
        # Adjust threshold based on error rates
        if fp_rate > fn_rate:
            # More false positives, increase threshold
            new_threshold = self.threshold + self.adaptation_rate
        elif fn_rate > fp_rate:
            # More false negatives, decrease threshold
            new_threshold = self.threshold - self.adaptation_rate
        else:
            # Balanced, no change
            new_threshold = self.threshold
        
        # Ensure threshold stays within bounds
        self.threshold = max(self.min_threshold, min(self.max_threshold, new_threshold))
        
        # Reset counters
        self.false_positives = 0
        self.false_negatives = 0
        
        logger.info(f"Adapted threshold to {self.threshold:.4f} (FP rate: {fp_rate:.4f}, FN rate: {fn_rate:.4f})")
    
    def get_threshold(self):
        """Get the current threshold"""
        return self.threshold

class DriftDetector:
    """Class for detecting concept drift in network traffic"""
    
    def __init__(self, window_size=100, warning_threshold=0.05, drift_threshold=0.1):
        """Initialize the drift detector"""
        self.window_size = window_size
        self.warning_threshold = warning_threshold
        self.drift_threshold = drift_threshold
        self.reference_window = deque(maxlen=window_size)
        self.current_window = deque(maxlen=window_size)
        self.in_warning_zone = False
        self.drift_detected = False
    
    def add_sample(self, features, prediction, actual=None):
        """Add a sample and check for drift"""
        # If actual label is not provided, use prediction
        label = actual if actual is not None else prediction
        
        # Add to current window
        self.current_window.append((features, label))
        
        # If reference window is not full, add to it as well
        if len(self.reference_window) < self.window_size:
            self.reference_window.append((features, label))
            return False, False
        
        # If current window is full, check for drift
        if len(self.current_window) >= self.window_size:
            return self._check_drift()
        
        return self.in_warning_zone, self.drift_detected
    
    def _check_drift(self):
        """Check for drift between reference and current windows"""
        # Extract labels
        reference_labels = [item[1] for item in self.reference_window]
        current_labels = [item[1] for item in self.current_window]
        
        # Calculate distribution difference
        ref_attack_rate = sum(1 for label in reference_labels if label) / len(reference_labels)
        cur_attack_rate = sum(1 for label in current_labels if label) / len(current_labels)
        
        distribution_diff = abs(ref_attack_rate - cur_attack_rate)
        
        # Check for drift
        prev_warning = self.in_warning_zone
        prev_drift = self.drift_detected
        
        self.in_warning_zone = distribution_diff >= self.warning_threshold
        self.drift_detected = distribution_diff >= self.drift_threshold
        
        # Log if status changed
        if self.in_warning_zone and not prev_warning:
            logger.warning(f"Drift warning: distribution difference {distribution_diff:.4f}")
        
        if self.drift_detected and not prev_drift:
            logger.warning(f"Drift detected: distribution difference {distribution_diff:.4f}")
            # Update reference window with current window
            self.reference_window = deque(self.current_window, maxlen=self.window_size)
        
        return self.in_warning_zone, self.drift_detected
    
    def reset(self):
        """Reset the detector"""
        self.reference_window.clear()
        self.current_window.clear()
        self.in_warning_zone = False
        self.drift_detected = False

class IncrementalModel:
    """Base class for incremental learning models"""
    
    def __init__(self, model_type='random_forest', max_samples=1000):
        """Initialize the incremental model"""
        self.model_type = model_type
        self.max_samples = max_samples
        self.model = None
        self.feature_names = None
        self.sample_buffer = deque(maxlen=max_samples)
        self.initialized = False
    
    def initialize(self, feature_names):
        """Initialize the model with feature names"""
        self.feature_names = feature_names
        
        if self.model_type == 'random_forest':
            self.model = RandomForestClassifier(n_estimators=10, warm_start=True)
        elif self.model_type == 'decision_tree':
            self.model = DecisionTreeClassifier()
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
        
        self.initialized = True
        logger.info(f"Initialized incremental model of type {self.model_type} with {len(feature_names)} features")
    
    def add_sample(self, features, label):
        """Add a sample to the buffer"""
        if not self.initialized:
            raise ValueError("Model not initialized")
        
        # Ensure features match expected format
        if isinstance(features, dict):
            # Convert dict to array using feature names
            feature_array = np.zeros(len(self.feature_names))
            for i, name in enumerate(self.feature_names):
                feature_array[i] = features.get(name, 0)
            features = feature_array
        
        # Add to buffer
        self.sample_buffer.append((features, label))
    
    def update(self):
        """Update the model with buffered samples"""
        if not self.initialized or not self.sample_buffer:
            return False
        
        # Extract features and labels
        X = np.array([sample[0] for sample in self.sample_buffer])
        y = np.array([sample[1] for sample in self.sample_buffer])
        
        # Fit the model
        with track_performance(logger, f"Updating {self.model_type} model"):
            self.model.fit(X, y)
        
        logger.info(f"Updated {self.model_type} model with {len(self.sample_buffer)} samples")
        return True
    
    def predict(self, features):
        """Make a prediction"""
        if not self.initialized:
            raise ValueError("Model not initialized")
        
        # Ensure features match expected format
        if isinstance(features, dict):
            # Convert dict to array using feature names
            feature_array = np.zeros(len(self.feature_names))
            for i, name in enumerate(self.feature_names):
                feature_array[i] = features.get(name, 0)
            features = feature_array
        
        # Reshape for single sample
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        # Make prediction
        prediction = self.model.predict(features)[0]
        
        # Get probability if available
        try:
            probability = self.model.predict_proba(features)[0]
            confidence = max(probability)
        except:
            confidence = 1.0 if prediction else 0.0
        
        return prediction, confidence
    
    def evaluate(self, test_features, test_labels):
        """Evaluate the model"""
        if not self.initialized:
            raise ValueError("Model not initialized")
        
        # Ensure features match expected format
        if isinstance(test_features[0], dict):
            # Convert dicts to arrays using feature names
            feature_arrays = []
            for features in test_features:
                feature_array = np.zeros(len(self.feature_names))
                for i, name in enumerate(self.feature_names):
                    feature_array[i] = features.get(name, 0)
                feature_arrays.append(feature_array)
            test_features = np.array(feature_arrays)
        
        # Make predictions
        predictions = self.model.predict(test_features)
        
        # Calculate metrics
        accuracy = accuracy_score(test_labels, predictions)
        precision = precision_score(test_labels, predictions, zero_division=0)
        recall = recall_score(test_labels, predictions, zero_division=0)
        f1 = f1_score(test_labels, predictions, zero_division=0)
        
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
        
        logger.info(f"Model evaluation: accuracy={accuracy:.4f}, precision={precision:.4f}, recall={recall:.4f}, f1={f1:.4f}")
        return metrics
    
    def save(self, file_path):
        """Save the model to a file"""
        if not self.initialized:
            raise ValueError("Model not initialized")
        
        with open(file_path, 'wb') as f:
            pickle.dump({
                'model_type': self.model_type,
                'model': self.model,
                'feature_names': self.feature_names,
                'initialized': self.initialized
            }, f)
        
        logger.info(f"Saved incremental model to {file_path}")
    
    @classmethod
    def load(cls, file_path):
        """Load a model from a file"""
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
        
        model = cls(model_type=data['model_type'])
        model.model = data['model']
        model.feature_names = data['feature_names']
        model.initialized = data['initialized']
        
        logger.info(f"Loaded incremental model from {file_path}")
        return model

class OnlineLearningManager:
    """Manager class for online learning and adaptation"""
    
    def __init__(self, models_dir='./ai_ids/models', profiles_dir='./ai_ids/profiles',
                 adaptation_interval=100, max_profiles=10):
        """Initialize the online learning manager"""
        self.models_dir = models_dir
        self.profiles_dir = profiles_dir
        self.adaptation_interval = adaptation_interval
        self.max_profiles = max_profiles
        
        # Create directories if they don't exist
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.profiles_dir, exist_ok=True)
        
        # Initialize components
        self.active_profile = None
        self.profiles = {}
        self.incremental_model = IncrementalModel()
        self.threshold_manager = AdaptiveThresholdManager()
        self.drift_detector = DriftDetector()
        
        # Counters
        self.packet_count = 0
        self.adaptation_count = 0
        
        # Load existing profiles
        self._load_profiles()
        
        # Create default profile if none exists
        if not self.profiles:
            self._create_default_profile()
    
    def _load_profiles(self):
        """Load existing profiles"""
        try:
            profile_files = [f for f in os.listdir(self.profiles_dir) if f.endswith('.pkl')]
            
            for file in profile_files:
                try:
                    with open(os.path.join(self.profiles_dir, file), 'rb') as f:
                        profile_data = pickle.load(f)
                        profile = NetworkProfile.from_dict(profile_data)
                        self.profiles[profile.name] = profile
                        logger.info(f"Loaded profile: {profile.name}")
                except Exception as e:
                    logger.error(f"Error loading profile {file}: {e}")
            
            logger.info(f"Loaded {len(self.profiles)} profiles")
            
            # Set active profile to the most recently updated one
            if self.profiles:
                self.active_profile = max(self.profiles.values(), key=lambda p: p.last_updated).name
                logger.info(f"Set active profile to {self.active_profile}")
        
        except Exception as e:
            logger.error(f"Error loading profiles: {e}")
    
    def _save_profile(self, profile_name):
        """Save a profile to disk"""
        try:
            profile = self.profiles.get(profile_name)
            if profile:
                file_path = os.path.join(self.profiles_dir, f"{profile_name}.pkl")
                with open(file_path, 'wb') as f:
                    pickle.dump(profile.to_dict(), f)
                logger.info(f"Saved profile {profile_name} to {file_path}")
        except Exception as e:
            logger.error(f"Error saving profile {profile_name}: {e}")
    
    def _create_default_profile(self):
        """Create a default profile"""
        default_profile = NetworkProfile("default", "Default network profile")
        self.profiles["default"] = default_profile
        self.active_profile = "default"
        self._save_profile("default")
        logger.info("Created default profile")
    
    def initialize_model(self, feature_names, base_model_path=None):
        """Initialize the incremental model"""
        # Initialize from scratch or load base model
        if base_model_path and os.path.exists(base_model_path):
            try:
                self.incremental_model = IncrementalModel.load(base_model_path)
                logger.info(f"Initialized incremental model from {base_model_path}")
            except Exception as e:
                logger.error(f"Error loading base model: {e}")
                self.incremental_model.initialize(feature_names)
        else:
            self.incremental_model.initialize(feature_names)
    
    def process_packet(self, packet_dict, features, prediction=None, confidence=None):
        """Process a packet for online learning"""
        self.packet_count += 1
        
        # Update active profile stats
        if self.active_profile and self.active_profile in self.profiles:
            self.profiles[self.active_profile].update_stats(packet_dict)
        
        # Check for drift
        if prediction is not None:
            warning, drift = self.drift_detector.add_sample(features, prediction)
            
            if drift:
                logger.warning("Concept drift detected, triggering adaptation")
                self._adapt_model()
        
        # Periodic adaptation
        if self.packet_count % self.adaptation_interval == 0:
            self._adapt_model()
            
            # Save active profile periodically
            if self.active_profile:
                self._save_profile(self.active_profile)
    
    def provide_feedback(self, packet_dict, features, prediction, actual, confidence):
        """Process user feedback for a prediction"""
        # Add sample to incremental model
        self.incremental_model.add_sample(features, actual)
        
        # Update threshold manager
        self.threshold_manager.update(confidence, prediction, actual)
        
        # Update drift detector with correct label
        self.drift_detector.add_sample(features, prediction, actual)
        
        # Update profile stats
        if self.active_profile and self.active_profile in self.profiles:
            adaptation_type = 'false_positive' if prediction and not actual else 'false_negative' if not prediction and actual else 'correct'
            self.profiles[self.active_profile].update_adaptation_stats(adaptation_type)
        
        logger.info(f"Processed feedback: prediction={prediction}, actual={actual}, confidence={confidence:.4f}")
        
        # Trigger adaptation if this is a misclassification
        if prediction != actual:
            self._adapt_model()
    
    def _adapt_model(self):
        """Adapt the model based on collected samples"""
        # Update the incremental model
        updated = self.incremental_model.update()
        
        if updated:
            self.adaptation_count += 1
            
            # Save the adapted model
            adapted_model_path = os.path.join(self.models_dir, f"adapted_model_{self.adaptation_count}.pkl")
            self.incremental_model.save(adapted_model_path)
            
            logger.info(f"Adapted model saved to {adapted_model_path} (adaptation #{self.adaptation_count})")
            
            # Clear sample buffer to prevent reusing the same samples
            self.incremental_model.sample_buffer.clear()
    
    def create_profile(self, name, description=None):
        """Create a new network profile"""
        if len(self.profiles) >= self.max_profiles:
            # Remove oldest profile
            oldest_profile = min(self.profiles.values(), key=lambda p: p.last_updated).name
            del self.profiles[oldest_profile]
            logger.info(f"Removed oldest profile: {oldest_profile}")
        
        # Create new profile
        profile = NetworkProfile(name, description)
        self.profiles[name] = profile
        self._save_profile(name)
        
        logger.info(f"Created new profile: {name}")
        return profile
    
    def switch_profile(self, profile_name):
        """Switch to a different profile"""
        if profile_name in self.profiles:
            self.active_profile = profile_name
            
            # Reset drift detector when switching profiles
            self.drift_detector.reset()
            
            logger.info(f"Switched to profile: {profile_name}")
            return True
        else:
            logger.warning(f"Profile not found: {profile_name}")
            return False
    
    def get_active_profile(self):
        """Get the active profile"""
        if self.active_profile and self.active_profile in self.profiles:
            return self.profiles[self.active_profile]
        return None
    
    def get_profile_list(self):
        """Get a list of all profiles"""
        return [profile.get_profile_summary() for profile in self.profiles.values()]
    
    def get_adaptation_stats(self):
        """Get adaptation statistics"""
        return {
            'packet_count': self.packet_count,
            'adaptation_count': self.adaptation_count,
            'active_profile': self.active_profile,
            'current_threshold': self.threshold_manager.get_threshold(),
            'drift_warning': self.drift_detector.in_warning_zone,
            'drift_detected': self.drift_detector.drift_detected
        }

# Create a singleton instance
online_learning_manager = OnlineLearningManager()

# Function to get the singleton instance
def get_online_learning_manager():
    """Get the singleton online learning manager instance"""
    return online_learning_manager
