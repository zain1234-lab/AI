"""
Model integration module for AI-enhanced Intrusion Detection System
------------------------------------------------------------------
This module provides model loading, prediction, and management
with support for multiple classifiers and online learning.
"""

import os
import time
import pickle
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from enhanced_logging import get_logger, track_performance, with_context
from platform_utils import get_platform_detector, get_memory_monitor

# Get logger for this module
logger = get_logger('model_integration')

# Get platform utilities
platform_detector = get_platform_detector()
memory_monitor = get_memory_monitor()

class ModelManager:
    """Class for managing machine learning models"""
    
    def __init__(self, models_dir=None):
        """Initialize the model manager"""
        self.models_dir = models_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
        self.models = {}
        self.scalers = {}
        self.feature_names = {}
        self.label_mapping = {}
        self.model_stats = {}
        self.default_model = None
        self.loaded = False
    
    def load_models(self, models_dir=None):
        """Load all models from the models directory"""
        if models_dir:
            self.models_dir = models_dir
        
        try:
            # Create models directory if it doesn't exist
            os.makedirs(self.models_dir, exist_ok=True)
            
            # Get all model files
            model_files = []
            for file in os.listdir(self.models_dir):
                if file.endswith('.pkl') and 'model' in file:
                    model_files.append(os.path.join(self.models_dir, file))
            
            # Load each model
            for model_file in model_files:
                try:
                    model_name = os.path.basename(model_file).replace('.pkl', '')
                    self._load_model(model_name)
                except Exception as e:
                    logger.error(f"Error loading model {model_file}: {e}")
            
            # Check if any models were loaded
            if not self.models:
                logger.warning("No models found, creating fallback model")
                self._create_fallback_model()
            
            # Set default model
            if not self.default_model and self.models:
                self.default_model = list(self.models.keys())[0]
            
            self.loaded = True
            logger.info(f"Loaded {len(self.models)} models")
            
            return True
        
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            
            # Create fallback model
            self._create_fallback_model()
            
            return False
    
    def _load_model(self, model_name):
        """Load a specific model and its associated files"""
        try:
            # Normalize paths
            model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
            scaler_path = os.path.join(self.models_dir, f"{model_name}_scaler.pkl")
            features_path = os.path.join(self.models_dir, f"{model_name}_features.pkl")
            mapping_path = os.path.join(self.models_dir, f"{model_name}_mapping.pkl")
            stats_path = os.path.join(self.models_dir, f"{model_name}_stats.pkl")
            
            # Convert to Path objects for cross-platform compatibility
            model_path = str(Path(model_path))
            scaler_path = str(Path(scaler_path))
            features_path = str(Path(features_path))
            mapping_path = str(Path(mapping_path))
            stats_path = str(Path(stats_path))
            
            # Load model
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.models[model_name] = pickle.load(f)
            else:
                logger.error(f"Model file not found: {model_path}")
                return False
            
            # Load scaler if exists
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scalers[model_name] = pickle.load(f)
            
            # Load feature names if exists
            if os.path.exists(features_path):
                with open(features_path, 'rb') as f:
                    self.feature_names[model_name] = pickle.load(f)
            
            # Load label mapping if exists
            if os.path.exists(mapping_path):
                with open(mapping_path, 'rb') as f:
                    self.label_mapping[model_name] = pickle.load(f)
            
            # Load model stats if exists
            if os.path.exists(stats_path):
                with open(stats_path, 'rb') as f:
                    self.model_stats[model_name] = pickle.load(f)
            
            logger.info(f"Loaded model {model_name}")
            
            # Set as default model if none set
            if not self.default_model:
                self.default_model = model_name
            
            return True
        
        except Exception as e:
            logger.error(f"Error loading model {model_name}: {e}")
            return False
    
    def _create_fallback_model(self):
        """Create a fallback model when no models are available"""
        try:
            model_name = "fallback_model"
            
            # Create a simple random forest classifier
            model = RandomForestClassifier(n_estimators=10, max_depth=5)
            
            # Create a simple dataset for training
            X = np.random.rand(100, 10)
            y = np.random.choice([0, 1], size=100)
            
            # Train the model
            model.fit(X, y)
            
            # Create a scaler
            scaler = StandardScaler()
            scaler.fit(X)
            
            # Create feature names
            feature_names = [f"feature_{i}" for i in range(10)]
            
            # Create label mapping
            label_mapping = {0: "benign", 1: "attack"}
            
            # Create model stats
            model_stats = {
                'accuracy': 0.5,
                'precision': 0.5,
                'recall': 0.5,
                'f1': 0.5,
                'training_time': 0.0,
                'feature_importance': {name: 1.0/len(feature_names) for name in feature_names}
            }
            
            # Save model files
            os.makedirs(self.models_dir, exist_ok=True)
            
            with open(os.path.join(self.models_dir, f"{model_name}.pkl"), 'wb') as f:
                pickle.dump(model, f)
            
            with open(os.path.join(self.models_dir, f"{model_name}_scaler.pkl"), 'wb') as f:
                pickle.dump(scaler, f)
            
            with open(os.path.join(self.models_dir, f"{model_name}_features.pkl"), 'wb') as f:
                pickle.dump(feature_names, f)
            
            with open(os.path.join(self.models_dir, f"{model_name}_mapping.pkl"), 'wb') as f:
                pickle.dump(label_mapping, f)
            
            with open(os.path.join(self.models_dir, f"{model_name}_stats.pkl"), 'wb') as f:
                pickle.dump(model_stats, f)
            
            # Add to model manager
            self.models[model_name] = model
            self.scalers[model_name] = scaler
            self.feature_names[model_name] = feature_names
            self.label_mapping[model_name] = label_mapping
            self.model_stats[model_name] = model_stats
            self.default_model = model_name
            
            logger.warning(f"Created fallback model {model_name}")
            
            return True
        
        except Exception as e:
            logger.error(f"Error creating fallback model: {e}")
            return False
    
    def predict(self, features, model_name=None):
        """Make a prediction using the specified model"""
        try:
            # Use default model if none specified
            if not model_name:
                model_name = self.default_model
            
            # Check if model exists
            if model_name not in self.models:
                logger.error(f"Model {model_name} not found")
                return None
            
            # Get model and associated files
            model = self.models[model_name]
            scaler = self.scalers.get(model_name)
            feature_names = self.feature_names.get(model_name, [])
            
            # Prepare features
            X = self._prepare_features(features, feature_names, scaler)
            
            # Make prediction
            y_pred = model.predict(X)
            
            # Get probabilities if available
            try:
                y_proba = model.predict_proba(X)
                confidence = np.max(y_proba, axis=1)[0]
            except:
                confidence = 1.0
            
            # Map label if mapping exists
            label = y_pred[0]
            if model_name in self.label_mapping:
                label_map = self.label_mapping[model_name]
                if str(label) in label_map:
                    label = label_map[str(label)]
                elif label in label_map:
                    label = label_map[label]
            
            return {
                'label': label,
                'confidence': float(confidence),
                'model': model_name
            }
        
        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            return None
    
    def _prepare_features(self, features, feature_names, scaler):
        """Prepare features for prediction"""
        try:
            # Convert to DataFrame if not already
            if not isinstance(features, pd.DataFrame):
                features = pd.DataFrame([features])
            
            # Select features if feature names provided
            if feature_names:
                # Check for missing features
                missing_features = [f for f in feature_names if f not in features.columns]
                
                # Add missing features with default values
                for feature in missing_features:
                    features[feature] = 0.0
                
                # Select only required features
                features = features[feature_names]
            
            # Apply scaler if provided
            X = features.values
            if scaler:
                X = scaler.transform(X)
            
            return X
        
        except Exception as e:
            logger.error(f"Error preparing features: {e}")
            return features.values
    
    def get_model_names(self):
        """Get names of all loaded models"""
        return list(self.models.keys())
    
    def get_model_stats(self, model_name=None):
        """Get statistics for a specific model or all models"""
        if model_name:
            return self.model_stats.get(model_name, {})
        else:
            return self.model_stats
    
    def get_model_status(self):
        """Get status of all models"""
        return {
            'loaded': self.loaded,
            'model_count': len(self.models),
            'default_model': self.default_model,
            'models': self.get_model_names()
        }

class DetectionEngine:
    """Class for detecting intrusions using loaded models"""
    
    def __init__(self, model_manager=None, threshold=0.5):
        """Initialize the detection engine"""
        self.model_manager = model_manager or ModelManager()
        self.threshold = threshold
        self.detection_count = 0
        self.false_positive_count = 0
        self.false_negative_count = 0
    
    def detect(self, features):
        """Detect if a packet is an intrusion"""
        try:
            # Make prediction
            prediction = self.model_manager.predict(features)
            
            if not prediction:
                return {
                    'is_attack': False,
                    'attack_type': 'Unknown',
                    'confidence': 0.0,
                    'detector': 'None'
                }
            
            # Check if attack based on threshold
            is_attack = False
            attack_type = 'benign'
            
            if prediction['label'] != 'benign' and prediction['confidence'] >= self.threshold:
                is_attack = True
                attack_type = prediction['label']
            
            # Update detection count
            self.detection_count += 1
            
            return {
                'is_attack': is_attack,
                'attack_type': attack_type,
                'confidence': prediction['confidence'],
                'detector': prediction['model']
            }
        
        except Exception as e:
            logger.error(f"Error detecting intrusion: {e}")
            return {
                'is_attack': False,
                'attack_type': 'Unknown',
                'confidence': 0.0,
                'detector': 'Error'
            }
    
    def provide_feedback(self, prediction, actual):
        """Provide feedback on a prediction"""
        try:
            # Update false positive/negative counts
            if prediction['is_attack'] and not actual:
                self.false_positive_count += 1
            elif not prediction['is_attack'] and actual:
                self.false_negative_count += 1
            
            return True
        
        except Exception as e:
            logger.error(f"Error providing feedback: {e}")
            return False
    
    def get_stats(self):
        """Get detection statistics"""
        return {
            'detection_count': self.detection_count,
            'false_positive_count': self.false_positive_count,
            'false_negative_count': self.false_negative_count,
            'false_positive_rate': self.false_positive_count / self.detection_count if self.detection_count > 0 else 0,
            'false_negative_rate': self.false_negative_count / self.detection_count if self.detection_count > 0 else 0
        }

# Create singleton instances
model_manager = ModelManager()
detection_engine = DetectionEngine(model_manager)

# Functions to get singleton instances
def get_model_manager():
    """Get the singleton model manager instance"""
    return model_manager

def get_detection_engine():
    """Get the singleton detection engine instance"""
    return detection_engine

def get_model_integration():
    """Get the model integration components"""
    return detection_engine
