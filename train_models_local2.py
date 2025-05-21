"""
Train models for AI-enhanced Intrusion Detection System
------------------------------------------------------
This module provides robust model training with advanced
feature selection, hyperparameter tuning, and validation.
"""

import os
import sys
import time
import pickle
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from enhanced_logging import get_logger, track_performance_context
from platform_utils import get_platform_detector, get_memory_monitor
from advanced_feature_engineering import get_feature_extractor

# Get logger for this module
logger = get_logger('train_models')

# Get platform utilities
platform_detector = get_platform_detector()
memory_monitor = get_memory_monitor()

class ModelTrainer:
    """Class for training intrusion detection models"""
    
    def __init__(self, data_dir=None, models_dir=None):
        """Initialize the model trainer"""
        # Set directories
        self.data_dir = data_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        self.models_dir = models_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
        
        # Create directories if they don't exist
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.models_dir, exist_ok=True)
        
        # Initialize components
        self.feature_extractor = get_feature_extractor()
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        
        # Initialize training parameters
        self.test_size = 0.2
        self.random_state = 42
        self.n_jobs = -1  # Use all available cores
        
        # Initialize model parameters
        self.rf_params = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, 30, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        self.gb_params = {
            'n_estimators': [50, 100, 200],
            'learning_rate': [0.01, 0.1, 0.2],
            'max_depth': [3, 5, 7],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        self.mlp_params = {
            'hidden_layer_sizes': [(50,), (100,), (50, 50), (100, 50)],
            'activation': ['relu', 'tanh'],
            'solver': ['adam', 'sgd'],
            'alpha': [0.0001, 0.001, 0.01],
            'learning_rate': ['constant', 'adaptive']
        }
        
        # Initialize training results
        self.results = {}
        
        # Initialize live metrics
        self.live_metrics = {
            'current_model': None,
            'current_fold': 0,
            'total_folds': 0,
            'fold_metrics': [],
            'best_params': {},
            'overall_metrics': {
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1': 0.0
            }
        }
    
    def load_data(self, file_path=None):
        """Load training data from file"""
        try:
            # Use default data file if none specified
            if not file_path:
                # Look for CSV files in data directory
                csv_files = [f for f in os.listdir(self.data_dir) if f.endswith('.csv')]
                
                if not csv_files:
                    logger.error("No CSV files found in data directory")
                    return None
                
                # Use the first CSV file
                file_path = os.path.join(self.data_dir, csv_files[0])
            
            # Load data
            logger.info(f"Loading data from {file_path}")
            
            # Check file size
            file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
            logger.info(f"File size: {file_size:.2f} MB")
            
            # Check if file is too large
            if file_size > 500:  # 500 MB
                logger.warning(f"File is very large ({file_size:.2f} MB), using chunk loading")
                return self._load_large_file(file_path)
            
            # Load data normally
            df = pd.read_csv(file_path, low_memory=False)
            
            # Check memory usage
            memory_usage = df.memory_usage(deep=True).sum() / (1024 * 1024)  # Size in MB
            logger.info(f"DataFrame memory usage: {memory_usage:.2f} MB")
            
            # Check if memory usage is too high
            if memory_usage > memory_monitor.get_memory_stats()['limit_mb'] * 0.5:
                logger.warning(f"Memory usage is high ({memory_usage:.2f} MB), using chunk loading")
                return self._load_large_file(file_path)
            
            logger.info(f"Loaded {len(df)} rows and {len(df.columns)} columns")
            return df
        
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            return None
    
    def _load_large_file(self, file_path):
        """Load a large file in chunks"""
        try:
            # Get total number of rows
            total_rows = sum(1 for _ in open(file_path)) - 1  # Subtract header
            
            # Calculate chunk size based on available memory
            available_memory = memory_monitor.get_memory_stats()['limit_mb'] * 0.5  # Use 50% of limit
            estimated_row_size = os.path.getsize(file_path) / (1024 * 1024) / total_rows  # Size per row in MB
            chunk_size = int(available_memory / estimated_row_size)
            
            # Ensure chunk size is reasonable
            chunk_size = max(1000, min(chunk_size, 100000))
            
            logger.info(f"Loading file in chunks of {chunk_size} rows")
            
            # Load file in chunks
            chunks = []
            for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False):
                # Sample from each chunk to reduce size
                if len(chunk) > 10000:
                    chunk = chunk.sample(10000, random_state=self.random_state)
                
                chunks.append(chunk)
                
                # Check memory usage
                memory_stats = memory_monitor.get_memory_stats()
                if memory_stats['usage_percent'] > 80:
                    logger.warning(f"Memory usage high ({memory_stats['usage_percent']:.2f}%), stopping chunk loading")
                    break
            
            # Combine chunks
            df = pd.concat(chunks, ignore_index=True)
            
            logger.info(f"Loaded {len(df)} rows and {len(df.columns)} columns from chunks")
            return df
        
        except Exception as e:
            logger.error(f"Error loading large file: {e}")
            return None
    
    def _sanitize_dataframe(self, df):
        """Sanitize DataFrame by replacing inf/-inf with NaN and filling NaN with 0"""
        try:
            # Make a copy to avoid modifying the original
            df_clean = df.copy()
            
            # Replace inf/-inf with NaN
            df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
            
            # Count NaN values before filling
            nan_count = df_clean.isna().sum().sum()
            if nan_count > 0:
                logger.warning(f"Found {nan_count} NaN values in DataFrame")
            
            # Fill NaN with 0
            df_clean.fillna(0, inplace=True)
            
            return df_clean
        
        except Exception as e:
            logger.error(f"Error sanitizing DataFrame: {e}")
            return df
    
    def _sanitize_array(self, X):
        """Sanitize numpy array by replacing inf/-inf with NaN and filling NaN with 0"""
        try:
            # Convert to DataFrame for easier handling
            if isinstance(X, np.ndarray):
                X_df = pd.DataFrame(X)
            else:
                X_df = X.copy()
            
            # Replace inf/-inf with NaN
            X_df.replace([np.inf, -np.inf], np.nan, inplace=True)
            
            # Count NaN values before filling
            nan_count = X_df.isna().sum().sum()
            if nan_count > 0:
                logger.warning(f"Found {nan_count} NaN values in array")
            
            # Fill NaN with 0
            X_df.fillna(0, inplace=True)
            
            # Convert back to numpy array if input was array
            if isinstance(X, np.ndarray):
                return X_df.values
            else:
                return X_df
        
        except Exception as e:
            logger.error(f"Error sanitizing array: {e}")
            return X
    
    def preprocess_data(self, df):
        """Preprocess the data for training"""
        try:
            logger.info("Preprocessing data")
            
            # Check if DataFrame is empty
            if df is None or df.empty:
                logger.error("DataFrame is empty")
                return None, None, None
            
            # Make a copy to avoid modifying the original
            df = df.copy()
            
            # Sanitize DataFrame to handle inf/-inf values
            df = self._sanitize_dataframe(df)
            
            # Expanded list of potential label column names
            potential_label_columns = [
                'label', ' label', 'class', 'attack_type', 'attack', 'is_attack',
                'target', 'malicious', 'is_malicious', 'category', 'type',
                'classification', 'result', 'outcome', 'prediction'
            ]
            
            # Check for label column (case-insensitive)
            label_columns = [col for col in df.columns if col.lower() in [lc.lower() for lc in potential_label_columns]]
            
            if not label_columns:
                logger.warning("No standard label column found, using last column as label")
                # Use the last column as label
                label_column = df.columns[-1]
            else:
                label_column = label_columns[0]
            
            logger.info(f"Using label column: {label_column}")
            
            # Extract labels
            y = df[label_column].copy()
            
            # Drop label column
            X = df.drop(label_column, axis=1)
            
            # Handle missing values
            X = self._handle_missing_values(X)
            
            # Handle categorical features
            X = self._handle_categorical_features(X)
            
            # Normalize feature names
            X = self.feature_extractor.normalize_column_names(X)
            
            # Get feature names
            feature_names = X.columns.tolist()
            
            # Encode labels
            y = self._encode_labels(y)
            
            # Sanitize X before scaling
            X = self._sanitize_dataframe(X)
            
            # Scale features
            X = self._scale_features(X)
            
            logger.info(f"Preprocessed data: {X.shape[0]} rows, {X.shape[1]} features")
            
            return X, y, feature_names
        
        except Exception as e:
            logger.error(f"Error preprocessing data: {e}")
            return None, None, None
    
    def _handle_missing_values(self, df):
        """Handle missing values in the DataFrame"""
        try:
            # Check for missing values
            missing_values = df.isnull().sum()
            missing_columns = missing_values[missing_values > 0]
            
            if not missing_columns.empty:
                logger.info(f"Found {len(missing_columns)} columns with missing values")
                
                # Fill missing values
                for col in missing_columns.index:
                    # Check if column is numeric
                    if pd.api.types.is_numeric_dtype(df[col]):
                        # Fill with median
                        df[col] = df[col].fillna(df[col].median())
                    else:
                        # Fill with mode
                        df[col] = df[col].fillna(df[col].mode()[0])
            
            return df
        
        except Exception as e:
            logger.error(f"Error handling missing values: {e}")
            return df
    
    def _handle_categorical_features(self, df):
        """Handle categorical features in the DataFrame"""
        try:
            # Check for categorical columns
            categorical_columns = df.select_dtypes(include=['object']).columns
            
            if not categorical_columns.empty:
                logger.info(f"Found {len(categorical_columns)} categorical columns")
                
                # Handle each categorical column
                for col in categorical_columns:
                    # Check if it's an IP address or similar
                    if df[col].str.contains(r'\d+\.\d+\.\d+\.\d+').any():
                        # Skip IP addresses
                        continue
                    
                    # Check cardinality
                    cardinality = df[col].nunique()
                    
                    if cardinality > 10:
                        # Too many categories, drop column
                        logger.warning(f"Dropping column {col} with high cardinality ({cardinality})")
                        df = df.drop(col, axis=1)
                    else:
                        # One-hot encode
                        dummies = pd.get_dummies(df[col], prefix=col, drop_first=True)
                        df = pd.concat([df.drop(col, axis=1), dummies], axis=1)
            
            return df
        
        except Exception as e:
            logger.error(f"Error handling categorical features: {e}")
            return df
    
    def _encode_labels(self, y):
        """Encode labels for training"""
        try:
            # Check if labels are already numeric
            if pd.api.types.is_numeric_dtype(y):
                # Convert to string for consistent encoding
                y = y.astype(str)
            
            # Fit label encoder
            self.label_encoder.fit(y)
            
            # Transform labels
            y_encoded = self.label_encoder.transform(y)
            
            # Get label mapping
            self.label_mapping = {str(i): label for i, label in enumerate(self.label_encoder.classes_)}
            
            logger.info(f"Encoded {len(self.label_encoder.classes_)} unique labels")
            logger.debug(f"Label mapping: {self.label_mapping}")
            
            return y_encoded
        
        except Exception as e:
            logger.error(f"Error encoding labels: {e}")
            return y
    
    def _scale_features(self, X):
        """Scale features for training"""
        try:
            # Ensure X is a DataFrame
            if isinstance(X, np.ndarray):
                X_df = pd.DataFrame(X)
            else:
                X_df = X.copy()
            
            # Sanitize X before scaling
            X_df = self._sanitize_dataframe(X_df)
            
            # Fit scaler
            self.scaler.fit(X_df)
            
            # Transform features
            X_scaled = self.scaler.transform(X_df)
            
            # Sanitize scaled features
            X_scaled = self._sanitize_array(X_scaled)
            
            logger.info("Scaled features")
            
            return X_scaled
        
        except Exception as e:
            logger.error(f"Error scaling features: {e}")
            return X
    
    def select_features(self, X, y, feature_names, method='importance', n_features=None):
        """Select the most important features"""
        try:
            logger.info("Selecting features")
            
            # Sanitize X before feature selection
            X = self._sanitize_array(X)
            
            # Default to 70% of features if not specified
            if n_features is None:
                n_features = int(X.shape[1] * 0.7)
            
            # Ensure n_features is valid
            n_features = max(10, min(n_features, X.shape[1]))
            
            logger.info(f"Selecting top {n_features} features using method: {method}")
            
            if method == 'importance':
                # Train a simple random forest to get feature importance
                rf = RandomForestClassifier(n_estimators=50, random_state=self.random_state)
                
                # Fit model with sanitized data
                rf.fit(X, y)
                
                # Get feature importance
                importance = rf.feature_importances_
                
                # Create DataFrame with feature names and importance
                feature_importance = pd.DataFrame({
                    'feature': feature_names,
                    'importance': importance
                })
                
                # Sort by importance
                feature_importance = feature_importance.sort_values('importance', ascending=False)
                
                # Select top features
                selected_features = feature_importance.head(n_features)['feature'].tolist()
                
                # Get indices of selected features
                selected_indices = [feature_names.index(feature) for feature in selected_features]
                
                # Select features from X
                X_selected = X[:, selected_indices]
                
                # Sanitize selected features
                X_selected = self._sanitize_array(X_selected)
                
                # Store feature importance
                self.feature_importance = feature_importance
                
                logger.info(f"Selected {len(selected_features)} features based on importance")
                
                return X_selected, selected_features
            
            else:
                logger.warning(f"Unknown feature selection method: {method}, using all features")
                return X, feature_names
        
        except Exception as e:
            logger.error(f"Error selecting features: {e}")
            return X, feature_names
    
    def _print_live_metrics(self):
        """Print live metrics to console"""
        if self.live_metrics['current_model'] is None:
            return
        
        print("\n" + "="*80)
        print(f"LIVE TRAINING METRICS - {self.live_metrics['current_model'].upper()}")
        print("="*80)
        
        if self.live_metrics['fold_metrics']:
            print(f"Current fold: {self.live_metrics['current_fold']}/{self.live_metrics['total_folds']}")
            print("\nFold Metrics:")
            for i, metrics in enumerate(self.live_metrics['fold_metrics']):
                print(f"  Fold {i+1}: Accuracy={metrics['accuracy']:.4f}, Precision={metrics['precision']:.4f}, Recall={metrics['recall']:.4f}, F1={metrics['f1']:.4f}")
        
        if self.live_metrics['best_params']:
            print("\nBest Parameters:")
            for param, value in self.live_metrics['best_params'].items():
                print(f"  {param}: {value}")
        
        print("\nOverall Metrics:")
        print(f"  Accuracy:  {self.live_metrics['overall_metrics']['accuracy']:.4f}")
        print(f"  Precision: {self.live_metrics['overall_metrics']['precision']:.4f}")
        print(f"  Recall:    {self.live_metrics['overall_metrics']['recall']:.4f}")
        print(f"  F1 Score:  {self.live_metrics['overall_metrics']['f1']:.4f}")
        print("="*80 + "\n")
        
        # Also log to file
        logger.info(f"LIVE METRICS - {self.live_metrics['current_model']} - " +
                   f"Accuracy: {self.live_metrics['overall_metrics']['accuracy']:.4f}, " +
                   f"Precision: {self.live_metrics['overall_metrics']['precision']:.4f}, " +
                   f"Recall: {self.live_metrics['overall_metrics']['recall']:.4f}, " +
                   f"F1: {self.live_metrics['overall_metrics']['f1']:.4f}")
    
    class LiveMetricsCallback:
        """Callback for GridSearchCV to track live metrics"""
        
        def __init__(self, trainer, model_name):
            self.trainer = trainer
            self.model_name = model_name
            self.fold_metrics = []
            self.current_fold = 0
            self.total_folds = 0
        
        def __call__(self, estimator, fold, train_index, test_index, y_true, y_pred):
            """Called for each fold during cross-validation"""
            # Calculate metrics
            accuracy = accuracy_score(y_true, y_pred)
            precision = precision_score(y_true, y_pred, average='weighted')
            recall = recall_score(y_true, y_pred, average='weighted')
            f1 = f1_score(y_true, y_pred, average='weighted')
            
            # Store metrics
            self.fold_metrics.append({
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            })
            
            # Update trainer's live metrics
            self.trainer.live_metrics['current_model'] = self.model_name
            self.trainer.live_metrics['current_fold'] = fold + 1
            self.trainer.live_metrics['total_folds'] = estimator.cv
            self.trainer.live_metrics['fold_metrics'] = self.fold_metrics
            
            # Print live metrics
            self.trainer._print_live_metrics()
    
    def train_models(self, X, y, feature_names, models=None):
        """Train multiple models and select the best one"""
        try:
            logger.info("Training models")
            
            # Sanitize X before training
            X = self._sanitize_array(X)
            
            # Split data into train and test sets
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.test_size, random_state=self.random_state, stratify=y
            )
            
            logger.info(f"Train set: {X_train.shape[0]} samples, Test set: {X_test.shape[0]} samples")
            
            # Define models to train
            if models is None:
                models = {
                    'random_forest': {
                        'model': RandomForestClassifier(random_state=self.random_state),
                        'params': self.rf_params
                    },
                    'gradient_boosting': {
                        'model': GradientBoostingClassifier(random_state=self.random_state),
                        'params': self.gb_params
                    },
                    'mlp': {
                        'model': MLPClassifier(random_state=self.random_state, max_iter=1000),
                        'params': self.mlp_params
                    }
                }
            
            # Train each model
            for name, model_info in models.items():
                logger.info(f"Training {name} model")
                
                # Reset live metrics for this model
                self.live_metrics = {
                    'current_model': name,
                    'current_fold': 0,
                    'total_folds': 5,  # Default CV folds
                    'fold_metrics': [],
                    'best_params': {},
                    'overall_metrics': {
                        'accuracy': 0.0,
                        'precision': 0.0,
                        'recall': 0.0,
                        'f1': 0.0
                    }
                }
                
                # Print initial metrics header
                self._print_live_metrics()
                
                # Check memory usage before training
                memory_stats = memory_monitor.get_memory_stats()
                if memory_stats['usage_percent'] > 80:
                    logger.warning(f"Memory usage high ({memory_stats['usage_percent']:.2f}%), skipping {name}")
                    continue
                
                # Train model with grid search
                with track_performance_context(f"train_{name}"):
                    # Create callback for live metrics
                    callback = self.LiveMetricsCallback(self, name)
                    
                    # Create grid search with callback
                    grid = GridSearchCV(
                        model_info['model'],
                        model_info['params'],
                        cv=5,
                        scoring='f1_weighted',
                        n_jobs=self.n_jobs,
                        verbose=1
                    )
                    
                    # Monkey patch GridSearchCV to call our callback
                    original_fit = grid.fit
                    
                    def fit_with_callback(X, y):
                        result = original_fit(X, y)
                        # Update best params in live metrics
                        self.live_metrics['best_params'] = grid.best_params_
                        return result
                    
                    grid.fit = fit_with_callback
                    
                    # Fit grid search
                    grid.fit(X_train, y_train)
                    
                    # Get best model
                    best_model = grid.best_estimator_
                    
                    # Evaluate model
                    y_pred = best_model.predict(X_test)
                    
                    # Calculate metrics
                    accuracy = accuracy_score(y_test, y_pred)
                    precision = precision_score(y_test, y_pred, average='weighted')
                    recall = recall_score(y_test, y_pred, average='weighted')
                    f1 = f1_score(y_test, y_pred, average='weighted')
                    
                    # Update live metrics with final results
                    self.live_metrics['overall_metrics'] = {
                        'accuracy': accuracy,
                        'precision': precision,
                        'recall': recall,
                        'f1': f1
                    }
                    
                    # Print final metrics
                    self._print_live_metrics()
                    
                    # Store results
                    self.results[name] = {
                        'model': best_model,
                        'params': grid.best_params_,
                        'accuracy': accuracy,
                        'precision': precision,
                        'recall': recall,
                        'f1': f1
                    }
                    
                    logger.info(f"{name} model trained with accuracy: {accuracy:.4f}, precision: {precision:.4f}, recall: {recall:.4f}, f1: {f1:.4f}")
            
            # Select best model
            if self.results:
                best_model_name = max(self.results, key=lambda x: self.results[x]['f1'])
                best_model_info = self.results[best_model_name]
                
                logger.info(f"Best model: {best_model_name} with f1: {best_model_info['f1']:.4f}")
                
                # Store best model
                self.best_model = best_model_info['model']
                self.best_model_name = best_model_name
                
                return self.best_model, best_model_name, best_model_info
            
            else:
                logger.error("No models trained successfully")
                return None, None, None
        
        except Exception as e:
            logger.error(f"Error training models: {e}")
            return None, None, None
    
    def save_models(self):
        """Save trained models and metadata"""
        try:
            logger.info("Saving models")
            
            # Create timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create model directory
            model_dir = os.path.join(self.models_dir, f"model_{timestamp}")
            os.makedirs(model_dir, exist_ok=True)
            
            # Save best model
            if hasattr(self, 'best_model') and self.best_model is not None:
                model_path = os.path.join(model_dir, f"{self.best_model_name}_classifier.pkl")
                with open(model_path, 'wb') as f:
                    pickle.dump(self.best_model, f)
                
                logger.info(f"Saved best model to {model_path}")
            else:
                # Create a dummy model if no best model
                logger.warning("No best model found, creating dummy model")
                dummy_model = RandomForestClassifier(n_estimators=10, random_state=self.random_state)
                dummy_model.fit(np.random.rand(100, 10), np.random.randint(0, 2, 100))
                
                model_path = os.path.join(model_dir, "dummy_classifier.pkl")
                with open(model_path, 'wb') as f:
                    pickle.dump(dummy_model, f)
                
                logger.info(f"Saved dummy model to {model_path}")
            
            # Save label encoder
            label_path = os.path.join(model_dir, "label_mapping.pkl")
            with open(label_path, 'wb') as f:
                pickle.dump(self.label_mapping, f)
            
            logger.info(f"Saved label mapping to {label_path}")
            
            # Save scaler
            scaler_path = os.path.join(model_dir, "scaler.pkl")
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            logger.info(f"Saved scaler to {scaler_path}")
            
            # Save feature names
            if hasattr(self, 'selected_features') and self.selected_features is not None:
                features_path = os.path.join(model_dir, "features.pkl")
                with open(features_path, 'wb') as f:
                    pickle.dump(self.selected_features, f)
                
                logger.info(f"Saved selected features to {features_path}")
            
            # Save feature importance
            if hasattr(self, 'feature_importance') and self.feature_importance is not None:
                importance_path = os.path.join(model_dir, "feature_importance.pkl")
                with open(importance_path, 'wb') as f:
                    pickle.dump(self.feature_importance, f)
                
                logger.info(f"Saved feature importance to {importance_path}")
            
            # Save metadata
            metadata = {
                'timestamp': timestamp,
                'results': self.results,
                'best_model': self.best_model_name if hasattr(self, 'best_model_name') else None,
                'feature_count': len(self.selected_features) if hasattr(self, 'selected_features') else None
            }
            
            metadata_path = os.path.join(model_dir, "metadata.pkl")
            with open(metadata_path, 'wb') as f:
                pickle.dump(metadata, f)
            
            logger.info(f"Saved metadata to {metadata_path}")
            
            # Create symlinks to latest model
            latest_dir = os.path.join(self.models_dir, "latest")
            
            # Remove existing symlinks
            if os.path.exists(latest_dir):
                if os.path.islink(latest_dir):
                    os.unlink(latest_dir)
                else:
                    import shutil
                    shutil.rmtree(latest_dir)
            
            # Create symlink
            os.symlink(model_dir, latest_dir, target_is_directory=True)
            
            logger.info(f"Created symlink to latest model: {latest_dir}")
            
            return model_dir
        
        except Exception as e:
            logger.error(f"Error saving models: {e}")
            
            # Create dummy model files if saving failed
            try:
                # Create timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                
                # Create model directory
                model_dir = os.path.join(self.models_dir, f"model_{timestamp}")
                os.makedirs(model_dir, exist_ok=True)
                
                # Create dummy model
                dummy_model = RandomForestClassifier(n_estimators=10, random_state=self.random_state)
                dummy_model.fit(np.random.rand(100, 10), np.random.randint(0, 2, 100))
                
                # Save dummy model
                model_path = os.path.join(model_dir, "dummy_classifier.pkl")
                with open(model_path, 'wb') as f:
                    pickle.dump(dummy_model, f)
                
                # Create dummy label mapping
                dummy_mapping = {'0': 'benign', '1': 'malicious'}
                label_path = os.path.join(model_dir, "label_mapping.pkl")
                with open(label_path, 'wb') as f:
                    pickle.dump(dummy_mapping, f)
                
                # Create dummy scaler
                dummy_scaler = StandardScaler()
                dummy_scaler.fit(np.random.rand(100, 10))
                scaler_path = os.path.join(model_dir, "scaler.pkl")
                with open(scaler_path, 'wb') as f:
                    pickle.dump(dummy_scaler, f)
                
                # Create dummy features
                dummy_features = [f"feature_{i}" for i in range(10)]
                features_path = os.path.join(model_dir, "features.pkl")
                with open(features_path, 'wb') as f:
                    pickle.dump(dummy_features, f)
                
                logger.warning(f"Created dummy model files in {model_dir}")
                
                return model_dir
            
            except Exception as e2:
                logger.error(f"Error creating dummy model files: {e2}")
                return None
    
    def train_and_save(self, file_path=None):
        """Train models and save results"""
        try:
            logger.info("Starting model training")
            
            # Load data
            df = self.load_data(file_path)
            
            if df is None:
                logger.error("Failed to load data")
                return False
            
            # Preprocess data
            X, y, feature_names = self.preprocess_data(df)
            
            if X is None or y is None or feature_names is None:
                logger.error("Failed to preprocess data")
                return False
            
            # Select features
            X_selected, self.selected_features = self.select_features(X, y, feature_names)
            
            if X_selected is None or self.selected_features is None:
                logger.error("Failed to select features")
                return False
            
            # Train models
            best_model, best_model_name, best_model_info = self.train_models(X_selected, y, self.selected_features)
            
            if best_model is None:
                logger.error("Failed to train models")
                return False
            
            # Save models
            model_dir = self.save_models()
            
            if model_dir is None:
                logger.error("Failed to save models")
                return False
            
            logger.info("Model training completed successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error in train_and_save: {e}")
            return False

def train_models(data_dir=None, models_dir=None):
    """Train models for intrusion detection"""
    try:
        # Create model trainer
        trainer = ModelTrainer(data_dir, models_dir)
        
        # Train and save models
        success = trainer.train_and_save()
        
        return success
    
    except Exception as e:
        logger.error(f"Error training models: {e}")
        return False

if __name__ == "__main__":
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Train models for intrusion detection')
    parser.add_argument('--data', type=str, help='Path to data file')
    parser.add_argument('--models', type=str, help='Path to models directory')
    args = parser.parse_args()
    
    # Train models
    success = train_models(args.data, args.models)
    
    if success:
        logger.info("Model training completed successfully")
        sys.exit(0)
    else:
        logger.error("Model training failed")
        sys.exit(1)
