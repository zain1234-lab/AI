#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
AI-IDS: Optimized Training Module
This module implements memory-efficient training with advanced techniques
for the AI-Enhanced Intrusion Detection System.
"""

import os
import gc
import time
import logging
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
from functools import partial
import psutil
from tqdm import tqdm
import multiprocessing as mp
from imblearn.over_sampling import SMOTE
import xgboost as xgb
import lightgbm as lgb
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam
import tensorflow as tf

# Configure memory growth for TensorFlow
gpus = tf.config.experimental.list_physical_devices('GPU')
if gpus:
    try:
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
    except RuntimeError as e:
        print(e)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='logs/training.log'
)
logger = logging.getLogger('AI-IDS.Training')

# Memory tracking
def get_memory_usage():
    """Get current memory usage in GB"""
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    memory_gb = memory_info.rss / (1024 * 1024 * 1024)
    return memory_gb

def log_memory(message):
    """Log memory usage with custom message"""
    memory_gb = get_memory_usage()
    logger.info(f"{message}: {memory_gb:.2f} GB")

class MemoryConstrainedDataLoader:
    """Memory-efficient data loader with chunking capabilities"""
    
    def __init__(self, file_path, max_memory_gb=5.0, chunksize=100000):
        self.file_path = file_path
        self.max_memory_gb = max_memory_gb
        self.chunksize = chunksize
        self._get_file_info()
    
    def _get_file_info(self):
        """Get basic file info without loading full dataset"""
        # Read just a small portion to get columns
        sample = pd.read_csv(self.file_path, nrows=5)
        self.columns = sample.columns
        
        # Count lines in file
        with open(self.file_path, 'r') as f:
            self.total_rows = sum(1 for _ in f) - 1  # Subtract header
    
    def get_optimized_chunksize(self):
        """Calculate optimal chunk size based on memory constraints"""
        # Sample memory usage
        sample = pd.read_csv(self.file_path, nrows=10000)
        memory_per_row = sample.memory_usage(deep=True).sum() / len(sample)
        max_rows = int((self.max_memory_gb * 0.5 * 1024 * 1024 * 1024) / memory_per_row)
        
        # Round to nearest 10,000
        optimal_chunksize = max(10000, min(self.chunksize, max_rows - (max_rows % 10000)))
        logger.info(f"Optimal chunk size calculated: {optimal_chunksize} rows")
        return optimal_chunksize
    
    def load_chunks(self):
        """Generator that yields chunks of data"""
        chunksize = self.get_optimized_chunksize()
        
        logger.info(f"Loading data in chunks of {chunksize} rows")
        chunks = pd.read_csv(self.file_path, chunksize=chunksize)
        
        for i, chunk in enumerate(chunks):
            log_memory(f"Loaded chunk {i+1}")
            yield chunk
            
            # Force garbage collection
            gc.collect()

class FeatureProcessor:
    """Process features with memory efficiency in mind"""
    
    def __init__(self, max_memory_gb=5.0):
        self.max_memory_gb = max_memory_gb
        self.scaler = StandardScaler()
        self.feature_cols = None
        self.target_col = None
    
    def identify_features_target(self, df_sample):
        """Identify feature and target columns from sample data"""
        # Assuming last column is the target variable if it contains labels
        self.target_col = df_sample.columns[-1]
        self.feature_cols = [col for col in df_sample.columns if col != self.target_col]
        
        logger.info(f"Identified target column: {self.target_col}")
        logger.info(f"Identified {len(self.feature_cols)} feature columns")
        return self.feature_cols, self.target_col
    
    def preprocess_chunk(self, chunk, fit_scaler=False):
        """Preprocess a chunk of data"""
        if self.feature_cols is None:
            self.identify_features_target(chunk)
        
        # Handle missing values
        chunk = chunk.fillna(0)
        
        # Extract features and target
        X = chunk[self.feature_cols]
        y = chunk[self.target_col]
        
        # Scale features
        if fit_scaler:
            X = self.scaler.fit_transform(X)
        else:
            X = self.scaler.transform(X)
        
        return X, y
    
    def save_scaler(self, output_dir):
        """Save the fitted scaler"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        scaler_path = os.path.join(output_dir, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        logger.info(f"Scaler saved to {scaler_path}")

class MemoryEfficientSMOTE:
    """Memory-efficient implementation of SMOTE for handling imbalanced data"""
    
    def __init__(self, max_memory_gb=5.0):
        self.max_memory_gb = max_memory_gb
        self.smote = SMOTE(random_state=42)
    
    def fit_resample_in_batches(self, X, y):
        """Apply SMOTE in batches to avoid memory issues"""
        # Check current memory
        current_memory = get_memory_usage()
        if current_memory > self.max_memory_gb * 0.7:
            logger.warning("Memory usage too high for SMOTE, skipping resampling")
            return X, y
        
        # Get class distribution
        class_counts = np.bincount(y)
        logger.info(f"Class distribution before SMOTE: {class_counts}")
        
        # If the minority class is too small, use regular SMOTE
        if min(class_counts) > 100 and max(class_counts) / min(class_counts) > 10:
            try:
                logger.info("Applying SMOTE resampling")
                X_res, y_res = self.smote.fit_resample(X, y)
                # Check if we're still within memory limits
                if get_memory_usage() < self.max_memory_gb * 0.9:
                    logger.info(f"SMOTE completed. New shape: {X_res.shape}")
                    return X_res, y_res
                else:
                    logger.warning("SMOTE exceeded memory limits, reverting to original data")
                    return X, y
            except Exception as e:
                logger.error(f"SMOTE failed: {str(e)}")
                return X, y
        else:
            logger.info("Class distribution doesn't require SMOTE or minority class too small")
            return X, y

class ModelTrainer:
    """Train multiple models with memory efficiency"""
    
    def __init__(self, output_dir='models', max_memory_gb=5.0):
        self.output_dir = output_dir
        self.max_memory_gb = max_memory_gb
        self.models = {}
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def train_random_forest(self, X_train, y_train, X_test, y_test):
        """Train a memory-efficient Random Forest model"""
        log_memory("Before Random Forest training")
        
        # Use reduced n_estimators if memory is constrained
        memory_usage = get_memory_usage()
        n_estimators = 100 if memory_usage < 3.0 else 50
        
        rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=10,
            min_samples_split=10,
            n_jobs=-1,
            random_state=42,
            verbose=0
        )
        
        logger.info(f"Training Random Forest with {n_estimators} estimators")
        rf.fit(X_train, y_train)
        
        # Evaluate
        accuracy = rf.score(X_test, y_test)
        logger.info(f"Random Forest accuracy: {accuracy:.4f}")
        
        # Save model
        model_path = os.path.join(self.output_dir, 'random_forest.pkl')
        joblib.dump(rf, model_path)
        logger.info(f"Random Forest model saved to {model_path}")
        
        self.models['random_forest'] = rf
        log_memory("After Random Forest training")
        return rf
    
    def train_xgboost(self, X_train, y_train, X_test, y_test):
        """Train a memory-efficient XGBoost model"""
        log_memory("Before XGBoost training")
        
        # Memory-efficient parameters
        xgb_params = {
            'max_depth': 6,
            'learning_rate': 0.1,
            'n_estimators': 100,
            'objective': 'binary:logistic' if len(np.unique(y_train)) == 2 else 'multi:softprob',
            'tree_method': 'hist',  # Memory-efficient histogram algorithm
            'num_class': len(np.unique(y_train)) if len(np.unique(y_train)) > 2 else None,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'reg_alpha': 0.1,
            'reg_lambda': 1.0,
            'random_state': 42
        }
        
        # Remove None values
        xgb_params = {k: v for k, v in xgb_params.items() if v is not None}
        
        logger.info("Training XGBoost model")
        clf = xgb.XGBClassifier(**xgb_params)
        clf.fit(X_train, y_train)
        
        # Evaluate
        accuracy = clf.score(X_test, y_test)
        logger.info(f"XGBoost accuracy: {accuracy:.4f}")
        
        # Save model
        model_path = os.path.join(self.output_dir, 'xgboost_model.pkl')
        joblib.dump(clf, model_path)
        logger.info(f"XGBoost model saved to {model_path}")
        
        self.models['xgboost'] = clf
        log_memory("After XGBoost training")
        return clf
    
    def train_lightgbm(self, X_train, y_train, X_test, y_test):
        """Train a memory-efficient LightGBM model"""
        log_memory("Before LightGBM training")
        
        # Memory-efficient parameters
        params = {
            'objective': 'binary' if len(np.unique(y_train)) == 2 else 'multiclass',
            'num_class': len(np.unique(y_train)) if len(np.unique(y_train)) > 2 else None,
            'metric': 'binary_logloss' if len(np.unique(y_train)) == 2 else 'multi_logloss',
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.9,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'verbose': -1
        }
        
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        logger.info("Training LightGBM model")
        lgb_model = lgb.LGBMClassifier(**params)
        lgb_model.fit(X_train, y_train)
        
        # Evaluate
        accuracy = lgb_model.score(X_test, y_test)
        logger.info(f"LightGBM accuracy: {accuracy:.4f}")
        
        # Save model
        model_path = os.path.join(self.output_dir, 'lightgbm_model.pkl')
        joblib.dump(lgb_model, model_path)
        logger.info(f"LightGBM model saved to {model_path}")
        
        self.models['lightgbm'] = lgb_model
        log_memory("After LightGBM training")
        return lgb_model
    
    def train_neural_network(self, X_train, y_train, X_test, y_test):
        """Train a memory-efficient neural network"""
        log_memory("Before Neural Network training")
        
        # Check memory availability
        if get_memory_usage() > 4.0:
            logger.warning("Memory usage too high for neural network training, skipping")
            return None
        
        # Convert to numpy arrays if not already
        X_train = np.array(X_train)
        y_train = np.array(y_train)
        X_test = np.array(X_test)
        y_test = np.array(y_test)
        
        # Determine output shape
        num_classes = len(np.unique(y_train))
        output_shape = num_classes if num_classes > 2 else 1
        output_activation = 'softmax' if num_classes > 2 else 'sigmoid'
        loss_function = 'sparse_categorical_crossentropy' if num_classes > 2 else 'binary_crossentropy'
        
        # Set up callbacks for early stopping and memory management
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
            ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=3, min_lr=0.0001)
        ]
        
        # Build a simple model with memory efficiency in mind
        model = Sequential([
            Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
            BatchNormalization(),
            Dropout(0.3),
            Dense(32, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            Dense(output_shape, activation=output_activation)
        ])
        
        # Compile with memory-optimized settings
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss=loss_function,
            metrics=['accuracy']
        )
        
        # Train with small batch size for memory efficiency
        logger.info("Training Neural Network model")
        history = model.fit(
            X_train, y_train,
            epochs=20,
            batch_size=256,
            validation_split=0.2,
            callbacks=callbacks,
            verbose=1
        )
        
        # Evaluate
        loss, accuracy = model.evaluate(X_test, y_test)
        logger.info(f"Neural Network accuracy: {accuracy:.4f}")
        
        # Save model
        model_path = os.path.join(self.output_dir, 'neural_network')
        model.save(model_path)
        logger.info(f"Neural Network model saved to {model_path}")
        
        self.models['neural_network'] = model
        log_memory("After Neural Network training")
        return model
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate all trained models"""
        results = {}
        
        for name, model in self.models.items():
            logger.info(f"Evaluating {name}")
            
            try:
                # Make predictions
                if hasattr(model, 'predict_proba'):
                    y_pred = model.predict_proba(X_test)
                    # Convert probabilities to class labels
                    if y_pred.shape[1] > 1:  # multiclass
                        y_pred = np.argmax(y_pred, axis=1)
                    else:  # binary
                        y_pred = (y_pred > 0.5).astype(int)
                else:
                    y_pred = model.predict(X_test)
                    # For neural networks
                    if len(y_pred.shape) > 1 and y_pred.shape[1] > 1:
                        y_pred = np.argmax(y_pred, axis=1)
                    elif len(y_pred.shape) > 1 and y_pred.shape[1] == 1:
                        y_pred = (y_pred > 0.5).astype(int).flatten()
                
                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                report = classification_report(y_test, y_pred, output_dict=True)
                
                results[name] = {
                    'accuracy': accuracy,
                    'report': report
                }
                
                logger.info(f"{name} accuracy: {accuracy:.4f}")
            except Exception as e:
                logger.error(f"Error evaluating {name}: {str(e)}")
        
        # Save evaluation results
        with open(os.path.join(self.output_dir, 'evaluation_results.txt'), 'w') as f:
            for name, result in results.items():
                f.write(f"{name} accuracy: {result['accuracy']:.4f}\n")
                f.write(f"{name} classification report:\n")
                for class_name, metrics in result['report'].items():
                    if isinstance(metrics, dict):
                        f.write(f"  {class_name}:\n")
                        for metric_name, value in metrics.items():
                            f.write(f"    {metric_name}: {value:.4f}\n")
                f.write("\n")
        
        return results

class SelfImprovingAdapter:
    """Implements self-improving capabilities for models"""
    
    def __init__(self, base_models_dir='models', adapted_models_dir='adapted_models'):
        self.base_models_dir = base_models_dir
        self.adapted_models_dir = adapted_models_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(adapted_models_dir):
            os.makedirs(adapted_models_dir)
    
    def create_network_profile(self, profile_name, data_sample):
        """Create a network profile from sample data"""
        profile_dir = os.path.join(self.adapted_models_dir, profile_name)
        if not os.path.exists(profile_dir):
            os.makedirs(profile_dir)
        
        # Extract key statistics
        profile_stats = {
            'packet_size_mean': data_sample['packet_size'].mean() if 'packet_size' in data_sample.columns else None,
            'packet_rate_mean': data_sample['packet_rate'].mean() if 'packet_rate' in data_sample.columns else None,
            'protocol_distribution': data_sample['protocol'].value_counts().to_dict() if 'protocol' in data_sample.columns else None,
            'created_at': time.time()
        }
        
        # Save profile
        profile_path = os.path.join(profile_dir, 'profile.json')
        pd.Series(profile_stats).to_json(profile_path)
        logger.info(f"Created network profile: {profile_name}")
        
        return profile_path
    
    def adapt_model(self, model_name, base_model, X_new, y_new, profile_name):
        """Adapt a model to new data for a specific profile"""
        profile_dir = os.path.join(self.adapted_models_dir, profile_name)
        if not os.path.exists(profile_dir):
            os.makedirs(profile_dir)
        
        # Determine model type and apply appropriate adaptation
        adapted_model = None
        
        if isinstance(base_model, RandomForestClassifier):
            # For Random Forest, we can fit incremental trees
            logger.info(f"Adapting Random Forest model for profile {profile_name}")
            
            # Create a small set of new trees
            new_trees = RandomForestClassifier(
                n_estimators=10,
                max_depth=10,
                random_state=42
            ).fit(X_new, y_new)
            
            # Combine estimators (simplified approach)
            adapted_model = RandomForestClassifier(
                n_estimators=len(base_model.estimators_) + len(new_trees.estimators_),
                max_depth=base_model.max_depth,
                random_state=42
            )
            
            # Manually copy over the estimators
            adapted_model.estimators_ = np.append(base_model.estimators_, new_trees.estimators_)
            
        elif isinstance(base_model, xgb.XGBClassifier):
            # For XGBoost, we can update with new data
            logger.info(f"Adapting XGBoost model for profile {profile_name}")
            
            # Clone the model
            adapted_model = xgb.XGBClassifier()
            adapted_model.fit(X_new[:1], y_new[:1])  # Initialize with minimal fit
            
            # Copy the model parameters
            adapted_model.get_booster().copy_trees(base_model.get_booster())
            
            # Update with new data
            adapted_model.fit(
                X_new, y_new, 
                xgb_model=adapted_model.get_booster(),
                sample_weight=np.ones(len(y_new)) * 0.3  # Lower weight for new data
            )
            
        elif isinstance(base_model, lgb.LGBMClassifier):
            # For LightGBM, we can continue training
            logger.info(f"Adapting LightGBM model for profile {profile_name}")
            
            # Clone the model and continue training
            adapted_model = lgb.LGBMClassifier()
            adapted_model.fit(X_new[:1], y_new[:1])  # Initialize with minimal fit
            adapted_model.booster_ = base_model.booster_.clone_and_reset()
            
            # Continue training with lower learning rate
            adapted_model.fit(
                X_new, y_new,
                init_model=adapted_model.booster_,
                callbacks=[lgb.reset_parameter(learning_rate=lambda iter: 0.01 * (0.99 ** iter))]
            )
            
        elif 'keras' in str(type(base_model)):
            # For neural networks, continue training
            logger.info(f"Adapting Neural Network model for profile {profile_name}")
            
            # Clone the model
            adapted_model = tf.keras.models.clone_model(base_model)
            adapted_model.compile(
                optimizer=Adam(learning_rate=0.0005),  # Lower learning rate for fine-tuning
                loss=base_model.loss,
                metrics=['accuracy']
            )
            
            # Copy the weights
            adapted_model.set_weights(base_model.get_weights())
            
            # Continue training with new data
            adapted_model.fit(
                X_new, y_new,
                epochs=5,
                batch_size=32,
                verbose=0
            )
        
        # Save adapted model
        if adapted_model is not None:
            model_path = os.path.join(profile_dir, f'{model_name}.pkl')
            joblib.dump(adapted_model, model_path)
            logger.info(f"Adapted model saved to {model_path}")
            return adapted_model
        else:
            logger.warning(f"Could not adapt model {model_name}")
            return base_model

def main():
    """Main training function"""
    start_time = time.time()
    log_memory("Starting training process")
    
    # Check for existing models directory
    models_dir = 'models'
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)
    
    # Set up data paths
    data_path = 'data/CICIDS2017/CICIDS2017.csv'
    if not os.path.exists(data_path):
        logger.error(f"Data file not found: {data_path}")
        alternative_data_path = 'data/CICIDS2017.csv'
        if os.path.exists(alternative_data_path):
            data_path = alternative_data_path
            logger.info(f"Using alternative data path: {data_path}")
        else:
            logger.error("No suitable data file found. Please check data paths.")
            return
    
    # Initialize components
    data_loader = MemoryConstrainedDataLoader(data_path, max_memory_gb=5.0)
    feature_processor = FeatureProcessor(max_memory_gb=5.0)
    smote_processor = MemoryEfficientSMOTE(max_memory_gb=5.0)
    model_trainer = ModelTrainer(output_dir=models_dir, max_memory_gb=5.0)
    
    # Process data in chunks
    logger.info("Starting data loading and preprocessing")
    X_chunks = []
    y_chunks = []
    
    # Process first chunk to fit scaler and identify features
    for i, chunk in enumerate(data_loader.load_chunks()):
        if i == 0:
            # Process first chunk and fit scaler
            X, y = feature_processor.preprocess_chunk(chunk, fit_scaler=True)
            X_chunks.append(X)
            y_chunks.append(y)
            
            # Save feature information
            feature_info = {
                'feature_cols': feature_processor.feature_cols,
                'target_col': feature_processor.target_col
            }
            joblib.dump(feature_info, os.path.join(models_dir, 'feature_info.pkl'))
            
            # Save scaler
            feature_processor.save_scaler(models_dir)
        else:
            # Process remaining chunks
            X, y = feature_processor.preprocess_chunk(chunk, fit_scaler=False)
            X_chunks.append(X)
            y_chunks.append(y)
        
        # Check memory usage after each chunk
        memory_usage = get_memory_usage()
        logger.info(f"Memory usage after chunk {i+1}: {memory_usage:.2f} GB")
        
        # If memory usage is getting high, break
        if memory_usage > 5.0:
            logger.warning(f"Memory usage exceeded 5GB after chunk {i+1}, stopping data loading")
            break
        
        # If we've processed enough data, break
        if i >= 10:  # Adjust this based on dataset size and memory constraints
            logger.info("Reached maximum number of chunks to process")
            break
    
    # Combine processed chunks
    X_combined = np.vstack(X_chunks)
    y_combined = np.concatenate(y_chunks)
    
    # Clear chunks to free memory
    X_chunks = None
    y_chunks = None
    gc.collect()
    log_memory("After combining chunks")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y_combined, test_size=0.2, random_state=42, stratify=y_combined
    )
    
    # Clear combined data to free memory
    X_combined = None
    y_combined = None
    gc.collect()
    log_memory("After train-test split")
    
    # Apply SMOTE for imbalanced data
    X_train, y_train = smote_processor.fit_resample_in_batches(X_train, y_train)
    log_memory("After SMOTE")
    
    # Train models
    logger.info("Training models")
    
    # Train Random Forest
    rf_model = model_trainer.train_random_forest(X_train, y_train, X_test, y_test)
    gc.collect()
    
    # Train XGBoost
    xgb_model = model_trainer.train_xgboost(X_train, y_train, X_test, y_test)
    gc.collect()
    
    # Train LightGBM
    lgb_model = model_trainer.train_lightgbm(X_train, y_train, X_test, y_test)
    gc.collect()
    
    # Check if memory allows for neural network training
    if get_memory_usage() < 4.0:
        nn_model = model_trainer.train_neural_network(X_train, y_train, X_test, y_test)
        gc.collect()
    
    # Evaluate models
    logger.info("Evaluating models")
    evaluation_results = model_trainer.evaluate_models(X_test, y_test)
    
    # Set up self-improving adapter
    adapter = SelfImprovingAdapter(base_models_dir=models_dir)
    
    # Create default profile
    logger.info("Creating default network profile")
    adapter.create_network_profile('default', pd.DataFrame(X_test[:1000]))
    
    # Example of adapting model with new data (simulated)
    logger.info("Simulating model adaptation")
    adapter.adapt_model('random_forest', rf_model, X_test[:1000], y_test[:1000], 'default')
    
    # Training complete
    training_time = time.time() - start_time
    logger.info(f"Training completed in {training_time:.2f} seconds")
    log_memory("End of training process")
    
    return evaluation_results

if __name__ == "__main__":
    main()
