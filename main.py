"""
Main script for AI-enhanced Intrusion Detection System
-----------------------------------------------------
This module serves as the entry point for the application,
integrating all components and providing the web interface.
"""

import os
import sys
import time
import threading
import logging
import argparse
from pathlib import Path

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import core modules
from enhanced_logging import get_logger, LoggingManager
from platform_utils import get_platform_detector, get_network_interface_manager, get_memory_monitor
from advanced_feature_engineering import get_feature_extractor
from self_improving_model import get_online_learning_manager
from packet_sniffing import get_packet_sniffer, get_packet_processor, set_model_integration
from model_integration import get_model_integration
from gui import create_app

# Get logger for this module
logger = get_logger('main')

# Get platform utilities
platform_detector = get_platform_detector()
network_manager = get_network_interface_manager()
memory_monitor = get_memory_monitor()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='AI-Enhanced Intrusion Detection System')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='Host to run the web interface on')
    parser.add_argument('--port', type=int, default=5000,
                        help='Port to run the web interface on')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    parser.add_argument('--interface', type=str, default=None,
                        help='Network interface to monitor')
    parser.add_argument('--models-dir', type=str, default=None,
                        help='Directory containing trained models')
    parser.add_argument('--log-dir', type=str, default=None,
                        help='Directory for log files')
    
    return parser.parse_args()

def setup_directories(args):
    """Set up necessary directories"""
    # Get platform-specific app data directory
    app_data_dir = platform_detector.get_app_data_dir('ai_ids')
    
    # Set up models directory
    models_dir = args.models_dir
    if not models_dir:
        models_dir = os.path.join(app_data_dir, 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    # Set up logs directory
    log_dir = args.log_dir
    if not log_dir:
        log_dir = os.path.join(app_data_dir, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up profiles directory
    profiles_dir = os.path.join(app_data_dir, 'profiles')
    os.makedirs(profiles_dir, exist_ok=True)
    
    # Set up data directory
    data_dir = os.path.join(app_data_dir, 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    return {
        'app_data_dir': app_data_dir,
        'models_dir': models_dir,
        'log_dir': log_dir,
        'profiles_dir': profiles_dir,
        'data_dir': data_dir
    }

def initialize_components(directories, args):
    """Initialize all system components"""
    # Initialize logging
    logging_manager = LoggingManager(log_dir=directories['log_dir'])
    logger.info("Logging system initialized")
    
    # Initialize model integration
    model_integration = get_model_integration()
    model_integration.models_dir = directories['models_dir']
    model_loaded = model_integration.load_models()
    logger.info(f"Model integration initialized, models loaded: {model_loaded}")
    
    # Initialize online learning
    online_learning = get_online_learning_manager()
    online_learning.models_dir = directories['models_dir']
    online_learning.profiles_dir = directories['profiles_dir']
    logger.info("Online learning system initialized")
    
    # Initialize packet processor with model integration
    packet_processor = set_model_integration(model_integration)
    logger.info("Packet processor initialized")
    
    # Initialize packet sniffer
    packet_sniffer = get_packet_sniffer()
    if args.interface:
        packet_sniffer.interface = args.interface
    logger.info(f"Packet sniffer initialized with interface: {packet_sniffer.interface}")
    
    # Initialize feature extractor
    feature_extractor = get_feature_extractor()
    logger.info("Feature extractor initialized")
    
    # Return initialized components
    return {
        'model_integration': model_integration,
        'online_learning': online_learning,
        'packet_processor': packet_processor,
        'packet_sniffer': packet_sniffer,
        'feature_extractor': feature_extractor
    }

def setup_packet_processing(components):
    """Set up packet processing pipeline"""
    packet_sniffer = components['packet_sniffer']
    packet_processor = components['packet_processor']
    online_learning = components['online_learning']
    
    # Define packet callback
    def packet_callback(packet_dict):
        try:
            # Process packet
            result = packet_processor.process_packet(packet_dict)
            
            # Update online learning
            if result:
                features = components['feature_extractor'].extract_features(packet_dict)
                online_learning.process_packet(
                    packet_dict, 
                    features, 
                    result.get('is_attack', False),
                    result.get('confidence', 0.0)
                )
        except Exception as e:
            logger.error(f"Error in packet callback: {e}")
    
    # Set packet callback
    packet_sniffer.callback = packet_callback
    
    logger.info("Packet processing pipeline set up")

def start_background_tasks(components):
    """Start background tasks"""
    # Memory monitoring task
    def memory_monitor_task():
        while True:
            try:
                # Check memory usage
                memory_stats = memory_monitor.get_memory_stats()
                
                # Log if usage is high
                if memory_stats['usage_percent'] > 80:
                    logger.warning(f"High memory usage: {memory_stats['current_mb']:.2f} MB ({memory_stats['usage_percent']:.2f}%)")
                    
                    # Try to reduce memory usage
                    memory_monitor.reduce_memory_usage()
                
                # Sleep for a while
                time.sleep(60)
            
            except Exception as e:
                logger.error(f"Error in memory monitor task: {e}")
                time.sleep(60)
    
    # Model adaptation task
    def model_adaptation_task():
        while True:
            try:
                # Get online learning manager
                online_learning = components['online_learning']
                
                # Get adaptation stats
                stats = online_learning.get_adaptation_stats()
                
                # Log stats periodically
                logger.info(f"Adaptation stats: {stats['adaptation_count']} adaptations, "
                           f"active profile: {stats['active_profile']}, "
                           f"threshold: {stats['current_threshold']:.4f}")
                
                # Sleep for a while
                time.sleep(300)
            
            except Exception as e:
                logger.error(f"Error in model adaptation task: {e}")
                time.sleep(300)
    
    # Start memory monitor thread
    memory_thread = threading.Thread(target=memory_monitor_task)
    memory_thread.daemon = True
    memory_thread.start()
    
    # Start model adaptation thread
    adaptation_thread = threading.Thread(target=model_adaptation_task)
    adaptation_thread.daemon = True
    adaptation_thread.start()
    
    logger.info("Background tasks started")

def main():
    """Main entry point"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up directories
    directories = setup_directories(args)
    
    # Initialize components
    components = initialize_components(directories, args)
    
    # Set up packet processing
    setup_packet_processing(components)
    
    # Start background tasks
    start_background_tasks(components)
    
    # Create Flask app
    app = create_app(components)
    
    # Log startup information
    logger.info(f"Starting web interface on {args.host}:{args.port}")
    logger.info(f"Platform: {platform_detector.os_name} {platform_detector.os_version}")
    logger.info(f"Python version: {platform_detector.python_version}")
    logger.info(f"Network interfaces: {', '.join(network_manager.get_interface_names())}")
    
    # Run the app
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()
