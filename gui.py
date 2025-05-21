"""
GUI module for AI-enhanced Intrusion Detection System
----------------------------------------------------
This module provides the web interface for the application,
with robust event handling and state management.
"""

import os
import time
import json
import threading
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from enhanced_logging import get_logger
from platform_utils import get_platform_detector, get_network_interface_manager

# Get logger for this module
logger = get_logger('gui')

# Get platform utilities
platform_detector = get_platform_detector()
network_manager = get_network_interface_manager()

class EventManager:
    """Class for managing events between backend and frontend"""
    
    def __init__(self, socketio):
        """Initialize the event manager"""
        self.socketio = socketio
        self.event_queue = []
        self.queue_lock = threading.Lock()
        self.connected_clients = 0
        self.last_status_update = 0
        self.status_update_interval = 1.0  # seconds
    
    def emit_event(self, event_type, data):
        """Emit an event to all clients"""
        try:
            # Add to queue for clients that reconnect
            with self.queue_lock:
                self.event_queue.append({
                    'type': event_type,
                    'data': data,
                    'timestamp': time.time()
                })
                
                # Limit queue size
                if len(self.event_queue) > 100:
                    self.event_queue.pop(0)
            
            # Emit to connected clients
            self.socketio.emit(event_type, data)
            
            return True
        
        except Exception as e:
            logger.error(f"Error emitting event: {e}")
            return False
    
    def get_recent_events(self, event_type=None, max_events=50):
        """Get recent events from the queue"""
        with self.queue_lock:
            if event_type:
                events = [e for e in self.event_queue if e['type'] == event_type]
            else:
                events = self.event_queue.copy()
            
            # Sort by timestamp (newest first) and limit
            events.sort(key=lambda e: e['timestamp'], reverse=True)
            return events[:max_events]
    
    def client_connected(self):
        """Handle client connection"""
        self.connected_clients += 1
        logger.info(f"Client connected (total: {self.connected_clients})")
    
    def client_disconnected(self):
        """Handle client disconnection"""
        self.connected_clients = max(0, self.connected_clients - 1)
        logger.info(f"Client disconnected (total: {self.connected_clients})")
    
    def update_status(self, components):
        """Update system status if enough time has passed"""
        current_time = time.time()
        
        # Only update at specified intervals
        if current_time - self.last_status_update < self.status_update_interval:
            return
        
        self.last_status_update = current_time
        
        try:
            # Get component status
            status = {
                'timestamp': current_time,
                'system': {
                    'platform': platform_detector.os_name,
                    'version': platform_detector.os_version,
                    'python': platform_detector.python_version
                }
            }
            
            # Add packet sniffer status if available
            if 'packet_sniffer' in components:
                status['packet_sniffer'] = components['packet_sniffer'].get_stats()
            
            # Add packet processor status if available
            if 'packet_processor' in components:
                status['packet_processor'] = components['packet_processor'].get_stats()
            
            # Add model integration status if available
            if 'model_integration' in components:
                status['model_integration'] = components['model_integration'].get_model_status()
            
            # Add online learning status if available
            if 'online_learning' in components:
                status['online_learning'] = components['online_learning'].get_adaptation_stats()
            
            # Emit status update
            self.emit_event('status_update', status)
        
        except Exception as e:
            logger.error(f"Error updating status: {e}")

class StateManager:
    """Class for managing application state"""
    
    def __init__(self):
        """Initialize the state manager"""
        self.state = {
            'monitoring': False,
            'selected_interface': None,
            'interfaces': [],
            'models_loaded': False,
            'detection_threshold': 0.5,
            'active_profile': None,
            'last_updated': time.time()
        }
        self.state_lock = threading.Lock()
    
    def update_state(self, updates):
        """Update the state with new values"""
        with self.state_lock:
            for key, value in updates.items():
                if key in self.state:
                    self.state[key] = value
            
            self.state['last_updated'] = time.time()
    
    def get_state(self):
        """Get the current state"""
        with self.state_lock:
            return self.state.copy()
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        try:
            # Refresh network manager
            network_manager.refresh_interfaces()
            
            # Update state with new interfaces
            interfaces = network_manager.get_interface_names()
            preferred = network_manager.get_preferred_interface()
            
            with self.state_lock:
                self.state['interfaces'] = interfaces
                
                # Set selected interface if not already set
                if not self.state['selected_interface'] and preferred:
                    self.state['selected_interface'] = preferred
            
            return interfaces
        
        except Exception as e:
            logger.error(f"Error refreshing interfaces: {e}")
            return []

def create_app(components=None):
    """Create the Flask application"""
    app = Flask(__name__, static_folder='static', template_folder='templates')
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    # Initialize managers
    event_manager = EventManager(socketio)
    state_manager = StateManager()
    
    # Store components
    app.config['components'] = components or {}
    app.config['event_manager'] = event_manager
    app.config['state_manager'] = state_manager
    
    # Refresh interfaces
    state_manager.refresh_interfaces()
    
    # Socket.IO event handlers
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        event_manager.client_connected()
        
        # Send initial state
        emit('state_update', state_manager.get_state())
        
        # Send recent events
        recent_packets = []
        if 'packet_processor' in app.config['components']:
            recent_packets = app.config['components']['packet_processor'].get_last_packets(20)
        
        emit('recent_packets', recent_packets)
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        event_manager.client_disconnected()
    
    @socketio.on('start_monitoring')
    def handle_start_monitoring(data):
        """Handle start monitoring request"""
        try:
            # Get selected interface
            interface = data.get('interface', state_manager.get_state()['selected_interface'])
            
            # Start packet sniffer
            if 'packet_sniffer' in app.config['components']:
                success = app.config['components']['packet_sniffer'].start(interface)
                
                if success:
                    # Update state
                    state_manager.update_state({
                        'monitoring': True,
                        'selected_interface': interface
                    })
                    
                    # Emit state update
                    event_manager.emit_event('state_update', state_manager.get_state())
                    
                    logger.info(f"Started monitoring on interface {interface}")
                    return jsonify({'success': True})
                else:
                    logger.error(f"Failed to start monitoring on interface {interface}")
                    return jsonify({'success': False, 'error': 'Failed to start packet sniffer'})
            else:
                logger.error("Packet sniffer not available")
                return jsonify({'success': False, 'error': 'Packet sniffer not available'})
        
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    @socketio.on('stop_monitoring')
    def handle_stop_monitoring():
        """Handle stop monitoring request"""
        try:
            # Stop packet sniffer
            if 'packet_sniffer' in app.config['components']:
                success = app.config['components']['packet_sniffer'].stop()
                
                if success:
                    # Update state
                    state_manager.update_state({
                        'monitoring': False
                    })
                    
                    # Emit state update
                    event_manager.emit_event('state_update', state_manager.get_state())
                    
                    logger.info("Stopped monitoring")
                    return jsonify({'success': True})
                else:
                    logger.error("Failed to stop monitoring")
                    return jsonify({'success': False, 'error': 'Failed to stop packet sniffer'})
            else:
                logger.error("Packet sniffer not available")
                return jsonify({'success': False, 'error': 'Packet sniffer not available'})
        
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    @socketio.on('refresh_interfaces')
    def handle_refresh_interfaces():
        """Handle refresh interfaces request"""
        try:
            # Refresh interfaces
            interfaces = state_manager.refresh_interfaces()
            
            # Emit state update
            event_manager.emit_event('state_update', state_manager.get_state())
            
            logger.info(f"Refreshed interfaces: {interfaces}")
            return jsonify({'success': True, 'interfaces': interfaces})
        
        except Exception as e:
            logger.error(f"Error refreshing interfaces: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    @socketio.on('set_interface')
    def handle_set_interface(data):
        """Handle set interface request"""
        try:
            # Get interface
            interface = data.get('interface')
            
            if not interface:
                return jsonify({'success': False, 'error': 'No interface specified'})
            
            # Update state
            state_manager.update_state({
                'selected_interface': interface
            })
            
            # Emit state update
            event_manager.emit_event('state_update', state_manager.get_state())
            
            logger.info(f"Set interface to {interface}")
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error setting interface: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    @socketio.on('set_threshold')
    def handle_set_threshold(data):
        """Handle set threshold request"""
        try:
            # Get threshold
            threshold = data.get('threshold')
            
            if threshold is None:
                return jsonify({'success': False, 'error': 'No threshold specified'})
            
            # Update state
            state_manager.update_state({
                'detection_threshold': float(threshold)
            })
            
            # Update online learning threshold
            if 'online_learning' in app.config['components']:
                app.config['components']['online_learning'].threshold_manager.threshold = float(threshold)
            
            # Emit state update
            event_manager.emit_event('state_update', state_manager.get_state())
            
            logger.info(f"Set threshold to {threshold}")
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error setting threshold: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    @socketio.on('provide_feedback')
    def handle_provide_feedback(data):
        """Handle user feedback for a prediction"""
        try:
            # Get feedback data
            packet_id = data.get('packet_id')
            is_attack = data.get('is_attack', False)
            
            if packet_id is None:
                return jsonify({'success': False, 'error': 'No packet ID specified'})
            
            # Find packet in recent packets
            packet = None
            if 'packet_processor' in app.config['components']:
                recent_packets = app.config['components']['packet_processor'].get_last_packets()
                for p in recent_packets:
                    if str(p.get('id', '')) == str(packet_id):
                        packet = p
                        break
            
            if not packet:
                return jsonify({'success': False, 'error': 'Packet not found'})
            
            # Process feedback
            if 'online_learning' in app.config['components'] and 'feature_extractor' in app.config['components']:
                # Extract features
                features = app.config['components']['feature_extractor'].extract_features(packet)
                
                # Provide feedback
                app.config['components']['online_learning'].provide_feedback(
                    packet,
                    features,
                    packet.get('is_attack', False),
                    is_attack,
                    packet.get('confidence', 0.0)
                )
                
                logger.info(f"Processed feedback for packet {packet_id}: is_attack={is_attack}")
                return jsonify({'success': True})
            else:
                logger.error("Online learning or feature extractor not available")
                return jsonify({'success': False, 'error': 'Online learning not available'})
        
        except Exception as e:
            logger.error(f"Error processing feedback: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    @socketio.on('get_profiles')
    def handle_get_profiles():
        """Handle get profiles request"""
        try:
            # Get profiles
            profiles = []
            if 'online_learning' in app.config['components']:
                profiles = app.config['components']['online_learning'].get_profile_list()
            
            return jsonify({'success': True, 'profiles': profiles})
        
        except Exception as e:
            logger.error(f"Error getting profiles: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    @socketio.on('switch_profile')
    def handle_switch_profile(data):
        """Handle switch profile request"""
        try:
            # Get profile
            profile_name = data.get('profile')
            
            if not profile_name:
                return jsonify({'success': False, 'error': 'No profile specified'})
            
            # Switch profile
            if 'online_learning' in app.config['components']:
                success = app.config['components']['online_learning'].switch_profile(profile_name)
                
                if success:
                    # Update state
                    state_manager.update_state({
                        'active_profile': profile_name
                    })
                    
                    # Emit state update
                    event_manager.emit_event('state_update', state_manager.get_state())
                    
                    logger.info(f"Switched to profile {profile_name}")
                    return jsonify({'success': True})
                else:
                    logger.error(f"Failed to switch to profile {profile_name}")
                    return jsonify({'success': False, 'error': 'Failed to switch profile'})
            else:
                logger.error("Online learning not available")
                return jsonify({'success': False, 'error': 'Online learning not available'})
        
        except Exception as e:
            logger.error(f"Error switching profile: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    @socketio.on('create_profile')
    def handle_create_profile(data):
        """Handle create profile request"""
        try:
            # Get profile data
            profile_name = data.get('name')
            description = data.get('description')
            
            if not profile_name:
                return jsonify({'success': False, 'error': 'No profile name specified'})
            
            # Create profile
            if 'online_learning' in app.config['components']:
                profile = app.config['components']['online_learning'].create_profile(profile_name, description)
                
                if profile:
                    logger.info(f"Created profile {profile_name}")
                    return jsonify({'success': True, 'profile': profile.get_profile_summary()})
                else:
                    logger.error(f"Failed to create profile {profile_name}")
                    return jsonify({'success': False, 'error': 'Failed to create profile'})
            else:
                logger.error("Online learning not available")
                return jsonify({'success': False, 'error': 'Online learning not available'})
        
        except Exception as e:
            logger.error(f"Error creating profile: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    # Background task for status updates
    def background_status_updates():
        """Background task for status updates"""
        while True:
            try:
                # Update status
                event_manager.update_status(app.config['components'])
                
                # Process new packets
                if 'packet_processor' in app.config['components']:
                    new_packets = app.config['components']['packet_processor'].get_last_packets(1)
                    
                    if new_packets:
                        # Emit new packet event
                        event_manager.emit_event('new_packet', new_packets[0])
                
                # Sleep for a short time
                time.sleep(0.1)
            
            except Exception as e:
                logger.error(f"Error in background status updates: {e}")
                time.sleep(1.0)
    
    # Start background task
    status_thread = threading.Thread(target=background_status_updates)
    status_thread.daemon = True
    status_thread.start()
    
    # Flask routes
    @app.route('/')
    def index():
        """Render the main page"""
        return render_template('index.html')
    
    @app.route('/dashboard')
    def dashboard():
        """Render the dashboard page"""
        return render_template('dashboard.html')
    
    @app.route('/packets')
    def packets():
        """Render the packets page"""
        return render_template('packets.html')
    
    @app.route('/alerts')
    def alerts():
        """Render the alerts page"""
        return render_template('alerts.html')
    
    @app.route('/statistics')
    def statistics():
        """Render the statistics page"""
        return render_template('statistics.html')
    
    @app.route('/settings')
    def settings():
        """Render the settings page"""
        return render_template('settings.html')
    
    @app.route('/api/status')
    def api_status():
        """Get system status"""
        try:
            # Get component status
            status = {
                'timestamp': time.time(),
                'state': state_manager.get_state()
            }
            
            # Add packet sniffer status if available
            if 'packet_sniffer' in app.config['components']:
                status['packet_sniffer'] = app.config['components']['packet_sniffer'].get_stats()
            
            # Add packet processor status if available
            if 'packet_processor' in app.config['components']:
                status['packet_processor'] = app.config['components']['packet_processor'].get_stats()
            
            # Add model integration status if available
            if 'model_integration' in app.config['components']:
                status['model_integration'] = app.config['components']['model_integration'].get_model_status()
            
            # Add online learning status if available
            if 'online_learning' in app.config['components']:
                status['online_learning'] = app.config['components']['online_learning'].get_adaptation_stats()
            
            return jsonify(status)
        
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/interfaces')
    def api_interfaces():
        """Get network interfaces"""
        try:
            # Refresh interfaces
            interfaces = state_manager.refresh_interfaces()
            
            # Get interface details
            interface_details = []
            for name in interfaces:
                interface = network_manager.get_interface_by_name(name)
                if interface:
                    interface_details.append(interface)
            
            return jsonify({
                'interfaces': interface_details,
                'preferred': network_manager.get_preferred_interface()
            })
        
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/packets')
    def api_packets():
        """Get recent packets"""
        try:
            # Get recent packets
            packets = []
            if 'packet_processor' in app.config['components']:
                packets = app.config['components']['packet_processor'].get_last_packets()
            
            return jsonify({'packets': packets})
        
        except Exception as e:
            logger.error(f"Error getting packets: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/alerts')
    def api_alerts():
        """Get recent alerts"""
        try:
            # Get recent packets that are attacks
            alerts = []
            if 'packet_processor' in app.config['components']:
                packets = app.config['components']['packet_processor'].get_last_packets()
                alerts = [p for p in packets if p.get('is_attack', False)]
            
            return jsonify({'alerts': alerts})
        
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/profiles')
    def api_profiles():
        """Get network profiles"""
        try:
            # Get profiles
            profiles = []
            if 'online_learning' in app.config['components']:
                profiles = app.config['components']['online_learning'].get_profile_list()
            
            return jsonify({'profiles': profiles})
        
        except Exception as e:
            logger.error(f"Error getting profiles: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/logs')
    def api_logs():
        """Get recent logs"""
        try:
            # Get log files
            log_files = []
            if hasattr(app, 'config') and 'log_dir' in app.config:
                log_dir = app.config['log_dir']
                if os.path.exists(log_dir):
                    for file in os.listdir(log_dir):
                        if file.endswith('.log'):
                            log_files.append(os.path.join(log_dir, file))
            
            # Get recent logs from main log file
            logs = []
            if log_files:
                main_log = log_files[0]
                with open(main_log, 'r') as f:
                    logs = f.readlines()[-100:]  # Get last 100 lines
            
            return jsonify({'logs': logs, 'log_files': log_files})
        
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return jsonify({'error': str(e)}), 500
    
    return app
