// Main JavaScript for AI-Enhanced Intrusion Detection System

// Initialize socket connection
const socket = io();

// DOM elements
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const startBtn = document.getElementById('start-btn');
const stopBtn = document.getElementById('stop-btn');

// Application state
let appState = {
    monitoring: false,
    selectedInterface: null,
    interfaces: [],
    modelsLoaded: false,
    detectionThreshold: 0.5,
    activeProfile: null
};

// Connect to socket
socket.on('connect', () => {
    console.log('Connected to server');
    showNotification('Connected to server', 'success');
});

// Handle disconnection
socket.on('disconnect', () => {
    console.log('Disconnected from server');
    updateStatus(false);
    showNotification('Disconnected from server', 'error');
});

// Handle state updates
socket.on('state_update', (state) => {
    console.log('State update:', state);
    appState = { ...appState, ...state };
    updateUI();
});

// Handle status updates
socket.on('status_update', (status) => {
    console.log('Status update:', status);
    
    // Update monitoring status
    if (status.packet_sniffer) {
        updateStatus(status.packet_sniffer.running);
    }
    
    // Update model status
    if (status.model_integration) {
        updateModelStatus(status.model_integration);
    }
    
    // Update online learning status
    if (status.online_learning) {
        updateOnlineLearningStatus(status.online_learning);
    }
    
    // Dispatch custom event for other components
    const event = new CustomEvent('statusUpdate', { detail: status });
    document.dispatchEvent(event);
});

// Handle new packet
socket.on('new_packet', (packet) => {
    console.log('New packet:', packet);
    
    // Dispatch custom event for other components
    const event = new CustomEvent('newPacket', { detail: packet });
    document.dispatchEvent(event);
    
    // Show notification for attacks
    if (packet.is_attack) {
        showNotification(`Attack detected: ${packet.attack_type}`, 'error');
    }
});

// Initialize UI
function initUI() {
    // Set up event listeners
    startBtn.addEventListener('click', startMonitoring);
    stopBtn.addEventListener('click', stopMonitoring);
    
    // Set active navigation link
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        const linkPath = link.getAttribute('href');
        if (currentPath === linkPath || 
            (currentPath === '/' && linkPath.includes('dashboard'))) {
            link.classList.add('active');
        }
    });
}

// Update UI based on state
function updateUI() {
    // Update monitoring status
    updateStatus(appState.monitoring);
    
    // Update interface selection if available
    if (appState.interfaces && appState.interfaces.length > 0) {
        const interfaceSelect = document.getElementById('interface-select');
        if (interfaceSelect) {
            interfaceSelect.innerHTML = '';
            appState.interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface;
                option.textContent = iface;
                if (iface === appState.selectedInterface) {
                    option.selected = true;
                }
                interfaceSelect.appendChild(option);
            });
        }
    }
    
    // Update threshold slider if available
    const thresholdSlider = document.getElementById('detection-threshold');
    const thresholdValue = document.getElementById('threshold-value');
    if (thresholdSlider && thresholdValue) {
        thresholdSlider.value = appState.detectionThreshold;
        thresholdValue.textContent = appState.detectionThreshold.toFixed(2);
    }
    
    // Update profile selection if available
    const profileSelect = document.getElementById('profile-select');
    if (profileSelect && appState.activeProfile) {
        const options = profileSelect.querySelectorAll('option');
        for (let i = 0; i < options.length; i++) {
            if (options[i].value === appState.activeProfile) {
                options[i].selected = true;
                break;
            }
        }
    }
    
    // Update system information if available
    const systemVersion = document.getElementById('system-version');
    const modelsDirectory = document.getElementById('models-directory');
    const lastStarted = document.getElementById('last-started');
    
    if (systemVersion) systemVersion.textContent = '1.0.0';
    if (modelsDirectory) modelsDirectory.textContent = '/ai_ids/models';
    if (lastStarted) lastStarted.textContent = appState.monitoring ? new Date().toLocaleString() : 'Never';
}

// Update status indicator
function updateStatus(isRunning) {
    if (isRunning) {
        statusDot.classList.remove('offline');
        statusDot.classList.add('online');
        statusText.textContent = 'Online';
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        statusDot.classList.remove('online');
        statusDot.classList.add('offline');
        statusText.textContent = 'Offline';
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }
}

// Update model status
function updateModelStatus(modelStatus) {
    const modelsLoaded = document.getElementById('models-loaded');
    if (modelsLoaded) {
        modelsLoaded.textContent = modelStatus.loaded ? 'Yes' : 'No';
        modelsLoaded.style.color = modelStatus.loaded ? 'var(--success-color)' : 'var(--accent-color)';
    }
    
    const availableModelsList = document.getElementById('available-models-list');
    if (availableModelsList && modelStatus.models) {
        availableModelsList.innerHTML = '';
        modelStatus.models.forEach(model => {
            const li = document.createElement('li');
            li.textContent = model;
            if (model === modelStatus.default_model) {
                li.innerHTML += ' <span class="default-model">(Default)</span>';
            }
            availableModelsList.appendChild(li);
        });
    }
}

// Update online learning status
function updateOnlineLearningStatus(learningStatus) {
    const activeProfile = document.getElementById('stat-active-profile');
    if (activeProfile) {
        activeProfile.textContent = learningStatus.active_profile || 'Default';
    }
    
    // Update profile list if available
    if (learningStatus.profiles) {
        const profileSelect = document.getElementById('profile-select');
        if (profileSelect) {
            profileSelect.innerHTML = '';
            learningStatus.profiles.forEach(profile => {
                const option = document.createElement('option');
                option.value = profile.name;
                option.textContent = profile.name;
                if (profile.name === learningStatus.active_profile) {
                    option.selected = true;
                }
                profileSelect.appendChild(option);
            });
        }
    }
}

// Start monitoring
function startMonitoring() {
    const selectedInterface = appState.selectedInterface;
    
    if (!selectedInterface) {
        showNotification('No interface selected', 'error');
        return;
    }
    
    socket.emit('start_monitoring', { interface: selectedInterface }, (response) => {
        if (response && response.success) {
            showNotification('Monitoring started', 'success');
        } else {
            showNotification(`Failed to start monitoring: ${response.error}`, 'error');
        }
    });
}

// Stop monitoring
function stopMonitoring() {
    socket.emit('stop_monitoring', {}, (response) => {
        if (response && response.success) {
            showNotification('Monitoring stopped', 'success');
        } else {
            showNotification(`Failed to stop monitoring: ${response.error}`, 'error');
        }
    });
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // Add to document
    document.body.appendChild(notification);
    
    // Show notification
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    
    // Remove after delay
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// Format date
function formatDate(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

// Format bytes
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Initialize on load
document.addEventListener('DOMContentLoaded', initUI);
