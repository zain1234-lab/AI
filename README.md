# AI-Enhanced Intrusion Detection System (AI-IDS)

## Overview
AI-IDS is a production-grade network intrusion detection system that uses advanced machine learning techniques to detect and classify network attacks in real-time. The system features a user-friendly web interface, robust logging, and self-improving models that adapt to your network's specific traffic patterns.

## Features
- Real-time packet capture and analysis
- Advanced machine learning models with 95%+ accuracy
- Self-improving models that adapt to your network
- Cross-platform support (Windows, Linux, macOS)
- Comprehensive logging system
- User-friendly web interface
- Detailed statistics and visualizations
- Memory-efficient processing (stays under 7GB RAM)

## System Requirements
- Python 3.11.x
- 4+ CPU cores recommended
- 8GB+ RAM (system uses max 7GB)
- Windows 11/10, Linux, or macOS
- Network interface with monitoring capabilities

## Installation

### Prerequisites
1. Install Python 3.11.x from [python.org](https://www.python.org/downloads/)
2. For Windows users, install Npcap from [npcap.com](https://npcap.com/#download)

### Setup
1. Extract the ZIP file to a directory of your choice
2. Open a command prompt/terminal in the extracted directory
3. Install required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Training Models
Before using the system, you need to train the models:

```
python train_models_local.py
```

This will train models using the provided dataset. For best results, use your own network data or the CICIDS2017 dataset.

### Starting the System
To start the system:

```
python main.py
```

This will launch the web interface at http://localhost:5000

### Web Interface
The web interface provides:
- Dashboard: Overview of network traffic and alerts
- Packets: Real-time view of captured packets
- Alerts: Detailed view of detected intrusions
- Statistics: Performance metrics and visualizations
- Settings: System configuration options

## Configuration
The system automatically detects available network interfaces, with preference for wireless interfaces. You can change the selected interface in the Settings page.

### Detection Threshold
Adjust the detection threshold in the Settings page:
- Lower values: More sensitive (may increase false positives)
- Higher values: Less sensitive (may increase false negatives)

### Network Profiles
Create custom profiles for different network environments. The system will adapt its detection models based on the active profile.

## Troubleshooting

### Common Issues
1. **"Failed to start monitoring"**: Ensure you have administrator/root privileges and the selected interface exists
2. **"No models loaded"**: Run `python train_models_local.py` to generate models
3. **"No interfaces found"**: Ensure your network interfaces are enabled and properly configured

### Logs
Detailed logs are stored in the `logs` directory. Check these files for troubleshooting:
- `system.log`: General system logs
- `detection.log`: Detection-related logs
- `training.log`: Model training logs

## Advanced Configuration
For advanced users, additional configuration options are available in the following files:
- `config.py`: System-wide configuration
- `model_config.py`: Model-specific settings
- `logging_config.py`: Logging configuration

## License
This software is provided for educational and research purposes only. Use at your own risk.

## Contact
For support or questions, please contact the development team.
