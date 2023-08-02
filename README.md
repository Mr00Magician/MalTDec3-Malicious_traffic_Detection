# Network Intrusion Detection System (NIDS)

## Overview

This project aims to create a Network Intrusion Detection System (NIDS) using Python and various networking libraries. The system sniffs network traffic, analyzes packets, and identifies potentially malicious activity. It employs a multi-layered approach to inspect and classify network packets, allowing for efficient detection and alerting.

## Features

- **Packet Sniffing**: Captures and processes network packets in real-time to extract relevant information.

- **Protocol Analysis**: Identifies various network protocols such as TCP, SSH, FTP, and HTTP.

- **Malicious IP Detection**: Utilizes machine learning models to detect potentially malicious IP addresses based on packet features.

- **Layered Inspection**: Implements a multi-layered inspection approach to increase the accuracy of intrusion detection.

## Installation

1. Clone the repository:
git clone https://github.com/your-username/NIDS.git
cd NIDS

2. Install required dependencies:
pip install -r requirements.txt


3. Run the main script to start packet sniffing and intrusion detection:
python main.py


## Usage

1. Ensure you have the necessary permissions to capture network traffic.

2. Run the `main.py` script to initiate the NIDS system.

3. The system will start capturing and analyzing network packets.

4. Suspected malicious activity will be flagged and logged in the output.

5. Monitor the console for alerts and notifications.

## Configuration

- Modify the packet processing functions in the `external.py` file to customize packet analysis.

- Update the machine learning models and parameters in the `Extract_Features_and_Predict.py` file for more accurate detection.

- Adjust the inspection layers and detection criteria in the `layers.py` file to suit your needs.

## Contributing

Contributions to this project are welcome. If you find any issues or have suggestions for improvements, please feel free to submit a pull request or open an issue.
