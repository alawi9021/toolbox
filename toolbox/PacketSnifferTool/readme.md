# Packet Sniffer Tool


This tool is a simple packet sniffer built in Python using the `scapy` library. It captures and displays network packet details to assist with network analysis.

## Installation

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/yourusername/PacketSnifferTool.git
   ```
2. Install the required library:
   ```bash
   pip install scapy
   ```
3. Run the script:
   ```bash
   python packet_sniffer_tool.py
   ```

## Usage

To start sniffing network packets, use the following commands:

- Capture packets on a specific network interface:
  ```bash
  python packet_sniffer_tool.py -i <interface_name>
  ```
- Capture a set number of packets:
  ```bash
  python packet_sniffer_tool.py -i <interface_name> -c <packet_count>
  ```

### Example
Capture 10 packets on the Wi-Fi interface:
```bash
python packet_sniffer_tool.py -i "Wi-Fi" -c 10
```

## Features

- Captures and displays basic information about IP packets:
  - Source and destination IP addresses
  - Protocol type
  - Source and destination ports (for TCP/UDP packets)
- Supports both TCP and UDP protocols.
- Basic error handling to manage exceptions during sniffing.

## Contributing

To contribute:
1. Fork this repository.
2. Create a new branch for your feature.
3. Submit a pull request when your changes are ready.

All contributions are welcome!

## License


