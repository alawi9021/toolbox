# NmapScan

This tool is used to scan a network for open ports and identify active services, helping to recognize potential security risks. The tool is written in Python and designed for network analysis.

## Installation

1. Clone this repo to your local machine  
   ```bash
   git clone https://github.com/yourusername/NmapScan.git
   ```
2. Install the required libraries
   ```bash
   pip install python-nmap
   ```
3. Run the script:
   ```bash
   python nmap_scan.py
   ```

## Usage

To scan IP addresses for open ports:
- Enter IPs manually:
  ```bash
  python nmap_scan.py --ips 192.168.1.1 192.168.1.2
  ```
- Scan IPs from a file:
  ```bash
  python nmap_scan.py --file ip_list.txt
  ```
- Save scan results to a file:
  ```bash
  python nmap_scan.py --ips 192.168.1.1 --save scan_results.txt
  ```

## Contributing

To contribute:
1. Fork the repo
2. Create a new branch for your feature
3. Submit a pull request when done

All contributions are welcome!

## License



