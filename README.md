# Real-Time Network Traffic Visualizer 🌐

This project provides a tool for visualizing network traffic in real-time on an interactive world map. It captures network packets from a live interface or a `.pcap` file, performs IP geolocation on the source and destination addresses, and plots the connections on a map.

## Features

- **Live Packet Sniffing**: Capture packets directly from any network interface.
- **PCAP File Support**: Analyze pre-existing traffic from `.pcap` files.
- **IP Geolocation**: Enriches data with city and country information for public IPs.
- **Protocol Analysis**: Identifies traffic protocols (TCP, UDP, etc.) and color-codes the connections.
- **Interactive Map**: The output is an interactive `HTML` map created with Folium. You can pan, zoom, and click on connections for more details.
- **User-Friendly CLI**: A simple command-line interface to control the tool's behavior.

## Installation

1.  **Clone the Repository**

    ```bash
    git clone [https://github.com/NoiseBridge7/Network-Tracking.git](https://github.com/NoiseBridge7/Network-Tracking.git)
    cd Network-Tracking
    ```

2.  **Install Dependencies**
    It's recommended to use a Python virtual environment.

    ```bash
    # Create and activate a virtual environment (optional but recommended)
    python3 -m venv venv
    source venv/bin/activate

    # Install the required packages
    pip install -r requirements.txt
    ```

3.  **Install TShark**
    `pyshark` is a wrapper for **TShark**, the command-line version of Wireshark. You must have it installed.

    - **On macOS (using Homebrew):**
      ```bash
      brew install wireshark
      ```
    - **On Debian/Ubuntu:**
      ```bash
      sudo apt-get install tshark
      ```
    - **On Windows:** Download and install from the [Wireshark website](https://www.wireshark.org/download.html).

## Usage

Use the `-h` or `--help` flag to see all available options.

```bash
python main.py -h
```

### Example Commands

- **Live Capture from an Interface**
  Capture 100 packets from the `en0` interface and save the map every 20 packets.

  ```bash
  sudo python main.py -i en0 -c 100 -u 20
  ```

  > **Note:** On Linux and macOS, you may need to run the script with `sudo` to capture from network interfaces.

- **Analyze a PCAP File**
  Process all packets from a file named `capture.pcap` and save the output to `traffic_analysis.html`.
  ```bash
  python main.py -f capture.pcap -o traffic_analysis.html
  ```

Once the script is running, open the `network_map.html` (or your specified output file) in a web browser. If you are doing a live capture, you can refresh the page to see the updated map.
