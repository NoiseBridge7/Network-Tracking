import pyshark
import folium
import geocoder
import argparse
import time
from collections import defaultdict

# --- NEW: Function to get your own public IP location ---
def get_my_location():
    """
    Finds the user's own public IP and returns its location details.
    This serves as the anchor point for the local side of all connections.
    """
    try:
        my_ip_info = geocoder.ip('me')
        if my_ip_info.ok and my_ip_info.latlng:
            print(f"Successfully determined your location: {my_ip_info.city}, {my_ip_info.country}")
            return {
                "coords": my_ip_info.latlng,
                "city": my_ip_info.city,
                "country": my_ip_info.country
            }
    except Exception as e:
        print(f"Could not determine your public IP location: {e}")
    # Fallback location if detection fails
    print("Warning: Could not find your location. Defaulting to a central point.")
    return {"coords": [20, 0], "city": "Unknown", "country": "Unknown"}

# --- Helper Functions ---

def get_public_ip_location(ip):
    """
    Retrieves geolocation data for a PUBLIC IP address.
    Returns None if the IP is private.
    """
    # Exclude private IP ranges and multicast
    if ip.startswith(('192.168.', '10.', '172.')) or ip.startswith('224.'):
        return None
    try:
        g = geocoder.ip(ip)
        if g.ok and g.latlng:
            return {
                "coords": g.latlng,
                "city": g.city,
                "country": g.country
            }
    except Exception as e:
        print(f"Could not geocode public IP {ip}: {e}")
    return None

def create_base_map():
    """Creates and returns a new Folium map centered on the world."""
    return folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')

# --- Main Logic ---

def process_packets(capture, packet_count_limit, map_update_interval, output_file, my_location):
    """
    Processes packets, treating all local IPs as 'my_location'.
    """
    print("Starting packet processing...")
    network_map = create_base_map()
    packet_count = 0
    
    connections = defaultdict(lambda: {'count': 0, 'protocols': set()})

    for packet in capture:
        try:
            protocol = packet.transport_layer
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # --- MODIFIED: Determine which IP is local and which is remote ---
            src_loc = get_public_ip_location(src_ip)
            dst_loc = get_public_ip_location(dst_ip)
            
            # Skip if both are private or neither are found
            if not src_loc and not dst_loc:
                continue
            
            # Assign my_location to the private IP
            if not src_loc:
                src_ip_str = "Your Network"
                dst_ip_str = dst_ip
                connection_key = tuple(sorted((src_ip_str, dst_ip_str)))
            else:
                dst_ip_str = "Your Network"
                src_ip_str = src_ip
                connection_key = tuple(sorted((src_ip_str, dst_ip_str)))
            
            connections[connection_key]['count'] += 1
            if protocol:
                connections[connection_key]['protocols'].add(protocol)

            packet_count += 1
            print(f"Processed packet {packet_count}: {src_ip} -> {dst_ip} ({protocol})")

            if packet_count % map_update_interval == 0:
                print(f"\nUpdating map with {len(connections)} unique connections...\n")
                network_map = create_base_map()
                visualize_connections(network_map, connections, my_location)
                network_map.save(output_file)
                print(f"Map updated and saved to {output_file}")

            if packet_count_limit and packet_count >= packet_count_limit:
                break

        except (AttributeError, KeyError):
            continue
    
    print("\nCapture finished. Generating final map...")
    network_map = create_base_map()
    visualize_connections(network_map, connections, my_location)
    network_map.save(output_file)
    print(f"Final map saved to {output_file}. Open this file in your browser.")

def visualize_connections(network_map, connections, my_location):
    """
    Draws all captured connections on the map, anchoring local IPs to my_location.
    """
    protocol_colors = {'TCP': 'red', 'UDP': 'blue', 'ICMP': 'green', 'DEFAULT': 'gray'}
    
    # Add a marker for your location
    folium.Marker(
        location=my_location['coords'],
        popup=f"Your Location: {my_location['city']}, {my_location['country']}",
        icon=folium.Icon(color='green', icon='home')
    ).add_to(network_map)

    for (ip1, ip2), data in connections.items():
        # Determine which is the remote IP
        remote_ip = ip1 if ip2 == "Your Network" else ip2
        
        remote_loc = get_public_ip_location(remote_ip)
        
        if remote_loc:
            popup_text = f"""
            <b>Connection</b><br>
            From: Your Network ({my_location['city']})<br>
            To: {remote_ip} ({remote_loc['city']}, {remote_loc['country']})<br>
            Packets: {data['count']}<br>
            Protocols: {', '.join(data['protocols'])}
            """
            
            main_protocol = next(iter(data['protocols']), 'DEFAULT')
            color = protocol_colors.get(main_protocol, protocol_colors['DEFAULT'])
            
            folium.PolyLine(
                locations=[my_location['coords'], remote_loc['coords']],
                color=color,
                weight=2.5,
                opacity=0.8,
                popup=folium.Popup(popup_text, max_width=300)
            ).add_to(network_map)

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Visualizer")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interface', type=str, help='Network interface to sniff on.')
    group.add_argument('-f', '--file', type=str, help='PCAP file to read packets from.')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture. 0 for infinite.')
    parser.add_argument('-u', '--update', type=int, default=25, help='Update the map every N packets.')
    parser.add_argument('-o', '--output', type=str, default='network_map.html', help='Output HTML file name.')
    
    args = parser.parse_args()
    
    # --- NEW: Get your location once at the start ---
    my_location = get_my_location()

    capture = None
    if args.interface:
        print(f"Starting live capture on interface: {args.interface}")
        capture = pyshark.LiveCapture(interface=args.interface)
    elif args.file:
        print(f"Reading packets from file: {args.file}")
        capture = pyshark.FileCapture(args.file)
        
    try:
        process_packets(
            capture=capture,
            packet_count_limit=args.count,
            map_update_interval=args.update,
            output_file=args.output,
            my_location=my_location # Pass your location to the main function
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        if capture:
            capture.close()

if __name__ == "__main__":
    main()