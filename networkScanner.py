import threading
from scapy.layers.l2 import ARP, Ether, srp
import ipaddress
import socket
import requests
import concurrent.futures

# Define multiple MAC address lookup services (without API keys)
mac_lookup_services = [
    "https://api.macvendors.com/{mac_address}",
    "https://macaddress.io/api/{mac_address}",
    "https://macvendors.co/api/{mac_address}",
]


# Function to perform MAC address lookup
def lookup_mac(mac_address):
    """
    Look up the manufacturer of a MAC address using multiple online services.

    Args:
        mac_address (str): MAC address to look up.

    Returns:
        str: Manufacturer name if found, "Not found" otherwise.
    """
    for service in mac_lookup_services:
        try:
            api_url = service.format(mac_address=mac_address)
            response = requests.get(api_url)
            if response.status_code == 200:
                return response.text
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
    return "Not found"


# Function to perform port scanning
def scan_ports(ip, ports):
    """
    Scan a range of ports on a given IP address.

    Args:
        ip (str): IP address to scan.
        ports (list): List of ports to scan.

    Returns:
        list: List of open ports.
    """
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports


def send_arp_request(thread_num, target_ips, network_interface, result, no_response_ranges, perform_lookup,
                     arp_responses, target_ports):
    """
    Send ARP requests to a range of IP addresses and store responses.

    Args:
        thread_num (int): Thread number.
        target_ips (list): List of target IP addresses to scan.
        network_interface (str): Network interface to use.
        result (list): List to store scan results.
        no_response_ranges (list): List to store IP ranges with no responses.
        perform_lookup (bool): Whether to perform manufacturer lookup.
        arp_responses (dict): Dictionary to store ARP responses.
        target_ports (list): List of ports to scan (if enabled).
    """
    start_ip = target_ips[0]
    end_ip = target_ips[-1]
    print(f"Thread {thread_num}: Sending ARP requests to devices {start_ip} through {end_ip}...")

    arp = ARP(pdst=target_ips)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    response, _ = srp(packet, timeout=3, iface=network_interface, verbose=False)

    if response:
        # Store ARP responses in the dictionary for this thread
        arp_responses[thread_num] = response
    else:
        no_response_ranges.append((start_ip, end_ip))


def print_arp_responses(result, perform_lookup, arp_responses, target_ports):
    """
    Print ARP responses and open ports.

    Args:
        result (list): List of scan results.
        perform_lookup (bool): Whether to perform manufacturer lookup.
        arp_responses (dict): Dictionary containing ARP responses.
        target_ports (list): List of ports to scan (if enabled).
    """
    for thread_num, response in arp_responses.items():
        print(f"Thread {thread_num}: Received ARP responses from {len(response)} devices:")
        for index, (sent, received) in enumerate(response, start=1):
            mac_address = received.hwsrc
            manufacturer = lookup_mac(mac_address) if perform_lookup else "N/A"
            ip_address = received.psrc
            open_ports = []
            if target_ports:
                open_ports = scan_ports(ip_address, target_ports)
            print(f"{index}. IP Address: {ip_address}, MAC Address: {mac_address}, Manufacturer: {manufacturer}")
            result.append(
                {'ip': ip_address, 'mac': mac_address, 'manufacturer': manufacturer, 'open_ports': open_ports})


def main():
    target_cidr = input("Enter the target CIDR range (e.g., 192.168.1.0/24): ")
    network_interface = input("Enter the network interface (e.g., Wi-Fi): ")
    num_threads = 5
    perform_lookup = input("Perform manufacturer lookup? Will slow the enumeration (yes/no): ").lower() == "yes"
    enable_port_scan = input(
        "WARNING: Very slow (O(n + m)), working on optimizing | Enable port scanning? (yes/no): ").lower() == "yes"

    if enable_port_scan:
        start_port = int(input("Enter the starting port: "))
        end_port = int(input("Enter the ending port: "))
        target_ports = list(range(start_port, end_port + 1))
    else:
        target_ports = []

    # Parse the CIDR notation to get the target IPs
    target_ips = [str(ip) for ip in ipaddress.IPv4Network(target_cidr, strict=False)]

    chunk_size = len(target_ips) // num_threads

    threads = []
    result = []
    no_response_ranges = []
    arp_responses = {}  # Initialize the arp_responses dictionary

    print(f"Scanning {target_cidr} using {num_threads} threads...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        for i in range(num_threads):
            start = i * chunk_size
            end = start + chunk_size if i < num_threads - 1 else len(target_ips)
            chunk = target_ips[start:end]

            thread = executor.submit(send_arp_request, i + 1, chunk, network_interface, result, no_response_ranges,
                                     perform_lookup, arp_responses, target_ports)
            threads.append(thread)

        concurrent.futures.wait(threads)

    print_arp_responses(result, perform_lookup, arp_responses, target_ports)  # Print ARP responses and open ports

    print("\nDevices that did not respond:")
    for start_ip, end_ip in no_response_ranges:
        print(f"  - IP Range: {start_ip} through {end_ip}")

    print("\nScan complete. Discovered devices:")
    result.sort(key=lambda x: x['ip'])  # Sort the discovered devices by IP address
    for device in result:
        print(f"IP Address: {device['ip']}, MAC Address: {device['mac']}, Manufacturer: {device['manufacturer']}")
        if device['open_ports']:
            print(f"  Open Ports: {', '.join(map(str, device['open_ports']))}")


if __name__ == "__main__":
    main()
