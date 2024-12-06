import nmap
from scapy.all import ARP, Ether, srp, conf

def arp_scan(ip):
    # Disable scapy verbose output
    conf.verb = 0

    # Create an ARP request packet
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the packet and capture the response
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Parse the response to get the MAC address
    for sent, received in answered_list:
        return received.hwsrc
    return None

def scan_device(ip_address):
    # Initialize the nmap.PortScanner object
    nm = nmap.PortScanner()

    # Perform a scan on the given IP address with detailed options
    print(f"Scanning IP address: {ip_address}")
    nm.scan(ip_address, arguments='-T4 -A -v')  # Detailed aggressive scan

    # Check if the scan was successful and results are available
    if ip_address in nm.all_hosts():
        host = nm[ip_address]

        # Get the device's OS information if available
        if 'osclass' in host and len(host['osclass']) > 0:
            os_info = host['osclass'][0]['osfamily']
        else:
            os_info = 'N/A'
        print(f"OS Family: {os_info}")

        # Get the MAC address using ARP scan
        mac_address = arp_scan(ip_address)
        if not mac_address and 'addresses' in host and 'mac' in host['addresses']:
            mac_address = host['addresses']['mac']
        mac_address = mac_address if mac_address else 'N/A'
        print(f"MAC Address: {mac_address}")

        # Get the device name if available
        if 'hostnames' in host and len(host['hostnames']) > 0:
            device_name = host['hostnames'][0]['name']
        else:
            device_name = 'N/A'
        print(f"Device Name: {device_name}")

        # Get additional information
        if 'osmatch' in host:
            os_match = host['osmatch'][0]['name'] if len(host['osmatch']) > 0 else 'N/A'
            print(f"OS Match: {os_match}")

        if 'vendor' in host['addresses']:
            vendor = host['addresses']['vendor']
            print(f"Vendor: {vendor}")

        for proto in host.all_protocols():
            print(f"\nProtocol : {proto}")
            lport = host[proto].keys()
            for port in lport:
                service = host[proto][port]['name']
                state = host[proto][port]['state']
                version = host[proto][port].get('version', 'N/A')
                product = host[proto][port].get('product', 'N/A')
                print(f"Port : {port}\tState : {state}\tService : {service}\tProduct : {product}\tVersion : {version}")
    else:
        print(f"No information available for IP address: {ip_address}")
if __name__ == "__main__":
    ip_address = input("Enter the IP address to scan: ")
    scan_device(ip_address)
