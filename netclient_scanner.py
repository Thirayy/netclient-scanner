import pyfiglet # type: ignore
import sys
import socket
from datetime import datetime
import ipaddress # For handling IP ranges

ascii_banner = pyfiglet.figlet_format("NETCLIENT SCANNER")
print(ascii_banner)

if len(sys.argv) != 2:
    print("Usage: python netclient_scanner.py <IP_range_CIDR>")
    print("Example: python netclient_scanner.py 192.168.1.0/24")
    sys.exit()

ip_range_str = sys.argv[1]

print("-" * 50)
print("Scanning started at:" + str(datetime.now()))
print("-" * 50)

active_hosts = []
target_port = 80 # Common port to check for host responsiveness

try:
    network = ipaddress.ip_network(ip_range_str, strict=False) # strict=False allows host bits to be set
    total_hosts = network.num_addresses - 2 # Exclude network and broadcast addresses for usable hosts
    if total_hosts < 1: # Handle cases like /31, /32 which have 0 or 1 usable hosts
        total_hosts = 1 # If the range is very small, treat as 1 for progress calculation

    print("\nScanning for active hosts in the range (this may take a while):")
    scanned_count = 0
    for ip in network.hosts(): # Iterate over usable hosts in the network
        scanned_count += 1
        print(f"  Scanning {ip} ({scanned_count}/{total_hosts}) ", end='\r')

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) # Decreased timeout for faster scan

        try:
            result = s.connect_ex((str(ip), target_port))
            if result == 0:
                print(f"  Host {ip} is active (port {target_port} open)    ") # Extra spaces to clear previous line
                active_hosts.append(str(ip))
        except socket.error:
            pass # Host not reachable or connection refused quickly
        finally:
            s.close()

except ValueError:
    print(f"Error: Invalid IP range format: {ip_range_str}")
    sys.exit()
except KeyboardInterrupt:
    print("\nExiting Program !!!!")
    sys.exit()
except Exception as e:
    print(f"\nAn unexpected error occurred: {e}")
    sys.exit()

print("\n" + "-" * 50)
print(f"Scan finished at: {datetime.now()}")
if active_hosts:
    print(f"Found {len(active_hosts)} active hosts in the range:")
    for host in active_hosts:
        print(f"  - {host}")
else:
    print("No active hosts found in the specified range.")
print("-" * 50)