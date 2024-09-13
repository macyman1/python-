import nmap
import sys

def scan_ip(ip_address):
    # Initialize the Nmap object
    nm = nmap.PortScanner()

    # Perform an aggressive scan to get a detailed report
    try:
        print(f"Scanning IP address: {ip_address}")
        
        # Perform scan (you can customize the scan arguments as needed)
        nm.scan(ip_address, arguments='-A')  # '-A' enables OS detection, version detection, script scanning, and traceroute

        # Print the detailed scan report
        print("\nScan Results:")
        print(f"Host: {nm[ip_address].hostname()}")
        print(f"State: {nm[ip_address].state()}")

        for proto in nm[ip_address].all_protocols():
            print(f"\nProtocol: {proto}")
            lport = nm[ip_address][proto].keys()
            for port in sorted(lport):
                print(f"Port: {port}\tState: {nm[ip_address][proto][port]['state']}")
                
        # Optional: print more detailed information
        print("\nDetailed Information:")
        print(nm.csv())  # Print the scan results in CSV format

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan.py <IP_ADDRESS>")
        sys.exit(1)

    ip = sys.argv[1]
    scan_ip(ip)
