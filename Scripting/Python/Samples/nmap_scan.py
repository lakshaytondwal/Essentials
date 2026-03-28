import nmap
import sys
import time

# Check if the correct number of arguments is provided
if len(sys.argv) != 2:
    print("Usage: python script.py <target_ip>")
    sys.exit(1)

target_ip = sys.argv[1]
nm_scan = nmap.PortScanner()

print('\nRunning ... \n')

# Perform scan with OS detection
try:
    nm_scanner = nm_scan.scan(target_ip, '80', arguments='-O')
except Exception as e:
    print(f"Error during scan: {e}")
    sys.exit(1)

# Check if host is up
if target_ip not in nm_scanner['scan']:
    print("Host not found. Exiting...")
    sys.exit(1)

host_info = nm_scanner['scan'][target_ip]

# Host status
host_is_up = "The host is: " + host_info['status']['state'] + ". \n"

# Port 80 status
if 'tcp' in host_info and 80 in host_info['tcp']:
    port_open = "The port 80 is: " + host_info['tcp'][80]['state'] + ". \n"
    method_scan = "The method of scanning is: " + host_info['tcp'][80]['reason'] + ". \n"
else:
    port_open = "The port 80 is: closed or not responding. \n"
    method_scan = "No method of scanning available. \n"

# OS detection result
if 'osmatch' in host_info and len(host_info['osmatch']) > 0:
    guessed_os = "There is a %s percent chance that the host is running %s" % (
        host_info['osmatch'][0]['accuracy'], host_info['osmatch'][0]['name']) + " .\n"
else:
    guessed_os = "OS detection failed or no OS matches found.\n"

# Write results to file
report_filename = f"{target_ip}.txt"
with open(report_filename, 'w') as f:
    f.write(host_is_up + port_open + method_scan + guessed_os)
    f.write("\nReport generated " + time.strftime("%Y-%m-%d_%H:%M:%S GMT", time.gmtime()))

print(f"\nScan complete. Report saved to {report_filename}")
