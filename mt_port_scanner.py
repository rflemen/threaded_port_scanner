# Multithreaded port scanner by Rob Flemen
from queue import Queue # Queue module for multithreading
import threading # Multithreading module
import socket # Socket module for network connections
import argparse # Argument parsing module
import pyfiglet # ASCII art module
import time # Time module for timing the scan
import re # Regular Expression module for IP address validation 


# Create the banner for the program
banner = pyfiglet.figlet_format("Port Scanner", font="slant")
print("\nThreaded...")
print(banner)
print("\t\t\t\t\t\t by Rob Flemen\n")


# Setup the queue, lists, and arguments parser
queue = Queue()
ports_open = []
ports_closed = []
parser = argparse.ArgumentParser()
parser.add_argument("ip_address", help="the ip address to be scanned")
parser.add_argument("-m", "--mode", help="1=Ports 1-1024; 2=Most common ports; 3=All ports", type=int)
args = parser.parse_args()
print(f"The IP to be scanned is: {args.ip_address}")
if args.mode == 1:
    print(f"The mode to be used is: Well known ports (1-1024)\n")
elif args.mode == 2:
    print(f"The mode to be used is: Most common ports\n")
elif args.mode == 3:
    print(f"The mode to be used is: All ports\n")


# Determine if IP addresses is valid IP address. REGEX pattern taken from: 
# "https://www.oreilly.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html 
# I did have to add an escape character "\" before the "\." for it to work completely correctly
def validate_ip(ip):
    pattern = re.compile('''(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)''')
    test = pattern.search(ip) 
    if test: # valid IP address
        return True
    else: # invalid IP address
        print("\nInvalid IP address entered. Exiting program.\n")
        exit()


# Make sure the IP address argument entered is a valid IP
validate_ip(args.ip_address)
target = args.ip_address
scan_mode = args.mode


# Function to scan the ports
def portscan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, port))
        s.shutdown(2)
        return True
    except:
        return False


# Determine which ports to scan based on the mode argument entered
def port_list(scan_mode):
    # Scan "well-known" ports
    if scan_mode == 1:
        for port in range(1, 1025):
            queue.put(port)
    elif scan_mode == 2:
        # Scan common ports
        ports = [20, 21, 22, 23, 25, 53, 69, 80, 88, 102, 110, 111, 135, 137, 139, 143, 381, 383, 443,
                 445, 464, 465, 587, 593, 636, 691, 902, 989, 990, 993, 1025, 1194, 1337, 1589, 1725, 2082, 
                 3074, 3306, 3389, 3585, 3586, 3724, 4444, 5432, 5900, 6665, 6666, 6667, 6668, 6669, 6881,
                 6970, 6999, 8086, 8087, 8222, 9100, 10000, 12345, 12345, 27374, 31337]
        for port in ports:
            queue.put(port)
    elif scan_mode == 3:
        # Scan all 65,535 ports
        for port in range(1, 65536):
            queue.put(port) 


# Assign workers to scan the ports and add open and closed ports to appropriate lists
def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            print(f"[\N{CHECK MARK}]\tport {format(port)} is OPEN!")
            ports_open.append(port)   
        else:
            ports_closed.append(port)


# Run the scanner
def run_scanner(threads, scan_mode):
    port_list(scan_mode)
    start_time = time.time()
    thread_list = []
    for t in range(threads): # Add threads to the thread list
        thread = threading.Thread(target=worker) # Create a thread and assign the worker function to it
        thread_list.append(thread) # Add the thread to the thread list
    for thread in thread_list: # Start the threads
        thread.start()
    for thread in thread_list:
        thread.join() # Wait for all threads to finish
    end_time = time.time()
    duration = end_time - start_time # Calculate the duration of the scan
    
    # Print the results of the scan and statistics
    print(f"\nStats for {target}:")
    print("--------------------------")
    print(f"[\N{CHECK MARK}]\t{len(ports_open)} ports are open: {ports_open}")
    print(f"[!]\t{len(ports_closed)} ports are closed.")
    print(f"[?]\t{len(ports_closed) + len(ports_open)} port scanned in {duration:.2f} seconds.")
    print(f"[?]\tScanned {int(((len(ports_closed) + len(ports_open))/duration))} ports per second.\n")


# Run the scanner
run_scanner(1800, scan_mode)
