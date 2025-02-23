# Multithreaded port scanner by Rob Flemen
from queue import Queue # Queue module for multithreading
import threading # Multithreading module
import socket # Socket module for network connections
import argparse # Argument parsing module
import pyfiglet # ASCII art module
import time # Time module for timing the scan
import re # Regular Expression module for IP address validation 


queue = Queue() # Create a queue object for multithreading
print_lock = threading.Lock() # Create a lock object for multithreading
ports_open = []
ports_closed = []


"""     -- F  U  N  C  T  I  O  N  S --     """


# Function to create the banner for the program
def print_banner():
    print("\nThreaded...\033[94m")
    scanner_banner = pyfiglet.figlet_format("Port Scanner", font="slant")
    print(scanner_banner, "\033[00m")
    print("v0.10\t\t\t\t\t\t by Rob Flemen\n")


# Function to get the arguments from the user
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="the ip address to be scanned")
    parser.add_argument("-m", "--mode", help="1=Ports 1-1024; 2=Most common ports; 3=All ports", type=int, default=1)
    args = parser.parse_args()
    print(f"The IP to be scanned is: \033[93m{args.ip}\033[00m")
    if args.mode == 1:
        print(f"The mode to be used is: \033[93mWell known ports (1-1024)\033[00m")
    elif args.mode == 2:
        print(f"The mode to be used is: \033[93mMost common ports\033[00m")
    elif args.mode == 3:
        print(f"The mode to be used is: \033[93mAll ports\033[00m")
    return args


# Determine if IP addresses is valid IP address using REGEX pattern
def validate_ip(ip):
    pattern = re.compile('''(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)''')
    test = pattern.search(ip) 
    if test: # valid IP address
        return ip
    else: # invalid IP address
        print("\n\033[91mInvalid IP address entered. Exiting program.\n\033[00m")
        exit()


# Function to get the domain name of the IP address, if available
def get_domain_name(target):
    print(f"Attempting to resolve the domain name for \033[93m{target}\033[00m")
    try:
        hostname = socket.gethostbyaddr(target)[0]
        return print(f"[\033[92mSUCCESS\033[00m] The domain name is: \033[93m{hostname}\033[00m\n")
    except socket.herror:
        return print("[\033[91mFAILED\033[00m] Domain name not found\n")


# Function to grab the banner of the service running on the open port, if available
def grab_banner(conn): 
    try:
        conn.send(b'GET /\n\n')
        ret = conn.recv(1024) 
        print(f"[\033[91mINFO\033[00m]", str(ret),"\n")
        return 
    except: 
        return


# Function to scan the ports
def scan_ports(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.1)
        s.connect((target, port))
        with print_lock:
            print(f"[\033[92m\N{CHECK MARK}\033[00m] port {format(port)} is OPEN!")
            grab_banner(s)
        s.shutdown(2)
        return (True)
    except:
        return False


# Function to determine which ports to scan based on the mode argument entered
def port_list(scan_mode):
    if scan_mode == 1: # Scan "well-known" ports
        for port in range(1, 1025):
            queue.put(port)
    elif scan_mode == 2: # Scan common ports
        ports = [20, 21, 22, 23, 25, 53, 69, 80, 88, 102, 110, 111, 135, 137, 139, 143, 381, 383, 443,
                 445, 464, 465, 587, 593, 636, 691, 902, 989, 990, 993, 1025, 1194, 1337, 1589, 1725, 2082, 
                 3074, 3306, 3389, 3585, 3586, 3724, 4444, 5432, 5900, 6665, 6666, 6667, 6668, 6669, 6881,
                 6970, 6999, 8086, 8087, 8222, 9100, 10000, 12345, 12345, 27374, 31337]
        for port in ports:
            queue.put(port)
    elif scan_mode == 3: # Scan all 65,535 ports
        for port in range(1, 65536):
            queue.put(port) 


# Function to assign workers to scan the ports and add open and closed ports to appropriate lists
def assign_worker():
    while not queue.empty():
        port = queue.get()
        if scan_ports(port):
            ports_open.append(port)   
        else:
            ports_closed.append(port)


# Function to start the scanner & print statistics
def start_scanner(threads, scan_mode):
    port_list(scan_mode)
    start_time = time.time()
    thread_list = []
    print(f"Attempting to scan the ports on \033[93m{target}\033[00m\n")
    for t in range(threads): # Add threads to the thread list
        thread = threading.Thread(target=assign_worker) # Create a thread and assign the worker function to it
        thread_list.append(thread) # Add the thread to the thread list
    for thread in thread_list: # Start the threads
        thread.start()
    for thread in thread_list:
        thread.join() # Wait for all threads to finish
    end_time = time.time()
    duration = end_time - start_time # Calculate the duration of the scan
    return duration
    

# Function to print the overall results of the scan
def print_results(duration):
    print(f"\nStats for \033[93m{target}\033[00m:")
    print("--------------------------")
    print(f"[\033[92m\N{CHECK MARK}\033[00m]\t\033[93m{len(ports_open)}\033[00m ports are \033[92mOPEN\033[00m: \033[93m{ports_open}\033[00m")
    print(f"[\033[91m!\033[00m]\t\033[93m{len(ports_closed)}\033[00m ports are \033[91mCLOSED\033[00m.")
    print(f"[\033[93m?\033[00m]\t\033[93m{len(ports_closed) + len(ports_open)}\033[00m ports scanned in \033[93m{duration:.2f}\033[00m seconds.")
    print(f"[\033[93m?\033[00m]\tScanned \033[93m{int(((len(ports_closed) + len(ports_open))/duration))}\033[00m ports per second.\n")


# Run the port scanner
print_banner() # Print the program banner
args = get_arguments() # Get the arguments from the user for use in program
target = validate_ip(args.ip) # Validate the IP address entered by user
scan_mode = args.mode # Get the scan mode seleted by user
get_domain_name(target) # Get the domain name of the IP address if available
duration = start_scanner(1800, scan_mode) # Start the port scanner and return the duration of the scan once completed
print_results(duration) # Print the statistics of the scan
