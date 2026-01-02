#!/usr/bin/python3
# Threaded port scanner
# Written by Rob Flemen
# Author Github: https://github.com/rflemen
# Author YouTube: https://www.youtube.com/@RobFlemen 
# 1/1/2026

from queue import Queue # Queue module for multithreading
from queue import Empty # Exception for empty queue
import threading # Multithreading module
import socket # Socket module for network connections
import argparse # Argument parsing module
import time # Time module for timing the scan
import ipaddress # IP address validation module
import ssl # SSL module for secure connections



"""     -- G  L  O  B  A  L  S --     """


queue = Queue() # Create a queue object for multithreading
print_lock = threading.Lock() # Create a lock object for multithreading
open_ports = []
closed_ports_count = 0

SERVICE_PROBES = {
    21: b'USER anonymous\r\n',
    22: b'\r\n',
    25: b'HELO example.com\r\n',
    80: b'HEAD / HTTP/1.0\r\n\r\n',
    110: b'QUIT\r\n',
    143: b'1 LOGOUT\r\n',
    443: b'HEAD / HTTP/1.0\r\n\r\n',
    3306: b'\r\n',

    # RDP (TPKT/X.224)
    3389: b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00",

    # WinRM HTTP
    5985: (
        b"POST /wsman HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
}


SERVICE_SIGNATURES = {
    "ssh": ["ssh"],
    "http": ["http", "server:"],
    "ftp": ["ftp"],
    "smtp": ["smtp"],
    "pop3": ["pop3"],
    "imap": ["imap"],
    "mysql": ["mysql"],

    # WinRM exposes HTTPAPI headers
    "winrm": ["microsoft-httpapi", "www-authenticate"],
}


"""     -- F  U  N  C  T  I  O  N  S --     """


# Function to create the banner for the program
def print_banner():        
    print("SCRiPT By:                ")
    print("        ,------.           ")            
    print(",--,--, |  .--. ',--,--,--.") 
    print("|      ;|  '--' ||        |") 
    print("|  ||  ||  | --' |  |  |  |") 
    print("`--''--'`--'     `--`--`--'")                            
    print("Threaded Port Scanner")
    print("Version 1.0 - Written by Rob Flemen")
    print("") 
    time.sleep(0.5)


# Function to get the arguments from the user
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="the ip address to be scanned")
    parser.add_argument("-m", "--mode", help="1=Ports 1-1024; 2=Most common ports; 3=All ports", type=int, default=1)
    args = parser.parse_args()
    print(f"IP to be scanned is: \033[93m{args.ip}\033[00m")
    if args.mode == 1:
        print(f"Scan mode: \033[93mWell known ports (1-1024)\033[00m")
    elif args.mode == 2:
        print(f"Scan mode: \033[93mMost common ports\033[00m")
    elif args.mode == 3:
        print(f"Scan mode: \033[93mAll ports\033[00m")
    return args


# Determine if IP addresses is valid
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        print("\nInvalid IP address. Exiting.\n")
        exit()


# Function to get the domain name of the IP address, if available
def get_domain_name(target):
    print(f"Attempting to resolve the domain name for \033[93m{target}\033[00m")
    try:
        hostname = socket.gethostbyaddr(target)[0]
        print(f"[\033[92mSUCCESS\033[00m] The domain name is: \033[93m{hostname}\033[00m\n")
    except (socket.timeout, ConnectionRefusedError, OSError, socket.herror):
        print("[\033[91mFAILED\033[00m] Domain name not found\n")
        

def tls_probe(target, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=2.0) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                tls_sock.settimeout(2.0)
                tls_sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = tls_sock.recv(1024)
                return data
    except Exception:
        return None


# Function to detect service
def fingerprint_service(conn, port):
    try:
        # TLS-only ports
        if port in (443, 5986):
            data = tls_probe(target, port)
            if not data:
                return "tls", "TLS service detected (no banner)"
            banner = data.decode(errors="ignore").lower()
            if port == 5986:
                return "winrm-https", "WinRM HTTPS detected"

            if "server:" in banner or "http" in banner:
                return "https", data.decode(errors="ignore").strip()

            return "tls", data.decode(errors="ignore").strip()
        # Plaintext services
        conn.settimeout(2.0)
        probe = SERVICE_PROBES.get(port, b'\r\n')
        conn.sendall(probe)
        data = conn.recv(1024)

        # RDP (binary protocol)
        if port == 3389 and data.startswith(b"\x03\x00"):
            return "rdp", "RDP detected (TPKT response)"
        if not data:
            return None, None
        banner = data.decode(errors="ignore").lower()
        for service, keywords in SERVICE_SIGNATURES.items():
            for keyword in keywords:
                if keyword in banner:
                    return service, data.decode(errors="ignore").strip()
        return "unknown", data.decode(errors="ignore").strip()

    except Exception:
        return None, None


# Function to scan the ports
def scan_ports(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((target, port))

        print(f"[\033[92m\N{CHECK MARK}\033[00m] port {format(port)} is OPEN!")

        with print_lock:
            service, banner = fingerprint_service(s, port)
            if service:
                print(f"    [\033[93mSERVICE\033[00m] {service.upper()}")
            if banner:
                print(f"    [\033[93mBANNER\033[00m]  {banner}")    
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        s.close()


# Function to determine which ports to scan based on the mode argument entered
def get_ports(scan_mode):
    if scan_mode == 1: # Scan "well-known" ports
        for port in range(1, 1025):
            queue.put(port)
    elif scan_mode == 2: # Scan common ports
        ports = [20, 21, 22, 23, 25, 53, 69, 80, 88, 102, 110, 111, 135, 137, 139, 143, 381, 383, 443,
                 445, 464, 465, 587, 593, 636, 691, 902, 989, 990, 993, 1025, 1194, 1337, 1589, 1725, 2082, 
                 3074, 3306, 3389, 3585, 3586, 3724, 4444, 5432, 5900, 5985, 5986, 6665, 6666, 6667, 6668, 6669,
                 6881, 6970, 6999, 8000, 8080, 8086, 8087, 8222, 9100, 9999, 10000, 12345, 27374, 31337]
        for port in ports:
            queue.put(port)
    elif scan_mode == 3: # Scan all 65,535 ports
        for port in range(1, 65536):
            queue.put(port) 


# Function to assign workers to scan the ports and add open and closed ports to appropriate lists
def assign_worker():
    global closed_ports_count
    while True:
        try:
            port = queue.get_nowait()
        except Empty:
            break
        result = scan_ports(port)
        with print_lock:
            if result:
                open_ports.append(port)
            else:
                closed_ports_count += 1
        queue.task_done()


# Function to start the scanner & print statistics
def start_scanner(threads, scan_mode):
    get_ports(scan_mode)
    start_time = time.time()
    thread_list = []
    print(f"Attempting to scan the ports on \033[93m{target}\033[00m\n")
    for t in range(threads): # Add threads to the thread list
        thread = threading.Thread(target=assign_worker) # Create a thread and assign the worker function to it
        thread_list.append(thread) # Add the thread to the thread list
    for thread in thread_list: # Start the threads
        thread.start()
    queue.join() # Wait for the queue to be empty
    for thread in thread_list:
        thread.join() # Wait for all threads to finish
    end_time = time.time()
    duration = end_time - start_time # Calculate the duration of the scan
    return duration
    

# Function to print the overall results of the scan
def print_results(duration):
    print(f"\nStats for \033[93m{target}\033[00m:")
    print("--------------------------")
    print(f"[\033[92m\N{CHECK MARK}\033[00m]\t\033[93m{len(open_ports)}\033[00m ports are \033[92mOPEN\033[00m: \033[93m{sorted(open_ports)}\033[00m")
    print(f"[\033[91m!\033[00m]\t\033[93m{closed_ports_count}\033[00m ports are \033[91mCLOSED\033[00m.")
    print(f"[\033[93m?\033[00m]\t\033[93m{(closed_ports_count) + len(open_ports)}\033[00m ports scanned in \033[93m{duration:.2f}\033[00m seconds.")
    print(f"[\033[93m?\033[00m]\tScanned \033[93m{int(((closed_ports_count + len(open_ports))/duration))}\033[00m ports per second.\n")


# Run the port scanner
try:
    print_banner() # Print the program banner
    args = get_arguments() # Get the arguments from the user for use in program
    target = validate_ip(args.ip) # Validate the IP address entered by user
    scan_mode = args.mode # Get the scan mode seleted by user
    get_domain_name(target) # Get the domain name of the IP address if available
    duration = start_scanner(200, scan_mode) # Start the port scanner and return the duration of the scan once completed
    print_results(duration) # Print the statistics of the scan
except KeyboardInterrupt:
    print("\n\033[91mScan interrupted by user. Exiting program. Goodbye!\n\033[00m")
    exit()
