"""
Author: Munir Howlader
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# TODO: Import the required modules (Step ii)
# socket, threading, sqlite3, os, platform, datetime
import socket
import threading
import sqlite3
import os
import platform
import datetime


# TODO: Print Python version and OS name (Step iii)

print(platform.python_version())
print(os.name)

# TODO: Create the common_ports dictionary (Step iv)
# Add a 1-line comment above it explaining what it stores

# Dictionary common_ports maps port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# TODO: Create the NetworkTool parent class (Step v)
# - Constructor: takes target, stores as private self.__target
# - @property getter for target
# - @target.setter with empty string validation
# - Destructor: prints "NetworkTool instance destroyed"

class NetworkTool:
    def __init__(self, target):
        self.__target = target
    
    # Q3: What is the benefit of using @property and @target.setter?
    '''Using @property and @target.setter gives us a safer way to work with the target value. Instead of
    changing self.__target directly from anywhere, we can control how it is read and updated. This is
    helpful because the setter can check for invalid values, like an empty string, before saving them.'''       
    @property
    def target(self):
        return self.__target
    
    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")
    
    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
'''PortScanner reuses code from NetworkTool through inheritance. It
automatically gets the targer related constructor, gettr, setter and destructors'''
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()



# - scan_port(self, port):


#     - try-except with socket operations
#     - Create socket, set timeout, connect_ex
#     - Determine Open/Closed status
#     - Look up service name from common_ports (use "Unknown" if not found)
#     - Acquire lock, append (port, status, service_name) tuple, release lock
#     - Close socket in finally block
#     - Catch socket.error, print error message


    def scan_port(self, port):
        sock = None
        #Q4: What would happen without try-except here?
        """Without a try-catch, any socket error during scanning could cause the program 
        to crash. Try-except allows the program to handle errors safetly and continue scanning
        the reamining ports"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            if sock:
                sock.close()




# - get_open_ports(self):
#     - Use list comprehension to return only "Open" results
#
#     Q2: Why do we use threading instead of scanning one port at a time?
    """We use threading because scanning ports one at a time would be much slower, especially if some ports
    take a while to respond. With threading, multiple ports can be checked at the same time, which speeds
    up the scan a lot. If we tried to scan all 1024 ports without threads, the program would still work,
    but it would take much longer to finish.""" 
    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

# - scan_range(self, start_port, end_port):
#     - Create threads list
#     - Create Thread for each port targeting scan_port
#     - Start all threads (one loop)
#     - Join all threads (separate loop)


    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

# TODO: Create save_results(target, results) function (Step vii)
# - Connect to scan_history.db
# - CREATE TABLE IF NOT EXISTS scans (id, target, port, status, service, scan_date)
# - INSERT each result with datetime.datetime.now()
# - Commit, close
# - Wrap in try-except for sqlite3.Error

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error: {e}")


# TODO: Create load_past_scans() function (Step viii)
# - Connect to scan_history.db
# - SELECT all from scans
# - Print each row in readable format
# - Handle missing table/db: print "No past scans found."
# - Close connection

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        for row in rows:
            target, port, status, service, scan_date = row
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

        conn.close()

    except sqlite3.Error:
        print("No past scans found.")
# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    # Getting the target IP
    try:
        target = input("Enter target IP address: ").strip()
        if target == "":
            target = "127.0.0.1"
    except Exception:
        target = "127.0.0.1"

    # Getting start port
    while True:
        try:
            start_port = int(input("Enter a starting port number (1-1024): "))
            if start_port < 1 or start_port > 1024:
                print("Port must be between 1 and 1024.")
            else:
                break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # end port
    while True:
        try:
            end_port = int(input("Enter an ending port number (1-1024): "))
            if end_port < 1 or end_port > 1024:
                print("Port must be between 1 and 1024.")
            elif end_port < start_port:
                print("Ending port must be greater than or equal to start port.")
            else:
                break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # scanner and scans
    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    # Show open ports
    open_ports = scanner.get_open_ports()
    print(f"--- Scan Results for {target} ---")
    for port, status, service_name in open_ports:
        print(f"Port {port}: {status} ({service_name})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    # Save results
    save_results(target, scanner.scan_results)

    # Show history if requested
    choice = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if choice == "yes":
        load_past_scans()


# Q5: New Feature Proposal
'''One additional feature I would add is a scan summary that groups open ports by service type, such as
Web, Remote Access, Email, and Other. This could use list comprehensions to filter the open ports into
separate lists based on their port numbers or service names.'''


# Diagram: See diagram_studentID.png in the repository root
