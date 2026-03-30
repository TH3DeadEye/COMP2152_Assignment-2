"""
Author: Arman Milani
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and OS
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Maps common port numbers to their well-known service names
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


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Without the setter, anything could set __target directly, including an empty string.
    # The setter validates the input first, so bad values get caught before they're stored.
    # From outside the class you still use scanner.target like a normal attribute, nothing changes.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner doesn't redefine the target property or the validation logic, it just
# inherits them from NetworkTool. super().__init__(target) handles the setup, so if
# I update the validation in NetworkTool later, PortScanner gets it automatically.

class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # A single unreachable port would crash the thread and you'd lose whatever
        # results were collected up to that point. The try-except catches it and
        # moves on to the next port instead.
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
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Each closed port waits out a 1 second timeout before moving on. Doing that
    # 1024 times in a row would take over 17 minutes. Threading runs the scans
    # at the same time so the whole thing finishes in a few seconds.
    
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, result[0], result[1], result[2], str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except Exception:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    target = input("Enter target IP address (default 127.0.0.1): ")
    target = target if target != "" else "127.0.0.1"

    try:
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
        print("Port must be between 1 and 1024.")
        exit()

    if end_port < start_port:
        print("End port must be greater than or equal to start port.")
        exit()

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port_info in open_ports:
        print(f"Port {port_info[0]}: {port_info[1]} ({port_info[2]})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    history = input("\nWould you like to see past scan history? (yes/no): ")
    if history == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# I would add a Port Risk Classifier that labels each open port as HIGH, MEDIUM, or LOW
# risk using a nested if-else,ports like 22 (SSH) and 3389 (RDP) are flagged HIGH since
# they're common attack targets, while everything else falls into MEDIUM or LOW.
# This makes the output actually useful instead of just listing what's open.
# Diagram: See diagram_101555606.png in the repository root
