import socket
import threading
import csv
import json
import matplotlib.pyplot as plt
from datetime import datetime
from queue import Queue
from ipaddress import ip_network

print_lock = threading.Lock()
results = []
scan_history = []

common_ports = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
}

vulnerable_banners = ["OpenSSH 7.2", "Apache/2.4.7"]

def clean_banner(banner):
    if "<!DOCTYPE" in banner or "<html" in banner:
        return "HTML Content Detected"
    return banner.split("\n")[0][:100]

def check_vulnerability(banner):
    for vuln in vulnerable_banners:
        if vuln in banner:
            return True
    return False

def scan_port(target, port, live_update_callback=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            try:
                s.send(b"Hello\r\n")
                banner = s.recv(1024).decode(errors='ignore').strip()
            except:
                banner = "No banner"
            banner = clean_banner(banner)
            service = common_ports.get(port, socket.getservbyport(port, "tcp") if port < 1025 else "Unknown")
            is_vulnerable = check_vulnerability(banner)
            with print_lock:
                message = f"[+] {target} Port {port} OPEN | Service: {service} | Banner: {banner}"
                if is_vulnerable:
                    message += " | VULNERABLE SIGNATURE DETECTED!"
                print(message)
                if live_update_callback:
                    live_update_callback(message)
                results.append({
                    "target": target,
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "vulnerable": is_vulnerable
                })
        s.close()
    except:
        pass

def worker(target, port_queue, live_update_callback=None):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port, live_update_callback)
        port_queue.task_done()

def start_scan(target, start_port, end_port, num_threads=100, live_update_callback=None):
    print(f"\nScanning {target} from port {start_port} to {end_port}")
    if live_update_callback:
        live_update_callback(f"\nScanning {target} from port {start_port} to {end_port}")
    port_queue = Queue()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(target, port_queue, live_update_callback))
        t.daemon = True
        threads.append(t)
        t.start()

    port_queue.join()
    save_results(target)

def start_subnet_scan(subnet_cidr, start_port, end_port, num_threads=100, live_update_callback=None):
    net = ip_network(subnet_cidr)
    for host in net.hosts():
        start_scan(str(host), start_port, end_port, num_threads, live_update_callback)

def save_results(target):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = "results/"
    scan_history.append({"target": target, "time": timestamp, "results": results})

    with open(folder + f"scan_log.txt", "a") as log:
        log.write(f"Scan for {target} at {timestamp}\n")
        for r in results:
            vuln_note = " | VULNERABLE" if r["vulnerable"] else ""
            log.write(f"{r['target']} Port {r['port']} | {r['service']} | {r['banner']}{vuln_note}\n")
        log.write("\n")

    with open(folder + f"scan_results.csv", "w", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["target", "port", "service", "banner", "vulnerable"])
        writer.writeheader()
        writer.writerows(results)

    with open(folder + f"scan_results.json", "w") as jsonfile:
        json.dump(results, jsonfile, indent=4)

    print("\nResults saved to 'results/' folder.")
    if results:
       generate_graph()
    else:
        print("No open ports found. Skipping graph generation.")

def generate_graph():
    open_ports = [r["port"] for r in results]
    plt.figure(figsize=(10, 6))
    plt.hist(open_ports, bins=20, edgecolor='black')
    plt.title("Open Ports Frequency")
    plt.xlabel("Port Number")
    plt.ylabel("Frequency")
    plt.grid(True)
    plt.savefig("results/port_scan_graph.png")
    plt.close()
    print("Graph saved as results/port_scan_graph.png")