import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk  # You need to install pillow package
import requests
import subprocess
import time
import psutil
import os
import threading
import statistics
import nmap
from scapy.all import ARP, Ether, srp, conf

server_process = None
root = None
status_label = None
camera_status_label = None
network_traffic_table = None
ddos_status_label = None
nmap_result_text = None
current_image_index = 0  # To keep track of the current image index

# Initialize the global variables for DDoS detection
prev_packets_sent = 0
prev_packets_recv = 0
prev_time = time.time()

# Placeholder lists for adaptive thresholds
packets_sent_rates = []
packets_recv_rates = []

# Adjusted threshold factor for DDoS detection (increase for more sensitivity)
DDOS_THRESHOLD_FACTOR = 2

def get_adaptive_average_packets_sent_rate():
    # Use a moving average of the last 10 values for adaptive thresholding
    return statistics.mean(packets_sent_rates[-10:])

def get_adaptive_average_packets_recv_rate():
    # Use a moving average of the last 10 values for adaptive thresholding
    return statistics.mean(packets_recv_rates[-10:])

def start_server():
    global server_process
    if server_process is None:
        server_process = subprocess.Popen(['python', 'flask_server.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status_label.config(text="Server started")
        # Start monitoring for access requests
        threading.Thread(target=monitor_access_requests, daemon=True).start()
    else:
        status_label.config(text="Server is already running")

def stop_server():
    global server_process
    if server_process is not None:
        try:
            requests.post('http://127.0.0.1:5000/shutdown')
        except requests.exceptions.RequestException as e:
            print(f"Error shutting down server: {e}")
        server_process = None
        status_label.config(text="Server stopped")
    else:
        status_label.config(text="Server is not running")

def toggle_camera():
    url = 'http://127.0.0.1:5000/toggle_camera'
    try:
        response = requests.post(url)
        if response.status_code == 200:
            camera_status = response.json().get("camera_on", False)
            camera_status_label.config(text="Camera On" if camera_status else "Camera Off")
        else:
            camera_status_label.config(text="Error toggling camera")
    except Exception as e:
        camera_status_label.config(text=f"Error: {e}")

def monitor_access_requests():
    while True:
        try:
            response = requests.get('http://127.0.0.1:5000/get_access_requests')
            if response.status_code == 200:
                requests_list = response.json().get("requests", [])
                for ip in requests_list:
                    show_access_request(ip)
        except requests.exceptions.RequestException as e:
            print(f"Error getting access requests: {e}")
        time.sleep(5)

def show_access_request(ip):
    if messagebox.askyesno("Access Request", f"Allow {ip} to access the stream?"):
        approve_access(ip)

def approve_access(ip):
    try:
        requests.post('http://127.0.0.1:5000/approve_access', json={"ip": ip})
        print(f"Access granted to {ip}")
    except requests.exceptions.RequestException as e:
        print(f"Error approving access for {ip}: {e}")

def bytes_to_readable_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f} {unit}{suffix}"
        bytes /= factor

def update_network_traffic():
    net_io = psutil.net_io_counters(pernic=True)
    network_traffic_table.delete(*network_traffic_table.get_children())
    for iface, stats in net_io.items():
        network_traffic_table.insert("", "end", values=(
            iface,
            bytes_to_readable_size(stats.bytes_sent),
            bytes_to_readable_size(stats.bytes_recv),
            stats.packets_sent,
            stats.packets_recv
        ))
    
    global prev_packets_sent, prev_packets_recv, prev_time

    net_io = psutil.net_io_counters()

    # Calculate time difference since last update
    current_time = time.time()
    time_diff = current_time - prev_time

    # Calculate packets sent and received during the time window
    packets_sent = net_io.packets_sent
    packets_recv = net_io.packets_recv
    packets_sent_diff = packets_sent - prev_packets_sent
    packets_recv_diff = packets_recv - prev_packets_recv

    # Update previous values for next iteration
    prev_packets_sent = packets_sent
    prev_packets_recv = packets_recv
    prev_time = current_time

    # Calculate packet rates
    packets_sent_rate = packets_sent_diff / time_diff
    packets_recv_rate = packets_recv_diff / time_diff

    # Store packet rates for adaptive thresholding
    packets_sent_rates.append(packets_sent_rate)
    packets_recv_rates.append(packets_recv_rate)

    # DDoS detection logic with adaptive thresholds
    ddos_detected = False
    adaptive_packets_sent_rate = get_adaptive_average_packets_sent_rate()
    adaptive_packets_recv_rate = get_adaptive_average_packets_recv_rate()

    if packets_sent_rate > DDOS_THRESHOLD_FACTOR * adaptive_packets_sent_rate or \
            packets_recv_rate > DDOS_THRESHOLD_FACTOR * adaptive_packets_recv_rate:
        ddos_detected = True

    if ddos_detected:
        print("DDoS attack detected!")
        print(f"Packets Sent Rate: {packets_sent_rate} packets/second")
        print(f"Packets Received Rate: {packets_recv_rate} packets/second")
        print(f"time: {current_time}")
        ddos_status_label.config(text="DDoS attack detected", fg="red")
    else:
        ddos_status_label.config(text="No DDoS attack detected", fg="green")
    
    root.after(1000, update_network_traffic)

def nmap_scan(ip_address):
    # Initialize the nmap.PortScanner object
    nm = nmap.PortScanner()

    # Perform a scan on the given IP address with detailed options
    result_text = f"Scanning IP address: {ip_address}\n"
    nm.scan(ip_address, arguments='-T4 -A -v')  # Detailed aggressive scan

    # Check if the scan was successful and results are available
    if ip_address in nm.all_hosts():
        host = nm[ip_address]

        # Get the device's OS information if available
        os_info = host['osclass'][0]['osfamily'] if 'osclass' in host and len(host['osclass']) > 0 else 'N/A'
        result_text += f"OS Family: {os_info}\n"

        # Get additional information
        for proto in host.all_protocols():
            result_text += f"\nProtocol : {proto}\n"
            lport = host[proto].keys()
            for port in lport:
                service = host[proto][port]['name']
                state = host[proto][port]['state']
                version = host[proto][port].get('version', 'N/A')
                product = host[proto][port].get('product', 'N/A')
                result_text += f"Port : {port}\tState : {state}\tService : {service}\tProduct : {product}\tVersion : {version}\n"
    else:
        result_text += f"No information available for IP address: {ip_address}\n"

    return result_text

def create_gui():
    global status_label, camera_status_label, root, network_traffic_table, ddos_status_label, nmap_result_text, current_image_index
    root = tk.Tk()
    root.title("Webcam Control")
    root.geometry("1000x800")  # Increased the size for the GUI

    # Control Buttons Frame
    control_frame = tk.Frame(root)
    control_frame.pack(side="top", anchor="ne", padx=10, pady=10)

    toggle_button = tk.Button(control_frame, text="Toggle Camera", command=toggle_camera)
    toggle_button.grid(row=0, column=0, padx=5)

    camera_status_label = tk.Label(control_frame, text="Camera Off")
    camera_status_label.grid(row=0, column=1, padx=5)

    start_server_button = tk.Button(control_frame, text="Start Server", command=start_server)
    start_server_button.grid(row=0, column=2, padx=5)

    stop_server_button = tk.Button(control_frame, text="Stop Server", command=stop_server)
    stop_server_button.grid(row=0, column=3, padx=5)

    status_label = tk.Label(root, text="Server not running")
    status_label.pack(pady=10)

    # Network Traffic Frame
    network_traffic_frame = tk.Frame(root)
    network_traffic_frame.pack(pady=10)

    network_traffic_label = tk.Label(network_traffic_frame, text="Network Traffic")
    network_traffic_label.pack()

    columns = ("Interface", "Bytes Sent", "Bytes Received", "Packets Sent", "Packets Received")
    network_traffic_table = ttk.Treeview(network_traffic_frame, columns=columns, show="headings")
    for col in columns:
        network_traffic_table.heading(col, text=col)
    network_traffic_table.pack()

    # DDoS Status Label
    ddos_status_label = tk.Label(root, text="No DDoS attack detected", fg="green")
    ddos_status_label.pack(pady=10)

    # Nmap Scan Frame
    nmap_frame = tk.Frame(root)
    nmap_frame.pack(side="left", anchor="nw", padx=10, pady=10)

    nmap_label = tk.Label(nmap_frame, text="Nmap Scan")
    nmap_label.pack()

    # Entry for user to input IP address
    ip_entry_label = tk.Label(nmap_frame, text="Enter IP Address:")
    ip_entry_label.pack()
    ip_entry = tk.Entry(nmap_frame)
    ip_entry.pack()

    # Button to trigger the Nmap scan
    nmap_button = tk.Button(nmap_frame, text="Scan", command=lambda: perform_nmap_scan(ip_entry.get()))
    nmap_button.pack()

    # Frame to display Nmap scan results
    nmap_result_frame = tk.Frame(root)
    nmap_result_frame.pack(side="left", anchor="nw", padx=10, pady=10)

    nmap_result_label = tk.Label(nmap_result_frame, text="Nmap Scan Results")
    nmap_result_label.pack()

    nmap_result_text = tk.Text(nmap_result_frame, width=50, height=20)
    nmap_result_text.pack()

    # Function to perform the Nmap scan and display results
    def perform_nmap_scan(ip):
        result = nmap_scan(ip)
        nmap_result_text.delete('1.0', tk.END)
        nmap_result_text.insert(tk.END, result)

    # Frame for displaying suspect images
    image_frame = tk.Frame(root)
    image_frame.pack(side="right", anchor="ne", padx=10, pady=10)

    # Label to display the image
    image_label = tk.Label(image_frame)
    image_label.pack()

    # Function to update the displayed image
    def update_image():
        global current_image_index  # Use the global current_image_index variable
        # Get the list of image files in the folder
        image_files = [f for f in os.listdir("detected_suspects/") if f.endswith(".jpg")]

        if image_files:
            # Load the image at the current index
            latest_image_path = os.path.join("detected_suspects/", image_files[current_image_index])
            latest_image = Image.open(latest_image_path)
            latest_image = latest_image.resize((400, 400), Image.ANTIALIAS)

            # Convert image for display in Tkinter
            photo = ImageTk.PhotoImage(latest_image)
            image_label.configure(image=photo)
            image_label.image = photo  # Keep a reference to avoid garbage collection

            # Display the file name
            filename_label.config(text="File Name: " + image_files[current_image_index])
            filename_label.place(x=50, y=10)

            # Update the current image index to the next image
            current_image_index = (current_image_index + 1) % len(image_files)
        else:
            image_label.configure(image=None)  # Clear the image if no images are available
            filename_label.config(text="No images available")

        # Schedule the next update
        root.after(1000, update_image)

    # Label to display the image file name
    filename_label = tk.Label(image_frame)
    filename_label.pack()

    # Start updating the displayed image
    update_image()

    # Start the network traffic update loop after initializing all elements
    root.after(1000, update_network_traffic)

    root.mainloop()

# Run the GUI
create_gui()
