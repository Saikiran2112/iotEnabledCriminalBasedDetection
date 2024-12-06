import requests
import threading
import time

# Replace this with your local machine's IP address
LOCAL_IP = "192.168.1.145"  # Example IP address, replace with your actual IP
PORT = 5000  # Port where your server is running
URL = f"http://{LOCAL_IP}:{PORT}/video_feed"

# Number of threads to simulate high traffic
NUM_THREADS = 1000

# Function to repeatedly send requests
def send_requests():
    while True:
        try:
            response = requests.get(URL)
            print(f"Request sent, status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")

# Create and start multiple threads
threads = []
for _ in range(NUM_THREADS):
    thread = threading.Thread(target=send_requests)
    thread.start()
    threads.append(thread)

# Let the threads run for a specific duration
duration = 30  # seconds
print(f"Running DDoS simulation for {duration} seconds...")
time.sleep(duration)

# Stopping threads is not straightforward in Python, usually handled by setting a flag.
print("DDoS simulation completed. You can stop the script now.")

# To stop the script, you'll need to manually interrupt (Ctrl+C) or terminate it.
