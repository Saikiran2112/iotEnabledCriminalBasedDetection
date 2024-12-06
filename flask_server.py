import cv2
import threading
from flask import Flask, Response, request, jsonify
from queue import Queue

app = Flask(__name__)

# Global variables
capture = None
is_camera_on = False
access_requests = Queue()
approved_ips = set()
lock = threading.Lock()

# Function to generate frames from the webcam
def generate_frames():
    global capture
    while is_camera_on:
        success, frame = capture.read()
        if not success:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

@app.route('/video_feed')
def video_feed():
    client_ip = request.remote_addr
    if client_ip in approved_ips:
        return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')
    else:
        access_requests.put(client_ip)
        return "Access request sent to GUI. Please wait for approval.", 202

@app.route('/camera_status')
def camera_status():
    return jsonify({"camera_on": is_camera_on})

@app.route('/toggle_camera', methods=['POST'])
def toggle_camera():
    global is_camera_on, capture
    with lock:
        if is_camera_on:
            is_camera_on = False
            if capture:
                capture.release()
            return jsonify({"camera_on": False})
        else:
            capture = cv2.VideoCapture(0)
            is_camera_on = True
            return jsonify({"camera_on": True})

@app.route('/shutdown', methods=['POST'])
def shutdown():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()
    return 'Server shutting down...'

@app.route('/get_access_requests')
def get_access_requests():
    requests_list = []
    while not access_requests.empty():
        requests_list.append(access_requests.get())
    return jsonify({"requests": requests_list})

@app.route('/approve_access', methods=['POST'])
def approve_access():
    ip = request.json.get("ip")
    approved_ips.add(ip)
    return jsonify({"approved": ip})

def run_server():
    app.run(host='0.0.0.0', port=5000)

if __name__ == "__main__":
    run_server()
