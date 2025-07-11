import socketio
import time

# Create a Socket.IO client
sio = socketio.Client()

@sio.event
def connect():
    print('Successfully connected to WebSocket server')

@sio.event
def connect_error(error):
    print(f"Connection error: {error}")

@sio.event
def disconnect():
    print('Disconnected from WebSocket server')

@sio.event
def scan_update(data):
    print('\n=== Received scan update ===')
    print(f"Total scans: {data['total_scans']}")
    print(f"Phishing count: {data['phishing_count']}")
    print("Recent scans:")
    for scan in data['recent_scans']:
        status = "✅ SAFE" if not scan['is_phishing'] else "❌ PHISHING"
        print(f"- {scan['url']} ({status}, {scan['confidence']*100:.1f}%)")

print("Connecting to WebSocket server...")
try:
    sio.connect('http://localhost:5000')
    
    # Keep the connection open and listen for updates
    print("Connected! Waiting for scan updates... (Press Ctrl+C to exit)")
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nDisconnecting...")
    sio.disconnect()
except Exception as e:
    print(f"Error: {e}")
