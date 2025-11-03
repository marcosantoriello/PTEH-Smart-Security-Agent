import os
import subprocess
import threading
from flask import Flask, request, jsonify

app = Flask(__name__)

def extract_traffic_features():
    subprocess.run(['ntlflowlyzer', '-c', 'config.json'], check=True)

@app.route("/new_pcap", methods=["POST"])
def new_pcap():
    data = request.json
    pcap_path = data.get('path')
    if not pcap_path or not os.path.exists(pcap_path):
        return jsonify({'error': 'PCAP File not found'}), 400
    
    # execute feature extraction on a separate thread
    threading.Thread(target=extract_traffic_features, args=(pcap_path,)).start()

    return jsonify({
        "status": "Processing started"
    }), 200



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
    
