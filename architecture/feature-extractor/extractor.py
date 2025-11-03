import os
import subprocess
import threading
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

# Logger config
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("feature_extractor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def extract_traffic_features(pcap_path):
    logger.info(f"Starting feature extraction for {pcap_path}")
    try:
        subprocess.run(['ntlflowlyzer', '-c', 'config.json'], check=True)
        logger.info(f"Feature extraction completed successfully for {pcap_path}")   
    except subprocess.CalledProcessError as e:
        logger.error(f"Extraction failed for {pcap_path} with error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during extraction for {pcap_path}: {e}")



@app.route("/new_pcap", methods=["POST"])
def new_pcap():
    data = request.json
    pcap_path = data.get('path')
    if not pcap_path or not os.path.exists(pcap_path):
        logger.error(f"PCAP file not found: {pcap_path}")
        return jsonify({'error': 'PCAP File not found'}), 400
    
    logger.info(f"Received new PCAP for processing: {pcap_path}")
    
    # execute feature extraction on a separate thread
    threading.Thread(target=extract_traffic_features, args=(pcap_path,)).start()

    return jsonify({
        "status": "Processing started"
    }), 200



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
    
