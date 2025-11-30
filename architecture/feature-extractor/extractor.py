import json
import os
import subprocess
import tempfile
import threading
import redis
from flask import Flask, request, jsonify
from datetime import datetime
from utils import get_logger

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

app = Flask(__name__)
logger = get_logger('feature_extractor')

def extract_traffic_features(pcap_path, base_config_path="config.json"):
    """
        Extract network features from the input pcap.
    """

    try:
        # the filename of the output is taken from the input filename
        base_name = os.path.splitext(os.path.basename(pcap_path))[0]
        output_filename = f"{base_name}.csv"
        output_path = os.path.join("/app/output", output_filename)

        with open(base_config_path, 'r') as f:
            config = json.load(f)

        config['pcap_file_address'] = pcap_path
        config['output_file_address'] = output_path
        
        # using a temporary config file to avoid concurrency issues
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_config_file:
            json.dump(config, temp_config_file, indent=2)
            temp_config_file.flush()
            temp_config_path = temp_config_file.name

        logger.info(f"Using temporary config file: {temp_config_path}")
        logger.info(f"Starting feature extraction for {pcap_path}")
    
        subprocess.run(['ntlflowlyzer', '-c', temp_config_path], check=True)
        os.remove(temp_config_path)

        redis_key = f"features:{output_filename}"
        upload_csv_to_redis(output_path, redis_key)

        logger.info(f"Feature extraction completed successfully for {pcap_path}")   
    except subprocess.CalledProcessError as e:
        logger.error(f"Extraction failed for {pcap_path} with error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during extraction for {pcap_path}: {e}")


def extract_timestamp_from_filename(filename: str):
    """
        Extract Unix timestamp from 'features:capture_YYYYMMDD_HHMMSS.csv'
    """
    name = filename.replace(".csv", "")
    parts = name.split("_")
    dt = datetime.strptime(parts[1] + parts[2], '%Y%m%d%H%M%S')

    return dt.timestamp()



def upload_csv_to_redis(csv_path, redis_key):
    """
        Save the .csv in Redis and saves the timestamp in the Redis sorted set 'features_index'
    """
    logger.info(f"Uploading CSV {csv_path} to Redis with key {redis_key}")
    try:
        with open(csv_path, 'r') as f:
            csv_content = f.read()
        redis_client.set(redis_key, csv_content)

        timestamp = extract_timestamp_from_filename(redis_key)
        redis_client.zadd("features_index", {redis_key: timestamp})
        logger.info(f"CSV data uploaded to Redis successfully under key {redis_key}")
    except Exception as e:
        logger.error(f"Failed to upload CSV to Redis: {e}")



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
    
