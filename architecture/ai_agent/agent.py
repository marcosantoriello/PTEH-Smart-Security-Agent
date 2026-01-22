import os
import redis
import json
import time
from utils import get_logger
from datetime import datetime
from typing import List, Dict
import requests
from ollama import Client

class SecurityAgent:
    def __init__(self):
        """Initialize SecurityAgent"""
        self.REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
        self.REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
        self.POLLING_INTERVAL = int(os.getenv('POLLING_INTERVAL', 15))
        self.OLLAMA_HOST = os.get_env('OLLAMA_HOST', 'http://host.docker.internal:11434')
        self.FIREWALL_URL = os.getenv('FIREWALL_URL', 'http://firewall:5002/apply_rule')

        self.redis_client = None
        self.ollama_client = None
        self.last_processed_ts = None
        self.model = None

        self.logger = get_logger('SecurityAgent')




    
    def _connect_to_redis(self):
        """
            Connect to Redis and retrieve last timestamp (if any)
        """
        self.logger.info("Connecting to Redis and retrieving last timestamp (if any)...")
        try:
            self.redis_client = redis.Redis(
                host=self.REDIS_HOST, 
                port=self.REDIS_PORT, 
                decode_responses=True
            )
            self.redis_client.ping()
            self.logger.info(f"Successfully connected to Redis at {self.REDIS_HOST}:{self.REDIS_PORT}")

            last_processed = self.redis_client.zrevrange("features_index", 0, 0, withscores=True)

            if not last_processed:
                self.last_processed_timestamp = None
                self.logger.info("Couldn't find the last processed timestamp")
            else:
                self.last_processed_timestamp = last_processed[0][1]
                self.logger.info(f"Last processed timestamp found. Resuming from {self.last_processed_timestamp=}")
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
    

    def setup(self):
        """
        Setup function:
            - Set up the logger
            - Connect to Redis
            - Retrieve last timestamp from Redis
            - Set the model
            - Set the Ollama client
        """
        self.logger.info("="*60)
        self.logger.info("Security Agent starting...")

        self._connect_to_redis()

        self.ollama_client = Client(host=self.OLLAMA_HOST)
        self.model = "llama3.2:3b"
        self.last_processed_ts = self._get_last_timestamp()



    def _get_last_timestamp(self) -> float:
        """Retrieves last processed timestamp from Redis"""
        try:
            result = self.redis_client.zrevrange(
                'agent_processed_index',
                0, 0,
                withscores=True
            )
            if result:
                return float(result[0][1])
        except Exception as e:
            self.logger.warning(f"Could not retrieve last timestamp: {e}")
        return 0.0




    def fetch_new_attacks(self) -> List[Dict]:
        """Retrieves new attacks from Redis"""
        try:
            keys = self.redis_client.zrangebyscore(
                'attacks_index',
                self.last_processed_ts,
                '+inf',
                start=0,
                num=10  # Max 10 attacks per batch
            )
            
            if not keys:
                return []
            
            attacks = []
            for key in keys:
                data = self.redis_client.get(key)
                if data:
                    attacks.extend(json.loads(data))
            
            self.logger.info(f"Fetched {len(attacks)} new attacks")
            return attacks
            
        except Exception as e:
            self.logger.error(f"Error fetching attacks: {e}")
            return []



    def generate_rule(self, attack: Dict) -> Dict:
        """Generates firewall rule using LLM"""


    




        


