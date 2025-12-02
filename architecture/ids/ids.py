import io
import os
import joblib
import redis
from utils import get_logger
import pandas as pd


class Ids:
    def __init__(self, model_path='model/model.pkl'):
        """
            Initialize IDS class
        """
        self.REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
        self.REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
        self.POLLING_INTERVAL = int(os.getenv('POLLING_INTERVAL', 10))
        self.MODEL_PATH = model_path

        self.redis_client = None
        self.last_processed_timestamp = None
        self.model = None
        self.scaler = None
        self.feature_names = None

        self.logger = get_logger('IDS')

    
    
    def setup(self):
        """
        Setup function:
            - Set up the logger
            - Connect to Redis
            - Retrieve last timestamp from Redis
            - Load the model
            - Load the scaler
        """
        self.logger.info("="*60)
        self.logger.info("Starting IDS module...")

        self._connect_to_redis()
        self._load_model_package()

        self.logger.info("Set up completed. IDS Up and Running!")



    def _connect_to_redis(self):
        """
            Connect to Redis and retrieve last timestamp (if any)
        """
        self.logger.info("Connecting to Reids and retrieving last timestamp (if any)...")
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

    

    def _load_model_package(self):
        """"
            Load model, scaler and feature_names from pickle file
        """
        self.logger.info("Loading model, scaler and feature names...")
        try:
            with open(self.MODEL_PATH, 'rb') as f:
                model_package = joblib.load(f)

                self.model = model_package['model']
                self.scaler = model_package['scaler']
                self.feature_names = model_package['feature_names']

                self.logger.info(f"Model package loaded from {self.MODEL_PATH}")
        except Exception as e:
            self.logger.error(f"Failed to load model package: {e}")

    

    def _get_new_files(self):
        """
            Retrieve new files from Redis in batches and merge them.

            Returns:
                pandas.DataFrame: a DataFrame containing the combined data from the new files.
        """
        retrieved_file_keys = self._get_new_files_keys()

        if not retrieved_file_keys:
            self.logger.info("No new files to retrieve")

        dataframes = []

        for key in retrieved_file_keys:
            try:
                csv_content = self.redis_client.get(key)

                if csv_content is None:
                    self.logger.warning(f"Key {key} exists in index but has no content.")
                    continue
                
                df = pd.read_csv(io.StringIO(csv_content))
                dataframes.append(df)
                self.logger.info(f"Loaded {len(df)} rows from {key}")
            
            except Exception as e:
                self.logger.error(f"Failed to load {key}: {e}. Skipping this file")
                continue
        
        if not dataframes:
            self.logger.warning("No valid files were loaded")
            return None
        
        combined_df = pd.concat(dataframes, ignore_index=True)
        self.logger.info(f"Successfully merged {len(dataframes)} file(s) into DataFrame with {len(combined_df)} rows")
        
        return combined_df
            
        

    def _get_new_files_keys(self):
        """
            Retrieve the keys of new files from Redis.

            Returns:
                list: a list of Redis keys representing the files to process.
        """
        try:
            if self.last_processed_timestamp is None:
                self.logger.info("No previous timestamp. Fetching all available files...")
                file_keys = self.redis_client.zrange("features_index", 0, -1)

            else:
                self.logger.info(f"Fetching files after timestamp {self.last_processed_timestamp}...")
                file_keys = self.redis_client.zrangebyscore(
                    "features_index",
                     f"({self.last_processed_timestamp}",
                    "+inf",
                )
            self.logger.info(f"Found {len(file_keys)} new file(s)")
            return file_keys
        except Exception as e:
            self.logger.error(f"Failed to retrieve new files keys: {e}")
            return []
        
    
    
    
