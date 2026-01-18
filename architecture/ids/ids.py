import io
import os
import joblib
import redis
from utils import get_logger
import pandas as pd
import numpy as np
import time


class Ids:
    def __init__(self, model_path='model/model.joblib'):
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
        self.label_encoder = None
        self.feature_names = None
        self.protocol_encoder = None

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

    

    def _load_model_package(self):
        """"
            Load model, scaler and feature_names from pickle file
        """
        self.logger.info("Loading model, scaler, feature names, label encoder and protocol encoder...")
        try:
            with open(self.MODEL_PATH, 'rb') as f:
                model_package = joblib.load(f)

                self.model = model_package['model']
                self.scaler = model_package['scaler']
                self.label_encoder = model_package['label_encoder']
                self.feature_names = model_package['selected_features']
                self.protocol_encoder = model_package['protocol_encoder']
                
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
            return None

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
        
    def _preprocess(self, df):
        """
        Preprocess data using pre-trained encoder and scaler.
        """
        if df is None:
            self.logger.warning("Preprocess called with df=None. Skipping.")
            return None
        try:
            self.logger.info(f"Starting preprocessing of {len(df)} rows...")
            
            df_clean = df.copy()

            # Handle infinite values
            inf_count = np.isinf(df_clean.select_dtypes(include=[np.number])).sum().sum()
            if inf_count > 0:
                self.logger.warning(f"Found {inf_count} infinite values, replacing with NaN")
                df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
            
            # Label Encoding for 'protocol' using the specific protocol_encoder
            if 'protocol' in df_clean.columns:
                if df_clean['protocol'].dtype == 'object':
                    self.logger.info("Encoding 'protocol' column using protocol_encoder...")

                    try:
                        # Use the specific protocol encoder provided in the model package
                        df_clean['protocol'] = self.protocol_encoder.transform(df_clean['protocol'].astype(str))
                        self.logger.debug(f"Protocol encoded successfully")
                        
                    except ValueError as e:
                        self.logger.error(f"Unknown protocol value encountered: {e}")
                        self.logger.info(f"Known protocols: {self.protocol_encoder.classes_}")
                        
                        # Handle unknown values
                        df_clean['protocol'] = df_clean['protocol'].apply(
                            lambda x: self._encode_protocol_safe(x)
                        )
            
            float_cols = df_clean.select_dtypes(include=['float64', 'float32']).columns
            if len(float_cols) > 0:
                df_clean[float_cols] = df_clean[float_cols].round(4)
            
            # Feature selection
            try:
                df_features = df_clean[self.feature_names]
            except KeyError as e:
                missing = set(self.feature_names) - set(df_clean.columns)
                self.logger.error(f"Missing required features: {missing}")
                raise
            
            # Check NaN
            nan_count = df_features.isnull().sum().sum()
            if nan_count > 0:
                self.logger.warning(f"Found {nan_count} NaN values in features")
            
            # Scale features
            X_scaled = self.scaler.transform(df_features)
            
            # Convert back to DataFrame to preserve feature names for model prediction
            X_scaled = pd.DataFrame(X_scaled, columns=self.feature_names, index=df_features.index)
            
            self.logger.info(f"Preprocessing completed: {X_scaled.shape}")
            
            return X_scaled, df_clean
        
        except Exception as e:
            self.logger.error(f"Preprocessing failed: {e}")
            raise


    def _encode_protocol_safe(self, value):
        """
        Encode a protocol value safely, handling unknown values.
        
        Args:
            value: Protocol value to encode
        
        Returns:
            int: Encoded value or -1 if unknown
        """
        try:
            return self.protocol_encoder.transform([str(value)])[0]
        except ValueError:
            self.logger.warning(f"Unknown protocol '{value}', using default (-1)")
            return -1


    def _predict(self, X_scaled, df_original):
        """
        Run model prediction and attach metadata for firewall rules.
        
        Args:
            X_scaled: Preprocessed and scaled features
            df_original: Original dataframe with metadata columns
            
        Returns:
            pandas.DataFrame: Predictions with metadata (src_ip, src_port, dst_ip, dst_port, protocol, etc.)
        """
        if X_scaled is None or df_original is None:
            self.logger.warning("Predict called with None input. Skipping.")
            return None
        
        try:
            self.logger.info(f"Starting prediction for {X_scaled.shape[0]} flows...")
            predictions = self.model.predict(X_scaled)
            prediction_proba = self.model.predict_proba(X_scaled)
            
            # Extract metadata columns for firewall rules
            metadata_cols = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol']
            metadata = df_original[metadata_cols].copy() if all(col in df_original.columns for col in metadata_cols) else pd.DataFrame()
            
            # Map predictions to labels
            predicted_labels = self.label_encoder.inverse_transform(predictions)
            
            results = pd.DataFrame({
                'prediction_id': predictions,
                'prediction': predicted_labels,
                'confidence': prediction_proba.max(axis=1),
                'timestamp': pd.Timestamp.now()
            })
            
            # Attach metadata
            if not metadata.empty:
                results = pd.concat([metadata.reset_index(drop=True), results], axis=1)
            
            attack_count = (predicted_labels != 'Benign').sum()
            benign_count = (predicted_labels == 'Benign').sum()
            
            self.logger.info(f"Prediction completed: {attack_count} attacks, {benign_count} benign flows")
            self.logger.info(f"Average confidence: {results['confidence'].mean():.3f}")
            
            return results
        
        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            raise


    def _update_last_processed_timestamp(self, file_keys):
        """
        Update the last processed timestamp after successful processing.
        
        Args:
            file_keys: List of processed Redis keys
        """
        if not file_keys:
            return
        
        try:
            # Get highest timestamp from processed files
            scores = self.redis_client.zmscore("features_index", file_keys)
            max_timestamp = max(float(s) for s in scores if s is not None)
            
            self.last_processed_timestamp = max_timestamp
            self.logger.info(f"Updated last processed timestamp to {max_timestamp}")
        
        except Exception as e:
            self.logger.error(f"Failed to update timestamp: {e}")



    def _save_predictions(self, predictions_df):
        """
        Save predictions to Redis for downstream analysis.
        
        Args:
            predictions_df: DataFrame with predictions and metadata
        """
        if predictions_df is None or predictions_df.empty:
            self.logger.warning("No predictions to save")
            return
        
        try:
            timestamp = int(time.time())
            redis_key = f"predictions:{timestamp}"
            
            # Save as JSON for easy parsing
            predictions_json = predictions_df.to_json(orient='records')
            self.redis_client.set(redis_key, predictions_json)
            
            # Add to sorted set for retrieval
            self.redis_client.zadd("predictions_index", {redis_key: timestamp})
            
            # Save attack flows separately for immediate firewall action
            attack_flows = predictions_df[predictions_df['prediction'] != 'Benign']
            if not attack_flows.empty:
                attack_key = f"attacks:{timestamp}"
                self.redis_client.set(attack_key, attack_flows.to_json(orient='records'))
                self.redis_client.zadd("attacks_index", {attack_key: timestamp})
                self.logger.warning(f"Detected {len(attack_flows)} ATTACK flows - saved to {attack_key}")
            
            self.logger.info(f"Saved {len(predictions_df)} predictions to Redis: {redis_key}")
        
        except Exception as e:
            self.logger.error(f"Failed to save predictions: {e}")
        


if __name__ == "__main__":
    ids = Ids()
    ids.setup()

    while True:
        try:
            df = ids._get_new_files()

            if df is None:
                ids.logger.info("No data to preprocess.")
            else:
                ids.logger.info("=== STARTING PREPROCESS ===")
                X_scaled, df_clean = ids._preprocess(df)

                ids.logger.info("=== STARTING PREDICTION ===")
                predictions = ids._predict(X_scaled, df_clean)

                ids._save_predictions(predictions)
                file_keys = ids._get_new_files_keys()
                ids._update_last_processed_timestamp(file_keys)

        
        except Exception as e:
            ids.logger.error(f"Error in main loop: {e}")

        
        ids.logger.info(f"Sleeping for {ids.POLLING_INTERVAL} seconds...")
        time.sleep(ids.POLLING_INTERVAL)

    
    
    
