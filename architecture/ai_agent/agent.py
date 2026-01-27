import os
import redis
import json
import time
from utils import get_logger
from datetime import datetime
from typing import List, Dict, Optional
import requests
from ollama import Client
import chromadb

class SecurityAgent:
    def __init__(self):
        """Initialize SecurityAgent"""
        self.REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
        self.REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
        self.POLLING_INTERVAL = int(os.getenv('POLLING_INTERVAL', 15))
        self.OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://host.docker.internal:11434')
        self.FIREWALL_URL = os.getenv('FIREWALL_URL', 'http://firewall:5002/apply-rule')
        self.OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3:latest')
        self.CHROMADB_PERSIST_DIR = os.getenv('CHROMADB_PERSIST_DIR', '/app/chroma_db')
        self.RAG_KNOWLEDGE_PATH = os.getenv('RAG_KNOWLEDGE_PATH', '/app/knowledge_base/iptables_rules.json')

        self.redis_client = None
        self.ollama_client = None
        self.last_processed_ts = None
        self.chroma_client = None
        self.collection = None

        self.logger = get_logger('SecurityAgent')


    
    def _connect_to_redis(self):
        """Connect to Redis"""
        self.logger.info("Connecting to Redis...")
        try:
            self.redis_client = redis.Redis(
                host=self.REDIS_HOST, 
                port=self.REDIS_PORT, 
                decode_responses=True
            )
            self.redis_client.ping()
            self.logger.info(f"Successfully connected to Redis at {self.REDIS_HOST}:{self.REDIS_PORT}")
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")


    def _setup_knowledge_base(self):
        """
        Load iptables rules from the knowledge document and populates ChromaDB collection.
        """

        
        self.chroma_client = chromadb.PersistentClient(path=self.CHROMADB_PERSIST_DIR)

        self.collection = self.chroma_client.get_or_create_collection(name="iptables_rules")

        # checking if the collection existed already or has just been created
        if self.collection.count() > 0:
            self.logger.info(f"Loaded existing collection")
            return
        
        # if the collection is empty, then I have to populate it
        self.logger.info("Collection empty, loading from JSON...")

        with open(self.RAG_KNOWLEDGE_PATH, 'r') as f:
            knowledge_data = json.load(f)

        documents = []
        metadatas = []
        ids = []

        try:
            rules = knowledge_data["rules"]
            
            for index, entry in enumerate(rules):
                attack_type = entry["attack_type"]
                description = entry["description"]
                rule = entry["rule"]
                reasoning = entry["reasoning"]

                documents.append(f"{attack_type}: {description}")
                metadatas.append({
                    'attack_type': attack_type,
                    'description': description,
                    'rule': rule,
                    'reasoning': reasoning
                })
                ids.append(f"rule_{index}")

                self.collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                self.logger.info(f"Knowledge base loaded: {len(rules)} rules indexed")


        except KeyError as e:
            self.logger.error(e)
            raise


    def setup(self):
        """
        Setup function:
            - Set up the logger
            - Connect to Redis
            - Retrieve last timestamp from Redis
            - Set the model
            - Set the Ollama client
            - Set RAG knowledge base
        """
        self.logger.info("="*60)
        self.logger.info("Security Agent starting...")

        self._connect_to_redis()

        self.ollama_client = Client(host=self.OLLAMA_HOST)
        self.last_processed_ts = self._get_last_timestamp()
        self._setup_knowledge_base()



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



    def fetch_new_attacks(self) -> tuple[List[Dict], List[str]]:
        """Retrieves new attacks from Redis
        
        Returns:
            tuple: (attacks, processed_keys) - List of attack dicts and list of Redis keys processed
        """
        try:
            keys = self.redis_client.zrangebyscore(
                'attacks_index',
                f"({self.last_processed_ts}",  # Exclude last processed timestamp
                '+inf',
                start=0,
                num=10  # Max 10 attacks per batch
            )
            
            if not keys:
                return [], []
            
            attacks = []
            for key in keys:
                self.logger.info(f"Processing prediction file: {key}")
                data = self.redis_client.get(key)
                if data:
                    attacks.extend(json.loads(data))
            
            self.logger.info(f"Fetched {len(attacks)} new attacks from {len(keys)} file(s)")
            return attacks, keys
            
        except Exception as e:
            self.logger.error(f"Error fetching attacks: {e}")
            return [], []


    def _retrieve_examples(self, attack_type: str):
        """
        Retrieve relevant firewall rule examples from the knowledge base
        
        :param attack_type: attack type from the IDS

        :return: List of metadata dictionaries containing rule examples
        """

        query_string = f"{attack_type} mitigation"

        self.logger.info(f"Retrieving examples for: {attack_type}")

        results = self.collection.query(
            query_texts=[query_string], 
            n_results=1
        )

        if results["metadatas"] and results['metadatas'][0]:
            examples = results['metadatas'][0]
            self.logger.info(f"Retrieved {len(examples)} examples")
            return examples
        else:
            return []


    def _build_prompt(self, attack: Dict, examples: Optional[List[dict]]=None) -> str:
        """Builds structured prompt for LLM. If any example is provided, then include it."""
        
        prompt = f"""You are a cybersecurity expert. Generate a precise iptables firewall rule to mitigate this attack.
            ATTACK DETAILS:
            - Type: {attack['prediction']}
            - Confidence: {attack['confidence']:.2%}
            - Source IP: {attack['src_ip']}
            - Source Port: {attack['src_port']}
            - Destination IP: {attack['dst_ip']}
            - Destination Port: {attack['dst_port']}
            - Protocol: {attack['protocol']}

            NETWORK CONTEXT:
            The firewall routes traffic between external network (attacker) and internal network (protected services).
            Traffic passes THROUGH the firewall, not TO the firewall.

            REQUIREMENTS:
            1. Generate ONLY the iptables command (no explanations before/after)
            2. Use appropriate action (DROP for volumetric attacks, REJECT for others)
            3. Use FORWARD chain (not INPUT - traffic is routed through firewall)
            4. Be specific to the source IP and attack type
            5. Use correct iptables syntax
            """
        
        if examples:
            prompt += "\nVALIDATED EXAMPLE:\n"
            for ex in examples:
                prompt += f"Rule: {ex['rule']}\n"
                prompt += f"Reasoning: {ex['reasoning']}\n"
                
        prompt += "Your iptables rule:"

        return prompt
    


    def _extract_rule_from_response(self, llm_response: str) -> str:
        """Extracts and cleans iptables rule from LLM response"""
        rule = llm_response.strip()

        # since the llm might add extra text, I only want to extract the command
        if '\n' in rule:
            lines = rule.split('\n')
            iptables_lines = [line for line in lines if line.strip().startswith('iptables')]
            if iptables_lines:
                rule = iptables_lines[0]
    
        return rule.strip()



    def generate_rule(self, attack: Dict) -> Dict:
        """Generates firewall rule using LLM"""

        examples = self._retrieve_examples(attack['prediction'])
        if not examples:
            prompt = self._build_prompt(attack)
            rag_used=False
        else:
            self.logger.info(f"RAG Example Retrieved:")
            self.logger.info(f"  - Attack Type: {examples[0]['attack_type']}")
            self.logger.info(f"  - Rule Template: {examples[0]['rule']}")
            self.logger.info(f"  - Reasoning: {examples[0]['reasoning']}")
            prompt = self._build_prompt(attack, examples)
            rag_used = True


        try:
            response = self.ollama_client.generate(
                model=self.OLLAMA_MODEL,
                prompt=prompt,
                options={
                    'temperature': 0.1, # low value to reduce randomness
                    'top_p': 0.9,
                }
            )

            rule = self._extract_rule_from_response(response['response'])

            self.logger.info(f"Generated rule: {rule}")


            return {
                'rule': rule,
                'reasoning': f"Mitigating {attack['prediction']} from {attack['src_ip']}",
                'attack_data': attack,
                'confidence': attack['confidence'],
                'timestamp': datetime.now().isoformat(),
                'rag_used': rag_used,
                'rag_examples': [ex['attack_type'] for ex in examples] if examples else []
            }

        except Exception as e:
            self.logger.error(f"Error generating rule: {e}")
            return None
    
    
    
    def _log_action(self, rule_data: Dict, success: bool, error=None):
        """Saves action to Redis for auditability"""
        log_entry = {
            **rule_data,
            'success': success,
            'error': error,
            'processed_at': datetime.utcnow().isoformat()
        }

        ts = int(time.time())
        key = f"agent_actions:{ts}"

        self.redis_client.set(key, json.dumps(log_entry))
        self.redis_client.zadd('agent_actions_index', {key: ts})
    
        attack_ts = rule_data['attack_data'].get('timestamp', ts)
        self.redis_client.zadd('agent_processed_index', {f"processed:{ts}": attack_ts})



    def validate_and_apply_rule(self, rule_data: Dict) -> bool:
        """Validates semantics and applies rule via Firewall Enforcer"""

        rule = rule_data['rule']
        attack = rule_data['attack_data']

        # checking if the src IP address is included in the rule
        src_ip = attack['src_ip']

        if src_ip not in rule:
            self.logger.warning(f"Rule does not contain source IP {src_ip}: {rule}")
            return False
        

        try:
            response = requests.post(self.FIREWALL_URL, json=rule_data, timeout=10)

            if response.status_code == 200 and response.json().get('success'):
                self.logger.info(f"Rule applied successfully: {rule}")
                self._log_action(rule_data, success=True)
                return True
            else:
                self.logger.error(f"Rule application failed: {response.json()}")
                self._log_action(rule_data, success=False, error=response.json())
                return False

        except Exception as e:
            self.logger.error(f"Error applying rule: {e}")
            self._log_action(rule_data, success=False, error=str(e))
            return False
        


    def run(self):
        """Main Loop"""
        self.logger.info("Starting AI Security Agent main loop...")
        self.logger.info(f"Polling interval: {self.POLLING_INTERVAL}s")
        self.logger.info(f"Using model: {self.OLLAMA_MODEL}")

        while True:
            try:
                attacks, processed_keys = self.fetch_new_attacks()

                if not attacks:
                    self.logger.debug(f"No new attacks, waiting {self.POLLING_INTERVAL}s")
                    time.sleep(self.POLLING_INTERVAL)
                    continue

                for attack in attacks:
                    self.logger.info(f"Processing attack: {attack['prediction']} from {attack['src_ip']}")
                    
                    rule_data = self.generate_rule(attack)
                    if not rule_data:
                        continue

                    self.validate_and_apply_rule(rule_data)

                # Update timestamp based on the highest score of processed Redis keys
                if processed_keys:
                    scores = self.redis_client.zmscore('attacks_index', processed_keys)
                    max_score = max(float(s) for s in scores if s is not None)
                    self.last_processed_ts = max_score
                    self.logger.info(f"Updated last_processed_ts to {max_score}")
                    
            except KeyboardInterrupt:
                self.logger.info("Received shutdown signal, stopping agent...")
                break
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}", exc_info=True)

            time.sleep(self.POLLING_INTERVAL)


        self.logger.info("AI Security Agent stopped")




if __name__ == '__main__':
    agent = SecurityAgent()
    agent.setup()
    agent.run()


        


