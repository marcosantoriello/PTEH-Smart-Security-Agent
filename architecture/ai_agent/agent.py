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
        self.OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://host.docker.internal:11434')
        self.FIREWALL_URL = os.getenv('FIREWALL_URL', 'http://firewall:5002/apply-rule')
        self.OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3:latest')

        self.redis_client = None
        self.ollama_client = None
        self.last_processed_ts = None

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



    def _build_prompt(self, attack: Dict) -> str:
        """Builds structured prompt for LLM"""
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

            GENERIC EXAMPLE FORMAT (this is very generic, so you don't need to strictly follow it):
            iptables -A FORWARD -s <IP> -p <protocol> --dport <port> -j DROP

            Your iptables rule:"""

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
        prompt = self._build_prompt(attack)

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
                'timestamp': datetime.now().isoformat()
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
                attacks = self.fetch_new_attacks()

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

                if attacks:
                    self.last_processed_ts = max(
                    float(a.get('timestamp', 0)) for a in attacks
                )
                    
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


        


