import redis
import json
from collections import defaultdict


class Evaluator:
    def __init__(self):
        self.redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

        with open('./metrics.json') as f:
            self.metrics = json.load(f)

        
    
    def is_rule_correct(self, rule, attack_type, src_ip):
        """Check if the rule is correct according to the metrics"""

        if attack_type not in self.metrics:
            return None
        
        metric = self.metrics[attack_type]

        if src_ip not in rule:
            return False
        
        for required in metric['must_have']:
            if required not in rule:
                return False
            
        for forbidden in metric['must_not_have']:
            if forbidden in rule:
                return False
            
        return True
    


    def run(self):
        """Main function. Fetch action files from redis and execute the evaluation"""

        keys = self.redis_client.zrange('agent_actions_index', 0, -1)

        if not keys:
            print("ERROR: No agent actions found in Redis")
            return None
        
        print(f"Found {len(keys)} agent actions")

        results = defaultdict(lambda: {'correct': 0, 'wrong': 0})

        for key in keys:
            try:
                action = json.loads(self.redis_client.get(key))

                attack_type = action['attack_data']['prediction']
                rule = action['rule']
                src_ip = action['attack_data']['src_ip']
                success = action['success']

                if not success or not rule:
                    continue

                correct = self.is_rule_correct(rule, attack_type, src_ip)

                if correct is None:
                    continue

                if correct:
                    results[attack_type]['correct'] += 1

                else:
                    results[attack_type]['wrong'] += 1

            except Exception as e:
                print(f"Error processing {key}: {e}")
                continue
        
        return dict(results)
    

    def print_report(self, results):
        """Print the report of the evaluation"""

        if not results:
            return
    
        print("\n" + "="*70)
        print("AI AGENT EVALUATION RESULTS")
        print("="*70)
        
        # Header
        print(f"\n{'Attack Type':<25} {'Correct':<10} {'Wrong':<10} {'Accuracy':<10}")
        print("-"*70)
        
        total_correct = 0
        total_wrong = 0
        
        for attack_type in sorted(results.keys()):
            data = results[attack_type]
            correct = data['correct']
            wrong = data['wrong']
            total = correct + wrong
            accuracy = correct / total if total > 0 else 0
            
            print(f"{attack_type:<25} {correct:<10} {wrong:<10} {accuracy:<10.2%}")
            
            total_correct += correct
            total_wrong += wrong
        
        print("-"*70)
        total_all = total_correct + total_wrong
        overall_acc = total_correct / total_all if total_all > 0 else 0
        print(f"{'OVERALL':<25} {total_correct:<10} {total_wrong:<10} {overall_acc:<10.2%}")
        print("="*70 + "\n")
    
    def save_json(self, results, filename='evaluation_results.json'):
        """Save to JSON file"""
        
        # Calculate metrics
        output = {'per_attack_type': {}, 'overall': {}}
        
        total_correct = 0
        total_wrong = 0
        
        for attack_type, data in results.items():
            correct = data['correct']
            wrong = data['wrong']
            total = correct + wrong
            accuracy = correct / total if total > 0 else 0
            
            output['per_attack_type'][attack_type] = {
                'correct': correct,
                'wrong': wrong,
                'total': total,
                'accuracy': accuracy
            }
            
            total_correct += correct
            total_wrong += wrong
        
        total_all = total_correct + total_wrong
        output['overall'] = {
            'correct': total_correct,
            'wrong': total_wrong,
            'total': total_all,
            'accuracy': total_correct / total_all if total_all > 0 else 0
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"Results saved to: {filename}")



def main():
    evaluator = Evaluator()

    results = evaluator.run()

    if results:
        evaluator.print_report(results)
        evaluator.save_json(results)

    
    
if __name__ == '__main__':
    main()

                