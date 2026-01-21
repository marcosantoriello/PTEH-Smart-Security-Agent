from flask import Flask, request, jsonify
import subprocess
import re
from utils import get_logger
from datetime import datetime

app = Flask(__name__)
logger = get_logger('FW_enforcer')

# regex for base pattern validation
IPTABLES_PATTERN = re.compile(
    r'^iptables\s+-[AILD]\s+\w+.*$'
)

def validate_syntax(rule: str) -> tuple[bool,str]:
    """Validate iptables syntax (without applying it)"""
    
    # First I make a check with the base syntax of iptables
    if not IPTABLES_PATTERN.match(rule):
        return False, "Invalid iptables syntax pattern"
    
    # Input sanitization
    blacklist = ['rm', 'dd', '&&', '||', ';', '`', '$']
    if any(cmd in rule for cmd in blacklist):
        return False, "Characters not allowed detected"
    
    # At this point, I want to check the validity of the command without applying it. For that
    # I can use iptables-restore with the flag --test
    try:
        # I just have to pass the rule, without "iptables"
        input_test_rule = rule.replace('iptables', '', 1).strip()

        test_rule = f"*filter\n{input_test_rule}\nCOMMIT\n"
        result = subprocess.run(
            ['iptables-restore', '--test'],
            input=test_rule.encode(),
            capture_output=True,
            timeout=5
        )
        if result.returncode != 0:
            return False, f"iptables-restore test failed: {result.stderr.decode()}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"
    
    return True, "Valid"

    

def apply_rule(rule: str) -> tuple[bool, str]:
    """Apply the rule"""
    try:
        result = subprocess.run(
            rule.split(),
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            return True, "Rule applied successfully"
        else:
            return False, result.stderr.decode()
    except Exception as e:
        return False, f"Application error: {str(e)}"
    



@app.route('/apply-rule', methods=['POST'])
def apply_firewall_rule():
    """
    Endpoint to apply firewall rule
    Body: {
        "rule": "iptables -A INPUT -s 172.20.0.10 -j DROP",
        "reasoning": "Blocking DoS Hulk from 172.20.0.10",
        "attack_data": {...}  # IDS data
    }
    """
    data = request.json
    rule = data.get('rule', '').strip()
    reasoning = data.get('reasoning', '')
    attack_data = data.get('attack_data', {})

    if not rule:
        return jsonify({'success': False, 'error': 'No rule provided'}), 400
    
    valid, msg = validate_syntax(rule)
    if not valid:
        logger.warning(f"Invalid rule rejected: {rule} - {msg}")
        return jsonify({
            'success': False,
            'error': msg,
            'rule': rule
        }), 400
    
    success, msg = apply_rule(rule)
    
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'rule': rule,
        'reasoning': reasoning,
        'attack_data': attack_data,
        'success': success,
        'message': msg
    }
    logger.info(f"Rule application: {log_entry}")
    
    return jsonify({
        'success': success,
        'message': msg,
        'rule': rule
    }), 200 if success else 500

@app.route('/list_rules', methods=['GET'])
def list_rules():
    """Endpoint to retrieve current rules"""
    try:
        result = subprocess.run(
            ['iptables', '-L', '-n', '-v'],
            capture_output=True,
            timeout=5
        )
        return jsonify({
            'rules': result.stdout.decode()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)

