"""
Firewall main module.
Integrates traffic sniffing with firewall rules.
"""
import os
import sys

# Add the sniffer module to the Python path
sys.path.insert(0, '/app')

from sniffer.packet_sniffer import TrafficSniffer
from utils import get_logger


def main():
    """Main entry point for the firewall service"""
    logger = get_logger('Firewall')
    
    # Get configuration from environment variables
    interface = os.getenv('SNIFFER_INTERFACE', 'eth0')
    feature_extractor_url = os.getenv('FEATURE_EXTRACTOR_URL', 'http://172.21.0.3:5000')
    
    logger.info(f"Starting firewall with traffic sniffer on interface: {interface}")
    logger.info(f"Feature extractor URL: {feature_extractor_url}")
    
    # Initialize the traffic sniffer
    sniffer = TrafficSniffer(
        interface=interface,
        packet_count=0,  # Unlimited
        filter_str=None,  # No filter - capture all traffic
        batch_size=100
    )
    
    # Start sniffing
    logger.info("Starting packet capture...")
    sniffer.start()


if __name__ == "__main__":
    main()
