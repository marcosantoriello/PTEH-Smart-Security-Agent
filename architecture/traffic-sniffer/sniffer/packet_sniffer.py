"""
Network Sniffer main module.
It captures packets on a specified network interface.
"""

import datetime
from scapy.all import sniff, conf, wrpcap
from .logger_config import setup_logger
from .packet_processor import PacketProcessor
import signal
import sys
import requests


class TrafficSniffer:

    def __init__(self, interface='eth0', packet_count=0, filter_str=None, batch_size=100):
        """
        Initialise the sniffer.
        
        Args:
            interface: Network interface to monitor
            packet_count: n. of packets to caputre (0 = unlimited)
            filter_str: Optional BPF filter (e.g.: 'tcp port 80')
        """

        self.interface = interface
        self.packet_count = packet_count
        self.filter_str = filter_str
        self.batch_size = batch_size
        self.logger = setup_logger()
        self.processor = PacketProcessor(self.logger)
        self.running = True
        self.packets_buffer = []

        # verbosity (0 for non-verbose, 1 for verbose)
        conf.verb = 0

        # handles interrupt signal
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)


    def signal_handler(self, sig, frame):
        """Handles graceful termination"""
        self.logger.info("\nInterruption received. Closing the sniffer...")
        self.running = False
        self.print_statistics()
        sys.exit(0)

    def notify_feature_extraction(self, filename, base_url='http://localhost:5000'):
        """
        Notifies the feature extractor that a new pcap has been saved and 
        sends the path to this new file.
        """
        path = f"/shared/pcap/{filename}"
        data = {'filename': filename, 'path': path}

        try:
            r = requests.post(f"{base_url}/new_pcap", json=data)
            if r.status_code == 200:
                self.logger.info(f"Notification sent successfully for file: {filename}")
            else:
                self.logger.error(f"Failed to send notification for {filename}: {r.text}")
        except Exception as e:
            self.logger.error(f"API call error while notifying feature extractor for {filename}: {e}")

    
    def packet_callback(self, packet):
        """
        Callback called for every captured packet
        
        Args:
            packet: captured packet
        """

        try:
            # packet processing
            packet_info = self.processor.process_packet(packet)
            
            log_message = self.processor.format_packet_info(packet_info)
            self.logger.info(log_message)
            self.logger.debug(f"Packet details: {packet_info}")

            self.packets_buffer.append(packet)

            # save every 100 packets
            if len(self.packets_buffer) >= self.batch_size:
                # generates filename with timestamp
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"capture_{timestamp}.pcap"
                filepath = f"/shared/pcap/{filename}"

                wrpcap(filepath, self.packets_buffer)
                self.notify_feature_extraction(filename)

                self.packets_buffer = []


        except Exception as e:
            self.logger.error(f"Error while processing the packet: {e}")

        
    def start(self):
        """Starts the capture"""

        try:
            self.logger.info("="*60)
            self.logger.info("Traffic Sniffer started!")
            self.logger.info(f"Interface: {self.interface}")
            if self.filter_str:
                self.logger.info(f"BPF Filter: {self.filter_str}")
            self.logger.info("="*60)

            # Starts the sniffer
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_count,
                filter=self.filter_str,
                store=False
            )

        except  PermissionError:
            self.logger.error("❌ Error: required root privileges")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"❌ Error during sniffing: {e}")
            sys.exit(1)


    def print_statistics(self):
        """Prints final stats"""
        self.logger.info("="*60)
        self.logger.info("📊 Final stats:")
        self.logger.info(f"   Captured packets: {self.processor.packet_count}")
        self.logger.info("="*60)

    
def main():
    import os

    interface = os.getenv('SNIFFER_INTERFACE', 'eth0')
    packet_count = int(os.getenv('SNIFFER_COUNT', '0'))
    filter_str = os.getenv('SNIFFER_FILTER', None)
        
    sniffer = TrafficSniffer(
        interface=interface,
        packet_count=packet_count,
        filter_str=filter_str
    )
    sniffer.start()



if __name__ == '__main__':
    main()

    

    
            


