"""
Processing and analysis module for captured packets.
It extracts the essential informations from the packets.
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP
from datetime import datetime

class PacketProcessor:
    
    
    def __init__(self, logger):
        """
        Initializes the processor.
        
        Args:
            logger: Logger
        """

        self.logger = logger
        self.packet_count = 0

    def process_packet(self, packet):
        """
        Processes a single packet and extracts the most relevant informations.
        
        Args:
            packet: Scapy Packet to analyze
        
        Returns:
            Dict with the extracted packet informations
        """

        self.packet_count += 1

        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'packet_number': self.packet_count,
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'length': len(packet)
        }

        # IP Packets
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst

            # identifies transport protocol
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = str(tcp_layer.flags)
            
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport

            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_info['protocol'] = 'ICMP'
                packet_info['icmp_type'] = packet[ICMP].type

        # ARP packets
        elif packet.haslayer(ARP):
            arp_layer = packet[ARP]
            packet_info['protocol'] = 'ARP'
            packet_info['arp_op'] = arp_layer.op  # 1=request, 2=reply
            packet_info['src_ip'] = arp_layer.psrc
            packet_info['dst_ip'] = arp_layer.pds

        return packet_info
    
    def format_packet_info(self, packet_info):
        """
        Formats packet informations for logging.
        
        Args:
            packet_info: Dict with packet informations
        
        Returns:
            Formatted string
        """

        if packet_info['protocol'] in ['TCP', 'UDP']:
            return (f"[{packet_info['packet_number']}] "
                   f"{packet_info['protocol']} | "
                   f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
                   f"{packet_info['dst_ip']}:{packet_info['dst_port']} | "
                   f"Len: {packet_info['length']}")
        else:
            return (f"[{packet_info['packet_number']}] "
                   f"{packet_info['protocol']} | "
                   f"{packet_info['src_ip']} -> {packet_info['dst_ip']} | "
                   f"Len: {packet_info['length']}")