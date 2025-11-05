#!/usr/bin/env python3
"""
VPN Packet Utilities - Packet parsing and manipulation.
"""

from vpn_common import PROTOCOL_NAMES, IP_VERSION_4


def parse_packet_info(packet):
    """
    Extract source IP, dest IP, and protocol from IP packet.
    
    Args:
        packet: Raw IP packet bytes
        
    Returns:
        str: Formatted packet information (e.g., "ICMP   10.0.0.1      → 8.8.8.8")
    """
    if len(packet) < 20:
        return "Invalid packet (too short)"
    
    version = packet[0] >> 4
    if version != IP_VERSION_4:
        return f"IPv{version} packet"
    
    protocol = packet[9]
    proto_name = PROTOCOL_NAMES.get(protocol, f"Proto-{protocol}")
    
    src_ip = ".".join(str(b) for b in packet[12:16])
    dst_ip = ".".join(str(b) for b in packet[16:20])
    
    return f"{proto_name:6} {src_ip:15} → {dst_ip:15}"


def is_ipv4_packet(packet):
    """
    Check if packet is IPv4.
    
    Args:
        packet: Raw packet bytes
        
    Returns:
        bool: True if IPv4, False otherwise
    """
    if len(packet) < 1:
        return False
    version = packet[0] >> 4
    return version == IP_VERSION_4


def get_packet_protocol(packet):
    """
    Get the protocol number from an IP packet.
    
    Args:
        packet: Raw IP packet bytes
        
    Returns:
        int: Protocol number (1=ICMP, 6=TCP, 17=UDP), or None if invalid
    """
    if len(packet) < 20:
        return None
    
    version = packet[0] >> 4
    if version != IP_VERSION_4:
        return None
    
    return packet[9]


def get_source_ip(packet):
    """
    Extract source IP address from packet.
    
    Args:
        packet: Raw IP packet bytes
        
    Returns:
        str: Source IP address (e.g., "10.0.0.1"), or None if invalid
    """
    if len(packet) < 20:
        return None
    
    return ".".join(str(b) for b in packet[12:16])


def get_dest_ip(packet):
    """
    Extract destination IP address from packet.
    
    Args:
        packet: Raw IP packet bytes
        
    Returns:
        str: Destination IP address (e.g., "8.8.8.8"), or None if invalid
    """
    if len(packet) < 20:
        return None
    
    return ".".join(str(b) for b in packet[16:20])
