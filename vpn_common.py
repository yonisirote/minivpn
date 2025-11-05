#!/usr/bin/env python3
"""
VPN Constants - Shared constants across the VPN implementation.
"""

# Encryption constants
GCM_NONCE_SIZE = 12  # 96-bit nonce for GCM
AES_KEY_SIZE = 32    # 256-bit key (AES-256)

# Network constants
DEFAULT_SERVER_PORT = 8888
DEFAULT_SERVER_TUN_IP = '10.8.0.1'
DEFAULT_CLIENT_TUN_IP = '10.8.0.2'
DEFAULT_VPN_SUBNET = '10.8.0.0/24'
DEFAULT_MTU = 1500

# Protocol constants
IP_VERSION_4 = 4
IP_VERSION_6 = 6

PROTOCOL_ICMP = 1
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

PROTOCOL_NAMES = {
    PROTOCOL_ICMP: "ICMP",
    PROTOCOL_TCP: "TCP",
    PROTOCOL_UDP: "UDP",
}
