#!/usr/bin/env python3
"""
VPN Configuration - Handles configuration loading and validation.
"""

import os
from dotenv import load_dotenv
from constants import (
    DEFAULT_SERVER_PORT,
    DEFAULT_SERVER_TUN_IP,
    DEFAULT_CLIENT_TUN_IP,
    DEFAULT_VPN_SUBNET,
)


class VPNConfig:
    """Base configuration class."""
    
    def __init__(self):
        load_dotenv()
        
    def get_int(self, key, default):
        """Get integer from environment with default."""
        value = os.getenv(key)
        if value is None:
            return default
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"Invalid integer value for {key}: {value}")
    
    def get_str(self, key, default=None, required=False):
        """Get string from environment with optional default."""
        value = os.getenv(key, default)
        if required and not value:
            raise ValueError(f"Required configuration {key} not set")
        return value


class ServerConfig(VPNConfig):
    """VPN Server configuration."""
    
    def __init__(self):
        super().__init__()
        self.port = self.get_int('SERVER_PORT', DEFAULT_SERVER_PORT)
        self.tun_ip = self.get_str('SERVER_TUN_IP', DEFAULT_SERVER_TUN_IP)
        self.vpn_subnet = self.get_str('VPN_SUBNET', DEFAULT_VPN_SUBNET)
        self.host = '0.0.0.0'  # Always listen on all interfaces
        
    def __repr__(self):
        return (
            f"ServerConfig(host={self.host}, port={self.port}, "
            f"tun_ip={self.tun_ip}, subnet={self.vpn_subnet})"
        )


class ClientConfig(VPNConfig):
    """VPN Client configuration."""
    
    def __init__(self, server_ip=None):
        super().__init__()
        
        # Server IP can come from argument or environment
        self.server_ip = server_ip or self.get_str('SERVER_IP', required=True)
        self.server_port = self.get_int('SERVER_PORT', DEFAULT_SERVER_PORT)
        self.tun_ip = self.get_str('CLIENT_TUN_IP', DEFAULT_CLIENT_TUN_IP)
        
    def __repr__(self):
        return (
            f"ClientConfig(server={self.server_ip}:{self.server_port}, "
            f"tun_ip={self.tun_ip})"
        )


def validate_ip_address(ip_str):
    """
    Validate IP address format.
    
    Args:
        ip_str: IP address string
        
    Returns:
        bool: True if valid IPv4 address
    """
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        
        return True
    except (ValueError, AttributeError):
        return False


def validate_port(port):
    """
    Validate port number.
    
    Args:
        port: Port number (int)
        
    Returns:
        bool: True if valid port (1-65535)
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False
