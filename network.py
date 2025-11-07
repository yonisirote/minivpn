#!/usr/bin/env python3
"""
VPN Network Operations - TUN interface and routing setup.
"""

import pytun
import subprocess


class TunInterface:
    """Manages TUN interface creation and configuration."""
    
    def __init__(self, name, ip_address, netmask='255.255.255.0', mtu=1500):
        """
        Initialize TUN interface configuration.
        
        Args:
            name: Interface name (e.g., 'tun0', 'tun1')
            ip_address: IP address for the interface (e.g., '10.8.0.1')
            netmask: Network mask (default: '255.255.255.0')
            mtu: Maximum transmission unit (default: 1500)
        """
        self.name = name
        self.ip_address = ip_address
        self.netmask = netmask
        self.mtu = mtu
        self.device = None
        
    def create(self):
        """Create and configure the TUN interface."""
        # Create TUN device
        self.device = pytun.TunTapDevice(
            name=self.name,
            flags=pytun.IFF_TUN | pytun.IFF_NO_PI
        )
        
        # Set IP address
        subprocess.run(
            ["ip", "addr", "add", f"{self.ip_address}/24", "dev", self.name],
            check=True,
            capture_output=True
        )
        
        # Bring interface up
        self.device.up()
        subprocess.run(
            ["ip", "link", "set", self.name, "up"],
            check=True,
            capture_output=True
        )
        
        # Disable IPv6 on the interface
        subprocess.run(
            ["sysctl", "-w", f"net.ipv6.conf.{self.name}.disable_ipv6=1"],
            check=True,
            capture_output=True
        )
        
        return self.device
    
    def read(self, buffer_size=None):
        """Read packet from TUN interface."""
        if not self.device:
            raise RuntimeError("TUN device not created")
        
        size = buffer_size or self.mtu
        return self.device.read(size)
    
    def write(self, packet):
        """Write packet to TUN interface."""
        if not self.device:
            raise RuntimeError("TUN device not created")
        
        return self.device.write(packet)
    
    def close(self):
        """Close and cleanup TUN interface."""
        if self.device:
            try:
                self.device.down()
                self.device.close()
            except:
                pass


class NetworkSetup:
    """Handles network configuration for VPN."""
    
    @staticmethod
    def enable_ip_forwarding():
        """Enable IP forwarding on the system."""
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True,
            capture_output=True
        )
    
    @staticmethod
    def setup_nat(vpn_subnet, output_interface=None):
        """
        Setup NAT (masquerading) for VPN traffic.
        
        Args:
            vpn_subnet: VPN subnet to NAT (e.g., '10.8.0.0/24')
            output_interface: Output interface name (auto-detected if None)
        """
        # Get default interface if not specified
        if not output_interface:
            try:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                output_interface = result.stdout.split()[4]
            except:
                output_interface = "eth0"  # Fallback
        
        # Remove existing rule if present (ignore errors)
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", vpn_subnet, "-j", "MASQUERADE"],
            capture_output=True
        )
        
        # Add NAT rule
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpn_subnet, "-j", "MASQUERADE"],
            check=True,
            capture_output=True
        )
        
        return output_interface
    
    @staticmethod
    def cleanup_nat(vpn_subnet):
        """
        Remove NAT rule for VPN subnet.
        
        Args:
            vpn_subnet: VPN subnet (e.g., '10.8.0.0/24')
        """
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", vpn_subnet, "-j", "MASQUERADE"],
                capture_output=True
            )
        except:
            pass
    
    @staticmethod
    def add_route(destination, gateway, interface):
        """
        Add a route to the routing table.
        
        Args:
            destination: Destination network (e.g., '8.8.8.8' or '0.0.0.0/0')
            gateway: Gateway IP address (e.g., '10.8.0.1')
            interface: Interface name (e.g., 'tun0')
        """
        subprocess.run(
            ["ip", "route", "add", destination, "via", gateway, "dev", interface],
            check=True,
            capture_output=True
        )
    
    @staticmethod
    def get_default_gateway():
        """
        Get the default gateway IP address.
        
        Returns:
            str: Gateway IP address, or None if not found
        """
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.split()[2]
        except:
            return None
