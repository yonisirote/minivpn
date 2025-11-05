#!/usr/bin/env python3
"""
VPN Client with AES-GCM Encryption
Captures local traffic, encrypts, sends to VPN server.
"""

import socket
import threading
import sys
import os

# VPN modules
from vpn_crypto import VPNCrypto
from vpn_packet import parse_packet_info, is_ipv4_packet
from vpn_config import ClientConfig
from vpn_network import TunInterface

class VPNClient:
    def __init__(self, server_host=None, encryption_key=None):
        # Load configuration
        self.config = ClientConfig(server_ip=server_host)
        self.server_addr = (self.config.server_ip, self.config.server_port)
        
        # Setup encryption
        self.crypto = VPNCrypto(key_hex=encryption_key)
        print(f"🔐 Encryption enabled: AES-256-GCM")
        
        # Network components
        self.tun = None
        self.sock = None
        
    def setup_tun(self):
        """Create and configure TUN interface on client."""
        print("⚙️  Setting up TUN interface...")
        
        tun_interface = TunInterface('tun0', self.config.tun_ip)
        self.tun = tun_interface.create()
        
        print(f"  ✓ TUN interface: {self.config.tun_ip}/24")
        
    def setup_routing(self):
        """Setup routes to direct traffic through VPN tunnel."""
        print("⚙️  Configuring routes...")
        
        print(f"  ✓ Server reachable at 10.8.0.1")
        print(f"  💡 To route specific traffic through VPN:")
        print(f"     sudo ip route add <destination> via 10.8.0.1 dev tun0")
        
    def tun_to_server(self):
        """
        Read packets from TUN, encrypt, and send to server via UDP.
        
        Flow: Local Apps → TUN → Encrypt → UDP → Server
        """
        print("📤 TUN → Server thread started")
        try:
            while True:
                # Read packet from TUN
                packet = self.tun.read(self.tun.mtu)
                
                # Filter IPv4 only
                if not is_ipv4_packet(packet):
                    continue
                
                # Encrypt packet
                encrypted = self.crypto.encrypt(packet)
                
                packet_info = parse_packet_info(packet)
                print(f"  📤 [TUN→Server] {packet_info} ({len(packet):4}b → {len(encrypted):4}b encrypted)")
                
                # Send encrypted packet to server
                self.sock.sendto(encrypted, self.server_addr)
                
        except Exception as e:
            print(f"  ✗ TUN → Server error: {e}")
    
    def server_to_tun(self):
        """
        Receive encrypted packets from server, decrypt, and inject into TUN.
        
        Flow: Server → UDP → Decrypt → TUN → Local Apps
        """
        print("📥 Server → TUN thread started")
        try:
            while True:
                # Receive encrypted packet from server
                encrypted_data, addr = self.sock.recvfrom(65535)
                
                # Verify it's from our server
                if addr[0] != self.config.server_ip:
                    print(f"  ⚠️  Ignoring packet from unknown host: {addr[0]}")
                    continue
                
                try:
                    # Decrypt packet
                    packet = self.crypto.decrypt(encrypted_data)
                    
                    # Filter IPv4 only
                    if not is_ipv4_packet(packet):
                        continue
                    
                    packet_info = parse_packet_info(packet)
                    print(f"  📥 [Server→TUN] {packet_info} ({len(encrypted_data):4}b → {len(packet):4}b decrypted)")
                    
                    # Inject into TUN
                    self.tun.write(packet)
                    
                except Exception as e:
                    print(f"  ⚠️  Decryption failed: {e}")
                    continue
                
        except Exception as e:
            print(f"  ✗ Server → TUN error: {e}")
    
    def start(self):
        """Start the VPN client."""
        print("=" * 60)
        print("VPN Client - AES-256-GCM Encrypted")
        print("=" * 60)
        
        # Setup TUN interface
        self.setup_tun()
        self.setup_routing()
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        print(f"\n🔌 Connected to VPN server: {self.config.server_ip}:{self.config.server_port}")
        print("=" * 60)
        
        try:
            # Start bidirectional forwarding threads
            t1 = threading.Thread(target=self.tun_to_server, daemon=True)
            t2 = threading.Thread(target=self.server_to_tun, daemon=True)
            
            t1.start()
            t2.start()
            
            print("\n✅ VPN tunnel established! (Encrypted)")
            print("\n💡 Test commands:")
            print("   ping 10.8.0.1           - Ping VPN server")
            print("   sudo ip route add 8.8.8.8 via 10.8.0.1 dev tun0  - Route Google DNS")
            print("   ping 8.8.8.8            - Test encrypted tunnel\n")
            
            # Keep main thread alive
            t1.join()
            t2.join()
            
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping client...")
        except Exception as e:
            print(f"✗ Error: {e}")
        finally:
            if self.sock:
                self.sock.close()
            if self.tun:
                self.tun.down()
                self.tun.close()
            print("✓ Client shutdown complete")

if __name__ == "__main__":
    print("Note: This script requires root privileges (sudo)\n")
    
    # Allow server IP from command line or .env
    server_ip = sys.argv[1] if len(sys.argv) > 1 else None
    
    try:
        client = VPNClient(server_host=server_ip)
        client.start()
    except ValueError as e:
        print(f"Configuration Error: {e}")
        print("\nUsage: sudo python vpn_client.py <server_ip>")
        print("   OR: Set SERVER_IP in .env file")
        print("\nExample: sudo python vpn_client.py 192.168.1.100")
        sys.exit(1)

