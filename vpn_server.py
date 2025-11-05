#!/usr/bin/env python3
"""
VPN Server with AES-GCM Encryption
Receives encrypted packets from client, decrypts, forwards to internet via NAT.
"""

import socket
import threading

# VPN modules
from vpn_crypto import VPNCrypto
from vpn_packet import parse_packet_info, is_ipv4_packet
from vpn_config import ServerConfig
from vpn_network import TunInterface, NetworkSetup

class VPNServer:
    def __init__(self, encryption_key=None):
        # Load configuration
        self.config = ServerConfig()
        
        # Setup encryption
        self.crypto = VPNCrypto(key_hex=encryption_key)
        print(f"🔐 Encryption enabled: AES-256-GCM")
        
        # Network components
        self.tun = None
        self.sock = None
        self.client_addr = None
        
    def setup_tun(self):
        """Create and configure TUN interface on server."""
        print("⚙️  Setting up TUN interface...")
        
        tun_interface = TunInterface('tun0', self.config.tun_ip)
        self.tun = tun_interface.create()
        
        print(f"  ✓ TUN interface: {self.config.tun_ip}/24")
        
        # Enable IP forwarding
        NetworkSetup.enable_ip_forwarding()
        print(f"  ✓ IP forwarding enabled")
        
        # Setup NAT
        output_iface = NetworkSetup.setup_nat(self.config.vpn_subnet)
        print(f"  ✓ NAT configured (MASQUERADE via {output_iface})")
        
    def tun_to_client(self):
        """
        Read packets from TUN, encrypt, and send to client via UDP.
        
        Flow: Internet → Server TUN → Encrypt → UDP → Client
        """
        print("📤 TUN → Client thread started")
        try:
            while True:
                # Read packet from TUN
                packet = self.tun.read(self.tun.mtu)
                
                # Filter IPv4 only
                if not is_ipv4_packet(packet):
                    continue
                
                if self.client_addr:
                    # Encrypt packet
                    encrypted = self.crypto.encrypt(packet)
                    
                    # Send encrypted packet to client
                    self.sock.sendto(encrypted, self.client_addr)
                    
                    packet_info = parse_packet_info(packet)
                    print(f"  📤 [TUN→Client] {packet_info} ({len(packet):4}b → {len(encrypted):4}b encrypted)")
                    
        except Exception as e:
            print(f"  ✗ TUN → Client error: {e}")
    
    def client_to_tun(self):
        """
        Receive encrypted packets from client, decrypt, and inject into TUN.
        
        Flow: Client → UDP → Decrypt → Server TUN → Internet
        """
        print("📥 Client → TUN thread started")
        try:
            while True:
                # Receive encrypted packet from client
                encrypted_data, addr = self.sock.recvfrom(65535)
                
                # Register client on first packet
                if not self.client_addr:
                    self.client_addr = addr
                    print(f"\n✅ Client connected: {addr[0]}:{addr[1]}\n")
                
                try:
                    # Decrypt packet
                    packet = self.crypto.decrypt(encrypted_data)
                    
                    # Filter IPv4 only
                    if not is_ipv4_packet(packet):
                        continue
                    
                    packet_info = parse_packet_info(packet)
                    print(f"  📥 [Client→TUN] {packet_info} ({len(encrypted_data):4}b → {len(packet):4}b decrypted)")
                    
                    # Inject into TUN
                    self.tun.write(packet)
                    
                except Exception as e:
                    print(f"  ⚠️  Decryption failed: {e}")
                    continue
                
        except Exception as e:
            print(f"  ✗ Client → TUN error: {e}")
    
    def start(self):
        """Start the VPN server."""
        print("=" * 60)
        print("VPN Server - AES-256-GCM Encrypted")
        print("=" * 60)
        
        # Setup TUN and NAT
        self.setup_tun()
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.config.host, self.config.port))
        
        print(f"\n🌐 Server listening on {self.config.host}:{self.config.port} (UDP)")
        print(f"   Waiting for client connection...\n")
        print("=" * 60)
        
        try:
            # Start bidirectional forwarding threads
            t1 = threading.Thread(target=self.tun_to_client, daemon=True)
            t2 = threading.Thread(target=self.client_to_tun, daemon=True)
            
            t1.start()
            t2.start()
            
            # Keep main thread alive
            t1.join()
            t2.join()
            
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping server...")
        finally:
            if self.sock:
                self.sock.close()
            if self.tun:
                self.tun.down()
                self.tun.close()
            
            # Clean up NAT rule
            NetworkSetup.cleanup_nat(self.config.vpn_subnet)
            
            print("✓ Server shutdown complete")

if __name__ == "__main__":
    print("Note: This script requires root privileges (sudo)\n")
    server = VPNServer()
    server.start()
