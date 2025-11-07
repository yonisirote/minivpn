#!/usr/bin/env python3
"""
VPN Server with AES-GCM Encryption
Receives encrypted packets from client, decrypts, forwards to internet via NAT.
"""

import socket
import threading
import time

# VPN modules
from crypto import VPNCrypto
from packet import parse_packet_info, is_ipv4_packet, get_dest_ip, get_source_ip
from config import ServerConfig
from network import TunInterface, NetworkSetup

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
        
        # Multi-client support (in-memory)
        self.clients = {}           # vpn_ip → (client_addr, last_seen)
        self.client_ips = {}        # client_addr → vpn_ip
        self.lock = threading.Lock()  # Thread-safe access
    
    def register_client(self, client_addr, vpn_ip):
        """Register client with their VPN IP (learned from packet source)"""
        with self.lock:
            # Check if this is a new registration or update
            is_new = client_addr not in self.client_ips
            
            # Update mappings
            self.client_ips[client_addr] = vpn_ip
            self.clients[vpn_ip] = (client_addr, time.time())
            
            if is_new:
                print(f"✅ New client: {client_addr[0]}:{client_addr[1]} → VPN IP {vpn_ip}")
            
            return vpn_ip
    
    def get_client_addr(self, vpn_ip):
        """Get client address from VPN IP"""
        with self.lock:
            if vpn_ip in self.clients:
                return self.clients[vpn_ip][0]
            return None
    
    def release_client_ip(self, client_addr):
        """Release client IP from registry"""
        with self.lock:
            if client_addr in self.client_ips:
                vpn_ip = self.client_ips.pop(client_addr)
                self.clients.pop(vpn_ip, None)
                print(f"ℹ️  Disconnected: {client_addr[0]}:{client_addr[1]} (was {vpn_ip})")
        
    def tun_to_client(self):
        """
        Read packets from TUN, encrypt, and send to appropriate client via UDP.
        
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
                
                # Extract destination VPN IP from packet
                dest_vpn_ip = get_dest_ip(packet)
                
                # Find which client has this VPN IP
                client_addr = self.get_client_addr(dest_vpn_ip)
                
                if client_addr:
                    # Encrypt packet
                    encrypted = self.crypto.encrypt(packet)
                    
                    # Send encrypted packet to specific client
                    self.sock.sendto(encrypted, client_addr)
                    
                    packet_info = parse_packet_info(packet)
                    print(f"  📤 [TUN→{dest_vpn_ip}] {packet_info} ({len(packet):4}b → {len(encrypted):4}b encrypted)")
                    
        except Exception as e:
            print(f"  ✗ TUN → Client error: {e}")
    
    def client_to_tun(self):
        """
        Receive encrypted packets from clients, decrypt, and inject into TUN.
        
        Flow: Client → UDP → Decrypt → Server TUN → Internet
        """
        print("📥 Client → TUN thread started")
        try:
            while True:
                # Receive encrypted packet from any client
                encrypted_data, client_addr = self.sock.recvfrom(65535)
                
                try:
                    # Decrypt packet
                    packet = self.crypto.decrypt(encrypted_data)
                    
                    # Filter IPv4 only
                    if not is_ipv4_packet(packet):
                        continue
                    
                    # Extract source VPN IP from packet (client's configured IP)
                    src_vpn_ip = get_source_ip(packet)
                    
                    # Register/update client with their VPN IP
                    self.register_client(client_addr, src_vpn_ip)
                    
                    packet_info = parse_packet_info(packet)
                    print(f"  📥 [{src_vpn_ip}→TUN] {packet_info} ({len(encrypted_data):4}b → {len(packet):4}b decrypted)")
                    
                    # Inject into TUN for routing to internet
                    self.tun.write(packet)
                    
                except Exception as e:
                    print(f"  ⚠️  Error from {client_addr}: {e}")
                    continue
                
        except Exception as e:
            print(f"  ✗ Client → TUN error: {e}")
    
    def start(self):
        """Start the VPN server."""
        print("=" * 60)
        print("VPN Server - AES-256-GCM Encrypted")
        print("=" * 60)
        
        # Setup TUN interface
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
