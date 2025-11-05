#!/usr/bin/env python3
"""
VPN Server with AES-GCM Encryption
Receives encrypted packets from client, decrypts, forwards to internet via NAT.
"""

import pytun
import subprocess
import socket
import threading
import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# Load environment variables
load_dotenv()

def parse_packet_info(packet):
    """Extract source IP, dest IP, and protocol from IP packet."""
    if len(packet) < 20:
        return "Invalid packet (too short)"
    
    version = packet[0] >> 4
    if version != 4:
        return f"IPv{version} packet"
    
    protocol = packet[9]
    protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    proto_name = protocol_names.get(protocol, f"Proto-{protocol}")
    
    src_ip = ".".join(str(b) for b in packet[12:16])
    dst_ip = ".".join(str(b) for b in packet[16:20])
    
    return f"{proto_name:6} {src_ip:15} → {dst_ip:15}"

class VPNServer:
    def __init__(self, host='0.0.0.0', port=None, encryption_key=None):
        self.host = host
        self.port = port or int(os.getenv('SERVER_PORT', 8888))
        self.tun_ip = os.getenv('SERVER_TUN_IP', '10.8.0.1')
        self.vpn_subnet = os.getenv('VPN_SUBNET', '10.8.0.0/24')
        self.tun = None
        self.sock = None
        self.client_addr = None
        
        # Encryption setup
        key_hex = encryption_key or os.getenv('ENCRYPTION_KEY')
        if not key_hex or key_hex == 'changeme_generate_a_real_key_with_command_above':
            raise ValueError("ENCRYPTION_KEY not set in .env! Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
        
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != 32:
            raise ValueError(f"Encryption key must be 32 bytes (64 hex chars), got {len(key_bytes)} bytes")
        
        self.cipher = AESGCM(key_bytes)
        print(f"🔐 Encryption enabled: AES-256-GCM")
        
    def encrypt_packet(self, plaintext):
        """Encrypt packet with AES-GCM. Returns nonce + ciphertext + tag."""
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        ciphertext = self.cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext  # nonce (12 bytes) + ciphertext + tag (16 bytes)
    
    def decrypt_packet(self, encrypted_data):
        """Decrypt packet. Expects nonce + ciphertext + tag."""
        if len(encrypted_data) < 12:
            raise ValueError("Encrypted data too short")
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        return plaintext
        
    def setup_tun(self):
        """Create and configure TUN interface on server."""
        print("⚙️  Setting up TUN interface...")
        
        self.tun = pytun.TunTapDevice(name='tun0', flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
        
        subprocess.run(
            ["ip", "addr", "add", f"{self.tun_ip}/24", "dev", self.tun.name],
            check=True, capture_output=True
        )
        
        self.tun.up()
        subprocess.run(
            ["ip", "link", "set", self.tun.name, "up"],
            check=True, capture_output=True
        )
        
        subprocess.run(
            ["sysctl", "-w", f"net.ipv6.conf.{self.tun.name}.disable_ipv6=1"],
            check=True, capture_output=True
        )
        
        print(f"  ✓ TUN interface: {self.tun_ip}/24")
        
        # Enable IP forwarding
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True, capture_output=True
        )
        print(f"  ✓ IP forwarding enabled")
        
        # Setup NAT
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", self.vpn_subnet, "-j", "MASQUERADE"],
                capture_output=True
            )
        except:
            pass
        
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", self.vpn_subnet, "-j", "MASQUERADE"],
            check=True, capture_output=True
        )
        print(f"  ✓ NAT configured (MASQUERADE)")
        
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
                version = packet[0] >> 4 if len(packet) > 0 else 0
                if version != 4:
                    continue
                
                if self.client_addr:
                    # Encrypt packet
                    encrypted = self.encrypt_packet(packet)
                    
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
                    packet = self.decrypt_packet(encrypted_data)
                    
                    # Filter IPv4 only
                    version = packet[0] >> 4 if len(packet) > 0 else 0
                    if version != 4:
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
        self.sock.bind((self.host, self.port))
        
        print(f"\n🌐 Server listening on {self.host}:{self.port} (UDP)")
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
            try:
                subprocess.run(
                    ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", self.vpn_subnet, "-j", "MASQUERADE"],
                    capture_output=True
                )
            except:
                pass
            
            print("✓ Server shutdown complete")

if __name__ == "__main__":
    print("Note: This script requires root privileges (sudo)\n")
    server = VPNServer()
    server.start()
