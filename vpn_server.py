#!/usr/bin/env python3
"""
VPN Server - Clean version for separate machine deployment
Receives packets from client, forwards to internet via NAT, and returns responses.
"""

import pytun
import subprocess
import socket
import threading
import os
from dotenv import load_dotenv

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
    def __init__(self, host='0.0.0.0', port=None):
        self.host = host
        self.port = port or int(os.getenv('SERVER_PORT', 8888))
        self.tun_ip = os.getenv('SERVER_TUN_IP', '10.8.0.1')
        self.vpn_subnet = os.getenv('VPN_SUBNET', '10.8.0.0/24')
        self.tun = None
        self.sock = None
        self.client_addr = None
        
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
        
        # Enable IP forwarding (allows server to route packets)
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True, capture_output=True
        )
        print(f"  ✓ IP forwarding enabled")
        
        # Setup NAT (MASQUERADE) so client traffic can reach internet
        # This rewrites the source IP of packets from 10.8.0.x to server's public IP
        try:
            # Remove rule if it exists
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
        Read packets from TUN (responses from internet) and send to client via UDP.
        
        Flow: Internet → Server TUN → UDP → Client
        """
        print("📤 TUN → Client thread started")
        try:
            while True:
                # Read packet from TUN (response packets coming back)
                packet = self.tun.read(self.tun.mtu)
                
                # Filter IPv4 only
                version = packet[0] >> 4 if len(packet) > 0 else 0
                if version != 4:
                    continue
                
                if self.client_addr:
                    # Send packet back to client via UDP
                    self.sock.sendto(packet, self.client_addr)
                    packet_info = parse_packet_info(packet)
                    print(f"  📤 [TUN→Client] {packet_info} ({len(packet):4} bytes)")
                    
        except Exception as e:
            print(f"  ✗ TUN → Client error: {e}")
    
    def client_to_tun(self):
        """
        Receive packets from client via UDP and inject into TUN.
        
        Flow: Client → UDP → Server TUN → Internet
        """
        print("📥 Client → TUN thread started")
        try:
            while True:
                # Receive packet from client
                packet, addr = self.sock.recvfrom(65535)
                
                # Register client on first packet
                if not self.client_addr:
                    self.client_addr = addr
                    print(f"\n✅ Client connected: {addr[0]}:{addr[1]}\n")
                
                # Filter IPv4 only
                version = packet[0] >> 4 if len(packet) > 0 else 0
                if version != 4:
                    continue
                
                packet_info = parse_packet_info(packet)
                print(f"  📥 [Client→TUN] {packet_info} ({len(packet):4} bytes)")
                
                # Inject into TUN (kernel will route to internet via NAT)
                self.tun.write(packet)
                
        except Exception as e:
            print(f"  ✗ Client → TUN error: {e}")
    
    def start(self):
        """Start the VPN server."""
        print("=" * 60)
        print("VPN Server - Ready for client connection")
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
