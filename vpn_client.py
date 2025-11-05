#!/usr/bin/env python3
"""
VPN Client - Clean version for separate machine deployment
Captures local traffic, sends to VPN server, receives responses.
"""

import pytun
import subprocess
import socket
import threading
import sys
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

class VPNClient:
    def __init__(self, server_host=None, server_port=None):
        self.server_host = server_host or os.getenv('SERVER_IP')
        self.server_port = server_port or int(os.getenv('SERVER_PORT', 8888))
        self.tun_ip = os.getenv('CLIENT_TUN_IP', '10.8.0.2')
        
        if not self.server_host:
            raise ValueError("Server IP not provided. Use command line arg or set SERVER_IP in .env")
        
        self.server_addr = (self.server_host, self.server_port)
        self.tun = None
        self.sock = None
        
    def setup_tun(self):
        """Create and configure TUN interface on client."""
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
        
    def setup_routing(self):
        """Setup routes to direct traffic through VPN tunnel."""
        print("⚙️  Configuring routes...")
        
        # Add route for VPN server's network through tunnel
        # This makes 10.8.0.1 (server) reachable
        print(f"  ✓ Server reachable at 10.8.0.1")
        
        # For full VPN: uncomment to route ALL traffic through tunnel
        # This would require backing up and restoring default gateway
        # subprocess.run(["ip", "route", "add", "default", "via", "10.8.0.1", "dev", self.tun.name])
        
        print(f"  💡 To route specific traffic through VPN:")
        print(f"     sudo ip route add <destination> via 10.8.0.1 dev tun0")
        
    def tun_to_server(self):
        """
        Read packets from TUN (outgoing traffic) and send to server via UDP.
        
        Flow: Local Apps → TUN → UDP → Server
        """
        print("📤 TUN → Server thread started")
        try:
            while True:
                # Read packet from TUN (outgoing traffic)
                packet = self.tun.read(self.tun.mtu)
                
                # Filter IPv4 only
                version = packet[0] >> 4 if len(packet) > 0 else 0
                if version != 4:
                    continue
                
                packet_info = parse_packet_info(packet)
                print(f"  📤 [TUN→Server] {packet_info} ({len(packet):4} bytes)")
                
                # Send to VPN server via UDP
                self.sock.sendto(packet, self.server_addr)
                
        except Exception as e:
            print(f"  ✗ TUN → Server error: {e}")
    
    def server_to_tun(self):
        """
        Receive packets from server via UDP and inject into TUN.
        
        Flow: Server → UDP → TUN → Local Apps
        """
        print("📥 Server → TUN thread started")
        try:
            while True:
                # Receive packet from server
                packet, addr = self.sock.recvfrom(65535)
                
                # Verify it's from our server
                if addr[0] != self.server_host:
                    print(f"  ⚠️  Ignoring packet from unknown host: {addr[0]}")
                    continue
                
                # Filter IPv4 only
                version = packet[0] >> 4 if len(packet) > 0 else 0
                if version != 4:
                    continue
                
                packet_info = parse_packet_info(packet)
                print(f"  📥 [Server→TUN] {packet_info} ({len(packet):4} bytes)")
                
                # Inject into TUN (deliver to local apps)
                self.tun.write(packet)
                
        except Exception as e:
            print(f"  ✗ Server → TUN error: {e}")
    
    def start(self):
        """Start the VPN client."""
        print("=" * 60)
        print("VPN Client - Connecting to server")
        print("=" * 60)
        
        # Setup TUN interface
        self.setup_tun()
        self.setup_routing()
        
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        print(f"\n🔌 Connected to VPN server: {self.server_host}:{self.server_port}")
        print("=" * 60)
        
        try:
            # Start bidirectional forwarding threads
            t1 = threading.Thread(target=self.tun_to_server, daemon=True)
            t2 = threading.Thread(target=self.server_to_tun, daemon=True)
            
            t1.start()
            t2.start()
            
            print("\n✅ VPN tunnel established!")
            print("\n💡 Test commands:")
            print("   ping 10.8.0.1           - Ping VPN server")
            print("   ip route add 8.8.8.8 via 10.8.0.1 dev tun0  - Route Google DNS through VPN")
            print("   ping 8.8.8.8            - Test internet through VPN\n")
            
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
    server_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('SERVER_IP')
    
    if not server_ip:
        print("Usage: sudo python vpn_client.py <server_ip>")
        print("   OR: Set SERVER_IP in .env file")
        print("\nExample: sudo python vpn_client.py 192.168.1.100")
        sys.exit(1)
    
    client = VPNClient(server_host=server_ip)
    client.start()
