# VPN Setup with .env Configuration

## Quick Start

### 1. Copy and configure .env file

```bash
cp .env.example .env
nano .env  # Edit with your server's IP
```

Example `.env`:
```bash
SERVER_IP=16.170.133.93
SERVER_PORT=8888
CLIENT_TUN_IP=10.8.0.2
SERVER_TUN_IP=10.8.0.1
VPN_SUBNET=10.8.0.0/24
```

### 2. Run Server (on EC2 or remote machine)

```bash
sudo python vpn_server.py
```

### 3. Run Client (on your local machine)

**Option A: Using .env file**
```bash
sudo python vpn_client.py
```

**Option B: Command line (overrides .env)**
```bash
sudo python vpn_client.py 16.170.133.93
```

### 4. Test the connection

```bash
# Ping VPN server
ping 10.8.0.1

# Route Google DNS through VPN
sudo ip route add 8.8.8.8 via 10.8.0.1 dev tun0
ping 8.8.8.8
```

## Enhanced Logging

The new version shows detailed packet information:

**Server Output:**
```
📥 [Client→TUN] ICMP   10.8.0.2        → 8.8.8.8        (  84 bytes)
📤 [TUN→Client] ICMP   8.8.8.8         → 10.8.0.2       (  84 bytes)
```

**Client Output:**
```
📤 [TUN→Server] ICMP   10.8.0.2        → 8.8.8.8        (  84 bytes)
📥 [Server→TUN] ICMP   8.8.8.8         → 10.8.0.2       (  84 bytes)
```

This shows:
- Protocol (ICMP, TCP, UDP)
- Source IP
- Destination IP
- Packet size

Perfect for understanding traffic flow and debugging!
