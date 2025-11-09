# MiniVPN 

A learning-focused VPN implementation with AES-256-GCM encryption, built with Python.

## Features

✅ **AES-256-GCM Encryption** - Modern authenticated encryption  
✅ **Multi-client support** - Server handles multiple simultaneous clients  
✅ **TUN interface** - Leverages Linux kernel routing  
✅ **NAT/Masquerading** - Automatic internet access through VPN  
✅ **Detailed logging** - See every packet flow  

---

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/yonisirote/minivpn.git
cd minivpn

# Install dependencies
pip install -r requirements.txt
```

### 2. Generate Encryption Key

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output for the next step.

### 3. Configure Environment


**Server `.env`:**
```bash
SERVER_PORT=8888
SERVER_TUN_IP=10.8.0.1
VPN_SUBNET=10.8.0.0/24
ENCRYPTION_KEY=<your_generated_key_here>
```

**Client `.env`:**
```bash
SERVER_IP=<your_server_ip>
SERVER_PORT=8888
CLIENT_TUN_IP=10.8.0.2
ENCRYPTION_KEY=<same_key_as_server>
```

### 4. Run Server

```bash
sudo python server.py
```

You should see:
```
🔐 Encryption enabled: AES-256-GCM
⚙️  Setting up TUN interface...
  ✓ TUN interface: 10.8.0.1/24
  ✓ IP forwarding enabled
  ✓ NAT configured (MASQUERADE via eth0)
🌐 Server listening on 0.0.0.0:8888 (UDP)
```

### 5. Run Client

**Option A: Using .env file**
```bash
sudo python client.py
```

**Option B: Specify server IP directly**
```bash
sudo python client.py 16.170.133.93
```

You should see:
```
✅ VPN tunnel established! (Encrypted)
```

---

## Routing Traffic Through VPN

By default, the VPN tunnel is established but traffic is not routed yet. You must configure routing:

### Option 1: Route Specific IPs/Websites

Route only certain destinations through the VPN:

```bash
# Route Google DNS through VPN
sudo ip route add 8.8.8.8 via 10.8.0.1 dev tun0

# Route Cloudflare DNS through VPN
sudo ip route add 1.1.1.1 via 10.8.0.1 dev tun0

# Route a specific subnet through VPN
sudo ip route add 192.168.100.0/24 via 10.8.0.1 dev tun0

# Test it
ping 8.8.8.8
```

### Option 2: Route ALL Traffic Through VPN

⚠️ **WARNING:** This replaces your default route. Use with caution!

```bash
# Route all internet traffic through VPN
sudo ip route add default via 10.8.0.1 dev tun0 metric 100

# Test it
ping 8.8.8.8
curl ifconfig.me  # Should show VPN server's public IP
```

### Removing Routes

When done, remove the routes:

```bash
# Remove specific route
sudo ip route del 8.8.8.8 via 10.8.0.1 dev tun0

# Remove default route through VPN
sudo ip route del default via 10.8.0.1 dev tun0 metric 100
```

Or simply stop the VPN client (Ctrl+C), which brings down the TUN interface and removes associated routes automatically.

---

## Testing the VPN

### 1. Test Server Connectivity

```bash
ping 10.8.0.1
```

### 2. Test Internet Through VPN

```bash
# Add route
sudo ip route add 8.8.8.8 via 10.8.0.1 dev tun0

# Ping Google DNS (should work and be encrypted)
ping 8.8.8.8
```

### 3. Check Your Public IP

```bash
# Route all traffic through VPN
sudo ip route add default via 10.8.0.1 dev tun0 metric 100

# Check public IP (should show VPN server's IP)
curl ifconfig.me

# Remove route
sudo ip route del default via 10.8.0.1 dev tun0 metric 100
```

---

## Logging

The VPN shows detailed packet information:

**Server Output:**
```
✅ New client: 203.0.113.50:12345 → VPN IP 10.8.0.2
📥 [10.8.0.2→TUN] ICMP   10.8.0.2        → 8.8.8.8         ( 112b →   84b decrypted)
📤 [TUN→10.8.0.2] ICMP   8.8.8.8         → 10.8.0.2        (  84b →  112b encrypted)
```

**Client Output:**
```
📤 [TUN→Server] ICMP   10.8.0.2        → 8.8.8.8         (  84b →  112b encrypted)
📥 [Server→TUN] ICMP   8.8.8.8         → 10.8.0.2        ( 112b →   84b decrypted)
```

**Legend:**
- Protocol: ICMP (ping), TCP (web/ssh), UDP (DNS)
- Source IP → Destination IP
- Packet sizes (plaintext → encrypted)

---


## How It Works

1. **Client** creates TUN interface (`tun0`) with IP `10.8.0.2`
2. **Server** creates TUN interface (`tun0`) with IP `10.8.0.1`
3. **Encryption**: All packets encrypted with AES-256-GCM before sending over UDP
4. **Routing**: Linux kernel routes packets through TUN interfaces
5. **NAT**: Server masquerades VPN traffic to internet
6. **Multi-client**: Server learns client VPN IPs from packet sources

```
Client App → tun0 → Encrypt → UDP → Server → Decrypt → tun0 → NAT → Internet
                                                                  ↓
Client App ← tun0 ← Decrypt ← UDP ← Server ← Encrypt ← tun0 ← Internet
```

---

