# VPN Setup Instructions

## Clean Two-Machine Setup

### On Server Machine:

1. **Install dependencies:**
   ```bash
   pip install python-pytun
   ```

2. **Run server:**
   ```bash
   sudo python vpn_server.py
   ```

3. **Note the server's IP address:**
   ```bash
   ip addr show
   # Look for your main network interface IP (e.g., 192.168.1.100)
   ```

4. **Allow UDP port 8888 through firewall (if needed):**
   ```bash
   sudo ufw allow 8888/udp
   # Or for iptables:
   sudo iptables -A INPUT -p udp --dport 8888 -j ACCEPT
   ```

### On Client Machine:

1. **Install dependencies:**
   ```bash
   pip install python-pytun
   ```

2. **Run client (replace with your server's IP):**
   ```bash
   sudo python vpn_client.py 192.168.1.100
   ```

3. **Test the tunnel:**
   ```bash
   # Ping the VPN server
   ping 10.8.0.1
   
   # Route specific traffic through VPN
   sudo ip route add 8.8.8.8 via 10.8.0.1 dev tun0
   ping 8.8.8.8
   ```

## What's Been Cleaned Up

✓ Removed all single-machine workarounds
✓ Removed localhost-specific code
✓ Removed route hacks
✓ Simplified debug output
✓ Added proper NAT configuration
✓ Added command-line argument for server IP
✓ Clear separation of concerns

## How It Works

```
Client Machine                    Server Machine
┌─────────────┐                  ┌─────────────┐
│ Your Apps   │                  │             │
│     ↓       │                  │             │
│   tun0      │                  │   tun0      │
│ 10.8.0.2    │                  │ 10.8.0.1    │
│     ↓       │                  │     ↑       │
│ vpn_client  │ ──── UDP ────→   │ vpn_server  │
│     ↓       │    Port 8888     │     ↓       │
└─────────────┘                  │    NAT      │
                                 │     ↓       │
                                 │  Internet   │
                                 └─────────────┘
```

## Next Steps After Testing

Once this works on two machines:
- Phase 3: Add encryption (AES-GCM or ChaCha20)
- Phase 4: Add authentication
- Phase 5: Handle reconnections and errors
