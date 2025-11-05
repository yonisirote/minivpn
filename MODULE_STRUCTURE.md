# VPN Module Structure

This VPN implementation is organized into focused, single-purpose modules:

## Module Organization

### `vpn_common.py` - Constants
**Purpose:** Shared constants used across the VPN
- Encryption parameters (key sizes, nonce sizes)
- Network defaults (ports, IP addresses, subnets)
- Protocol constants (ICMP=1, TCP=6, UDP=17)

### `vpn_crypto.py` - Encryption
**Purpose:** All cryptographic operations
- `VPNCrypto` class for AES-256-GCM encryption/decryption
- Key validation and management
- Key generation utility

### `vpn_packet.py` - Packet Processing
**Purpose:** IP packet parsing and manipulation
- Extract packet information (protocol, source/dest IPs)
- Validate packet types (IPv4 filtering)
- Parse protocol headers

### `vpn_config.py` - Configuration
**Purpose:** Configuration loading and validation
- `ServerConfig` class for server settings
- `ClientConfig` class for client settings  
- Environment variable loading (.env support)
- IP/port validation helpers

### `vpn_network.py` - Network Operations
**Purpose:** TUN interface and routing management
- `TunInterface` class for TUN device operations
- `NetworkSetup` class for NAT, forwarding, routing
- System network configuration helpers

### `vpn_client.py` - Client Implementation
**Purpose:** VPN client main logic
- Uses above modules for all functionality
- Client-specific connection logic
- Packet forwarding threads

### `vpn_server.py` - Server Implementation  
**Purpose:** VPN server main logic
- Uses above modules for all functionality
- Server-specific connection handling
- Multi-client support (future)

## Benefits of This Structure

1. **Single Responsibility:** Each file has one clear purpose
2. **Reusability:** Components can be used independently
3. **Testability:** Easy to test each module in isolation
4. **Maintainability:** Changes are localized to specific files
5. **Readability:** Clear what each file does from its name
6. **Extensibility:** Easy to add new features without touching unrelated code

## Import Examples

```python
# Use encryption
from vpn_crypto import VPNCrypto
crypto = VPNCrypto()
encrypted = crypto.encrypt(packet)

# Parse packets
from vpn_packet import parse_packet_info, is_ipv4_packet
if is_ipv4_packet(data):
    info = parse_packet_info(data)

# Configure
from vpn_config import ServerConfig
config = ServerConfig()

# Network setup
from vpn_network import TunInterface, NetworkSetup
tun = TunInterface('tun0', '10.8.0.1')
tun.create()
NetworkSetup.enable_ip_forwarding()
```
