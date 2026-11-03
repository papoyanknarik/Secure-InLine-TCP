## Secure Bidirectional TUN Tunnel

This project provides an authenticated and encrypted IP tunnel connecting two Linux network namespaces.

### Main Features

- Ephemeral X25519 key exchange
- HMAC-based authentication with a pre-shared key
- HKDF session key and directional key generation
- AES-256-GCM encryption and authentication
- Separate nonce management for each direction
- Replay protection with a 64-packet sliding window
- Bidirectional packet forwarding between TUN and UDP
- IPv4 and TCP communication between PC1 and PC2

### Network Topology

```text
PC1 (10.0.1.1)
    |
Device1 (10.0.1.2 / 10.0.2.1)
    |
Encrypted UDP Tunnel (port 9003)
    |
Device2 (10.0.2.2 / 10.0.3.1)
    |
PC2 (10.0.3.2)
