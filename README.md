# Secure Bidirectional TUN Tunnel

This project implements an authenticated and encrypted IP tunnel between two Linux network namespaces.

## Security Features

- Ephemeral X25519 key exchange
- Pre-shared key (PSK) authentication using HMAC
- HKDF session key and directional key derivation
- AES-256-GCM authenticated encryption
- Separate nonce management for each direction
- Replay protection with a 64-packet sliding window
- Bidirectional UDP/TUN packet forwarding
- IPv4 and TCP communication

## Network Topology

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
```

## Building the Application

Compile the application using GCC and OpenSSL:

```bash
gcc -Wall -Wextra -Werror -Iinclude \
    src/secure_tunnel.c \
    src/tunnel_handshake_client.c \
    src/tunnel_handshake_server.c \
    src/tunnel_session.c \
    src/tunnel_keys.c \
    src/crypto_utils.c \
    src/tun_device.c \
    src/payload_crypto.c \
    src/aes_gcm.c \
    src/nonce_manager.c \
    src/replay_protection.c \
    -lcrypto -o secure_tunnel
```

## Running the Tunnel

Start Device2 first:

```bash
sudo ip netns exec device2 ./secure_tunnel 2
```

Then start Device1 in another terminal:

```bash
sudo ip netns exec device1 ./secure_tunnel 1
```

Configure the network routes:

```bash
sudo ip netns exec device1 ip route replace 10.0.3.0/24 dev tun-d1
sudo ip netns exec device2 ip route replace 10.0.1.0/24 dev tun-d2
```

## Testing

The following tests can be used to verify the tunnel:

**ICMP connectivity:**

```bash
sudo ip netns exec pc1 ping -c 4 10.0.3.2
```

**HTTP server on PC2:**

```bash
sudo ip netns exec pc2 python3 -m http.server 8080 --bind 10.0.3.2 --directory /tmp
```

**TCP connection from PC1:**

```bash
sudo ip netns exec pc1 curl -I http://10.0.3.2:8080
```

The handshake, encrypted packet transmission, bidirectional communication, ICMP connectivity, and TCP connectivity should be verified through these tests.

## Limitations

This project is an educational prototype and is not a production-ready VPN. Automatic rekeying, reliable session recovery, and a complete security audit are not implemented.

Secret keys and pre-shared keys must never be committed to the Git repository.
