
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

PC1 (10.0.1.1)
    |
Device1 (10.0.1.2 / 10.0.2.1)
    |
Encrypted UDP Tunnel (port 9003)
    |
Device2 (10.0.2.2 / 10.0.3.1)
    |
PC2 (10.0.3.2)

### Starting the Tunnel

Build the `secure_tunnel` executable from the project's C source files and link it with OpenSSL's `libcrypto`.

Run Device2 first:

    sudo ip netns exec device2 ./secure_tunnel 2

Then start Device1:

    sudo ip netns exec device1 ./secure_tunnel 1

Set up the required routes:

    sudo ip netns exec device1 ip route replace 10.0.3.0/24 dev tun-d1
    sudo ip netns exec device2 ip route replace 10.0.1.0/24 dev tun-d2

Check the connection:

    sudo ip netns exec pc1 ping -c 4 10.0.3.2
    sudo ip netns exec pc1 curl -I http://10.0.3.2:8080

For the HTTP test, a web server must be running on PC2 and listening on port 8080.

### Security Considerations

This implementation is an educational prototype and should not be considered a production-ready VPN. Features such as automatic rekeying, session recovery, complete packet validation, and a full security audit are not included.

Do not store secret keys or pre-shared keys in the Git repository.
