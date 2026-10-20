```text
  NIP: 1
  Title: Mycelium: Onion Routing and Mixnet Layer for NETFORY Iroh
  Authors: TechnoLog <technolog@smartholdem.io> / <SeZLuyhhYf2qxs4ArPJ71oEu3x8EsVw51C@sth>
  Status: Draft
  Discussions-To: https://github.com/netfory/NIPs/issues
  Type: Standards Track
  Category: Network / Privacy
  Created: 2026-09-18
  Last Update: 2026-09-18
```

# Mycelium: Onion Routing Protocol Specification

## Abstract

**Mycelium** is an application-layer onion routing (mixnet) protocol designed natively for the NETFORY P2P ecosystem. Operating on top of Iroh transport primitives (`iroh-net` QUIC streams and cryptographic `NodeID` addressing), Mycelium provides end-to-end metadata privacy, sender-receiver unlinkability, and robust censorship resistance. It enables multi-hop encrypted circuit routing, ensuring that intermediate relay nodes can only decrypt the immediate routing instructions without knowing the ultimate origin or destination of a packet.

---

## Motivation

Standard P2P connections (including direct Iroh hole-punching and single-hop TLS/QUIC relays) provide high throughput and low latency, but they expose metadata: an observer or a relay node can observe which `NodeID` is communicating with which target. In adversarial network environments under aggressive deep packet inspection (DPI) or localized surveillance, this metadata leakage compromises user sovereignty.

While classical Tor provides onion routing over TCP, it suffers from high latency and protocol overhead unsuited for modern decentralized applications. Mycelium leverages Iroh's high-performance QUIC multiplexing and cryptographic node identities to establish low-latency, multi-hop anonymous circuits tailored for NETFORY mesh infrastructure.

---

## Specification

### 1. Circuit Topography & Node Roles

A Mycelium anonymous circuit consists of a directed path of three intermediate relay nodes chosen pseudo-randomly from the active NETFORY DHT routing table:

1. **Entry Node (Guard):** Knows the client's real `NodeID`/IP, but does not know the final destination or message content.
2. **Middle Node (Mix):** Knows only the previous hop (Entry) and the next hop (Exit). It is entirely blind to both origin and destination.
3. **Exit Node:** Knows the final recipient `NodeID` and unwraps the innermost layer to deliver the payload, but does not know the original sender.

### 2. Cryptographic Handshake & Key Agreement

* **Primitive:** X25519 for ephemeral Diffie-Hellman key exchanges combined with HKDF-SHA256 for session key derivation.
* **Encryption:** Authenticated encryption with associated data (AEAD) using **ChaCha20-Poly1305**.
* **Circuit Setup:** The client performs a telescoping path-building handshake:
1. Establishes an encrypted session with the Entry node.
2. Extends the circuit through the Entry node to establish a session with the Middle node.
3. Extends further through the Middle node to establish a session with the Exit node.

### 3. Packet Framing & Fixed-Size Cells

To prevent traffic analysis based on packet-length profiling (side-channel attacks), all application-layer messages are segmented or padded into **Fixed-Size Cells** (default size: **2048 bytes**).

* If a payload is smaller than 2048 bytes, it is padded with cryptographically secure pseudorandom bytes.
* If larger, it is fragmented across multiple sequential cells with sequence identifiers.

### 4. Layered Onion Encryption Structure

A Mycelium packet directed through a 3-hop circuit (`Client -> Guard -> Middle -> Exit -> Recipient`) is wrapped in three layers of encryption.

When constructing a cell, the client encrypts the payload sequentially from inside out:

1. **Innermost Layer ($L_3$):** Encrypted with the Exit node's session key. Contains the target recipient's `NodeID`, command code (`DATA`, `PING`, `CLOSE`), and the actual data payload.
2. **Middle Layer ($L_2$):** Encrypted with the Middle node's session key. Wraps $L_3$ and specifies the forwarding instruction to the Exit node.
3. **Outermost Layer ($L_1$):** Encrypted with the Entry node's session key. Wraps $L_2$ and specifies the forwarding instruction to the Middle node.

```
[ Client ] 
   │ (Encrypted with Guard key)
   ▼
[ Guard Node ] --(Decrypts L1, forwards L2)--> [ Middle Node ]
                                                 │ (Decrypts L2, forwards L3)
                                                 ▼
                                              [ Exit Node ] --(Decrypts L3, delivers)--> [ Recipient ]

```

### 5. Transport over Iroh (ALPN)

Mycelium tunnels its cells over dedicated Iroh QUIC streams identified by the Application-Layer Protocol Negotiation (ALPN) token:

```rust
pub const MYCELIUM_ALPN: &[u8] = b"netfory/mycelium/1";

```

Because QUIC multiplexes multiple streams over a single UDP connection without Head-of-Line blocking, multiple independent Mycelium circuits can run concurrently over the same physical Iroh connection without interfering with each other.

---

## Rationale

* **Why fixed-size cells?** Variable-length packet analysis allows adversaries to correlate traffic patterns entering and leaving relay nodes. Fixed-size framing neutralizes this vector.
* **Why 3 hops?** The standard 3-hop topology (Guard-Middle-Exit) provides an optimal mathematical balance between cryptographic security (preventing collusion between entry and exit nodes) and network latency.
* **Why Iroh instead of TCP/IP?** Iroh provides native NAT traversal, robust cryptographic identities (`NodeID` instead of raw IP addresses), and high-speed QUIC framing out-of-the-box.



---

## Security Considerations

1. **Collusion Attacks:** If the malicious actor operates both the Entry and Exit nodes of the same circuit, timing correlation attacks can potentially link sender to receiver. Mitigation: Random circuit selection with weighted preferences for high-reputation community nodes.
2. **Timing Analysis:** Global passive adversaries monitoring network ingress and egress can correlate packet timings. Mitigation: Optional dummy-traffic generation (padding cells with random noise at randomized intervals).
3. **Exit Node Liability:** Exit nodes forward traffic to the final recipient. To protect honest exit node operators, exit policies can restrict traffic types or enforce encrypted end-to-end NETFORY application payloads only.

---

## Reference Implementation (Rust Outline)

```rust
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, Nonce};
use iroh::NodeId;

pub const CELL_SIZE: usize = 2048;

/// Represents a single Mycelium fixed-size routing cell
pub struct MyceliumCell {
    pub payload: [u8; CELL_SIZE],
}

impl MyceliumCell {
    /// Peels one layer of onion encryption at the relay node
    pub fn peel(&mut self, cipher: &ChaCha20Poly1305, nonce: &Nonce) -> Result<(), &'static str> {
        // In-place decryption of the outer layer
        cipher.decrypt_in_place(nonce, b"", &mut self.payload)
            .map_err(|_| "Failed to decrypt onion layer")?;
        Ok(())
    }
}

```