**AegisDrop** is a production-grade, zero-knowledge secure file-sharing platform engineered to eliminate custodial cloud vulnerabilities, forensic data remanence, and synchronous peer-to-peer (P2P) network dependencies.

Conventional file transfer protocols force an unacceptable trade-off between **custodial cloud storage** (which retains files indefinitely and holds server-side decryption keys) and **synchronous P2P tools** (which break if the sender disconnects). AegisDrop resolves this through an **asynchronous ephemeral cloud relay** backed by **client-side split-hash key derivation**, **1 MB chunked binary AES-256 encryption**, and **automated Department of Defense (DoD) 2-pass Burn-on-Read disk sanitization**.
---

## Key Architectural Features

* **Zero-Knowledge Architecture:** Cryptographic passphrases, plaintext filenames, and raw file bytes never leave client memory. The central cloud server acts purely as an untrusted ciphertext transit buffer.
* **Asynchronous Ephemeral Staging:** Senders can upload an encrypted vault, close their browser, and disconnect immediately. The payload safely awaits the receiver in ciphertext form without requiring concurrent online presence.
* **Client-Side Split-Hash Derivation:** A single user-defined custom passphrase mathematically yields two distinct cryptographic domains: a public routing hash sent to the server for vault lookup, and private 256-bit AES/HMAC keys that remain strictly confined to client RAM.
* **1 MB Chunked Binary Streams (Zero String Allocation Limits):** Eliminates browser heap exhaustion and JavaScript engine allocation crashes (`RangeError: Invalid string length`) by streaming raw `Uint8Array` binary blobs via multipart `FormData`, bypassing Base64 memory inflation.
* **Cryptographic Tamper Detection:** Every binary chunk is signed on the fly using incremental HMAC-SHA256. Any modification to ciphertext in transit or on disk immediately aborts decryption.
* **Automated Burn-on-Read & Dead-Man's Switch:** Stored files are destroyed the moment the receiver verifies delivery, or automatically shredded when the user-selected Time-To-Live (TTL) countdown reaches zero.
* **Forensic Disk Sanitization (DoD 2-Pass Standard):** Rather than standard operating system pointer unlinking (`os.remove()`), the cloud disk shredder overwrites physical sectors with cryptographically secure random entropy (`os.urandom`) followed by zero-fill bytes (`0x00`) with forced cache flushes (`os.fsync`).
* **Mobile-Optimized QR Bridge:** Automatically generates an out-of-band scannable QR code and direct URI containing the pre-loaded custom key for seamless cross-device transfers over LAN or mobile hotspots.

---

## 3-Node Operational Topology

```
+-----------------------------------------------------------------------------------------+
|                                1. SENDER NODE (PC / Mobile)                             |
|  - Selects file & enters/generates custom key (K)                                       |
|  - Derives: H_route = SHA256(K || Salt_route)                                           |
|             K_enc   = PBKDF2(K, Salt_crypto, 1000 iter)                                 |
|             K_mac   = PBKDF2(K, Salt_mac, 1000 iter)                                    |
|  - Encrypts file in 1 MB binary chunks (AES-256-CBC) + incremental HMAC-SHA256          |
+-----------------------------------------------------------------------------------------+
                                           |
                   1. Multipart FormData   | (Raw .bin + IV + HMAC + Encrypted Meta)
                   [Sender Goes Offline]   v
+-----------------------------------------------------------------------------------------+
|                             2. CLOUD RELAY SERVER (Flask PC)                            |
|  - Stores ciphertext as raw binary: cloud_vaults/<vault_uid>.bin                        |
|  - Indexes vault purely under public H_route (Zero-Knowledge)                           |
|  - Background Daemon: Monitors active TTL timers every 1.0 second                       |
+-----------------------------------------------------------------------------------------+
                                           |
            2. Stream Ciphertext (.bin)    | (On H_route query match)
                                           v
+-----------------------------------------------------------------------------------------+
|                               3. RECEIVER NODE (PC / Mobile)                            |
|  - Scans QR Code / enters Custom Key (K)                                                |
|  - Derives identical H_route, K_enc, and K_mac in browser RAM                           |
|  - Fetches and verifies incremental HMAC-SHA256 signature tag                           |
|  - Decrypts 1 MB binary chunks locally into Blob & downloads file                       |
+-----------------------------------------------------------------------------------------+
                                           |
                               3. POST     | /api/burn (ACK)
                                           v
+-----------------------------------------------------------------------------------------+
|                         4. AUTOMATED CRYPTOGRAPHIC SHREDDER                             |
|  - Overwrites physical file sectors with random noise (os.urandom) + os.fsync           |
|  - Overwrites physical file sectors with 0x00 zero-fill + os.fsync                      |
|  - Unlinks disk pointer: 0 recoverable bytes remaining in cloud storage                 |
+-----------------------------------------------------------------------------------------+
```

---
## Cryptographic Architecture

### 1. Split-Key Mathematical Derivation
When an author inputs a custom passphrase $K$ (e.g., `falcon-orbit-99`), the client browser computes three domain-separated cryptographic branches:

$$H_{\text{route}} = \text{SHA-256}(K \parallel \text{Salt}_{\text{route}})$$

$$K_{\text{enc}} = \text{PBKDF2-SHA256}(K, \text{Salt}_{\text{crypto}}, 1000, 256)$$

$$K_{\text{mac}} = \text{PBKDF2-SHA256}(K, \text{Salt}_{\text{mac}}, 1000, 256)$$

* $H_{\text{route}}$ is transmitted across the network so the server can index the vault.
* $K_{\text{enc}}$ and $K_{\text{mac}}$ remain strictly inside client RAM.

### 2. Chunked Stream Encryption & Tagging
Files are partitioned into binary chunks of size $S = 1{,}048{,}576\text{ bytes}$ ($1\text{ MB}$). Each chunk $i$ is encrypted under a derived dynamic vector:

$$\text{IV}_i = \text{BaseIV} \oplus i$$

$$\text{CipherChunk}_i = \text{AES-256-CBC}(K_{\text{enc}}, \text{IV}_i, \text{PlainChunk}_i)$$

Concurrently, an incremental HMAC state calculates:

$$\text{Tag} = \text{HMAC-SHA256}(K_{\text{mac}}, \text{CipherChunks} \parallel \text{BaseIV} \parallel \text{EncryptedMetadata})$$
---

## Technical Specifications

| Domain | Technology / Specification |
| :--- | :--- |
| **Backend Framework** | Python 3.10+ / Flask (Multi-Threaded Execution Engine) |
| **Concurrency Control** | `threading.RLock` Reentrant Synchronization |
| **Frontend UI** | HTML5, Tailwind CSS (Glassmorphism Dark Theme), Lucide Icons |
| **Client-Side Cryptography** | CryptoJS (AES-256-CBC, PBKDF2, SHA-256, HMAC) |
| **In-Browser Compression** | Pako (Deflate / Inflate Stream Processing) |
| **QR Code Engine** | QRCode.js (Client-Side Rendering) |
| **Disk Sanitization** | Low-Level OS POSIX/Win32 I/O Overwrites (`os.urandom`, `0x00`, `os.fsync`) |

---

## Directory Layout

```text
AegisDrop/
├── .gitignore
├── requirements.txt
├── README.md
├── app.py
├── cloud_vaults/          # Ephemeral directory for staged binary vaults
└── templates/
    └── index.html         # Unified responsive single-page client interface
```
Screenshots
<img width="1273" height="896" alt="image" src="https://github.com/user-attachments/assets/74a54ddb-a233-430e-a424-65ab89bda7cf" />
<img width="1280" height="868" alt="image" src="https://github.com/user-attachments/assets/642ad264-1e45-4ca6-bc67-b1e746f2ca1f" />
<img width="1306" height="783" alt="image" src="https://github.com/user-attachments/assets/0429e988-ef45-4c04-95f3-2a743ff8965b" />


