# VARTA
Varta - secured decentralized high-sensitive data vault / password manager. It was developed for personal use and learning purposes.

## Values

**Vita sine libertate nihil**

🛡️ Freedom and Privacy 🐺


## Mission

This project is a personal endeavor to move the internet towards a more decentralized and user-controlled future, where freedom is the ultimate goal. We eager to help people, who value their privacy and security, warriors for the free future of the Ukraine 🇺🇦.

***By Ukraine to Ukraine and the World with Love*** 🇺🇦 🌎


## Installation

### Prerequisites
- **Rust** 1.70+ (install via [rustup](https://rustup.rs/))
- **macOS** (for hardware-backed encryption via Keychain)
  - Other platforms supported with software-only encryption

### Build from Source

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/varta.git
   cd varta
   ```

2. **Build the project**
   ```bash
   cargo build --release
   ```

3. **Run VARTA**
   ```bash
   cargo run --release
   ```

### Dependencies

The project uses the following key dependencies:
- `aes-gcm` / `aes-siv` - Symmetric encryption
- `ed25519-dalek` - Classical digital signatures
- `pqcrypto-dilithium` - Post-quantum signatures
- `security-framework` - macOS Keychain integration (macOS only)
- `borsh` - Binary serialization
- `hkdf` - Key derivation

### First Run

On first launch, VARTA will:
1. Generate a device key (stored in macOS Keychain on Apple devices)
2. Prompt you to enter a PIN for key encryption
3. Display the welcome screen

```
    ██╗   ██╗ █████╗ ██████╗ ████████╗ █████╗ 
    ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
    ██║   ██║███████║██████╔╝   ██║   ███████║
    ╚██╗ ██╔╝██╔══██║██╔══██╗   ██║   ██╔══██║
     ╚████╔╝ ██║  ██║██║  ██║   ██║   ██║  ██║
      ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝

    🔐 Secure Password Manager v0.2.0
    🛡️  Hardware-backed encryption on Apple devices
```

Type `help` to see available commands.


## Features & Architecture
- Fully anonymous 
- Decentralized architecture
- P2P / Federated / Centralized (Relayed) hybrid approach
- Zero-trust & Audit-first design
- Flexible consensus mechanisms
- Isolated storage nodes
- Open-source core and API
- Multi-layer encryption
- E2EE
- Quantum-resistant algorithms
- Backup & Recovery
- Cross-platform support
- API-first design

