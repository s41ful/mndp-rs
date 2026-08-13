# mndp-rs

A simple Rust library and CLI tool for discovering MikroTik devices on your local network using the MikroTik Neighbor Discovery Protocol (MNDP).

## 📦 Installation

### As a Library
Add `mndp-rs` to your `Cargo.toml`:

```toml
[dependencies]
mndp-rs = { git = "https://github.com/s41ful/mndp-rs.git" }
```

## As a CLI tool

Install directly via cargo:

```bash
cargo install --git https://github.com/s41ful/mndp-rs.git
```

## ⚙️ Prerequisites & Privileges

- General Usage (0.0.0.0): Listening on all interfaces without raw socket capture runs under standard user privileges.
- Linux / macOS: Binding to specific network interfaces (e.g., eth0) requires root/sudo privileges or CAP_NET_RAW capabilities.
- Windows: Capturing on specific interfaces requires Npcap installed with WinPcap compatibility mode enabled.

🛠 Usage
CLI Application

Listen for MNDP packets for a set duration:
```bash
# Search for 30 seconds
mndp -t 30s

# Search on a specific interface (may require elevated privileges)
mndp -i eth0 -t 10s
```

If running from source:
```bash
cargo run -- -t 30s
```

Rust Library:

```rust
use std::time::Duration;
use mndp_rs::{Listener, MndpConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = MndpConfig::new();
    config.timeout = Duration::from_secs(10);
    
    // Listen on 0.0.0.0 without raw socket privileges
    config.interface = None; 
    
    // Target a specific interface (requires elevated privileges)
    // config.interface = Some("eth0".to_string());

    let mut listener = Listener::new(config);
    let devices = listener.discover()?;

    for device in devices {
        println!("Identity: {}", device.identity);
        println!("MAC Address: {}", device.mac_address);
        println!("IPv4 Address: {}", device.ipv4_address);
        println!("Board: {}", device.board);
        println!("Software Version: {}", device.version);
        println!("----------------------------------------");
    }

    Ok(())
}
```

## 📄 License

MIT License  
See `LICENSE` file for details.
