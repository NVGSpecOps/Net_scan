# NetScan

A fast, cross-platform CLI network scanner that discovers online hosts via ICMP ping. Zero external dependencies — pure Python stdlib.

```


---

## Features

- **Auto-detects** your local network and subnet mask — no args needed
- **Cross-platform** — Windows, Linux, macOS
- **Concurrent scanning** with adaptive worker count (scales with network size)
- **Memory-efficient** — hosts and futures processed in chunks; safe on `/16`+ networks
- Graceful `Ctrl+C` with partial results

---

## Requirements

- Python 3.10+
- No third-party packages

---

## Installation

```bash
git clone https://github.com/NVGSpecOps/netscan.git
cd netscan
```

> **Linux/macOS:** ICMP requires elevated privileges. Run with `sudo` or grant the binary `cap_net_raw`.

---

## Usage

```bash
# Auto-detect local network and scan it
python net_scanner.py

# Scan explicit targets
python net_scanner.py 192.168.9.0/24
python net_scanner.py 192.168.9.0      # implies /24
python net_scanner.py 192.168.9       # implies .0/24
python net_scanner.py 10.0.0.0/16

# Help
python net_scanner.py -h
```

### Linux/macOS — without sudo (optional)

```bash
# Grant raw socket capability to the Python interpreter
sudo setcap cap_net_raw+ep $(which python3)
```

---

## How It Works

```
parse_network()
     │
     ▼
get_local_ip_and_mask()   ← ip addr (Linux) / ifconfig (macOS) / ipconfig (Windows)
     │
     ▼
scan_network()
  ├─ hosts consumed as a generator (O(1) memory)
  ├─ submitted in chunks of max_workers × 4
  └─ ThreadPoolExecutor (adaptive, capped at 256 workers)
          │
          └─ ping(ip)  ←  OS-aware flags, returncode-based detection
```

**Concurrency model:** Futures are submitted in chunks to bound peak memory. A `/16` scan (65,534 hosts) never holds more than `chunk_size` live `Future` objects at once.

---

## Performance

| Network | Hosts | Approx. time* |
|---------|-------|---------------|
| `/24`   | 254   | ~3 s          |
| `/16`   | 65,534 | ~8–12 min    |

\* Depends on network latency and host density. Each ping has a 2 s timeout.

---

## Platform Notes

| OS | IP detection | Ping timeout flag |
|----|-------------|-------------------|
| Linux | `ip addr` → `ifconfig` | `-W 1` (seconds) |
| macOS | `ifconfig` | `-W 500` (milliseconds) |
| Windows | `ipconfig` | `-w 500` (milliseconds) |

---

## Limitations

- ICMP only — hosts with ping blocked by firewall will appear offline
- IPv4 only
- Requires network-level access (see sudo note above)

---

## License

MIT © NVGSpecOps
