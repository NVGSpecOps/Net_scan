import sys
import socket
import ipaddress
import concurrent.futures
import platform
import subprocess
import re
from itertools import islice

# ── Cached at module load; platform never changes between pings ───────────────
_SYSTEM: str = platform.system().lower()


# =============================================================================
def print_app_name() -> None:
    print("Welcome to NetScan, a network scanner brought to you by >>> NVGSpecOps <<<")


# =============================================================================
def _parse_ifconfig(output: str) -> tuple[str, str] | None:
    """
    Parses `ifconfig` output (macOS / older Linux).
    Netmask may be dotted-decimal or hex (macOS).
    Skips loopback (127.x.x.x).
    """
    for m in re.finditer(r'inet ([\d.]+).*?netmask (0x[\da-f]+|[\d.]+)', output):
        ip, mask = m.group(1), m.group(2)
        if ip.startswith('127.'):
            continue
        if mask.startswith('0x'):
            mask = socket.inet_ntoa(int(mask, 16).to_bytes(4, 'big'))
        return ip, mask
    return None


def _parse_ip_addr(output: str) -> tuple[str, str] | None:
    """
    Parses `ip addr` output (modern Linux) — CIDR notation.
    Skips loopback.
    """
    for m in re.finditer(r'inet ([\d.]+)/(\d+)', output):
        ip, prefix = m.group(1), int(m.group(2))
        if ip.startswith('127.'):
            continue
        # Convert prefix length → dotted-decimal mask via stdlib
        mask = str(ipaddress.IPv4Network(f'0.0.0.0/{prefix}').netmask)
        return ip, mask
    return None


def get_local_ip_and_mask() -> tuple[str, str]:
    """
    Detects the local (non-loopback) IP and subnet mask.
    Strategy: platform-specific command → dummy-connect fallback.
    """
    if _SYSTEM == 'windows':
        try:
            output = subprocess.check_output(
                'ipconfig', universal_newlines=True, timeout=5
            )
            ip_m  = re.search(r'IPv4 Address[. ]*: ([\d.]+)', output)
            msk_m = re.search(r'Subnet Mask[. ]*: ([\d.]+)', output)
            if ip_m and msk_m and not ip_m.group(1).startswith('127.'):
                return ip_m.group(1), msk_m.group(1)
        except Exception:
            pass
    else:
        # Modern Linux prefers `ip addr`; macOS / older Linux use `ifconfig`
        for cmd, parser in [('ip addr', _parse_ip_addr), ('ifconfig', _parse_ifconfig)]:
            try:
                output = subprocess.check_output(
                    cmd, shell=True, universal_newlines=True, timeout=5
                )
                result = parser(output)
                if result:
                    return result
            except Exception:
                continue

    # Last-resort: dummy UDP connect reveals outbound interface IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0], '255.255.255.0'
    except Exception:
        return '192.168.9.0', '255.255.255.0'


# =============================================================================
def mask_to_cidr(mask: str) -> int:
    """
    Converts dotted-decimal mask → CIDR prefix length via stdlib (no manual bit-counting).
    """
    return ipaddress.IPv4Network(f'0.0.0.0/{mask}').prefixlen


# =============================================================================
def parse_network(arg: str | None = None) -> ipaddress.IPv4Network:
    if not arg:
        ip, mask = get_local_ip_and_mask()
        return ipaddress.ip_network(f"{ip}/{mask_to_cidr(mask)}", strict=False)
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)
    if re.fullmatch(r'\d+\.\d+\.\d+', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)
    if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)
    raise ValueError(f"Invalid network format: {arg!r}")


# =============================================================================
def _build_ping_cmd(ip: str) -> list[str]:
    """
    Builds the OS-appropriate ping command.
    Bug fix: macOS -W is in milliseconds; Linux -W is in seconds.
    """
    if _SYSTEM == 'windows':
        return ['ping', '-n', '1', '-w', '500', ip]   # 500 ms
    if _SYSTEM == 'darwin':
        return ['ping', '-c', '1', '-W', '500', ip]   # macOS: ms
    return ['ping', '-c', '1', '-W', '1', ip]         # Linux: seconds


def ping(ip: str) -> str | None:
    """
    Returns ip if host is reachable, None otherwise.
    Uses returncode instead of fragile TTL regex — returncode 0 ↔ host replied.
    stderr discarded (DEVNULL) to avoid buffering unused output.
    """
    try:
        result = subprocess.run(
            _build_ping_cmd(ip),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return ip if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, OSError):
        return None


# =============================================================================
def _chunked(iterable, size: int):
    """Yields successive chunks of `size` items from iterable (lazy)."""
    it = iter(iterable)
    while chunk := list(islice(it, size)):
        yield chunk


def scan_network(network: ipaddress.IPv4Network) -> list[str]:
    """
    Parallel ping-sweep with bounded memory.

    Design:
    - Hosts are consumed lazily via a generator — no upfront list allocation.
    - Futures are submitted in chunks (chunk_size) to cap the number of live
      Future objects at any point (critical for /16 or larger networks).
    - max_workers is adaptive: scales with host count, capped at 256.

    Complexity: O(N) time, O(chunk_size) memory for pending futures.
    """
    total = network.num_addresses - 2  # exclude network + broadcast addresses
    if total <= 0:
        print("Network too small to scan.")
        return []

    max_workers = min(256, max(50, total // 4))
    chunk_size  = max_workers * 4          # limits live Future objects in memory

    print(f"Scanning {network}  ({total} hosts, {max_workers} workers)...")

    online: list[str] = []
    hosts = (str(ip) for ip in network.hosts())   # generator — no full list in RAM

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for chunk in _chunked(hosts, chunk_size):
                futures = {executor.submit(ping, ip): ip for ip in chunk}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        if result := future.result():
                            online.append(result)
                    except Exception:
                        pass
    except KeyboardInterrupt:
        print("\nScan interrupted. Showing partial results...")

    return online


# =============================================================================
def show_help() -> None:
    print(
        "Usage: netscan [network]\n"
        "Scan a network for online devices.\n\n"
        "Options:\n"
        "  -h, --help      Show this help message\n\n"
        "Examples:\n"
        "  netscan                  # Auto-detect and scan local network\n"
        "  netscan 192.168.9.0      # Scan 192.168.9.0/24\n"
        "  netscan 192.168.9        # Scan 192.168.9.0/24\n"
        "  netscan 192.168.9.0/24   # Scan 192.168.9.0/24\n"
        "  netscan 10.0.0.0/16      # Scan 10.0.0.0/16"
    )


# =============================================================================
def main() -> None:
    print_app_name()   # Bug fix: was defined but never called

    args = sys.argv[1:]

    if not args:
        network_arg = None
    elif args[0] in ('-h', '--help'):
        show_help()
        return
    elif len(args) == 1:
        network_arg = args[0]
    else:
        print("Error: too many arguments.")
        show_help()
        return

    try:
        network = parse_network(network_arg)
    except ValueError as e:
        print(f"Error: {e}")
        show_help()
        return

    try:
        online = scan_network(network)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return

    print(f"\n{len(online)} host(s) online:")
    for host in sorted(online, key=lambda x: tuple(map(int, x.split('.')))):
        print(f"  {host}")


if __name__ == '__main__':
    main()