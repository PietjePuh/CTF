"""Simple TCP port scanner for CTF challenges.

A lightweight, socket-based port scanner for quick enumeration during CTFs.
For EDUCATIONAL and CTF use only. Only scan systems you have permission to test.

DISCLAIMER: Unauthorized port scanning may violate laws and terms of service.
Only use this tool on systems you own or have explicit written permission to test,
such as CTF challenge targets, lab environments, or your own infrastructure.

Usage:
    python port_scanner.py <target> [--ports 1-1024] [--timeout 1.0] [--threads 50]
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

# Common service names for well-known ports
COMMON_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "Web-Console",
    27017: "MongoDB",
}


@dataclass(frozen=True)
class ScanResult:
    port: int
    is_open: bool
    service: str
    banner: str


def parse_port_range(port_str: str) -> list[int]:
    """Parse a port range string into a list of ports.

    Supports formats: '80', '1-1024', '22,80,443', '1-100,443,8080-8090'

    Args:
        port_str: Port range string to parse.

    Returns:
        Sorted list of unique port numbers.

    Raises:
        ValueError: If the port string contains invalid values.
    """
    ports: set[int] = set()

    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port out of range: {part}")
            if start > end:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of range: {port}")
            ports.add(port)

    return sorted(ports)


def scan_port(host: str, port: int, timeout: float = 1.0) -> ScanResult:
    """Scan a single TCP port on the target host.

    Args:
        host: Target hostname or IP address.
        port: Port number to scan.
        timeout: Connection timeout in seconds.

    Returns:
        ScanResult with open/closed status and any banner grabbed.
    """
    service = COMMON_SERVICES.get(port, "unknown")
    banner = ""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                # Try banner grab
                try:
                    sock.settimeout(0.5)
                    sock.sendall(b"\r\n")
                    banner_bytes = sock.recv(1024)
                    banner = banner_bytes.decode("utf-8", errors="replace").strip()[:100]
                except (socket.timeout, OSError):
                    pass

                return ScanResult(port, True, service, banner)

    except (socket.timeout, OSError):
        pass

    return ScanResult(port, False, service, "")


def scan_target(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    max_threads: int = 50,
) -> list[ScanResult]:
    """Scan multiple ports on a target using thread pool.

    Args:
        host: Target hostname or IP address.
        ports: List of ports to scan.
        timeout: Connection timeout per port in seconds.
        max_threads: Maximum concurrent scanning threads.

    Returns:
        List of ScanResult for open ports only, sorted by port number.
    """
    open_ports: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=min(max_threads, len(ports))) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()
            if result.is_open:
                open_ports.append(result)

    return sorted(open_ports, key=lambda r: r.port)


def format_results(host: str, results: list[ScanResult], total_scanned: int) -> str:
    """Format scan results as a readable table."""
    lines = [
        f"Scan results for {host}",
        f"Scanned {total_scanned} ports",
        "",
        f"{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER':<50}",
        "-" * 85,
    ]

    if not results:
        lines.append("No open ports found.")
    else:
        for r in results:
            banner_preview = r.banner[:50] if r.banner else ""
            lines.append(f"{r.port:<10} {'open':<10} {r.service:<15} {banner_preview:<50}")

    lines.append("")
    lines.append(f"Found {len(results)} open port(s)")

    return "\n".join(lines)


def main() -> None:
    """CLI entry point for port scanning."""
    parser = argparse.ArgumentParser(
        description="Simple TCP port scanner for CTF challenges.",
        epilog="DISCLAIMER: Only scan targets you have permission to test.",
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "--ports", "-p",
        default="1-1024",
        help="Port range to scan (default: 1-1024). Examples: '80', '1-1024', '22,80,443'",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Maximum concurrent threads (default: 50)",
    )

    args = parser.parse_args()

    # Resolve hostname
    try:
        ip = socket.gethostbyname(args.target)
        print(f"Scanning {args.target} ({ip})...")
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)

    # Parse ports
    try:
        ports = parse_port_range(args.ports)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Scanning {len(ports)} ports with timeout={args.timeout}s, threads={args.threads}")
    print()

    results = scan_target(ip, ports, args.timeout, args.threads)
    print(format_results(args.target, results, len(ports)))


if __name__ == "__main__":
    main()
