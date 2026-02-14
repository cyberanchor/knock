import argparse
import logging
import os
import random
import sys
import time
from scapy.all import IP, TCP, send, conf

# Suppress scapy warnings
conf.verb = 0

# ---- Root check ----
if os.geteuid() != 0:
    print("[!] Error: root privileges required. Run with sudo.")
    sys.exit(1)

# Setup argument parsing
parser = argparse.ArgumentParser(description="TCP Port Knock v5 — single-step redundant auth")
parser.add_argument("server", type=str, help="The IP address of the target server")
parser.add_argument("--sport", type=int, default=53909, help="Source port (default: 53909)")
parser.add_argument("--mss", type=int, default=1234, help="MSS value (default: 1234)")
parser.add_argument("--window", type=int, default=31337, help="TCP window size (default: 31337)")
parser.add_argument("--count", type=int, default=10, help="Number of redundant packets to send (default: 10)")
parser.add_argument("--delay", type=float, default=0.3, help="Delay between packets in seconds (default: 0.3)")
parser.add_argument("--port-range", type=str, default="1024-65535", help="Port range for random targets (default: 1024-65535)")
parser.add_argument("--debug", action="store_true", help="Enable debug output")
args = parser.parse_args()

# Parse port range
port_min, port_max = map(int, args.port_range.split("-"))

# Set up logging
log_level = logging.DEBUG if args.debug else logging.INFO
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("knock")


def generate_ports(count, port_min, port_max):
    """
    Generate random unique destination ports, avoiding common service ports
    """
    ports = set()
    while len(ports) < count:
        p = random.randint(port_min, port_max)
        ports.add(p)
    return list(ports)


def send_knock(server, port, sport, mss, window):
    """
    Send a SYN packet with sport + MSS + window (triple auth)
    """
    seq = random.randint(1, 2**32 - 1)
    packet = IP(dst=server) / TCP(
        dport=port,
        sport=sport,
        flags="S",
        seq=seq,
        window=window,
        options=[("MSS", mss)]
    )

    log.info(f"SYN -> {server}:{port}  sport={sport}  mss={mss}  win={window}  size={len(packet)}b")
    log.debug(f"  IP  dst={server}  ttl={packet[IP].ttl}  id={packet[IP].id}")
    log.debug(f"  TCP dport={port}  sport={sport}  flags=S  seq={seq}")
    log.debug(f"  TCP window={window}  options={packet[TCP].options}")

    try:
        send(packet, verbose=0)
        log.debug(f"  Packet sent OK")
    except PermissionError:
        log.error("Permission denied — raw socket failed")
        sys.exit(1)
    except OSError as e:
        log.error(f"Network error: {e}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Failed to send packet: {e}")
        sys.exit(1)


def knock_burst(server, sport, mss, window, count, delay, port_min, port_max):
    """
    Send N auth packets to random ports for redundancy
    """
    ports = generate_ports(count, port_min, port_max)

    log.info(f"Sending {count} auth packets to random ports ({port_min}-{port_max})")
    log.debug(f"  Target ports: {ports}")

    sent = 0
    for i, port in enumerate(ports, 1):
        send_knock(server, port, sport, mss, window)
        sent += 1
        if i < count:
            time.sleep(delay)

    log.info(f"Burst complete -> {server}  ({sent}/{count} sent, delay={delay}s)")


if __name__ == "__main__":
    log.info(f"Target: {args.server}")
    log.info(f"Auth:   sport={args.sport}  mss={args.mss}  window={args.window}")
    log.info(f"Burst:  {args.count} packets, delay={args.delay}s, range={args.port_range}")
    log.debug(f"Server matches first available: window > mss > sport")
    log.info("Starting knock burst...")

    try:
        knock_burst(
            args.server, args.sport, args.mss, args.window,
            args.count, args.delay, port_min, port_max
        )
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        sys.exit(1)

    log.info("Done.")
