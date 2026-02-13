# knock

**Simple single-step TCP SYN port knocking with nftables**

A stealth firewall that authenticates clients via hidden fields in TCP SYN packets (window size, MSS option, source port). 
The server runs a default-drop policy with zero network-visible responses — no RST, no ICMP, no open ports. 
After a successful knock, the client IP gains full access for 24 hours.

---

## How It Works

```
Client                                          Server (nftables)
  │                                               │
  │  SYN to random port                           │
  │  sport=53909, mss=1234, window=31337          │
  │─────────────────────────────────────────────► │
  │              (×10 packets, 0.3s apart)        │
  │                                               │
  │  First packet arrives                         │
  │  ─► nftables matches window=31337             │
  │  ─► adds client IP to @authed set (24h)       │
  │  ─► drops the SYN (no response)               │
  │                                               │
  │  Remaining packets arrive                     │
  │  ─► IP already in @authed → silent drop       │
  │                                               │
  │  Client connects normally                     │
  │  SSH / HTTPS / any port                       │
  │─────────────────────────────────────────────► │
  │◄──────────────────────────────────────────────│
  │              (connection established)         │
```

### Authentication Fields

Each knock packet carries three independent credentials in the TCP SYN header. The server accepts whichever survives the network path:

| Field | Offset | Value | Survives NAT | Survives MSS Clamping |
|-------|--------|-------|--------------|-----------------------|
| **Window Size** | TCP byte 14-15 | `31337` (0x7A69) | ✅ Yes | ✅ Yes |
| **MSS Option** | TCP option kind=2 | `1234` (0x04D2) | ✅ Yes | ⚠️ Sometimes |
| **Source Port** | TCP byte 0-1 | `53909` (0xD295) | ❌ Rewritten | ✅ Yes |

**Priority:** window → MSS → source port (first match wins)

### Packet Hex Layout

```
Ethernet Frame → IP Header → TCP Header (what nftables inspects)
                              ┌─────────────────────────────────────┐
TCP Header:                   │ Offset  Field          Value        │
                              │ ──────  ─────          ─────        │
                              │ 0-1     Source Port    0xD295 (53909)
                              │ 2-3     Dest Port      (random)     │
                              │ 4-7     Sequence       (random)     │
                              │ 8-11    Ack Number     0x00000000   │
                              │ 12      Data Offset    0x60 (6 DW)  │
                              │ 13      Flags          0x02 (SYN)   │
                              │ 14-15   Window Size    0x7A69 (31337)
                              │ 16-17   Checksum       (computed)   │
                              │ 18-19   Urgent Ptr     0x0000       │
                              ├─────────────────────────────────────┤
TCP Options:                  │ 20      Kind           0x02 (MSS)   │
                              │ 21      Length          0x04        │
                              │ 22-23   MSS Value      0x04D2 (1234)│
                              └─────────────────────────────────────┘
Total: 24 bytes TCP header (20 base + 4 MSS option)
       20 bytes IP header
       ──────────
       44 bytes on the wire
```

---

## Quick Start

### Server (AlmaLinux 9 / RHEL 9)

```bash
# 1. Install nftables (usually pre-installed)
sudo dnf install -y nftables

# 2. Disable ICMP echo (stealth)
echo 'net.ipv4.icmp_echo_ignore_all = 1' | sudo tee /etc/sysctl.d/99-stealth.conf
sudo sysctl --system

# 3. Deploy knock rules
sudo cp knock.nft /etc/nftables/knock.nft
sudo nft -c -f /etc/nftables/knock.nft    # syntax check (dry-run)
sudo nft -f /etc/nftables/knock.nft        # apply

# 4. Verify
sudo nft list table inet knock_filter
```

### Client

```bash
# Install scapy
pip install scapy

# Run knock (requires root for raw sockets)
sudo python3 knock.py --debug IP

# Then connect normally
ssh user@IP
```

---

## Client Usage

```
usage: knock.py [-h] [--sport N] [--mss N] [--window N]
                [--count N] [--delay SEC] [--port-range MIN-MAX]
                [--debug] server

TCP Port Knock v5 — single-step redundant auth
```

### Examples

```bash
# Basic knock (10 packets, default credentials)
sudo python3 knock.py IP

# Debug mode (show all packet details)
sudo python3 knock.py IP --debug

# High-loss network (send 20 packets, slower)
sudo python3 knock.py IP --count 20 --delay 0.5

# Custom credentials (must match server knock.nft)
sudo python3 knock.py IP --sport 41337 --mss 4321 --window 1337

# Restrict target port range
sudo python3 knock.py IP --port-range 10000-60000
```

### Parameters

| Flag | Default | Description |
|------|---------|-------------|
| `server` | — | Target server IP (required) |
| `--sport` | `53909` | TCP source port |
| `--mss` | `1234` | TCP MSS option value |
| `--window` | `31337` | TCP window size |
| `--count` | `10` | Number of redundant packets |
| `--delay` | `0.3` | Seconds between packets |
| `--port-range` | `1024-65535` | Random destination port range |
| `--debug` | off | Verbose packet-level output |

---

## Server: nftables Commands

### Apply Rules

```bash
# Syntax check (safe, no changes applied)
sudo nft -c -f /etc/nftables/knock.nft

# Apply rules
sudo nft -f /etc/nftables/knock.nft

# Atomic replace (delete old table, load new)
sudo nft delete table inet knock_filter
sudo nft -f /etc/nftables/knock.nft
```

### Inspect State

```bash
# Full ruleset with counters
sudo nft list table inet knock_filter

# Rules with handle numbers (needed for delete/insert)
sudo nft -a list chain inet knock_filter input

# Authenticated IPs (with remaining TTL)
sudo nft list set inet knock_filter authed

# Banned IPs
sudo nft list set inet knock_filter ban
```

### Manage IPs at Runtime

```bash
# Grant access to an IP for 24 hours
sudo nft add element inet knock_filter authed { 198.51.100.5 timeout 24h }

# Grant access for 7 days
sudo nft add element inet knock_filter authed { 198.51.100.5 timeout 7d }

# Revoke access
sudo nft delete element inet knock_filter authed { 198.51.100.5 }

# Ban an IP for 1 hour
sudo nft add element inet knock_filter ban { IP timeout 1h }

# Unban an IP
sudo nft delete element inet knock_filter ban { IP }

# Emergency: whitelist current SSH session
MYIP=$(echo $SSH_CLIENT | awk '{print $1}')
sudo nft add element inet knock_filter authed { $MYIP timeout 24h }

# Full reset for a specific IP (remove from all sets)
sudo nft delete element inet knock_filter authed { IP } 2>/dev/null
sudo nft delete element inet knock_filter ban     { IP } 2>/dev/null

# Reset all counters
sudo nft reset counters table inet knock_filter
```

### Persistence

```bash
# Save knock table to a standalone file (survives reboot)
sudo nft list table inet knock_filter > /etc/nftables/knock.nft

# Add include to main nftables config
echo 'include "/etc/nftables/knock.nft"' | sudo tee -a /etc/sysconfig/nftables.conf

# Or save entire ruleset (if no Podman/other managed tables)
sudo nft list ruleset > /etc/sysconfig/nftables.conf
```

> **Note:** Podman/netavark manages its own `ip nat` and `ip filter` tables.
> Use the `include` method to avoid conflicts on reboot.

---

## Traffic Analysis with tcpdump

### Capture Knock Packets (match by window, MSS, or source port)

```bash
sudo tcpdump -i eth0 -nn -vvv 'tcp[tcpflags] & tcp-syn != 0 and (src port 53909 or tcp[14:2] = 0x7a69 or tcp[20:4] = 0x020404d2)'
```

**Filter breakdown:**

| Expression | Matches |
|-----------|---------|
| `tcp[tcpflags] & tcp-syn != 0` | SYN packets only |
| `src port 53909` | Source port = 53909 |
| `tcp[14:2] = 0x7a69` | TCP window = 31337 at header offset 14 |
| `tcp[20:4] = 0x020404d2` | MSS option: kind=02, len=04, value=04D2 (1234) |

### Capture All SYN to Server

```bash
sudo tcpdump -i eth0 -nn -vvv 'tcp[tcpflags] & tcp-syn != 0 and dst host IP'
```

### Capture with Hex Dump (deep inspection)

```bash
sudo tcpdump -i eth0 -nn -XX -vvv 'tcp[14:2] = 0x7a69' | head -100
```

---

## Debugging & Audit

### Live Log Monitoring

```bash
# Watch knock events in real-time
sudo journalctl -kf | grep -E 'NFT\|KNOCK|NFT\|ALLOW'

# Filter by event type
sudo journalctl -kf | grep 'EV=auth_win'    # successful window auth
sudo journalctl -kf | grep 'EV=auth_mss'    # successful MSS auth
sudo journalctl -kf | grep 'EV=auth_sport'  # successful sport auth
sudo journalctl -kf | grep 'EV=ban_drop'    # banned IP dropped
sudo journalctl -kf | grep 'EV=unban'       # IP unbanned via knock
```

### Log Event Reference

| Event | Meaning |
|-------|---------|
| `EV=auth_win` | New IP authenticated via TCP window |
| `EV=auth_mss` | New IP authenticated via MSS option |
| `EV=auth_sport` | New IP authenticated via source port |
| `EV=unban_win` | Banned IP unbanned via window knock |
| `EV=unban_mss` | Banned IP unbanned via MSS knock |
| `EV=unban_sport` | Banned IP unbanned via sport knock |
| `EV=ban_drop` | Packet from banned IP silently dropped |
| `EV=authed_new` | Authed IP opened new connection |

### nftables Packet Tracing

```bash
# Terminal 1: start trace monitor
sudo nft monitor trace

# Terminal 2: inject trace rule (matches all TCP SYN)
sudo nft insert rule inet knock_filter input \
  tcp flags syn meta nftrace set 1

# After debugging: remove trace rule
sudo nft -a list chain inet knock_filter input | grep nftrace
sudo nft delete rule inet knock_filter input handle <N>
```

### Verify Services Are Reachable After Knock

```bash
# From client, after running knock.py:
nc -vz IP 22      # SSH
```

### Connectivity Audit

```bash
# Server-side: confirm services are listening
sudo ss -lntp | grep -E ':(22|443)\b'

# Server-side: check Podman DNAT rules
sudo nft list chain ip nat NETAVARK-HOSTPORT-DNAT 2>/dev/null

# Server-side: verify forward chain counters
sudo nft -a list chain inet knock_filter forward
```

---

## Safe Deployment via SSH

When applying rules over SSH, use a timed rollback to avoid lockout:

```bash
# 1. Backup current rules
sudo nft list ruleset > /root/nft_backup_$(date +%Y%m%d_%H%M%S).conf

# 2. Schedule automatic rollback in 60 seconds
( sleep 60 && nft -f /root/nft_backup_*.conf ) &
ROLLBACK_PID=$!

# 3. Apply new rules
sudo nft delete table inet knock_filter 2>/dev/null
sudo nft -f /etc/nftables/knock.nft

# 4. Test access — if SSH still works, cancel rollback:
kill $ROLLBACK_PID 2>/dev/null

# 5. If SSH dies, rollback fires automatically after 60s
```
