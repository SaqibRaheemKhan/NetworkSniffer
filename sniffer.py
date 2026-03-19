#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           ARCH TECHNOLOGIES - CYBER SECURITY MONTH 1        ║
║              TASK 1: BASIC NETWORK SNIFFER                   ║
╠══════════════════════════════════════════════════════════════╣
║  Developed by : Saqib Raheem Khan                            ║
║  Purpose      : Capture & analyze network packets            ║
║  Language     : Python 3                                     ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import struct
import textwrap
import argparse
import datetime
import sys
import os
import signal

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLOR CODES  (for terminal styling)
# ─────────────────────────────────────────────────────────────────────────────
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

C = Colors()

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
 ███╗   ██╗███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║       ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{C.RESET}
{C.YELLOW}         ╔══════════════════════════════════════════════════════╗
         ║     🔬  ARCH TECHNOLOGIES  |  Cyber Security M-1      ║
         ║     👤  Developed by : Saqib Raheem Khan              ║
         ║     📡  Tool        : Basic Network Sniffer           ║
         ╚══════════════════════════════════════════════════════╝{C.RESET}
"""

# ─────────────────────────────────────────────────────────────────────────────
# PROTOCOL MAPS
# ─────────────────────────────────────────────────────────────────────────────
PROTOCOLS = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    2:   "IGMP",
    89:  "OSPF",
    132: "SCTP",
}

TCP_FLAGS = {
    0x001: "FIN",
    0x002: "SYN",
    0x004: "RST",
    0x008: "PSH",
    0x010: "ACK",
    0x020: "URG",
}

WELL_KNOWN_PORTS = {
    20:  "FTP-DATA",   21:  "FTP",     22:  "SSH",
    23:  "TELNET",     25:  "SMTP",    53:  "DNS",
    67:  "DHCP",       68:  "DHCP",    69:  "TFTP",
    80:  "HTTP",       110: "POP3",    119: "NNTP",
    123: "NTP",        143: "IMAP",    161: "SNMP",
    194: "IRC",        389: "LDAP",    443: "HTTPS",
    445: "SMB",        587: "SMTP-TLS",993: "IMAPS",
    995: "POP3S",      1433:"MSSQL",   3306:"MySQL",
    3389:"RDP",        5432:"PostgreSQL", 6379:"Redis",
    8080:"HTTP-ALT",   8443:"HTTPS-ALT",
}

# ─────────────────────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────────────────────
class Stats:
    def __init__(self):
        self.total     = 0
        self.tcp       = 0
        self.udp       = 0
        self.icmp      = 0
        self.other     = 0
        self.bytes     = 0
        self.start_time = datetime.datetime.now()

    def show(self):
        duration = (datetime.datetime.now() - self.start_time).total_seconds()
        print(f"\n{C.CYAN}{C.BOLD}{'═'*62}")
        print(f"  📊  SESSION STATISTICS")
        print(f"{'═'*62}{C.RESET}")
        print(f"  {C.WHITE}Duration      :{C.RESET} {C.YELLOW}{duration:.1f}s{C.RESET}")
        print(f"  {C.WHITE}Total Packets :{C.RESET} {C.GREEN}{self.total}{C.RESET}")
        print(f"  {C.WHITE}Total Bytes   :{C.RESET} {C.GREEN}{self.bytes:,}{C.RESET}")
        print(f"  {C.WHITE}TCP           :{C.RESET} {C.CYAN}{self.tcp}{C.RESET}")
        print(f"  {C.WHITE}UDP           :{C.RESET} {C.MAGENTA}{self.udp}{C.RESET}")
        print(f"  {C.WHITE}ICMP          :{C.RESET} {C.YELLOW}{self.icmp}{C.RESET}")
        print(f"  {C.WHITE}Other         :{C.RESET} {C.DIM}{self.other}{C.RESET}")
        if duration > 0:
            print(f"  {C.WHITE}Avg Rate      :{C.RESET} {C.GREEN}{self.total/duration:.1f} pkt/s{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}{'═'*62}{C.RESET}\n")

stats = Stats()

# ─────────────────────────────────────────────────────────────────────────────
# HELPER UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def fmt_mac(raw_bytes):
    """Format 6 bytes into a MAC address string."""
    return ":".join(f"{b:02X}" for b in raw_bytes)

def fmt_ip(raw_bytes):
    """Format 4 bytes into an IP address string."""
    return ".".join(str(b) for b in raw_bytes)

def port_service(port):
    """Return known service name for port, else empty string."""
    svc = WELL_KNOWN_PORTS.get(port, "")
    return f" ({svc})" if svc else ""

def get_tcp_flags(flags):
    """Return human-readable TCP flag string."""
    active = [name for bit, name in TCP_FLAGS.items() if flags & bit]
    return "+".join(active) if active else "NONE"

def hex_dump(data, indent=4):
    """Pretty hex dump of raw bytes."""
    pad = " " * indent
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = " ".join(f"{b:02X}" for b in chunk)
        text_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{pad}{C.DIM}{i:04X}  {hex_part:<47}  {text_part}{C.RESET}")
    return "\n".join(lines)

def wrap_data(data, width=60, indent=6):
    """Try to decode payload as ASCII, fall back to hex."""
    pad = " " * indent
    try:
        text = data.decode("utf-8", errors="strict")
        lines = textwrap.wrap(text, width)
        return "\n".join(f"{pad}{C.DIM}{l}{C.RESET}" for l in lines) or f"{pad}{C.DIM}(empty){C.RESET}"
    except Exception:
        return hex_dump(data[:64])  # show first 64 bytes as hex

def separator(char="─", width=62, color=C.DIM):
    print(f"{color}{char * width}{C.RESET}")

def log_to_file(log_file, message):
    """Write plain text (no ANSI) to log file."""
    if log_file:
        clean = message
        for code in vars(Colors).values():
            if isinstance(code, str) and code.startswith("\033"):
                clean = clean.replace(code, "")
        log_file.write(clean + "\n")

# ─────────────────────────────────────────────────────────────────────────────
# ETHERNET FRAME PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_ethernet(raw):
    """
    Ethernet II Frame:
      6 bytes  – Destination MAC
      6 bytes  – Source MAC
      2 bytes  – EtherType
    """
    dst_mac = fmt_mac(raw[:6])
    src_mac = fmt_mac(raw[6:12])
    eth_type = struct.unpack("!H", raw[12:14])[0]
    payload  = raw[14:]
    return dst_mac, src_mac, eth_type, payload

# ─────────────────────────────────────────────────────────────────────────────
# IP HEADER PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_ipv4(data):
    """
    IPv4 Header (minimum 20 bytes):
      4 bits  – Version
      4 bits  – IHL (header length in 32-bit words)
      1 byte  – DSCP/ECN
      2 bytes – Total Length
      2 bytes – Identification
      3 bits  – Flags
      13 bits – Fragment Offset
      1 byte  – TTL
      1 byte  – Protocol
      2 bytes – Header Checksum
      4 bytes – Source IP
      4 bytes – Destination IP
    """
    version_ihl = data[0]
    version     = version_ihl >> 4
    ihl         = (version_ihl & 0xF) * 4   # in bytes
    ttl, proto  = data[8], data[9]
    src_ip      = fmt_ip(data[12:16])
    dst_ip      = fmt_ip(data[16:20])
    total_len   = struct.unpack("!H", data[2:4])[0]
    payload     = data[ihl:]
    return version, ihl, ttl, proto, src_ip, dst_ip, total_len, payload

# ─────────────────────────────────────────────────────────────────────────────
# TCP HEADER PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_tcp(data):
    """
    TCP Header (minimum 20 bytes):
      2 bytes – Source Port
      2 bytes – Destination Port
      4 bytes – Sequence Number
      4 bytes – Acknowledgement Number
      4 bits  – Data Offset (header length in 32-bit words)
      6 bits  – Reserved
      6 bits  – Flags
      2 bytes – Window Size
      2 bytes – Checksum
      2 bytes – Urgent Pointer
    """
    src_port, dst_port = struct.unpack("!HH", data[:4])
    seq_num, ack_num   = struct.unpack("!II", data[4:12])
    offset_flags       = struct.unpack("!H", data[12:14])[0]
    offset             = (offset_flags >> 12) * 4
    flags              = offset_flags & 0x1FF
    window             = struct.unpack("!H", data[14:16])[0]
    payload            = data[offset:]
    return src_port, dst_port, seq_num, ack_num, flags, window, payload

# ─────────────────────────────────────────────────────────────────────────────
# UDP HEADER PARSER
# ─────────────────────────────────────────────────────────────────────────────
def parse_udp(data):
    """
    UDP Header (fixed 8 bytes):
      2 bytes – Source Port
      2 bytes – Destination Port
      2 bytes – Length
      2 bytes – Checksum
    """
    src_port, dst_port, length = struct.unpack("!HHH", data[:6])
    payload = data[8:]
    return src_port, dst_port, length, payload

# ─────────────────────────────────────────────────────────────────────────────
# ICMP PARSER
# ─────────────────────────────────────────────────────────────────────────────
ICMP_TYPES = {
    0: "Echo Reply",         3: "Dest. Unreachable",
    5: "Redirect",           8: "Echo Request",
    11: "Time Exceeded",     12: "Parameter Problem",
}

def parse_icmp(data):
    icmp_type, code = data[0], data[1]
    type_name = ICMP_TYPES.get(icmp_type, f"Type-{icmp_type}")
    return icmp_type, code, type_name

# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
def display_ethernet(pkt_num, ts, dst_mac, src_mac, eth_type):
    print(f"\n{C.GREEN}{C.BOLD}[ PKT #{pkt_num:04d} ]  {ts}  EtherType: 0x{eth_type:04X}{C.RESET}")
    separator()
    print(f"  {C.CYAN}🔗 Ethernet{C.RESET}")
    print(f"     Src MAC : {C.YELLOW}{src_mac}{C.RESET}")
    print(f"     Dst MAC : {C.YELLOW}{dst_mac}{C.RESET}")

def display_ipv4(version, ihl, ttl, proto, src_ip, dst_ip, total_len):
    proto_name = PROTOCOLS.get(proto, f"PROTO-{proto}")
    print(f"  {C.BLUE}🌐 IPv{version}{C.RESET}")
    print(f"     {src_ip}{C.DIM} ──▶{C.RESET}  {dst_ip}")
    print(f"     Protocol : {C.MAGENTA}{proto_name}{C.RESET}  |  TTL: {ttl}  |  Len: {total_len}B  |  Hdr: {ihl}B")

def display_tcp(src_port, dst_port, seq_num, ack_num, flags, window, payload, verbose):
    flag_str = get_tcp_flags(flags)
    src_svc  = port_service(src_port)
    dst_svc  = port_service(dst_port)
    print(f"  {C.CYAN}📡 TCP{C.RESET}")
    print(f"     Port  : {C.GREEN}{src_port}{src_svc}{C.RESET}  ──▶  {C.GREEN}{dst_port}{dst_svc}{C.RESET}")
    print(f"     Flags : {C.YELLOW}{flag_str}{C.RESET}  |  Seq: {seq_num}  |  Ack: {ack_num}  |  Win: {window}")
    if verbose and payload:
        print(f"     {C.DIM}Payload ({len(payload)}B):{C.RESET}")
        print(wrap_data(payload))

def display_udp(src_port, dst_port, length, payload, verbose):
    src_svc = port_service(src_port)
    dst_svc = port_service(dst_port)
    print(f"  {C.MAGENTA}📡 UDP{C.RESET}")
    print(f"     Port  : {C.GREEN}{src_port}{src_svc}{C.RESET}  ──▶  {C.GREEN}{dst_port}{dst_svc}{C.RESET}")
    print(f"     Length: {length}B")
    if verbose and payload:
        print(f"     {C.DIM}Payload ({len(payload)}B):{C.RESET}")
        print(wrap_data(payload))

def display_icmp(icmp_type, code, type_name):
    print(f"  {C.YELLOW}📶 ICMP{C.RESET}")
    print(f"     Type: {icmp_type} ({type_name})  |  Code: {code}")

# ─────────────────────────────────────────────────────────────────────────────
# PACKET FILTER CHECK
# ─────────────────────────────────────────────────────────────────────────────
def passes_filter(proto_num, src_ip, dst_ip, args):
    """Return True if this packet matches the user-specified filter."""
    if args.protocol:
        wanted = args.protocol.upper()
        actual = PROTOCOLS.get(proto_num, "OTHER")
        if actual != wanted:
            return False
    if args.ip:
        if args.ip not in (src_ip, dst_ip):
            return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
# CORE SNIFFER LOOP
# ─────────────────────────────────────────────────────────────────────────────
def sniff(args, log_file=None):
    """Open a raw socket and capture packets."""
    try:
        # AF_PACKET requires Linux; SOCK_RAW captures at link layer
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print(f"\n{C.RED}[!] Permission denied. Run with:  sudo python3 sniffer.py{C.RESET}\n")
        sys.exit(1)
    except AttributeError:
        print(f"\n{C.RED}[!] AF_PACKET is not available on this OS.")
        print(f"    This tool requires Linux. Windows/macOS users see README.{C.RESET}\n")
        sys.exit(1)

    print(f"{C.GREEN}[✔] Socket opened.  Capturing packets… (Ctrl+C to stop){C.RESET}")
    print(f"{C.DIM}    Filter: Protocol={args.protocol or 'ALL'}  IP={args.ip or 'ALL'}  Count={args.count or '∞'}{C.RESET}\n")

    pkt_num = 0

    while True:
        if args.count and pkt_num >= args.count:
            print(f"\n{C.YELLOW}[!] Packet limit ({args.count}) reached.{C.RESET}")
            break

        raw_data, _ = conn.recvfrom(65536)
        stats.bytes += len(raw_data)

        # ── Ethernet ─────────────────────────────────────────────────────────
        try:
            dst_mac, src_mac, eth_type, ip_data = parse_ethernet(raw_data)
        except Exception:
            continue

        # Only process IPv4 (EtherType 0x0800)
        if eth_type != 0x0800:
            continue

        # ── IPv4 ─────────────────────────────────────────────────────────────
        try:
            version, ihl, ttl, proto, src_ip, dst_ip, total_len, transport = parse_ipv4(ip_data)
        except Exception:
            continue

        # Apply filters
        if not passes_filter(proto, src_ip, dst_ip, args):
            continue

        pkt_num += 1
        stats.total += 1
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Build the output string for display + optional logging
        display_ethernet(pkt_num, ts, dst_mac, src_mac, eth_type)
        display_ipv4(version, ihl, ttl, proto, src_ip, dst_ip, total_len)

        # ── Protocol layer ────────────────────────────────────────────────────
        if proto == 6:      # TCP
            stats.tcp += 1
            try:
                sp, dp, seq, ack, flags, win, payload = parse_tcp(transport)
                display_tcp(sp, dp, seq, ack, flags, win, payload, args.verbose)
            except Exception as e:
                print(f"  {C.RED}[!] TCP parse error: {e}{C.RESET}")

        elif proto == 17:   # UDP
            stats.udp += 1
            try:
                sp, dp, length, payload = parse_udp(transport)
                display_udp(sp, dp, length, payload, args.verbose)
            except Exception as e:
                print(f"  {C.RED}[!] UDP parse error: {e}{C.RESET}")

        elif proto == 1:    # ICMP
            stats.icmp += 1
            try:
                t, c, tname = parse_icmp(transport)
                display_icmp(t, c, tname)
            except Exception as e:
                print(f"  {C.RED}[!] ICMP parse error: {e}{C.RESET}")

        else:
            stats.other += 1
            proto_name = PROTOCOLS.get(proto, f"PROTO-{proto}")
            print(f"  {C.DIM}⚙  {proto_name} packet{C.RESET}")

        if log_file:
            log_to_file(log_file, f"PKT #{pkt_num:04d}  {ts}  {src_ip} -> {dst_ip}  Proto={PROTOCOLS.get(proto, proto)}")

    conn.close()

# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL HANDLER
# ─────────────────────────────────────────────────────────────────────────────
def handle_exit(sig, frame):
    print(f"\n{C.YELLOW}[!] Interrupted by user.{C.RESET}")
    stats.show()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────
def build_args():
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description="📡 Basic Network Sniffer — ARCH Technologies | Saqib Raheem Khan",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python3 sniffer.py
  sudo python3 sniffer.py -p TCP
  sudo python3 sniffer.py -p UDP -v
  sudo python3 sniffer.py --ip 192.168.1.1
  sudo python3 sniffer.py -c 50 -o capture.log
  sudo python3 sniffer.py -p ICMP -v -c 10
"""
    )
    parser.add_argument("-p", "--protocol", metavar="PROTO",
                        choices=["TCP", "UDP", "ICMP", "IGMP"],
                        help="Filter by protocol: TCP, UDP, ICMP, IGMP")
    parser.add_argument("--ip", metavar="IP_ADDR",
                        help="Filter packets containing this IP address")
    parser.add_argument("-c", "--count", type=int, metavar="N",
                        help="Stop after capturing N packets")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show packet payload data")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save packet summary to a log file")
    return parser.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)
    args = build_args()

    log_file = None
    if args.output:
        try:
            log_file = open(args.output, "w")
            log_file.write(f"# Network Sniffer Log — {datetime.datetime.now()}\n")
            log_file.write(f"# Developed by: Saqib Raheem Khan | ARCH Technologies\n\n")
            print(f"{C.GREEN}[✔] Logging to: {args.output}{C.RESET}")
        except OSError as e:
            print(f"{C.RED}[!] Cannot open log file: {e}{C.RESET}")
            sys.exit(1)

    try:
        sniff(args, log_file)
    finally:
        if log_file:
            log_file.close()
        stats.show()

if __name__ == "__main__":
    main()
