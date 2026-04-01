#!/usr/bin/env python3

"""
/*******************************************************************************
*                                                                              *
*                        Brno University of Technology                         *
*                      Faculty of Information Technology                       *
*                                                                              *
*                        Počítačové komunikace a sítě                          *
*                                                                              *
*            Author: Hugo Bohacsek [xbohach00 AT stud.fit.vutbr.cz]            *
*                                   Brno 2026                                  *
*                                                                              *
*       Implementation of the 1st project L4 scanner target for testing        *
*                                                                              *
*******************************************************************************/
"""

import os
import sys
import json
import time
import random
import select
import signal
import socket
import struct
import threading
import subprocess

from datetime import datetime
from collections import defaultdict
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse, urlencode
from http.server import HTTPServer, BaseHTTPRequestHandler

# =============================================================
# Configuration
# =============================================================

WEB_PORT = 8888
TARGET_HOST = "147.229.192.165"
INTERFACE = "ens1"
VPN_INTERFACE = "tun0"
VPN_ADDR = "vpnfit.ipk.marek.cat"
REFRESH_INTERVAL = 450
IPTABLES_BACKUP = "/tmp/iptables_backup.rules"
IP6TABLES_BACKUP = "/tmp/ip6tables_backup.rules"
MAX_LOG_ENTRIES = 200
MAX_LOG_WEB = MAX_LOG_ENTRIES // 2

# Guaranteed ports (fixed, never change)
# TCP
G_TCP_OPEN      = [9001, 9002, 9003]     # Always open
G_TCP_CLOSED    = [9011, 9012, 9013]     # Always closed (no listener, no rule)
G_TCP_FILTERED  = [9021, 9022, 9023]     # Always filtered (iptables DROP)

# UDP
G_UDP_OPEN      = [9031, 9032, 9033]     # Always open
G_UDP_CLOSED    = [9041, 9042, 9043]     # Always closed (no listener, no rule)
G_UDP_FILTERED  = [9051, 9052, 9053]     # Always filtered (iptables DROP)

# Combined test ports (for mixed TCP+UDP scenarios)
G_COMBO_TCP_OPEN     = [9061, 9062, 9063]
G_COMBO_TCP_CLOSED   = [9064, 9065]
G_COMBO_UDP_OPEN     = [9071, 9072]
G_COMBO_UDP_CLOSED   = [9073, 9074]

ALL_GUARANTEED = (
    G_TCP_OPEN + G_TCP_CLOSED + G_TCP_FILTERED +
    G_UDP_OPEN + G_UDP_CLOSED + G_UDP_FILTERED +
    G_COMBO_TCP_OPEN + G_COMBO_TCP_CLOSED +
    G_COMBO_UDP_OPEN + G_COMBO_UDP_CLOSED
)

# Randomized ports
RAND_PORT_START = 10000
RAND_PORT_END   = 10250
NUM_OPEN_TCP     = 25
NUM_OPEN_UDP     = 15
NUM_FILTERED_TCP = 20
NUM_FILTERED_UDP = 10

# =============================================================
# Global state
# =============================================================

state = {
    # Guaranteed
    "g_tcp_open": G_TCP_OPEN,
    "g_tcp_closed": G_TCP_CLOSED,
    "g_tcp_filtered": G_TCP_FILTERED,
    "g_udp_open": G_UDP_OPEN,
    "g_udp_closed": G_UDP_CLOSED,
    "g_udp_filtered": G_UDP_FILTERED,
    "g_combo_tcp_open": G_COMBO_TCP_OPEN,
    "g_combo_tcp_closed": G_COMBO_TCP_CLOSED,
    "g_combo_udp_open": G_COMBO_UDP_OPEN,
    "g_combo_udp_closed": G_COMBO_UDP_CLOSED,
    # Randomized
    "tcp_open": [],
    "tcp_closed": [],
    "tcp_filtered": [],
    "udp_open": [],
    "udp_closed": [],
    "udp_filtered": [],
    "last_refresh": None,
    "next_refresh": None,
    "backup_saved": False,
}

conn_log = []
ip_summary = defaultdict(lambda: {
    "first_seen": None,
    "last_seen": None,
    "tcp_count": 0,
    "udp_count": 0,
    "ports_scanned": set(),
})

listener_sockets = []
listener_stop = threading.Event()
state_lock = threading.Lock()
log_lock = threading.Lock()
stop_event = threading.Event()
cleanup_lock = threading.Lock()
cleanup_done = False


# =============================================================
# Backup / Restore iptables
# =============================================================

def backup_iptables():
    subprocess.run(["iptables-save"], stdout=open(IPTABLES_BACKUP, "w"), check=True)
    subprocess.run(["ip6tables-save"], stdout=open(IP6TABLES_BACKUP, "w"), check=True)
    state["backup_saved"] = True
    print(f"[+] iptables backed up to {IPTABLES_BACKUP}")
    print(f"[+] ip6tables backed up to {IP6TABLES_BACKUP}")


def restore_iptables():
    if not state["backup_saved"]:
        return
    try:
        subprocess.run(["iptables-restore"], stdin=open(IPTABLES_BACKUP, "r"), check=True)
        subprocess.run(["ip6tables-restore"], stdin=open(IP6TABLES_BACKUP, "r"), check=True)
        print("[+] ip(6)tables restored from backup")
    except Exception as e:
        print(f"[!] Failed to restore iptables: {e}")
        print(f"[!] Manual restore: iptables-restore < {IPTABLES_BACKUP}")


# =============================================================
# Port listeners - pure Python sockets for reliability
# =============================================================

def close_listeners():
    global listener_sockets
    listener_stop.set()
    for s in listener_sockets:
        try:
            s.close()
        except Exception as e:
            print(f"[ERROR] close listeners: {e}")
    listener_sockets = []


def bind_listeners(tcp_ports, udp_ports):
    """Bind sockets for given ports. Returns list of sockets."""
    sockets = []
    failed_tcp = 0
    failed_udp = 0
    failed_tcp_v6 = 0
    failed_udp_v6 = 0

    for port in tcp_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(5)
            s.setblocking(False)
            sockets.append(s)
        except OSError as e:
            failed_tcp += 1
            print(f"    [!] TCP bind failed port {port}: {e}")

        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Keep IPv6 and IPv4 sockets separate for predictable dual-stack behavior.
            if hasattr(socket, "IPV6_V6ONLY"):
                s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s6.bind(("::", port))
            s6.listen(5)
            s6.setblocking(False)
            sockets.append(s6)
        except OSError as e:
            failed_tcp_v6 += 1
            print(f"    [!] TCPv6 bind failed port {port}: {e}")

    for port in udp_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.setblocking(False)
            sockets.append(s)
        except OSError as e:
            failed_udp += 1
            print(f"    [!] UDP bind failed port {port}: {e}")

        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "IPV6_V6ONLY"):
                s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s6.bind(("::", port))
            s6.setblocking(False)
            sockets.append(s6)
        except OSError as e:
            failed_udp_v6 += 1
            print(f"    [!] UDPv6 bind failed port {port}: {e}")

    if failed_tcp:
        print(f"    [!] Failed to bind {failed_tcp} TCP ports")
    if failed_tcp_v6:
        print(f"    [!] Failed to bind {failed_tcp_v6} TCPv6 ports")
    if failed_udp:
        print(f"    [!] Failed to bind {failed_udp} UDP ports")
    if failed_udp_v6:
        print(f"    [!] Failed to bind {failed_udp_v6} UDPv6 ports")

    return sockets


def start_listeners(tcp_ports, udp_ports):
    """Start listener thread handling all open ports."""
    global listener_sockets
    close_listeners()
    listener_stop.clear()

    listener_sockets = bind_listeners(tcp_ports, udp_ports)

    t = threading.Thread(target=listener_loop, args=(listener_sockets,), daemon=True)
    t.start()


def listener_loop(sockets):
    while not listener_stop.is_set() and not stop_event.is_set():
        if not sockets:
            time.sleep(0.5)
            continue
        try:
            readable, _, _ = select.select(sockets, [], [], 0.5)
        except (ValueError, OSError):
            break
        for s in readable:
            try:
                if s.type == socket.SOCK_STREAM:
                    conn, addr = s.accept()
                    conn.close()
                else:
                    s.recvfrom(1024)
            except:
                pass # Spams logs console when ports reroll


# =============================================================
# Firewall rules
# =============================================================

def clear_all_test_rules():
    """Remove all L4SCAN_TEST iptables rules."""
    all_ports = list(range(9000, 9100)) + list(range(RAND_PORT_START, RAND_PORT_END))
    for port in all_ports:
        for proto in ["tcp", "udp"]:
            delete_drop_rule(port, proto)
        delete_udp_reject_rule(port)


def delete_drop_rule(port, proto):
    for table_cmd in ["iptables", "ip6tables"]:
        subprocess.run(
            [table_cmd, "-D", "INPUT", "-p", proto, "--dport", str(port),
             "-j", "DROP", "-m", "comment", "--comment", "L4SCAN_TEST"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )


def add_drop_rule(port, proto):
    for table_cmd in ["iptables", "ip6tables"]:
        subprocess.run(
            [table_cmd, "-A", "INPUT", "-p", proto, "--dport", str(port),
             "-j", "DROP", "-m", "comment", "--comment", "L4SCAN_TEST"],
            capture_output=True, check=True
        )


def add_udp_reject_rule(port):
    subprocess.run(
        ["iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port),
         "-j", "REJECT", "--reject-with", "icmp-port-unreachable",
         "-m", "comment", "--comment", "L4SCAN_TEST"],
        capture_output=True, check=True
    )
    subprocess.run(
        ["ip6tables", "-A", "INPUT", "-p", "udp", "--dport", str(port),
         "-j", "REJECT", "--reject-with", "icmp6-port-unreachable",
         "-m", "comment", "--comment", "L4SCAN_TEST"],
        capture_output=True, check=True
    )


def delete_udp_reject_rule(port):
    subprocess.run(
        ["iptables", "-D", "INPUT", "-p", "udp", "--dport", str(port),
         "-j", "REJECT", "--reject-with", "icmp-port-unreachable",
         "-m", "comment", "--comment", "L4SCAN_TEST"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    subprocess.run(
        ["ip6tables", "-D", "INPUT", "-p", "udp", "--dport", str(port),
         "-j", "REJECT", "--reject-with", "icmp6-port-unreachable",
         "-m", "comment", "--comment", "L4SCAN_TEST"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


# =============================================================
# Setup guaranteed ports
# =============================================================

def setup_guaranteed():
    """Set up guaranteed port states."""
    print("[*] Setting up guaranteed ports...")

    # Filtered = ip(6)tables DROP
    for port in G_TCP_FILTERED:
        add_drop_rule(port, "tcp")
    for port in G_UDP_FILTERED:
        add_drop_rule(port, "udp")

    # Closed UDP = explicit ICMP port-unreachable for stable scanner behavior.
    for port in G_UDP_CLOSED + G_COMBO_UDP_CLOSED:
        add_udp_reject_rule(port) # Could make it random

    print(f"    TCP open:     {G_TCP_OPEN}")
    print(f"    TCP closed:   {G_TCP_CLOSED}")
    print(f"    TCP filtered: {G_TCP_FILTERED}")
    print(f"    UDP open:     {G_UDP_OPEN}")
    print(f"    UDP closed:   {G_UDP_CLOSED}")
    print(f"    UDP filtered: {G_UDP_FILTERED}")
    print(f"    Combo TCP open:   {G_COMBO_TCP_OPEN}")
    print(f"    Combo TCP closed: {G_COMBO_TCP_CLOSED}")
    print(f"    Combo UDP open:   {G_COMBO_UDP_OPEN}")
    print(f"    Combo UDP closed: {G_COMBO_UDP_CLOSED}")
    print("[+] Guaranteed ports configured")


# =============================================================
# Port randomization
# =============================================================

def randomize_ports():
    print(f"\n[*] Randomizing ports at {datetime.now().strftime('%H:%M:%S')}...")

    # Close randomized listeners (keep guaranteed alive via separate list)
    close_listeners()

    # Clear only randomized range rules
    for port in range(RAND_PORT_START, RAND_PORT_END):
        for proto in ["tcp", "udp"]:
            delete_drop_rule(port, proto)
        delete_udp_reject_rule(port)

    all_ports = list(range(RAND_PORT_START, RAND_PORT_END))
    random.shuffle(all_ports)

    idx = 0
    tcp_open = sorted(all_ports[idx:idx + NUM_OPEN_TCP])
    idx += NUM_OPEN_TCP
    tcp_filtered = sorted(all_ports[idx:idx + NUM_FILTERED_TCP])
    idx += NUM_FILTERED_TCP
    udp_open = sorted(all_ports[idx:idx + NUM_OPEN_UDP])
    idx += NUM_OPEN_UDP
    udp_filtered = sorted(all_ports[idx:idx + NUM_FILTERED_UDP])
    idx += NUM_FILTERED_UDP

    tcp_used = set(tcp_open + tcp_filtered)
    udp_used = set(udp_open + udp_filtered)
    tcp_closed = sorted([p for p in range(RAND_PORT_START, RAND_PORT_END) if p not in tcp_used])
    udp_closed = sorted([p for p in range(RAND_PORT_START, RAND_PORT_END) if p not in udp_used])

    # Combine guaranteed + randomized listeners
    all_tcp_listen = G_TCP_OPEN + G_COMBO_TCP_OPEN + tcp_open
    all_udp_listen = G_UDP_OPEN + G_COMBO_UDP_OPEN + udp_open
    start_listeners(all_tcp_listen, all_udp_listen)

    print(f"    Rand TCP open:     {len(tcp_open)} ports")
    print(f"    Rand UDP open:     {len(udp_open)} ports")

    for port in tcp_filtered:
        add_drop_rule(port, "tcp")
    print(f"    Rand TCP filtered: {len(tcp_filtered)} ports")

    for port in udp_filtered:
        add_drop_rule(port, "udp")
    print(f"    Rand UDP filtered: {len(udp_filtered)} ports")

    for port in udp_closed:
        add_udp_reject_rule(port)
    print(f"    Rand UDP closed(reject): {len(udp_closed)} ports")

    print(f"    Rand TCP closed:   {len(tcp_closed)} ports")
    print(f"    Rand UDP closed:   {len(udp_closed)} ports")

    now = datetime.now()
    with state_lock:
        state["tcp_open"] = tcp_open
        state["tcp_closed"] = tcp_closed
        state["tcp_filtered"] = tcp_filtered
        state["udp_open"] = udp_open
        state["udp_closed"] = udp_closed
        state["udp_filtered"] = udp_filtered
        state["last_refresh"] = now.strftime("%Y-%m-%d %H:%M:%S")
        state["next_refresh"] = (
            datetime.fromtimestamp(now.timestamp() + REFRESH_INTERVAL)
        ).strftime("%Y-%m-%d %H:%M:%S")

    print(f"[+] Ports randomized. Next refresh at {state['next_refresh']}")


# =============================================================
# Packet sniffer
# =============================================================

def log_packet(src_ip, src_port, dst_port, proto, flags=""):
    now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    entry = {
        "time": now,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "flags": flags,
    }
    with log_lock:
        conn_log.append(entry)
        if len(conn_log) > MAX_LOG_ENTRIES:
            del conn_log[:len(conn_log) - MAX_LOG_ENTRIES]
        summary = ip_summary[src_ip]
        if summary["first_seen"] is None:
            summary["first_seen"] = now
        summary["last_seen"] = now
        if proto == "TCP":
            summary["tcp_count"] += 1
        else:
            summary["udp_count"] += 1
        summary["ports_scanned"].add(dst_port)
    print(f"    [{now}] {src_ip}:{src_port} -> :{dst_port} {proto} {flags}")


def parse_tcp_flags(flags_byte):
    names = []
    if flags_byte & 0x02: names.append("SYN")
    if flags_byte & 0x10: names.append("ACK")
    if flags_byte & 0x04: names.append("RST")
    if flags_byte & 0x01: names.append("FIN")
    if flags_byte & 0x08: names.append("PSH")
    return ",".join(names) if names else f"0x{flags_byte:02x}"


def sniffer_thread():
    try:
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, INTERFACE.encode())
        sock_tcp.settimeout(0.5)
    except Exception as e:
        print(f"[!] Sniffer TCP setup failed: {e}")
        return

    try:
        sock_udp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, INTERFACE.encode())
        sock_udp.settimeout(0.5)
    except Exception as e:
        print(f"[!] Sniffer UDP setup failed: {e}")
        sock_udp = None

    print("[+] Packet sniffer started")
    sniffer_socks = [sock_tcp]
    if sock_udp:
        sniffer_socks.append(sock_udp)

    while not stop_event.is_set():
        try:
            readable, _, _ = select.select(sniffer_socks, [], [], 0.5)
        except Exception as e:
            print(f"[ERROR] sniffer1: {e}")
        for sock in readable:
            try:
                data, _ = sock.recvfrom(65535)
                if len(data) < 20:
                    continue
                ihl = (data[0] & 0x0f) * 4
                protocol = data[9]
                src_ip = socket.inet_ntoa(data[12:16])
                if protocol == 6 and len(data) >= ihl + 14:
                    src_port = struct.unpack("!H", data[ihl:ihl+2])[0]
                    dst_port = struct.unpack("!H", data[ihl+2:ihl+4])[0]
                    flags = data[ihl + 13]
                    if (9000 <= dst_port < 9100 or RAND_PORT_START <= dst_port < RAND_PORT_END):
                        if (flags & 0x02) and not (flags & 0x10):
                            log_packet(src_ip, src_port, dst_port, "TCP", parse_tcp_flags(flags))
                elif protocol == 17 and len(data) >= ihl + 8:
                    src_port = struct.unpack("!H", data[ihl:ihl+2])[0]
                    dst_port = struct.unpack("!H", data[ihl+2:ihl+4])[0]
                    if (9000 <= dst_port < 9100 or RAND_PORT_START <= dst_port < RAND_PORT_END):
                        log_packet(src_ip, src_port, dst_port, "UDP", "")
            except Exception as e:
                print(f"[ERROR] sniffer2: {e}")
    sock_tcp.close()
    if sock_udp:
        sock_udp.close()


# =============================================================
# Refresh loop
# =============================================================

def refresh_loop():
    while not stop_event.is_set():
        randomize_ports()
        stop_event.wait(REFRESH_INTERVAL)


# =============================================================
# Test scenario definitions
# =============================================================

def build_test_scenarios(target_host):
    """Build test commands matching last year's automated test patterns.
    Each group has a 'location': 'remote' (needs test server) or 'local' (run on scanner machine)."""
    T = target_host
    I = INTERFACE

    scenarios = []

    # ==========================================================
    # REMOTE TESTS - require this test server
    # ==========================================================

    # --- IPv4 TCP single port tests ---
    scenarios.append({
        "category": "IPv4 TCP - Single Ports",
        "location": "remote",
        "tests": [
            {
                "name": "test_lan[IPv4-single open TCP port]",
                "desc": "Single open TCP port",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_OPEN[0]} {T}",
                "expect": f"{T} {G_TCP_OPEN[0]} tcp open",
            },
            {
                "name": "test_lan[IPv4-single closed TCP port]",
                "desc": "Single closed TCP port",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_CLOSED[0]} {T}",
                "expect": f"{T} {G_TCP_CLOSED[0]} tcp closed",
            },
            {
                "name": "test_lan[IPv4-single filtered TCP port]",
                "desc": "Single filtered TCP port",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_FILTERED[0]} {T}",
                "expect": f"{T} {G_TCP_FILTERED[0]} tcp filtered",
            },
        ]
    })

    # --- IPv4 TCP sequence/range tests ---
    scenarios.append({
        "category": "IPv4 TCP - Sequences & Ranges",
        "location": "remote",
        "tests": [
            {
                "name": "test_lan[IPv4-sequence of 2 closed TCP ports]",
                "desc": "Two closed TCP ports",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_CLOSED[0]},{G_TCP_CLOSED[1]} {T}",
                "expect": f"Both ports tcp closed",
            },
            {
                "name": "test_lan[IPv4-sequence of 2 open TCP ports]",
                "desc": "Two open TCP ports",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_OPEN[0]},{G_TCP_OPEN[1]} {T}",
                "expect": f"Both ports tcp open",
            },
            {
                "name": "test_lan[IPv4-sequence of 2 open and closed TCP ports]",
                "desc": "One open + one closed TCP port",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_OPEN[0]},{G_TCP_CLOSED[0]} {T}",
                "expect": f"{G_TCP_OPEN[0]} tcp open, {G_TCP_CLOSED[0]} tcp closed",
            },
            {
                "name": "test_lan[IPv4-range of 3 open and closed TCP ports]",
                "desc": "Range with mixed open/closed TCP",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_OPEN[0]}-{G_TCP_CLOSED[2]} {T}",
                "expect": f"Open: {G_TCP_OPEN}, Closed: {G_TCP_CLOSED}",
            },
        ]
    })

    # --- IPv4 UDP single port tests ---
    scenarios.append({
        "category": "IPv4 UDP - Single Ports",
        "location": "remote",
        "tests": [
            {
                "name": "test_lan[IPv4-single open UDP port]",
                "desc": "Single open UDP port",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -u {G_UDP_OPEN[0]} {T}",
                "expect": f"{T} {G_UDP_OPEN[0]} udp open",
            },
            {
                "name": "test_lan[IPv4-single closed UDP port]",
                "desc": "Single closed UDP port",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -u {G_UDP_CLOSED[0]} {T}",
                "expect": f"{T} {G_UDP_CLOSED[0]} udp closed",
            },
            {
                "name": "test_lan[IPv4-single filtered UDP port]",
                "desc": "Single filtered UDP port",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -u {G_UDP_FILTERED[0]} {T}",
                "expect": f"{T} {G_UDP_FILTERED[0]} udp open (no ICMP = open per spec)",
            },
        ]
    })

    # --- IPv4 UDP sequence/range tests ---
    scenarios.append({
        "category": "IPv4 UDP - Sequences & Ranges",
        "location": "remote",
        "tests": [
            {
                "name": "test_lan[IPv4-sequence of 2 closed UDP ports]",
                "desc": "Two closed UDP ports",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -u {G_UDP_CLOSED[0]},{G_UDP_CLOSED[1]} {T}",
                "expect": f"Both ports udp closed",
            },
            {
                "name": "test_lan[IPv4-sequence of 2 open UDP ports]",
                "desc": "Two open UDP ports",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -u {G_UDP_OPEN[0]},{G_UDP_OPEN[1]} {T}",
                "expect": f"Both ports udp open",
            },
            {
                "name": "test_lan[IPv4-sequence of 2 open and closed UDP ports]",
                "desc": "One open + one closed UDP port",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -u {G_UDP_OPEN[0]},{G_UDP_CLOSED[0]} {T}",
                "expect": f"{G_UDP_OPEN[0]} udp open, {G_UDP_CLOSED[0]} udp closed",
            },
            {
                "name": "test_lan[IPv4-range of 3 open and closed UDP ports]",
                "desc": "Range with mixed open/closed UDP",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -u {G_UDP_OPEN[0]}-{G_UDP_CLOSED[2]} {T}",
                "expect": f"Open: {G_UDP_OPEN}, Closed: {G_UDP_CLOSED}",
            },
        ]
    })

    # --- IPv4 Combined TCP + UDP ---
    scenarios.append({
        "category": "IPv4 Combined TCP + UDP",
        "location": "remote",
        "tests": [
            {
                "name": "test_lan[IPv4-range of 3 TCP + sequence of 2 UDP]",
                "desc": "Mixed TCP range + UDP sequence",
                "cmd": (f"sudo ./ipk-L4-scan -i {I} "
                        f"-t {G_COMBO_TCP_OPEN[0]},{G_COMBO_TCP_OPEN[1]},{G_COMBO_TCP_CLOSED[0]} "
                        f"-u {G_COMBO_UDP_OPEN[0]},{G_COMBO_UDP_CLOSED[0]} {T}"),
                "expect": "TCP: 9061,9062 open + 9064 closed. UDP: 9071 open + 9073 closed",
            },
        ]
    })

    # --- Timeout tests ---
    scenarios.append({
        "category": "Timeout Tests",
        "location": "remote",
        "tests": [
            {
                "name": "test_timeout_short",
                "desc": "Very short timeout (100ms)",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -w 100 -t {G_TCP_FILTERED[0]} {T}",
                "expect": f"{T} {G_TCP_FILTERED[0]} tcp filtered (should be fast)",
            },
            {
                "name": "test_timeout_long",
                "desc": "Long timeout (5000ms)",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -w 5000 -t {G_TCP_FILTERED[0]} {T}",
                "expect": f"{T} {G_TCP_FILTERED[0]} tcp filtered (takes ~10s with retry)",
            },
        ]
    })

    # --- DNS tests (use real hostnames, needs network but not this server) ---
    scenarios.append({
        "category": "DNS Resolution",
        "location": "remote",
        "tests": [
            {
                "name": "test_dns_a_aaaa_single",
                "desc": "Hostname with single A+AAAA",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t 80 www.vutbr.cz",
                "expect": "Should scan both IPv4 and IPv6 addresses",
            },
            {
                "name": "test_dns_a_aaaa_multiple",
                "desc": "Hostname with multiple DNS answers",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t 80 www.google.com",
                "expect": "Should scan all resolved addresses",
            },
        ]
    })

    # --- SYN-only verification ---
    scenarios.append({
        "category": "SYN-only Verification",
        "location": "remote",
        "tests": [
            {
                "name": "test_lan_tcp_handshake_allowed",
                "desc": "Verify SYN-only (no full handshake). Run tcpdump alongside.",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_OPEN[0]} {T}",
                "expect": "tcpdump should show SYN out, SYN-ACK back, NO ACK from scanner",
            },
            {
                "name": "test_lan_tcp_handshake_allowed_short_port_arg",
                "desc": "Same with comma-separated ports",
                "cmd": f"sudo ./ipk-L4-scan -i {I} -t {G_TCP_OPEN[0]},{G_TCP_OPEN[1]} {T}",
                "expect": "SYN-only for both ports, no completed handshake",
            },
        ]
    })

    # ==========================================================
    # LOCAL TESTS - run on your scanner machine, no server needed
    # ==========================================================

    # --- Interface & Help ---
    scenarios.append({
        "category": "Interface & Help",
        "location": "local",
        "tests": [
            {
                "name": "test_arg_interface",
                "desc": "List active interfaces",
                "cmd": f"sudo ./ipk-L4-scan -i",
                "expect": "Should list active interfaces (lo, enp..., etc.) and exit 0",
            },
            {
                "name": "test_arg_help",
                "desc": "Show help (-h)",
                "cmd": f"sudo ./ipk-L4-scan -h",
                "expect": "Should print usage and exit 0",
            },
            {
                "name": "test_arg_help_long",
                "desc": "Show help (--help)",
                "cmd": f"sudo ./ipk-L4-scan --help",
                "expect": "Should print usage and exit 0",
            },
        ]
    })

    # --- DNS errors ---
    scenarios.append({
        "category": "DNS Errors",
        "location": "local",
        "tests": [
            {
                "name": "test_dns_invalid",
                "desc": "Invalid hostname",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 80 thishost.does.not.exist.invalid",
                "expect": "Should print error and exit non-zero",
            },
        ]
    })

    # --- Localhost / loopback tests ---
    scenarios.append({
        "category": "Localhost / Loopback",
        "location": "local",
        "tests": [
            {
                "name": "test_tcp[127.0.0.1 single open TCP port]",
                "desc": "TCP scan on 127.0.0.1 (need a listener: nc -l -p 9001)",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 9001 127.0.0.1",
                "expect": f"127.0.0.1 9001 tcp open (if listener running)",
            },
            {
                "name": "test_tcp[localhost single open TCP port]",
                "desc": "TCP scan on localhost hostname",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 9001 localhost",
                "expect": f"127.0.0.1 9001 tcp open (if listener running)",
            },
            {
                "name": "test_tcp[localhost closed TCP port]",
                "desc": "TCP scan closed port on localhost",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 19999 localhost",
                "expect": f"127.0.0.1 19999 tcp closed",
            },
        ]
    })

    # --- IPv6 loopback tests ---
    scenarios.append({
        "category": "IPv6 Loopback (::1)",
        "location": "local",
        "tests": [
            {
                "name": "test_lan[IPv6-single open TCP port]",
                "desc": "Open TCP port over IPv6 (need: nc -l -p 9001)",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 9001 ::1",
                "expect": f"::1 9001 tcp open",
            },
            {
                "name": "test_lan[IPv6-single closed TCP port]",
                "desc": "Closed TCP port over IPv6",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 19999 ::1",
                "expect": f"::1 19999 tcp closed",
            },
            {
                "name": "test_lan[IPv6-sequence of 2 closed TCP ports]",
                "desc": "Two closed TCP ports over IPv6",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 19998,19999 ::1",
                "expect": "Both tcp closed",
            },
            {
                "name": "test_lan[IPv6-sequence of 2 open and closed TCP ports]",
                "desc": "Mixed TCP over IPv6 (need: nc -l -p 9001)",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 9001,19999 ::1",
                "expect": f"9001 open, 19999 closed",
            },
            {
                "name": "test_lan[IPv6-sequence of 2 open TCP ports]",
                "desc": "Two open TCP over IPv6 (need: nc -l -p 9001 & nc -l -p 9002)",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 9001,9002 ::1",
                "expect": "Both tcp open",
            },
            {
                "name": "test_lan[IPv6-range of 3 open and closed TCP ports]",
                "desc": "Range with mixed TCP over IPv6",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 9001-9013 ::1",
                "expect": "Open: listeners running, Closed: rest",
            },
            {
                "name": "test_lan[IPv6-single open UDP port]",
                "desc": "Open UDP over IPv6 (need: nc -u -l -p 9031)",
                "cmd": f"sudo ./ipk-L4-scan -i lo -u 9031 ::1",
                "expect": f"::1 9031 udp open",
            },
            {
                "name": "test_lan[IPv6-single closed UDP port]",
                "desc": "Closed UDP over IPv6",
                "cmd": f"sudo ./ipk-L4-scan -i lo -u 19999 ::1",
                "expect": f"::1 19999 udp closed",
            },
            {
                "name": "test_lan[IPv6-sequence of 2 closed UDP ports]",
                "desc": "Two closed UDP over IPv6",
                "cmd": f"sudo ./ipk-L4-scan -i lo -u 19998,19999 ::1",
                "expect": "Both udp closed",
            },
            {
                "name": "test_lan[IPv6-sequence of 2 open and closed UDP ports]",
                "desc": "Mixed UDP over IPv6 (need: nc -u -l -p 9031)",
                "cmd": f"sudo ./ipk-L4-scan -i lo -u 9031,19999 ::1",
                "expect": f"9031 open, 19999 closed",
            },
            {
                "name": "test_lan[IPv6-sequence of 2 open UDP ports]",
                "desc": "Two open UDP over IPv6",
                "cmd": f"sudo ./ipk-L4-scan -i lo -u 9031,9032 ::1",
                "expect": "Both udp open",
            },
            {
                "name": "test_lan[IPv6-range of 3 open and closed UDP ports]",
                "desc": "Range with mixed UDP over IPv6",
                "cmd": f"sudo ./ipk-L4-scan -i lo -u 9031-9043 ::1",
                "expect": "Open: listeners running, Closed: rest",
            },
            {
                "name": "test_lan[IPv6-combined TCP+UDP]",
                "desc": "Combined TCP + UDP over IPv6",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 9001,19999 -u 9031,19999 ::1",
                "expect": "TCP + UDP results over IPv6",
            },
        ]
    })

    # --- Edge cases ---
    scenarios.append({
        "category": "Edge Cases - Argument Parsing",
        "location": "local",
        "tests": [
            {
                "name": "test_edge_no_ports",
                "desc": "No -t or -u specified",
                "cmd": f"sudo ./ipk-L4-scan -i lo 127.0.0.1",
                "expect": "Should print error (need at least -t or -u) and exit non-zero",
            },
            {
                "name": "test_edge_no_host",
                "desc": "No host specified",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 80",
                "expect": "Should print error (HOST required) and exit non-zero",
            },
            {
                "name": "test_edge_no_interface",
                "desc": "No -i specified",
                "cmd": f"sudo ./ipk-L4-scan -t 80 127.0.0.1",
                "expect": "Should print error (-i required) and exit non-zero",
            },
            {
                "name": "test_edge_bad_interface",
                "desc": "Non-existent interface",
                "cmd": f"sudo ./ipk-L4-scan -i nonexistent0 -t 80 127.0.0.1",
                "expect": "Should warn about missing address or fail gracefully",
            },
            {
                "name": "test_edge_wrong_interface",
                "desc": "Scan remote host via loopback (wrong interface)",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 80 8.8.8.8",
                "expect": "Should warn (no route) or report filtered - not crash",
            },
            {
                "name": "test_edge_duplicate_ports",
                "desc": "Duplicate ports in list",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t 22,22,22 127.0.0.1",
                "expect": "Should handle gracefully (scan once or three times, no crash)",
            },
            {
                "name": "test_edge_args_any_order",
                "desc": "Arguments in unusual order (host first)",
                "cmd": f"sudo ./ipk-L4-scan 127.0.0.1 -t 22 -i lo",
                "expect": "Should work - spec says args in any order",
            },
            {
                "name": "test_edge_short_port_arg",
                "desc": "Port arg without space (-t22 instead of -t 22)",
                "cmd": f"sudo ./ipk-L4-scan -i lo -t22 127.0.0.1",
                "expect": "May work or error - tests parser robustness",
            },
        ]
    })

    # --- Signal handling ---
    scenarios.append({
        "category": "Signal Handling",
        "location": "local",
        "tests": [
            {
                "name": "test_sigint",
                "desc": "Ctrl+C during scan (sends SIGINT after 2s)",
                "cmd": f"timeout -s INT 2 sudo ./ipk-L4-scan -i lo -t 1-65535 127.0.0.1",
                "expect": "Should terminate gracefully with exit 0, partial output OK",
            },
            {
                "name": "test_sigterm",
                "desc": "SIGTERM during scan",
                "cmd": f"timeout -s TERM 2 sudo ./ipk-L4-scan -i lo -t 1-65535 127.0.0.1",
                "expect": "Should terminate gracefully",
            },
        ]
    })

    return scenarios


# =============================================================
# Web UI
# =============================================================

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>L4 Scanner Test Environment</title>
    <meta http-equiv="refresh" content="10;url={refresh_url}">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Courier New', monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #00d4ff; margin-bottom: 10px; font-size: 1.4em; }}
        .meta {{ color: #888; margin-bottom: 20px; font-size: 0.9em; }}
        .meta span {{ color: #00d4ff; }}
        .target-switch {{
            margin-top: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .target-presets {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            width: 100%;
            margin-top: 2px;
        }}
        .target-preset {{
            background: #0f2342;
            color: #b8d8ff;
            border: 1px solid #2f4b70;
            border-radius: 999px;
            padding: 5px 9px;
            font-family: inherit;
            font-size: 0.78em;
            cursor: pointer;
            display: inline-block;
            text-decoration: none;
        }}
        .target-preset:hover {{ background: #17335f; }}
        .target-preset.active {{
            background: #1f5a2e;
            border-color: #37a058;
            color: #d7ffe4;
        }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }}
        .card {{ background: #16213e; border: 1px solid #333; border-radius: 8px; padding: 16px; }}
        .card h2 {{ font-size: 1em; margin-bottom: 8px; }}
        .card h2.open {{ color: #00ff88; }}
        .card h2.closed {{ color: #ff4444; }}
        .card h2.filtered {{ color: #ffaa00; }}
        .card h2.scanner {{ color: #ff66ff; }}
        .card h2.log {{ color: #aaaaff; }}
        .card h2.test {{ color: #66ffcc; }}
        .card h2.guaranteed {{ color: #ff9966; }}
        .ports {{ font-size: 0.8em; color: #aaa; word-break: break-all; max-height: 200px; overflow-y: auto; line-height: 1.6; }}
        .count {{ font-size: 0.85em; color: #666; margin-bottom: 6px; }}
        .cmd {{ background: #0a0a1a; border: 1px solid #333; border-radius: 4px; padding: 12px; margin-top: 10px; font-size: 0.82em; color: #00d4ff; overflow-x: auto; }}
        .cmd .label {{ color: #888; display: block; margin-bottom: 4px; }}
        .cmd pre {{ cursor: pointer; transition: color 0.15s ease; }}
        .cmd pre:hover {{ color: #7fe7ff; }}
        .grid .card span.label {{ color: #888; display: block; margin-bottom: 6px; font-size: 0.85em; }}
        .grid .card pre {{ color: #00d4ff; cursor: pointer; transition: color 0.15s ease; margin: 0; }}
        .grid .card pre:hover {{ color: #7fe7ff; }}
        .section {{ margin-bottom: 24px; }}
        .section > h2 {{ color: #00d4ff; font-size: 1.1em; margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 4px; }}
        pre {{ white-space: pre-wrap; }}
        code {{ cursor: pointer; }}
        .copy-hint {{ color: #6fb3ff; font-size: 0.76em; margin-top: 6px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
        th {{ text-align: left; color: #00d4ff; padding: 6px 8px; border-bottom: 1px solid #333; }}
        td {{ padding: 4px 8px; border-bottom: 1px solid #222; color: #ccc; }}
        tr:hover td {{ background: #1a1a3e; }}
        .log-table {{ max-height: 300px; overflow-y: auto; }}
        .ip-highlight {{ color: #ff66ff; font-weight: bold; }}
        .proto-tcp {{ color: #00ff88; }}
        .proto-udp {{ color: #ffaa00; }}
        .test-name {{ color: #66ffcc; font-weight: bold; font-size: 0.85em; }}
        .test-desc {{ color: #aaa; font-size: 0.82em; }}
        .test-expect {{ color: #888; font-size: 0.78em; font-style: italic; }}
        .test-cat {{ color: #ff9966; font-size: 0.95em; margin-top: 16px; margin-bottom: 6px; border-bottom: 1px solid #333; padding-bottom: 4px; }}
        .test-group {{ padding: 12px; margin-bottom: 16px; border-radius: 8px; }}
        .test-group.remote {{ background: #0a2a0a; border: 1px solid #1a4a1a; }}
        .test-group.local {{ background: #2a1a0a; border: 1px solid #4a3a1a; }}
        .test-group-title {{ margin-bottom: 8px; font-size: 1em; }}
        .test-group-title.remote {{ color: #00ff88; }}
        .test-group-title.local {{ color: #ffaa00; }}
        .test-group-subtitle {{ color: #888; font-size: 0.8em; margin-bottom: 10px; }}
        .test-grid {{ display: flex; flex-wrap: wrap; gap: 10px; }}
        .test-card {{ flex: 0 0 calc(50% - 5px); max-width: calc(50% - 5px); min-width: 0; padding: 10px; }}
        .collapsible {{ border: 1px solid #333; border-radius: 6px; background: #101b34; }}
        .collapsible-summary {{
            list-style: none;
            cursor: pointer;
            color: #ff66ff;
            font-weight: bold;
            padding: 10px 12px;
            border-bottom: 1px solid #2a3a55;
            user-select: none;
        }}
        .collapsible-summary::-webkit-details-marker {{ display: none; }}
        .collapsible-summary::before {{ content: "[+]"; color: #ff66ff; margin-right: 8px; }}
        details[open] > .collapsible-summary::before {{ content: "[-]"; }}
        .collapsible-body {{ padding: 10px 12px 12px; }}
        .log-controls {{ display: flex; gap: 8px; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }}
        .log-input {{
            flex: 1 1 320px;
            min-width: 200px;
            background: #0a0a1a;
            color: #d8e6ff;
            border: 1px solid #2f4b70;
            border-radius: 4px;
            padding: 8px 10px;
            font-family: inherit;
            font-size: 0.85em;
        }}
        .log-btn {{
            background: #13294d;
            color: #9fd4ff;
            border: 1px solid #2f4b70;
            border-radius: 4px;
            padding: 8px 10px;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.82em;
        }}
        .log-btn:hover {{ background: #1a3765; }}
        .log-status {{ color: #89a1c3; font-size: 0.8em; }}
        @media (max-width: 720px) {{
            .test-card {{ flex-basis: 100%; max-width: 100%; }}
        }}
    </style>
</head>
<body>
    <h1>L4 Scanner Test Environment</h1>
    <div class="meta">
        VPN IPv4: <span>{vpn_host}</span> |
        Target IPv6: <span>{target_ipv6}</span> |
        Active target: <span>{selected_target}</span> ({selected_network_label} / {selected_mode_label}) |
        Randomized range: <span>{rand_start}-{rand_end}</span> |
        Last refresh: <span>{last_refresh}</span> |
        Next refresh: <span>{next_refresh}</span> |
        Discord: <a href="https://discord.com/users/414505536936214531" target="_blank" rel="noopener noreferrer" style="color:#00d4ff;">_.miau._</a>
        <div class="target-switch">
            <div class="target-presets">
                <a class="target-preset {preset_vpn_ip_active}" href="/?target_mode=ip">VPN IP</a>
                <a class="target-preset {preset_vpn_address_active}" href="/?target_mode=address">VPN ADDRESS</a>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Incoming Scanners</h2>
        <div class="card">
            <details class="collapsible">
                <summary class="collapsible-summary">ACTIVE SCANNERS ({scanner_count})</summary>
                <div class="collapsible-body">{scanner_table}</div>
            </details>
        </div>
    </div>

    <div class="section">
        <h2>Recent Activity ({log_count} packets)</h2>
        <div class="card">
            <h2 class="log">PACKET LOG</h2>
            <div class="log-controls">
                <input id="logFilterInput" class="log-input" type="text" placeholder="Filter packets by source IP, proto, port, or flags">
                <button id="logFilterClear" class="log-btn" type="button">Clear filter</button>
                <span id="logFilterStatus" class="log-status"></span>
            </div>
            <div class="log-table">{log_table}</div>
        </div>
    </div>

    <div class="section">
        <h2>Guaranteed Ports (fixed, never change)</h2>
        <div class="grid">
            <div class="card">
                <h2 class="guaranteed">TCP</h2>
                <div class="ports">
                    <span style="color:#00ff88">OPEN: {g_tcp_open}</span><br>
                    <span style="color:#ff4444">CLOSED: {g_tcp_closed}</span><br>
                    <span style="color:#ffaa00">FILTERED: {g_tcp_filtered}</span>
                </div>
            </div>
            <div class="card">
                <h2 class="guaranteed">UDP</h2>
                <div class="ports">
                    <span style="color:#00ff88">OPEN: {g_udp_open}</span><br>
                    <span style="color:#ff4444">CLOSED: {g_udp_closed}</span><br>
                    <span style="color:#ffaa00">FILTERED: {g_udp_filtered}</span>
                </div>
            </div>
        </div>
        <div class="card">
            <h2 class="guaranteed">Combined (TCP + UDP)</h2>
            <div class="ports">
                <span style="color:#00ff88">TCP OPEN: {g_combo_tcp_open}</span> |
                <span style="color:#ff4444">TCP CLOSED: {g_combo_tcp_closed}</span> |
                <span style="color:#00ff88">UDP OPEN: {g_combo_udp_open}</span> |
                <span style="color:#ff4444">UDP CLOSED: {g_combo_udp_closed}</span>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Randomized Ports (range {rand_start}-{rand_end})</h2>
        <div class="grid">
            <div class="card">
                <h2 class="open">TCP OPEN ({tcp_open_count})</h2>
                <div class="ports">{tcp_open_ports}</div>
            </div>
            <div class="card">
                <h2 class="filtered">TCP FILTERED ({tcp_filtered_count})</h2>
                <div class="ports">{tcp_filtered_ports}</div>
            </div>
        </div>
        <div class="grid">
            <div class="card">
                <h2 class="open">UDP OPEN ({udp_open_count})</h2>
                <div class="ports">{udp_open_ports}</div>
            </div>
            <div class="card">
                <h2 class="filtered">UDP FILTERED ({udp_filtered_count})</h2>
                <div class="ports">{udp_filtered_ports}</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Test Scenarios ({test_count} tests)</h2>
        {test_html}
    </div>

    <div class="section">
        <h2>Validation Script</h2>
        <div style="color:#888;font-size:0.82em;margin-bottom:10px;">
            Save as <code style="color:#00d4ff;">validate.py</code> and run alongside scanner to check results.
        </div>
        <div class="cmd">
            <span class="label"># validate.py - pipe scanner output through this</span>
            <pre>#!/usr/bin/env python3
\"\"\"Validate ipk-L4-scan output against test server state.
Usage: sudo ./ipk-L4-scan -i {interface} -t 9001-9053 -u 9031-9053 {target_host} | python3 validate.py
\"\"\"
import json, sys, urllib.request

API = "http://{target_host}:{web_port}/api/state"
state = json.loads(urllib.request.urlopen(API).read())

# Build lookup: all guaranteed + randomized ports
lookup = {{}}
for key in state:
    if key.startswith(("g_", "tcp_", "udp_", "g_combo_")):
        ports = state[key]
        if isinstance(ports, list):
            for p in ports:
                # key format: [g_]{{proto}}_{{status}} or g_combo_{{proto}}_{{status}}
                parts = key.replace("g_combo_", "").replace("g_", "").split("_")
                if len(parts) == 2:
                    proto, status = parts
                    lookup.setdefault(proto, {{}}).setdefault(status, set()).add(p)

ok = 0
fail = 0
total = 0

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    total += 1
    try:
        ip, port, proto, status = line.split()
        port = int(port)
    except ValueError:
        print(f"  PARSE_ERR  {{line}}")
        fail += 1
        continue

    expected_ports = lookup.get(proto, {{}}).get(status, set())
    if port in expected_ports:
        print(f"  OK    {{line}}")
        ok += 1
    else:
        # Check what the expected status was
        found = None
        for s, ports in lookup.get(proto, {{}}).items():
            if port in ports:
                found = s
                break
        if found:
            print(f"  FAIL  {{line}}  (expected: {{found}})")
        else:
            print(f"  SKIP  {{line}}  (port not in test range)")
        fail += 1

print(f"\\nResults: {{ok}} OK, {{fail}} FAIL, {{total}} total")
sys.exit(1 if fail > 0 else 0)</pre>
        </div>
        <div class="cmd">
            <span class="label"># Quick one-liner (guaranteed ports only):</span>
            <pre>sudo ./ipk-L4-scan -i {interface} -t 9001-9053 -u 9031-9053 {target_host} 2>/dev/null | \\
  python3 validate.py</pre>
        </div>
        <div class="cmd">
            <span class="label"># With randomized range:</span>
            <pre>sudo ./ipk-L4-scan -i {interface} -t 10000-10999 -u 10000-10999 {target_host} 2>/dev/null | \\
  python3 validate.py</pre>
        </div>
    </div>

    <div class="section">
        <h2>Automated Test Runner (from /api/tests)</h2>
        <div style="color:#888;font-size:0.82em;margin-bottom:10px;">
            Save as <code style="color:#00d4ff;">run_tests_from_api.py</code>. It pulls test commands from
            <code style="color:#00d4ff;">/api/tests</code>, executes them, and verifies scanner-style output
            against <code style="color:#00d4ff;">/api/state</code>. For non-scanner outputs, it falls back to
            matching the API <code style="color:#00d4ff;">expect</code> text.
        </div>
        <div class="cmd">
            <span class="label"># run_tests_from_api.py</span>
            <pre>#!/usr/bin/env python3
\"\"\"Run test scenarios from /api/tests and verify outputs.

Usage:
  python3 run_tests_from_api.py --base-url http://{target_host}:{web_port}

Notes:
- Requires scanner binary available for commands in /api/tests.
- Many commands include sudo; run with appropriate privileges.
- Defaults to remote tests because they are the ones targeting this server.
\"\"\"

import argparse
import json
import re
import shlex
import subprocess
import sys
import urllib.request


SCAN_LINE_RE = re.compile(r"^(\\S+)\\s+(\\d+)\\s+(tcp|udp)\\s+(open|closed|filtered)\\s*$", re.IGNORECASE)


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode())


def build_state_lookup(state):
    lookup = {{}}
    for key, ports in state.items():
        if not isinstance(ports, list):
            continue
        if not key.startswith(("g_", "tcp_", "udp_", "g_combo_")):
            continue
        parts = key.replace("g_combo_", "").replace("g_", "").split("_")
        if len(parts) != 2:
            continue
        proto, status = parts
        proto = proto.lower()
        status = status.lower()
        lookup.setdefault(proto, {{}}).setdefault(status, set()).update(ports)
    return lookup


def parse_scan_lines(output):
    parsed = []
    for raw in output.splitlines():
        m = SCAN_LINE_RE.match(raw.strip())
        if not m:
            continue
        host, port, proto, status = m.groups()
        parsed.append((host, int(port), proto.lower(), status.lower(), raw.strip()))
    return parsed


def verify_with_state(parsed_lines, state_lookup):
    if not parsed_lines:
        return None, ["no scanner-style lines found"]

    errors = []
    for _, port, proto, status, raw in parsed_lines:
        expected_ports = state_lookup.get(proto, {{}}).get(status, set())
        if port not in expected_ports:
            expected_status = None
            for st, ports in state_lookup.get(proto, {{}}).items():
                if port in ports:
                    expected_status = st
                    break
            if expected_status:
                errors.append(f"{{raw}} (expected status: {{expected_status}})")
            else:
                errors.append(f"{{raw}} (port not present in API state lookup)")

    return len(errors) == 0, errors


def run_test(test, state_lookup, timeout_s):
    cmd = test["cmd"]
    # Keep command semantics exactly as provided by API.
    cp = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    merged = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
    parsed = parse_scan_lines(merged)
    ok_state, errors = verify_with_state(parsed, state_lookup)

    if ok_state is True:
        return True, "state-verified", cp.returncode, merged

    expected_hint = test.get("expect", "").strip()
    if expected_hint and expected_hint.lower() in merged.lower():
        return True, "expect-text-matched", cp.returncode, merged

    reason = "no verifiable scanner output"
    if errors:
        reason = "; ".join(errors[:3])
    return False, reason, cp.returncode, merged


def iter_tests(scenarios, location_filter):
    for group in scenarios:
        location = group.get("location", "remote")
        if location_filter != "all" and location != location_filter:
            continue
        category = group.get("category", "uncategorized")
        for test in group.get("tests", []):
            yield location, category, test


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://{target_host}:{web_port}")
    ap.add_argument("--location", choices=["remote", "local", "all"], default="remote")
    ap.add_argument("--timeout", type=int, default=20, help="Per-test timeout in seconds")
    ap.add_argument("--stop-on-fail", action="store_true")
    args = ap.parse_args()

    tests_api = args.base_url.rstrip("/") + "/api/tests"
    state_api = args.base_url.rstrip("/") + "/api/state"

    scenarios = fetch_json(tests_api)
    state = fetch_json(state_api)
    state_lookup = build_state_lookup(state)

    total = 0
    passed = 0
    failed = 0

    print(f"[*] Loaded scenarios from: {{tests_api}}")
    print(f"[*] Loaded state from:     {{state_api}}")

    for location, category, test in iter_tests(scenarios, args.location):
        total += 1
        name = test.get("name", "unnamed-test")
        print(f"\\n[{{total}}] {{name}} ({{location}} / {{category}})")
        print(f"    cmd: {{test['cmd']}}")

        try:
            ok, reason, rc, output = run_test(test, state_lookup, args.timeout)
        except subprocess.TimeoutExpired:
            ok = False
            reason = f"timeout after {{args.timeout}}s"
            rc = -1
            output = ""

        if ok:
            passed += 1
            print(f"    PASS ({{reason}}, rc={{rc}})")
        else:
            failed += 1
            print(f"    FAIL ({{reason}}, rc={{rc}})")
            preview = "\\n".join(output.splitlines()[:12]).strip()
            if preview:
                print("    output preview:")
                for line in preview.splitlines():
                    print(f"      {{line}}")
            if args.stop_on_fail:
                break

    print(f"\\nResults: {{passed}} PASS, {{failed}} FAIL, {{total}} total")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()</pre>
        </div>
        <div class="cmd">
            <span class="label"># Run remote tests only (default):</span>
            <pre>python3 run_tests_from_api.py --base-url http://{target_host}:{web_port}</pre>
        </div>
        <div class="cmd">
            <span class="label"># Run remote tests from API and stop on first failure:</span>
            <pre>python3 run_tests_from_api.py --base-url http://{target_host}:{web_port} --location remote --stop-on-fail</pre>
        </div>
    </div>

    <div class="section">
        <h2>JSON API</h2>
        <div class="cmd">
            <pre>curl http://{target_host}:{web_port}/api/state      # port state
curl http://{target_host}:{web_port}/api/scanners   # scanner summary
curl http://{target_host}:{web_port}/api/log         # packet log
curl http://{target_host}:{web_port}/api/tests       # test scenarios</pre>
            <div class="copy-hint">Click any command or code snippet to copy</div>
        </div>
    </div>
    <script>
        (() => {{
            const copyText = async (text) => {{
                const value = (text || "").trim();
                if (!value) return false;
                try {{
                    await navigator.clipboard.writeText(value);
                    return true;
                }} catch (_) {{
                    const ta = document.createElement("textarea");
                    ta.value = value;
                    ta.setAttribute("readonly", "");
                    ta.style.position = "fixed";
                    ta.style.top = "-1000px";
                    document.body.appendChild(ta);
                    ta.focus();
                    ta.select();
                    const ok = document.execCommand("copy");
                    document.body.removeChild(ta);
                    return ok;
                }}
            }};

            const showCopied = (el) => {{
                const prev = el.dataset.copyLabel || "";
                if (!el.dataset.copyLabel) {{
                    el.dataset.copyLabel = el.textContent;
                }}
                el.textContent = "Copied";
                setTimeout(() => {{
                    if (prev) el.textContent = prev;
                }}, 900);
            }};

            document.querySelectorAll("pre, code").forEach((el) => {{
                el.title = "Click to copy";
                el.addEventListener("click", async (ev) => {{
                    ev.stopPropagation();
                    const ok = await copyText(el.innerText || el.textContent);
                    if (!ok) return;

                    if (el.tagName === "CODE") {{
                        const original = el.getAttribute("data-original-text") || el.textContent;
                        if (!el.getAttribute("data-original-text")) {{
                            el.setAttribute("data-original-text", original);
                        }}
                        el.textContent = "Copied";
                        setTimeout(() => {{
                            el.textContent = el.getAttribute("data-original-text");
                        }}, 900);
                    }} else if (el.parentElement && el.parentElement.classList.contains("cmd")) {{
                        const hint = el.parentElement.querySelector(".copy-hint");
                        if (hint) {{
                            const old = hint.textContent;
                            hint.textContent = "Copied";
                            setTimeout(() => {{ hint.textContent = old; }}, 900);
                        }}
                    }}
                }});
            }});

            const logInput = document.getElementById("logFilterInput");
            const clearBtn = document.getElementById("logFilterClear");
            const status = document.getElementById("logFilterStatus");

            const applyLogFilter = () => {{
                const tableRows = document.querySelectorAll("#packet-log-table tbody tr");
                const query = (logInput?.value || "").trim().toLowerCase();
                let visibleCount = 0;

                tableRows.forEach((row) => {{
                    const searchText = row.getAttribute("data-search") || "";
                    const matched = !query || searchText.includes(query);
                    row.style.display = matched ? "" : "none";
                    if (matched) visibleCount += 1;
                }});

                if (status) {{
                    if (!tableRows.length) {{
                        status.textContent = "No packets to filter";
                    }} else if (!query) {{
                        status.textContent = `Showing all ${{tableRows.length}} packets`;
                    }} else {{
                        status.textContent = `Showing ${{visibleCount}} of ${{tableRows.length}} packets`;
                    }}
                }}
            }};

            if (logInput) {{
                logInput.addEventListener("input", applyLogFilter);
            }}

            if (clearBtn) {{
                clearBtn.addEventListener("click", () => {{
                    if (logInput) logInput.value = "";
                    applyLogFilter();
                }});
            }}

            applyLogFilter();
        }})();
    </script>
</body>
</html>"""


def build_scanner_table():
    with log_lock:
        if not ip_summary:
            return "<div class='count'>No scanners detected yet</div>"
        rows = []
        for ip, info in sorted(ip_summary.items(), key=lambda x: x[1]["last_seen"] or "", reverse=True):
            rows.append(
                f"<tr><td class='ip-highlight'>{ip}</td>"
                f"<td>{info['first_seen']}</td><td>{info['last_seen']}</td>"
                f"<td class='proto-tcp'>{info['tcp_count']}</td>"
                f"<td class='proto-udp'>{info['udp_count']}</td>"
                f"<td>{len(info['ports_scanned'])}</td></tr>"
            )
    return ("<table><tr><th>Source IP</th><th>First seen</th><th>Last seen</th>"
            "<th>TCP</th><th>UDP</th><th>Ports</th></tr>" + "".join(rows) + "</table>")


def build_log_table():
    with log_lock:
        if not conn_log:
            return "<div class='count'>No packets captured yet</div>"
        rows = []
        for entry in reversed(conn_log[-MAX_LOG_WEB:]):
            pc = "proto-tcp" if entry["proto"] == "TCP" else "proto-udp"
            search_blob = (
                f"{entry['time']} {entry['src_ip']} {entry['src_port']} "
                f"{entry['dst_port']} {entry['proto']} {entry['flags']}"
            ).lower()
            rows.append(
                f"<tr data-search='{search_blob}'><td>{entry['time']}</td><td class='ip-highlight'>{entry['src_ip']}</td>"
                f"<td>{entry['src_port']}</td><td>{entry['dst_port']}</td>"
                f"<td class='{pc}'>{entry['proto']}</td><td>{entry['flags']}</td></tr>"
            )
    return ("<table id='packet-log-table'><thead><tr><th>Time</th><th>Source</th><th>SPort</th>"
            "<th>DPort</th><th>Proto</th><th>Flags</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def build_test_html(scenarios, target_host):
    """Build HTML for test scenarios, split into remote and local sections."""
    remote_parts = []
    local_parts = []
    remote_count = 0
    local_count = 0

    for group in scenarios:
        location = group.get("location", "remote")
        parts = remote_parts if location == "remote" else local_parts

        parts.append(f"<div class='test-cat'>{group['category']}</div>")
        parts.append("<div class='test-grid'>")
        for test in group["tests"]:
            if location == "remote":
                remote_count += 1
            else:
                local_count += 1
            parts.append("<div class='card test-card'>")
            parts.append(f"<div class='test-name'>{test['name']}</div>")
            parts.append(f"<div class='test-desc'>{test['desc']}</div>")
            parts.append(f"<div class='cmd'><pre>{test['cmd']}</pre></div>")
            parts.append(f"<div class='test-expect'>Expected: {test['expect']}</div>")
            parts.append(f"</div>")
        parts.append("</div>")

    static_tcp = ",".join(str(p) for p in (G_TCP_OPEN + G_TCP_CLOSED + G_TCP_FILTERED))
    static_udp = ",".join(str(p) for p in (G_UDP_OPEN + G_UDP_CLOSED + G_UDP_FILTERED))
    static_combo_tcp = ",".join(str(p) for p in (G_COMBO_TCP_OPEN + G_COMBO_TCP_CLOSED))
    static_combo_udp = ",".join(str(p) for p in (G_COMBO_UDP_OPEN + G_COMBO_UDP_CLOSED))

    html = ""
    html += ("<div class='section'>"
             "<h2 style='color:#7fc7ff;'>Quick Scan Commands</h2>"
             "<div style='color:#888; font-size: 0.9em; margin-bottom: 12px;'>"
             "Fast commands for full-range and static-only verification.</div>"
             "<div class='grid'>"
             "<div class='card'><span class='label'># Scan whole test range (TCP+UDP)</span>"
             f"<pre>sudo ./ipk-L4-scan -i {INTERFACE} -t 9000-{RAND_PORT_END - 1} -u 9000-{RAND_PORT_END - 1} {target_host}</pre></div>"
             "<div class='card'><span class='label'># Static TCP only (guaranteed fixed ports)</span>"
             f"<pre>sudo ./ipk-L4-scan -i {INTERFACE} -t {static_tcp} {target_host}</pre></div>"
             "<div class='card'><span class='label'># Static UDP only (guaranteed fixed ports)</span>"
             f"<pre>sudo ./ipk-L4-scan -i {INTERFACE} -u {static_udp} {target_host}</pre></div>"
             "<div class='card'><span class='label'># Static combo (TCP+UDP combo ports)</span>"
             f"<pre>sudo ./ipk-L4-scan -i {INTERFACE} -t {static_combo_tcp} -u {static_combo_udp} {target_host}</pre></div>"
             "</div></div>")

    html += ("<div class='test-group remote'>"
             f"<h3 class='test-group-title remote'>"
             f"&#127760; Remote Tests &mdash; scan this server ({remote_count} tests)</h3>"
             "<div class='test-group-subtitle'>"
             "Run these on your scanner machine. They target this test server and "
             "require it to be running.</div>"
             + "".join(remote_parts) + "</div>")

    html += ("<div class='test-group local'>"
             f"<h3 class='test-group-title local'>"
             f"&#128187; Local Tests &mdash; run on scanner machine ({local_count} tests)</h3>"
             "<div class='test-group-subtitle'>"
             "Run these directly on the machine where your scanner is built. "
             "No test server needed. For open port tests, start listeners locally "
             "(e.g. <code style='color:#00d4ff;'>nc -l -p 9001 &amp;</code>).</div>"
             + "".join(local_parts) + "</div>")

    return html, remote_count + local_count


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle each request in a separate thread to prevent blocking."""
    daemon_threads = True


def detect_server_ipv6(ifname):
    """Detect global IPv6 address on the given interface.
    /proc/net/if_inet6 format: hex_addr ifindex prefix_len scope flags ifname
    Scope: 00=global, 20=link-local, 05=site, 01=loopback
    We want anything that's NOT link-local (20) or loopback (01)."""
    import ipaddress

    def is_usable(addr_text):
        try:
            addr = ipaddress.IPv6Address(addr_text)
            if addr.is_link_local or addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                return False
            return True
        except Exception:
            return False

    # 1) Primary source: /proc/net/if_inet6 entries on the requested interface.
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                if parts[5] != ifname:
                    continue
                scope = parts[3]
                # Skip link-local (20) and loopback (01)
                if scope in ("20", "01"):
                    continue
                hex_str = parts[0]
                formatted = ":".join(hex_str[i:i+4] for i in range(0, 32, 4))
                addr = ipaddress.IPv6Address(formatted)
                # Skip link-local even if scope was wrong
                if addr.is_link_local or addr.is_loopback:
                    continue
                return str(addr)
    except Exception as e:
        print(f"[!] IPv6 detection error: {e}")

    # 2) Fallback: ask iproute for global addresses on the interface.
    try:
        cp = subprocess.run(
            ["ip", "-6", "addr", "show", "dev", ifname, "scope", "global"],
            capture_output=True,
            text=True,
            check=False,
        )
        if cp.returncode == 0:
            for line in cp.stdout.splitlines():
                s = line.strip()
                if not s.startswith("inet6 "):
                    continue
                # Format: inet6 2001:db8::1/64 scope global ...
                addr = s.split()[1].split("/")[0]
                if is_usable(addr):
                    return addr
    except Exception:
        pass

    # 3) Fallback: infer source IPv6 via kernel routing decision.
    for probe_target in ("2001:4860:4860::8888", "2620:fe::fe"):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                # UDP connect does not send packets; it picks the source address.
                s.connect((probe_target, 53, 0, 0))
                src = s.getsockname()[0]
                if is_usable(src):
                    return src
            finally:
                s.close()
        except Exception:
            continue

    return None


def detect_interface_public_ipv4(ifname):
    """Detect IPv4 global address configured on the interface."""
    try:
        cp = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", ifname, "scope", "global"],
            capture_output=True,
            text=True,
            check=False,
        )
        if cp.returncode == 0:
            for line in cp.stdout.splitlines():
                s = line.strip()
                if not s.startswith("inet "):
                    continue
                # Format: inet 203.0.113.10/24 brd ...
                return s.split()[1].split("/")[0]
    except Exception as e:
        print(f"[!] IPv4 detection error: {e}")
    return None


def normalize_target_selection(network, target_mode):
    net = (network or "vpn").strip().lower()
    mode = (target_mode or "ip").strip().lower()
    if net != "vpn":
        net = "vpn"
    if mode not in ("ip", "address"):
        mode = "ip"
    return net, mode


def resolve_scan_target(network, target_mode):
    net, mode = normalize_target_selection(network, target_mode)
    if mode == "address":
        return VPN_ADDR
    return VPN_HOST or TARGET_HOST


def build_refresh_url(network, target_mode):
    query = urlencode({"network": network, "target_mode": target_mode})
    return f"/?{query}"


# Detect at module level (updated in main)
SERVER_IPV6 = None
VPN_HOST = None


class Handler(BaseHTTPRequestHandler):
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except BrokenPipeError:
            pass

    def do_GET(self):
        try:
            self._handle_get()
        except BrokenPipeError:
            pass

    def _handle_get(self):
        parsed = urlparse(self.path)
        request_path = parsed.path
        query = parse_qs(parsed.query)
        selected_network, selected_mode = normalize_target_selection(
            query.get("network", ["vpn"])[0],
            query.get("target_mode", ["ip"])[0],
        )
        selected_target = resolve_scan_target(selected_network, selected_mode)

        if request_path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            with state_lock:
                self.wfile.write(json.dumps(state, indent=2).encode())

        elif request_path == "/api/log":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            with log_lock:
                self.wfile.write(json.dumps(conn_log, indent=2).encode())

        elif request_path == "/api/scanners":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            with log_lock:
                summary = {}
                for ip, info in ip_summary.items():
                    summary[ip] = {
                        "first_seen": info["first_seen"],
                        "last_seen": info["last_seen"],
                        "tcp_count": info["tcp_count"],
                        "udp_count": info["udp_count"],
                        "unique_ports": len(info["ports_scanned"]),
                    }
                self.wfile.write(json.dumps(summary, indent=2).encode())

        elif request_path == "/api/tests":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            scenarios = build_test_scenarios(selected_target)
            self.wfile.write(json.dumps(scenarios, indent=2).encode())

        elif request_path == "/" or request_path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            scenarios = build_test_scenarios(selected_target)
            test_html, test_count = build_test_html(scenarios, selected_target)

            with state_lock:
                with log_lock:
                    scanner_count = len(ip_summary)
                    log_count = min(MAX_LOG_WEB, len(conn_log))

                html = HTML_TEMPLATE.format(
                    refresh_url=build_refresh_url(selected_network, selected_mode),
                    target_host=selected_target,
                    selected_target=selected_target,
                    selected_network_label="VPN",
                    selected_mode_label="IP" if selected_mode == "ip" else "ADDRESS",
                    preset_vpn_ip_active="active" if selected_mode == "ip" else "",
                    preset_vpn_address_active="active" if selected_mode == "address" else "",
                    vpn_host=VPN_HOST or "none detected",
                    target_ipv6=SERVER_IPV6 or "none detected",
                    interface=INTERFACE,
                    last_refresh=state["last_refresh"] or "never",
                    next_refresh=state["next_refresh"] or "pending",
                    web_port=WEB_PORT,
                    # Guaranteed
                    g_tcp_open=", ".join(str(p) for p in G_TCP_OPEN),
                    g_tcp_closed=", ".join(str(p) for p in G_TCP_CLOSED),
                    g_tcp_filtered=", ".join(str(p) for p in G_TCP_FILTERED),
                    g_udp_open=", ".join(str(p) for p in G_UDP_OPEN),
                    g_udp_closed=", ".join(str(p) for p in G_UDP_CLOSED),
                    g_udp_filtered=", ".join(str(p) for p in G_UDP_FILTERED),
                    g_combo_tcp_open=", ".join(str(p) for p in G_COMBO_TCP_OPEN),
                    g_combo_tcp_closed=", ".join(str(p) for p in G_COMBO_TCP_CLOSED),
                    g_combo_udp_open=", ".join(str(p) for p in G_COMBO_UDP_OPEN),
                    g_combo_udp_closed=", ".join(str(p) for p in G_COMBO_UDP_CLOSED),
                    # Randomized
                    rand_start=RAND_PORT_START,
                    rand_end=RAND_PORT_END - 1,
                    tcp_open_count=len(state["tcp_open"]),
                    tcp_open_ports=", ".join(str(p) for p in state["tcp_open"]),
                    tcp_filtered_count=len(state["tcp_filtered"]),
                    tcp_filtered_ports=", ".join(str(p) for p in state["tcp_filtered"]),
                    udp_open_count=len(state["udp_open"]),
                    udp_open_ports=", ".join(str(p) for p in state["udp_open"]),
                    udp_filtered_count=len(state["udp_filtered"]),
                    udp_filtered_ports=", ".join(str(p) for p in state["udp_filtered"]),
                    # Activity
                    scanner_table=build_scanner_table(),
                    scanner_count=scanner_count,
                    log_table=build_log_table(),
                    log_count=log_count,
                    # Tests
                    test_html=test_html,
                    test_count=test_count,
                )
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


# =============================================================
# Main
# =============================================================

def cleanup(signum=None, frame=None):
    global cleanup_done

    with cleanup_lock:
        if cleanup_done:
            return
        cleanup_done = True

    print("\n[*] Cleaning up...")
    stop_event.set()
    close_listeners()
    clear_all_test_rules()
    restore_iptables()
    print("[+] Cleanup complete.")
    sys.exit(0)


def main():
    global SERVER_IPV6, VPN_HOST

    if os.geteuid() != 0:
        print("Error: must run as root (sudo)")
        sys.exit(1)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Detect IPv6
    SERVER_IPV6 = detect_server_ipv6(INTERFACE)
    VPN_HOST = detect_interface_public_ipv4(VPN_INTERFACE)

    if not VPN_HOST:
        print(f"[!] IPv4 public address not detected on {VPN_INTERFACE}; VPN host fallback is {TARGET_HOST}")

    if not SERVER_IPV6:
        # Debug: show what's in /proc/net/if_inet6 for this interface
        try:
            with open("/proc/net/if_inet6") as f:
                entries = [l.strip() for l in f if INTERFACE in l]
            if entries:
                print(f"[!] IPv6 not detected but /proc/net/if_inet6 has entries for {INTERFACE}:")
                for e in entries:
                    print(f"    {e}")
                print(f"    (all were filtered out - check scope/link-local)")
            else:
                print(f"[!] No IPv6 entries for {INTERFACE} in /proc/net/if_inet6")
        except Exception:
            pass

    scenarios = build_test_scenarios(TARGET_HOST)
    total_tests = sum(len(g["tests"]) for g in scenarios)

    print("=" * 60)
    print("  L4 Scanner Test Environment")
    print("=" * 60)
    print(f"  Target IPv4:   {TARGET_HOST}")
    print(f"  VPN IPv4:      {VPN_HOST or 'none detected'}")
    print(f"  Target IPv6:   {SERVER_IPV6 or 'none detected'}")
    print(f"  Interface:     {INTERFACE}")
    print(f"  VPN interface: {VPN_INTERFACE}")
    print(f"  Web UI:        http://{TARGET_HOST}:{WEB_PORT}")
    print(f"  Guaranteed:    ports 9001-9074 (fixed)")
    print(f"  Randomized:    ports {RAND_PORT_START}-{RAND_PORT_END - 1} (every {REFRESH_INTERVAL // 60}min)")
    print(f"  Test scenarios: {total_tests}")
    print(f"  Listeners:     Python sockets (no external deps)")
    print(f"  Web server:    threaded (no request blocking)")
    print("=" * 60)

    backup_iptables()
    clear_all_test_rules()
    setup_guaranteed()

    refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
    refresh_thread.start()

    sniff_thread = threading.Thread(target=sniffer_thread, daemon=True)
    sniff_thread.start()

    print(f"[+] Starting threaded web server on port {WEB_PORT}...")
    server = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()