#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║  BERRY SENTINEL v5.0 — Detector Conductual C2 · TUI Interactivo               ║
║  Zero-Signature · Bulletproof Collection · Deep Scan · Kill Engine            ║
║                                                                                ║
║  python3 sentinel.py [opciones]                                                ║
║    --all          Incluir conexiones locales/loopback                          ║
║    --interval N   Refresco en segundos (default: 2)                            ║
║    --log FILE     Guardar alertas en archivo                                   ║
║    --json         Exportar JSON al salir                                       ║
║    --whitelist    IPs/CIDRs a ignorar (coma)                                   ║
║    --no-color     Sin colores ANSI                                             ║
║    --verbose      Detalle extendido                                            ║
║    --top N        Máximo filas (default: 50)                                   ║
║    --diag         Diagnóstico: muestra qué métodos funcionan                   ║
║    --no-tui       Modo legacy sin curses (scroll clásico)                      ║
║                                                                                ║
║  TECLAS TUI INTERACTIVO:                                                       ║
║    k / K    → Matar proceso por ID (kill PID)                                  ║
║    d / D    → Ver detalles de conexión seleccionada                            ║
║    ↑ ↓      → Navegar tabla                                                    ║
║    F / f    → Filtrar por severidad                                            ║
║    q        → Salir                                                            ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import ctypes
import curses
import datetime
import glob
import hashlib
import ipaddress
import json
import os
import platform
import re
import signal
import socket
import struct
import subprocess
import sys
import textwrap
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Set

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

VERSION = "5.0.0"
SYSTEM = platform.system().lower()
IS_ANDROID = (
    os.path.isfile("/system/build.prop")
    or "android" in platform.platform().lower()
    or "ANDROID_ROOT" in os.environ
    or "TERMUX_VERSION" in os.environ
    or os.path.isdir("/data/data/com.termux")
)

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}

SHELL_BINS = frozenset({
    "bash", "sh", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "ash",
    "busybox", "mksh",
    "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
})

SCRIPT_ENGINES = frozenset({
    "python", "python3", "python3.8", "python3.9", "python3.10",
    "python3.11", "python3.12", "python3.13", "python2",
    "perl", "perl5", "ruby", "node", "nodejs", "php", "php-cgi",
    "java", "groovy", "lua", "luajit", "tclsh", "wish",
})

C2_SUSPECT_PORTS = frozenset({
    4444, 4445, 5555, 1234, 9999, 6666, 7777, 2222, 3333,
    13337, 31337, 9949, 9948, 8443,
    6667, 6697, 1337, 50050, 50051, 2323,
    8081, 8082, 40813, 40814, 1080, 3128,
    7331, 9090, 8888, 4443,
    # Adicionales Sliver/Empire
    31338, 31339, 8448, 9001, 9002, 2525, 6060, 7878,
    # Meterpreter comunes
    4455, 4446, 4447, 4448,
})

COMMON_PORTS = frozenset({80, 443, 53, 22, 25, 110, 143, 993, 995, 587, 465})

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

BEACON_INTERVALS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600]

# ═══════════════════════════════════════════════════════════════════════════════
# FIRMAS C2 CONOCIDAS — Meterpreter, Cobalt Strike, Sliver, Empire, etc.
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class C2Signature:
    name: str
    description: str
    score_bonus: int
    checks: List[dict]  # {type: port|port_range|cmdline|procname|ioc, value: ...}

C2_SIGNATURES: List[C2Signature] = [
    # ── Metasploit / Meterpreter ──────────────────────────────────────────────
    C2Signature("Meterpreter", "Metasploit reverse shell payload", 55, [
        {"type": "port", "value": 4444},
        {"type": "port", "value": 4445},
        {"type": "port_range", "min": 4444, "max": 4449},
        {"type": "cmdline", "value": r"meterpreter|msfconsole|msf[0-9]|reverse_tcp|reverse_https|staged_payload"},
        {"type": "procname", "value": r"^(ruby|msfconsole|msfrpcd|msfd)$"},
        # TLS JA3 fingerprint Meterpreter (patrón de puertos efímeros)
        {"type": "ioc", "value": "meterpreter_port_pattern"},
    ]),
    # ── Cobalt Strike ─────────────────────────────────────────────────────────
    C2Signature("CobaltStrike", "Cobalt Strike Beacon C2 framework", 60, [
        {"type": "port", "value": 50050},
        {"type": "port", "value": 50051},
        {"type": "port", "value": 8080},
        {"type": "port", "value": 8443},
        {"type": "port", "value": 443},
        {"type": "cmdline", "value": r"cobaltstrike|beacon\.(x64|x86|dll)|cobalt_strike|cs\.jar|teamserver"},
        {"type": "procname", "value": r"^(java|cobaltstrike|beacon)"},
        # Cobalt Strike default sleep + jitter: intervalos ~60s con jitter ~30%
        {"type": "beacon_interval", "interval": 60, "jitter_max": 0.35},
        {"type": "beacon_interval", "interval": 300, "jitter_max": 0.35},
        {"type": "ioc", "value": "cs_malleable_profile"},  # puertos arbitrarios
    ]),
    # ── Sliver ────────────────────────────────────────────────────────────────
    C2Signature("Sliver", "BishopFox Sliver C2 framework", 58, [
        {"type": "port", "value": 31337},
        {"type": "port", "value": 31338},
        {"type": "port", "value": 8888},
        {"type": "port", "value": 9001},
        {"type": "port", "value": 443},
        {"type": "cmdline", "value": r"sliver[-_](client|server)|implant.*sliver|/tmp/[a-zA-Z]{8,}"},
        {"type": "procname", "value": r"^sliver"},
        {"type": "beacon_interval", "interval": 60, "jitter_max": 0.50},
    ]),
    # ── Empire / PowerShell Empire ────────────────────────────────────────────
    C2Signature("Empire", "BC-Security PowerShell Empire C2", 55, [
        {"type": "port", "value": 1234},
        {"type": "port", "value": 7777},
        {"type": "port", "value": 443},
        {"type": "port", "value": 80},
        {"type": "cmdline", "value": r"empire|invoke-empire|powershell.*-enc|stager\.ps1|launcher\.bat|empire_agent"},
        {"type": "procname", "value": r"^(python3?|empire|powershell|pwsh)$"},
        {"type": "beacon_interval", "interval": 5, "jitter_max": 0.40},
    ]),
    # ── Brute Ratel ───────────────────────────────────────────────────────────
    C2Signature("BruteRatel", "Brute Ratel C4 commercial C2", 62, [
        {"type": "port", "value": 443},
        {"type": "port", "value": 8443},
        {"type": "port", "value": 2083},
        {"type": "cmdline", "value": r"brute.?ratel|badger|brc4"},
        {"type": "procname", "value": r"^(badger|brute_ratel)"},
    ]),
    # ── Havoc ─────────────────────────────────────────────────────────────────
    C2Signature("Havoc", "Havoc C2 Framework (HavocFramework)", 58, [
        {"type": "port", "value": 40056},
        {"type": "port", "value": 443},
        {"type": "port", "value": 8080},
        {"type": "cmdline", "value": r"havoc|demon\.x(64|86)|teamserver.*havoc"},
        {"type": "procname", "value": r"^(havoc|demon)"},
        {"type": "beacon_interval", "interval": 2, "jitter_max": 0.30},
    ]),
    # ── Pupy RAT ──────────────────────────────────────────────────────────────
    C2Signature("Pupy", "Pupy RAT cross-platform backdoor", 52, [
        {"type": "port", "value": 9999},
        {"type": "port", "value": 443},
        {"type": "cmdline", "value": r"pupy|pupyrat|pupy\.py|pupy_server"},
        {"type": "procname", "value": r"^(python3?|pupy)$"},
    ]),
    # ── Merlin ────────────────────────────────────────────────────────────────
    C2Signature("Merlin", "Merlin C2 Go-based HTTP/2 C2", 54, [
        {"type": "port", "value": 443},
        {"type": "port", "value": 8443},
        {"type": "cmdline", "value": r"merlin[-_]?(agent|server|client)|merlinAgent"},
        {"type": "procname", "value": r"^merlin"},
    ]),
    # ── Covenant ──────────────────────────────────────────────────────────────
    C2Signature("Covenant", "Covenant .NET C2 framework", 54, [
        {"type": "port", "value": 7443},
        {"type": "port", "value": 443},
        {"type": "cmdline", "value": r"covenant|grunt|dotnet.*covenant|GruntHTTP"},
        {"type": "procname", "value": r"^(dotnet|covenant)"},
    ]),
    # ── Posh-C2 ───────────────────────────────────────────────────────────────
    C2Signature("PoshC2", "PoshC2 PowerShell C2 proxy", 52, [
        {"type": "port", "value": 443},
        {"type": "port", "value": 8080},
        {"type": "cmdline", "value": r"poshc2|posh-c2|FComServer|ImplantCore|posh_dropper"},
        {"type": "procname", "value": r"^(python3?|powershell|pwsh)$"},
    ]),
    # ── Mythic ────────────────────────────────────────────────────────────────
    C2Signature("Mythic", "Mythic C2 collaborative framework", 56, [
        {"type": "port", "value": 7443},
        {"type": "port", "value": 443},
        {"type": "port", "value": 80},
        {"type": "cmdline", "value": r"mythic|poseidon_agent|apfell|atlas_agent"},
        {"type": "procname", "value": r"^(poseidon|apfell|atlas|mythic)"},
    ]),
    # ── Quasar RAT ────────────────────────────────────────────────────────────
    C2Signature("QuasarRAT", "Quasar Remote Administration Tool", 50, [
        {"type": "port_range", "min": 4782, "max": 4785},
        {"type": "cmdline", "value": r"quasar|Client\.exe|QuasarRAT"},
        {"type": "procname", "value": r"^(Client|QuasarRAT|quasar)"},
    ]),
    # ── Netcat/Socat shells genéricos ─────────────────────────────────────────
    C2Signature("NetcatShell", "Netcat/Socat reverse shell", 45, [
        {"type": "cmdline", "value": r"(nc|ncat|netcat|socat)\s+.*(\d{1,3}\.){3}\d{1,3}\s+\d+"},
        {"type": "cmdline", "value": r"socat.*exec.*bash|socat.*pty"},
    ]),
    # ── DNS-over-HTTPS C2 (DoH) ───────────────────────────────────────────────
    C2Signature("DNS-C2", "DNS tunneling / C2-over-DNS", 40, [
        {"type": "port", "value": 53},
        {"type": "cmdline", "value": r"dnscat|iodine|dns2tcp|dnscapy"},
    ]),
]

def match_signatures(c: "Conn") -> List[Tuple[str, str, int]]:
    """Evalúa firmas C2 contra una conexión. Devuelve lista de (nombre, desc, bonus)."""
    matches = []
    p = c.proc
    pn = p.name.lower() if p and p.name else ""
    cmd = p.cmdline.lower() if p and p.cmdline else ""
    rport = c.remote_port
    lport = c.local_port
    for sig in C2_SIGNATURES:
        hit = False
        for chk in sig.checks:
            t = chk["type"]
            if t == "port":
                if rport == chk["value"] or lport == chk["value"]:
                    hit = True; break
            elif t == "port_range":
                if chk["min"] <= rport <= chk["max"] or chk["min"] <= lport <= chk["max"]:
                    hit = True; break
            elif t == "cmdline" and cmd:
                if re.search(chk["value"], cmd, re.I):
                    hit = True; break
            elif t == "procname" and pn:
                if re.search(chk["value"], pn, re.I):
                    hit = True; break
            elif t == "beacon_interval":
                # se verifica externamente en Engine
                pass
        if hit:
            matches.append((sig.name, sig.description, sig.score_bonus))
    return matches


class Sev(IntEnum):
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4

SEV_META = {
    Sev.INFO:     ("INFO",    "\033[37m",    "·"),
    Sev.LOW:      ("BAJO",    "\033[36m",    "○"),
    Sev.MEDIUM:   ("MEDIO",   "\033[33m",    "●"),
    Sev.HIGH:     ("ALTO",    "\033[91m",    "▲"),
    Sev.CRITICAL: ("CRÍTICO", "\033[31;1m",  "█"),
}

RST = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"

# Contador global para IDs únicos de conexiones
_conn_id_counter = 0
_conn_id_lock = threading.Lock()

def next_conn_id() -> int:
    global _conn_id_counter
    with _conn_id_lock:
        _conn_id_counter += 1
        return _conn_id_counter


@dataclass
class ProcInfo:
    pid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    uid: int = -1
    ppid: int = 0
    parent_name: str = ""
    parent_chain: List[Tuple[int, str]] = field(default_factory=list)
    create_time: float = 0.0
    threads: int = 0
    fd_count: int = 0
    fd_types: Dict[str, int] = field(default_factory=dict)
    stdin_is_socket: bool = False
    stdout_is_socket: bool = False
    stderr_is_socket: bool = False
    stdin_is_pipe: bool = False
    stdout_is_pipe: bool = False
    stderr_is_pipe: bool = False
    socket_inodes: Set[int] = field(default_factory=set)
    children_pids: List[int] = field(default_factory=list)
    io_read: int = -1
    io_write: int = -1
    exe_deleted: bool = False
    mem_suspicious_regions: int = 0
    env_suspect_keys: List[str] = field(default_factory=list)
    maps_rwx_count: int = 0


@dataclass
class Conn:
    protocol: str = "tcp"
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    state: str = ""
    inode: int = 0
    family: str = "IPv4"
    pid: int = 0
    proc: Optional[ProcInfo] = None
    score: float = 0.0
    severity: Sev = Sev.INFO
    tags: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    source: str = ""
    conn_id: int = field(default_factory=next_conn_id)
    sig_matches: List[Tuple[str, str, int]] = field(default_factory=list)


@dataclass
class BeaconTracker:
    timestamps: List[float] = field(default_factory=list)
    intervals: List[float] = field(default_factory=list)
    avg_interval: float = 0.0
    jitter_pct: float = 1.0
    is_beacon: bool = False
    confidence: float = 0.0


def is_root() -> bool:
    if SYSTEM == "windows":
        try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except: return False
    return os.geteuid() == 0

def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in PRIVATE_NETS)
    except: return False

def is_loopback(ip):
    try: return ipaddress.ip_address(ip).is_loopback
    except: return ip.startswith("127.") or ip == "::1"

def hex2ip(h):
    if len(h) == 8:
        return socket.inet_ntoa(struct.pack("=I", int(h, 16)))
    elif len(h) == 32:
        raw = b""
        for i in range(0, 32, 8):
            raw += struct.pack("=I", int(h[i:i+8], 16))
        return socket.inet_ntop(socket.AF_INET6, raw)
    return h

def hex2port(h): return int(h, 16)

def fmt_b(n):
    if n < 0: return "—"
    for u in ("B","K","M","G","T"):
        if abs(n) < 1024.0: return f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024.0
    return f"{n:.1f}P"

def fmt_t(s):
    if s < 0: return "—"
    if s < 60: return f"{s:.0f}s"
    if s < 3600: return f"{int(s)//60}m{int(s)%60:02d}s"
    if s < 86400:
        h, r = divmod(int(s), 3600); return f"{h}h{r//60:02d}m"
    d, r = divmod(int(s), 86400); return f"{d}d{r//3600:02d}h"

def trunc(t, w):
    if not t: return ""
    return t if len(t) <= w else t[:w-1] + "…"

def sread(path):
    try:
        with open(path, "r", errors="replace") as f: return f.read()
    except: return ""

def sreadlink(path):
    try: return os.readlink(path)
    except: return ""

def runcmd(cmd, timeout=4.0):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "LC_ALL": "C"})
        return r.stdout
    except: return ""


# ═══════════════════════════════════════════════════════════════════════
# PARSER /proc/net/*
# ═══════════════════════════════════════════════════════════════════════

def parse_proc_net_content(content, proto, family):
    results = []
    lines = content.strip().split("\n")
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10: continue
        try:
            la_raw, lp_raw = parts[1].split(":")
            ra_raw, rp_raw = parts[2].split(":")
            la = hex2ip(la_raw); lp = hex2port(lp_raw)
            ra = hex2ip(ra_raw); rp = hex2port(rp_raw)
            st = TCP_STATES.get(parts[3], parts[3]) if proto == "tcp" else "ACTIVE"
            inode = int(parts[9])
            if family == "IPv6":
                if la.startswith("::ffff:"): la = la[7:]
                if ra.startswith("::ffff:"): ra = ra[7:]
            if ra in ("0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0"): ra = ""; rp = 0
            results.append(Conn(protocol=proto, local_addr=la, local_port=lp,
                remote_addr=ra, remote_port=rp, state=st, inode=inode, family=family))
        except: continue
    return results


def read_proc_net_all():
    files = {"tcp": ("tcp","IPv4"), "tcp6": ("tcp","IPv6"),
             "udp": ("udp","IPv4"), "udp6": ("udp","IPv6")}

    def try_read_file(name):
        paths_to_try = [f"/proc/self/net/{name}", f"/proc/net/{name}"]
        for p in paths_to_try:
            c = sread(p)
            if c and len(c.splitlines()) > 1: return c, f"open({p.split('/')[-3]})"
        for p in paths_to_try:
            c = runcmd(["cat", p], timeout=2)
            if c and len(c.splitlines()) > 1: return c, f"cat({p.split('/')[-3]})"
        for p in paths_to_try:
            try:
                c = os.popen(f"cat {p} 2>/dev/null").read()
                if c and len(c.splitlines()) > 1: return c, f"popen({p.split('/')[-3]})"
            except: pass
        for p in paths_to_try:
            c = runcmd(["sh", "-c", f"cat {p}"], timeout=2)
            if c and len(c.splitlines()) > 1: return c, f"sh({p.split('/')[-3]})"
        return "", ""

    all_conns = []; methods = set()
    for name, (proto, family) in files.items():
        content, method = try_read_file(name)
        if content:
            conns = parse_proc_net_content(content, proto, family)
            for c in conns: c.source = f"proc/{method}"
            all_conns.extend(conns)
            if method: methods.add(method.split("(")[0])
    return all_conns, "+".join(sorted(methods)) if methods else ""


def build_inode_pid_map():
    imap = {}
    try: entries = os.listdir("/proc")
    except: return imap
    for e in entries:
        if not e.isdigit(): continue
        fd_dir = f"/proc/{e}/fd"
        try: fds = os.listdir(fd_dir)
        except: continue
        for fn in fds:
            t = sreadlink(f"{fd_dir}/{fn}")
            if t.startswith("socket:["):
                try: imap[int(t[8:-1])] = int(e)
                except: pass
    return imap


_proc_cache = {}

def get_proc_info(pid, deep=False):
    if pid in _proc_cache: return _proc_cache[pid]
    info = ProcInfo(pid=pid)
    base = f"/proc/{pid}"
    if not os.path.isdir(base):
        _proc_cache[pid] = info; return info

    for line in sread(f"{base}/status").split("\n"):
        k = line.split(":", 1)
        if len(k) < 2: continue
        key, val = k[0].strip(), k[1].strip()
        if key == "Name": info.name = val
        elif key == "PPid":
            try: info.ppid = int(val)
            except: pass
        elif key == "Uid":
            try: info.uid = int(val.split()[0])
            except: pass
        elif key == "Threads":
            try: info.threads = int(val)
            except: pass

    info.exe = sreadlink(f"{base}/exe")
    if info.exe.endswith(" (deleted)"):
        info.exe_deleted = True; info.exe = info.exe.replace(" (deleted)", "")

    raw = sread(f"{base}/cmdline")
    if raw: info.cmdline = raw.replace("\x00", " ").strip()

    stat = sread(f"{base}/stat")
    if stat:
        try:
            rp = stat.rfind(")")
            if rp > 0:
                after = stat[rp+2:].split()
                if len(after) >= 20:
                    ticks = int(after[19])
                    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
                    up = sread("/proc/uptime")
                    if up: info.create_time = time.time() - float(up.split()[0]) + ticks/hz
        except: pass

    fd_dir = f"{base}/fd"
    try:
        fds = os.listdir(fd_dir)
        info.fd_count = len(fds)
        for fn in fds:
            t = sreadlink(f"{fd_dir}/{fn}")
            if not t: continue
            if t.startswith("socket:["):
                info.fd_types["socket"] = info.fd_types.get("socket", 0) + 1
                try: info.socket_inodes.add(int(t[8:-1]))
                except: pass
            elif t.startswith("pipe:["): info.fd_types["pipe"] = info.fd_types.get("pipe", 0) + 1
            elif t.startswith("/dev/pts") or t.startswith("/dev/tty"):
                info.fd_types["tty"] = info.fd_types.get("tty", 0) + 1
            elif t.startswith("/dev/null"):
                info.fd_types["devnull"] = info.fd_types.get("devnull", 0) + 1
            else: info.fd_types["file"] = info.fd_types.get("file", 0) + 1
            if fn == "0":
                info.stdin_is_socket = t.startswith("socket:[")
                info.stdin_is_pipe = t.startswith("pipe:[")
            elif fn == "1":
                info.stdout_is_socket = t.startswith("socket:[")
                info.stdout_is_pipe = t.startswith("pipe:[")
            elif fn == "2":
                info.stderr_is_socket = t.startswith("socket:[")
                info.stderr_is_pipe = t.startswith("pipe:[")
    except: pass

    for line in sread(f"{base}/io").split("\n"):
        if line.startswith("read_bytes:"):
            try: info.io_read = int(line.split(":")[1].strip())
            except: pass
        elif line.startswith("write_bytes:"):
            try: info.io_write = int(line.split(":")[1].strip())
            except: pass

    if info.ppid > 0:
        for line in sread(f"/proc/{info.ppid}/status").split("\n"):
            if line.startswith("Name:"):
                info.parent_name = line.split(":", 1)[1].strip(); break

    chain = []; cpid = info.ppid; visited = {info.pid}
    for _ in range(6):
        if cpid <= 1 or cpid in visited: break
        visited.add(cpid); name = ""; ppid = 0
        for line in sread(f"/proc/{cpid}/status").split("\n"):
            if line.startswith("Name:"): name = line.split(":",1)[1].strip()
            elif line.startswith("PPid:"):
                try: ppid = int(line.split(":",1)[1].strip())
                except: pass
        if name: chain.append((cpid, name))
        cpid = ppid
    info.parent_chain = chain

    ch = sread(f"{base}/task/{pid}/children")
    if ch: info.children_pids = [int(c) for c in ch.split() if c.isdigit()]

    if deep:
        maps = sread(f"{base}/maps")
        for line in maps.split("\n"):
            parts = line.split()
            if len(parts) >= 2 and len(parts[1]) >= 4:
                if parts[1][0]=='r' and parts[1][1]=='w' and parts[1][2]=='x':
                    info.maps_rwx_count += 1
        env = sread(f"{base}/environ")
        if env:
            for sp in ["LD_PRELOAD", "LD_LIBRARY_PATH", "HISTFILE=/dev/null",
                        "PYTHONDONTWRITEBYTECODE", "TERM=dumb"]:
                if sp in env.replace("\x00", "\n"):
                    info.env_suspect_keys.append(sp.split("=")[0])
        try:
            checked = 0
            sus_strings = [b"/bin/sh", b"/bin/bash", b"socket", b"reverse",
                           b"connect_back", b"pty.spawn", b"subprocess", b"PRIVMSG", b"beacon"]
            for mline in maps.split("\n"):
                if checked >= 5: break
                parts = mline.split()
                if len(parts) < 2: continue
                perms = parts[1]
                if perms[0] != 'r': continue
                nm = parts[5] if len(parts) > 5 else ""
                if nm and not nm.startswith("["): continue
                ar = parts[0].split("-")
                if len(ar) != 2: continue
                start = int(ar[0], 16); end = int(ar[1], 16); sz = end - start
                if sz > 1048576: continue
                with open(f"{base}/mem", "rb") as mem:
                    mem.seek(start); data = mem.read(min(sz, 65536))
                for ss in sus_strings:
                    if ss in data: info.mem_suspicious_regions += 1; break
                checked += 1
        except: pass

    _proc_cache[pid] = info
    return info


def get_proc_info_psutil(pid):
    if pid in _proc_cache: return _proc_cache[pid]
    info = ProcInfo(pid=pid)
    if not HAS_PSUTIL or pid <= 0: return info
    try:
        p = psutil.Process(pid); info.name = p.name() or ""
        try: info.exe = p.exe() or ""
        except: pass
        try: info.cmdline = " ".join(p.cmdline()) if p.cmdline() else ""
        except: pass
        try:
            info.ppid = p.ppid(); par = p.parent()
            if par: info.parent_name = par.name()
        except: pass
        try: info.create_time = p.create_time()
        except: pass
        try:
            io = p.io_counters(); info.io_read = io.read_bytes; info.io_write = io.write_bytes
        except: pass
        try: info.threads = p.num_threads()
        except: pass
        chain = []; cpid = info.ppid; visited = {pid}
        for _ in range(6):
            if cpid <= 1 or cpid in visited: break
            visited.add(cpid)
            try:
                pp = psutil.Process(cpid); chain.append((cpid, pp.name())); cpid = pp.ppid()
            except: break
        info.parent_chain = chain
    except: pass
    _proc_cache[pid] = info
    return info


def split_addr(raw):
    if raw.startswith("["):
        be = raw.rfind("]"); addr = raw[1:be]
        port = int(raw[be+2:]) if be+2 < len(raw) else 0
        return addr, port
    cc = raw.count(":")
    if cc > 1:
        last = raw.rfind(":"); return raw[:last], int(raw[last+1:]) if last+1 < len(raw) else 0
    last = raw.rfind(":")
    if last < 0: return raw, 0
    try: port = int(raw[last+1:])
    except: port = 0
    return (raw[:last] if raw[:last] != "*" else ""), port


# ═══════════════════════════════════════════════════════════════════════
# COLLECTOR
# ═══════════════════════════════════════════════════════════════════════

class Collector:
    def __init__(self, privileged, diag=False):
        self.privileged = privileged
        self.diag = diag
        self.ok = []
        self.fail = []

    def collect(self):
        global _proc_cache
        _proc_cache.clear()
        self.ok = []; self.fail = []
        all_conns = []; seen = set()

        def dk(c):
            return f"{c.protocol}:{c.local_addr}:{c.local_port}:{c.remote_addr}:{c.remote_port}:{c.state}"

        def add(conns, method):
            added = 0
            for c in conns:
                k = dk(c)
                if k not in seen:
                    seen.add(k); c.source = method; all_conns.append(c); added += 1
                elif c.pid > 0:
                    for ex in all_conns:
                        if dk(ex) == k and ex.pid == 0:
                            ex.pid = c.pid; ex.source += f"+{method}"; break
            if conns: self.ok.append(f"{method}({len(conns)}/{added}new)")
            else: self.fail.append(method)

        if SYSTEM != "windows":
            pn_conns, pn_method = read_proc_net_all()
            if pn_conns: add(pn_conns, f"proc/{pn_method}")
            else: self.fail.append("/proc/net")

        imap = {}
        if SYSTEM != "windows":
            imap = build_inode_pid_map()
            mapped = 0
            for c in all_conns:
                if c.pid == 0 and c.inode > 0 and c.inode in imap:
                    c.pid = imap[c.inode]; mapped += 1
            if imap: self.ok.append(f"inode-map({len(imap)}inodes,{mapped}mapped)")

        if SYSTEM != "windows":
            ss_out = runcmd(["ss", "-tunap", "--no-header"], timeout=4)
            if not ss_out: ss_out = runcmd(["ss", "-tunap"], timeout=4)
            if ss_out:
                ss_conns = self._parse_ss(ss_out)
                if ss_conns: add(ss_conns, "ss")
            else: self.fail.append("ss")

        if SYSTEM == "windows":
            ns_out = runcmd(["netstat", "-ano"], timeout=6)
        else:
            ns_out = runcmd(["netstat", "-tunap"], timeout=4)
            if not ns_out: ns_out = runcmd(["netstat", "-tuna"], timeout=4)
        if ns_out:
            ns_conns = self._parse_netstat(ns_out)
            if ns_conns: add(ns_conns, "netstat")
        else: self.fail.append("netstat")

        if HAS_PSUTIL:
            psu_conns = self._try_psutil()
            if psu_conns: add(psu_conns, "psutil")
            else: self.fail.append("psutil(vacío)")
        else: self.fail.append("psutil(no inst)")

        if SYSTEM != "windows":
            lsof_conns = self._try_lsof()
            if lsof_conns: add(lsof_conns, "lsof")

        for c in all_conns:
            if c.pid > 0 and c.proc is None:
                if os.path.isdir(f"/proc/{c.pid}"):
                    c.proc = get_proc_info(c.pid, deep=self.privileged)
                elif HAS_PSUTIL:
                    c.proc = get_proc_info_psutil(c.pid)

        desc = ", ".join(self.ok) if self.ok else "ninguno"
        return all_conns, desc

    def _parse_ss(self, out):
        conns = []
        for line in out.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("State") or line.startswith("Netid"): continue
            try:
                parts = line.split()
                if len(parts) < 5: continue
                idx = 0; proto = "tcp"
                if parts[0] in ("tcp", "udp"): proto = parts[0]; idx = 1
                state_raw = parts[idx]
                known = {"ESTAB","LISTEN","SYN-SENT","SYN-RECV","FIN-WAIT-1",
                         "FIN-WAIT-2","TIME-WAIT","CLOSE-WAIT","LAST-ACK","CLOSING","CLOSE","UNCONN"}
                if state_raw in known:
                    local_raw = parts[idx+3] if idx+3 < len(parts) else ""
                    remote_raw = parts[idx+4] if idx+4 < len(parts) else ""
                else:
                    state_raw = "ACTIVE"
                    local_raw = parts[idx+2] if idx+2 < len(parts) else ""
                    remote_raw = parts[idx+3] if idx+3 < len(parts) else ""
                if not local_raw or not remote_raw: continue
                la, lp = split_addr(local_raw); ra, rp = split_addr(remote_raw)
                sm = {"ESTAB":"ESTABLISHED","UNCONN":"ACTIVE","SYN-SENT":"SYN_SENT",
                      "SYN-RECV":"SYN_RECV","FIN-WAIT-1":"FIN_WAIT1","FIN-WAIT-2":"FIN_WAIT2",
                      "TIME-WAIT":"TIME_WAIT","CLOSE-WAIT":"CLOSE_WAIT","LAST-ACK":"LAST_ACK"}
                state = sm.get(state_raw, state_raw)
                pid = 0; m = re.search(r'pid=(\d+)', line)
                if m: pid = int(m.group(1))
                if ra in ("*","0.0.0.0","::","::0"): ra = ""; rp = 0
                conns.append(Conn(protocol=proto[:3], local_addr=la, local_port=lp,
                    remote_addr=ra, remote_port=rp, state=state, pid=pid))
            except: continue
        return conns

    def _parse_netstat(self, out):
        conns = []
        for line in out.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("Active") or line.startswith("Proto"): continue
            try:
                parts = line.split()
                if len(parts) < 4: continue
                proto = parts[0].lower()
                if SYSTEM == "windows":
                    la, lp = split_addr(parts[1]); ra, rp = split_addr(parts[2])
                    state = parts[3] if proto.startswith("tcp") and len(parts)>3 else "ACTIVE"
                    pid = int(parts[4]) if len(parts)>4 and parts[4].isdigit() else 0
                else:
                    la, lp = split_addr(parts[3]); ra, rp = split_addr(parts[4])
                    state = parts[5] if len(parts)>5 and proto.startswith("tcp") else "ACTIVE"
                    pid = 0
                    if len(parts) >= 7 and "/" in parts[6]:
                        try: pid = int(parts[6].split("/")[0])
                        except: pass
                if ra in ("*","0.0.0.0","::","::0","-"): ra = ""; rp = 0
                conns.append(Conn(protocol="tcp" if "tcp" in proto else "udp",
                    local_addr=la, local_port=lp, remote_addr=ra, remote_port=rp,
                    state=state, pid=pid))
            except: continue
        return conns

    def _try_psutil(self):
        if not HAS_PSUTIL: return []
        conns = []
        for kind in ("inet","inet6"):
            try:
                for c in psutil.net_connections(kind=kind):
                    la = c.laddr; ra = c.raddr
                    r_addr = ra.ip if ra else ""; r_port = ra.port if ra else 0
                    if r_addr in ("0.0.0.0","::","::0"): r_addr = ""; r_port = 0
                    conns.append(Conn(
                        protocol="udp" if c.type == socket.SOCK_DGRAM else "tcp",
                        local_addr=la.ip if la else "", local_port=la.port if la else 0,
                        remote_addr=r_addr, remote_port=r_port,
                        state=c.status if c.status else "NONE", pid=c.pid or 0))
            except: continue
        return conns

    def _try_lsof(self):
        out = runcmd(["lsof", "-i", "-n", "-P", "+c", "0"], timeout=5)
        if not out: return []
        conns = []
        for line in out.strip().split("\n"):
            if line.startswith("COMMAND"): continue
            parts = line.split()
            if len(parts) < 9: continue
            try:
                pid = int(parts[1]); nf = parts[8]
                state = parts[9].strip("()") if len(parts) > 9 else ""
                if "->" in nf:
                    lr, rr = nf.split("->")
                    la, lp = split_addr(lr); ra, rp = split_addr(rr)
                elif ":" in nf:
                    la, lp = split_addr(nf); ra, rp = "", 0
                else: continue
                proto = "udp" if "UDP" in parts[7] else "tcp"
                conns.append(Conn(protocol=proto, local_addr=la, local_port=lp,
                    remote_addr=ra, remote_port=rp, state=state, pid=pid))
            except: continue
        return conns


# ═══════════════════════════════════════════════════════════════════════
# ENGINE (heurísticas + firmas)
# ═══════════════════════════════════════════════════════════════════════

class Engine:
    def __init__(self, whitelist=None):
        self.wl = []
        self.beacons = {}
        for e in (whitelist or []):
            e = e.strip()
            if not e: continue
            try:
                if "/" in e: self.wl.append(ipaddress.ip_network(e, strict=False))
                else:
                    a = ipaddress.ip_address(e)
                    self.wl.append(ipaddress.ip_network(f"{e}/{32 if a.version==4 else 128}", strict=False))
            except: pass

    def _is_wl(self, ip):
        try:
            a = ipaddress.ip_address(ip); return any(a in n for n in self.wl)
        except: return False

    def analyze(self, c: Conn) -> Conn:
        if c.remote_addr and self._is_wl(c.remote_addr):
            c.severity = Sev.INFO; c.tags = ["WL"]; c.score = 0; return c

        s = 0.0; tags = []; p = c.proc
        hp = p is not None and p.name
        pn = p.name.lower() if hp else ""
        cmd = p.cmdline.lower() if hp and p.cmdline else ""
        exe = p.exe.lower() if hp and p.exe else ""

        ish = hp and (pn.rstrip(".exe") in SHELL_BINS or
              any(x in pn for x in ("bash","mksh","/sh","cmd.exe","powershell","pwsh")))
        ise = hp and any(e in pn or e in exe for e in SCRIPT_ENGINES)
        hr = bool(c.remote_addr) and not is_loopback(c.remote_addr)
        est = c.state in ("ESTABLISHED","ACTIVE","CLOSE_WAIT")

        if hp and est:
            if p.stdin_is_socket and p.stdout_is_socket: s+=55; tags.append("FD→SOCK")
            elif p.stdin_is_socket or p.stdout_is_socket: s+=35; tags.append("FD½→SOCK")
            elif p.stdin_is_pipe and p.stdout_is_pipe and p.stderr_is_pipe:
                if ish or ise: s+=25; tags.append("FD-PIPE")

        if hp and hr and est:
            if ish: s+=40; tags.append("SHELL→NET")
            elif ise: s+=25; tags.append("INTERP→NET")

        if hp and p.fd_types.get("socket",0) >= 2 and hr and est and ise:
            s+=10; tags.append("MULTI-SOCK")

        if hp and p.parent_chain:
            pnames = [x[1].lower() for x in p.parent_chain]; chain_s = " ".join(pnames)
            webs = {"apache","nginx","httpd","lighttpd","iis","tomcat","gunicorn","uwsgi","caddy"}
            if any(w in chain_s for w in webs) and (ish or ise): s+=35; tags.append("WEBSHELL")
            if ish and any(e in chain_s for e in SCRIPT_ENGINES): s+=20; tags.append("STAGED")
            if len(p.parent_chain)>=2 and p.parent_chain[-1][1].lower() in ("init","systemd","launchd"):
                if ish and hr: s+=15; tags.append("SVC→SH")

        if c.state == "LISTEN" and c.local_port > 1024 and hp and (ish or ise):
            s+=35; tags.append("BIND-SHELL")
            if c.local_port > 10000: s+=10

        tp = c.remote_port if hr else c.local_port
        if tp in C2_SUSPECT_PORTS:
            if tp in COMMON_PORTS:
                if ish or ise: s+=12; tags.append(f"C2P({tp})")
            else: s+=18; tags.append(f"C2P({tp})")

        if hp and not p.exe and est and hr: s+=20; tags.append("NO-BIN")
        if hp and p.exe_deleted: s+=25; tags.append("EXE-DEL!")
        if hp and p.exe:
            for sp in ("/tmp/","/dev/shm/","/var/tmp/","/data/local/tmp/"):
                if p.exe.startswith(sp): s+=15; tags.append("EXE-TMP"); break

        if cmd:
            for pat, pts, tag in [
                (r"-e\s+(bash|sh|cmd|powershell|pwsh)",30,"EXEC-FLAG"),
                (r"(nc|ncat|netcat|socat)\s+.*\d+",35,"NETCAT"),
                (r"mkfifo|/dev/tcp|/dev/udp",40,"PIPE-REDIR"),
                (r"base64.*decode|eval\s*\(|exec\s*\(",18,"EVAL"),
                (r"socket\s*\.\s*connect|pty\s*\.\s*spawn",25,"SOCK-SPAWN"),
                (r"subprocess\s*\.\s*(call|popen|run)",12,"SUBPROC"),
                (r"\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}",20,"HEX"),
                (r"iex\s*\(|invoke-expression|downloadstring",30,"PS-REM"),
                (r"certutil.*urlcache|bitsadmin.*transfer",25,"LOLBIN"),
                (r"(wget|curl).*\|\s*(bash|sh|python|perl)",35,"PIPE-EXEC"),
                (r"-c\s+['\"]import\s+socket",30,"PY-INLINE"),
                (r"bash\s+-i\s+>",40,"BASH-REDIR"),
                (r"os\.(dup2|popen)|pty\.",30,"DUP-PTY"),
                (r"connect_back|reverse.*shell|bind.*shell",35,"REVSHELL"),
            ]:
                if re.search(pat, cmd):
                    s += pts
                    if tag not in tags: tags.append(tag)

        if hp and p.create_time > 0 and est and hr:
            alive = time.time() - p.create_time
            if alive < 10: s+=15; tags.append("NUEVO<10s")
            elif alive < 30: s+=8; tags.append("JOVEN")

        if hp and p.io_read>0 and p.io_write>0 and ish and p.io_read<50000 and p.io_write<50000 and hr:
            s+=8; tags.append("IO-CMD")

        if hr and est:
            bk = f"{c.remote_addr}:{c.remote_port}"; self._beacon(bk)
            bt = self.beacons.get(bk)
            if bt and bt.is_beacon: s += 25*bt.confidence; tags.append(f"BCN({bt.avg_interval:.0f}s)")

        if c.remote_port==53 and hr and not is_private(c.remote_addr):
            if hp and pn not in ("systemd-resolve","dnsmasq","resolved","unbound"):
                s+=15; tags.append("DNS-EXT")

        if hp and c.remote_port in (443,8443,4443) and est:
            browsers = {"firefox","chrome","chromium","safari","edge","opera","brave","vivaldi",
                        "webview","electron","wget","curl","apt","pip","com.android"}
            if not any(b in pn for b in browsers):
                if ise or ish: s+=15; tags.append("TLS-NOBR")

        if c.pid == 0 and hr and est: s+=5; tags.append("PID?")

        if hp and p.create_time > 0 and time.time()-p.create_time > 300 and ise and hr and est:
            s+=10; tags.append("PERSIST")

        if hp and p.maps_rwx_count > 2: s+=20; tags.append(f"RWX({p.maps_rwx_count})")
        if hp and p.mem_suspicious_regions > 0: s+=15; tags.append(f"MEM({p.mem_suspicious_regions})")
        if hp and p.env_suspect_keys: s+=10; tags.append("ENV:"+",".join(p.env_suspect_keys[:2]))

        # ── Firmas C2 conocidas ──────────────────────────────────────────────
        sig_matches = match_signatures(c)
        c.sig_matches = sig_matches
        for sname, sdesc, sbonus in sig_matches:
            if f"SIG:{sname}" not in tags:
                s += sbonus; tags.append(f"SIG:{sname}")

        c.score = min(s, 100.0); c.tags = tags
        if s >= 65: c.severity = Sev.CRITICAL
        elif s >= 45: c.severity = Sev.HIGH
        elif s >= 25: c.severity = Sev.MEDIUM
        elif s >= 8: c.severity = Sev.LOW
        else: c.severity = Sev.INFO
        return c

    def _beacon(self, key):
        now = time.time()
        if key not in self.beacons:
            self.beacons[key] = BeaconTracker(timestamps=[now]); return
        bt = self.beacons[key]; bt.timestamps.append(now)
        bt.timestamps = [t for t in bt.timestamps if t > now - 1800]
        if len(bt.timestamps) < 4: return
        ts = sorted(bt.timestamps)
        bt.intervals = [ts[i+1]-ts[i] for i in range(len(ts)-1)]
        bt.avg_interval = sum(bt.intervals)/len(bt.intervals)
        if bt.avg_interval > 0.5:
            devs = [abs(iv-bt.avg_interval)/bt.avg_interval for iv in bt.intervals]
            bt.jitter_pct = sum(devs)/len(devs)
        else: bt.jitter_pct = 1.0
        if bt.jitter_pct < 0.30 and len(bt.intervals) >= 3:
            for ki in BEACON_INTERVALS:
                if abs(bt.avg_interval-ki) < ki*0.35:
                    bt.is_beacon = True
                    bt.confidence = max(0.4,1.0-bt.jitter_pct)*min(len(bt.intervals)/8,1.0); return
            if bt.jitter_pct < 0.12:
                bt.is_beacon = True; bt.confidence = 0.5*min(len(bt.intervals)/8,1.0)


# ═══════════════════════════════════════════════════════════════════════
# LOGGER
# ═══════════════════════════════════════════════════════════════════════

class Logger:
    def __init__(self, path=None):
        self.path = path; self.entries = []; self._lk = threading.Lock()
        if self.path:
            with open(self.path,"a") as f:
                f.write(f"\n{'='*60}\nSENTINEL {datetime.datetime.now().isoformat()}\n{'='*60}\n\n")

    def log(self, c):
        if c.severity < Sev.LOW: return
        sigs = [s[0] for s in c.sig_matches]
        e = {"ts":datetime.datetime.now().isoformat(),"id":c.conn_id,
             "sev":SEV_META[c.severity][0],"score":c.score,
             "pid":c.pid,"name":c.proc.name if c.proc else "?",
             "cmd":(c.proc.cmdline[:200] if c.proc and c.proc.cmdline else ""),
             "remote":f"{c.remote_addr}:{c.remote_port}","local":f"{c.local_addr}:{c.local_port}",
             "state":c.state,"tags":c.tags,"sigs":sigs,"src":c.source}
        with self._lk:
            self.entries.append(e)
            if self.path:
                try:
                    with open(self.path,"a") as f: f.write(json.dumps(e,ensure_ascii=False)+"\n")
                except: pass

    def export(self, path):
        with self._lk:
            with open(path,"w") as f: json.dump(self.entries, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════
# KILL ENGINE
# ═══════════════════════════════════════════════════════════════════════

def kill_pid(pid: int, force: bool = False) -> Tuple[bool, str]:
    """Mata un proceso por PID. Devuelve (éxito, mensaje)."""
    if pid <= 0: return False, f"PID inválido: {pid}"
    if SYSTEM == "windows":
        try:
            r = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True, text=True, timeout=5)
            ok = r.returncode == 0
            return ok, r.stdout.strip() or r.stderr.strip()
        except Exception as e:
            return False, str(e)
    else:
        sig = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.kill(pid, sig)
            time.sleep(0.3)
            # Verificar si realmente murió
            try:
                os.kill(pid, 0)
                # Aún vive → usar SIGKILL
                if not force:
                    os.kill(pid, signal.SIGKILL)
                    return True, f"SIGTERM ignorado → SIGKILL enviado a PID {pid}"
                return False, f"PID {pid} sigue activo tras SIGKILL"
            except ProcessLookupError:
                return True, f"PID {pid} terminado ({'SIGKILL' if force else 'SIGTERM'})"
            except PermissionError:
                return True, f"PID {pid} señal enviada (sin permiso para verificar)"
        except ProcessLookupError:
            return False, f"PID {pid} no existe"
        except PermissionError:
            return False, f"Permiso denegado para señal PID {pid} (necesita root)"
        except Exception as e:
            return False, str(e)


# ═══════════════════════════════════════════════════════════════════════
# TUI CURSES — MODO INTERACTIVO PROFESIONAL
# ═══════════════════════════════════════════════════════════════════════

# Paleta de colores curses (par_id → (fg, bg))
CP_HEADER    = 1   # cyan sobre negro
CP_SEP       = 2   # dim blanco
CP_CRITICAL  = 3   # rojo brillante
CP_HIGH      = 4   # rojo normal
CP_MEDIUM    = 5   # amarillo
CP_LOW       = 6   # cyan
CP_INFO      = 7   # blanco
CP_SEL       = 8   # negro sobre cyan (fila seleccionada)
CP_TITLE     = 9   # blanco brillante
CP_SIG       = 10  # magenta (firma C2)
CP_OK        = 11  # verde
CP_DIM       = 12  # gris
CP_KILL_OK   = 13  # verde sobre negro
CP_KILL_ERR  = 14  # rojo sobre negro
CP_PROMPT    = 15  # amarillo sobre azul oscuro

SEV_CP = {
    Sev.CRITICAL: CP_CRITICAL,
    Sev.HIGH:     CP_HIGH,
    Sev.MEDIUM:   CP_MEDIUM,
    Sev.LOW:      CP_LOW,
    Sev.INFO:     CP_INFO,
}

SEV_ICONS = {
    Sev.CRITICAL: "█",
    Sev.HIGH:     "▲",
    Sev.MEDIUM:   "●",
    Sev.LOW:      "○",
    Sev.INFO:     "·",
}

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_HEADER,   curses.COLOR_CYAN,    -1)
    curses.init_pair(CP_SEP,      curses.COLOR_WHITE,   -1)
    curses.init_pair(CP_CRITICAL, curses.COLOR_RED,     -1)
    curses.init_pair(CP_HIGH,     curses.COLOR_RED,     -1)
    curses.init_pair(CP_MEDIUM,   curses.COLOR_YELLOW,  -1)
    curses.init_pair(CP_LOW,      curses.COLOR_CYAN,    -1)
    curses.init_pair(CP_INFO,     curses.COLOR_WHITE,   -1)
    curses.init_pair(CP_SEL,      curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(CP_TITLE,    curses.COLOR_WHITE,   -1)
    curses.init_pair(CP_SIG,      curses.COLOR_MAGENTA, -1)
    curses.init_pair(CP_OK,       curses.COLOR_GREEN,   -1)
    curses.init_pair(CP_DIM,      8 if curses.COLORS >= 16 else curses.COLOR_WHITE, -1)
    curses.init_pair(CP_KILL_OK,  curses.COLOR_GREEN,   -1)
    curses.init_pair(CP_KILL_ERR, curses.COLOR_RED,     -1)
    curses.init_pair(CP_PROMPT,   curses.COLOR_YELLOW,  curses.COLOR_BLUE)


def safe_addstr(win, y, x, text, attr=0, max_w=None):
    """Escribe en curses sin crashear si se sale de pantalla."""
    try:
        h, w = win.getmaxyx()
        if y < 0 or y >= h or x >= w: return
        if max_w: text = text[:max_w]
        room = w - x - 1
        if room <= 0: return
        win.addstr(y, x, text[:room], attr)
    except curses.error: pass


def draw_hline(win, y, w, char="─", attr=0):
    try: win.addstr(y, 0, char * min(w, win.getmaxyx()[1]-1), attr)
    except curses.error: pass


class CursesTUI:
    """TUI interactivo con curses. Refresco automático + navegación + kill."""

    COL_SPEC = [
        # (header, width, key)
        ("ID",    5,  "conn_id"),
        ("SEV",   7,  "severity"),
        ("PTS",   5,  "score"),
        ("PID",   7,  "pid"),
        ("PROC",  14, "name"),
        ("REMOTO",26, "remote"),
        ("LP",    6,  "lport"),
        ("P",     3,  "proto"),
        ("ESTADO",12, "state"),
        ("TX",    6,  "tx"),
        ("RX",    6,  "rx"),
        ("VIVO",  6,  "uptime"),
        ("FIRMAS/TAGS", 0, "tags"),   # expansible
    ]

    def __init__(self, sentinel):
        self.sentinel = sentinel
        self.sel = 0           # fila seleccionada
        self.scroll = 0        # offset scroll vertical
        self.conns = []        # copia actual para render
        self.filter_sev = Sev.INFO   # filtro mínimo severidad
        self.show_detail = False
        self.detail_conn = None
        self.status_msg = ""   # mensaje en barra inferior
        self.status_color = CP_OK
        self.kill_mode = False  # esperando PID para kill
        self._lock = threading.Lock()

    def run(self, stdscr):
        init_colors()
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)

        # Hilo de refresco de datos
        def data_loop():
            while self.sentinel._run:
                self.sentinel._cycle_data()
                with self._lock:
                    self.conns = list(self.sentinel.last_conns)
                    # ajustar selección
                    visible = self._filtered()
                    if self.sel >= len(visible): self.sel = max(0, len(visible)-1)
                time.sleep(self.sentinel.interval)

        t = threading.Thread(target=data_loop, daemon=True)
        t.start()

        while self.sentinel._run:
            with self._lock:
                conns_snap = list(self.conns)
            self._draw(stdscr, conns_snap)
            stdscr.refresh()

            try: key = stdscr.getch()
            except curses.error: key = -1

            if key == -1:
                time.sleep(0.05); continue

            if self.kill_mode:
                self._handle_kill_input(stdscr, key)
            elif self.show_detail:
                if key in (ord('q'), ord('d'), ord('D'), 27):
                    self.show_detail = False
                    self.detail_conn = None
            else:
                self._handle_key(stdscr, key, conns_snap)

        # Cleanup
        curses.curs_set(1)

    def _filtered(self) -> List[Conn]:
        return [c for c in self.conns if c.severity >= self.filter_sev]

    def _draw(self, stdscr, conns):
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        visible = sorted(
            [c for c in conns if c.severity >= self.filter_sev],
            key=lambda c: c.score, reverse=True
        )

        if self.show_detail and self.detail_conn:
            self._draw_detail(stdscr, self.detail_conn, h, w)
            return

        row = 0
        row = self._draw_header(stdscr, row, w)
        row = self._draw_stats(stdscr, row, w, conns)
        row = self._draw_table_header(stdscr, row, w)
        row = self._draw_rows(stdscr, row, w, h, visible)
        self._draw_footer(stdscr, h, w)

        if self.kill_mode:
            self._draw_kill_prompt(stdscr, h, w)

    def _draw_header(self, win, row, w):
        title = " BERRY SENTINEL v5.0  ─  C2 & Reverse Shell Detector  ─  TUI Interactivo "
        attr = curses.color_pair(CP_HEADER) | curses.A_BOLD
        border = curses.color_pair(CP_HEADER)
        safe_addstr(win, row, 0, "╔" + "═"*(w-2) + "╗", border)
        row += 1
        pad = max(w - 2 - len(title), 0)
        safe_addstr(win, row, 0, "║", border)
        safe_addstr(win, row, 1, title, attr)
        safe_addstr(win, row, 1+len(title), " "*pad + "║", border)
        row += 1
        safe_addstr(win, row, 0, "╚" + "═"*(w-2) + "╝", border)
        row += 1
        return row

    def _draw_stats(self, win, row, w, conns):
        priv = self.sentinel.priv
        scans = self.sentinel.scans
        method = trunc(self.sentinel.last_method, 35)
        ms = self.sentinel.last_ms
        now = datetime.datetime.now().strftime("%H:%M:%S")
        total = len(conns)
        threats = sum(1 for c in conns if c.severity >= Sev.MEDIUM)
        criticals = sum(1 for c in conns if c.severity == Sev.CRITICAL)
        sigs = sum(1 for c in conns if c.sig_matches)
        filter_name = SEV_META[self.filter_sev][0]

        priv_str = "◉ ROOT+DEEP" if priv else "○ USER"
        priv_attr = curses.color_pair(CP_OK) if priv else curses.color_pair(CP_MEDIUM)

        safe_addstr(win, row, 0, " ", 0)
        safe_addstr(win, row, 1, priv_str, priv_attr | curses.A_BOLD)
        x = 1 + len(priv_str) + 2

        parts_info = [
            (f"Scan#{scans}", CP_DIM),
            (f"{ms:.0f}ms", CP_DIM),
            (f"Src:{method}", CP_DIM),
            (f"Conn:{total}", CP_TITLE),
            (f"Threats:{threats}", CP_HIGH if threats else CP_OK),
            (f"Critical:{criticals}", CP_CRITICAL if criticals else CP_DIM),
            (f"Sigs:{sigs}", CP_SIG if sigs else CP_DIM),
            (f"Filtro:≥{filter_name}", CP_MEDIUM),
            (now, CP_TITLE),
        ]
        for txt, cp in parts_info:
            if x + len(txt) + 3 >= w: break
            safe_addstr(win, row, x, txt, curses.color_pair(cp))
            x += len(txt)
            safe_addstr(win, row, x, "  │  ", curses.color_pair(CP_DIM))
            x += 5

        row += 1
        draw_hline(win, row, w, "─", curses.color_pair(CP_DIM))
        row += 1
        return row

    def _col_widths(self, w):
        """Calcula anchos adaptados al terminal."""
        fixed = sum(c[1] for c in self.COL_SPEC if c[1] > 0)
        extra = max(0, w - fixed - len(self.COL_SPEC)*1 - 2)
        widths = []
        for hdr, ww, key in self.COL_SPEC:
            if key == "tags": widths.append(max(10, extra))
            else: widths.append(ww)
        return widths

    def _draw_table_header(self, win, row, w):
        widths = self._col_widths(w)
        x = 0
        attr = curses.color_pair(CP_TITLE) | curses.A_BOLD
        for (hdr, _, _), cw in zip(self.COL_SPEC, widths):
            safe_addstr(win, row, x, f"{hdr:<{cw}}", attr)
            x += cw + 1
        row += 1
        draw_hline(win, row, w, "─", curses.color_pair(CP_DIM))
        row += 1
        return row

    def _draw_rows(self, win, start_row, w, h, visible):
        widths = self._col_widths(w)
        avail = h - start_row - 2  # espacio para footer
        if avail <= 0: return start_row

        # Ajustar scroll
        if self.sel >= self.scroll + avail: self.scroll = self.sel - avail + 1
        if self.sel < self.scroll: self.scroll = self.sel

        for idx, c in enumerate(visible[self.scroll:self.scroll+avail]):
            real_idx = idx + self.scroll
            row = start_row + idx
            if row >= h - 2: break

            p = c.proc
            sv = c.severity
            cp = SEV_CP[sv]
            is_sel = (real_idx == self.sel)
            base_attr = curses.color_pair(CP_SEL) if is_sel else 0
            sev_attr  = (curses.color_pair(CP_SEL) | curses.A_BOLD) if is_sel else (curses.color_pair(cp) | curses.A_BOLD)

            # Si es CRITICAL, fondo resaltado
            if sv == Sev.CRITICAL and not is_sel:
                base_attr = curses.color_pair(CP_CRITICAL) | curses.A_BOLD

            cells = [
                str(c.conn_id),
                f"{SEV_ICONS[sv]} {SEV_META[sv][0][:5]}",
                f"{c.score:5.1f}",
                str(c.pid) if c.pid > 0 else "—",
                trunc(p.name if p else "?", widths[4]),
                trunc(f"{c.remote_addr}:{c.remote_port}" if c.remote_addr else "—", widths[5]),
                str(c.local_port),
                c.protocol[:3],
                trunc(c.state, widths[8]),
                fmt_b(p.io_write) if p and p.io_write >= 0 else "—",
                fmt_b(p.io_read) if p and p.io_read >= 0 else "—",
                fmt_t(time.time()-p.create_time) if p and p.create_time > 0 else "—",
                _format_tags(c),
            ]

            x = 0
            win.move(row, 0)
            if is_sel:
                win.clrtoeol()
            for i, (cell, cw) in enumerate(zip(cells, widths)):
                cell_txt = f"{cell:<{cw}}"[:cw]
                if i == 0:  # ID column
                    attr = curses.color_pair(CP_DIM) | base_attr
                elif i == 1:  # SEV
                    attr = sev_attr
                elif i == 2:  # PTS
                    if sv >= Sev.CRITICAL: attr = curses.color_pair(CP_CRITICAL) | curses.A_BOLD
                    elif sv >= Sev.HIGH: attr = curses.color_pair(CP_HIGH)
                    elif sv >= Sev.MEDIUM: attr = curses.color_pair(CP_MEDIUM)
                    else: attr = curses.color_pair(CP_DIM)
                    if is_sel: attr = curses.color_pair(CP_SEL)
                elif i == 12:  # TAGS — color si tiene sigs
                    if c.sig_matches: attr = curses.color_pair(CP_SIG) | curses.A_BOLD
                    elif sv >= Sev.HIGH: attr = curses.color_pair(CP_HIGH)
                    elif sv >= Sev.MEDIUM: attr = curses.color_pair(CP_MEDIUM)
                    else: attr = curses.color_pair(CP_DIM)
                    if is_sel: attr = curses.color_pair(CP_SEL)
                else:
                    attr = base_attr if is_sel else 0

                safe_addstr(win, row, x, cell_txt, attr)
                x += cw + 1

        return start_row + min(avail, len(visible))

    def _draw_footer(self, win, h, w):
        row = h - 1
        draw_hline(win, row-1, w, "─", curses.color_pair(CP_DIM))
        keys = "↑↓:nav  d:detalle  k:kill  f:filtro  q:salir"
        status = self.status_msg
        attr_k = curses.color_pair(CP_DIM)
        attr_s = curses.color_pair(self.status_color) | curses.A_BOLD
        safe_addstr(win, row, 0, keys, attr_k)
        if status:
            x = w - len(status) - 2
            safe_addstr(win, row, max(x, len(keys)+2), f" {status} ", attr_s)

    def _draw_detail(self, win, c: Conn, h, w):
        """Panel de detalles completo para una conexión."""
        win.erase()
        p = c.proc
        sv = c.severity
        cp = SEV_CP[sv]
        attr_title = curses.color_pair(CP_HEADER) | curses.A_BOLD
        attr_label = curses.color_pair(CP_DIM) | curses.A_BOLD
        attr_val   = 0

        row = 0
        border = "═" * (w - 2)
        safe_addstr(win, row, 0, f"╔{border}╗", curses.color_pair(CP_HEADER)); row += 1
        title = f" DETALLE — ID:{c.conn_id}  SEV:{SEV_META[sv][0]}  SCORE:{c.score:.1f}  PID:{c.pid} "
        safe_addstr(win, row, 0, "║", curses.color_pair(CP_HEADER))
        safe_addstr(win, row, 1, title, attr_title)
        safe_addstr(win, row, 1+len(title), " "*(w-3-len(title)) + "║", curses.color_pair(CP_HEADER)); row += 1
        safe_addstr(win, row, 0, f"╚{border}╝", curses.color_pair(CP_HEADER)); row += 1

        def lbl(label, val, cp_val=0):
            nonlocal row
            if row >= h - 2: return
            safe_addstr(win, row, 2, f"{label:16}", attr_label)
            safe_addstr(win, row, 18, str(val), curses.color_pair(cp_val) if cp_val else attr_val)
            row += 1

        lbl("Conexión ID", c.conn_id)
        lbl("Protocolo", f"{c.protocol.upper()} {c.family}")
        lbl("Estado", c.state)
        lbl("Local", f"{c.local_addr}:{c.local_port}")
        lbl("Remoto", f"{c.remote_addr}:{c.remote_port}" if c.remote_addr else "—", CP_HIGH if c.remote_addr else 0)
        lbl("Fuente datos", c.source)

        row += 1
        if p:
            lbl("Proceso PID", p.pid)
            lbl("Nombre", p.name)
            if p.exe:
                col = CP_CRITICAL if p.exe_deleted else 0
                lbl("Ejecutable", p.exe + (" ⚠ BORRADO!" if p.exe_deleted else ""), col)
            if p.cmdline:
                safe_addstr(win, row, 2, f"{'Cmdline':16}", attr_label)
                safe_addstr(win, row, 18, trunc(p.cmdline, w-20)); row += 1
            lbl("UID", p.uid)
            lbl("PPID", f"{p.ppid} ({p.parent_name})")
            if p.parent_chain:
                chain = " → ".join(f"{n}({i})" for i,n in p.parent_chain)
                safe_addstr(win, row, 2, f"{'Cadena padre':16}", attr_label)
                safe_addstr(win, row, 18, trunc(chain, w-20)); row += 1
            lbl("Threads", p.threads)
            lbl("FDs", p.fd_count)
            fds_str = ", ".join(f"{k}:{v}" for k,v in p.fd_types.items())
            if fds_str: lbl("FD tipos", fds_str)

            fd_flags = []
            if p.stdin_is_socket: fd_flags.append("stdin→SOCKET")
            if p.stdout_is_socket: fd_flags.append("stdout→SOCKET")
            if p.stderr_is_socket: fd_flags.append("stderr→SOCKET")
            if p.stdin_is_pipe: fd_flags.append("stdin→pipe")
            if p.stdout_is_pipe: fd_flags.append("stdout→pipe")
            if fd_flags: lbl("FD flags", ", ".join(fd_flags), CP_CRITICAL)

            if p.maps_rwx_count > 0: lbl("Mem RWX", f"{p.maps_rwx_count} regiones", CP_CRITICAL)
            if p.mem_suspicious_regions > 0: lbl("Mem sospech.", f"{p.mem_suspicious_regions} regiones", CP_HIGH)
            if p.env_suspect_keys: lbl("ENV sospech.", ", ".join(p.env_suspect_keys), CP_HIGH)
            if p.exe_deleted: lbl("⚠ Binario", "ELIMINADO EN DISCO", CP_CRITICAL)
            tx = fmt_b(p.io_write) if p.io_write >= 0 else "—"
            rx = fmt_b(p.io_read) if p.io_read >= 0 else "—"
            lbl("I/O TX/RX", f"{tx} / {rx}")
            uptime = fmt_t(time.time()-p.create_time) if p.create_time > 0 else "—"
            lbl("Uptime proc.", uptime)

        row += 1
        if c.tags:
            safe_addstr(win, row, 2, f"{'Tags heur.'  :16}", attr_label)
            safe_addstr(win, row, 18, ", ".join(c.tags), curses.color_pair(CP_MEDIUM)); row += 1

        if c.sig_matches:
            safe_addstr(win, row, 2, f"{'▸ FIRMAS C2':16}", curses.color_pair(CP_SIG) | curses.A_BOLD); row += 1
            for sname, sdesc, sbonus in c.sig_matches:
                if row >= h - 2: break
                safe_addstr(win, row, 4, f"  ✦ {sname}", curses.color_pair(CP_SIG) | curses.A_BOLD)
                safe_addstr(win, row, 4+4+len(sname), f"  {sdesc}  (+{sbonus}pts)",
                            curses.color_pair(CP_DIM)); row += 1

        row += 1
        draw_hline(win, h-2, w, "─", curses.color_pair(CP_DIM))
        safe_addstr(win, h-1, 0, " [q/d/ESC] Cerrar detalle", curses.color_pair(CP_DIM))

    def _draw_kill_prompt(self, win, h, w):
        """Overlay para matar proceso."""
        prompt = " ╔══ KILL PROCESS ══╗ Ingresa PID (Enter=confirmar, ESC=cancelar): "
        attr = curses.color_pair(CP_PROMPT) | curses.A_BOLD
        y = h // 2
        safe_addstr(win, y, max(0, w//2 - len(prompt)//2), prompt[:w-1], attr)
        # Mostrar buffer de entrada
        buf = self._kill_buf if hasattr(self, '_kill_buf') else ""
        x_buf = max(0, w//2 - len(prompt)//2) + len(prompt)
        safe_addstr(win, y, x_buf, buf + "█", attr)

    def _handle_key(self, stdscr, key, conns):
        visible = sorted([c for c in conns if c.severity >= self.filter_sev],
                         key=lambda c: c.score, reverse=True)
        if key in (curses.KEY_UP, ord('k') if False else -999):
            if key == curses.KEY_UP and self.sel > 0: self.sel -= 1
        elif key == curses.KEY_UP:
            if self.sel > 0: self.sel -= 1
        elif key == curses.KEY_DOWN:
            if self.sel < len(visible) - 1: self.sel += 1
        elif key in (ord('d'), ord('D')):
            if 0 <= self.sel < len(visible):
                self.detail_conn = visible[self.sel]
                self.show_detail = True
        elif key in (ord('k'), ord('K')):
            self.kill_mode = True
            self._kill_buf = ""
            # Pre-cargar PID del seleccionado
            if 0 <= self.sel < len(visible):
                self._kill_buf = str(visible[self.sel].pid) if visible[self.sel].pid > 0 else ""
        elif key in (ord('f'), ord('F')):
            # Ciclar filtro
            levels = list(Sev)
            idx = levels.index(self.filter_sev)
            self.filter_sev = levels[(idx + 1) % len(levels)]
            self.status_msg = f"Filtro → ≥{SEV_META[self.filter_sev][0]}"
            self.status_color = CP_MEDIUM
        elif key in (ord('q'), ord('Q')):
            self.sentinel._run = False

    def _handle_kill_input(self, stdscr, key):
        if not hasattr(self, '_kill_buf'): self._kill_buf = ""
        if key == 27:  # ESC
            self.kill_mode = False; self._kill_buf = ""
            self.status_msg = "Kill cancelado"; self.status_color = CP_DIM
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self._kill_buf = self._kill_buf[:-1]
        elif key in (ord('\n'), ord('\r'), curses.KEY_ENTER):
            buf = self._kill_buf.strip()
            self.kill_mode = False; self._kill_buf = ""
            if buf.isdigit():
                pid = int(buf)
                ok, msg = kill_pid(pid)
                self.status_msg = msg[:60]
                self.status_color = CP_KILL_OK if ok else CP_KILL_ERR
            else:
                self.status_msg = f"PID inválido: '{buf}'"
                self.status_color = CP_KILL_ERR
        elif chr(key).isdigit():
            self._kill_buf += chr(key)


def _format_tags(c: Conn) -> str:
    parts = []
    for sname, _, _ in c.sig_matches:
        parts.append(f"⚑{sname}")
    for tag in c.tags:
        if not tag.startswith("SIG:"):
            parts.append(tag)
    return ", ".join(parts[:6]) or "—"


# ═══════════════════════════════════════════════════════════════════════
# TUI LEGACY (no curses) — fallback
# ═══════════════════════════════════════════════════════════════════════

class LegacyTUI:
    def __init__(self, color=True): self.color = color
    def c(self, code, text): return f"{code}{text}{RST}" if self.color else text
    @property
    def w(self):
        try: return os.get_terminal_size().columns
        except: return 80
    def clear(self):
        sys.stdout.write("\033[2J\033[H" if SYSTEM != "windows" else "")
        sys.stdout.flush()
        if SYSTEM == "windows": os.system("cls")

    def header(self, priv, show_all, total, threats, sigs, method, ms, n):
        w = self.w
        print(self.c("\033[96m","╔"+"═"*(w-2)+"╗"))
        t = " BERRY SENTINEL v5.0 — C2 & Reverse Shell Detector "
        pad = max(w-4-len(t),0)
        print(self.c("\033[96m","║ ")+self.c(B+"\033[96m",t)+" "*pad+self.c("\033[96m"," ║"))
        print(self.c("\033[96m","╚"+"═"*(w-2)+"╝"))
        p = self.c("\033[92m","◉ ROOT+DEEP") if priv else self.c("\033[93m","○ USER")
        m = "ALL" if show_all else "REMOTE"
        tx = " TERMUX" if IS_ANDROID else ""
        th = self.c("\033[91;1m",str(threats)) if threats else self.c("\033[92m","0")
        sg = self.c("\033[95m",str(sigs)) if sigs else self.c(DIM,"0")
        now = datetime.datetime.now().strftime("%H:%M:%S")
        parts = [f" {p}",f"{m}{tx}",f"Src:{trunc(method,30)}",f"Conn:{self.c(B,str(total))}",
                 f"Threats:{th}",f"Sigs:{sg}",f"{ms:.0f}ms",f"#{n}",now]
        print(" │ ".join(parts))
        print(self.c(DIM,"─"*w))

    def table(self, conns, verbose, max_rows):
        w = self.w
        if not conns: print(self.c(DIM,"\n  [sin conexiones]\n")); return
        hdr = (f" {'':1} {'SEV':>7} {'PTS':>5} {'ID':>5} {'PID':>7} {'PROCESO':<14} "
               f"{'REMOTO':<24} {'LP':>5} {'P':3} {'ESTADO':<12} "
               f"{'TX':>6} {'RX':>6} {'VIVO':>6}  {'FIRMAS/INDICADORES'}")
        print(self.c(B+"\033[97m",hdr)); print(self.c(DIM,"─"*w))
        shown = sorted(conns, key=lambda c: c.score, reverse=True)
        if not verbose:
            hi = [c for c in shown if c.severity >= Sev.LOW]
            lo = [c for c in shown if c.severity < Sev.LOW]
            shown = hi + lo
        for c in shown[:max_rows]:
            sl, sc_c, icon = SEV_META[c.severity][:3]
            p = c.proc; sv = c.score
            if sv>=65: scs=self.c("\033[31;1m",f"{sv:5.1f}")
            elif sv>=45: scs=self.c("\033[91m",f"{sv:5.1f}")
            elif sv>=25: scs=self.c("\033[33m",f"{sv:5.1f}")
            elif sv>=8: scs=self.c("\033[36m",f"{sv:5.1f}")
            else: scs=self.c(DIM,f"{sv:5.1f}")
            nm=trunc(p.name if p else "?",14)
            rm=f"{c.remote_addr}:{c.remote_port}" if c.remote_addr else "—"
            rm=trunc(rm,24); pids=f"{c.pid:>7}" if c.pid>0 else "      —"
            cid=f"{c.conn_id:>5}"
            tx=fmt_b(p.io_write) if p and p.io_write>=0 else "—"
            rx=fmt_b(p.io_read) if p and p.io_read>=0 else "—"
            al=fmt_t(time.time()-p.create_time) if p and p.create_time>0 else "—"
            # Tags + firmas
            sig_str = ",".join(f"⚑{s[0]}" for s in c.sig_matches) if c.sig_matches else ""
            tag_str = ",".join(t for t in c.tags[:4] if not t.startswith("SIG:"))
            tg = sig_str + ("," if sig_str and tag_str else "") + tag_str or "—"
            if c.sig_matches: tg=self.c("\033[95;1m",tg)
            elif c.severity>=Sev.HIGH: tg=self.c("\033[91m",tg)
            elif c.severity>=Sev.MEDIUM: tg=self.c("\033[33m",tg)
            ic=self.c(sc_c,icon); sevs=self.c(sc_c+B,f"{sl:>7}")
            line=(f" {ic} {sevs} {scs} {cid} {pids} {nm:<14} "
                  f"{rm:<24} {c.local_port:>5} {c.protocol:3} {c.state:<12} "
                  f"{tx:>6} {rx:>6} {al:>6}  {tg}")
            if c.severity>=Sev.CRITICAL: print(self.c("\033[41;97m",line))
            elif c.severity>=Sev.HIGH: print(self.c("\033[91m",line))
            else: print(line)
        if len(shown)>max_rows: print(self.c(DIM,f"  +{len(shown)-max_rows} ocultas"))

    def details(self, conns):
        threats=[c for c in conns if c.severity>=Sev.MEDIUM]
        if not threats: return
        print(); print(self.c("\033[93;1m"," ⚠  AMENAZAS")); print(self.c(DIM,"─"*self.w))
        for c in sorted(threats,key=lambda x:x.score,reverse=True)[:6]:
            sl,sc,_=SEV_META[c.severity][:3]; p=c.proc
            sig_info = ""
            if c.sig_matches:
                sig_info = "  ⚑ " + ", ".join(f"{s[0]}(+{s[2]}pts)" for s in c.sig_matches)
            print(); print(self.c(sc+B,f"  [{sl}] {c.score:.1f}pts │ ID:{c.conn_id} │ PID {c.pid} ({p.name if p else '?'}) │ {c.remote_addr}:{c.remote_port} │ via {c.source}"))
            if sig_info: print(self.c("\033[95;1m",f"  ⚑ FIRMAS:{sig_info}"))
            if p:
                if p.exe: print(self.c(DIM,f"    Exe    : {p.exe}{' ⚠ DELETED!' if p.exe_deleted else ''}"))
                if p.cmdline: print(self.c(DIM,f"    Cmd    : {trunc(p.cmdline,140)}"))
                if p.parent_chain: print(self.c(DIM,f"    Padres : {' → '.join(f'{n}({i})' for i,n in p.parent_chain)}"))
                fd_f=[]
                if p.stdin_is_socket: fd_f.append("stdin→SOCKET")
                if p.stdout_is_socket: fd_f.append("stdout→SOCKET")
                if p.stderr_is_socket: fd_f.append("stderr→SOCKET")
                if p.stdin_is_pipe: fd_f.append("stdin→pipe")
                if p.stdout_is_pipe: fd_f.append("stdout→pipe")
                if fd_f: print(self.c("\033[91m",f"    FDs    : {', '.join(fd_f)}"))
                if p.maps_rwx_count>0: print(self.c("\033[91m",f"    RWX    : {p.maps_rwx_count} regiones"))
                if p.mem_suspicious_regions>0: print(self.c("\033[91m",f"    MEM    : {p.mem_suspicious_regions} regiones sospechosas"))
                if p.env_suspect_keys: print(self.c("\033[93m",f"    ENV    : {', '.join(p.env_suspect_keys)}"))
            if c.tags: print(self.c("\033[93m",f"    Tags   : {', '.join(c.tags)}"))

    def no_threats(self):
        print(); print(self.c("\033[92m","  ✓ Sin indicadores de compromiso")); print()

    def footer(self, n, kill_pid_fn=None):
        print(self.c(DIM,"─"*self.w))
        print(self.c(DIM,f" Ctrl+C salir │ Scans: {n} │ Para matar un proceso: Ctrl+C y luego: kill -9 <PID>"))


# ═══════════════════════════════════════════════════════════════════════
# SENTINEL PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════

class Sentinel:
    def __init__(self, args):
        self.priv=is_root(); self.show_all=args.all
        self.interval=max(0.5,min(60,args.interval))
        self.verbose=args.verbose; self.max_rows=args.top
        self.json_exp=args.json; self.show_diag=getattr(args,'diag',False)
        self.no_tui=getattr(args,'no_tui',False)
        wl=[x.strip() for x in args.whitelist.split(",")] if args.whitelist else []
        self.coll=Collector(self.priv, diag=self.show_diag)
        self.eng=Engine(whitelist=wl)
        self.log=Logger(path=args.log)
        self.scans=0; self._run=True
        self.last_conns=[]
        self.last_method=""
        self.last_ms=0.0

        # TUI legacy para modo no-curses
        self._legacy=LegacyTUI(color=not args.no_color)

    def run(self):
        signal.signal(signal.SIGINT, self._exit)
        try: signal.signal(signal.SIGTERM, self._exit)
        except: pass

        if self.no_tui:
            self._startup_legacy()
            while self._run:
                try: self._cycle_legacy(); time.sleep(self.interval)
                except KeyboardInterrupt: self._exit(); break
                except Exception as e:
                    print(f"\n[ERROR] {e}"); import traceback; traceback.print_exc(); time.sleep(3)
        else:
            self._startup_curses()

    def _startup_curses(self):
        """Lanza TUI curses interactivo."""
        ctui = CursesTUI(self)
        # Primer ciclo de datos antes de entrar a curses
        self._cycle_data()
        try:
            curses.wrapper(ctui.run)
        except Exception as e:
            # Fallback a modo legacy si curses falla
            print(f"\n[WARN] curses falló ({e}), usando modo legacy\n")
            self.no_tui = True
            self._startup_legacy()
            while self._run:
                try: self._cycle_legacy(); time.sleep(self.interval)
                except KeyboardInterrupt: self._exit(); break
        self._on_exit()

    def _startup_legacy(self):
        self._legacy.clear()
        ps = "SÍ → deep scan" if self.priv else "NO → parcial"
        tx = " (Termux)" if IS_ANDROID else ""
        print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║          BERRY SENTINEL v{VERSION}                          ║
    ║    C2 Detector · Zero-Sig · Firmas · Kill Engine         ║
    ╚═══════════════════════════════════════════════════════════╝
      Sistema    : {platform.system()} {platform.release()}{tx}
      Privilegios: {ps}
      Modo       : {"ALL" if self.show_all else "REMOTE"} / Legacy TUI
      Firmas C2  : {len(C2_SIGNATURES)} frameworks conocidos
      Intervalo  : {self.interval}s

      Iniciando...\n""")
        time.sleep(1)

    def _cycle_data(self):
        """Recolecta y analiza datos (sin render)."""
        t0=time.time(); raw, method = self.coll.collect()
        if not self.show_all:
            filt=[]
            for c in raw:
                if not c.remote_addr:
                    if c.state=="LISTEN" and c.proc:
                        n=c.proc.name.lower()
                        if any(s in n for s in SHELL_BINS) or any(e in n for e in SCRIPT_ENGINES):
                            filt.append(c)
                    continue
                if is_loopback(c.remote_addr): continue
                filt.append(c)
            raw=filt
        analyzed=[self.eng.analyze(c) for c in raw]
        for c in analyzed: self.log.log(c)
        self.scans+=1
        self.last_conns=analyzed
        self.last_method=method
        self.last_ms=(time.time()-t0)*1000

    def _cycle_legacy(self):
        self._cycle_data()
        analyzed=self.last_conns; method=self.last_method; ms=self.last_ms
        threats=sum(1 for c in analyzed if c.severity>=Sev.MEDIUM)
        sigs=sum(1 for c in analyzed if c.sig_matches)
        self._legacy.clear()
        self._legacy.header(self.priv,self.show_all,len(analyzed),threats,sigs,method,ms,self.scans)
        self._legacy.table(analyzed,self.verbose,self.max_rows)
        if threats>0: self._legacy.details(analyzed)
        else: self._legacy.no_threats()
        self._legacy.footer(self.scans)

    def _exit(self, *_):
        self._run=False
        print("\n")
        self._on_exit()
        sys.exit(0)

    def _on_exit(self):
        if self.json_exp:
            out=f"sentinel_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.log.export(out); print(f"  ✓ JSON: {out}")
        if self.log.path: print(f"  ✓ Log: {self.log.path}")
        print(f"  ✓ Alertas: {len(self.log.entries)} │ Scans: {self.scans}\n")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    ap=argparse.ArgumentParser(
        description=f"BERRY SENTINEL v{VERSION} — Detector Conductual C2 con TUI Interactivo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            Ejemplos:
              python3 sentinel.py                   TUI interactivo (recomendado)
              python3 sentinel.py --no-tui          Modo scroll clásico
              python3 sentinel.py --all             + conexiones locales
              python3 sentinel.py --all --diag      + diagnóstico
              sudo python3 sentinel.py --all        Deep scan (root)
              python3 sentinel.py --log a.log -j    Log + JSON

            Firmas C2 incluidas ({len(C2_SIGNATURES)}):
              {', '.join(s.name for s in C2_SIGNATURES)}

            Teclas TUI:
              ↑↓ navegar · d detalle · k kill · f filtro · q salir

            Funciona: Linux, Termux/Android, macOS, Windows
        """))
    ap.add_argument("--all","-a",action="store_true",help="Incluir conexiones locales/loopback")
    ap.add_argument("--interval","-i",type=float,default=2.0,help="Intervalo refresco (seg)")
    ap.add_argument("--log","-l",type=str,default=None,help="Archivo log")
    ap.add_argument("--json","-j",action="store_true",help="Exportar JSON al salir")
    ap.add_argument("--whitelist","-w",type=str,default=None,help="IPs/CIDRs a ignorar")
    ap.add_argument("--no-color",action="store_true",help="Sin ANSI color")
    ap.add_argument("--verbose","-v",action="store_true",help="Mostrar todas las conexiones")
    ap.add_argument("--top","-t",type=int,default=50,help="Máx. filas visibles")
    ap.add_argument("--diag","-d",action="store_true",help="Diagnóstico de recolección")
    ap.add_argument("--no-tui",action="store_true",help="Modo legacy sin curses")
    ap.add_argument("--version","-V",action="version",version=f"Berry Sentinel v{VERSION}")
    Sentinel(ap.parse_args()).run()

if __name__ == "__main__":
    main()
