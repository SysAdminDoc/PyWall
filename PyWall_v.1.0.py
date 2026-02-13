#!/usr/bin/env python3
"""
PyWall v1.0 - Professional Windows Firewall Management Suite
=================================================================
A comprehensive, standalone Windows firewall management tool that
takes full control of Windows Firewall, providing application-level
policies, real-time threat detection, granular rule management, and
intelligent connection monitoring.

Architecture:
  - Dashboard:     Real-time bandwidth, threat alerts, traffic categories, quick actions
  - Network Map:   Radial visualization of connections by country/category/process
  - Connections:   Live connection table with GeoIP/DNS/WHOIS intel, categories, reputation
  - Rules:         Full CRUD firewall rule manager with categories
  - Applications:  Per-app network policies with active enforcement and reputation scores
  - History:       SQLite-backed searchable connection database
  - Timeline:      Connection session tracking with start/end times and duration
  - Security:      Threat detection, blocklists, port scan alerts, anomaly detection
  - Schedule:      Time-based rule scheduling, templates, profiles, export/import
  - Plugins:       Extension system, DNS blocking, bandwidth quotas, anomaly alerts

Features:
  - Traffic categorization (Streaming, Gaming, Social, System, etc.)
  - Process reputation scoring (trust grades A-F)
  - Anomaly detection (baseline behavior and alert on deviations)
  - Rule templates (Privacy, Gaming, Work Lockdown, Server, etc.)
  - Scheduled rules (enable/disable rules by time and day)
  - Network profiles (auto-switch settings by network)
  - Bandwidth quotas (daily/weekly per-process limits)
  - DNS-level blocking (via Windows hosts file)
  - Plugin system (Python scripts for custom event hooks)
  - Full config export/import
  - Connection grouping by process

Run as Administrator:  python PyWall.py
"""
import subprocess as _sp, sys as _sys, importlib as _il, os as _os, ctypes as _ct
from pathlib import Path as _P

NOWIN = 0x08000000

def _bootstrap():
    errors = []
    try:
        if not _ct.windll.shell32.IsUserAnAdmin():
            script = _os.path.abspath(_sys.argv[0])
            params = " ".join([f'"{script}"'] + [f'"{a}"' for a in _sys.argv[1:]])
            ret = _ct.windll.shell32.ShellExecuteW(None, "runas", _sys.executable, params, None, 1)
            if ret > 32: _sys.exit(0)
            else: errors.append("Failed to elevate. Right-click > Run as Administrator.")
    except: pass
    if _sys.version_info < (3, 8):
        errors.append(f"Python 3.8+ required (found {_sys.version}).")
    try:
        _sp.run([_sys.executable, "-m", "pip", "--version"], capture_output=True, timeout=15, creationflags=NOWIN)
    except:
        try: _sp.check_call([_sys.executable, "-m", "ensurepip", "--default-pip"], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, creationflags=NOWIN)
        except: errors.append("pip not available.")
    for imp, pip in {"PyQt6":"PyQt6","psutil":"psutil","requests":"requests"}.items():
        try: _il.import_module(imp)
        except ImportError:
            try: _sp.check_call([_sys.executable, "-m", "pip", "install", pip, "-q", "--break-system-packages"], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, creationflags=NOWIN)
            except Exception as e: errors.append(f"Failed to install {pip}: {e}")
    try:
        r = _sp.run(["powershell", "-NoProfile", "-Command", "echo ok"], capture_output=True, text=True, timeout=10, creationflags=NOWIN)
        if r.returncode != 0: errors.append("PowerShell not responding.")
    except FileNotFoundError: errors.append("PowerShell not found.")
    except: pass
    # Enable firewall auditing
    try: _sp.run(["auditpol", "/set", "/subcategory:Filtering Platform Connection", "/failure:enable", "/success:enable"], capture_output=True, timeout=10, creationflags=NOWIN)
    except: pass
    for p in ("domain","private","public"):
        try: _sp.run(["netsh", "advfirewall", "set", f"{p}profile", "logging", "allowedconnections", "enable", "droppedconnections", "enable"], capture_output=True, timeout=10, creationflags=NOWIN)
        except: pass
    if errors:
        print("\n=== PyWall Prerequisites Failed ===")
        for e in errors: print(f"  - {e}")
        try:
            import tkinter as tk; from tkinter import messagebox
            root = tk.Tk(); root.withdraw()
            messagebox.showerror("PyWall - Setup Failed", "Prerequisites:\n\n" + "\n".join(f"* {e}" for e in errors))
            root.destroy()
        except: pass
        _sys.exit(1)

_bootstrap()

# ================================================================
#  IMPORTS
# ================================================================
import os, sys, json, csv, time, socket, re, datetime, subprocess, importlib.util, argparse
import traceback, ctypes, sqlite3, struct, statistics, ipaddress, hashlib, logging
from pathlib import Path
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from queue import Queue, Empty
from threading import Lock, Event as TEvent, RLock
from concurrent.futures import ThreadPoolExecutor
import psutil, requests
from PyQt6.QtWidgets import *
from PyQt6.QtCore import (Qt, QTimer, QThread, pyqtSignal, QPoint, QSize,
                           QRect, QPropertyAnimation, QEasingCurve)
from PyQt6.QtGui import (QFont, QColor, QIcon, QPixmap, QPainter, QAction,
                          QLinearGradient, QPen, QBrush, QPainterPath, QIntValidator)

log = logging.getLogger("PyWall")
logging.basicConfig(level=logging.WARNING)

APP  = "PyWall"
VER  = "4.1.0"
PFX  = "PW_"
CDIR = Path(os.environ.get("APPDATA", ".")) / "PyWall"
CFILE= CDIR / "config.json"
LOGF = CDIR / "connections.csv"
DBFILE = CDIR / "history.db"
PLUGDIR = CDIR / "plugins"
CDIR.mkdir(parents=True, exist_ok=True)
PLUGDIR.mkdir(parents=True, exist_ok=True)
STARTUP_TASK_NAME = "PyWall"
PRIV = re.compile(r'^(0\.0\.0\.0|127\.|::1$|::$|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|fe80:|fd)')
PORTS = {20:"FTP-D",21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
         123:"NTP",135:"RPC",143:"IMAP",389:"LDAP",443:"HTTPS",445:"SMB",
         993:"IMAPS",995:"POP3S",1433:"MSSQL",3306:"MySQL",3389:"RDP",
         5353:"mDNS",5432:"Postgres",5900:"VNC",8080:"Alt-HTTP",8443:"Alt-HTTPS"}
NOWIN_FLAG = 0x08000000

# Admin privilege detection
def _is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False
IS_ADMIN = _is_admin()

# Hide console window (prevents the black CMD window from showing alongside the GUI)
def _hide_console():
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0
    except: pass

# NT device path -> DOS path mapping (cached)
_drive_map = None
def _nt_to_dos(path):
    """Convert NT device paths like \\device\\harddiskvolume3\\... to C:\\..."""
    global _drive_map
    if not path or path == "-": return path
    path_lower = path.lower()
    if not path_lower.startswith("\\device\\"): return path
    if _drive_map is None:
        _drive_map = {}
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(512)
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                drive = f"{letter}:"
                if ctypes.windll.kernel32.QueryDosDeviceW(drive, buf, 512):
                    _drive_map[buf.value.lower()] = drive
        except: pass
    for device, drive in _drive_map.items():
        if path_lower.startswith(device.lower()):
            return drive + path[len(device):]
    return path

# ================================================================
#  THEMES
# ================================================================
THEMES = {
    "Midnight": dict(bg0="#0C0C14",bg1="#12121E",bg2="#181828",bg3="#0E0E1A",bd1="#1E1E32",bd2="#2A2A44",bl="#3B82F6",cy="#06B6D4",rd="#EF4444",gn="#22C55E",am="#F59E0B",t1="#E8E8F0",t2="#8888A8",t3="#555570",ra="#101020",rh="#141428",rs="#1A2540"),
    "Charcoal": dict(bg0="#1A1A24",bg1="#22222E",bg2="#2A2A38",bg3="#1E1E2A",bd1="#333346",bd2="#40405A",bl="#5B9CF6",cy="#22D3EE",rd="#F87171",gn="#4ADE80",am="#FBBF24",t1="#F0F0F8",t2="#9898B8",t3="#6A6A88",ra="#202030",rh="#262638",rs="#283050"),
    "Slate": dict(bg0="#1E2028",bg1="#262832",bg2="#2E303C",bg3="#222430",bd1="#383A4A",bd2="#484A60",bl="#60A5FA",cy="#34D399",rd="#FB7185",gn="#6EE7B7",am="#FCD34D",t1="#F1F5F9",t2="#94A3B8",t3="#64748B",ra="#242632",rh="#2A2C3A",rs="#2D3A50"),
    "Nord": dict(bg0="#2E3440",bg1="#3B4252",bg2="#434C5E",bg3="#353B49",bd1="#4C566A",bd2="#5E6A82",bl="#88C0D0",cy="#8FBCBB",rd="#BF616A",gn="#A3BE8C",am="#EBCB8B",t1="#ECEFF4",t2="#D8DEE9",t3="#7B88A0",ra="#333947",rh="#3D4455",rs="#3A4560"),
    "Graphite": dict(bg0="#28282E",bg1="#32323A",bg2="#3C3C46",bg3="#2E2E36",bd1="#48484F",bd2="#58586A",bl="#7C9CF5",cy="#6DD4D4",rd="#E8737A",gn="#7ACC8A",am="#E8C36E",t1="#EAEAF0",t2="#A0A0B8",t3="#707088",ra="#30303A",rh="#363640",rs="#2E3848"),
    "Light": dict(bg0="#F8F9FA",bg1="#FFFFFF",bg2="#E9ECEF",bg3="#F1F3F5",bd1="#DEE2E6",bd2="#CED4DA",bl="#2563EB",cy="#0891B2",rd="#DC2626",gn="#16A34A",am="#D97706",t1="#1A1A2E",t2="#495057",t3="#868E96",ra="#F1F3F5",rh="#E9ECEF",rs="#DBEAFE"),
    "Frost": dict(bg0="#F0F4F8",bg1="#E8EEF4",bg2="#D6E0EC",bg3="#EAF0F6",bd1="#C4D1E0",bd2="#A8BAD0",bl="#3B82F6",cy="#0E7490",rd="#E11D48",gn="#059669",am="#CA8A04",t1="#1E293B",t2="#475569",t3="#94A3B8",ra="#E2EAF4",rh="#DAE4F0",rs="#BFDBFE"),
}
S = dict(THEMES["Charcoal"])

def set_theme(name):
    if name in THEMES:
        S.clear(); S.update(THEMES[name])
        try: cfg["theme"] = name
        except: pass

# ================================================================
#  CONFIG
# ================================================================
class Cfg:
    _D = dict(
        poll=2.0, tray=True, log=True, dns=True, owners=True, maxrows=5000,
        toast=True, toast_sec=8, notify_blocked=False, notify_priv=False,
        theme="Charcoal",
        geoip=True, bw_tracking=True, first_seen_alert=True,
        blocklist_telemetry=True, blocklist_ads=False, blocklist_custom=False,
        history_db=True, history_days=30,
        fw_mode="monitor",           # monitor | whitelist | blacklist
        ask_new_apps=True,
        auto_block_inbound=True,
        kill_blocked=False,
        app_profiles={},
        fw_profiles={"Domain":True,"Private":True,"Public":True},
        detect_portscan=True, detect_bruteforce=True,
        portscan_threshold=15, bruteforce_threshold=10,
        threat_auto_block=False,
        vt_api_key="",               # VirusTotal API key for binary reputation scanning
        start_monitoring=True, first_run=True,
        # Scheduled rules
        scheduled_rules=[],          # list of {rule_name, enabled, schedule:{days:[0-6], start:"HH:MM", end:"HH:MM"}}
        # Network profiles
        net_profiles={},             # {ssid_or_name: {fw_mode, app_profiles, ...}}
        auto_switch_profile=False,
        # Bandwidth quotas
        quotas_enabled=False,
        quotas={},                   # {process_name: {daily_mb:int, weekly_mb:int, action:"alert"|"block"}}
        global_daily_mb=0,           # 0 = unlimited
        # Anomaly detection
        anomaly_enabled=True,
        anomaly_sensitivity=2.0,     # std deviations
        # Traffic categorization
        categorize_traffic=True,
        # Process reputation
        reputation_enabled=True,
        # DNS blocking
        dns_block_enabled=False,
        dns_block_port=5353,
        # Plugin system
        plugins_enabled=True,
        # Connection grouping
        group_connections=True,
    )
    def __init__(s):
        s.d = dict(s._D)
        if CFILE.exists():
            try:
                with open(CFILE) as f: s.d.update(json.load(f))
            except: pass
        if s.d.get("theme") in THEMES: set_theme(s.d["theme"])
    def save(s):
        try:
            with open(CFILE, "w") as f: json.dump(s.d, f, indent=2)
        except: pass
    def __getitem__(s, k): return s.d.get(k, s._D.get(k))
    def __setitem__(s, k, v): s.d[k] = v; s.save()
    def get(s, k, d=None): return s.d.get(k, s._D.get(k, d))
cfg = Cfg()

# ================================================================
#  DATA STRUCTURES
# ================================================================
@dataclass
class CI:
    key:str=""; ts:str=""; src:str=""; dir:str=""; proto:str=""
    la:str=""; lp:str=""; ra:str=""; rp:str=""
    host:str="-"; proc:str="?"; pid:int=0; svc:str="-"
    state:str=""; path:str=""; org:str="-"; cmd:str=""
    stat:str="-"; country:str="-"; cc:str=""
    bytes_sent:int=0; bytes_recv:int=0

@dataclass
class FWRule:
    name:str=""; desc:str=""; direction:str="OUT"; action:str="BLOCK"
    enabled:bool=True; profile:str="Any"; group:str=""
    remote_addr:str="Any"; local_addr:str="Any"
    remote_port:str="Any"; local_port:str="Any"
    protocol:str="Any"; program:str=""
    source:str="system"

@dataclass
class ThreatEvent:
    ts:str=""; type:str=""; severity:str="medium"
    source_ip:str=""; details:str=""; action_taken:str=""
    blocked:bool=False

# ================================================================
#  CACHES
# ================================================================
class LRU:
    def __init__(s, c=5000): s._d=OrderedDict(); s._l=Lock(); s._c=c
    def get(s, k, d=None):
        with s._l:
            if k in s._d: s._d.move_to_end(k); return s._d[k]
            return d
    def put(s, k, v):
        with s._l:
            s._d[k]=v; s._d.move_to_end(k)
            while len(s._d)>s._c: s._d.popitem(last=False)
    def __contains__(s, k):
        with s._l: return k in s._d
    def items(s):
        with s._l: return list(s._d.items())
    def clear(s):
        with s._l: s._d.clear()

dns_c = LRU(5000); who_c = LRU(5000); geo_c = LRU(5000); prc_c = LRU(1000)
blk = set(); blk_lk = Lock(); seen = set(); seen_lk = Lock()

def _geoip_batch(ips):
    results = {}
    batch = [ip for ip in ips[:100] if ip and not PRIV.match(ip)]
    if not batch: return results
    try:
        r = requests.post("http://ip-api.com/batch",
                          json=[{"query":ip,"fields":"countryCode,country,query"} for ip in batch], timeout=10)
        if r.status_code == 200:
            for item in r.json():
                if item.get("countryCode"): results[item["query"]] = (item["countryCode"], item["country"])
    except: pass
    return results

# ================================================================
#  SQLITE CONNECTION DATABASE (WAL mode, indexed)
# ================================================================
class ConnDB:
    _SCHEMA = """CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, src TEXT, dir TEXT, proto TEXT,
        la TEXT, lp TEXT, ra TEXT, rp TEXT,
        host TEXT, proc TEXT, pid INTEGER, svc TEXT,
        state TEXT, org TEXT, stat TEXT, country TEXT, cc TEXT,
        UNIQUE(ts, proto, la, lp, ra, rp, pid) ON CONFLICT IGNORE
    )"""
    _IDX = [
        "CREATE INDEX IF NOT EXISTS idx_ts ON connections(ts)",
        "CREATE INDEX IF NOT EXISTS idx_proc ON connections(proc)",
        "CREATE INDEX IF NOT EXISTS idx_ra ON connections(ra)",
        "CREATE INDEX IF NOT EXISTS idx_cc ON connections(cc)",
        "CREATE INDEX IF NOT EXISTS idx_stat ON connections(stat)",
    ]
    def __init__(self):
        self._lock = Lock()
        self._conn = None
        self._init()
    def _init(self):
        try:
            self._conn = sqlite3.connect(str(DBFILE), check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(self._SCHEMA)
            for idx in self._IDX: self._conn.execute(idx)
            self._conn.commit()
        except Exception as e: print(f"[DB] Init error: {e}")
    def insert(self, ci):
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO connections (ts,src,dir,proto,la,lp,ra,rp,host,proc,pid,svc,state,org,stat,country,cc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ci.ts,ci.src,ci.dir,ci.proto,ci.la,ci.lp,ci.ra,ci.rp,ci.host,ci.proc,ci.pid,ci.svc,ci.state,ci.org,ci.stat,ci.country,ci.cc))
                self._conn.commit()
            except: pass
    def insert_batch(self, items):
        with self._lock:
            try:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO connections (ts,src,dir,proto,la,lp,ra,rp,host,proc,pid,svc,state,org,stat,country,cc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [(c.ts,c.src,c.dir,c.proto,c.la,c.lp,c.ra,c.rp,c.host,c.proc,c.pid,c.svc,c.state,c.org,c.stat,c.country,c.cc) for c in items])
                self._conn.commit()
            except: pass
    def search(self, query="", limit=500, offset=0, proc_filter="", country_filter="", hours=0):
        with self._lock:
            try:
                w = []; p = []
                if query:
                    w.append("(host LIKE ? OR proc LIKE ? OR ra LIKE ? OR org LIKE ?)")
                    p.extend([f"%{query}%"]*4)
                if proc_filter: w.append("proc=?"); p.append(proc_filter)
                if country_filter: w.append("country=?"); p.append(country_filter)
                if hours > 0:
                    cutoff = (datetime.datetime.now() - datetime.timedelta(hours=hours)).strftime("%H:%M:%S")
                    w.append("ts >= ?"); p.append(cutoff)
                where = " WHERE " + " AND ".join(w) if w else ""
                sql = f"SELECT ts,src,dir,proto,la,lp,ra,rp,host,proc,pid,svc,state,org,stat,country,cc FROM connections{where} ORDER BY id DESC LIMIT ? OFFSET ?"
                p.extend([limit, offset])
                return self._conn.execute(sql, p).fetchall()
            except: return []
    def get_stats(self, hours=24):
        with self._lock:
            try:
                total = self._conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
                blocked = self._conn.execute("SELECT COUNT(*) FROM connections WHERE stat LIKE '%BLOCK%' OR stat LIKE '%BL:%'").fetchone()[0]
                unique_ips = self._conn.execute("SELECT COUNT(DISTINCT ra) FROM connections").fetchone()[0]
                unique_procs = self._conn.execute("SELECT COUNT(DISTINCT proc) FROM connections").fetchone()[0]
                return {"total": total, "blocked": blocked, "unique_ips": unique_ips, "unique_procs": unique_procs}
            except: return {"total":0,"blocked":0,"unique_ips":0,"unique_procs":0}
    def prune(self, days=30):
        with self._lock:
            try:
                cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
                self._conn.execute("DELETE FROM connections WHERE ts < ?", (cutoff,))
                self._conn.commit()
            except: pass
    def get_unique_procs(self):
        with self._lock:
            try: return [r[0] for r in self._conn.execute("SELECT DISTINCT proc FROM connections WHERE proc != '?' ORDER BY proc").fetchall()]
            except: return []
    def get_unique_countries(self):
        with self._lock:
            try: return [r for r in self._conn.execute("SELECT DISTINCT cc, country FROM connections WHERE cc != '' ORDER BY country").fetchall()]
            except: return []
    def get_top_blocked(self, n=20):
        with self._lock:
            try: return self._conn.execute("SELECT ra, COUNT(*) as cnt FROM connections WHERE stat LIKE '%BLOCK%' GROUP BY ra ORDER BY cnt DESC LIMIT ?", (n,)).fetchall()
            except: return []
    def count(self):
        with self._lock:
            try: return self._conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
            except: return 0

conn_db = ConnDB()

# ================================================================
#  BLOCKLIST SYSTEM
# ================================================================
TELEMETRY_DOMAINS = {
    "vortex.data.microsoft.com","settings-win.data.microsoft.com",
    "watson.telemetry.microsoft.com","watson.microsoft.com",
    "telemetry.microsoft.com","oca.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com","umwatsonc.events.data.microsoft.com",
    "v10c.events.data.microsoft.com","v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com","us.vortex-win.data.microsoft.com",
    "eu.vortex-win.data.microsoft.com","telecommand.telemetry.microsoft.com",
    "compatexchange.cloudapp.net","diagnostics.support.microsoft.com",
    "corp.sts.microsoft.com","statsfe1.ws.microsoft.com",
    "pre.footprintpredict.com","feedback.windows.com",
    "feedback.microsoft-hohm.com","rad.msn.com","preview.msn.com",
    "ads.msn.com","a.ads2.msads.net","b.ads2.msads.net","ad.doubleclick.net",
    "choice.microsoft.com","df.telemetry.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com","telemetry.appex.bing.net",
    "telemetry.urs.microsoft.com","settings.data.microsoft.com",
    "data.microsoft.com","statsfe2.update.microsoft.com.akadns.net",
}
TELEMETRY_IPS = {
    "13.64.0.0/11","13.96.0.0/13","13.104.0.0/14","20.33.0.0/16",
    "20.40.0.0/13","20.128.0.0/16","23.96.0.0/13","40.64.0.0/10",
    "52.96.0.0/12","52.112.0.0/14","52.120.0.0/14","104.40.0.0/13",
    "131.253.0.0/16","134.170.0.0/16","137.116.0.0/15","157.56.0.0/14",
}
blocklist_hits = defaultdict(int)
blocklist_lk = Lock()
_telemetry_nets = []

def _init_telemetry_nets():
    global _telemetry_nets
    for cidr in TELEMETRY_IPS:
        try: _telemetry_nets.append(ipaddress.ip_network(cidr, strict=False))
        except: pass
_init_telemetry_nets()

_custom_bl_cache = None
_custom_bl_time = 0

def _load_custom_blocklist():
    """Load custom blocklist from disk, cache for 60s."""
    global _custom_bl_cache, _custom_bl_time
    now = time.time()
    if _custom_bl_cache is not None and now - _custom_bl_time < 60:
        return _custom_bl_cache
    entries = []
    bl_path = CDIR / "custom_blocklist.txt"
    if bl_path.exists():
        try:
            with open(bl_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.append(line)
        except: pass
    _custom_bl_cache = entries
    _custom_bl_time = now
    return entries

def check_blocklist(host, ip):
    if not cfg.get("blocklist_telemetry", False): return False
    if host and host not in ("-", "..."):
        for d in TELEMETRY_DOMAINS:
            if host.endswith(d) or host == d:
                with blocklist_lk: blocklist_hits[host] += 1
                return True
    if ip and not PRIV.match(ip):
        try:
            addr = ipaddress.ip_address(ip)
            for net in _telemetry_nets:
                if addr in net:
                    with blocklist_lk: blocklist_hits[ip] += 1
                    return True
        except: pass
    # Custom blocklist (cached in memory)
    if cfg.get("blocklist_custom"):
        for entry in _load_custom_blocklist():
            if host and host.endswith(entry): return True
            if ip == entry: return True
    return False

# ================================================================
#  BANDWIDTH TRACKER
# ================================================================
class BandwidthTracker:
    def __init__(self):
        self._lock = Lock()
        self._prev = psutil.net_io_counters()
        self._prev_time = time.time()
        self._per_proc = {}
        self._proc_prev = {}
        self._history = []
        self._max_hist = 300
        self._total_sent = 0
        self._total_recv = 0
        self._rate_up = 0.0
        self._rate_dn = 0.0
    def update(self):
        with self._lock:
            now = time.time(); dt = max(now - self._prev_time, 0.1)
            cur = psutil.net_io_counters()
            ds = cur.bytes_sent - self._prev.bytes_sent
            dr = cur.bytes_recv - self._prev.bytes_recv
            self._rate_up = ds / dt; self._rate_dn = dr / dt
            self._total_sent += ds; self._total_recv += dr
            self._history.append((self._rate_up, self._rate_dn))
            if len(self._history) > self._max_hist: self._history.pop(0)
            self._prev = cur; self._prev_time = now
            # Per-process
            try:
                per = {}
                for p in psutil.process_iter(['pid', 'name']):
                    try:
                        io = p.io_counters()
                        prev = self._proc_prev.get(p.pid, (0, 0))
                        s = max(io.write_bytes - prev[0], 0)
                        r = max(io.read_bytes - prev[1], 0)
                        self._proc_prev[p.pid] = (io.write_bytes, io.read_bytes)
                        nm = p.info['name']
                        if nm in per: per[nm] = (per[nm][0]+s, per[nm][1]+r)
                        else: per[nm] = (s, r)
                    except: continue
                self._per_proc = per
            except: pass
    def rates(self):
        with self._lock: return (self._rate_up, self._rate_dn)
    def totals(self):
        with self._lock: return (self._total_sent, self._total_recv)
    def get_history(self, n=120):
        with self._lock: return list(self._history[-n:])
    def get_top_processes(self, n=10):
        with self._lock:
            items = sorted(self._per_proc.items(), key=lambda x: x[1][0]+x[1][1], reverse=True)
            return items[:n]
    def format_bytes(self, b):
        for u in ("B","KB","MB","GB","TB"):
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} PB"
    def format_rate(self, bps):
        for u in ("B/s","KB/s","MB/s","GB/s"):
            if bps < 1024: return f"{bps:.1f} {u}"
            bps /= 1024
        return f"{bps:.1f} TB/s"
bw = BandwidthTracker()

# ================================================================
#  FIRST-SEEN PROCESS TRACKING
# ================================================================
_known_procs_file = CDIR / "known_procs.json"
_known_procs = {}
_known_procs_lk = Lock()

def _load_known_procs():
    global _known_procs
    if _known_procs_file.exists():
        try:
            with open(_known_procs_file) as f: _known_procs = json.load(f)
        except: _known_procs = {}
_load_known_procs()

def _save_known_procs():
    try:
        with open(_known_procs_file, "w") as f: json.dump(_known_procs, f, indent=2)
    except: pass

def check_first_seen(proc_name):
    with _known_procs_lk:
        if proc_name in _known_procs: return False
        _known_procs[proc_name] = datetime.datetime.now().isoformat()
        _save_known_procs()
        return True

# ================================================================
#  FIREWALL ENGINE - Complete Windows Firewall Management
# ================================================================
def _ps(cmd, t=20):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NoLogo", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=t, creationflags=NOWIN_FLAG)
        return (r.returncode == 0, r.stdout.strip())
    except Exception as e: return (False, str(e))

class FirewallEngine:
    """Comprehensive Windows Firewall management engine.
    Provides full CRUD for firewall rules, profile management,
    status control, and policy enforcement."""

    def __init__(self):
        self._rule_cache = []
        self._cache_lock = Lock()
        self._cache_time = 0
        self._cache_ttl = 120  # seconds - rules don't change often
        self._known_names = set()  # Fast lookup to prevent duplicate rule creation
        self._known_names_loaded = False

    # ---- Profile Management ----
    def get_profile_status(self):
        """Get enabled status for all firewall profiles."""
        ok, out = _ps(
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress", 15)
        result = {"Domain": True, "Private": True, "Public": True}
        if ok and out:
            try:
                data = json.loads(out)
                if isinstance(data, dict): data = [data]
                for p in data:
                    result[p["Name"]] = bool(p["Enabled"])
            except: pass
        return result

    def set_profile_status(self, profile, enabled):
        """Enable or disable a firewall profile (Domain/Private/Public)."""
        state = "True" if enabled else "False"
        ok, _ = _ps(f'Set-NetFirewallProfile -Name {profile} -Enabled {state}', 10)
        return ok

    def get_active_profile(self):
        """Get the currently active network profile."""
        ok, out = _ps(
            "Get-NetConnectionProfile | Select-Object -First 1 -ExpandProperty NetworkCategory", 10)
        if ok and out:
            return out.strip()
        return "Unknown"

    def get_default_actions(self):
        """Get default inbound/outbound actions per profile."""
        ok, out = _ps(
            "Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress", 15)
        result = {}
        if ok and out:
            try:
                data = json.loads(out)
                if isinstance(data, dict): data = [data]
                for p in data:
                    nm = p["Name"]
                    result[nm] = {
                        "inbound": "Block" if p.get("DefaultInboundAction") in (2,"2",4,"4") else "Allow",
                        "outbound": "Block" if p.get("DefaultOutboundAction") in (2,"2",4,"4") else "Allow"
                    }
            except: pass
        return result

    def set_default_action(self, profile, direction, action):
        """Set default action (Allow/Block) for a profile direction."""
        prop = "DefaultInboundAction" if direction == "Inbound" else "DefaultOutboundAction"
        ok, _ = _ps(f'Set-NetFirewallProfile -Name {profile} -{prop} {action}', 10)
        return ok

    # ---- Rule CRUD ----
    def create_rule(self, name, direction="Outbound", action="Block",
                    remote_addr="", remote_port="", local_addr="", local_port="",
                    protocol="", program="", profile="Any", desc="", enabled=True, group=""):
        """Create a new firewall rule with full parameter support."""
        parts = [f'New-NetFirewallRule -DisplayName "{name}" -Direction {direction} -Action {action}']
        parts.append(f'-Enabled {"True" if enabled else "False"}')
        if profile and profile != "Any": parts.append(f'-Profile "{profile}"')
        else: parts.append('-Profile Any')
        if remote_addr and remote_addr not in ("*", "Any"): parts.append(f'-RemoteAddress "{remote_addr}"')
        if remote_port and remote_port not in ("*", "Any"): parts.append(f'-RemotePort "{remote_port}"')
        if local_addr and local_addr not in ("*", "Any"): parts.append(f'-LocalAddress "{local_addr}"')
        if local_port and local_port not in ("*", "Any"): parts.append(f'-LocalPort "{local_port}"')
        if protocol and protocol not in ("", "Any"): parts.append(f'-Protocol {protocol}')
        if program and program not in ("-", "N/A", ""): parts.append(f'-Program "{_nt_to_dos(program)}"')
        if group: parts.append(f'-Group "{group}"')
        if desc: parts.append(f'-Description "{desc[:200]}"')
        ok, out = _ps(" ".join(parts), 20)
        if ok:
            self._invalidate_cache()
            with self._cache_lock:
                self._known_names.add(name)
        return ok, out

    def edit_rule(self, name, **kwargs):
        """Edit an existing firewall rule. Pass only fields to change."""
        parts = [f'Set-NetFirewallRule -DisplayName "{name}"']
        fmap = {
            "new_name": "NewDisplayName", "direction": "Direction", "action": "Action",
            "enabled": "Enabled", "profile": "Profile", "desc": "Description",
        }
        for k, v in kwargs.items():
            if k in fmap and v is not None:
                if k == "enabled": v = "True" if v else "False"
                parts.append(f'-{fmap[k]} "{v}"')
        # Address/port filters need separate cmdlet
        addr_parts = []
        if "remote_addr" in kwargs: addr_parts.append(f'-RemoteAddress "{kwargs["remote_addr"]}"')
        if "local_addr" in kwargs: addr_parts.append(f'-LocalAddress "{kwargs["local_addr"]}"')
        if "remote_port" in kwargs or "local_port" in kwargs or "protocol" in kwargs:
            port_parts = [f'Get-NetFirewallRule -DisplayName "{name}" | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter']
            if "protocol" in kwargs: port_parts.append(f'-Protocol {kwargs["protocol"]}')
            if "remote_port" in kwargs: port_parts.append(f'-RemotePort "{kwargs["remote_port"]}"')
            if "local_port" in kwargs: port_parts.append(f'-LocalPort "{kwargs["local_port"]}"')
            _ps(" ".join(port_parts), 15)
        if addr_parts:
            _ps(f'Get-NetFirewallRule -DisplayName "{name}" | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter ' + " ".join(addr_parts), 15)
        if "program" in kwargs:
            prog = kwargs["program"]
            if prog: _ps(f'Get-NetFirewallRule -DisplayName "{name}" | Get-NetFirewallApplicationFilter | Set-NetFirewallApplicationFilter -Program "{prog}"', 15)
        ok, out = _ps(" ".join(parts), 15) if len(parts) > 1 else (True, "")
        if ok: self._invalidate_cache()
        return ok, out

    def delete_rule(self, name):
        """Delete a firewall rule by display name."""
        ok, out = _ps(f'Remove-NetFirewallRule -DisplayName "{name}" -EA SilentlyContinue', 15)
        if ok:
            self._invalidate_cache()
            with self._cache_lock:
                self._known_names.discard(name)
        return ok, out

    def enable_rule(self, name, enabled=True):
        """Enable or disable a firewall rule."""
        state = "True" if enabled else "False"
        ok, _ = _ps(f'Set-NetFirewallRule -DisplayName "{name}" -Enabled {state}', 10)
        if ok: self._invalidate_cache()
        return ok

    def delete_rules_bulk(self, names):
        """Delete multiple rules efficiently."""
        if not names: return True
        # Batch delete via pipeline
        filter_str = " -or ".join([f'$_.DisplayName -eq "{n}"' for n in names[:50]])
        ok, _ = _ps(f'Get-NetFirewallRule | Where-Object {{ {filter_str} }} | Remove-NetFirewallRule', 30)
        if ok: self._invalidate_cache()
        return ok

    def toggle_rules_bulk(self, names, enabled=True):
        """Enable/disable multiple rules."""
        if not names: return True
        state = "True" if enabled else "False"
        filter_str = " -or ".join([f'$_.DisplayName -eq "{n}"' for n in names[:50]])
        ok, _ = _ps(f'Get-NetFirewallRule | Where-Object {{ {filter_str} }} | Set-NetFirewallRule -Enabled {state}', 30)
        if ok: self._invalidate_cache()
        return ok

    # ---- Rule Queries ----
    def get_all_rules(self, force_refresh=False):
        """Get ALL firewall rules with full detail. Cached for performance."""
        with self._cache_lock:
            if not force_refresh and self._rule_cache and (time.time() - self._cache_time) < self._cache_ttl:
                return list(self._rule_cache)
        rules = self._fetch_all_rules()
        with self._cache_lock:
            self._rule_cache = rules
            self._cache_time = time.time()
            self._known_names = {r.name for r in rules}
            self._known_names_loaded = True
        return rules

    def _fetch_all_rules(self):
        """Fetch all rules from Windows Firewall via PowerShell."""
        cmd = ('Get-NetFirewallRule -EA SilentlyContinue | '
            'ForEach-Object { $af=$_|Get-NetFirewallAddressFilter -EA SilentlyContinue; '
            '$pf=$_|Get-NetFirewallPortFilter -EA SilentlyContinue; '
            '$ap=$_|Get-NetFirewallApplicationFilter -EA SilentlyContinue; '
            '[PSCustomObject]@{'
            'DN=$_.DisplayName;Desc=$_.Description;Dir=[int]$_.Direction;Act=[int]$_.Action;'
            'En=[int]$_.Enabled;Prof=$_.Profile.ToString();Grp=$_.Group;'
            'RA=$af.RemoteAddress;LA=$af.LocalAddress;'
            'RP=$pf.RemotePort;LP=$pf.LocalPort;Proto=$pf.Protocol;'
            'Prog=$ap.Program} } | ConvertTo-Json -Compress')
        ok, out = _ps(cmd, 120)
        rules = []
        if ok and out:
            try:
                data = json.loads(out)
                if isinstance(data, dict): data = [data]
                for r in data:
                    def _j(v):
                        if isinstance(v, list): return ",".join(str(x) for x in v)
                        return str(v) if v else ""
                    src = "pywall" if str(r.get("DN","")).startswith(PFX) else "system"
                    rules.append(FWRule(
                        name=r.get("DN",""),
                        desc=r.get("Desc","") or "",
                        direction="Inbound" if r.get("Dir") in (1,"1") else "Outbound",
                        action="Block" if r.get("Act") in (2,"2") else "Allow",
                        enabled=r.get("En") in (1,"1",True),
                        profile=r.get("Prof","Any") or "Any",
                        group=r.get("Grp","") or "",
                        remote_addr=_j(r.get("RA","")),
                        local_addr=_j(r.get("LA","")),
                        remote_port=_j(r.get("RP","")),
                        local_port=_j(r.get("LP","")),
                        protocol=str(r.get("Proto","Any") or "Any"),
                        program=r.get("Prog","") or "",
                        source=src,
                    ))
            except: pass
        return rules

    def get_pywall_rules(self):
        """Get only PyWall-created rules."""
        return [r for r in self.get_all_rules() if r.source == "pywall"]

    def get_rule_count(self):
        """Quick rule count without full fetch."""
        ok, out = _ps("(Get-NetFirewallRule).Count", 10)
        if ok and out:
            try: return int(out)
            except: pass
        return len(self.get_all_rules())

    def _invalidate_cache(self):
        with self._cache_lock:
            self._cache_time = 0

    def rule_exists(self, name):
        """Check if a rule with this name already exists. Uses in-memory set first, then PS fallback."""
        with self._cache_lock:
            if self._known_names_loaded:
                return name in self._known_names
        # Fallback: quick PS check (only runs before first full scan)
        ok, out = _ps(f'(Get-NetFirewallRule -DisplayName "{name}" -EA SilentlyContinue) -ne $null', 8)
        return ok and out.strip().lower() == "true"

    # ---- Quick Actions ----
    def block_ip(self, ip, direction="Outbound", name_suffix=""):
        """Quick-block an IP address. Skips if rule already exists."""
        safe = ip.replace(":", "-").replace("/", "_")
        nm = f"{PFX}Block_{safe}_{direction[:3]}{name_suffix}"
        if self.rule_exists(nm): return True, "Rule already exists"
        ok, out = self.create_rule(nm, direction, "Block", remote_addr=ip,
                                desc=f"Blocked by PyWall at {datetime.datetime.now():%Y-%m-%d %H:%M}")
        return ok, out

    def block_port(self, port, proto="TCP", direction="Outbound"):
        nm = f"{PFX}Block_Port{port}_{proto}_{direction[:3]}"
        if self.rule_exists(nm): return True, "Rule already exists"
        return self.create_rule(nm, direction, "Block", remote_port=str(port), protocol=proto,
                                desc=f"Port blocked by PyWall")

    def block_program(self, prog_path, direction="Outbound"):
        safe = Path(prog_path).stem[:30]
        nm = f"{PFX}Block_{safe}_{direction[:3]}"
        if self.rule_exists(nm): return True, "Rule already exists"
        return self.create_rule(nm, direction, "Block", program=prog_path,
                                desc=f"Program blocked by PyWall")

    def allow_ip(self, ip, direction="Outbound"):
        safe = ip.replace(":", "-").replace("/", "_")
        nm = f"{PFX}Allow_{safe}_{direction[:3]}"
        if self.rule_exists(nm): return True, "Rule already exists"
        return self.create_rule(nm, direction, "Allow", remote_addr=ip,
                                desc=f"Allowed by PyWall")

    def allow_program(self, prog_path, direction="Outbound"):
        safe = Path(prog_path).stem[:30]
        nm = f"{PFX}Allow_{safe}_{direction[:3]}"
        if self.rule_exists(nm): return True, "Rule already exists"
        return self.create_rule(nm, direction, "Allow", program=prog_path,
                                desc=f"Program allowed by PyWall")

    # ---- Connection Management ----
    def kill_connection(self, pid):
        """Terminate a process to kill its connections."""
        try:
            p = psutil.Process(pid)
            p.terminate()
            return True
        except: return False

    def kill_connections_by_ip(self, ip):
        """Kill all connections to a specific IP."""
        killed = 0
        for c in psutil.net_connections(kind='all'):
            if c.raddr and c.raddr.ip == ip and c.pid:
                try:
                    psutil.Process(c.pid).terminate()
                    killed += 1
                except: pass
        return killed

fw = FirewallEngine()

# ================================================================
#  THREAT DETECTOR
# ================================================================
class ThreatDetector:
    """Detects port scans, brute force attempts, and suspicious activity."""
    def __init__(self):
        self._lock = Lock()
        self._port_hits = defaultdict(list)   # ip -> [timestamp, ...]
        self._block_hits = defaultdict(list)  # ip -> [timestamp, ...]
        self._events = []
        self._max_events = 500
        self._auto_blocked_threats = set()  # Prevent duplicate threat block rules

    def record_connection(self, ip, port, blocked=False):
        """Record a connection attempt for threat analysis."""
        now = time.time()
        with self._lock:
            if cfg.get("detect_portscan"):
                self._port_hits[ip].append((now, port))
                # Clean old entries (60s window)
                self._port_hits[ip] = [(t, p) for t, p in self._port_hits[ip] if now - t < 60]
                unique_ports = len(set(p for _, p in self._port_hits[ip]))
                if unique_ports >= cfg.get("portscan_threshold", 15):
                    self._add_event("PORT_SCAN", "high", ip,
                                    f"Port scan detected: {unique_ports} ports probed in 60s",
                                    auto_block=cfg.get("threat_auto_block"))
                    self._port_hits[ip].clear()

            if blocked and cfg.get("detect_bruteforce"):
                self._block_hits[ip].append(now)
                self._block_hits[ip] = [t for t in self._block_hits[ip] if now - t < 60]
                if len(self._block_hits[ip]) >= cfg.get("bruteforce_threshold", 10):
                    self._add_event("BRUTE_FORCE", "high", ip,
                                    f"Brute force detected: {len(self._block_hits[ip])} blocked attempts in 60s",
                                    auto_block=cfg.get("threat_auto_block"))
                    self._block_hits[ip].clear()

    def _add_event(self, etype, severity, ip, details, auto_block=False):
        evt = ThreatEvent(
            ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            type=etype, severity=severity, source_ip=ip,
            details=details, blocked=auto_block,
            action_taken="Auto-blocked" if auto_block else "Logged"
        )
        self._events.append(evt)
        if len(self._events) > self._max_events: self._events.pop(0)
        if auto_block and ip:
            if ip not in self._auto_blocked_threats:
                self._auto_blocked_threats.add(ip)
                fw.block_ip(ip, "Inbound", f"_THREAT_{etype}")

    def get_events(self, n=100):
        with self._lock: return list(self._events[-n:])

    def get_stats(self):
        with self._lock:
            total = len(self._events)
            high = sum(1 for e in self._events if e.severity == "high")
            blocked = sum(1 for e in self._events if e.blocked)
            return {"total": total, "high": high, "blocked": blocked}

    def clear(self):
        with self._lock: self._events.clear()

threats = ThreatDetector()

# ================================================================
#  STARTUP & LOGGING
# ================================================================
_tracked_rules_file = CDIR / "tracked_rules.json"
def load_tracked_rules():
    if _tracked_rules_file.exists():
        try:
            with open(_tracked_rules_file) as f: return json.load(f)
        except: pass
    return []
def save_tracked_rules(rules):
    try:
        with open(_tracked_rules_file, "w") as f: json.dump(rules, f, indent=2)
    except: pass

def get_startup_enabled():
    ok, out = _ps(f'Get-ScheduledTask -TaskName "{STARTUP_TASK_NAME}" -EA SilentlyContinue | Select-Object -ExpandProperty State', 10)
    return ok and "Ready" in out

def set_startup_enabled(enabled):
    if enabled:
        exe = sys.executable
        script = os.path.abspath(sys.argv[0])
        if getattr(sys, 'frozen', False):
            cmd = (f'$a=New-ScheduledTaskAction -Execute "{exe}"; '
                   f'$t=New-ScheduledTaskTrigger -AtLogon; '
                   f'$p=New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest; '
                   f'$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0); '
                   f'Register-ScheduledTask -TaskName "{STARTUP_TASK_NAME}" -Action $a -Trigger $t -Principal $p -Settings $s -Force')
        else:
            cmd = (f'$a=New-ScheduledTaskAction -Execute "{exe}" -Argument \'"{script}"\'; '
                   f'$t=New-ScheduledTaskTrigger -AtLogon; '
                   f'$p=New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest; '
                   f'$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 0); '
                   f'Register-ScheduledTask -TaskName "{STARTUP_TASK_NAME}" -Action $a -Trigger $t -Principal $p -Settings $s -Force')
        ok, _ = _ps(cmd, 15); return ok
    else:
        ok, _ = _ps(f'Unregister-ScheduledTask -TaskName "{STARTUP_TASK_NAME}" -Confirm:$false -EA SilentlyContinue', 10)
        return ok

def log_conn(ci):
    if not cfg["log"]: return
    try:
        hdr = not LOGF.exists()
        with open(LOGF, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if hdr: w.writerow(["Time","Src","Dir","Proto","LA","LP","RA","RP","Host","Proc","PID","Svc","Org","Country","CC","Status"])
            w.writerow([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ci.src,ci.dir,ci.proto,ci.la,ci.lp,ci.ra,ci.rp,ci.host,ci.proc,ci.pid,ci.svc,ci.org,ci.country,ci.cc,ci.stat])
    except: pass

# ================================================================
#  WORKER THREADS
# ================================================================
class DNSWorker(QThread):
    ready = pyqtSignal(str, str)
    def __init__(s): super().__init__(); s._q=Queue(); s._stop=TEvent()
    def add(s, ip):
        if ip and ip not in dns_c and not PRIV.match(ip): s._q.put(ip)
    def run(s):
        while not s._stop.is_set():
            try:
                ip = s._q.get(timeout=1)
                if ip in dns_c: continue
                try:
                    h = socket.gethostbyaddr(ip)[0]
                    dns_c.put(ip, h); s.ready.emit(ip, h)
                except: dns_c.put(ip, "-")
            except Empty: pass
    def stop(s): s._stop.set()

class WhoWorker(QThread):
    ready = pyqtSignal(str, str)
    def __init__(s): super().__init__(); s._q=Queue(); s._stop=TEvent()
    def add(s, ip):
        if ip and ip not in who_c and not PRIV.match(ip): s._q.put(ip)
    def run(s):
        while not s._stop.is_set():
            try:
                ip = s._q.get(timeout=1)
                if ip in who_c: continue
                try:
                    r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
                    if r.status_code == 200:
                        d = r.json(); org = d.get("org", "-")
                        who_c.put(ip, org); s.ready.emit(ip, org)
                    else: who_c.put(ip, "-")
                except: who_c.put(ip, "-")
            except Empty: pass
    def stop(s): s._stop.set()

class GeoIPWorker(QThread):
    ready = pyqtSignal(str, str, str)
    def __init__(s): super().__init__(); s._q=Queue(); s._stop=TEvent(); s._batch=[]
    def add(s, ip):
        if ip and ip not in geo_c and not PRIV.match(ip): s._q.put(ip)
    def run(s):
        while not s._stop.is_set():
            try:
                while not s._q.empty() and len(s._batch) < 100:
                    ip = s._q.get_nowait()
                    if ip not in geo_c: s._batch.append(ip)
            except: pass
            if s._batch:
                results = _geoip_batch(s._batch)
                for ip, (cc, country) in results.items():
                    geo_c.put(ip, (cc, country))
                    s.ready.emit(ip, cc, country)
                s._batch.clear()
            s._stop.wait(2)
    def stop(s): s._stop.set()

class ConnWorker(QThread):
    ready = pyqtSignal(list)
    need_dns = pyqtSignal(str)
    need_who = pyqtSignal(str)
    need_geo = pyqtSignal(str)
    first_seen = pyqtSignal(str, str)
    ask_allow = pyqtSignal(object)  # CI for ask-to-allow
    _bg_pool = ThreadPoolExecutor(max_workers=2)  # for background reputation checks
    def __init__(s): super().__init__(); s._stop=TEvent(); s._pool_ref = ConnWorker._bg_pool
    def run(s):
        while not s._stop.is_set():
            try:
                conns = s._scan()
                s.ready.emit(conns)
                bw.update()
                if conns and cfg["history_db"]:
                    conn_db.insert_batch([c for c in conns if c.ra and c.ra != "*" and c.dir != "Listen"])
            except: pass
            s._stop.wait(cfg["poll"])
    def _scan(s):
        out = []; now = datetime.datetime.now().strftime("%H:%M:%S")
        app_profiles = cfg.get("app_profiles", {})
        for c in psutil.net_connections(kind='all'):
            try:
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                la = c.laddr.ip if c.laddr else ""; lp = str(c.laddr.port) if c.laddr else ""
                ra = c.raddr.ip if c.raddr else ""; rp = str(c.raddr.port) if c.raddr else ""
                if not ra:
                    d = "Listen"
                else: d = "Out"
                pid = c.pid or 0
                pn, pp, sv, cm = s._proc(pid)
                st = c.status if hasattr(c, 'status') and c.status else "?"
                key = f"L|{proto}|{la}:{lp}|{ra}:{rp}|{pid}"
                h = dns_c.get(ra, "..."); o = who_c.get(ra, "...")
                geo = geo_c.get(ra); cc = ""; country = "-"
                if geo: cc, country = geo
                elif ra and PRIV.match(ra): cc = "LAN"; country = "Local"
                with blk_lk: rs = "BLOCKED" if ra in blk else "-"
                # Blocklist check
                if h and h not in ("...", "-"):
                    if check_blocklist(h, ra): rs = "BL:TELEMETRY"
                # Application policy enforcement
                proc_lower = pn.lower() if pn else ""
                policy = app_profiles.get(proc_lower, app_profiles.get(pn, ""))
                if policy == "block" and ra and ra != "*" and d != "Listen":
                    rs = "POLICY:BLOCK"
                elif policy == "ask" and ra and ra != "*" and d != "Listen":
                    rs = "POLICY:ASK"
                # Threat detection for inbound
                if ra and ra != "*" and d != "Listen":
                    threats.record_connection(ra, rp, blocked=(rs != "-"))
                    # Only request resolution for IPs not yet cached
                    if dns_c.get(ra, None) is None: s.need_dns.emit(ra)
                    if who_c.get(ra, None) is None: s.need_who.emit(ra)
                    if geo_c.get(ra, None) is None: s.need_geo.emit(ra)
                ci = CI(key=key, ts=now, src="Live", dir=d, proto=proto,
                       la=la, lp=lp, ra=ra or "*", rp=rp or "*",
                       host=h or "-", proc=pn, pid=pid, svc=sv, state=st,
                       path=pp, org=o or "-", cmd=cm, stat=rs,
                       country=country, cc=cc)
                out.append(ci)
                # Backend integrations
                if ra and ra != "*" and d != "Listen":
                    try: reputation.record(ci)
                    except: pass
                    # Background signature + VT check for new processes
                    if pp and pp != "-" and pp not in reputation._sig_cache:
                        _path = pp  # capture for closure
                        def _bg_check(p=_path):
                            try: reputation.check_signature(p)
                            except: pass
                            try: reputation.check_virustotal(p)
                            except: pass
                        try: s._pool_ref.submit(_bg_check)
                        except: pass
                    try: anomaly_det.record(ci)
                    except: pass
                    try: sessions.update(ci)
                    except: pass
                    try: plugins.fire("connection", ci)
                    except: pass
                # First-seen detection
                if pn and pn not in ("?", "System", "-") and ra and ra != "*":
                    if check_first_seen(pn):
                        s.first_seen.emit(pn, pp)
                        if cfg.get("ask_new_apps") and policy not in ("allow", "block"):
                            s.ask_allow.emit(ci)
            except: continue
        return out
    def _proc(s, pid):
        if pid <= 0: return ("System", "-", "-", "-")
        c = prc_c.get(pid)
        if c: return c
        try:
            p = psutil.Process(pid); nm = p.name()
            pp = "-"
            try: pp = _nt_to_dos(p.exe())
            except: pass
            cm = "-"
            try: cm = " ".join(p.cmdline())
            except: pass
            r = (nm, pp, "-", cm); prc_c.put(pid, r); return r
        except: return ("?", "-", "-", "-")
    def stop(s): s._stop.set()

class EvtWorker(QThread):
    ready = pyqtSignal(list)
    new_block = pyqtSignal(object)
    def __init__(s):
        super().__init__(); s._stop = TEvent()
        s._last_id = 0
    def run(s):
        while not s._stop.is_set():
            try: s._poll()
            except: pass
            s._stop.wait(3)
    def _poll(s):
        cmd = ("Get-WinEvent -FilterHashtable @{LogName='Security';Id=5157} -MaxEvents 50 -EA SilentlyContinue | "
               "Select-Object RecordId, TimeCreated, "
               "@{N='SrcAddr';E={$_.Properties[3].Value}}, "
               "@{N='SrcPort';E={$_.Properties[4].Value}}, "
               "@{N='DstAddr';E={$_.Properties[5].Value}}, "
               "@{N='DstPort';E={$_.Properties[6].Value}}, "
               "@{N='Proto';E={$_.Properties[7].Value}}, "
               "@{N='PID';E={$_.Properties[0].Value}}, "
               "@{N='AppPath';E={$_.Properties[1].Value}} | ConvertTo-Json -Compress")
        ok, out = _ps(cmd, 20)
        if not ok or not out: return
        evts = []
        try:
            data = json.loads(out)
            if isinstance(data, dict): data = [data]
        except: return
        for e in data:
            rid = e.get("RecordId", 0)
            if rid <= s._last_id: continue
            s._last_id = max(s._last_id, rid)
            proto = {6:"TCP", 17:"UDP"}.get(e.get("Proto"), str(e.get("Proto","")))
            sa = str(e.get("SrcAddr",""))
            sp = str(e.get("SrcPort",""))
            da = str(e.get("DstAddr",""))
            dp = str(e.get("DstPort",""))
            pid = int(e.get("PID", 0))
            app = _nt_to_dos(str(e.get("AppPath","")))
            proc = Path(app).name if app and app != "-" else "?"
            ts_raw = e.get("TimeCreated","")
            ts = ""
            if ts_raw:
                try:
                    if "/Date(" in str(ts_raw):
                        ms = int(str(ts_raw).split("(")[1].split(")")[0].split("-")[0].split("+")[0])
                        dt = datetime.datetime.fromtimestamp(ms / 1000)
                        ts = dt.strftime("%H:%M:%S")
                    else: ts = str(ts_raw)[-8:]
                except: ts = str(ts_raw)[-8:]
            key = f"E|{proto}|{sa}:{sp}|{da}:{dp}|{rid}"
            ci = CI(key=key, ts=ts, src="Event", dir="Out", proto=proto,
                   la=sa, lp=sp, ra=da, rp=dp, host=dns_c.get(da,"-"),
                   proc=proc, pid=pid, svc="-", state="Blocked",
                   path=app, org=who_c.get(da,"-"), cmd=app, stat="BLOCKED")
            evts.append(ci)
            with blk_lk: blk.add(da)
            s.new_block.emit(ci)
            try: plugins.fire("block", ci)
            except: pass
        if evts: s.ready.emit(evts)
    def stop(s): s._stop.set()

class RuleScanWorker(QThread):
    ready = pyqtSignal(list)
    def __init__(s, filt=""): super().__init__(); s.filt = filt
    def run(s):
        rules = fw.get_all_rules(force_refresh=True)
        if s.filt:
            fl = s.filt.lower()
            rules = [r for r in rules if fl in r.name.lower() or fl in r.program.lower() or fl in r.desc.lower()]
        s.ready.emit(rules)

# ================================================================
#  TRAFFIC CATEGORIZER
# ================================================================
_CATEGORIES = {
    "Streaming": {"netflix","hulu","disney","twitch","youtube","spotify","deezer","tidal","plex",
                  "crunchyroll","hbomax","peacock","paramount","roku","amazonvideo","primevideo"},
    "Social Media": {"facebook","instagram","twitter","x.com","tiktok","snapchat","reddit","linkedin",
                     "pinterest","tumblr","mastodon","threads","bsky"},
    "Gaming": {"steam","valve","epicgames","riotgames","blizzard","battle.net","xbox","playstation",
               "ea.com","ubisoft","gog","origin","bethesda"},
    "Cloud Storage": {"dropbox","onedrive","gdrive","icloud","box.com","mega.nz","pcloud","sync.com",
                      "googledrive","sharepoint"},
    "Messaging": {"discord","slack","telegram","whatsapp","signal","teams","zoom","webex","skype","viber"},
    "Email": {"outlook","gmail","yahoo","protonmail","thunderbird","imap","smtp","pop3"},
    "Development": {"github","gitlab","bitbucket","stackoverflow","npmjs","pypi","docker","aws",
                    "azure","gcloud","heroku","vercel","netlify"},
    "Ads/Tracking": {"doubleclick","googlesyndication","googleadservices","facebook.com/tr",
                     "analytics","adnxs","criteo","taboola","outbrain","amplitude","mixpanel","segment"},
    "System": {"windowsupdate","microsoft.com","msedge","msn.com","bing.com","office","windows.net",
               "akamai","cloudflare","fastly","amazonaws","azure"},
    "CDN": {"akamai","cloudflare","fastly","cloudfront","edgecast","stackpath","jsdelivr","unpkg"},
    "VPN/Proxy": {"nordvpn","expressvpn","protonvpn","surfshark","mullvad","windscribe","openvpn","wireguard"},
    "Shopping": {"amazon","ebay","etsy","shopify","walmart","target","aliexpress","wish"},
}
_PORT_CATEGORIES = {
    (80, 443, 8080, 8443): "Web",
    (25, 110, 143, 465, 587, 993, 995): "Email",
    (21, 22, 990): "File Transfer",
    (53, 5353): "DNS",
    (3389,): "Remote Desktop",
    (5900, 5901): "VNC",
    (1433, 3306, 5432, 27017, 6379): "Database",
}

class TrafficCategorizer:
    """Classify connections into human-readable categories."""
    def __init__(self):
        self._cache = {}

    def categorize(self, host, ra, rp, proc=""):
        key = f"{host}|{ra}|{rp}|{proc}"
        if key in self._cache: return self._cache[key]
        cat = self._classify(host, ra, rp, proc)
        self._cache[key] = cat
        return cat

    def _classify(self, host, ra, rp, proc):
        h = (host or "").lower()
        p = proc.lower() if proc else ""
        # Check domain-based categories
        for cat, keywords in _CATEGORIES.items():
            for kw in keywords:
                if kw in h or kw in p:
                    return cat
        # Check port-based categories
        try:
            port = int(rp)
            for ports, cat in _PORT_CATEGORIES.items():
                if port in ports: return cat
        except (ValueError, TypeError): pass
        # Private IP = LAN
        if ra and PRIV.match(ra): return "LAN"
        return "Unknown"

    def get_summary(self, connections):
        """Return {category: count} from a list of CI objects."""
        counts = {}
        for c in connections:
            cat = self.categorize(c.host, c.ra, c.rp, c.proc)
            counts[cat] = counts.get(cat, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

categorizer = TrafficCategorizer()

# ================================================================
#  PROCESS REPUTATION SCORING
# ================================================================
class ReputationScorer:
    """Assign trust scores to processes based on behavior, signatures, and threat intel."""
    def __init__(self):
        self._scores = {}     # proc_name -> {score, reasons, last_update}
        self._history = {}    # proc_name -> {conn_count, unique_ips, first_seen, countries}
        self._sig_cache = {}  # path -> "Signed"|"Unsigned"|"Unknown"
        self._vt_cache = {}   # sha256 -> {positives, total, scanned}
        self._hash_cache = {} # path -> sha256
        self._known_safe = {"svchost.exe","system","lsass.exe","services.exe","csrss.exe",
                           "explorer.exe","taskhostw.exe","sihost.exe","ctfmon.exe",
                           "chrome.exe","firefox.exe","msedge.exe","code.exe","cmd.exe",
                           "powershell.exe","windowsterminal.exe","python.exe","python3.exe",
                           "node.exe","git.exe","conhost.exe","dllhost.exe","smartscreen.exe",
                           "searchhost.exe","runtimebroker.exe","applicationframehost.exe",
                           "textinputhost.exe","securityhealthservice.exe","msiexec.exe"}

    def record(self, ci):
        """Record a connection for reputation tracking."""
        proc = ci.proc.lower() if ci.proc else "?"
        if proc not in self._history:
            self._history[proc] = {"conn_count": 0, "unique_ips": set(), "unique_ports": set(),
                                    "first_seen": time.time(), "countries": set(), "blocked": 0,
                                    "path": ci.path or "-"}
        h = self._history[proc]
        h["conn_count"] += 1
        if ci.ra and ci.ra not in ("*", ""): h["unique_ips"].add(ci.ra)
        if ci.rp and ci.rp not in ("*", ""): h["unique_ports"].add(ci.rp)
        if ci.country and ci.country not in ("-", "Local", ""): h["countries"].add(ci.country)
        if ci.stat and ci.stat.startswith(("BLOCKED", "POLICY:BLOCK", "BL:")): h["blocked"] += 1

    def check_signature(self, path):
        """Check if executable is digitally signed (cached)."""
        if not path or path == "-": return "Unknown"
        if path in self._sig_cache: return self._sig_cache[path]
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-Command",
                f"(Get-AuthenticodeSignature '{path}').Status"],
                capture_output=True, text=True, timeout=10, creationflags=NOWIN_FLAG)
            status = r.stdout.strip()
            result = "Signed" if status == "Valid" else ("Unsigned" if status == "NotSigned" else status)
            self._sig_cache[path] = result
            return result
        except:
            self._sig_cache[path] = "Unknown"
            return "Unknown"

    def get_file_hash(self, path):
        """Get SHA256 hash of a file (cached)."""
        if not path or path == "-": return None
        if path in self._hash_cache: return self._hash_cache[path]
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
            result = h.hexdigest()
            self._hash_cache[path] = result
            return result
        except:
            return None

    def check_virustotal(self, path):
        """Check file hash against VirusTotal API (requires API key in config)."""
        api_key = cfg.get("vt_api_key", "")
        if not api_key: return None
        if path in self._vt_cache: return self._vt_cache[path]
        file_hash = self.get_file_hash(path)
        if not file_hash: return None
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": api_key}, timeout=15)
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result = {"malicious": data.get("malicious", 0), "suspicious": data.get("suspicious", 0),
                          "undetected": data.get("undetected", 0), "harmless": data.get("harmless", 0),
                          "scanned": True}
                self._vt_cache[path] = result
                return result
            elif r.status_code == 404:
                self._vt_cache[path] = {"malicious": 0, "suspicious": 0, "scanned": False}
                return self._vt_cache[path]
        except: pass
        return None

    def score(self, proc_name):
        """Calculate reputation score 0-100 for a process."""
        proc = proc_name.lower()
        # Known safe system processes
        if proc in self._known_safe:
            return {"score": 85, "grade": "A", "reasons": ["Known system/common application"]}
        h = self._history.get(proc)
        if not h:
            return {"score": 50, "grade": "C", "reasons": ["No connection history yet"]}
        score = 50
        reasons = []
        # Age bonus (up to +15)
        age_days = (time.time() - h["first_seen"]) / 86400
        if age_days > 7: score += 5; reasons.append("Seen for 7+ days")
        if age_days > 30: score += 10; reasons.append("Seen for 30+ days")
        # Signed binary check (+15 / -10)
        path = h.get("path", "")
        if path and path != "-":
            sig = self._sig_cache.get(path)
            if sig == "Signed": score += 15; reasons.append("Digitally signed binary")
            elif sig == "Unsigned": score -= 10; reasons.append("NOT digitally signed")
            try:
                if Path(path).exists():
                    loc = str(Path(path)).lower()
                    if "program files" in loc or "windows" in loc:
                        score += 10; reasons.append("Installed in trusted location")
            except: pass
        # VirusTotal results
        vt = self._vt_cache.get(path)
        if vt and vt.get("scanned"):
            if vt["malicious"] > 0:
                score -= min(40, vt["malicious"] * 5)
                reasons.append(f"VirusTotal: {vt['malicious']} detections!")
            elif vt["suspicious"] > 0:
                score -= 10; reasons.append(f"VirusTotal: {vt['suspicious']} suspicious")
            else:
                score += 10; reasons.append("VirusTotal: clean")
        # Connection pattern
        ips = len(h["unique_ips"])
        if ips > 50: score -= 10; reasons.append(f"High IP diversity ({ips} unique)")
        elif ips < 10: score += 5; reasons.append("Focused connection pattern")
        # Block ratio penalty
        if h["conn_count"] > 10:
            block_ratio = h["blocked"] / h["conn_count"]
            if block_ratio > 0.3: score -= 15; reasons.append(f"{block_ratio:.0%} connections blocked")
            elif block_ratio == 0: score += 5; reasons.append("No blocked connections")
        # Country diversity
        countries = len(h["countries"])
        if countries > 10: score -= 5; reasons.append(f"Connects to {countries} countries")
        # Port scan behavior
        ports = len(h["unique_ports"])
        if ports > 20: score -= 10; reasons.append(f"Uses {ports} different ports")
        score = max(0, min(100, score))
        if score >= 75: grade = "A"
        elif score >= 60: grade = "B"
        elif score >= 40: grade = "C"
        elif score >= 20: grade = "D"
        else: grade = "F"
        return {"score": score, "grade": grade, "reasons": reasons}

    def get_all_scores(self):
        """Return sorted list of (proc_name, score_dict)."""
        results = []
        for proc in self._history:
            results.append((proc, self.score(proc)))
        results.sort(key=lambda x: x[1]["score"])
        return results

reputation = ReputationScorer()

# ================================================================
#  ANOMALY DETECTION
# ================================================================
class AnomalyDetector:
    """Detect anomalous network behavior by baselining normal patterns."""
    def __init__(self):
        self._baselines = {}    # proc -> {avg_conns_per_min, avg_unique_ips, avg_bytes, std_*}
        self._windows = {}      # proc -> deque of (timestamp, conn_count, unique_ips)
        self._alerts = []       # list of anomaly alert dicts
        self._window_sec = 300  # 5 min windows
        self._last_window = 0
        self._known_countries = {}  # proc -> set of countries seen
        self._global_countries = set()  # all countries ever connected to
        self._hourly_procs = defaultdict(set)  # hour -> set of procs active at that hour

    def record(self, ci):
        """Record connection for anomaly baselining."""
        proc = ci.proc.lower() if ci.proc else "?"
        now = time.time()
        if proc not in self._windows:
            self._windows[proc] = {"counts": [], "current": {"ts": now, "conns": 0, "ips": set()}}
        w = self._windows[proc]
        w["current"]["conns"] += 1
        if ci.ra: w["current"]["ips"].add(ci.ra)
        # GeoIP novelty tracking
        if ci.country and ci.country not in ("-", "Local", "", "..."):
            if proc not in self._known_countries:
                self._known_countries[proc] = set()
            if ci.country not in self._known_countries[proc]:
                # New country for this process!
                is_new_global = ci.country not in self._global_countries
                self._known_countries[proc].add(ci.country)
                self._global_countries.add(ci.country)
                # Alert if process has history but this is a new country
                if proc in self._baselines or (proc in self._windows and
                        len(self._windows[proc].get("counts", [])) > 3):
                    hour = datetime.datetime.now().hour
                    severity = "New country"
                    if is_new_global:
                        severity = "First-ever connection to country"
                    if hour < 6 or hour > 23:
                        severity += " (unusual hour)"
                    self.add_alert(proc, [f"{severity}: {ci.country} ({ci.cc}) via {ci.ra}"])
        # Track hourly activity
        hour = datetime.datetime.now().hour
        self._hourly_procs[hour].add(proc)
        # Unusual hour detection
        if len(self._hourly_procs) > 24:
            if proc not in self._hourly_procs.get((hour - 1) % 24, set()) and \
               proc not in self._hourly_procs.get((hour + 1) % 24, set()) and \
               len(self._windows.get(proc, {}).get("counts", [])) > 12:
                # Process not normally active at this hour
                pass  # Only flag if combined with other anomalies
        # Roll window
        if now - w["current"]["ts"] > self._window_sec:
            w["counts"].append({"conns": w["current"]["conns"],
                                "ips": len(w["current"]["ips"]), "ts": w["current"]["ts"]})
            # Keep 288 windows (24 hours at 5 min intervals)
            if len(w["counts"]) > 288: w["counts"] = w["counts"][-288:]
            w["current"] = {"ts": now, "conns": 0, "ips": set()}
            self._update_baseline(proc)

    def _update_baseline(self, proc):
        w = self._windows.get(proc)
        if not w or len(w["counts"]) < 6: return  # Need 30+ min of data
        conns = [x["conns"] for x in w["counts"]]
        ips = [x["ips"] for x in w["counts"]]
        self._baselines[proc] = {
            "avg_conns": statistics.mean(conns),
            "std_conns": statistics.stdev(conns) if len(conns) > 1 else 0,
            "avg_ips": statistics.mean(ips),
            "std_ips": statistics.stdev(ips) if len(ips) > 1 else 0,
            "samples": len(conns),
        }

    def check(self, proc, sensitivity=2.0):
        """Check current window against baseline. Returns list of anomaly descriptions."""
        proc = proc.lower()
        b = self._baselines.get(proc)
        w = self._windows.get(proc)
        if not b or not w or b["samples"] < 6: return []
        anomalies = []
        curr = w["current"]
        # Connection count anomaly
        if b["std_conns"] > 0:
            z_conns = (curr["conns"] - b["avg_conns"]) / b["std_conns"]
            if z_conns > sensitivity:
                anomalies.append(f"Unusual connection volume: {curr['conns']} "
                                 f"(normal: {b['avg_conns']:.0f}+/-{b['std_conns']:.0f})")
        elif curr["conns"] > b["avg_conns"] * 3 and curr["conns"] > 10:
            anomalies.append(f"Connection spike: {curr['conns']} (normal: {b['avg_conns']:.0f})")
        # IP diversity anomaly
        curr_ips = len(curr["ips"])
        if b["std_ips"] > 0:
            z_ips = (curr_ips - b["avg_ips"]) / b["std_ips"]
            if z_ips > sensitivity:
                anomalies.append(f"Unusual IP diversity: {curr_ips} "
                                 f"(normal: {b['avg_ips']:.0f}+/-{b['std_ips']:.0f})")
        return anomalies

    def get_alerts(self):
        return list(self._alerts)

    def add_alert(self, proc, anomalies):
        self._alerts.append({
            "ts": datetime.datetime.now().strftime("%H:%M:%S"),
            "proc": proc, "anomalies": anomalies,
        })
        if len(self._alerts) > 500: self._alerts = self._alerts[-500:]

    def get_country_stats(self):
        """Return per-process country novelty info."""
        return {proc: list(countries) for proc, countries in self._known_countries.items()}

anomaly_det = AnomalyDetector()

# ================================================================
#  RULE SCHEDULER
# ================================================================
class RuleScheduler:
    """Enable/disable firewall rules based on time schedules."""
    def __init__(self):
        self._schedules = []  # loaded from config
        self._states = {}     # rule_name -> currently_enabled

    def load(self):
        self._schedules = cfg.get("scheduled_rules", [])

    def save(self):
        cfg["scheduled_rules"] = self._schedules
        cfg.save()

    def add(self, rule_name, days, start_time, end_time, action="enable"):
        self._schedules.append({
            "rule_name": rule_name, "days": days,
            "start": start_time, "end": end_time,
            "action": action, "active": True,
        })
        self.save()

    def remove(self, index):
        if 0 <= index < len(self._schedules):
            self._schedules.pop(index)
            self.save()

    def tick(self):
        """Called periodically to check and apply schedules."""
        now = datetime.datetime.now()
        day = now.weekday()  # 0=Mon, 6=Sun
        current = now.strftime("%H:%M")
        for sched in self._schedules:
            if not sched.get("active"): continue
            name = sched["rule_name"]
            if day not in sched.get("days", []): continue
            in_window = sched["start"] <= current <= sched["end"]
            should_enable = (in_window and sched["action"] == "enable") or \
                           (not in_window and sched["action"] == "disable")
            curr_state = self._states.get(name)
            if should_enable and curr_state is not True:
                fw.toggle_rule(name, True)
                self._states[name] = True
            elif not should_enable and curr_state is not False:
                fw.toggle_rule(name, False)
                self._states[name] = False

    def get_schedules(self): return list(self._schedules)

scheduler = RuleScheduler()

# ================================================================
#  NETWORK PROFILE MANAGER
# ================================================================
class NetworkProfileManager:
    """Detect network changes and auto-switch firewall profiles."""
    def __init__(self):
        self._current = ""
        self._profiles = cfg.get("net_profiles", {})

    def detect_network(self):
        """Detect current network name via netsh."""
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5, creationflags=NOWIN_FLAG)
            for line in r.stdout.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid: return ssid
        except: pass
        # Fallback: use active connection name
        try:
            r = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=5, creationflags=NOWIN_FLAG)
            for line in r.stdout.splitlines():
                if "Connected" in line:
                    parts = line.split()
                    if len(parts) >= 4: return parts[-1]
        except: pass
        return "Unknown"

    def check_and_switch(self):
        """Check if network changed and apply corresponding profile."""
        network = self.detect_network()
        if network == self._current: return None
        old = self._current
        self._current = network
        if not cfg.get("auto_switch_profile"): return None
        profile = self._profiles.get(network)
        if profile:
            if "fw_mode" in profile: cfg["fw_mode"] = profile["fw_mode"]
            if "app_profiles" in profile:
                existing = cfg.get("app_profiles", {})
                existing.update(profile["app_profiles"])
                cfg["app_profiles"] = existing
            cfg.save()
            return f"Switched to profile '{network}' (from '{old}')"
        return None

    def save_current_as(self, name):
        self._profiles[name] = {
            "fw_mode": cfg["fw_mode"],
            "app_profiles": dict(cfg.get("app_profiles", {})),
        }
        cfg["net_profiles"] = self._profiles
        cfg.save()

    def get_profiles(self): return dict(self._profiles)
    def get_current_network(self): return self._current
    def remove_profile(self, name):
        self._profiles.pop(name, None)
        cfg["net_profiles"] = self._profiles
        cfg.save()

net_profiles = NetworkProfileManager()

# ================================================================
#  BANDWIDTH QUOTA MANAGER
# ================================================================
class BandwidthQuotaManager:
    """Track bandwidth per process and enforce daily/weekly quotas."""
    def __init__(self):
        self._daily = {}     # proc -> bytes today
        self._weekly = {}    # proc -> bytes this week
        self._global_daily = 0
        self._last_day = datetime.date.today()
        self._last_week = datetime.date.today().isocalendar()[1]
        self._violations = []

    def record(self, proc, nbytes):
        """Record bandwidth for a process."""
        today = datetime.date.today()
        week = today.isocalendar()[1]
        if today != self._last_day:
            self._daily.clear(); self._last_day = today; self._global_daily = 0
        if week != self._last_week:
            self._weekly.clear(); self._last_week = week
        p = proc.lower()
        self._daily[p] = self._daily.get(p, 0) + nbytes
        self._weekly[p] = self._weekly.get(p, 0) + nbytes
        self._global_daily += nbytes

    def check_quotas(self):
        """Check all quotas and return list of violations."""
        violations = []
        quotas = cfg.get("quotas", {})
        for proc, limits in quotas.items():
            p = proc.lower()
            daily = self._daily.get(p, 0) / (1024*1024)
            weekly = self._weekly.get(p, 0) / (1024*1024)
            daily_limit = limits.get("daily_mb", 0)
            weekly_limit = limits.get("weekly_mb", 0)
            if daily_limit > 0 and daily > daily_limit:
                violations.append({"proc": proc, "type": "daily", "usage_mb": daily,
                                    "limit_mb": daily_limit, "action": limits.get("action", "alert")})
            if weekly_limit > 0 and weekly > weekly_limit:
                violations.append({"proc": proc, "type": "weekly", "usage_mb": weekly,
                                    "limit_mb": weekly_limit, "action": limits.get("action", "alert")})
        # Global daily
        gdl = cfg.get("global_daily_mb", 0)
        if gdl > 0 and self._global_daily / (1024*1024) > gdl:
            violations.append({"proc": "GLOBAL", "type": "daily",
                                "usage_mb": self._global_daily / (1024*1024),
                                "limit_mb": gdl, "action": "alert"})
        self._violations = violations
        return violations

    def get_usage(self):
        """Return sorted daily usage."""
        return sorted(self._daily.items(), key=lambda x: -x[1])

    def get_violations(self): return list(self._violations)

quota_mgr = BandwidthQuotaManager()

# ================================================================
#  DNS-LEVEL BLOCKER
# ================================================================
class DNSBlocker:
    """Block domains at DNS level using Windows hosts file."""
    _HOSTS = Path("C:/Windows/System32/drivers/etc/hosts")
    _MARKER_START = "# === PyWall DNS Block Start ==="
    _MARKER_END = "# === PyWall DNS Block End ==="

    def __init__(self):
        self._blocked = set()
        self._load()

    def _load(self):
        """Load current PyWall DNS blocks from hosts file."""
        try:
            content = self._HOSTS.read_text(encoding="utf-8")
            in_block = False
            for line in content.splitlines():
                if self._MARKER_START in line: in_block = True; continue
                if self._MARKER_END in line: in_block = False; continue
                if in_block and line.strip() and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2: self._blocked.add(parts[1].lower())
        except: pass

    def add(self, domain):
        self._blocked.add(domain.lower().strip())
        self._write()

    def remove(self, domain):
        self._blocked.discard(domain.lower().strip())
        self._write()

    def _write(self):
        """Rewrite PyWall section of hosts file."""
        try:
            content = self._HOSTS.read_text(encoding="utf-8")
            lines = content.splitlines()
            out = []; skip = False
            for line in lines:
                if self._MARKER_START in line: skip = True; continue
                if self._MARKER_END in line: skip = False; continue
                if not skip: out.append(line)
            # Append our block
            if self._blocked:
                out.append("")
                out.append(self._MARKER_START)
                for d in sorted(self._blocked):
                    out.append(f"0.0.0.0 {d}")
                out.append(self._MARKER_END)
            self._HOSTS.write_text("\n".join(out) + "\n", encoding="utf-8")
            # Flush DNS
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                          creationflags=NOWIN_FLAG, timeout=10)
        except Exception as e:
            log.warning(f"DNS blocker write failed: {e}")

    def get_blocked(self): return sorted(self._blocked)
    def is_blocked(self, domain): return domain.lower() in self._blocked

dns_blocker = DNSBlocker()

# ================================================================
#  PLUGIN SYSTEM
# ================================================================
class PluginManager:
    """Load and execute Python plugin scripts from the plugins directory."""
    def __init__(self):
        self._plugins = {}    # name -> module
        self._hooks = {}      # event_name -> [callback, ...]

    def load_all(self):
        """Scan plugins directory and load all .py files."""
        if not cfg.get("plugins_enabled"): return
        self._plugins.clear()
        self._hooks.clear()
        for f in PLUGDIR.glob("*.py"):
            try:
                name = f.stem
                spec = importlib.util.spec_from_file_location(name, f)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                self._plugins[name] = mod
                # Register hooks
                if hasattr(mod, "on_connection"):
                    self._hooks.setdefault("connection", []).append(mod.on_connection)
                if hasattr(mod, "on_block"):
                    self._hooks.setdefault("block", []).append(mod.on_block)
                if hasattr(mod, "on_threat"):
                    self._hooks.setdefault("threat", []).append(mod.on_threat)
                if hasattr(mod, "on_start"):
                    self._hooks.setdefault("start", []).append(mod.on_start)
                if hasattr(mod, "on_stop"):
                    self._hooks.setdefault("stop", []).append(mod.on_stop)
            except Exception as e:
                log.warning(f"Plugin load failed [{f.name}]: {e}")

    def fire(self, event, *args, **kwargs):
        """Fire all hooks for an event."""
        for cb in self._hooks.get(event, []):
            try: cb(*args, **kwargs)
            except Exception as e:
                log.warning(f"Plugin hook error [{event}]: {e}")

    def get_plugins(self):
        return {name: {"file": str(PLUGDIR / f"{name}.py"),
                        "hooks": [e for e, cbs in self._hooks.items()
                                  for cb in cbs if cb.__module__ == name]}
                for name, mod in self._plugins.items()}

    def reload(self):
        self.load_all()

    def create_example_plugins(self):
        """Create example plugin files if plugin directory is empty."""
        PLUGDIR.mkdir(parents=True, exist_ok=True)
        existing = list(PLUGDIR.glob("*.py"))
        if existing: return  # Don't overwrite
        examples = {
            "webhook_notifier.py": '''"""Webhook Notifier - Send alerts to any webhook URL (Slack, Discord, Teams)."""
import requests, json

WEBHOOK_URL = ""  # Set your webhook URL here

def on_block(ci):
    if not WEBHOOK_URL: return
    try:
        payload = {"text": f"[PyWall] Blocked: {ci.proc} -> {ci.ra}:{ci.rp} ({ci.country})"}
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
    except: pass

def on_threat(event):
    if not WEBHOOK_URL: return
    try:
        payload = {"text": f"[PyWall THREAT] {event.type}: {event.source_ip} - {event.details}"}
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
    except: pass

def on_start():
    if not WEBHOOK_URL: return
    try: requests.post(WEBHOOK_URL, json={"text": "[PyWall] Monitoring started"}, timeout=5)
    except: pass
''',
            "csv_logger.py": '''"""CSV Logger - Log all connections and blocks to CSV files."""
import csv, os, datetime
from pathlib import Path

LOG_DIR = Path(os.environ.get("APPDATA", ".")) / "PyWall" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

def _get_file():
    return LOG_DIR / f"connections_{datetime.date.today().isoformat()}.csv"

def on_connection(ci):
    f = _get_file()
    new = not f.exists()
    with open(f, "a", newline="") as fp:
        w = csv.writer(fp)
        if new: w.writerow(["time","process","remote_ip","remote_port","hostname","country","status"])
        w.writerow([ci.ts, ci.proc, ci.ra, ci.rp, ci.host, ci.country, ci.stat])

def on_block(ci):
    f = LOG_DIR / f"blocks_{datetime.date.today().isoformat()}.csv"
    new = not f.exists()
    with open(f, "a", newline="") as fp:
        w = csv.writer(fp)
        if new: w.writerow(["time","process","remote_ip","remote_port","hostname","country"])
        w.writerow([ci.ts, ci.proc, ci.ra, ci.rp, ci.host, ci.country])
''',
            "ip_reputation.py": '''"""IP Reputation Checker - Flag connections to known malicious IPs using AbuseIPDB."""
import requests

API_KEY = ""  # Set your AbuseIPDB API key here
_checked = set()

def on_connection(ci):
    if not API_KEY or not ci.ra or ci.ra == "*": return
    if ci.ra in _checked: return
    _checked.add(ci.ra)
    if len(_checked) > 5000: _checked.clear()  # Prevent memory bloat
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
            headers={"Key": API_KEY, "Accept": "application/json"},
            params={"ipAddress": ci.ra, "maxAgeInDays": 90}, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            if score > 50:
                print(f"[IP-REP] HIGH RISK: {ci.ra} (score: {score}%) - {ci.proc}")
    except: pass
''',
            "connection_stats.py": '''"""Connection Stats - Track and report connection statistics on stop."""
from collections import defaultdict

_stats = defaultdict(lambda: {"conns": 0, "ips": set(), "blocked": 0})

def on_connection(ci):
    proc = ci.proc or "?"
    _stats[proc]["conns"] += 1
    if ci.ra: _stats[proc]["ips"].add(ci.ra)
    if ci.stat and ci.stat not in ("-", ""): _stats[proc]["blocked"] += 1

def on_stop():
    print("\\n=== PyWall Session Statistics ===")
    for proc, s in sorted(_stats.items(), key=lambda x: -x[1]["conns"])[:10]:
        print(f"  {proc}: {s['conns']} connections, {len(s['ips'])} unique IPs, {s['blocked']} blocked")
    _stats.clear()
''',
        }
        for name, content in examples.items():
            try:
                (PLUGDIR / name).write_text(content, encoding="utf-8")
            except: pass

plugins = PluginManager()

# ================================================================
#  RULE TEMPLATES
# ================================================================
RULE_TEMPLATES = {
    "Privacy Mode": {
        "desc": "Block known telemetry, tracking, and advertising endpoints.",
        "rules": [
            {"name": "Block_Telemetry_Out", "direction": "Outbound", "action": "Block",
             "remote_addr": "13.107.4.50,13.69.131.175,13.107.5.88,131.253.33.203,40.77.226.250",
             "desc": "Block Microsoft telemetry IPs"},
            {"name": "Block_Ads_DNS", "direction": "Outbound", "action": "Block",
             "remote_port": "443", "protocol": "TCP",
             "remote_addr": "216.58.215.226,172.217.14.99",
             "desc": "Block common ad servers"},
        ],
        "settings": {"blocklist_telemetry": True, "blocklist_ads": True},
    },
    "Gaming PC": {
        "desc": "Allow gaming platforms, block telemetry and background noise.",
        "rules": [
            {"name": "Allow_Steam", "direction": "Outbound", "action": "Allow",
             "program": "C:\\Program Files (x86)\\Steam\\steam.exe", "desc": "Allow Steam"},
            {"name": "Allow_Discord", "direction": "Outbound", "action": "Allow",
             "program": "C:\\Users\\*\\AppData\\Local\\Discord\\*\\Discord.exe", "desc": "Allow Discord"},
            {"name": "Block_Telemetry_Out", "direction": "Outbound", "action": "Block",
             "remote_addr": "13.107.4.50,13.69.131.175", "desc": "Block telemetry"},
        ],
        "settings": {"blocklist_telemetry": True},
    },
    "Work Lockdown": {
        "desc": "Strict mode: block all outbound except browser, email, and VPN.",
        "rules": [
            {"name": "Block_All_Out", "direction": "Outbound", "action": "Block",
             "desc": "Default block all outbound"},
            {"name": "Allow_HTTPS_Out", "direction": "Outbound", "action": "Allow",
             "remote_port": "443", "protocol": "TCP", "desc": "Allow HTTPS"},
            {"name": "Allow_HTTP_Out", "direction": "Outbound", "action": "Allow",
             "remote_port": "80", "protocol": "TCP", "desc": "Allow HTTP"},
            {"name": "Allow_DNS_Out", "direction": "Outbound", "action": "Allow",
             "remote_port": "53", "protocol": "UDP", "desc": "Allow DNS"},
        ],
        "settings": {"fw_mode": "whitelist"},
    },
    "Server Hardening": {
        "desc": "Block all outbound except updates, allow only specified inbound.",
        "rules": [
            {"name": "Block_All_Out", "direction": "Outbound", "action": "Block",
             "desc": "Block all outbound by default"},
            {"name": "Allow_WinUpdate", "direction": "Outbound", "action": "Allow",
             "remote_port": "443", "protocol": "TCP",
             "program": "C:\\Windows\\System32\\svchost.exe", "desc": "Allow Windows Update"},
            {"name": "Allow_DNS_Out", "direction": "Outbound", "action": "Allow",
             "remote_port": "53", "protocol": "UDP", "desc": "Allow DNS"},
            {"name": "Block_All_In", "direction": "Inbound", "action": "Block",
             "desc": "Block all inbound by default"},
        ],
        "settings": {"fw_mode": "whitelist", "auto_block_inbound": True},
    },
    "Maximum Privacy": {
        "desc": "Aggressive privacy: block all telemetry, ads, trackers, and non-essential traffic.",
        "rules": [
            {"name": "Block_MS_Telemetry_1", "direction": "Outbound", "action": "Block",
             "remote_addr": "13.107.4.50,13.69.131.175,13.107.5.88,131.253.33.203,40.77.226.250,40.77.228.92",
             "desc": "Microsoft telemetry batch 1"},
            {"name": "Block_MS_Telemetry_2", "direction": "Outbound", "action": "Block",
             "remote_addr": "52.114.74.43,52.114.77.164,52.114.132.73,52.178.178.16",
             "desc": "Microsoft telemetry batch 2"},
        ],
        "settings": {"blocklist_telemetry": True, "blocklist_ads": True, "dns_block_enabled": True},
    },
    "Minimal Monitoring": {
        "desc": "Light touch: just monitor and log, no blocking.",
        "rules": [],
        "settings": {"fw_mode": "monitor", "threat_auto_block": False,
                     "auto_block_inbound": False, "ask_new_apps": False},
    },
}

# ================================================================
#  EXPORT / IMPORT
# ================================================================
class ConfigExporter:
    """Export/import full PyWall configuration."""
    @staticmethod
    def export_all(filepath):
        """Export rules, settings, app profiles to a JSON file."""
        data = {
            "version": VER, "exported": datetime.datetime.now().isoformat(),
            "settings": dict(cfg.d),
            "pywall_rules": [],
            "scheduled_rules": cfg.get("scheduled_rules", []),
            "net_profiles": cfg.get("net_profiles", {}),
            "quotas": cfg.get("quotas", {}),
            "dns_blocked": dns_blocker.get_blocked(),
        }
        # Get PyWall rules
        for r in fw.get_pywall_rules():
            data["pywall_rules"].append({
                "name": r.name, "direction": r.direction, "action": r.action,
                "enabled": r.enabled, "profile": r.profile, "remote_addr": r.remote_addr,
                "remote_port": r.remote_port, "local_addr": r.local_addr,
                "local_port": r.local_port, "protocol": r.protocol,
                "program": r.program, "desc": r.desc,
            })
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return True

    @staticmethod
    def import_all(filepath, merge=True):
        """Import configuration. merge=True keeps existing rules, False replaces all."""
        with open(filepath) as f:
            data = json.load(f)
        results = {"settings": 0, "rules_created": 0, "rules_skipped": 0, "errors": []}
        # Settings
        if "settings" in data:
            for k, v in data["settings"].items():
                if k not in ("app_profiles", "net_profiles", "scheduled_rules", "quotas"):
                    cfg[k] = v
                    results["settings"] += 1
            # Merge app profiles
            if "app_profiles" in data["settings"]:
                existing = cfg.get("app_profiles", {})
                existing.update(data["settings"]["app_profiles"])
                cfg["app_profiles"] = existing
        # Rules
        existing_names = {r.name for r in fw.get_pywall_rules()}
        for r in data.get("pywall_rules", []):
            if r["name"] in existing_names:
                results["rules_skipped"] += 1; continue
            ok, out = fw.create_rule(
                name=r["name"], direction=r.get("direction", "Outbound"),
                action=r.get("action", "Block"), remote_addr=r.get("remote_addr", ""),
                remote_port=r.get("remote_port", ""), local_addr=r.get("local_addr", ""),
                local_port=r.get("local_port", ""), protocol=r.get("protocol", ""),
                program=r.get("program", ""), profile=r.get("profile", "Any"),
                desc=r.get("desc", ""), enabled=r.get("enabled", True))
            if ok: results["rules_created"] += 1
            else: results["errors"].append(f"{r['name']}: {out[:60]}")
        # Scheduled rules, profiles, quotas
        if "scheduled_rules" in data:
            cfg["scheduled_rules"] = data["scheduled_rules"]
        if "net_profiles" in data:
            cfg["net_profiles"] = data["net_profiles"]
        if "quotas" in data:
            cfg["quotas"] = data["quotas"]
        # DNS blocks
        for d in data.get("dns_blocked", []):
            dns_blocker.add(d)
        cfg.save()
        return results

exporter = ConfigExporter()

# ================================================================
#  RULE CONFLICT DETECTOR
# ================================================================
class RuleConflictDetector:
    """Detect contradictory or redundant firewall rules."""
    def analyze(self, rules=None):
        """Return list of conflict/issue dicts."""
        if rules is None: rules = fw.get_all_rules(force_refresh=True)
        issues = []
        # Index rules by scope
        ip_rules = defaultdict(list)     # ip -> [(rule, action)]
        port_rules = defaultdict(list)   # port -> [(rule, action)]
        prog_rules = defaultdict(list)   # program -> [(rule, action)]
        for r in rules:
            if not r.enabled: continue
            if r.remote_addr and r.remote_addr not in ("*", "Any", ""):
                for addr in r.remote_addr.split(","):
                    ip_rules[addr.strip()].append(r)
            if r.remote_port and r.remote_port not in ("*", "Any", ""):
                for port in r.remote_port.replace("-", ",").split(","):
                    port_rules[port.strip()].append(r)
            if r.program and r.program not in ("*", "Any", ""):
                prog_rules[r.program.lower()].append(r)
        # Find IP conflicts (same IP, different actions)
        for ip, rlist in ip_rules.items():
            actions = set(r.action for r in rlist)
            if len(actions) > 1:
                names = [r.name for r in rlist]
                issues.append({
                    "type": "conflict", "severity": "high",
                    "desc": f"IP {ip} has both Allow and Block rules",
                    "rules": names, "suggestion": "Remove one to avoid unpredictable behavior",
                })
        # Find program conflicts
        for prog, rlist in prog_rules.items():
            dirs = defaultdict(list)
            for r in rlist: dirs[(r.direction, r.action)].append(r)
            actions_out = set(r.action for r in rlist if r.direction == "Outbound")
            actions_in = set(r.action for r in rlist if r.direction == "Inbound")
            for actions, direction in [(actions_out, "Outbound"), (actions_in, "Inbound")]:
                if len(actions) > 1:
                    names = [r.name for r in rlist if r.direction == direction]
                    issues.append({
                        "type": "conflict", "severity": "high",
                        "desc": f"{Path(prog).name} has both Allow and Block rules ({direction})",
                        "rules": names, "suggestion": "Keep only the intended policy",
                    })
        # Find redundant rules (same target, same action, same direction)
        seen = {}
        for r in rules:
            if not r.enabled: continue
            key = f"{r.direction}|{r.action}|{r.remote_addr}|{r.remote_port}|{r.program}|{r.protocol}"
            if key in seen:
                issues.append({
                    "type": "redundant", "severity": "low",
                    "desc": f"Duplicate rules: '{seen[key]}' and '{r.name}'",
                    "rules": [seen[key], r.name],
                    "suggestion": "Remove the duplicate to keep rules clean",
                })
            else:
                seen[key] = r.name
        # Find overly broad rules
        for r in rules:
            if not r.enabled: continue
            if (r.action == "Block" and r.name.startswith(PFX) and
                not r.remote_addr and not r.remote_port and not r.program and
                r.protocol in ("", "Any", "*")):
                issues.append({
                    "type": "warning", "severity": "medium",
                    "desc": f"Rule '{r.name}' blocks ALL traffic in {r.direction} with no filters",
                    "rules": [r.name],
                    "suggestion": "Add IP, port, or program filters to avoid blocking everything",
                })
        issues.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["severity"], 3))
        return issues

conflict_detector = RuleConflictDetector()
class ConnectionGrouper:
    """Group connections by process for cleaner display."""
    def group(self, connections):
        """Group connections by process name. Returns {proc: [ci, ...]}."""
        groups = {}
        for c in connections:
            key = c.proc or "?"
            groups.setdefault(key, []).append(c)
        return groups

    def summarize(self, connections):
        """Return summary stats per process group."""
        groups = self.group(connections)
        summaries = []
        for proc, conns in groups.items():
            ips = set(c.ra for c in conns if c.ra and c.ra != "*")
            ports = set(c.rp for c in conns if c.rp and c.rp != "*")
            blocked = sum(1 for c in conns if c.stat and c.stat != "-")
            countries = set(c.country for c in conns if c.country and c.country not in ("-", ""))
            path = next((c.path for c in conns if c.path and c.path != "-"), "-")
            cat = categorizer.categorize(
                next((c.host for c in conns if c.host not in ("-","...")), ""),
                next((c.ra for c in conns if c.ra and c.ra != "*"), ""),
                next((c.rp for c in conns if c.rp and c.rp != "*"), ""),
                proc)
            summaries.append({
                "proc": proc, "count": len(conns), "unique_ips": len(ips),
                "unique_ports": len(ports), "blocked": blocked,
                "countries": len(countries), "path": path, "category": cat,
                "connections": conns,
            })
        summaries.sort(key=lambda x: -x["count"])
        return summaries

grouper = ConnectionGrouper()

# ================================================================
#  CONNECTION SESSION TRACKER
# ================================================================
class SessionTracker:
    """Track connection sessions with SQLite persistence."""
    def __init__(self):
        self._active = {}    # key -> {start, last_seen, bytes, ci}
        self._completed = [] # list of completed sessions (in-memory recent)
        self._db_path = Path(os.environ.get("APPDATA", ".")) / "PyWall" / "sessions.db"
        self._db_lock = Lock()
        self._init_db()

    def _init_db(self):
        """Create sessions table if not exists."""
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proc TEXT, ra TEXT, rp TEXT, proto TEXT, host TEXT,
                    country TEXT, category TEXT, start_time TEXT, end_time TEXT,
                    duration_sec REAL, status TEXT, date TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sess_date ON sessions(date)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sess_proc ON sessions(proc)")
                # Prune sessions older than 30 days
                conn.execute("DELETE FROM sessions WHERE date < date('now', '-30 days')")
                conn.commit()
        except Exception as e:
            log.warning(f"Session DB init failed: {e}")

    def _save_to_db(self, session):
        """Persist a completed session to SQLite."""
        try:
            with self._db_lock:
                with sqlite3.connect(str(self._db_path)) as conn:
                    conn.execute(
                        "INSERT INTO sessions (proc, ra, rp, proto, host, country, category, "
                        "start_time, end_time, duration_sec, status, date) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, date('now'))",
                        (session["proc"], session["ra"], session["rp"], session["proto"],
                         session["host"], session["country"], session["category"],
                         session["start"], session["end"], session["duration_sec"],
                         session["status"]))
        except: pass

    def update(self, ci):
        """Update or create a session for a connection."""
        key = f"{ci.proto}|{ci.la}:{ci.lp}|{ci.ra}:{ci.rp}|{ci.proc}"
        now = time.time()
        if key in self._active:
            self._active[key]["last_seen"] = now
        else:
            self._active[key] = {"start": now, "last_seen": now, "ci": ci}

    def prune(self, timeout=30):
        """Move stale sessions to completed and persist to DB."""
        now = time.time()
        to_remove = []
        for key, sess in self._active.items():
            if now - sess["last_seen"] > timeout:
                to_remove.append(key)
                duration = sess["last_seen"] - sess["start"]
                session = {
                    "proc": sess["ci"].proc, "ra": sess["ci"].ra, "rp": sess["ci"].rp,
                    "proto": sess["ci"].proto, "host": sess["ci"].host,
                    "country": sess["ci"].country, "category": categorizer.categorize(
                        sess["ci"].host, sess["ci"].ra, sess["ci"].rp, sess["ci"].proc),
                    "start": datetime.datetime.fromtimestamp(sess["start"]).strftime("%H:%M:%S"),
                    "end": datetime.datetime.fromtimestamp(sess["last_seen"]).strftime("%H:%M:%S"),
                    "duration_sec": round(duration, 1),
                    "status": sess["ci"].stat,
                }
                self._completed.append(session)
                self._save_to_db(session)
        for key in to_remove: del self._active[key]
        # Keep last 2000 in memory
        if len(self._completed) > 2000: self._completed = self._completed[-2000:]

    def get_active(self):
        return [{"proc": s["ci"].proc, "ra": s["ci"].ra, "rp": s["ci"].rp,
                 "host": s["ci"].host, "start": datetime.datetime.fromtimestamp(
                     s["start"]).strftime("%H:%M:%S"),
                 "duration_sec": round(time.time() - s["start"], 1)}
                for s in self._active.values()]

    def get_completed(self):
        return list(reversed(self._completed))

    def get_timeline(self, last_n=100):
        """Return last N sessions for timeline view."""
        return list(reversed(self._completed[-last_n:]))

    def get_history(self, date=None, proc=None, limit=500):
        """Query persisted session history from SQLite."""
        try:
            with self._db_lock:
                with sqlite3.connect(str(self._db_path)) as conn:
                    conn.row_factory = sqlite3.Row
                    sql = "SELECT * FROM sessions WHERE 1=1"
                    params = []
                    if date:
                        sql += " AND date = ?"; params.append(date)
                    if proc:
                        sql += " AND proc LIKE ?"; params.append(f"%{proc}%")
                    sql += " ORDER BY id DESC LIMIT ?"
                    params.append(limit)
                    rows = conn.execute(sql, params).fetchall()
                    return [dict(r) for r in rows]
        except:
            return []

    def get_stats(self):
        """Get aggregate session statistics."""
        try:
            with self._db_lock:
                with sqlite3.connect(str(self._db_path)) as conn:
                    total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
                    today = conn.execute("SELECT COUNT(*) FROM sessions WHERE date = date('now')").fetchone()[0]
                    avg_dur = conn.execute("SELECT AVG(duration_sec) FROM sessions WHERE duration_sec > 0").fetchone()[0] or 0
                    top_proc = conn.execute(
                        "SELECT proc, COUNT(*) as cnt FROM sessions GROUP BY proc ORDER BY cnt DESC LIMIT 1"
                    ).fetchone()
                    return {"total": total, "today": today, "avg_duration": round(avg_dur, 1),
                            "top_process": top_proc[0] if top_proc else "-"}
        except:
            return {"total": 0, "today": 0, "avg_duration": 0, "top_process": "-"}

sessions = SessionTracker()
class ToastNotification(QWidget):
    action_taken = pyqtSignal(dict, object)

    def __init__(self, ci, parent=None, ask_mode=False):
        super().__init__(parent)
        self.ci = ci
        self._ask_mode = ask_mode
        # Note: Do NOT use WindowDoesNotAcceptFocus - on Windows it can prevent
        # mouse click events from reaching child QPushButton widgets.
        # WA_ShowWithoutActivating prevents focus-steal on show, which is sufficient.
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint |
                            Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self._expanded = False
        self._base_h = 200 if ask_mode else 190
        self._exp_h = 370
        self.setFixedSize(420, self._base_h)
        self._timer = QTimer(self); self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._dismiss)
        self._hovered = False
        self._action_fired = False
        self._build()
        self._position()

    def start_dismiss_timer(self, ms):
        """Start the auto-dismiss countdown. Cancellable on hover."""
        if ms > 0:
            self._timer.start(ms)

    def enterEvent(self, event):
        """Pause auto-dismiss while mouse is over the toast."""
        self._hovered = True
        self._timer.stop()
        super().enterEvent(event)

    def leaveEvent(self, event):
        """Resume auto-dismiss when mouse leaves (only if no action taken)."""
        self._hovered = False
        if not self._action_fired and cfg.get("toast_sec", 10) > 0:
            self._timer.start(cfg["toast_sec"] * 1000)
        super().leaveEvent(event)

    def _ss(self):
        return f"""
            QWidget {{ font-family: 'Segoe UI'; }}
            QLabel {{ color: {S['t1']}; border: none; }}
            QPushButton {{ padding: 5px 10px; border-radius: 4px; font-size: 11px;
                          border: 1px solid {S['bd2']}; color: {S['t1']}; background: {S['bg2']}; }}
            QPushButton:hover {{ background: {S['bd2']}; }}
            QComboBox {{ background: {S['bg2']}; color: {S['t1']}; border: 1px solid {S['bd2']};
                        padding: 3px 8px; border-radius: 3px; }}
            QComboBox::drop-down {{ border: none; width: 20px; }}
            QComboBox::down-arrow {{ image: none; border-left: 4px solid transparent;
                                    border-right: 4px solid transparent; border-top: 5px solid {S['t2']}; }}
            QComboBox QAbstractItemView {{ background: {S['bg1']}; color: {S['t1']};
                                          selection-background-color: {S['bl']}; border: 1px solid {S['bd2']}; }}
        """

    def _build(self):
        self.setStyleSheet(self._ss())
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        # Header
        hdr = QHBoxLayout()
        icon_color = S['am'] if self._ask_mode else S['rd']
        title_text = "New Application Detected" if self._ask_mode else "Connection Blocked"
        icon_lbl = QLabel("?!" if self._ask_mode else "!!"); icon_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        icon_lbl.setStyleSheet(f"color: {icon_color}; background: transparent; border: none;")
        title = QLabel(title_text); title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {icon_color}; border: none;")
        close_btn = QPushButton("X"); close_btn.setFixedSize(24, 24)
        close_btn.setStyleSheet(f"background: transparent; border: none; color: {S['t3']}; font-size: 12px;")
        close_btn.clicked.connect(self._close_toast)
        hdr.addWidget(icon_lbl); hdr.addWidget(title); hdr.addStretch(); hdr.addWidget(close_btn)
        layout.addLayout(hdr)

        # Info
        proc_text = f"{self.ci.proc}" + (f"  (PID: {self.ci.pid})" if self.ci.pid else "")
        lbl_proc = QLabel(proc_text); lbl_proc.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        lbl_proc.setStyleSheet(f"color: {S['cy']}; border: none;"); layout.addWidget(lbl_proc)

        dest = f"{self.ci.ra}:{self.ci.rp}"
        if self.ci.host not in ("-", "...", ""): dest = f"{self.ci.host} ({self.ci.ra}:{self.ci.rp})"
        lbl_dest = QLabel(dest); lbl_dest.setStyleSheet(f"color: {S['t2']}; font-size: 10px; border: none;")
        layout.addWidget(lbl_dest)

        if self.ci.path and self.ci.path != "-":
            path_text = self.ci.path
            if len(path_text) > 60: path_text = "..." + path_text[-57:]
            lbl_path = QLabel(path_text); lbl_path.setStyleSheet(f"color: {S['t3']}; font-size: 9px; border: none;")
            layout.addWidget(lbl_path)

        # Quick action buttons
        btn_row = QHBoxLayout()
        if self._ask_mode:
            btn_allow = QPushButton("Allow"); btn_allow.setStyleSheet(f"background: {S['gn']}; color: white; font-weight: bold;")
            btn_allow.clicked.connect(lambda _=False: self._quick("allow_app"))
            btn_block = QPushButton("Block"); btn_block.setStyleSheet(f"background: {S['rd']}; color: white; font-weight: bold;")
            btn_block.clicked.connect(lambda _=False: self._quick("block_app"))
            btn_edit = QPushButton("Edit Rule..."); btn_edit.setStyleSheet(f"background: {S['bl']}; color: white;")
            btn_edit.clicked.connect(lambda _=False: self._open_edit())
            btn_row.addWidget(btn_allow); btn_row.addWidget(btn_block); btn_row.addWidget(btn_edit)
        else:
            btn_blk_ip = QPushButton("Block IP")
            btn_blk_ip.clicked.connect(lambda _=False: self._quick("block_ip"))
            btn_blk_ip.setStyleSheet(f"background: {S['rd']}; color: white;")
            btn_allow = QPushButton("Allow IP")
            btn_allow.clicked.connect(lambda _=False: self._quick("allow_ip"))
            btn_allow.setStyleSheet(f"background: {S['gn']}; color: white;")
            btn_edit = QPushButton("Edit Rule..."); btn_edit.setStyleSheet(f"background: {S['bl']}; color: white;")
            btn_edit.clicked.connect(lambda _=False: self._open_edit())
            btn_more = QPushButton("More..."); btn_more.clicked.connect(self._toggle_expand)
            btn_row.addWidget(btn_blk_ip); btn_row.addWidget(btn_allow); btn_row.addWidget(btn_edit); btn_row.addWidget(btn_more)
        layout.addLayout(btn_row)

        # Expandable section
        self._exp_widget = QWidget()
        self._exp_widget.setVisible(False)
        exp_layout = QVBoxLayout(self._exp_widget)
        exp_layout.setContentsMargins(0, 6, 0, 0)

        # Direction
        dir_row = QHBoxLayout()
        dir_row.addWidget(QLabel("Direction:"))
        self._dir_cb = QComboBox(); self._dir_cb.addItems(["Outbound", "Inbound", "Both"])
        dir_row.addWidget(self._dir_cb)
        dir_row.addWidget(QLabel("Action:"))
        self._act_cb = QComboBox(); self._act_cb.addItems(["Block", "Allow"])
        dir_row.addWidget(self._act_cb)
        exp_layout.addLayout(dir_row)

        # Rule type
        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Rule Type:"))
        self._type_cb = QComboBox()
        self._type_cb.addItems(["Block IP", "Block Port", "Block Process", "Block IP+Port", "Custom"])
        type_row.addWidget(self._type_cb)
        exp_layout.addLayout(type_row)

        # Duration
        dur_row = QHBoxLayout()
        dur_row.addWidget(QLabel("Duration:"))
        self._dur_cb = QComboBox()
        self._dur_cb.addItems(["Permanent", "5 minutes", "30 minutes", "1 hour", "Until reboot"])
        dur_row.addWidget(self._dur_cb)
        exp_layout.addLayout(dur_row)

        btn_apply = QPushButton("Apply Custom Rule")
        btn_apply.setStyleSheet(f"background: {S['bl']}; color: white; font-weight: bold; padding: 6px;")
        btn_apply.clicked.connect(self._apply_custom)
        exp_layout.addWidget(btn_apply)
        layout.addWidget(self._exp_widget)

    def _toggle_expand(self):
        self._expanded = not self._expanded
        self._exp_widget.setVisible(self._expanded)
        self.setFixedHeight(self._exp_h if self._expanded else self._base_h)
        self._position()

    def _quick(self, action):
        self._action_fired = True
        self._timer.stop()
        self.action_taken.emit({"type": action, "direction": "Outbound"}, self.ci)
        self._close_toast()

    def _apply_custom(self):
        self._action_fired = True
        self._timer.stop()
        dirs = {"Outbound":"Outbound","Inbound":"Inbound","Both":"Both"}
        self.action_taken.emit({
            "type": "custom",
            "direction": dirs.get(self._dir_cb.currentText(), "Outbound"),
            "action": self._act_cb.currentText(),
            "rule_type": self._type_cb.currentText(),
            "duration": self._dur_cb.currentText(),
        }, self.ci)
        self._close_toast()

    def _open_edit(self):
        """Open full CreateRuleDialog prefilled with this connection's details."""
        self._action_fired = True
        self._timer.stop()
        prefill = {
            "remote_addr": self.ci.ra,
            "remote_port": self.ci.rp,
            "protocol": self.ci.proto,
            "direction": "Outbound" if self.ci.dir == "Out" else "Inbound",
            "action": "Block",
            "program": self.ci.path if self.ci.path and self.ci.path != "-" else "",
            "name": f"{PFX}{self.ci.proc}_{self.ci.ra.replace(':','-').replace('/','_')}",
            "desc": f"Rule for {self.ci.proc} -> {self.ci.host or self.ci.ra}:{self.ci.rp}",
        }
        main_win = self.parent()
        self._close_toast()
        dlg = CreateRuleDialog(main_win, prefill=prefill)
        if hasattr(main_win, '_refresh_rules_panel'):
            dlg.rule_created.connect(main_win._refresh_rules_panel)
        dlg.exec()

    def _position(self):
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            x = geo.right() - self.width() - 16
            existing = [t for t in (self.parent()._toasts if self.parent() and hasattr(self.parent(), '_toasts') else []) if t.isVisible() and t is not self]
            offset = sum(t.height() + 8 for t in existing)
            y = geo.bottom() - self.height() - 16 - offset
            self.move(x, y)

    def _dismiss(self): self._close_toast()
    def _close_toast(self):
        self._timer.stop()
        self.hide()
        if self.parent() and hasattr(self.parent(), '_toasts'):
            if self in self.parent()._toasts: self.parent()._toasts.remove(self)
            self._reposition_all()
        self.deleteLater()

    def _reposition_all(self):
        if not self.parent() or not hasattr(self.parent(), '_toasts'): return
        screen = QApplication.primaryScreen()
        if not screen: return
        geo = screen.availableGeometry()
        x = geo.right() - 420 - 16; offset = 0
        for t in self.parent()._toasts:
            if t.isVisible():
                t.move(x, geo.bottom() - t.height() - 16 - offset)
                offset += t.height() + 8

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width(), self.height(), 10, 10)
        p.fillPath(path, QColor(S['bg1']))
        accent = S['am'] if self._ask_mode else S['rd']
        p.setPen(QPen(QColor(accent), 1.5)); p.drawPath(path)
        p.end()

# ================================================================
#  CREATE RULE DIALOG - Professional firewall rule creation
# ================================================================
class CreateRuleDialog(QDialog):
    """WFC-style rule editor with detected addresses, programs, and services."""
    rule_created = pyqtSignal()

    def __init__(self, parent=None, prefill=None):
        super().__init__(parent)
        self._prefill = prefill or {}
        editing = self._prefill.get("_editing", False)
        self.setWindowTitle("Edit Rule" if editing else "Create Firewall Rule")
        self.setMinimumSize(680, 700)
        self._detected_ips = set()
        self._detected_progs = set()
        self._detect_values()
        self._build()

    def _detect_values(self):
        """Gather detected IPs and programs from live connections."""
        try:
            for c in psutil.net_connections(kind='all'):
                if c.raddr:
                    self._detected_ips.add(c.raddr.ip)
                if c.laddr:
                    self._detected_ips.add(c.laddr.ip)
                if c.pid:
                    try:
                        p = psutil.Process(c.pid)
                        exe = p.exe()
                        if exe: self._detected_progs.add(exe)
                    except: pass
        except: pass
        # Also gather from cache
        for ci_key, ci_val in list(dns_c.items())[:200]:
            if ci_key and ci_key not in ("*",""): self._detected_ips.add(ci_key)

    def _make_addr_combo(self, placeholder="", initial=""):
        """Create an editable ComboBox with Any + detected addresses."""
        cb = QComboBox(); cb.setEditable(True)
        cb.addItem("Any")
        cb.addItem("LocalSubnet")
        # Add detected remote IPs sorted
        sorted_ips = sorted(self._detected_ips, key=lambda x: (not x.startswith("192.168"), not x.startswith("10."), x))
        for ip in sorted_ips[:50]:
            cb.addItem(ip)
        cb.lineEdit().setPlaceholderText(placeholder or "Any (IP, CIDR, or comma-separated)")
        if initial and initial not in ("*", "Any", ""):
            idx = cb.findText(initial)
            if idx >= 0: cb.setCurrentIndex(idx)
            else: cb.setCurrentText(initial)
        else:
            cb.setCurrentIndex(0)
        return cb

    def _make_port_combo(self, placeholder="", initial=""):
        """Create an editable ComboBox with common ports."""
        cb = QComboBox(); cb.setEditable(True)
        cb.addItems(["All Ports", "80", "443", "80,443", "53", "22", "3389", "8080", "25,587", "21", "1024-65535"])
        cb.lineEdit().setPlaceholderText(placeholder or "All Ports")
        if initial and initial not in ("*", "Any", "All Ports", ""):
            idx = cb.findText(initial)
            if idx >= 0: cb.setCurrentIndex(idx)
            else: cb.setCurrentText(initial)
        else:
            cb.setCurrentIndex(0)
        return cb

    def _make_prog_combo(self, initial=""):
        """Create an editable ComboBox with detected programs."""
        cb = QComboBox(); cb.setEditable(True)
        cb.addItem("All Programs")
        sorted_progs = sorted(self._detected_progs, key=lambda x: Path(x).name.lower())
        for prog in sorted_progs[:60]:
            cb.addItem(prog)
        cb.lineEdit().setPlaceholderText("All Programs (or select/type a path)")
        if initial and initial not in ("*", "Any", ""):
            idx = cb.findText(initial)
            if idx >= 0: cb.setCurrentIndex(idx)
            else: cb.setCurrentText(initial)
        else:
            cb.setCurrentIndex(0)
        return cb

    def _build(self):
        self.setStyleSheet(f"""
            QDialog {{ background: {S['bg0']}; }}
            QLabel {{ color: {S['t1']}; font-size: 11px; }}
            QLineEdit, QComboBox, QSpinBox {{ background: {S['bg2']}; color: {S['t1']};
                border: 1px solid {S['bd1']}; padding: 6px; border-radius: 4px; font-size: 11px; }}
            QLineEdit:focus, QComboBox:focus {{ border-color: {S['bl']}; }}
            QComboBox::drop-down {{ border: none; width: 24px; }}
            QComboBox::down-arrow {{ image: none; border-left: 5px solid transparent;
                border-right: 5px solid transparent; border-top: 6px solid {S['t2']}; }}
            QComboBox QAbstractItemView {{ background: {S['bg1']}; color: {S['t1']};
                selection-background-color: {S['bl']}; border: 1px solid {S['bd2']}; }}
            QGroupBox {{ color: {S['t2']}; border: 1px solid {S['bd1']}; border-radius: 6px;
                margin-top: 12px; padding-top: 16px; font-weight: bold; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; }}
            QPushButton {{ padding: 8px 20px; border-radius: 5px; font-size: 12px; font-weight: bold;
                border: 1px solid {S['bd2']}; color: {S['t1']}; background: {S['bg2']}; }}
            QPushButton:hover {{ background: {S['bd2']}; }}
            QCheckBox {{ color: {S['t1']}; spacing: 6px; }}
            QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 3px;
                border: 1px solid {S['bd2']}; background: {S['bg2']}; }}
            QCheckBox::indicator:checked {{ background: {S['bl']}; border-color: {S['bl']}; }}
        """)
        layout = QVBoxLayout(self); layout.setSpacing(6)

        # Title
        editing = self._prefill.get("_editing", False)
        title_text = "Edit Firewall Rule" if editing else "Create Firewall Rule"
        title = QLabel(title_text)
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {S['bl']};")
        layout.addWidget(title)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ border: none; background: {S['bg0']}; }}")
        container = QWidget(); form = QVBoxLayout(container); form.setSpacing(4)

        # ---- Program ----
        grp_prog = QGroupBox("Program")
        g_prog = QVBoxLayout(grp_prog)
        prog_row = QHBoxLayout()
        self._program = self._make_prog_combo(self._prefill.get("program", ""))
        self._program.setToolTip("Select a detected program or type/browse for an executable.\n'All Programs' applies the rule to all applications.")
        prog_row.addWidget(self._program, 1)
        btn_browse = QPushButton("Browse...")
        btn_browse.setStyleSheet("padding: 6px 12px; font-size: 11px; font-weight: normal;")
        btn_browse.clicked.connect(self._browse_program)
        prog_row.addWidget(btn_browse)
        g_prog.addLayout(prog_row)
        form.addWidget(grp_prog)

        # ---- Basic ----
        grp_basic = QGroupBox("Rule Settings")
        g1 = QVBoxLayout(grp_basic)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Name:"))
        self._name = QLineEdit()
        self._name.setPlaceholderText(f"{PFX}MyRule_Block_Out")
        self._name.setText(self._prefill.get("name", ""))
        r1.addWidget(self._name)
        g1.addLayout(r1)

        r_desc = QHBoxLayout()
        r_desc.addWidget(QLabel("Description:"))
        self._desc = QLineEdit()
        self._desc.setPlaceholderText("Optional description")
        self._desc.setText(self._prefill.get("desc", ""))
        r_desc.addWidget(self._desc)
        g1.addLayout(r_desc)

        r3 = QHBoxLayout()
        r3.addWidget(QLabel("Direction:"))
        self._direction = QComboBox(); self._direction.addItems(["Outbound", "Inbound"])
        if self._prefill.get("direction"): self._direction.setCurrentText(self._prefill["direction"])
        r3.addWidget(self._direction)
        r3.addWidget(QLabel("Action:"))
        self._action = QComboBox(); self._action.addItems(["Block", "Allow"])
        if self._prefill.get("action"): self._action.setCurrentText(self._prefill["action"])
        r3.addWidget(self._action)
        g1.addLayout(r3)

        r4 = QHBoxLayout()
        r4.addWidget(QLabel("Protocol:"))
        self._protocol = QComboBox(); self._protocol.addItems(["Any", "TCP", "UDP", "ICMPv4", "ICMPv6"])
        if self._prefill.get("protocol"): self._protocol.setCurrentText(self._prefill["protocol"])
        r4.addWidget(self._protocol)
        r4.addWidget(QLabel("Profile:"))
        self._profile = QComboBox(); self._profile.addItems(["Any", "Domain", "Private", "Public", "Domain,Private", "Private,Public", "Domain,Private,Public"])
        if self._prefill.get("profile"): self._profile.setCurrentText(self._prefill["profile"])
        r4.addWidget(self._profile)
        g1.addLayout(r4)

        self._enabled = QCheckBox("Enabled")
        self._enabled.setChecked(self._prefill.get("_enabled", True) if "_enabled" in self._prefill else True)
        g1.addWidget(self._enabled)
        form.addWidget(grp_basic)

        # ---- Addresses ----
        grp_net = QGroupBox("Local and Remote IP Addresses")
        g2 = QVBoxLayout(grp_net)
        r5 = QHBoxLayout()
        r5.addWidget(QLabel("Remote Addresses:"))
        self._remote_addr = self._make_addr_combo("Any", self._prefill.get("remote_addr", ""))
        self._remote_addr.setToolTip("Select a detected IP, type a custom address, or choose 'Any'.\nSupports IPs, CIDR ranges, and comma-separated lists.")
        r5.addWidget(self._remote_addr, 1)
        g2.addLayout(r5)
        r6 = QHBoxLayout()
        r6.addWidget(QLabel("Local Addresses:"))
        self._local_addr = self._make_addr_combo("Any", self._prefill.get("local_addr", ""))
        r6.addWidget(self._local_addr, 1)
        g2.addLayout(r6)
        form.addWidget(grp_net)

        # ---- Ports ----
        grp_ports = QGroupBox("Protocols and Ports")
        g3 = QVBoxLayout(grp_ports)
        r7 = QHBoxLayout()
        r7.addWidget(QLabel("Remote Ports:"))
        self._remote_port = self._make_port_combo("All Ports", self._prefill.get("remote_port", ""))
        r7.addWidget(self._remote_port, 1)
        g3.addLayout(r7)
        r8 = QHBoxLayout()
        r8.addWidget(QLabel("Local Ports:"))
        self._local_port = self._make_port_combo("All Ports", self._prefill.get("local_port", ""))
        r8.addWidget(self._local_port, 1)
        g3.addLayout(r8)
        form.addWidget(grp_ports)

        scroll.setWidget(container)
        layout.addWidget(scroll)

        # Buttons
        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Cancel"); btn_cancel.clicked.connect(self.reject)
        btn_label = "Apply" if editing else "Create Rule"
        btn_create = QPushButton(btn_label)
        btn_create.setStyleSheet(f"background: {S['bl']}; color: white;")
        btn_create.clicked.connect(self._create)
        btn_row.addStretch(); btn_row.addWidget(btn_cancel); btn_row.addWidget(btn_create)
        layout.addLayout(btn_row)

    def _browse_program(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Program", "C:\\", "Executables (*.exe);;All Files (*)")
        if path: self._program.setCurrentText(path)

    def _get_combo_value(self, combo, empty_values=("Any", "All Ports", "All Programs", "*", "")):
        """Get combo value, returning empty string for 'Any'-type defaults."""
        val = combo.currentText().strip()
        if val in empty_values: return ""
        return val

    def _create(self):
        name = self._name.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Rule name is required.")
            return
        if not name.startswith(PFX): name = PFX + name

        # If editing (name already exists), delete old rule first
        if self._prefill.get("_editing"):
            old_name = self._prefill.get("_original_name", name)
            fw.delete_rule(old_name)

        ok, out = fw.create_rule(
            name=name,
            direction=self._direction.currentText(),
            action=self._action.currentText(),
            remote_addr=self._get_combo_value(self._remote_addr),
            remote_port=self._get_combo_value(self._remote_port),
            local_addr=self._get_combo_value(self._local_addr),
            local_port=self._get_combo_value(self._local_port),
            protocol=self._protocol.currentText() if self._protocol.currentText() != "Any" else "",
            program=self._get_combo_value(self._program),
            profile=self._profile.currentText(),
            desc=self._desc.text().strip(),
            enabled=self._enabled.isChecked(),
        )
        if ok:
            self.rule_created.emit()
            self.accept()  # Close immediately, no confirmation popup
        else:
            QMessageBox.critical(self, "Error", f"Failed to create rule:\n{out}")

# ================================================================
#  RULES MANAGER - Full CRUD firewall rule management
# ================================================================
class RulesManager(QDialog):
    """WFC-style firewall rule manager with sidebar panel for actions, filters, and quick-create."""
    rules_changed = pyqtSignal()

    def __init__(self, parent=None, embedded=False):
        super().__init__(parent)
        self._embedded = embedded
        self._rules = []
        self._all_rules = []
        if not embedded:
            self.setWindowTitle("PyWall - Rules Panel")
            self.setMinimumSize(1200, 750)
        self._build()

    def _make_sidebar_btn(self, text, icon_char="", callback=None, color=None, bold=False):
        """Create a styled sidebar button matching WFC aesthetic."""
        btn = QPushButton(f"  {icon_char}  {text}" if icon_char else f"  {text}")
        btn.setFixedHeight(30)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        style = f"text-align: left; padding-left: 8px; border: none; border-radius: 3px; font-size: 11px;"
        if bold: style += " font-weight: bold;"
        if color: style += f" color: {color};"
        else: style += f" color: {S['t1']};"
        style += f" background: transparent;"
        btn.setStyleSheet(f"QPushButton {{ {style} }} QPushButton:hover {{ background: {S['bg2']}; }}")
        if callback: btn.clicked.connect(callback)
        return btn

    def _make_section_label(self, text):
        """Create a section header label for the sidebar."""
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        lbl.setStyleSheet(f"color: {S['bl']}; padding: 8px 4px 4px 4px; border-bottom: 1px solid {S['bd1']};")
        return lbl

    def _build(self):
        ss = f"""
            QLabel {{ color: {S['t1']}; }}
            QLineEdit {{ background: {S['bg2']}; color: {S['t1']}; border: 1px solid {S['bd1']};
                padding: 5px 8px; border-radius: 4px; }}
            QComboBox {{ background: {S['bg2']}; color: {S['t1']}; border: 1px solid {S['bd1']};
                padding: 4px 8px; border-radius: 3px; }}
            QComboBox::drop-down {{ border: none; width: 20px; }}
            QComboBox::down-arrow {{ image: none; border-left: 4px solid transparent;
                border-right: 4px solid transparent; border-top: 5px solid {S['t2']}; }}
            QComboBox QAbstractItemView {{ background: {S['bg1']}; color: {S['t1']};
                selection-background-color: {S['bl']}; border: 1px solid {S['bd2']}; }}
            QTableWidget {{ background: {S['ra']}; gridline-color: {S['bd1']}; color: {S['t1']};
                border: 1px solid {S['bd1']}; selection-background-color: {S['rs']}; font-size: 11px; }}
            QTableWidget::item {{ padding: 3px 6px; border-bottom: 1px solid {S['bg2']}; }}
            QHeaderView::section {{ background: {S['bg2']}; color: {S['t2']}; border: none;
                padding: 5px 8px; font-weight: bold; font-size: 10px; border-right: 1px solid {S['bd1']}; }}
            QCheckBox {{ color: {S['t1']}; }}
            QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {S['bd2']}; border-radius: 2px; background: {S['bg2']}; }}
            QCheckBox::indicator:checked {{ background: {S['bl']}; }}
        """
        if not self._embedded:
            self.setStyleSheet(f"QDialog {{ background: {S['bg0']}; }} " + ss)

        layout = QVBoxLayout(self) if not self._embedded else QVBoxLayout()
        if self._embedded: self.setLayout(layout)
        layout.setContentsMargins(4, 4, 4, 4); layout.setSpacing(4)

        # Header with stats
        self._stats_lbl = QLabel("Loading rules...")
        self._stats_lbl.setStyleSheet(f"color: {S['t3']}; font-size: 10px; padding: 2px 4px;")
        layout.addWidget(self._stats_lbl)

        # Main content: table (left) + sidebar (right)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---- LEFT: Rules Table ----
        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels(["Name", "Group", "Program", "Direction", "Action", "Remote Addr", "Profile", "Enabled"])
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setColumnWidth(0, 220)   # name
        self._table.setColumnWidth(1, 100)   # group
        self._table.setColumnWidth(2, 260)   # program (full path like WFC)
        self._table.setColumnWidth(3, 70)    # dir
        self._table.setColumnWidth(4, 55)    # action
        self._table.setColumnWidth(5, 130)   # remote addr
        self._table.setColumnWidth(6, 65)    # profile
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._ctx_menu)
        self._table.doubleClicked.connect(lambda idx: self._edit_rule())
        self._table.currentCellChanged.connect(self._on_row_select)
        splitter.addWidget(self._table)

        # ---- RIGHT: Sidebar Panel (WFC-style) ----
        sidebar = QWidget()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet(f"background: {S['bg1']}; border-left: 1px solid {S['bd1']};")
        sb = QVBoxLayout(sidebar); sb.setContentsMargins(6, 6, 6, 6); sb.setSpacing(2)

        # Display section
        sb.addWidget(self._make_section_label("Display"))
        self._filt_source = QComboBox()
        self._filt_source.addItems(["All rules", "PyWall rules", "System rules", "Block rules", "Allow rules"])
        self._filt_source.setFixedHeight(26)
        self._filt_source.currentTextChanged.connect(self._apply_filter)
        sb.addWidget(self._filt_source)

        # Filter section
        sb.addWidget(self._make_section_label("Filter"))
        self._filt_dir = QComboBox()
        self._filt_dir.addItems(["No filter", "Inbound", "Outbound", "Enabled", "Disabled"])
        self._filt_dir.setFixedHeight(26)
        self._filt_dir.currentTextChanged.connect(self._apply_filter)
        sb.addWidget(self._filt_dir)

        # Search section
        sb.addWidget(self._make_section_label("Search"))
        self._search = QLineEdit(); self._search.setPlaceholderText("Type to filter...")
        self._search.setFixedHeight(26)
        self._search.textChanged.connect(self._apply_filter)
        sb.addWidget(self._search)

        # Actions section
        sb.addWidget(self._make_section_label("Actions"))
        sb.addWidget(self._make_sidebar_btn("Refresh list", "", self._scan))
        sb.addWidget(self._make_sidebar_btn("Show invalid rules", "", self._show_invalid))
        sb.addWidget(self._make_sidebar_btn("Show duplicate rules", "", self._show_duplicates))

        # Options section (context-sensitive - acts on selected rule)
        sb.addWidget(self._make_section_label("Options"))
        sb.addWidget(self._make_sidebar_btn("Allow", "", lambda: self._set_selected_action("Allow"), S.get('gn', '#22c55e')))
        sb.addWidget(self._make_sidebar_btn("Block", "", lambda: self._set_selected_action("Block"), S.get('rd', '#ef4444')))
        sb.addWidget(self._make_sidebar_btn("Enable", "", lambda: self._bulk_toggle(True)))
        sb.addWidget(self._make_sidebar_btn("Disable", "", lambda: self._bulk_toggle(False)))
        sb.addWidget(self._make_sidebar_btn("Properties", "", self._edit_rule))
        sb.addWidget(self._make_sidebar_btn("Create duplicate", "", self._dup_selected))
        sb.addWidget(self._make_sidebar_btn("Delete", "", self._delete_selected, S.get('rd', '#ef4444')))
        sb.addWidget(self._make_sidebar_btn("Open file location", "", self._open_file_loc))

        # Create new rule section
        sb.addWidget(self._make_section_label("Create new rule"))
        sb.addWidget(self._make_sidebar_btn("Blank rule", "", self._new_rule))
        sb.addWidget(self._make_sidebar_btn("Browse to allow", "", lambda: self._browse_create("Allow")))
        sb.addWidget(self._make_sidebar_btn("Browse to block", "", lambda: self._browse_create("Block")))

        sb.addStretch()
        splitter.addWidget(sidebar)
        splitter.setSizes([1000, 200])
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
        layout.addWidget(splitter)

        self.setStyleSheet(self.styleSheet() + ss)
        self._scan()

    def _on_row_select(self, row, col, prev_row, prev_col):
        """Update sidebar info when a row is selected."""
        pass  # Sidebar actions use current selection directly

    def _scan(self):
        self._stats_lbl.setText("Scanning firewall rules...")
        self._worker = RuleScanWorker()
        self._worker.ready.connect(self._on_scan)
        self._worker.start()

    def _on_scan(self, rules):
        self._all_rules = rules
        self._apply_filter()
        total = len(rules)
        pw = sum(1 for r in rules if r.source == "pywall")
        blk = sum(1 for r in rules if r.action == "Block")
        en = sum(1 for r in rules if r.enabled)
        self._stats_lbl.setText(f"Display - {len(self._rules)} rules  |  Total: {total}  |  PyWall: {pw}  |  Block: {blk}  |  Allow: {total-blk}  |  Enabled: {en}")

    def _apply_filter(self, *_):
        txt = self._search.text().lower()
        src = self._filt_source.currentText()
        dir_f = self._filt_dir.currentText()
        rules = list(self._all_rules)

        if txt:
            rules = [r for r in rules if txt in r.name.lower() or txt in r.program.lower()
                     or txt in r.desc.lower() or txt in r.remote_addr.lower()
                     or txt in r.remote_port.lower() or txt in r.local_addr.lower()
                     or txt in r.local_port.lower() or txt in r.protocol.lower()
                     or txt in r.group.lower()]
        if src == "PyWall rules": rules = [r for r in rules if r.source == "pywall"]
        elif src == "System rules": rules = [r for r in rules if r.source == "system"]
        elif src == "Block rules": rules = [r for r in rules if r.action == "Block"]
        elif src == "Allow rules": rules = [r for r in rules if r.action == "Allow"]
        if dir_f == "Inbound": rules = [r for r in rules if r.direction == "Inbound"]
        elif dir_f == "Outbound": rules = [r for r in rules if r.direction == "Outbound"]
        elif dir_f == "Enabled": rules = [r for r in rules if r.enabled]
        elif dir_f == "Disabled": rules = [r for r in rules if not r.enabled]

        self._rules = rules
        self._populate(rules)
        self._stats_lbl.setText(f"Display - {len(rules)} rules  |  Total: {len(self._all_rules)}")

    def _populate(self, rules):
        self._table.setUpdatesEnabled(False)
        self._table.blockSignals(True)
        self._table.setRowCount(len(rules))
        for i, r in enumerate(rules):
            items = [
                r.name, r.group, r.program,
                r.direction, r.action, r.remote_addr[:50],
                r.profile, "Yes" if r.enabled else "No"
            ]
            for j, val in enumerate(items):
                item = QTableWidgetItem(val)
                # Color coding
                if j == 3:  # direction
                    item.setForeground(QColor(S['cy']) if val == "Inbound" else QColor(S['t2']))
                elif j == 4:  # action
                    item.setForeground(QColor(S['rd']) if val == "Block" else QColor(S['gn']))
                elif j == 7:  # enabled
                    item.setForeground(QColor(S['gn']) if val == "Yes" else QColor(S['t3']))
                # Highlight PyWall rules
                if r.source == "pywall" and j == 0:
                    item.setForeground(QColor(S['bl']))
                # Highlight disabled rows
                if not r.enabled and j not in (4, 7):
                    item.setForeground(QColor(S['t3']))
                self._table.setItem(i, j, item)
            self._table.setRowHeight(i, 26)
        self._table.blockSignals(False)
        self._table.setUpdatesEnabled(True)

    def _get_selected_rules(self):
        """Get rules from selected rows."""
        rows = set(idx.row() for idx in self._table.selectedIndexes())
        return [self._rules[r] for r in sorted(rows) if r < len(self._rules)]

    def _get_selected_names(self):
        return [r.name for r in self._get_selected_rules()]

    def _new_rule(self):
        dlg = CreateRuleDialog(self)
        dlg.rule_created.connect(self._scan)
        dlg.rule_created.connect(lambda: self.rules_changed.emit())
        dlg.exec()

    def _browse_create(self, action):
        """Browse for an exe and create an allow/block rule for it."""
        path, _ = QFileDialog.getOpenFileName(self, f"Select Program to {action}", "C:\\", "Executables (*.exe);;All Files (*)")
        if not path: return
        stem = Path(path).stem[:30]
        name = f"{PFX}{action}_{stem}_Out"
        direction = "Outbound"
        ok, _ = fw.create_rule(name, direction, action, program=path,
                               desc=f"{action} rule for {Path(path).name}")
        if ok:
            self.rules_changed.emit()
            self._scan()

    def _edit_rule(self, index=None):
        rules = self._get_selected_rules()
        if not rules: return
        rule = rules[0]
        dlg = CreateRuleDialog(self, prefill={
            "name": rule.name, "desc": rule.desc, "direction": rule.direction,
            "action": rule.action, "protocol": rule.protocol,
            "remote_addr": rule.remote_addr, "remote_port": rule.remote_port,
            "local_addr": rule.local_addr, "local_port": rule.local_port,
            "program": rule.program, "profile": rule.profile,
            "_editing": True, "_original_name": rule.name,
            "_enabled": rule.enabled,
        })
        dlg.setWindowTitle(f"Properties - {rule.name}")
        dlg.rule_created.connect(self._scan)
        dlg.rule_created.connect(lambda: self.rules_changed.emit())
        dlg.exec()

    def _set_selected_action(self, action):
        """Change selected rules to Allow or Block immediately."""
        rules = self._get_selected_rules()
        if not rules: return
        for rule in rules:
            fw.delete_rule(rule.name)
            fw.create_rule(rule.name, rule.direction, action,
                          remote_addr=rule.remote_addr, remote_port=rule.remote_port,
                          local_addr=rule.local_addr, local_port=rule.local_port,
                          protocol=rule.protocol, program=rule.program,
                          profile=rule.profile, desc=rule.desc, enabled=rule.enabled)
        self.rules_changed.emit()
        self._scan()

    def _delete_selected(self):
        names = self._get_selected_names()
        if not names: return
        reply = QMessageBox.question(self, "Delete Rules",
                                     f"Delete {len(names)} selected rule(s)?\n\nThis cannot be undone.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for n in names: fw.delete_rule(n)
            self.rules_changed.emit()
            self._scan()

    def _bulk_toggle(self, enabled):
        names = self._get_selected_names()
        if not names: return
        for n in names: fw.enable_rule(n, enabled)
        self.rules_changed.emit()
        self._scan()

    def _dup_selected(self):
        rules = self._get_selected_rules()
        if not rules: return
        rule = rules[0]
        dlg = CreateRuleDialog(self, prefill={
            "name": rule.name + "_copy", "desc": rule.desc, "direction": rule.direction,
            "action": rule.action, "protocol": rule.protocol,
            "remote_addr": rule.remote_addr, "remote_port": rule.remote_port,
            "program": rule.program, "profile": rule.profile,
        })
        dlg.rule_created.connect(self._scan)
        dlg.rule_created.connect(lambda: self.rules_changed.emit())
        dlg.exec()

    def _open_file_loc(self):
        rules = self._get_selected_rules()
        if not rules or not rules[0].program: return
        prog = Path(rules[0].program)
        if prog.exists():
            subprocess.Popen(["explorer", "/select,", str(prog)])
        else:
            QMessageBox.information(self, "File Not Found", f"Program not found:\n{prog}")

    def _show_invalid(self):
        """Find rules pointing to non-existent programs."""
        invalid = [r for r in self._all_rules if r.program and not Path(r.program).exists()]
        if not invalid:
            QMessageBox.information(self, "Invalid Rules", "No invalid rules found. All program paths exist.")
            return
        self._rules = invalid
        self._populate(invalid)
        self._stats_lbl.setText(f"Showing {len(invalid)} invalid rules (program file missing)")

    def _show_duplicates(self):
        """Find rules with duplicate names or identical configurations."""
        seen = {}
        dupes = []
        for r in self._all_rules:
            key = f"{r.direction}|{r.action}|{r.program}|{r.remote_addr}|{r.remote_port}|{r.local_port}"
            if key in seen:
                if seen[key] not in dupes: dupes.append(seen[key])
                dupes.append(r)
            else:
                seen[key] = r
        if not dupes:
            QMessageBox.information(self, "Duplicate Rules", "No duplicate rules found.")
            return
        self._rules = dupes
        self._populate(dupes)
        self._stats_lbl.setText(f"Showing {len(dupes)} duplicate rules")

    def _ctx_menu(self, pos):
        row = self._table.rowAt(pos.y())
        if row < 0 or row >= len(self._rules): return
        rule = self._rules[row]
        menu = QMenu(self)
        menu.setStyleSheet(f"QMenu {{ background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bd2']}; }} QMenu::item:selected {{ background: {S['bl']}; }}")
        menu.addAction("Properties", self._edit_rule)
        menu.addSeparator()
        menu.addAction("Allow", lambda: self._set_selected_action("Allow"))
        menu.addAction("Block", lambda: self._set_selected_action("Block"))
        menu.addSeparator()
        if rule.enabled:
            menu.addAction("Disable", lambda: self._bulk_toggle(False))
        else:
            menu.addAction("Enable", lambda: self._bulk_toggle(True))
        menu.addSeparator()
        menu.addAction("Create duplicate", self._dup_selected)
        menu.addAction("Delete", self._delete_selected)
        menu.addSeparator()
        if rule.program:
            menu.addAction("Open file location", self._open_file_loc)
        menu.addAction("Copy name", lambda: QApplication.clipboard().setText(rule.name))
        if rule.remote_addr and rule.remote_addr not in ("*", "Any", ""):
            menu.addAction(f"Copy address: {rule.remote_addr[:30]}", lambda: QApplication.clipboard().setText(rule.remote_addr))
        menu.exec(self._table.viewport().mapToGlobal(pos))

    def get_widget(self):
        """Return the layout's parent widget for embedding in tabs."""
        return self

# ================================================================
#  SETTINGS DIALOG
# ================================================================
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP} Settings")
        self.setFixedSize(560, 700)
        self._build()

    def _build(self):
        self.setStyleSheet(f"""
            QDialog {{ background: {S['bg0']}; }}
            QLabel {{ color: {S['t1']}; font-size: 11px; }}
            QGroupBox {{ color: {S['t2']}; border: 1px solid {S['bd1']}; border-radius: 6px; margin-top: 12px; padding-top: 16px; font-weight: bold; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; }}
            QCheckBox {{ color: {S['t1']}; spacing: 6px; }}
            QCheckBox::indicator {{ width: 15px; height: 15px; border-radius: 3px; border: 1px solid {S['bd2']}; background: {S['bg2']}; }}
            QCheckBox::indicator:checked {{ background: {S['bl']}; border-color: {S['bl']}; }}
            QSpinBox, QDoubleSpinBox {{ background: {S['bg2']}; color: {S['t1']}; border: 1px solid {S['bd1']}; padding: 4px; border-radius: 4px; }}
            QComboBox {{ background: {S['bg2']}; color: {S['t1']}; border: 1px solid {S['bd1']}; padding: 4px 8px; border-radius: 4px; }}
            QComboBox::drop-down {{ border: none; width: 20px; }}
            QComboBox::down-arrow {{ image: none; border-left: 4px solid transparent; border-right: 4px solid transparent; border-top: 5px solid {S['t2']}; }}
            QComboBox QAbstractItemView {{ background: {S['bg1']}; color: {S['t1']}; selection-background-color: {S['bl']}; border: 1px solid {S['bd2']}; }}
            QPushButton {{ padding: 8px 20px; border-radius: 5px; font-size: 12px; border: 1px solid {S['bd2']}; color: {S['t1']}; background: {S['bg2']}; }}
            QPushButton:hover {{ background: {S['bd2']}; }}
        """)
        layout = QVBoxLayout(self)
        title = QLabel(f"{APP} Settings"); title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold)); title.setStyleSheet(f"color: {S['bl']};")
        layout.addWidget(title)

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setStyleSheet(f"QScrollArea {{ border: none; background: {S['bg0']}; }}")
        container = QWidget(); form = QVBoxLayout(container)

        # Firewall Control
        grp_fw = QGroupBox("Firewall Control")
        g0 = QVBoxLayout(grp_fw)
        r0 = QHBoxLayout()
        r0.addWidget(QLabel("Default Mode:"))
        self._fw_mode = QComboBox(); self._fw_mode.addItems(["Monitor Only", "Whitelist (Block All + Allow Rules)", "Blacklist (Allow All + Block Rules)"])
        self._fw_mode.setToolTip("Monitor Only: Watch traffic without changing firewall behavior.\nWhitelist: Block everything, only allow what you explicitly permit.\nBlacklist: Allow everything, only block what you explicitly deny.")
        modes = {"monitor": 0, "whitelist": 1, "blacklist": 2}
        self._fw_mode.setCurrentIndex(modes.get(cfg["fw_mode"], 0))
        r0.addWidget(self._fw_mode)
        g0.addLayout(r0)
        self._ask_new = QCheckBox("Ask-to-allow for first-seen applications"); self._ask_new.setChecked(cfg["ask_new_apps"])
        self._ask_new.setToolTip("When a new application makes its first network connection,\nshow a notification asking whether to allow or block it.")
        g0.addWidget(self._ask_new)
        self._auto_block_in = QCheckBox("Auto-block unsolicited inbound connections"); self._auto_block_in.setChecked(cfg["auto_block_inbound"])
        self._auto_block_in.setToolTip("Automatically create block rules for inbound connections\nthat weren't initiated by your system. Recommended for security.")
        g0.addWidget(self._auto_block_in)
        self._kill_blocked = QCheckBox("Kill process when blocking (terminate connection)"); self._kill_blocked.setChecked(cfg["kill_blocked"])
        self._kill_blocked.setToolTip("When a connection is blocked, also terminate the process.\nAGGRESSIVE: May close applications unexpectedly. Use with caution.")
        g0.addWidget(self._kill_blocked)
        self._start_mon = QCheckBox("Auto-start monitoring on launch"); self._start_mon.setChecked(cfg["start_monitoring"])
        self._start_mon.setToolTip("Begin monitoring network connections automatically when PyWall starts.\nIf disabled, you must click 'Start Monitor' manually.")
        g0.addWidget(self._start_mon)
        form.addWidget(grp_fw)

        # Security
        grp_sec = QGroupBox("Security Detection")
        gs = QVBoxLayout(grp_sec)
        self._detect_ps = QCheckBox("Detect port scans"); self._detect_ps.setChecked(cfg["detect_portscan"])
        self._detect_ps.setToolTip("Alert when a single IP address connects to many different ports\non your system in a short time. This is a common attack reconnaissance technique.")
        gs.addWidget(self._detect_ps)
        self._detect_bf = QCheckBox("Detect brute force attempts"); self._detect_bf.setChecked(cfg["detect_bruteforce"])
        self._detect_bf.setToolTip("Alert when the same IP generates many blocked connection attempts.\nOften indicates password guessing or automated attack tools.")
        gs.addWidget(self._detect_bf)
        self._threat_ab = QCheckBox("Auto-block detected threats"); self._threat_ab.setChecked(cfg["threat_auto_block"])
        self._threat_ab.setToolTip("Automatically create a firewall block rule when a threat is detected.\nThe source IP will be permanently blocked until you remove the rule.")
        gs.addWidget(self._threat_ab)
        rs = QHBoxLayout(); rs.addWidget(QLabel("Port scan threshold (ports/60s):"))
        self._ps_thresh = QSpinBox(); self._ps_thresh.setRange(5, 100); self._ps_thresh.setValue(cfg["portscan_threshold"])
        self._ps_thresh.setToolTip("How many unique ports an IP must hit within 60 seconds\nto trigger a port scan alert. Lower = more sensitive.\nDefault: 15. Recommended range: 10-25.")
        rs.addWidget(self._ps_thresh)
        gs.addLayout(rs)
        # VirusTotal integration
        vt_row = QHBoxLayout(); vt_row.addWidget(QLabel("VirusTotal API Key:"))
        self._vt_key = QLineEdit(); self._vt_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._vt_key.setText(cfg.get("vt_api_key", ""))
        self._vt_key.setPlaceholderText("Paste your free VT API key for binary reputation checks")
        self._vt_key.setToolTip("Get a free API key at virustotal.com.\nEnables automatic malware scanning of processes\nby checking their file hash against 70+ antivirus engines.\nLeave blank to disable.")
        vt_row.addWidget(self._vt_key)
        gs.addLayout(vt_row)
        form.addWidget(grp_sec)

        # Intelligence
        grp_intel = QGroupBox("Intelligence")
        gi = QVBoxLayout(grp_intel)
        self._geoip = QCheckBox("GeoIP country lookups"); self._geoip.setChecked(cfg["geoip"])
        self._geoip.setToolTip("Look up the country of origin for each remote IP address.\nShown in the Connections table and Dashboard country list.")
        gi.addWidget(self._geoip)
        self._first_seen = QCheckBox("First-seen process alerts"); self._first_seen.setChecked(cfg["first_seen_alert"])
        self._first_seen.setToolTip("Show an alert the first time a new application\nmakes a network connection. Helps you notice new or unexpected software.")
        gi.addWidget(self._first_seen)
        self._bw = QCheckBox("Bandwidth tracking"); self._bw.setChecked(cfg["bw_tracking"])
        self._bw.setToolTip("Track upload/download bandwidth per process and overall.\nPowers the Dashboard bandwidth graph and Top Processes table.")
        gi.addWidget(self._bw)
        form.addWidget(grp_intel)

        # Blocklists
        grp_bl = QGroupBox("Blocklists")
        gb = QVBoxLayout(grp_bl)
        self._bl_telem = QCheckBox("Microsoft telemetry (35+ domains + IP ranges)"); self._bl_telem.setChecked(cfg["blocklist_telemetry"])
        self._bl_telem.setToolTip("Block known Microsoft telemetry/data collection endpoints.\nIncludes domains like vortex.data.microsoft.com and associated IP ranges.\nMay affect Windows Update or Microsoft Store in some cases.")
        gb.addWidget(self._bl_telem)
        self._bl_ads = QCheckBox("Ad/tracker domains"); self._bl_ads.setChecked(cfg["blocklist_ads"])
        self._bl_ads.setToolTip("Block common advertising and tracking domains.\nReduces tracking but may break some website features.")
        gb.addWidget(self._bl_ads)
        self._bl_custom = QCheckBox("Custom blocklist (custom_blocklist.txt)"); self._bl_custom.setChecked(cfg["blocklist_custom"])
        self._bl_custom.setToolTip("Load a custom blocklist from 'custom_blocklist.txt' in the PyWall directory.\nOne IP or domain per line. Lines starting with # are comments.")
        gb.addWidget(self._bl_custom)
        form.addWidget(grp_bl)

        # Monitor
        grp_mon = QGroupBox("Monitor")
        gm = QVBoxLayout(grp_mon)
        rp = QHBoxLayout(); rp.addWidget(QLabel("Poll interval (seconds):"))
        self._poll = QDoubleSpinBox(); self._poll.setRange(0.5, 30); self._poll.setSingleStep(0.5); self._poll.setValue(cfg["poll"])
        self._poll.setToolTip("How often PyWall checks for new network connections.\nLower = faster updates but more CPU usage.\nDefault: 2.0 seconds. Recommended: 1.0-5.0.")
        rp.addWidget(self._poll)
        gm.addLayout(rp)
        rm = QHBoxLayout(); rm.addWidget(QLabel("Max table rows:"))
        self._maxrows = QSpinBox(); self._maxrows.setRange(500, 50000); self._maxrows.setSingleStep(500); self._maxrows.setValue(cfg["maxrows"])
        self._maxrows.setToolTip("Maximum number of rows shown in the Connections table.\nOlder entries are removed when this limit is reached.\nHigher values use more memory.")
        rm.addWidget(self._maxrows)
        gm.addLayout(rm)
        self._dns_chk = QCheckBox("DNS reverse lookups"); self._dns_chk.setChecked(cfg["dns"])
        self._dns_chk.setToolTip("Resolve IP addresses to hostnames (e.g., 142.250.80.14 -> google.com).\nMakes it easier to identify what connections are for.")
        gm.addWidget(self._dns_chk)
        self._owners_chk = QCheckBox("WHOIS org lookups"); self._owners_chk.setChecked(cfg["owners"])
        self._owners_chk.setToolTip("Look up the organization that owns each IP address.\nShows company names like 'Google LLC' or 'Cloudflare, Inc.'")
        gm.addWidget(self._owners_chk)
        form.addWidget(grp_mon)

        # History
        grp_hist = QGroupBox("History Database")
        gh = QVBoxLayout(grp_hist)
        self._hist_db = QCheckBox("Record connections to SQLite"); self._hist_db.setChecked(cfg["history_db"])
        self._hist_db.setToolTip("Save all observed connections to a local SQLite database.\nAllows you to search and analyze past network activity\nin the History tab. Database is stored in the PyWall directory.")
        gh.addWidget(self._hist_db)
        rh = QHBoxLayout(); rh.addWidget(QLabel("Retention days:"))
        self._hist_days = QSpinBox(); self._hist_days.setRange(1, 365); self._hist_days.setValue(cfg["history_days"])
        self._hist_days.setToolTip("How many days of history to keep.\nRecords older than this are automatically deleted.\nDefault: 30 days.")
        rh.addWidget(self._hist_days)
        gh.addLayout(rh)
        form.addWidget(grp_hist)

        # Notifications
        grp_ntf = QGroupBox("Notifications")
        gn = QVBoxLayout(grp_ntf)
        self._toast_chk = QCheckBox("Show toast notifications"); self._toast_chk.setChecked(cfg["toast"])
        self._toast_chk.setToolTip("Display popup notifications in the corner of your screen\nfor important events like blocked connections and new applications.")
        gn.addWidget(self._toast_chk)
        self._nb = QCheckBox("Notify on blocked connections"); self._nb.setChecked(cfg["notify_blocked"])
        self._nb.setToolTip("Show a notification every time a connection is blocked.\nCan be noisy on systems with many blocked connections.")
        gn.addWidget(self._nb)
        rt = QHBoxLayout(); rt.addWidget(QLabel("Toast duration (seconds):"))
        self._toast_sec = QSpinBox(); self._toast_sec.setRange(3, 60); self._toast_sec.setValue(cfg["toast_sec"])
        self._toast_sec.setToolTip("How long toast notifications stay on screen before auto-dismissing.\nClick any notification to dismiss it immediately.")
        rt.addWidget(self._toast_sec)
        gn.addLayout(rt)
        form.addWidget(grp_ntf)

        # System
        grp_sys = QGroupBox("System")
        gsy = QVBoxLayout(grp_sys)
        self._tray_chk = QCheckBox("Minimize to system tray"); self._tray_chk.setChecked(cfg["tray"])
        self._tray_chk.setToolTip("When you close the window, minimize to the system tray\ninstead of quitting. PyWall continues monitoring in the background.\nRight-click the tray icon for options.")
        gsy.addWidget(self._tray_chk)
        self._log_chk = QCheckBox("Log connections to CSV"); self._log_chk.setChecked(cfg["log"])
        self._log_chk.setToolTip("Write every connection to a CSV file for external analysis.\nFile is saved in the PyWall directory.")
        gsy.addWidget(self._log_chk)
        self._startup_chk = QCheckBox("Start with Windows (elevated)"); self._startup_chk.setChecked(get_startup_enabled())
        self._startup_chk.setToolTip("Add PyWall to Windows startup with administrator privileges.\nPyWall needs admin rights to manage firewall rules.")
        gsy.addWidget(self._startup_chk)
        form.addWidget(grp_sys)

        scroll.setWidget(container)
        layout.addWidget(scroll)

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Cancel"); btn_cancel.clicked.connect(self.reject)
        btn_save = QPushButton("Save Settings"); btn_save.setStyleSheet(f"background: {S['bl']}; color: white;"); btn_save.clicked.connect(self._save)
        btn_row.addStretch(); btn_row.addWidget(btn_cancel); btn_row.addWidget(btn_save)
        layout.addLayout(btn_row)

    def _save(self):
        modes = {0: "monitor", 1: "whitelist", 2: "blacklist"}
        cfg["fw_mode"] = modes.get(self._fw_mode.currentIndex(), "monitor")
        cfg["ask_new_apps"] = self._ask_new.isChecked()
        cfg["auto_block_inbound"] = self._auto_block_in.isChecked()
        cfg["kill_blocked"] = self._kill_blocked.isChecked()
        cfg["start_monitoring"] = self._start_mon.isChecked()
        cfg["detect_portscan"] = self._detect_ps.isChecked()
        cfg["detect_bruteforce"] = self._detect_bf.isChecked()
        cfg["threat_auto_block"] = self._threat_ab.isChecked()
        cfg["portscan_threshold"] = self._ps_thresh.value()
        cfg["vt_api_key"] = self._vt_key.text().strip()
        cfg["geoip"] = self._geoip.isChecked()
        cfg["first_seen_alert"] = self._first_seen.isChecked()
        cfg["bw_tracking"] = self._bw.isChecked()
        cfg["blocklist_telemetry"] = self._bl_telem.isChecked()
        cfg["blocklist_ads"] = self._bl_ads.isChecked()
        cfg["blocklist_custom"] = self._bl_custom.isChecked()
        cfg["poll"] = self._poll.value()
        cfg["maxrows"] = self._maxrows.value()
        cfg["dns"] = self._dns_chk.isChecked()
        cfg["owners"] = self._owners_chk.isChecked()
        cfg["history_db"] = self._hist_db.isChecked()
        cfg["history_days"] = self._hist_days.value()
        cfg["toast"] = self._toast_chk.isChecked()
        cfg["notify_blocked"] = self._nb.isChecked()
        cfg["toast_sec"] = self._toast_sec.value()
        cfg["tray"] = self._tray_chk.isChecked()
        cfg["log"] = self._log_chk.isChecked()
        set_startup_enabled(self._startup_chk.isChecked())
        cfg.save()
        self.accept()

# ================================================================
#  ABOUT DIALOG
# ================================================================
class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"About {APP}")
        self.setFixedSize(480, 520)
        self.setStyleSheet(f"QDialog {{ background: {S['bg0']}; }} QLabel {{ color: {S['t1']}; }}")
        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(30, 25, 30, 25)
        title = QLabel(APP); title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold)); title.setStyleSheet(f"color: {S['bl']};"); title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        ver = QLabel(f"Version {VER}"); ver.setAlignment(Qt.AlignmentFlag.AlignCenter); ver.setStyleSheet(f"color: {S['t2']}; font-size: 13px;")
        layout.addWidget(ver)
        layout.addSpacing(10)
        desc = QLabel("Professional Windows Firewall Management Suite\n\n"
                       "PyWall provides comprehensive firewall control, replacing\n"
                       "the need for third-party firewall software. It leverages\n"
                       "the Windows Filtering Platform through Windows Firewall\n"
                       "to deliver enterprise-grade network security.\n\n"
                       "Features:\n"
                       " - Complete firewall rule management (CRUD)\n"
                       " - Real-time connection monitoring & intelligence\n"
                       " - Per-application network policies & enforcement\n"
                       " - Bandwidth tracking & visualization\n"
                       " - GeoIP, DNS, WHOIS intelligence\n"
                       " - VirusTotal & digital signature verification\n"
                       " - Threat detection (port scans, brute force)\n"
                       " - GeoIP novelty & anomaly detection\n"
                       " - Blocklist enforcement (telemetry, ads, custom)\n"
                       " - SQLite connection history with search\n"
                       " - Toast notifications with ask-to-allow\n"
                       " - Network profile management\n"
                       " - Rule health check & conflict detection\n"
                       " - Plugin system with example plugins\n"
                       " - CLI mode for scripting & automation\n"
                       " - Session tracking & timeline view\n"
                       " - Config import with diff preview\n"
                       " - 7 themes (5 dark + 2 light), system tray\n"
                       " - Crash recovery & admin detection")
        desc.setWordWrap(True); desc.setStyleSheet(f"color: {S['t2']}; font-size: 11px; line-height: 1.4;")
        layout.addWidget(desc)
        layout.addStretch()

        # Action buttons
        btn_row = QHBoxLayout(); btn_row.addStretch()
        btn_welcome = QPushButton("Show Welcome Guide")
        btn_welcome.setStyleSheet(f"padding: 6px 14px; border-radius: 4px; border: 1px solid {S['bd2']}; color: {S['t1']}; background: {S['bg2']}; font-size: 11px;")
        btn_welcome.setToolTip("Re-open the welcome guide that appeared on first launch")
        btn_welcome.clicked.connect(lambda: (self.accept(), parent._show_welcome() if parent else None))
        btn_row.addWidget(btn_welcome)
        btn_help = QPushButton("Quick Reference")
        btn_help.setStyleSheet(f"padding: 6px 14px; border-radius: 4px; border: 1px solid {S['bd2']}; color: {S['t1']}; background: {S['bg2']}; font-size: 11px;")
        btn_help.setToolTip("Open the quick reference help guide")
        btn_help.clicked.connect(lambda: (self.accept(), parent._show_help() if parent else None))
        btn_row.addWidget(btn_help)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        inspired = QLabel("Inspired by simplewall, GlassWire, Fort Firewall, Portmaster")
        inspired.setAlignment(Qt.AlignmentFlag.AlignCenter); inspired.setStyleSheet(f"color: {S['t3']}; font-size: 10px;")
        layout.addWidget(inspired)
        copy_lbl = QLabel("Open Source - MIT License"); copy_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter); copy_lbl.setStyleSheet(f"color: {S['t3']}; font-size: 10px;")
        layout.addWidget(copy_lbl)

# ================================================================
#  DASHBOARD WIDGETS
# ================================================================
class BandwidthGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(160)
        self._data = []

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor(S['bg3']))

        # Border
        p.setPen(QPen(QColor(S['bd1']), 1))
        p.drawRect(0, 0, w-1, h-1)

        data = bw.get_history(w // 3)
        if not data:
            p.setPen(QColor(S['t3']))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No bandwidth data")
            p.end(); return

        max_val = max(max(u, d) for u, d in data) or 1
        pad_t, pad_b, pad_l, pad_r = 20, 25, 50, 10
        gw = w - pad_l - pad_r; gh = h - pad_t - pad_b
        n = len(data); step = gw / max(n - 1, 1)

        # Grid lines
        p.setPen(QPen(QColor(S['bd1']), 1, Qt.PenStyle.DotLine))
        for i in range(5):
            y = pad_t + int(gh * i / 4)
            p.drawLine(pad_l, y, w - pad_r, y)
            val = max_val * (1 - i / 4)
            p.setPen(QColor(S['t3'])); p.setFont(QFont("Segoe UI", 7))
            p.drawText(2, y + 4, bw.format_rate(val))
            p.setPen(QPen(QColor(S['bd1']), 1, Qt.PenStyle.DotLine))

        # Upload curve (blue filled)
        up_path = QPainterPath(); up_path.moveTo(pad_l, pad_t + gh)
        for i, (u, _) in enumerate(data):
            x = pad_l + i * step; y = pad_t + gh - (u / max_val) * gh
            up_path.lineTo(x, y)
        up_path.lineTo(pad_l + (n-1)*step, pad_t+gh); up_path.closeSubpath()
        grad = QLinearGradient(0, pad_t, 0, pad_t+gh)
        grad.setColorAt(0, QColor(S['bl'])); grad.setColorAt(1, QColor(S['bl']+"20"))
        p.fillPath(up_path, grad)
        # Upload line
        p.setPen(QPen(QColor(S['bl']), 2))
        for i in range(1, n):
            x0 = pad_l+(i-1)*step; y0 = pad_t+gh-(data[i-1][0]/max_val)*gh
            x1 = pad_l+i*step; y1 = pad_t+gh-(data[i][0]/max_val)*gh
            p.drawLine(int(x0),int(y0),int(x1),int(y1))

        # Download curve (cyan filled)
        dn_path = QPainterPath(); dn_path.moveTo(pad_l, pad_t+gh)
        for i, (_, d) in enumerate(data):
            x = pad_l + i * step; y = pad_t + gh - (d / max_val) * gh
            dn_path.lineTo(x, y)
        dn_path.lineTo(pad_l+(n-1)*step, pad_t+gh); dn_path.closeSubpath()
        grad2 = QLinearGradient(0, pad_t, 0, pad_t+gh)
        grad2.setColorAt(0, QColor(S['cy'])); grad2.setColorAt(1, QColor(S['cy']+"20"))
        p.fillPath(dn_path, grad2)
        p.setPen(QPen(QColor(S['cy']), 2))
        for i in range(1, n):
            x0 = pad_l+(i-1)*step; y0 = pad_t+gh-(data[i-1][1]/max_val)*gh
            x1 = pad_l+i*step; y1 = pad_t+gh-(data[i][1]/max_val)*gh
            p.drawLine(int(x0),int(y0),int(x1),int(y1))

        # Legend
        p.setFont(QFont("Segoe UI", 8))
        up_r, dn_r = bw.rates()
        p.setPen(QColor(S['bl'])); p.drawText(pad_l, h-4, f"Upload: {bw.format_rate(up_r)}")
        p.setPen(QColor(S['cy'])); p.drawText(pad_l+160, h-4, f"Download: {bw.format_rate(dn_r)}")
        p.end()

class StatCard(QFrame):
    def __init__(self, title, value="0", color=None, parent=None):
        super().__init__(parent)
        self.setFixedSize(170, 80)
        self.setStyleSheet(f"background: {S['bg1']}; border: 1px solid {S['bd1']}; border-radius: 8px;")
        layout = QVBoxLayout(self); layout.setContentsMargins(12, 8, 12, 8)
        self._title = QLabel(title); self._title.setStyleSheet(f"color: {S['t3']}; font-size: 9px; font-weight: bold; border: none;"); self._title.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._value = QLabel(str(value)); self._value.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        c = color or S['t1']
        self._value.setStyleSheet(f"color: {c}; border: none;"); self._value.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._title); layout.addWidget(self._value)
    def setValue(self, v):
        self._value.setText(str(v))
    def setColor(self, c):
        self._value.setStyleSheet(f"color: {c}; border: none;")

# ================================================================
#  NETWORK MAP WIDGET (Radial Visualization)
# ================================================================
class NetworkMapWidget(QWidget):
    """Animated radial connection visualization with pulsing traffic lines."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._conns = []
        self._mode = "By Country"
        self._pulse_phase = 0.0  # 0-1 animation phase
        self._particles = []     # active traffic particles
        self.setMinimumHeight(300)
        # Animation timer
        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._tick_anim)
        self._anim_timer.start(50)  # 20fps

    def _tick_anim(self):
        self._pulse_phase = (self._pulse_phase + 0.05) % 1.0
        # Update particles
        self._particles = [(x+dx, y+dy, dx, dy, life-1, col)
                           for x, y, dx, dy, life, col in self._particles if life > 0]
        # Spawn new particles from active connections
        if self._conns and len(self._particles) < 60:
            import random, math
            ci = random.choice(self._conns)
            angle = random.uniform(0, 2 * math.pi)
            speed = random.uniform(1.5, 3.0)
            self._particles.append((
                self.width()//2, self.height()//2,
                math.cos(angle) * speed, math.sin(angle) * speed,
                random.randint(20, 45),
                S['rd'] if (ci.stat and ci.stat not in ("-","")) else S['bl']
            ))
        if self.isVisible(): self.update()

    def paintEvent(self, event):
        import math
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w // 2, h // 2
        radius = min(w, h) // 2 - 60

        # Background
        p.fillRect(0, 0, w, h, QColor(S['bg0']))

        # Draw particles (background layer)
        for px, py, dx, dy, life, col in self._particles:
            alpha = min(255, life * 8)
            pc = QColor(col); pc.setAlpha(alpha)
            p.setBrush(pc); p.setPen(Qt.PenStyle.NoPen)
            sz = max(1, life // 10)
            p.drawEllipse(QPoint(int(px), int(py)), sz, sz)

        # Center node with pulse ring
        pulse_r = 18 + int(6 * math.sin(self._pulse_phase * 2 * math.pi))
        ring_color = QColor(S['bl']); ring_color.setAlpha(40)
        p.setBrush(Qt.BrushStyle.NoBrush); p.setPen(QPen(ring_color, 2))
        p.drawEllipse(QPoint(cx, cy), pulse_r + 8, pulse_r + 8)
        p.setBrush(QColor(S['bl'])); p.setPen(QPen(QColor(S['bl']), 2))
        p.drawEllipse(QPoint(cx, cy), 18, 18)
        p.setPen(QColor(S['t1'])); p.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        p.drawText(QRect(cx-18, cy-9, 36, 18), Qt.AlignmentFlag.AlignCenter, "PC")

        if not self._conns:
            p.setPen(QColor(S['t3'])); p.setFont(QFont("Segoe UI", 11))
            p.drawText(QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "Waiting for connections...")
            p.end(); return

        # Group connections
        groups = {}
        cat_colors = {
            "Web": S['bl'], "Streaming": S['cy'], "Gaming": S['gn'], "Social Media": S['am'],
            "Messaging": S['am'], "Email": "#8B5CF6", "System": S['t2'], "CDN": S['t3'],
            "Ads/Tracking": S['rd'], "Cloud Storage": "#06B6D4", "Development": "#10B981",
            "LAN": S['t3'], "Unknown": S['t3'], "DNS": "#818CF8", "Shopping": "#F472B6",
        }
        country_colors = ["#3B82F6","#06B6D4","#22C55E","#F59E0B","#EF4444","#8B5CF6",
                          "#EC4899","#14B8A6","#F97316","#6366F1","#84CC16","#E11D48"]

        for ci in self._conns:
            if not ci.ra or ci.ra == "*" or PRIV.match(ci.ra or ""): continue
            if self._mode == "By Country":
                key = ci.country if ci.country and ci.country not in ("-","","Local") else "Unknown"
            elif self._mode == "By Category":
                key = categorizer.categorize(ci.host, ci.ra, ci.rp, ci.proc)
            else:
                key = ci.proc or "?"
            groups.setdefault(key, []).append(ci)

        if not groups:
            p.setPen(QColor(S['t3'])); p.setFont(QFont("Segoe UI", 11))
            p.drawText(QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, "No external connections")
            p.end(); return

        n = len(groups)
        angle_step = 2 * math.pi / max(n, 1)

        for i, (key, conns) in enumerate(sorted(groups.items(), key=lambda x: -len(x[1]))):
            angle = i * angle_step - math.pi / 2
            node_r = radius * 0.7
            nx = cx + int(node_r * math.cos(angle))
            ny = cy + int(node_r * math.sin(angle))

            # Color
            if self._mode == "By Category":
                color = QColor(cat_colors.get(key, S['t3']))
            elif self._mode == "By Country":
                color = QColor(country_colors[i % len(country_colors)])
            else:
                hue = (i * 137) % 360
                color = QColor.fromHsv(hue, 180, 220)

            # Animated connection line with pulse
            count = len(conns)
            line_w = max(1, min(count, 8))
            blocked = sum(1 for c in conns if c.stat and c.stat not in ("-",""))
            line_color = QColor(S['rd']) if blocked > count/2 else color
            # Pulse alpha based on traffic volume
            pulse_alpha = 80 + min(count * 15, 175)
            pulse_alpha = int(pulse_alpha * (0.7 + 0.3 * math.sin(self._pulse_phase * 2 * math.pi + i)))
            line_color.setAlpha(max(30, min(255, pulse_alpha)))
            p.setPen(QPen(line_color, line_w))
            p.drawLine(cx, cy, nx, ny)

            # Traffic flow dots along the line
            for dot_i in range(min(count, 4)):
                t = (self._pulse_phase + dot_i * 0.25) % 1.0
                dot_x = int(cx + (nx - cx) * t)
                dot_y = int(cy + (ny - cy) * t)
                dot_color = QColor(line_color); dot_color.setAlpha(200)
                p.setBrush(dot_color); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPoint(dot_x, dot_y), 2, 2)

            # Node with glow effect
            node_size = max(8, min(count * 2, 28))
            glow = QColor(color); glow.setAlpha(30)
            p.setBrush(glow); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPoint(nx, ny), node_size + 6, node_size + 6)
            p.setBrush(color); p.setPen(QPen(color.darker(120), 1))
            p.drawEllipse(QPoint(nx, ny), node_size, node_size)

            # Count badge inside node
            if count > 1:
                p.setPen(QColor("#FFFFFF")); p.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
                p.drawText(QRect(nx-node_size, ny-node_size, node_size*2, node_size*2),
                           Qt.AlignmentFlag.AlignCenter, str(count))

            # Label
            p.setPen(QColor(S['t1'])); p.setFont(QFont("Segoe UI", 8))
            label = key[:14] if len(key) > 14 else key
            lbl_x = nx + node_size + 4 if nx > cx else nx - node_size - 4 - len(label)*6
            p.drawText(lbl_x, ny - 6, f"{label}")
            p.setFont(QFont("Segoe UI", 7)); p.setPen(QColor(S['t3']))
            blk_str = f" ({blocked} blk)" if blocked else ""
            p.drawText(lbl_x, ny + 8, f"{count} conn{blk_str}")

        # Stats overlay
        p.setPen(QColor(S['t2'])); p.setFont(QFont("Segoe UI", 9))
        total = sum(len(v) for v in groups.values())
        p.drawText(10, h - 10, f"{total} connections | {n} {self._mode.replace('By ', '').lower()}")
        p.end()

# ================================================================
#  SCHEDULE DIALOG
# ================================================================
class ScheduleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Rule Schedule")
        self.setFixedSize(400, 350)
        self.setStyleSheet(f"background: {S['bg0']}; color: {S['t1']};")
        layout = QVBoxLayout(self); layout.setSpacing(10)

        # Rule name
        layout.addWidget(QLabel("Rule Name:"))
        self._rule = QComboBox()
        rules = fw.get_pywall_rules()
        self._rule.addItems([r.name for r in rules])
        self._rule.setEditable(True)
        self._rule.setToolTip("Select or type a firewall rule name to schedule")
        layout.addWidget(self._rule)

        # Days
        layout.addWidget(QLabel("Days:"))
        days_row = QHBoxLayout()
        self._day_checks = {}
        for i, d in enumerate(["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]):
            cb = QCheckBox(d); cb.setChecked(i < 5)  # Mon-Fri default
            self._day_checks[i] = cb
            days_row.addWidget(cb)
        layout.addLayout(days_row)

        # Time range
        time_row = QHBoxLayout()
        time_row.addWidget(QLabel("Start:"))
        self._start = QLineEdit("09:00"); self._start.setFixedWidth(60)
        time_row.addWidget(self._start)
        time_row.addWidget(QLabel("End:"))
        self._end = QLineEdit("17:00"); self._end.setFixedWidth(60)
        time_row.addWidget(self._end)
        time_row.addStretch()
        layout.addLayout(time_row)

        # Action
        layout.addWidget(QLabel("Action during scheduled time:"))
        self._action = QComboBox()
        self._action.addItems(["enable", "disable"])
        self._action.setToolTip("Enable: rule is active during the time window\nDisable: rule is deactivated during the time window")
        layout.addWidget(self._action)

        layout.addStretch()
        btns = QHBoxLayout()
        btn_ok = QPushButton("Add Schedule"); btn_ok.setStyleSheet(f"background: {S['bl']}; color: white;")
        btn_ok.clicked.connect(self.accept)
        btn_cancel = QPushButton("Cancel"); btn_cancel.clicked.connect(self.reject)
        btns.addStretch(); btns.addWidget(btn_ok); btns.addWidget(btn_cancel)
        layout.addLayout(btns)

    def get_data(self):
        days = [i for i, cb in self._day_checks.items() if cb.isChecked()]
        return {
            "rule_name": self._rule.currentText(),
            "days": days, "start": self._start.text(), "end": self._end.text(),
            "action": self._action.currentText(),
        }

# ================================================================
#  MAIN WINDOW
# ================================================================
# ================================================================
#  WELCOME / ONBOARDING DIALOG
# ================================================================
class WelcomeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome to PyWall")
        self.setFixedSize(620, 560)
        self.setStyleSheet(f"""
            QDialog {{ background: {S['bg0']}; }}
            QLabel {{ color: {S['t1']}; }}
            QPushButton {{ padding: 8px 20px; border-radius: 5px; font-size: 12px;
                          border: 1px solid {S['bd2']}; color: {S['t1']}; background: {S['bg2']}; }}
            QPushButton:hover {{ background: {S['bd2']}; }}
        """)
        self._page = 0
        self._pages = [
            ("Welcome to PyWall", "PyWall is a professional Windows Firewall management suite that gives you complete control over your network security.",
             [("Monitor", "See every network connection in real time - what's connecting, where, and why."),
              ("Control", "Create, edit, and manage firewall rules with an easy-to-use interface."),
              ("Protect", "Detect threats like port scans and brute force attacks automatically."),
              ("Per-App Policies", "Set Allow, Block, or Ask policies for each application individually.")]),
            ("Getting Started", "Here's a quick overview of each tab to help you navigate:",
             [("Dashboard", "Overview hub - stats, bandwidth graph, traffic categories, and quick actions."),
              ("Network Map", "Radial visualization showing active connections grouped by country, category, or process."),
              ("Connections", "Live view of all connections with categories & reputation. Right-click to act."),
              ("Timeline", "Connection session tracking with start/end times and duration history.")]),
            ("Advanced Features", "PyWall includes powerful network intelligence tools:",
             [("Traffic Categories", "Connections are auto-classified as Streaming, Gaming, Social, System, etc."),
              ("Reputation Scoring", "Processes get trust grades (A-F) based on behavior patterns."),
              ("Rule Templates", "One-click rule presets: Privacy Mode, Gaming PC, Work Lockdown, and more."),
              ("Anomaly Detection", "Baselines your network and alerts when something deviates from normal.")]),
            ("Tips & Features", "A few things to know:",
             [("Scheduled Rules", "Enable/disable rules by time and day. Great for blocking social media during work."),
              ("Network Profiles", "Auto-switch firewall settings when you change Wi-Fi networks."),
              ("Plugins", "Extend PyWall with Python scripts. Place .py files in the plugins folder."),
              ("Export/Import", "Full config backup: rules, settings, schedules, profiles. Transfer to another PC.")]),
        ]
        self._build()

    def _build(self):
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(30, 24, 30, 20)
        self._layout.setSpacing(12)
        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._layout.addWidget(self._content, 1)

        # Navigation
        nav = QHBoxLayout()
        self._dots = QLabel()
        self._dots.setStyleSheet(f"color: {S['t3']}; font-size: 18px;")
        self._dots.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav.addStretch()
        self._btn_back = QPushButton("Back")
        self._btn_back.clicked.connect(lambda: self._go(-1))
        nav.addWidget(self._btn_back)
        nav.addWidget(self._dots)
        self._btn_next = QPushButton("Next")
        self._btn_next.setStyleSheet(f"background: {S['bl']}; color: white; font-weight: bold;")
        self._btn_next.clicked.connect(lambda: self._go(1))
        nav.addWidget(self._btn_next)
        nav.addStretch()
        self._layout.addLayout(nav)
        self._show_page()

    def _go(self, delta):
        self._page += delta
        if self._page >= len(self._pages):
            cfg["first_run"] = False; cfg.save()
            self.accept(); return
        if self._page < 0: self._page = 0
        self._show_page()

    def _show_page(self):
        # Clear content
        while self._content_layout.count():
            w = self._content_layout.takeAt(0).widget()
            if w: w.deleteLater()
        title, desc, items = self._pages[self._page]

        # Shield icon + title
        t = QLabel(f"  {title}")
        t.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        t.setStyleSheet(f"color: {S['bl']};")
        self._content_layout.addWidget(t)
        d = QLabel(desc); d.setWordWrap(True)
        d.setStyleSheet(f"color: {S['t2']}; font-size: 12px; padding: 6px 0 10px 0;")
        self._content_layout.addWidget(d)
        for name, info in items:
            card = QFrame()
            card.setStyleSheet(f"background: {S['bg1']}; border: 1px solid {S['bd1']}; border-radius: 8px; padding: 12px;")
            cl = QVBoxLayout(card); cl.setSpacing(4)
            n = QLabel(name); n.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            n.setStyleSheet(f"color: {S['cy']}; border: none;")
            cl.addWidget(n)
            i = QLabel(info); i.setWordWrap(True)
            i.setStyleSheet(f"color: {S['t2']}; font-size: 11px; border: none;")
            cl.addWidget(i)
            self._content_layout.addWidget(card)
        self._content_layout.addStretch()

        # Update navigation
        self._btn_back.setVisible(self._page > 0)
        self._btn_next.setText("Get Started" if self._page == len(self._pages) - 1 else "Next")
        dots = "".join(["O " if i == self._page else "o " for i in range(len(self._pages))])
        self._dots.setText(dots.strip())


class HelpDialog(QDialog):
    """Quick reference help dialog."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("PyWall Help")
        self.setFixedSize(540, 480)
        self.setStyleSheet(f"""
            QDialog {{ background: {S['bg0']}; }}
            QLabel {{ color: {S['t1']}; }}
            QPushButton {{ padding: 6px 16px; border-radius: 4px; border: 1px solid {S['bd2']};
                          color: {S['t1']}; background: {S['bg2']}; }}
        """)
        layout = QVBoxLayout(self); layout.setContentsMargins(20, 16, 20, 16)
        t = QLabel("PyWall Quick Reference")
        t.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        t.setStyleSheet(f"color: {S['bl']};")
        layout.addWidget(t)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ border: none; }}")
        content = QWidget(); cl = QVBoxLayout(content); cl.setSpacing(10)
        sections = [
            ("Keyboard & Mouse", [
                "Right-click connections, rules, or threats for context menus",
                "Double-click a rule in the Rules tab to edit it",
                "Press Enter in search fields to trigger search",
            ]),
            ("Firewall Modes", [
                "Monitor: Watch traffic without blocking (default)",
                "Block All Outbound: Blocks everything not explicitly allowed",
                "Per-App Policies: Set Allow/Block/Ask per application",
            ]),
            ("Notifications", [
                "Block IP / Allow IP: Quick one-click actions",
                "Edit Rule: Opens full rule editor prefilled with connection details",
                "More: Expands advanced options (direction, type, duration)",
            ]),
            ("Security", [
                "Port Scan Detection: Alerts when an IP probes multiple ports",
                "Brute Force Detection: Alerts on repeated blocked connections",
                "Auto-Block: Automatically creates block rules for detected threats",
            ]),
            ("Tips", [
                "Hover over any control for a tooltip explaining what it does",
                "Use Settings to configure thresholds, notifications, and behavior",
                "Export rules to JSON for backup or sharing between machines",
            ]),
        ]
        for title, items in sections:
            h = QLabel(title); h.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            h.setStyleSheet(f"color: {S['cy']};"); cl.addWidget(h)
            for item in items:
                l = QLabel(f"  {item}"); l.setWordWrap(True)
                l.setStyleSheet(f"color: {S['t2']}; font-size: 11px;"); cl.addWidget(l)
        cl.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)
        btn_close = QPushButton("Close"); btn_close.clicked.connect(self.accept)
        btn_close.setStyleSheet(f"background: {S['bl']}; color: white;")
        bh = QHBoxLayout(); bh.addStretch(); bh.addWidget(btn_close); bh.addStretch()
        layout.addLayout(bh)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP} v{VER}")
        self.setMinimumSize(1280, 800)
        self.resize(1520, 920)
        self._monitoring = False
        self._auto_block = False
        self._auto_blocked_ips = set()  # Track IPs already auto-blocked to prevent duplicates
        self._filter_src = "Live + Events"
        self._filter_dir = "All"
        self._filter_pro = "All"
        self._filter_txt = ""
        self._start_time = datetime.datetime.now()
        self._evt_count = 0
        self._conn_data = []
        self._toasts = []
        self._toast_dedup = {}
        self._toast_cooldown = 60
        self._suppressed = set()
        self._restart_pending = False

        self._apply_theme()
        self._build_ui()
        self._build_tray()
        self._init_workers()
        self._init_timers()
        self._refresh_rules_panel()
        self._check_fw_status()

        # Auto-start monitoring
        if cfg.get("start_monitoring") or cfg.get("_was_monitoring", False):
            QTimer.singleShot(500, self._toggle_monitor)
            if cfg.get("_was_monitoring") and not cfg.get("start_monitoring"):
                QTimer.singleShot(600, lambda: self._sbar.setText("Monitoring resumed from previous session"))

        # First-run welcome dialog
        if cfg.get("first_run", True):
            QTimer.singleShot(800, self._show_welcome)

    def _show_welcome(self):
        dlg = WelcomeDialog(self)
        dlg.exec()

    def _show_help(self):
        dlg = HelpDialog(self)
        dlg.exec()

    def _switch_theme(self, name):
        if name not in THEMES or name == cfg["theme"]: return
        set_theme(name)
        self._restart_pending = True
        QApplication.quit()

    def _apply_theme(self):
        self.setStyleSheet(f"""
            QMainWindow {{ background: {S['bg0']}; }}
            QLabel {{ color: {S['t1']}; }}
            QTabWidget::pane {{ border: 1px solid {S['bd1']}; background: {S['bg0']}; }}
            QTabBar::tab {{ background: {S['bg1']}; color: {S['t3']}; padding: 8px 20px; border: 1px solid {S['bd1']};
                border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; font-size: 11px; }}
            QTabBar::tab:selected {{ background: {S['bg0']}; color: {S['bl']}; font-weight: bold; border-bottom: 2px solid {S['bl']}; }}
            QTabBar::tab:hover {{ color: {S['t1']}; background: {S['bg2']}; }}
            QTableWidget {{ background: {S['ra']}; gridline-color: {S['bd1']}; color: {S['t1']};
                border: 1px solid {S['bd1']}; selection-background-color: {S['rs']}; font-size: 11px; }}
            QTableWidget::item {{ padding: 2px 5px; border-bottom: 1px solid {S['bg2']}; }}
            QTableWidget::item:selected {{ background: {S['rs']}; }}
            QHeaderView::section {{ background: {S['bg2']}; color: {S['t2']}; border: none;
                padding: 4px 6px; font-weight: bold; font-size: 10px; border-right: 1px solid {S['bd1']}; }}
            QLineEdit {{ background: {S['bg2']}; color: {S['t1']}; border: 1px solid {S['bd1']}; padding: 5px 8px; border-radius: 4px; }}
            QComboBox {{ background: {S['bg2']}; color: {S['t1']}; border: 1px solid {S['bd1']}; padding: 4px 8px; border-radius: 3px; }}
            QComboBox::drop-down {{ border: none; width: 20px; }}
            QComboBox::down-arrow {{ image: none; border-left: 4px solid transparent; border-right: 4px solid transparent; border-top: 5px solid {S['t2']}; }}
            QComboBox QAbstractItemView {{ background: {S['bg1']}; color: {S['t1']}; selection-background-color: {S['bl']}; border: 1px solid {S['bd2']}; }}
            QPushButton {{ padding: 5px 14px; border-radius: 4px; font-size: 11px; border: 1px solid {S['bd2']}; color: {S['t1']}; background: {S['bg2']}; }}
            QPushButton:hover {{ background: {S['bd2']}; }}
            QSplitter::handle {{ background: {S['bd1']}; }}
            QScrollBar:vertical {{ background: {S['bg1']}; width: 10px; border-radius: 5px; }}
            QScrollBar::handle:vertical {{ background: {S['bd2']}; border-radius: 5px; min-height: 20px; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
            QScrollBar:horizontal {{ background: {S['bg1']}; height: 10px; }}
            QScrollBar::handle:horizontal {{ background: {S['bd2']}; border-radius: 5px; min-width: 20px; }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}
            QCheckBox {{ color: {S['t1']}; }}
            QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {S['bd2']}; border-radius: 2px; background: {S['bg2']}; }}
            QCheckBox::indicator:checked {{ background: {S['bl']}; }}
            QMenu {{ background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bd2']}; }}
            QMenu::item:selected {{ background: {S['bl']}; }}
            QToolTip {{ background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bl']};
                padding: 8px 10px; font-size: 11px; border-radius: 4px; }}
        """)

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        # ======== TOP BAR ========
        top_bar = QWidget(); top_bar.setFixedHeight(52)
        top_bar.setStyleSheet(f"background: {S['bg1']}; border-bottom: 1px solid {S['bd1']};")
        tb = QHBoxLayout(top_bar); tb.setContentsMargins(14, 0, 14, 0); tb.setSpacing(10)

        # Logo
        logo_lbl = QLabel(f" {APP}"); logo_lbl.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        logo_lbl.setStyleSheet(f"color: {S['bl']}; border: none;")
        tb.addWidget(logo_lbl)
        ver_lbl = QLabel(f"v{VER}"); ver_lbl.setStyleSheet(f"color: {S['t3']}; font-size: 10px; border: none;")
        tb.addWidget(ver_lbl)
        tb.addSpacing(20)

        # Start/Stop + Status
        self._status_dot = QLabel(); self._status_dot.setFixedSize(10, 10)
        self._status_dot.setStyleSheet(f"background: {S['t3']}; border-radius: 5px; border: none;")
        self._status_dot.setToolTip("Green = monitoring active, Gray = monitoring stopped")
        tb.addWidget(self._status_dot)
        self._status_lbl = QLabel("OFFLINE"); self._status_lbl.setStyleSheet(f"color: {S['t3']}; font-size: 10px; font-weight: bold; border: none;")
        self._status_lbl.setToolTip("Current monitoring status")
        tb.addWidget(self._status_lbl)
        # Admin privilege indicator
        admin_lbl = QLabel("ADMIN" if IS_ADMIN else "LIMITED")
        admin_color = S['gn'] if IS_ADMIN else S['am']
        admin_lbl.setStyleSheet(f"color: {admin_color}; font-size: 9px; font-weight: bold; border: 1px solid {admin_color}; border-radius: 3px; padding: 1px 4px;")
        admin_lbl.setToolTip("ADMIN: Full firewall control available.\nLIMITED: Some features require admin privileges.\nRun PyWall as Administrator for full access." if not IS_ADMIN else "Running with full administrator privileges.")
        tb.addWidget(admin_lbl)

        self._btn_start = QPushButton("Start Monitor")
        self._btn_start.setStyleSheet(f"background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #2563EB,stop:1 #1D4ED8); border-color: {S['bl']}; color: white; padding: 6px 18px; font-weight: bold;")
        self._btn_start.setToolTip("Start or stop the network connection monitor.\nWhen active, PyWall watches all network traffic in real time.")
        self._btn_start.clicked.connect(self._toggle_monitor)
        tb.addWidget(self._btn_start)
        tb.addSpacing(10)

        # Bandwidth display
        self._bw_up = QLabel("-- B/s"); self._bw_up.setStyleSheet(f"color: {S['bl']}; font-size: 10px; border: none;")
        self._bw_up.setToolTip("Current upload speed")
        self._bw_dn = QLabel("-- B/s"); self._bw_dn.setStyleSheet(f"color: {S['cy']}; font-size: 10px; border: none;")
        self._bw_dn.setToolTip("Current download speed")
        bw_w = QWidget(); bw_l = QVBoxLayout(bw_w); bw_l.setContentsMargins(0,0,0,0); bw_l.setSpacing(0)
        bw_l.addWidget(self._bw_up); bw_l.addWidget(self._bw_dn)
        tb.addWidget(bw_w)

        tb.addStretch()

        # FW Profile indicator
        self._profile_lbl = QLabel("Profile: --")
        self._profile_lbl.setStyleSheet(f"color: {S['am']}; font-size: 10px; border: none;")
        self._profile_lbl.setToolTip("The active Windows Firewall profile.\nDomain = corporate network, Private = home/trusted, Public = untrusted.")
        tb.addWidget(self._profile_lbl)
        tb.addSpacing(10)

        # Theme selector
        theme_cb = QComboBox(); theme_cb.addItems(list(THEMES.keys()))
        theme_cb.setCurrentText(cfg["theme"]); theme_cb.setFixedWidth(100)
        theme_cb.setToolTip("Change the color theme.\nRequires a restart to take full effect.")
        theme_cb.currentTextChanged.connect(self._switch_theme)
        tb.addWidget(theme_cb)

        btn_help = QPushButton("?")
        btn_help.setFixedSize(30, 30)
        btn_help.setStyleSheet(f"background: {S['bg2']}; color: {S['cy']}; font-weight: bold; font-size: 13px; border-radius: 15px;")
        btn_help.setToolTip("Open the help guide")
        btn_help.clicked.connect(self._show_help)
        tb.addWidget(btn_help)
        btn_settings = QPushButton("Settings"); btn_settings.clicked.connect(self._open_settings)
        btn_settings.setToolTip("Configure monitoring, security, notifications, and more")
        tb.addWidget(btn_settings)
        btn_about = QPushButton("About"); btn_about.clicked.connect(self._open_about)
        btn_about.setToolTip("About PyWall and version information")
        tb.addWidget(btn_about)
        root.addWidget(top_bar)

        # ======== TAB WIDGET ========
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        root.addWidget(self._tabs)

        self._build_dashboard_tab()       # idx 0 - always eager
        self._build_netmap_tab()          # idx 1 - always eager (lightweight)
        self._build_connections_tab()     # idx 2 - always eager (primary view)
        # Lazy-loaded tabs: build placeholder, construct on first visit
        self._lazy_tabs = {}
        self._add_lazy_tab("Rules", self._build_rules_tab, 3)
        self._add_lazy_tab("Applications", self._build_apps_tab, 4)
        self._add_lazy_tab("History", self._build_history_tab, 5)
        self._add_lazy_tab("Timeline", self._build_timeline_tab, 6)
        self._add_lazy_tab("Security", self._build_security_tab, 7)
        self._add_lazy_tab("Schedule", self._build_schedule_tab, 8)
        self._add_lazy_tab("Plugins", self._build_plugins_tab, 9)
        self._tabs.currentChanged.connect(self._on_tab_changed)

        # Tab tooltips
        tab_tips = [
            "Overview of your network activity, bandwidth, and quick actions",
            "Live radial visualization of active connections by country and category",
            "Live view of all network connections - right-click to act",
            "Browse, search, and manage all Windows Firewall rules",
            "Set per-application network policies (Allow / Block / Ask)",
            "Search and browse previously recorded connections",
            "Connection session timeline with duration and activity tracking",
            "Security threat detection and blocklist management",
            "Schedule firewall rules to enable/disable at specific times",
            "Manage plugins that extend PyWall with custom event handlers",
        ]
        for i, tip in enumerate(tab_tips):
            self._tabs.setTabToolTip(i, tip)

        # ======== STATUS BAR ========
        sbar = QWidget(); sbar.setFixedHeight(26)
        sbar.setStyleSheet(f"background: {S['bg1']}; border-top: 1px solid {S['bd1']};")
        sb = QHBoxLayout(sbar); sb.setContentsMargins(10, 0, 10, 0)
        self._sbar = QLabel("Ready"); self._sbar.setStyleSheet(f"color: {S['t2']}; font-size: 10px; border: none;")
        self._sbar.setToolTip("Status messages from PyWall operations appear here")
        sb.addWidget(self._sbar)
        sb.addStretch()
        self._sbar_r = QLabel(f"DB: {DBFILE.name}  |  Log: {LOGF.name}")
        self._sbar_r.setStyleSheet(f"color: {S['t3']}; font-size: 9px; border: none;")
        self._sbar_r.setToolTip(f"Database file: {DBFILE}\nLog file: {LOGF}")
        sb.addWidget(self._sbar_r)
        root.addWidget(sbar)

    # ================================================================
    #  TAB BUILDERS
    # ================================================================
    # ================================================================
    #  LAZY TAB LOADING
    # ================================================================
    def _add_lazy_tab(self, title, build_fn, expected_idx):
        """Add a placeholder tab that gets built on first visit."""
        placeholder = QWidget()
        lbl = QLabel(f"Loading {title}...")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(f"color: {S['t3']}; font-size: 13px;")
        lay = QVBoxLayout(placeholder); lay.addWidget(lbl)
        self._tabs.addTab(placeholder, title)
        actual_idx = self._tabs.count() - 1
        self._lazy_tabs[actual_idx] = (build_fn, title)

    def _on_tab_changed(self, idx):
        """Build lazy tab on first visit, then auto-refresh content."""
        if idx in self._lazy_tabs:
            build_fn, title = self._lazy_tabs.pop(idx)
            try:
                # Remove placeholder
                old = self._tabs.widget(idx)
                # Build the real tab content
                build_fn()
                # The build_fn appends a new tab at the end - move it to the correct index
                last_idx = self._tabs.count() - 1
                if last_idx != idx:
                    widget = self._tabs.widget(last_idx)
                    text = self._tabs.tabText(last_idx)
                    self._tabs.removeTab(last_idx)
                    self._tabs.removeTab(idx)
                    self._tabs.insertTab(idx, widget, text)
                    self._tabs.setCurrentIndex(idx)
                else:
                    # build_fn replaced at the same index somehow, remove old placeholder
                    pass
                if old:
                    old.deleteLater()
            except Exception as e:
                log.warning(f"Failed to build lazy tab '{title}': {e}")
        # Auto-refresh content when switching to a tab
        try:
            tab_name = self._tabs.tabText(idx)
            if tab_name == "Rules" and hasattr(self, '_rules_mgr'):
                QTimer.singleShot(50, self._rules_mgr._scan)
            elif tab_name == "Applications" and hasattr(self, '_app_tbl'):
                QTimer.singleShot(50, self._refresh_apps)
            elif tab_name == "History" and hasattr(self, '_hist_tbl'):
                QTimer.singleShot(50, self._search_history)
            elif tab_name == "Timeline" and hasattr(self, '_timeline_active_tbl'):
                QTimer.singleShot(50, self._update_timeline)
            elif tab_name == "Security" and hasattr(self, '_sec_total'):
                QTimer.singleShot(50, self._update_security)
            elif tab_name == "Schedule" and hasattr(self, '_sched_tbl'):
                QTimer.singleShot(50, self._update_schedule_tab)
            elif tab_name == "Plugins" and hasattr(self, '_plug_tbl'):
                QTimer.singleShot(50, self._update_plugins_ui)
            elif tab_name == "Dashboard":
                QTimer.singleShot(50, self._update_dashboard)
        except: pass

    # ================================================================
    #  TAB BUILDERS
    # ================================================================
    def _build_dashboard_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(12, 12, 12, 12)

        # Stat cards row
        cards = QHBoxLayout(); cards.setSpacing(10)
        self._dash_conn = StatCard("Active Connections", "0", S['bl'])
        self._dash_conn.setToolTip("Number of active network connections right now.\nIncludes TCP and UDP connections from all applications.")
        self._dash_blk = StatCard("Blocked", "0", S['rd'])
        self._dash_blk.setToolTip("Connections blocked by firewall rules, blocklists,\nor application policies during this session.")
        self._dash_rules = StatCard("Firewall Rules", "0", S['cy'])
        self._dash_rules.setToolTip("Total number of Windows Firewall rules currently active.\nIncludes both system rules and PyWall-created rules.")
        self._dash_evt = StatCard("Security Events", "0", S['am'])
        self._dash_evt.setToolTip("Blocked connection events from the Windows Security log.\nThese are connections that Windows Firewall denied.")
        self._dash_up = StatCard("Uptime", "00:00:00", S['t2'])
        self._dash_up.setToolTip("How long PyWall has been running this session.")
        self._dash_traffic = StatCard("Total Traffic", "0 B", S['gn'])
        self._dash_traffic.setToolTip("Total network data transferred (upload + download)\nsince PyWall started.")
        for c in [self._dash_conn, self._dash_blk, self._dash_rules, self._dash_evt, self._dash_up, self._dash_traffic]:
            cards.addWidget(c)
        cards.addStretch()
        layout.addLayout(cards)

        # Bandwidth graph + side panels
        mid = QHBoxLayout()
        # Graph
        graph_frame = QWidget()
        gf_l = QVBoxLayout(graph_frame); gf_l.setContentsMargins(0,0,0,0)
        gf_hdr = QLabel("Network Bandwidth"); gf_hdr.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        gf_hdr.setStyleSheet(f"color: {S['t2']};")
        gf_l.addWidget(gf_hdr)
        self._bw_graph = BandwidthGraph()
        self._bw_graph.setToolTip("Live bandwidth graph showing upload (blue) and download (cyan) speeds over time.")
        gf_l.addWidget(self._bw_graph)
        mid.addWidget(graph_frame, 3)

        # Side panels
        side = QVBoxLayout(); side.setSpacing(6)

        # Top Processes
        tp_hdr = QLabel("Top Processes by Bandwidth"); tp_hdr.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        tp_hdr.setStyleSheet(f"color: {S['t2']};")
        side.addWidget(tp_hdr)
        self._top_proc_tbl = QTableWidget(); self._top_proc_tbl.setColumnCount(3)
        self._top_proc_tbl.setHorizontalHeaderLabels(["Process", "Sent", "Received"])
        self._top_proc_tbl.horizontalHeader().setStretchLastSection(True)
        self._top_proc_tbl.verticalHeader().setVisible(False)
        self._top_proc_tbl.setMaximumHeight(180)
        self._top_proc_tbl.setColumnWidth(0, 140); self._top_proc_tbl.setColumnWidth(1, 80)
        self._top_proc_tbl.setToolTip("Applications using the most bandwidth.\nShows cumulative data sent and received per process.")
        side.addWidget(self._top_proc_tbl)

        # Threat summary
        th_hdr = QLabel("Recent Threats"); th_hdr.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        th_hdr.setStyleSheet(f"color: {S['t2']};")
        side.addWidget(th_hdr)
        self._threat_list = QListWidget()
        self._threat_list.setMaximumHeight(120)
        self._threat_list.setStyleSheet(f"QListWidget {{ background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bd1']}; border-radius: 4px; }} QListWidget::item {{ padding: 3px; }}")
        self._threat_list.setToolTip("Recent security threats detected by PyWall.\nIncludes port scans, brute force attempts, and other suspicious activity.\nSee the Security tab for full details.")
        side.addWidget(self._threat_list)

        # Top countries
        tc_hdr = QLabel("Top Countries by Connections"); tc_hdr.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        tc_hdr.setStyleSheet(f"color: {S['t2']};")
        side.addWidget(tc_hdr)
        self._top_country_tbl = QTableWidget(); self._top_country_tbl.setColumnCount(3)
        self._top_country_tbl.setHorizontalHeaderLabels(["CC", "Country", "Connections"])
        self._top_country_tbl.horizontalHeader().setStretchLastSection(True)
        self._top_country_tbl.verticalHeader().setVisible(False)
        self._top_country_tbl.setMaximumHeight(150)
        self._top_country_tbl.setColumnWidth(0, 40); self._top_country_tbl.setColumnWidth(1, 120)
        self._top_country_tbl.setToolTip("Which countries your network connections are going to.\nBased on GeoIP lookup of remote IP addresses.")
        side.addWidget(self._top_country_tbl)

        # Traffic categories
        cat_hdr = QLabel("Traffic by Category"); cat_hdr.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        cat_hdr.setStyleSheet(f"color: {S['t2']};")
        side.addWidget(cat_hdr)
        self._cat_tbl = QTableWidget(); self._cat_tbl.setColumnCount(2)
        self._cat_tbl.setHorizontalHeaderLabels(["Category", "Count"])
        self._cat_tbl.horizontalHeader().setStretchLastSection(True)
        self._cat_tbl.verticalHeader().setVisible(False)
        self._cat_tbl.setMaximumHeight(150)
        self._cat_tbl.setColumnWidth(0, 120)
        self._cat_tbl.setToolTip("Breakdown of your connections by traffic type.\nCategories are auto-detected from domain/IP/process patterns.")
        side.addWidget(self._cat_tbl)

        mid.addLayout(side, 2)
        layout.addLayout(mid)

        # Quick actions bar
        qa = QHBoxLayout()
        qa_lbl = QLabel("Quick Actions:"); qa_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        qa_lbl.setStyleSheet(f"color: {S['t2']};")
        qa.addWidget(qa_lbl)

        btn_block_all = QPushButton("Block All Outbound")
        btn_block_all.setStyleSheet(f"background: {S['rd']}; color: white;")
        btn_block_all.setToolTip("ADVANCED: Set the default outbound firewall action to BLOCK.\n\nThis blocks ALL outgoing traffic unless explicitly allowed.\nOnly use this if you have allow rules for your essential apps\n(browser, email, etc). A confirmation dialog will appear.")
        btn_block_all.clicked.connect(self._quick_block_all_outbound)
        qa.addWidget(btn_block_all)

        btn_allow_all = QPushButton("Reset to Default")
        btn_allow_all.setToolTip("Restore Windows Firewall to default settings.\nInbound: Block (except allowed rules)\nOutbound: Allow all\n\nThis is the standard Windows behavior.")
        btn_allow_all.clicked.connect(self._quick_reset_default)
        qa.addWidget(btn_allow_all)

        btn_flush = QPushButton("Flush PyWall Rules")
        btn_flush.setToolTip("Remove all firewall rules created by PyWall.\nSystem rules and rules from other programs are not affected.\nUseful for starting fresh.")
        btn_flush.clicked.connect(self._flush_pywall_rules)
        qa.addWidget(btn_flush)

        qa.addStretch()

        # Firewall profile toggles
        prof_lbl = QLabel("Firewall Profiles:"); prof_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        prof_lbl.setStyleSheet(f"color: {S['t2']};")
        prof_lbl.setToolTip("Windows Firewall applies different rules based on your network type.\nKeep all profiles enabled for maximum protection.")
        qa.addWidget(prof_lbl)
        self._prof_checks = {}
        prof_tips = {
            "Domain": "Domain profile: Active when connected to a corporate domain network.\nUsually the most permissive - managed by IT policies.",
            "Private": "Private profile: Active on trusted networks (home, office).\nAllows more connections than Public.",
            "Public": "Public profile: Active on untrusted networks (coffee shops, airports).\nMost restrictive - blocks unsolicited inbound connections.",
        }
        for p in ("Domain", "Private", "Public"):
            cb = QCheckBox(p); cb.setChecked(True)
            cb.setToolTip(prof_tips[p])
            cb.stateChanged.connect(lambda state, pn=p: self._toggle_profile(pn, state))
            self._prof_checks[p] = cb
            qa.addWidget(cb)
        layout.addLayout(qa)

        self._tabs.addTab(page, "Dashboard")

    def _build_connections_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(8, 8, 8, 8)

        # Toolbar
        tb = QHBoxLayout()
        btn_clear = QPushButton("Clear"); btn_clear.clicked.connect(self._clear)
        btn_clear.setToolTip("Clear all connections from the table.\nDoes not affect firewall rules or history.")
        tb.addWidget(btn_clear)
        btn_export = QPushButton("Export Rules"); btn_export.clicked.connect(self._export_rules)
        btn_export.setToolTip("Export all PyWall-created rules to a JSON file.\nUseful for backup or transferring rules to another PC.")
        tb.addWidget(btn_export)
        btn_import = QPushButton("Import Rules"); btn_import.clicked.connect(self._import_rules)
        btn_import.setToolTip("Import previously exported PyWall rules from a JSON file.")
        tb.addWidget(btn_import)
        tb.addSpacing(10)

        # Filters
        src_lbl = QLabel("Source:"); src_lbl.setToolTip("Choose which data source to display")
        tb.addWidget(src_lbl)
        self._f_src = QComboBox(); self._f_src.addItems(["Live + Events", "Live Only", "Events Only"])
        self._f_src.setToolTip("Live: Real-time connections from your system.\nEvents: Blocked connections from Windows Security log.\nLive + Events: Show both (default).")
        self._f_src.currentTextChanged.connect(lambda v: setattr(self, '_filter_src', v))
        tb.addWidget(self._f_src)

        dir_lbl = QLabel("Direction:"); dir_lbl.setToolTip("Filter by traffic direction")
        tb.addWidget(dir_lbl)
        self._f_dir = QComboBox(); self._f_dir.addItems(["All", "Out", "In/Listen"])
        self._f_dir.setToolTip("All: Show all connections.\nOut: Only outgoing connections (your PC to remote).\nIn/Listen: Only incoming connections and listening ports.")
        self._f_dir.currentTextChanged.connect(lambda v: setattr(self, '_filter_dir', v))
        tb.addWidget(self._f_dir)

        proto_lbl = QLabel("Protocol:"); proto_lbl.setToolTip("Filter by network protocol")
        tb.addWidget(proto_lbl)
        self._f_pro = QComboBox(); self._f_pro.addItems(["All", "TCP", "UDP"])
        self._f_pro.setToolTip("TCP: Reliable connections (web, email, file transfer).\nUDP: Fast, connectionless traffic (video, DNS, gaming).")
        self._f_pro.currentTextChanged.connect(lambda v: setattr(self, '_filter_pro', v))
        tb.addWidget(self._f_pro)

        self._f_txt = QLineEdit(); self._f_txt.setPlaceholderText("Search by IP, hostname, process...")
        self._f_txt.setFixedWidth(200)
        self._f_txt.setToolTip("Type to filter connections by IP address, hostname, process name, organization, or country.\nFilters in real time as you type.")
        self._f_txt.textChanged.connect(lambda v: setattr(self, '_filter_txt', v))
        tb.addWidget(self._f_txt)
        tb.addStretch()

        self._auto_blk_chk = QCheckBox("Auto-Block")
        self._auto_blk_chk.setToolTip("When enabled, automatically creates a firewall rule\nto block any connection that triggers a block notification.\nUse with caution - may block legitimate traffic.")
        self._auto_blk_chk.stateChanged.connect(lambda s: setattr(self, '_auto_block', bool(s)))
        tb.addWidget(self._auto_blk_chk)
        self._toast_chk_tb = QCheckBox("Notifications")
        self._toast_chk_tb.setChecked(cfg["toast"])
        self._toast_chk_tb.setToolTip("Show popup notifications when connections are blocked.\nClick actions on the notification to quickly block or allow.")
        self._toast_chk_tb.stateChanged.connect(lambda s: cfg.__setitem__("toast", bool(s)))
        tb.addWidget(self._toast_chk_tb)
        self._grp_chk = QCheckBox("Group")
        self._grp_chk.setToolTip("Group connections by process name for a cleaner view")
        self._grp_chk.setChecked(cfg.get("group_connections", False))
        self._grp_chk.stateChanged.connect(lambda s: (cfg.__setitem__("group_connections", bool(s)), cfg.save(), self._update_table()))
        tb.addWidget(self._grp_chk)

        # Category filter
        self._f_cat = QComboBox(); self._f_cat.addItems(["All Categories"] + sorted(_CATEGORIES.keys()) + ["LAN", "Unknown"])
        self._f_cat.setToolTip("Filter connections by traffic category")
        self._f_cat.currentTextChanged.connect(lambda v: setattr(self, '_filter_cat', v))
        self._filter_cat = "All Categories"
        tb.addWidget(self._f_cat)

        layout.addLayout(tb)

        # Main splitter: table | detail + rules
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Connection table
        self._conn_tbl = QTableWidget()
        cols = ["Time","Src","Dir","Proto","Local Addr","L.Port","Remote Addr","R.Port",
                "Hostname","Process","PID","Owner","State","Country","CC","Category","Rep","Status","Action"]
        self._conn_tbl.setColumnCount(len(cols))
        self._conn_tbl.setHorizontalHeaderLabels(cols)
        self._conn_tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._conn_tbl.verticalHeader().setVisible(False)
        self._conn_tbl.setAlternatingRowColors(True)
        self._conn_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._conn_tbl.setToolTip("All active network connections.\nRight-click any row to block, allow, kill, or create a custom rule.")
        self._conn_tbl.currentCellChanged.connect(self._on_select)
        self._conn_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._conn_tbl.customContextMenuRequested.connect(self._ctx_menu)
        widths = [58,38,35,38,100,45,110,45,140,95,38,80,65,75,35,75,30,80,50]
        for i, w in enumerate(widths): self._conn_tbl.setColumnWidth(i, w)
        splitter.addWidget(self._conn_tbl)

        # Right panel: detail + rules
        right = QWidget()
        rl = QVBoxLayout(right); rl.setContentsMargins(4, 0, 0, 0)

        # Enhanced detail panel with rich info
        detail_hdr = QHBoxLayout()
        detail_lbl = QLabel("Connection Details"); detail_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        detail_lbl.setStyleSheet(f"color: {S['t2']};")
        detail_hdr.addWidget(detail_lbl); detail_hdr.addStretch()
        self._detail_collapse_btn = QPushButton("Collapse")
        self._detail_collapse_btn.setStyleSheet(f"padding: 2px 6px; font-size: 9px; border: 1px solid {S['bd1']}; color: {S['t3']};")
        self._detail_collapse_btn.setCheckable(True)
        self._detail_collapse_btn.clicked.connect(lambda c: (
            self._detail_widget.setVisible(not c),
            self._detail_collapse_btn.setText("Expand" if c else "Collapse")
        ))
        detail_hdr.addWidget(self._detail_collapse_btn)
        rl.addLayout(detail_hdr)

        self._detail_widget = QTextEdit()
        self._detail_widget.setReadOnly(True)
        self._detail_widget.setMaximumHeight(200)
        self._detail_widget.setStyleSheet(
            f"background: {S['bg1']}; padding: 6px; border: 1px solid {S['bd1']}; "
            f"border-radius: 4px; color: {S['t2']}; font-size: 11px; font-family: Consolas;")
        self._detail_widget.setPlainText("Click any connection to view its details here.\nRight-click for actions like Block, Allow, or Kill.")
        self._detail_widget.setToolTip("Detailed info about the selected connection.\nShows process, network, reputation, and geographic data.")
        rl.addWidget(self._detail_widget)
        # Keep backward compat with _detail for _on_select
        self._detail = self._detail_widget
        self._detail.setToolTip("Details about the selected connection.\nShows process info, remote address, hostname, country, and status.")
        rl.addWidget(self._detail)

        # PyWall rules panel
        rules_hdr = QHBoxLayout()
        rh_lbl = QLabel("PyWall Rules"); rh_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        rh_lbl.setStyleSheet(f"color: {S['t2']};")
        rh_lbl.setToolTip("Firewall rules created by PyWall.\nRight-click to delete. Use '+ New' to create a rule manually.")
        rules_hdr.addWidget(rh_lbl); rules_hdr.addStretch()
        btn_new_rule = QPushButton("+ New Rule"); btn_new_rule.clicked.connect(self._open_create_rule)
        btn_new_rule.setStyleSheet(f"background: {S['gn']}; color: white; padding: 3px 8px; font-size: 10px;")
        btn_new_rule.setToolTip("Open the rule creation dialog to manually create\na new Windows Firewall rule with full control over all settings.")
        rules_hdr.addWidget(btn_new_rule)
        btn_ref = QPushButton("Refresh"); btn_ref.clicked.connect(self._refresh_rules_panel)
        btn_ref.setStyleSheet("padding: 3px 8px; font-size: 10px;")
        btn_ref.setToolTip("Reload the PyWall rules list from Windows Firewall")
        rules_hdr.addWidget(btn_ref)
        rl.addLayout(rules_hdr)

        self._rules_tbl = QTableWidget()
        self._rules_tbl.setColumnCount(6)
        self._rules_tbl.setHorizontalHeaderLabels(["Name","Dir","Action","Address","Port","Program"])
        self._rules_tbl.verticalHeader().setVisible(False)
        self._rules_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._rules_tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._rules_tbl.horizontalHeader().setStretchLastSection(True)
        self._rules_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._rules_tbl.customContextMenuRequested.connect(self._rule_ctx)
        self._rules_tbl.setToolTip("Rules created by PyWall.\nRight-click to delete a rule.")
        rl.addWidget(self._rules_tbl)

        splitter.addWidget(right)
        splitter.setSizes([900, 350])
        layout.addWidget(splitter)
        self._tabs.addTab(page, "Connections")

    def _build_rules_tab(self):
        """Embed the full RulesManager as a tab."""
        self._rules_mgr = RulesManager(self, embedded=True)
        self._rules_mgr.rules_changed.connect(self._refresh_rules_panel)
        self._tabs.addTab(self._rules_mgr, "Rules")

    def _build_apps_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(12, 12, 12, 12)

        # Header
        hdr = QHBoxLayout()
        hdr_lbl = QLabel("Application Network Control"); hdr_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        hdr_lbl.setStyleSheet(f"color: {S['bl']};")
        hdr.addWidget(hdr_lbl)
        hdr.addStretch()
        btn_refresh = QPushButton("Refresh"); btn_refresh.clicked.connect(self._refresh_apps)
        btn_refresh.setToolTip("Reload the list of active applications and their network activity")
        hdr.addWidget(btn_refresh)
        btn_block_new = QPushButton("Block All Unknown")
        btn_block_new.setStyleSheet(f"background: {S['rd']}; color: white;")
        btn_block_new.setToolTip("Block all applications that don't have an explicit policy set.\nCreates outbound block rules for each unknown app.\nUse this to lock down your system to only approved apps.")
        btn_block_new.clicked.connect(self._block_all_unknown_apps)
        hdr.addWidget(btn_block_new)
        btn_allow_all = QPushButton("Clear All Policies")
        btn_allow_all.setStyleSheet(f"background: {S['gn']}; color: white;")
        btn_allow_all.setToolTip("Remove all per-application policies.\nApps will return to default behavior (allowed unless blocked by other rules).")
        btn_allow_all.clicked.connect(self._allow_all_apps)
        hdr.addWidget(btn_allow_all)
        layout.addLayout(hdr)

        desc = QLabel("Control which applications can access the network. Set per-app policies using the buttons below.\nPolicies are enforced immediately via Windows Firewall rules and real-time connection monitoring.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color: {S['t3']}; font-size: 11px; padding: 4px 0;")
        layout.addWidget(desc)

        self._app_tbl = QTableWidget()
        self._app_tbl.setColumnCount(8)
        self._app_tbl.setHorizontalHeaderLabels(["Process", "Path", "Connections", "Bandwidth", "First Seen", "Rep", "Policy", "Actions"])
        self._app_tbl.verticalHeader().setVisible(False)
        self._app_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._app_tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._app_tbl.horizontalHeader().setStretchLastSection(True)
        self._app_tbl.setColumnWidth(0, 140); self._app_tbl.setColumnWidth(1, 260)
        self._app_tbl.setColumnWidth(2, 80); self._app_tbl.setColumnWidth(3, 90)
        self._app_tbl.setColumnWidth(4, 130); self._app_tbl.setColumnWidth(5, 50); self._app_tbl.setColumnWidth(6, 80)
        self._app_tbl.setToolTip("List of all applications with active network connections.\nUse the Allow/Block buttons in the Actions column to set policies.\nPolicies: MONITOR (default, just watch) | ALLOW (always permit) | BLOCK (always deny)")
        layout.addWidget(self._app_tbl)
        self._tabs.addTab(page, "Applications")

    def _build_history_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(8, 8, 8, 8)

        # Header
        hdr_lbl = QLabel("Connection History"); hdr_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        hdr_lbl.setStyleSheet(f"color: {S['bl']};")
        layout.addWidget(hdr_lbl)
        desc = QLabel("Search and browse previously recorded network connections. Data is stored locally in an SQLite database.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color: {S['t3']}; font-size: 11px; padding: 0 0 6px 0;")
        layout.addWidget(desc)

        # Search toolbar
        tb = QHBoxLayout()
        self._hist_search = QLineEdit(); self._hist_search.setPlaceholderText("Search by IP, hostname, process...")
        self._hist_search.setFixedWidth(250); self._hist_search.returnPressed.connect(self._search_history)
        self._hist_search.setToolTip("Enter keywords to search across all connection fields.\nPress Enter or click Search to run the query.")
        tb.addWidget(self._hist_search)

        proc_lbl = QLabel("Process:"); proc_lbl.setToolTip("Filter results to a specific process")
        tb.addWidget(proc_lbl)
        self._hist_proc = QComboBox(); self._hist_proc.addItem("All"); self._hist_proc.setFixedWidth(150)
        self._hist_proc.setToolTip("Filter by process name. Click 'Refresh Filters' to populate this list.")
        tb.addWidget(self._hist_proc)

        country_lbl = QLabel("Country:"); country_lbl.setToolTip("Filter results to a specific country")
        tb.addWidget(country_lbl)
        self._hist_country = QComboBox(); self._hist_country.addItem("All"); self._hist_country.setFixedWidth(120)
        self._hist_country.setToolTip("Filter by country. Click 'Refresh Filters' to populate this list.")
        tb.addWidget(self._hist_country)

        time_lbl = QLabel("Time Range:"); time_lbl.setToolTip("Limit results to a specific time window")
        tb.addWidget(time_lbl)
        self._hist_time = QComboBox(); self._hist_time.addItems(["All", "1 hour", "24 hours", "7 days", "30 days"])
        self._hist_time.setToolTip("Show connections from the selected time period.\nAll = no time limit.")
        tb.addWidget(self._hist_time)

        btn_search = QPushButton("Search"); btn_search.setStyleSheet(f"background: {S['bl']}; color: white;")
        btn_search.clicked.connect(self._search_history)
        btn_search.setToolTip("Run the search with current filters")
        tb.addWidget(btn_search)
        btn_rf = QPushButton("Refresh Filters"); btn_rf.clicked.connect(self._refresh_history_filters)
        btn_rf.setToolTip("Reload the Process and Country filter dropdowns\nwith values from the database.")
        tb.addWidget(btn_rf)
        tb.addStretch()
        self._hist_count = QLabel(""); self._hist_count.setStyleSheet(f"color: {S['t3']}; font-size: 10px;")
        tb.addWidget(self._hist_count)
        layout.addLayout(tb)

        # History table
        self._hist_tbl = QTableWidget()
        hcols = ["Time","Src","Dir","Proto","Local Addr","L.Port","Remote Addr","R.Port","Hostname","Process","PID","Owner","Country","CC","Status"]
        self._hist_tbl.setColumnCount(len(hcols))
        self._hist_tbl.setHorizontalHeaderLabels(hcols)
        self._hist_tbl.verticalHeader().setVisible(False)
        self._hist_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._hist_tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._hist_tbl.horizontalHeader().setStretchLastSection(True)
        self._hist_tbl.setToolTip("Past network connections stored in the local database.\nUse the search bar and filters above to find specific connections.")
        layout.addWidget(self._hist_tbl)

        # Pagination
        pag = QHBoxLayout()
        btn_prev = QPushButton("Previous"); btn_prev.clicked.connect(lambda: self._hist_page(-1))
        btn_prev.setToolTip("Go to the previous page of results")
        btn_next = QPushButton("Next"); btn_next.clicked.connect(lambda: self._hist_page(1))
        btn_next.setToolTip("Go to the next page of results")
        self._hist_page_lbl = QLabel("Page 1"); self._hist_page_lbl.setStyleSheet(f"color: {S['t2']};")
        pag.addWidget(btn_prev); pag.addWidget(self._hist_page_lbl); pag.addWidget(btn_next)
        pag.addStretch()
        self._hist_total = QLabel(f"Total records: {conn_db.count()}")
        self._hist_total.setStyleSheet(f"color: {S['t3']}; font-size: 10px;")
        pag.addWidget(self._hist_total)
        layout.addLayout(pag)
        self._hist_offset = 0
        self._tabs.addTab(page, "History")

    def _build_security_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(12, 12, 12, 12)

        # Header
        hdr_lbl = QLabel("Threat Detection & Security"); hdr_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        hdr_lbl.setStyleSheet(f"color: {S['bl']};")
        layout.addWidget(hdr_lbl)
        desc = QLabel("PyWall monitors for suspicious activity like port scans and brute force attempts. Configure detection thresholds in Settings.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color: {S['t3']}; font-size: 11px; padding: 0 0 6px 0;")
        layout.addWidget(desc)

        # Threat stats
        stats_row = QHBoxLayout()
        self._sec_total = StatCard("Total Threats", "0", S['am'])
        self._sec_total.setToolTip("Total number of security threats detected this session.\nIncludes port scans, brute force attempts, and blocklist hits.")
        self._sec_high = StatCard("High Severity", "0", S['rd'])
        self._sec_high.setToolTip("Threats classified as high severity.\nThese typically indicate active attacks or persistent probing.")
        self._sec_blocked = StatCard("Auto-Blocked", "0", S['gn'])
        self._sec_blocked.setToolTip("Threats that were automatically blocked by creating firewall rules.\nEnable 'Auto-block detected threats' in Settings to use this feature.")
        stats_row.addWidget(self._sec_total); stats_row.addWidget(self._sec_high); stats_row.addWidget(self._sec_blocked)
        stats_row.addStretch()
        layout.addLayout(stats_row)

        # Threat events table
        te_lbl = QLabel("Threat Events"); te_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        te_lbl.setStyleSheet(f"color: {S['t2']};")
        layout.addWidget(te_lbl)
        self._threat_tbl = QTableWidget()
        self._threat_tbl.setColumnCount(6)
        self._threat_tbl.setHorizontalHeaderLabels(["Time", "Type", "Severity", "Source IP", "Details", "Action"])
        self._threat_tbl.verticalHeader().setVisible(False)
        self._threat_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._threat_tbl.horizontalHeader().setStretchLastSection(True)
        self._threat_tbl.setColumnWidth(0, 130); self._threat_tbl.setColumnWidth(1, 100)
        self._threat_tbl.setColumnWidth(2, 80); self._threat_tbl.setColumnWidth(3, 130)
        self._threat_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._threat_tbl.customContextMenuRequested.connect(self._threat_ctx)
        self._threat_tbl.setToolTip("Detected security events.\nRight-click a threat to block the source IP or view details.")
        layout.addWidget(self._threat_tbl)

        # Blocklist management
        bl_row = QHBoxLayout()
        bl_lbl = QLabel("Blocklist Hits:"); bl_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        bl_lbl.setStyleSheet(f"color: {S['t2']};")
        bl_lbl.setToolTip("Connections that matched an entry in your enabled blocklists.\nConfigure blocklists in Settings > Blocklists.")
        bl_row.addWidget(bl_lbl)
        self._bl_hits_list = QListWidget()
        self._bl_hits_list.setMaximumHeight(150)
        self._bl_hits_list.setStyleSheet(f"QListWidget {{ background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bd1']}; border-radius: 4px; }}")
        self._bl_hits_list.setToolTip("IPs and domains that matched your blocklists.\nEnable blocklists in Settings for telemetry, ads, or custom lists.")
        bl_row.addWidget(self._bl_hits_list)
        layout.addLayout(bl_row)

        # Controls
        ctrl = QHBoxLayout()
        btn_clear_threats = QPushButton("Clear Threat Log"); btn_clear_threats.clicked.connect(lambda: (threats.clear(), self._update_security()))
        btn_clear_threats.setToolTip("Clear all threats from the list.\nDoes not remove any block rules that were already created.")
        ctrl.addWidget(btn_clear_threats)
        btn_export_threats = QPushButton("Export Threats"); btn_export_threats.clicked.connect(self._export_threats)
        btn_export_threats.setToolTip("Export the threat log to a file for analysis or reporting.")
        ctrl.addWidget(btn_export_threats)
        ctrl.addStretch()
        layout.addLayout(ctrl)

        self._tabs.addTab(page, "Security")

    # ================================================================
    #  NETWORK MAP TAB (Radial Visualization)
    # ================================================================
    def _build_netmap_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(8, 8, 8, 8)
        hdr = QHBoxLayout()
        h_lbl = QLabel("Network Map"); h_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        h_lbl.setStyleSheet(f"color: {S['bl']};")
        hdr.addWidget(h_lbl)
        h_desc = QLabel("Real-time radial visualization of active connections")
        h_desc.setStyleSheet(f"color: {S['t3']}; font-size: 11px; padding-left: 10px;")
        hdr.addWidget(h_desc); hdr.addStretch()
        # View mode
        self._netmap_mode = QComboBox()
        self._netmap_mode.addItems(["By Country", "By Category", "By Process"])
        self._netmap_mode.setToolTip("Group connections by: country of origin, traffic category, or process name")
        self._netmap_mode.currentTextChanged.connect(lambda: self._netmap_widget.update())
        hdr.addWidget(self._netmap_mode)
        layout.addLayout(hdr)

        # Stats cards
        cards = QHBoxLayout()
        self._nm_active = StatCard("Active", "0", S['bl'])
        self._nm_countries = StatCard("Countries", "0", S['gn'])
        self._nm_categories = StatCard("Categories", "0", S['cy'])
        self._nm_blocked = StatCard("Blocked", "0", S['rd'])
        for c in [self._nm_active, self._nm_countries, self._nm_categories, self._nm_blocked]:
            cards.addWidget(c)
        cards.addStretch()
        layout.addLayout(cards)

        # Radial map widget
        self._netmap_widget = NetworkMapWidget(self)
        layout.addWidget(self._netmap_widget, 1)

        # Legend
        leg = QHBoxLayout()
        for cat, color in [("Web", S['bl']), ("Streaming", S['cy']), ("Gaming", S['gn']),
                           ("Social", S['am']), ("System", S['t2']), ("Blocked", S['rd']), ("Other", S['t3'])]:
            dot = QLabel(f"  {cat}"); dot.setStyleSheet(f"color: {color}; font-size: 10px;")
            leg.addWidget(dot)
        leg.addStretch()
        layout.addLayout(leg)
        self._tabs.addTab(page, "Network Map")

    def _update_netmap(self):
        conns = list(self._conn_data)
        self._nm_active.setValue(str(len(conns)))
        countries = set(c.country for c in conns if c.country and c.country not in ("-", "", "Local"))
        self._nm_countries.setValue(str(len(countries)))
        cats = set(categorizer.categorize(c.host, c.ra, c.rp, c.proc) for c in conns)
        self._nm_categories.setValue(str(len(cats)))
        blocked = sum(1 for c in conns if c.stat and c.stat not in ("-", ""))
        self._nm_blocked.setValue(str(blocked))
        self._netmap_widget._conns = conns
        self._netmap_widget._mode = self._netmap_mode.currentText()
        self._netmap_widget.update()

    # ================================================================
    #  TIMELINE TAB (Connection Sessions)
    # ================================================================
    def _build_timeline_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(8, 8, 8, 8)
        hdr = QHBoxLayout()
        h_lbl = QLabel("Connection Timeline"); h_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        h_lbl.setStyleSheet(f"color: {S['bl']};")
        hdr.addWidget(h_lbl)
        h_desc = QLabel("Session history with start/end times, duration, and activity tracking")
        h_desc.setStyleSheet(f"color: {S['t3']}; font-size: 11px; padding-left: 10px;")
        hdr.addWidget(h_desc); hdr.addStretch()
        self._tl_filter = QLineEdit(); self._tl_filter.setPlaceholderText("Filter sessions...")
        self._tl_filter.setFixedWidth(200)
        self._tl_filter.setToolTip("Filter timeline by process name, IP, host, or category")
        self._tl_filter.textChanged.connect(lambda: self._update_timeline())
        hdr.addWidget(self._tl_filter)
        layout.addLayout(hdr)

        # Stats
        tl_cards = QHBoxLayout()
        self._tl_active = StatCard("Active Sessions", "0", S['gn'])
        self._tl_completed = StatCard("Completed", "0", S['bl'])
        self._tl_avg_dur = StatCard("Avg Duration", "0s", S['cy'])
        for c in [self._tl_active, self._tl_completed, self._tl_avg_dur]:
            tl_cards.addWidget(c)
        tl_cards.addStretch()
        layout.addLayout(tl_cards)

        # Active sessions
        a_lbl = QLabel("Active Sessions"); a_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        a_lbl.setStyleSheet(f"color: {S['t2']};")
        layout.addWidget(a_lbl)
        self._tl_active_tbl = QTableWidget()
        self._tl_active_tbl.setColumnCount(5)
        self._tl_active_tbl.setHorizontalHeaderLabels(["Process", "Remote", "Host", "Started", "Duration"])
        self._tl_active_tbl.verticalHeader().setVisible(False)
        self._tl_active_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tl_active_tbl.horizontalHeader().setStretchLastSection(True)
        self._tl_active_tbl.setMaximumHeight(200)
        layout.addWidget(self._tl_active_tbl)

        # Completed sessions
        c_lbl = QLabel("Completed Sessions"); c_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        c_lbl.setStyleSheet(f"color: {S['t2']};")
        layout.addWidget(c_lbl)
        self._tl_comp_tbl = QTableWidget()
        self._tl_comp_tbl.setColumnCount(8)
        self._tl_comp_tbl.setHorizontalHeaderLabels(["Process", "Remote", "Host", "Country", "Category", "Start", "End", "Duration"])
        self._tl_comp_tbl.verticalHeader().setVisible(False)
        self._tl_comp_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tl_comp_tbl.horizontalHeader().setStretchLastSection(True)
        self._tl_comp_tbl.setColumnWidth(0, 120); self._tl_comp_tbl.setColumnWidth(1, 130)
        self._tl_comp_tbl.setColumnWidth(2, 150); self._tl_comp_tbl.setColumnWidth(3, 60)
        self._tl_comp_tbl.setColumnWidth(4, 90); self._tl_comp_tbl.setColumnWidth(5, 70)
        self._tl_comp_tbl.setColumnWidth(6, 70)
        layout.addWidget(self._tl_comp_tbl)
        self._tabs.addTab(page, "Timeline")

    def _update_timeline(self):
        filt = self._tl_filter.text().lower() if hasattr(self, '_tl_filter') else ""
        # Active
        active = sessions.get_active()
        if filt:
            active = [a for a in active if filt in a.get("proc","").lower() or filt in a.get("host","").lower()
                      or filt in a.get("ra","").lower()]
        self._tl_active.setValue(str(len(active)))
        self._tl_active_tbl.setRowCount(len(active))
        for i, s in enumerate(active):
            dur = s.get("duration_sec", 0)
            dur_str = f"{int(dur//60)}m {int(dur%60)}s" if dur >= 60 else f"{dur:.0f}s"
            for j, v in enumerate([s.get("proc","?"), f"{s.get('ra','')}:{s.get('rp','')}",
                                   s.get("host","-"), s.get("start",""), dur_str]):
                item = QTableWidgetItem(str(v))
                item.setForeground(QColor(S['gn'] if j == 4 else S['t1']))
                self._tl_active_tbl.setItem(i, j, item)

        # Completed
        completed = sessions.get_timeline(200)
        if filt:
            completed = [c for c in completed if filt in c.get("proc","").lower() or filt in c.get("host","").lower()
                         or filt in c.get("ra","").lower() or filt in c.get("category","").lower()]
        self._tl_completed.setValue(str(len(completed)))
        if completed:
            avg_dur = sum(c.get("duration_sec", 0) for c in completed) / len(completed)
            self._tl_avg_dur.setValue(f"{avg_dur:.0f}s")
        self._tl_comp_tbl.setRowCount(min(len(completed), 500))
        for i, s in enumerate(completed[:500]):
            dur = s.get("duration_sec", 0)
            dur_str = f"{int(dur//60)}m {int(dur%60)}s" if dur >= 60 else f"{dur:.0f}s"
            for j, v in enumerate([s.get("proc","?"), f"{s.get('ra','')}:{s.get('rp','')}",
                                   s.get("host","-"), s.get("country","-"), s.get("category","?"),
                                   s.get("start",""), s.get("end",""), dur_str]):
                item = QTableWidgetItem(str(v))
                if j == 4:
                    cat_colors = {"Streaming": S['cy'], "Gaming": S['gn'], "Social Media": S['am'],
                                  "Ads/Tracking": S['rd'], "System": S['t2']}
                    item.setForeground(QColor(cat_colors.get(v, S['t1'])))
                self._tl_comp_tbl.setItem(i, j, item)

    # ================================================================
    #  SCHEDULE TAB
    # ================================================================
    def _build_schedule_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(12, 12, 12, 12)
        hdr = QHBoxLayout()
        h_lbl = QLabel("Rule Scheduler"); h_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        h_lbl.setStyleSheet(f"color: {S['bl']};")
        hdr.addWidget(h_lbl)
        h_desc = QLabel("Schedule firewall rules to enable/disable at specific times and days")
        h_desc.setStyleSheet(f"color: {S['t3']}; font-size: 11px; padding-left: 10px;")
        hdr.addWidget(h_desc); hdr.addStretch()
        btn_add = QPushButton("+ Add Schedule"); btn_add.setStyleSheet(f"background: {S['gn']}; color: white;")
        btn_add.setToolTip("Create a new schedule for a firewall rule")
        btn_add.clicked.connect(self._add_schedule)
        hdr.addWidget(btn_add)
        btn_del = QPushButton("Remove Selected"); btn_del.setStyleSheet(f"background: {S['rd']}; color: white;")
        btn_del.clicked.connect(self._remove_schedule)
        hdr.addWidget(btn_del)
        layout.addLayout(hdr)

        self._sched_tbl = QTableWidget()
        self._sched_tbl.setColumnCount(6)
        self._sched_tbl.setHorizontalHeaderLabels(["Rule Name", "Days", "Start", "End", "Action", "Active"])
        self._sched_tbl.verticalHeader().setVisible(False)
        self._sched_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._sched_tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._sched_tbl.horizontalHeader().setStretchLastSection(True)
        self._sched_tbl.setColumnWidth(0, 250); self._sched_tbl.setColumnWidth(1, 200)
        self._sched_tbl.setColumnWidth(2, 80); self._sched_tbl.setColumnWidth(3, 80)
        self._sched_tbl.setColumnWidth(4, 80)
        layout.addWidget(self._sched_tbl)

        # Templates section
        tmpl_hdr = QHBoxLayout()
        t_lbl = QLabel("Rule Templates"); t_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        t_lbl.setStyleSheet(f"color: {S['bl']};")
        tmpl_hdr.addWidget(t_lbl)
        t_desc = QLabel("Pre-built rule sets for common scenarios")
        t_desc.setStyleSheet(f"color: {S['t3']}; font-size: 11px; padding-left: 10px;")
        tmpl_hdr.addWidget(t_desc); tmpl_hdr.addStretch()
        layout.addLayout(tmpl_hdr)

        tmpl_grid = QHBoxLayout(); tmpl_grid.setSpacing(10)
        for name, tmpl in RULE_TEMPLATES.items():
            card = QFrame()
            card.setStyleSheet(f"QFrame {{ background: {S['bg1']}; border: 1px solid {S['bd1']}; border-radius: 8px; padding: 12px; }}")
            card.setFixedSize(200, 130)
            cl = QVBoxLayout(card); cl.setContentsMargins(8, 8, 8, 8)
            n_lbl = QLabel(name); n_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            n_lbl.setStyleSheet(f"color: {S['bl']}; border: none;")
            cl.addWidget(n_lbl)
            d_lbl = QLabel(tmpl["desc"]); d_lbl.setWordWrap(True)
            d_lbl.setStyleSheet(f"color: {S['t3']}; font-size: 9px; border: none;")
            cl.addWidget(d_lbl)
            r_count = QLabel(f"{len(tmpl['rules'])} rules")
            r_count.setStyleSheet(f"color: {S['t2']}; font-size: 9px; border: none;")
            cl.addWidget(r_count)
            btn = QPushButton("Apply"); btn.setStyleSheet(f"background: {S['bl']}; color: white; border-radius: 4px; padding: 4px;")
            btn.clicked.connect(lambda _, n=name: self._apply_template(n))
            cl.addWidget(btn)
            tmpl_grid.addWidget(card)
        tmpl_grid.addStretch()
        layout.addLayout(tmpl_grid)

        # Export/Import section
        ei_hdr = QHBoxLayout()
        ei_lbl = QLabel("Configuration"); ei_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        ei_lbl.setStyleSheet(f"color: {S['bl']};")
        ei_hdr.addWidget(ei_lbl); ei_hdr.addStretch()
        btn_export = QPushButton("Export Full Config")
        btn_export.setToolTip("Export all PyWall settings, rules, schedules, profiles, and DNS blocks to a JSON file")
        btn_export.setStyleSheet(f"background: {S['cy']}; color: white;")
        btn_export.clicked.connect(self._export_full_config)
        ei_hdr.addWidget(btn_export)
        btn_import = QPushButton("Import Config")
        btn_import.setToolTip("Import a previously exported PyWall configuration file")
        btn_import.setStyleSheet(f"background: {S['am']}; color: white;")
        btn_import.clicked.connect(self._import_full_config)
        ei_hdr.addWidget(btn_import)
        btn_health = QPushButton("Health Check")
        btn_health.setToolTip("Scan all firewall rules for conflicts, redundancies, and potential issues")
        btn_health.setStyleSheet(f"background: {S['gn']}; color: white;")
        btn_health.clicked.connect(self._run_health_check)
        ei_hdr.addWidget(btn_health)
        layout.addLayout(ei_hdr)

        # Network profiles
        np_hdr = QHBoxLayout()
        np_lbl = QLabel("Network Profiles"); np_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        np_lbl.setStyleSheet(f"color: {S['bl']};")
        np_hdr.addWidget(np_lbl)
        self._np_current = QLabel("Current: detecting...")
        self._np_current.setStyleSheet(f"color: {S['t2']}; font-size: 11px; padding-left: 10px;")
        np_hdr.addWidget(self._np_current); np_hdr.addStretch()
        btn_save_prof = QPushButton("Save Current as Profile")
        btn_save_prof.setToolTip("Save the current firewall mode and app policies as a profile for this network")
        btn_save_prof.clicked.connect(self._save_network_profile)
        np_hdr.addWidget(btn_save_prof)
        self._np_auto = QCheckBox("Auto-switch")
        self._np_auto.setChecked(cfg.get("auto_switch_profile", False))
        self._np_auto.setToolTip("Automatically apply saved profiles when switching networks")
        self._np_auto.stateChanged.connect(lambda s: (cfg.__setitem__("auto_switch_profile", bool(s)), cfg.save()))
        np_hdr.addWidget(self._np_auto)
        layout.addLayout(np_hdr)

        self._np_tbl = QTableWidget()
        self._np_tbl.setColumnCount(3)
        self._np_tbl.setHorizontalHeaderLabels(["Network", "Mode", "Actions"])
        self._np_tbl.verticalHeader().setVisible(False)
        self._np_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._np_tbl.horizontalHeader().setStretchLastSection(True)
        self._np_tbl.setMaximumHeight(150)
        layout.addWidget(self._np_tbl)
        layout.addStretch()
        self._tabs.addTab(page, "Schedule")

    def _update_schedule_tab(self):
        # Schedules
        scheds = scheduler.get_schedules()
        self._sched_tbl.setRowCount(len(scheds))
        day_names = {0:"Mon", 1:"Tue", 2:"Wed", 3:"Thu", 4:"Fri", 5:"Sat", 6:"Sun"}
        for i, s in enumerate(scheds):
            days_str = ", ".join(day_names.get(d, "?") for d in s.get("days", []))
            vals = [s.get("rule_name",""), days_str, s.get("start",""), s.get("end",""),
                    s.get("action","enable"), "Yes" if s.get("active") else "No"]
            for j, v in enumerate(vals):
                item = QTableWidgetItem(str(v))
                if j == 5: item.setForeground(QColor(S['gn'] if v == "Yes" else S['rd']))
                self._sched_tbl.setItem(i, j, item)
        # Network profiles
        net = net_profiles.get_current_network()
        self._np_current.setText(f"Current: {net}")
        profiles = net_profiles.get_profiles()
        self._np_tbl.setRowCount(len(profiles))
        for i, (name, prof) in enumerate(profiles.items()):
            self._np_tbl.setItem(i, 0, QTableWidgetItem(name))
            self._np_tbl.setItem(i, 1, QTableWidgetItem(prof.get("fw_mode", "monitor")))
            btn = QPushButton("Delete")
            btn.setStyleSheet(f"background: {S['rd']}; color: white; padding: 2px 6px;")
            btn.clicked.connect(lambda _, n=name: self._delete_network_profile(n))
            self._np_tbl.setCellWidget(i, 2, btn)

    def _add_schedule(self):
        dlg = ScheduleDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            scheduler.add(data["rule_name"], data["days"], data["start"], data["end"], data["action"])
            self._update_schedule_tab()
            self._sbar.setText(f"Schedule added for '{data['rule_name']}'")

    def _remove_schedule(self):
        row = self._sched_tbl.currentRow()
        if row >= 0:
            scheduler.remove(row)
            self._update_schedule_tab()
            self._sbar.setText("Schedule removed")

    def _apply_template(self, name):
        tmpl = RULE_TEMPLATES.get(name)
        if not tmpl: return
        reply = QMessageBox.question(self, "Apply Template",
            f"Apply '{name}' template?\n\n{tmpl['desc']}\n\nThis will create {len(tmpl['rules'])} firewall rules"
            + (f" and change settings." if tmpl.get("settings") else "."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes: return
        created = 0
        for r in tmpl["rules"]:
            ok, _ = fw.create_rule(
                name=f"{PFX}{r['name']}", direction=r.get("direction", "Outbound"),
                action=r.get("action", "Block"), remote_addr=r.get("remote_addr", ""),
                remote_port=r.get("remote_port", ""), protocol=r.get("protocol", ""),
                program=r.get("program", ""), desc=r.get("desc", ""))
            if ok: created += 1
        if tmpl.get("settings"):
            for k, v in tmpl["settings"].items():
                cfg[k] = v
            cfg.save()
        self._refresh_rules_panel()
        self._sbar.setText(f"Template '{name}' applied: {created} rules created")

    def _export_full_config(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Config", str(CDIR / "pywall_config.json"),
                                               "JSON (*.json)")
        if path:
            try:
                exporter.export_all(path)
                self._sbar.setText(f"Configuration exported to {path}")
            except Exception as e:
                self._sbar.setText(f"Export failed: {e}")

    def _import_full_config(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Config", "", "JSON (*.json)")
        if not path: return
        try:
            with open(path) as f:
                data = json.load(f)
            # Build diff preview
            diff_lines = self._build_import_diff(data)
            if not diff_lines:
                QMessageBox.information(self, "Import Config", "No changes detected in the import file.")
                return
            # Show diff dialog
            dlg = QDialog(self); dlg.setWindowTitle("Config Import Preview"); dlg.setMinimumSize(700, 500)
            layout = QVBoxLayout(dlg)
            lbl = QLabel("Review changes before importing:"); lbl.setStyleSheet(f"color: {S['t1']}; font-weight: bold;")
            layout.addWidget(lbl)
            txt = QTextEdit(); txt.setReadOnly(True); txt.setPlainText("\n".join(diff_lines))
            txt.setStyleSheet(f"background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bd1']}; font-family: Consolas; font-size: 11px;")
            layout.addWidget(txt)
            btn_row = QHBoxLayout()
            btn_cancel = QPushButton("Cancel"); btn_cancel.clicked.connect(dlg.reject)
            btn_apply = QPushButton("Apply Changes"); btn_apply.setStyleSheet(f"background: {S['gn']}; color: white; font-weight: bold;")
            btn_apply.clicked.connect(dlg.accept)
            btn_row.addStretch(); btn_row.addWidget(btn_cancel); btn_row.addWidget(btn_apply)
            layout.addLayout(btn_row)
            if dlg.exec() != QDialog.DialogCode.Accepted: return
            # Apply
            results = exporter.import_all(path)
            msg = (f"Imported: {results['settings']} settings, {results['rules_created']} rules created, "
                   f"{results['rules_skipped']} skipped")
            if results['errors']: msg += f", {len(results['errors'])} errors"
            self._sbar.setText(msg)
            self._refresh_rules_panel()
        except Exception as e:
            self._sbar.setText(f"Import failed: {e}")

    def _build_import_diff(self, data):
        """Build a human-readable diff of what the import will change."""
        lines = []
        # Settings changes
        if "settings" in data:
            setting_changes = []
            for k, v in data["settings"].items():
                if k in ("app_profiles", "net_profiles", "scheduled_rules", "quotas"):
                    continue
                current = cfg.get(k)
                if current != v:
                    setting_changes.append(f"  {k}: {current} -> {v}")
            if setting_changes:
                lines.append(f"=== SETTINGS ({len(setting_changes)} changes) ===")
                lines.extend(setting_changes)
                lines.append("")
            # App profile changes
            if "app_profiles" in data["settings"]:
                new_profiles = data["settings"]["app_profiles"]
                existing = cfg.get("app_profiles", {})
                added = [k for k in new_profiles if k not in existing]
                changed = [k for k in new_profiles if k in existing and existing[k] != new_profiles[k]]
                if added or changed:
                    lines.append(f"=== APP POLICIES ({len(added)} new, {len(changed)} changed) ===")
                    for k in added: lines.append(f"  + {k}: {new_profiles[k]}")
                    for k in changed: lines.append(f"  ~ {k}: {existing[k]} -> {new_profiles[k]}")
                    lines.append("")
        # Firewall rules
        rules = data.get("pywall_rules", [])
        if rules:
            existing_names = set()
            try: existing_names = {r.name for r in fw.get_pywall_rules()}
            except: pass
            new_rules = [r for r in rules if r.get("name") not in existing_names]
            skip_rules = [r for r in rules if r.get("name") in existing_names]
            lines.append(f"=== FIREWALL RULES ({len(new_rules)} new, {len(skip_rules)} existing/skipped) ===")
            for r in new_rules:
                lines.append(f"  + {r.get('name')}: {r.get('action','?')} {r.get('direction','?')} "
                             f"addr={r.get('remote_addr','')} port={r.get('remote_port','')} "
                             f"prog={Path(r.get('program','')).name if r.get('program') else ''}")
            if skip_rules:
                lines.append(f"  (skipping {len(skip_rules)} existing rules)")
            lines.append("")
        # Scheduled rules
        if "scheduled_rules" in data:
            count = len(data["scheduled_rules"])
            lines.append(f"=== SCHEDULED RULES ({count} entries, will REPLACE current) ===")
            for sr in data["scheduled_rules"][:5]:
                lines.append(f"  {sr.get('rule_name', '?')} - {'enabled' if sr.get('enabled') else 'disabled'}")
            if count > 5: lines.append(f"  ... and {count - 5} more")
            lines.append("")
        # Network profiles
        if "net_profiles" in data:
            count = len(data["net_profiles"])
            lines.append(f"=== NETWORK PROFILES ({count} profiles, will REPLACE current) ===")
            for name in list(data["net_profiles"].keys())[:5]:
                lines.append(f"  {name}")
            lines.append("")
        # DNS blocks
        if "dns_blocked" in data:
            count = len(data["dns_blocked"])
            lines.append(f"=== DNS BLOCKS ({count} domains will be added) ===")
            for d in data["dns_blocked"][:5]:
                lines.append(f"  {d}")
            if count > 5: lines.append(f"  ... and {count - 5} more")
            lines.append("")
        # Quotas
        if "quotas" in data:
            count = len(data["quotas"])
            lines.append(f"=== BANDWIDTH QUOTAS ({count} entries, will REPLACE current) ===")
            for proc, q in list(data["quotas"].items())[:5]:
                lines.append(f"  {proc}: daily={q.get('daily_mb',0)}MB weekly={q.get('weekly_mb',0)}MB")
            lines.append("")
        return lines

    def _save_network_profile(self):
        net = net_profiles.get_current_network()
        name, ok = QInputDialog.getText(self, "Save Profile", "Profile name:", text=net)
        if ok and name:
            net_profiles.save_current_as(name)
            self._update_schedule_tab()
            self._sbar.setText(f"Network profile '{name}' saved")

    def _delete_network_profile(self, name):
        net_profiles.remove_profile(name)
        self._update_schedule_tab()
        self._sbar.setText(f"Network profile '{name}' deleted")

    def _run_health_check(self):
        """Scan rules for conflicts and show results."""
        self._sbar.setText("Running rule health check...")
        def _do():
            try:
                issues = conflict_detector.analyze()
                QTimer.singleShot(0, lambda: self._show_health_results(issues))
            except Exception as e:
                QTimer.singleShot(0, lambda: self._sbar.setText(f"Health check failed: {e}"))
        self._pool.submit(_do)

    def _show_health_results(self, issues):
        if not issues:
            QMessageBox.information(self, "Health Check", "No issues found! Your firewall rules look clean.")
            self._sbar.setText("Health check passed - no issues found")
            return
        sev_icons = {"high": "!!!", "medium": "!!", "low": "!"}
        sev_colors = {"high": "RED", "medium": "AMBER", "low": "GRAY"}
        lines = [f"Found {len(issues)} issue(s):\n"]
        for i, issue in enumerate(issues, 1):
            sev = issue['severity'].upper()
            lines.append(f"{i}. [{sev}] {issue['desc']}")
            lines.append(f"   Rules: {', '.join(issue.get('rules', []))}")
            lines.append(f"   Suggestion: {issue.get('suggestion', '')}\n")
        msg = "\n".join(lines)
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Rule Health Check - {len(issues)} Issues")
        dlg.setMinimumSize(600, 400)
        layout = QVBoxLayout(dlg)
        txt = QTextEdit(); txt.setReadOnly(True); txt.setPlainText(msg)
        txt.setStyleSheet(f"background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bd1']}; font-family: Consolas; font-size: 11px;")
        layout.addWidget(txt)
        btn_close = QPushButton("Close"); btn_close.clicked.connect(dlg.accept)
        layout.addWidget(btn_close)
        dlg.exec()
        high_count = sum(1 for i in issues if i['severity'] == 'high')
        self._sbar.setText(f"Health check: {len(issues)} issues ({high_count} high severity)")

    # ================================================================
    #  PLUGINS TAB
    # ================================================================
    def _build_plugins_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(12, 12, 12, 12)
        hdr = QHBoxLayout()
        h_lbl = QLabel("Plugin Manager"); h_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        h_lbl.setStyleSheet(f"color: {S['bl']};")
        hdr.addWidget(h_lbl)
        h_desc = QLabel("Extend PyWall with custom Python scripts")
        h_desc.setStyleSheet(f"color: {S['t3']}; font-size: 11px; padding-left: 10px;")
        hdr.addWidget(h_desc); hdr.addStretch()
        btn_reload = QPushButton("Reload Plugins")
        btn_reload.setToolTip("Rescan the plugins folder and reload all plugins")
        btn_reload.clicked.connect(self._reload_plugins)
        hdr.addWidget(btn_reload)
        btn_open = QPushButton("Open Folder")
        btn_open.setToolTip(f"Open the plugins folder: {PLUGDIR}")
        btn_open.clicked.connect(lambda: subprocess.Popen(["explorer", str(PLUGDIR)]))
        hdr.addWidget(btn_open)
        btn_new = QPushButton("+ New Plugin")
        btn_new.setStyleSheet(f"background: {S['gn']}; color: white;")
        btn_new.clicked.connect(self._create_sample_plugin)
        hdr.addWidget(btn_new)
        btn_examples = QPushButton("Install Examples")
        btn_examples.setToolTip("Install 4 example plugins: webhook notifier, CSV logger, IP reputation checker, connection stats")
        btn_examples.setStyleSheet(f"background: {S['bl']}; color: white;")
        btn_examples.clicked.connect(self._install_example_plugins)
        hdr.addWidget(btn_examples)
        layout.addLayout(hdr)

        # Plugin enabled toggle
        self._plug_enabled = QCheckBox("Plugins enabled")
        self._plug_enabled.setChecked(cfg.get("plugins_enabled", True))
        self._plug_enabled.stateChanged.connect(lambda s: (cfg.__setitem__("plugins_enabled", bool(s)), cfg.save()))
        layout.addWidget(self._plug_enabled)

        # Plugins table
        self._plug_tbl = QTableWidget()
        self._plug_tbl.setColumnCount(3)
        self._plug_tbl.setHorizontalHeaderLabels(["Plugin Name", "Hooks", "File"])
        self._plug_tbl.verticalHeader().setVisible(False)
        self._plug_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._plug_tbl.horizontalHeader().setStretchLastSection(True)
        self._plug_tbl.setColumnWidth(0, 200); self._plug_tbl.setColumnWidth(1, 200)
        layout.addWidget(self._plug_tbl)

        # Event hooks documentation
        doc = QLabel("Plugin API: Place .py files in the plugins folder. Available hooks:\n"
                     "  on_connection(ci) - Called for every new connection\n"
                     "  on_block(ci) - Called when a connection is blocked\n"
                     "  on_threat(event) - Called when a security threat is detected\n"
                     "  on_start() - Called when monitoring starts\n"
                     "  on_stop() - Called when monitoring stops")
        doc.setWordWrap(True)
        doc.setStyleSheet(f"background: {S['bg1']}; color: {S['t2']}; padding: 12px; border: 1px solid {S['bd1']}; "
                          f"border-radius: 6px; font-family: 'Consolas'; font-size: 11px;")
        layout.addWidget(doc)

        # Anomaly alerts section
        a_hdr = QHBoxLayout()
        a_lbl = QLabel("Anomaly Alerts"); a_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        a_lbl.setStyleSheet(f"color: {S['bl']};")
        a_hdr.addWidget(a_lbl)
        self._anom_enabled = QCheckBox("Anomaly detection enabled")
        self._anom_enabled.setChecked(cfg.get("anomaly_enabled", True))
        self._anom_enabled.stateChanged.connect(lambda s: (cfg.__setitem__("anomaly_enabled", bool(s)), cfg.save()))
        a_hdr.addWidget(self._anom_enabled); a_hdr.addStretch()
        layout.addLayout(a_hdr)

        self._anom_tbl = QTableWidget()
        self._anom_tbl.setColumnCount(3)
        self._anom_tbl.setHorizontalHeaderLabels(["Time", "Process", "Anomaly"])
        self._anom_tbl.verticalHeader().setVisible(False)
        self._anom_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._anom_tbl.horizontalHeader().setStretchLastSection(True)
        self._anom_tbl.setMaximumHeight(200)
        layout.addWidget(self._anom_tbl)

        # DNS blocker section
        dns_hdr = QHBoxLayout()
        dns_lbl = QLabel("DNS-Level Blocking"); dns_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        dns_lbl.setStyleSheet(f"color: {S['bl']};")
        dns_hdr.addWidget(dns_lbl); dns_hdr.addStretch()
        self._dns_add = QLineEdit(); self._dns_add.setPlaceholderText("domain.com")
        self._dns_add.setFixedWidth(200)
        self._dns_add.setToolTip("Enter a domain to block at the DNS level via the Windows hosts file")
        dns_hdr.addWidget(self._dns_add)
        btn_dns_add = QPushButton("Block Domain"); btn_dns_add.setStyleSheet(f"background: {S['rd']}; color: white;")
        btn_dns_add.clicked.connect(self._add_dns_block)
        dns_hdr.addWidget(btn_dns_add)
        btn_dns_rem = QPushButton("Unblock Selected")
        btn_dns_rem.clicked.connect(self._remove_dns_block)
        dns_hdr.addWidget(btn_dns_rem)
        layout.addLayout(dns_hdr)

        self._dns_list = QListWidget()
        self._dns_list.setMaximumHeight(150)
        self._dns_list.setStyleSheet(f"QListWidget {{ background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bd1']}; border-radius: 4px; }}")
        layout.addWidget(self._dns_list)

        # Bandwidth quotas section
        q_hdr = QHBoxLayout()
        q_lbl = QLabel("Bandwidth Quotas"); q_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        q_lbl.setStyleSheet(f"color: {S['bl']};")
        q_hdr.addWidget(q_lbl)
        self._quota_enabled = QCheckBox("Quotas enabled")
        self._quota_enabled.setChecked(cfg.get("quotas_enabled", False))
        self._quota_enabled.stateChanged.connect(lambda s: (cfg.__setitem__("quotas_enabled", bool(s)), cfg.save()))
        q_hdr.addWidget(self._quota_enabled); q_hdr.addStretch()
        btn_add_quota = QPushButton("+ Add Quota"); btn_add_quota.setStyleSheet(f"background: {S['gn']}; color: white;")
        btn_add_quota.clicked.connect(self._add_quota)
        q_hdr.addWidget(btn_add_quota)
        layout.addLayout(q_hdr)

        self._quota_tbl = QTableWidget()
        self._quota_tbl.setColumnCount(5)
        self._quota_tbl.setHorizontalHeaderLabels(["Process", "Daily MB", "Weekly MB", "Today Used", "Action"])
        self._quota_tbl.verticalHeader().setVisible(False)
        self._quota_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._quota_tbl.horizontalHeader().setStretchLastSection(True)
        self._quota_tbl.setMaximumHeight(150)
        layout.addWidget(self._quota_tbl)

        layout.addStretch()
        self._tabs.addTab(page, "Plugins")

    def _reload_plugins(self):
        plugins.reload()
        self._update_plugins_ui()
        self._sbar.setText(f"Loaded {len(plugins.get_plugins())} plugins")

    def _install_example_plugins(self):
        """Install example plugins into the plugins directory."""
        plugins.create_example_plugins()
        plugins.reload()
        self._update_plugins_ui()
        count = len(plugins.get_plugins())
        self._sbar.setText(f"Installed example plugins ({count} loaded)")
        QMessageBox.information(self, "Example Plugins", 
            f"Installed 4 example plugins:\n\n"
            f"1. webhook_notifier.py - Send alerts to Slack/Discord/Teams\n"
            f"2. csv_logger.py - Log connections to daily CSV files\n"
            f"3. ip_reputation.py - Check IPs against AbuseIPDB\n"
            f"4. connection_stats.py - Track session statistics\n\n"
            f"Configure API keys in each file as needed.\n"
            f"Click 'Open Folder' to edit them.")

    def _update_plugins_ui(self):
        plist = plugins.get_plugins()
        self._plug_tbl.setRowCount(len(plist))
        for i, (name, info) in enumerate(plist.items()):
            self._plug_tbl.setItem(i, 0, QTableWidgetItem(name))
            self._plug_tbl.setItem(i, 1, QTableWidgetItem(", ".join(info.get("hooks", []))))
            self._plug_tbl.setItem(i, 2, QTableWidgetItem(info.get("file", "")))
        # Anomaly alerts
        alerts = anomaly_det.get_alerts()
        self._anom_tbl.setRowCount(len(alerts))
        for i, a in enumerate(alerts[-50:]):
            self._anom_tbl.setItem(i, 0, QTableWidgetItem(a.get("ts", "")))
            self._anom_tbl.setItem(i, 1, QTableWidgetItem(a.get("proc", "")))
            anomaly_str = "; ".join(a.get("anomalies", []))
            item = QTableWidgetItem(anomaly_str)
            item.setForeground(QColor(S['am']))
            self._anom_tbl.setItem(i, 2, item)
        # DNS blocks
        self._dns_list.clear()
        for d in dns_blocker.get_blocked():
            self._dns_list.addItem(d)
        # Quotas
        quotas = cfg.get("quotas", {})
        self._quota_tbl.setRowCount(len(quotas))
        for i, (proc, limits) in enumerate(quotas.items()):
            daily_used = quota_mgr._daily.get(proc.lower(), 0) / (1024*1024)
            self._quota_tbl.setItem(i, 0, QTableWidgetItem(proc))
            self._quota_tbl.setItem(i, 1, QTableWidgetItem(str(limits.get("daily_mb", 0))))
            self._quota_tbl.setItem(i, 2, QTableWidgetItem(str(limits.get("weekly_mb", 0))))
            used_item = QTableWidgetItem(f"{daily_used:.1f} MB")
            if limits.get("daily_mb", 0) > 0 and daily_used > limits["daily_mb"]:
                used_item.setForeground(QColor(S['rd']))
            self._quota_tbl.setItem(i, 3, used_item)
            self._quota_tbl.setItem(i, 4, QTableWidgetItem(limits.get("action", "alert")))

    def _create_sample_plugin(self):
        name, ok = QInputDialog.getText(self, "New Plugin", "Plugin name:")
        if ok and name:
            safe = re.sub(r'[^a-zA-Z0-9_]', '_', name)
            path = PLUGDIR / f"{safe}.py"
            sample = (f'"""PyWall Plugin: {name}"""\n\n'
                      'def on_connection(ci):\n'
                      '    """Called for every new connection."""\n'
                      '    pass\n\n'
                      'def on_block(ci):\n'
                      '    """Called when a connection is blocked."""\n'
                      '    pass\n\n'
                      'def on_threat(event):\n'
                      '    """Called when a security threat is detected."""\n'
                      '    pass\n')
            path.write_text(sample, encoding="utf-8")
            self._sbar.setText(f"Plugin '{safe}.py' created in {PLUGDIR}")
            self._reload_plugins()

    def _add_dns_block(self):
        domain = self._dns_add.text().strip()
        if domain:
            dns_blocker.add(domain)
            self._dns_add.clear()
            self._update_plugins_ui()
            self._sbar.setText(f"DNS blocked: {domain}")

    def _remove_dns_block(self):
        item = self._dns_list.currentItem()
        if item:
            dns_blocker.remove(item.text())
            self._update_plugins_ui()
            self._sbar.setText(f"DNS unblocked: {item.text()}")

    def _add_quota(self):
        proc, ok = QInputDialog.getText(self, "Add Quota", "Process name (e.g. chrome.exe):")
        if not ok or not proc: return
        daily, ok = QInputDialog.getInt(self, "Daily Limit", "Daily limit in MB (0 = unlimited):", 0, 0, 999999)
        if not ok: return
        weekly, ok = QInputDialog.getInt(self, "Weekly Limit", "Weekly limit in MB (0 = unlimited):", 0, 0, 999999)
        if not ok: return
        quotas = cfg.get("quotas", {})
        quotas[proc] = {"daily_mb": daily, "weekly_mb": weekly, "action": "alert"}
        cfg["quotas"] = quotas
        cfg.save()
        self._update_plugins_ui()
        self._sbar.setText(f"Quota added for {proc}: {daily}MB/day, {weekly}MB/week")

    # ================================================================
    #  SYSTEM TRAY, WORKERS, TIMERS
    # ================================================================
    def _make_tray_icon(self, color):
        """Create a shield-shaped tray icon in the given color."""
        pm = QPixmap(32, 32); pm.fill(QColor(0, 0, 0, 0))
        p = QPainter(pm); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Shield shape
        path = QPainterPath()
        path.moveTo(16, 2); path.cubicTo(8, 2, 2, 4, 2, 10)
        path.lineTo(2, 18); path.cubicTo(2, 24, 8, 30, 16, 30)
        path.cubicTo(24, 30, 30, 24, 30, 18); path.lineTo(30, 10)
        path.cubicTo(30, 4, 24, 2, 16, 2)
        p.setBrush(QBrush(QColor(color))); p.setPen(Qt.PenStyle.NoPen)
        p.drawPath(path)
        # "PW" text
        p.setPen(QPen(QColor("#FFFFFF")))
        f = QFont("Segoe UI", 8, QFont.Weight.Bold); p.setFont(f)
        p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, "PW")
        p.end()
        return QIcon(pm)

    def _update_tray_state(self, state="idle"):
        """Update tray icon color: idle=blue, monitoring=green, warning=amber, threat=red."""
        colors = {"idle": S['bl'], "monitoring": S['gn'], "warning": S['am'], "threat": S['rd']}
        color = colors.get(state, S['bl'])
        self._tray.setIcon(self._make_tray_icon(color))
        self._tray_state = state

    def _build_tray(self):
        self._tray = QSystemTrayIcon(self)
        self._tray_state = "idle"
        self._tray.setIcon(self._make_tray_icon(S['bl']))
        self._tray.setToolTip(f"{APP} - Stopped")
        self._tray.activated.connect(self._show_from_tray)
        menu = QMenu()
        menu.setStyleSheet(f"QMenu {{ background: {S['bg1']}; color: {S['t1']}; border: 1px solid {S['bd2']}; }} QMenu::item:selected {{ background: {S['bl']}; }}")
        self._tray_toggle = menu.addAction("Start Monitor", self._toggle_monitor)
        menu.addAction("Show", self._show_from_tray)
        menu.addSeparator()
        menu.addAction("Exit", self._real_close)
        self._tray.setContextMenu(menu)
        self._tray.show()

    def _show_from_tray(self, reason=None):
        if reason == QSystemTrayIcon.ActivationReason.Trigger or reason is None:
            self.showNormal(); self.activateWindow(); self.raise_()

    def _init_workers(self):
        self._dns = DNSWorker(); self._dns.ready.connect(self._on_dns); self._dns.start()
        self._who = WhoWorker(); self._who.ready.connect(self._on_who); self._who.start()
        self._geo = GeoIPWorker(); self._geo.ready.connect(self._on_geo); self._geo.start()
        self._pool = ThreadPoolExecutor(max_workers=4)

    def _init_timers(self):
        # Uptime ticker + bandwidth
        self._timer_tick = QTimer(self); self._timer_tick.timeout.connect(self._tick_uptime); self._timer_tick.start(1000)
        # Dashboard refresh (10s - only updates when visible)
        self._timer_dash = QTimer(self); self._timer_dash.timeout.connect(self._update_dashboard); self._timer_dash.start(10000)
        # Security refresh (15s - only updates when visible)
        self._timer_sec = QTimer(self); self._timer_sec.timeout.connect(self._update_security); self._timer_sec.start(15000)
        # Profile check (60s - runs in background thread)
        self._timer_prof = QTimer(self); self._timer_prof.timeout.connect(self._check_fw_status); self._timer_prof.start(60000)
        # Rule scheduler tick (60s)
        self._timer_sched = QTimer(self); self._timer_sched.timeout.connect(self._tick_scheduler); self._timer_sched.start(60000)
        # Network profile check (30s)
        self._timer_netprof = QTimer(self); self._timer_netprof.timeout.connect(self._tick_net_profile); self._timer_netprof.start(30000)
        # Session pruning (15s)
        self._timer_sessions = QTimer(self); self._timer_sessions.timeout.connect(self._tick_sessions); self._timer_sessions.start(15000)
        # Quota check + anomaly (30s)
        self._timer_quota = QTimer(self); self._timer_quota.timeout.connect(self._tick_quotas); self._timer_quota.start(30000)
        # New feature tab refresh (5s)
        self._timer_features = QTimer(self); self._timer_features.timeout.connect(self._tick_feature_tabs); self._timer_features.start(5000)

    def _tick_uptime(self):
        delta = datetime.datetime.now() - self._start_time
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        self._dash_up.setValue(f"{h:02d}:{m:02d}:{s:02d}")
        # Bandwidth rates
        up_r, dn_r = bw.rates()
        self._bw_up.setText(f"Up: {bw.format_rate(up_r)}")
        self._bw_dn.setText(f"Dn: {bw.format_rate(dn_r)}")
        # Only repaint graph every 2s and when dashboard is visible
        if s % 2 == 0 and hasattr(self, '_tabs') and self._tabs.currentIndex() == 0:
            self._bw_graph.update()
        # Total traffic
        ts, tr = bw.totals()
        self._dash_traffic.setValue(bw.format_bytes(ts + tr))

    def _check_fw_status(self):
        """Run firewall status check in background thread to avoid UI freeze."""
        self._pool.submit(self._check_fw_status_bg)

    def _check_fw_status_bg(self):
        try:
            profiles = fw.get_profile_status()
            active = fw.get_active_profile()
            QTimer.singleShot(0, lambda: self._apply_fw_status(profiles, active))
        except:
            QTimer.singleShot(0, lambda: self._sbar.setText("Windows Firewall: Status unknown"))

    def _apply_fw_status(self, profiles, active):
        self._profile_lbl.setText(f"Profile: {active}")
        for p, enabled in profiles.items():
            if p in self._prof_checks:
                self._prof_checks[p].blockSignals(True)
                self._prof_checks[p].setChecked(enabled)
                self._prof_checks[p].blockSignals(False)
        all_on = all(profiles.values())
        if all_on:
            self._sbar.setText(f"Windows Firewall: Active ({active})")
        else:
            disabled = [p for p, e in profiles.items() if not e]
            self._sbar.setText(f"WARNING: Firewall disabled for: {', '.join(disabled)}")

    # ================================================================
    #  MONITOR TOGGLE
    # ================================================================
    def _toggle_monitor(self):
        if self._monitoring:
            self._conn_w.stop(); self._evt_w.stop()
            self._monitoring = False
            try: plugins.fire("stop")
            except: pass
            self._btn_start.setText("Start Monitor")
            self._btn_start.setStyleSheet(f"background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #2563EB,stop:1 #1D4ED8); border-color: {S['bl']}; color: white; padding: 6px 18px; font-weight: bold;")
            self._status_lbl.setText("OFFLINE"); self._status_lbl.setStyleSheet(f"color: {S['t3']}; border: none;")
            self._status_dot.setStyleSheet(f"background: {S['t3']}; border-radius: 5px; border: none;")
            self._tray_toggle.setText("Start Monitor"); self._tray.setToolTip(f"{APP} - Stopped")
            self._update_tray_state("idle")
            self._sbar.setText("Monitor stopped")
            # Save state for crash recovery
            cfg["_was_monitoring"] = False; cfg.save()
        else:
            self._conn_w = ConnWorker()
            self._conn_w.ready.connect(self._on_conns)
            self._conn_w.need_dns.connect(self._dns.add)
            self._conn_w.need_who.connect(self._who.add)
            self._conn_w.need_geo.connect(self._geo.add)
            self._conn_w.first_seen.connect(self._on_first_seen)
            self._conn_w.ask_allow.connect(self._on_ask_allow)
            self._conn_w.start()
            self._evt_w = EvtWorker()
            self._evt_w.ready.connect(self._on_events)
            self._evt_w.new_block.connect(self._on_new_block)
            self._evt_w.start()
            self._monitoring = True
            self._btn_start.setText("Stop Monitor")
            self._btn_start.setStyleSheet(f"background: #DC2626; border-color: {S['rd']}; color: white; padding: 6px 18px; font-weight: bold;")
            self._status_lbl.setText("LIVE"); self._status_lbl.setStyleSheet(f"color: {S['gn']}; border: none;")
            self._status_dot.setStyleSheet(f"background: {S['gn']}; border-radius: 5px; border: none;")
            self._tray_toggle.setText("Stop Monitor"); self._tray.setToolTip(f"{APP} - Monitoring")
            self._update_tray_state("monitoring")
            self._sbar.setText("Monitoring active")
            # Save state for crash recovery
            cfg["_was_monitoring"] = True; cfg.save()
            # Initialize new features
            try: scheduler.load()
            except: pass
            try: plugins.load_all(); plugins.fire("start")
            except: pass
            try: net_profiles.detect_network()
            except: pass
            try: self._update_plugins_ui()
            except: pass
            # Seed auto-block dedup set from existing rules (also populates fw._known_names)
            def _seed_autoblock():
                try:
                    all_rules = fw.get_all_rules(force_refresh=True)
                    for r in all_rules:
                        if r.source == "pywall" and r.action == "Block" and r.remote_addr and r.remote_addr not in ("*", "Any", ""):
                            for addr in r.remote_addr.split(","):
                                self._auto_blocked_ips.add(addr.strip())
                except: pass
            self._pool.submit(_seed_autoblock)

    # ================================================================
    #  FEATURE TICK HANDLERS
    # ================================================================
    def _tick_scheduler(self):
        def _do():
            try: scheduler.tick()
            except: pass
        self._pool.submit(_do)

    def _tick_net_profile(self):
        def _do():
            try:
                msg = net_profiles.check_and_switch()
                if msg:
                    QTimer.singleShot(0, lambda: self._sbar.setText(msg))
            except: pass
        self._pool.submit(_do)

    def _tick_sessions(self):
        try: sessions.prune(30)
        except: pass

    def _tick_quotas(self):
        # Check bandwidth quotas
        if cfg.get("quotas_enabled"):
            violations = quota_mgr.check_quotas()
            for v in violations:
                if v["action"] == "block" and v["proc"] != "GLOBAL":
                    try:
                        for c in self._conn_data:
                            if c.proc.lower() == v["proc"].lower() and c.path and c.path != "-":
                                fw.block_program(c.path, "Outbound")
                                break
                    except: pass
                QTimer.singleShot(0, lambda v=v: self._sbar.setText(
                    f"Quota exceeded: {v['proc']} ({v['usage_mb']:.0f}MB / {v['limit_mb']}MB {v['type']})"))
        # Check anomalies
        if cfg.get("anomaly_enabled"):
            sens = cfg.get("anomaly_sensitivity", 2.0)
            for proc in set(c.proc.lower() for c in self._conn_data if c.proc):
                anomalies = anomaly_det.check(proc, sens)
                if anomalies:
                    anomaly_det.add_alert(proc, anomalies)
            # Update tray icon based on alert state
            if anomaly_det.get_alerts():
                if self._tray_state != "threat":
                    QTimer.singleShot(0, lambda: self._update_tray_state("warning"))

    def _tick_feature_tabs(self):
        """Update feature tabs only when they are visible."""
        if not hasattr(self, '_tabs'): return
        idx = self._tabs.currentIndex()
        try:
            tab_name = self._tabs.tabText(idx)
            if tab_name == "Network Map": self._update_netmap()
            elif tab_name == "Timeline": self._update_timeline()
            elif tab_name == "Schedule": self._update_schedule_tab()
            elif tab_name == "Plugins": self._update_plugins_ui()
        except: pass

    # ================================================================
    #  DATA HANDLERS
    # ================================================================
    def _on_conns(self, conns):
        if self._filter_src == "Events Only": return
        self._conn_data = conns
        self._update_table()

    def _on_events(self, evts):
        if self._filter_src == "Live Only": return
        self._evt_count += len(evts)
        self._dash_evt.setValue(str(self._evt_count))
        for ci in evts:
            with seen_lk:
                if ci.key in seen: continue
                seen.add(ci.key)
            self._conn_data.append(ci)
            log_conn(ci)

    def _on_dns(self, ip, hostname):
        dns_c.put(ip, hostname)
    def _on_who(self, ip, org):
        who_c.put(ip, org)
    def _on_geo(self, ip, cc, country):
        geo_c.put(ip, (cc, country))

    def _on_first_seen(self, proc_name, path):
        if cfg.get("first_seen_alert"):
            self._sbar.setText(f"New process detected: {proc_name} ({path})")

    def _on_ask_allow(self, ci):
        """Show ask-to-allow toast for new application."""
        if not cfg.get("ask_new_apps"): return
        # Already handled — has a policy or is suppressed
        if ci.proc and ci.proc.lower() in cfg.get("app_profiles", {}): return
        if f"proc|{ci.proc}" in self._suppressed: return
        dedup_key = f"ask|{ci.proc}"
        now = time.time()
        if dedup_key in self._toast_dedup and now - self._toast_dedup[dedup_key] < 300: return
        self._toast_dedup[dedup_key] = now
        toast = ToastNotification(ci, self, ask_mode=True)
        toast.action_taken.connect(self._handle_toast_action)
        self._toasts.append(toast)
        toast.show()

    def _update_table(self):
        # Only update if Connections tab is visible (index 2 with new tabs)
        if hasattr(self, '_tabs') and self._tabs.currentIndex() != 2: return
        data = list(self._conn_data)
        # Apply filters
        if self._filter_dir == "Out": data = [c for c in data if c.dir == "Out"]
        elif self._filter_dir == "In/Listen": data = [c for c in data if c.dir in ("In", "Listen")]
        if self._filter_pro == "TCP": data = [c for c in data if c.proto == "TCP"]
        elif self._filter_pro == "UDP": data = [c for c in data if c.proto == "UDP"]
        if self._filter_txt:
            ft = self._filter_txt.lower()
            data = [c for c in data if ft in c.host.lower() or ft in c.proc.lower() or ft in c.ra.lower() or ft in c.org.lower() or ft in c.country.lower()]
        # Category filter
        if hasattr(self, '_filter_cat') and self._filter_cat != "All Categories":
            fc = self._filter_cat
            data = [c for c in data if categorizer.categorize(c.host, c.ra, c.rp, c.proc) == fc]
        # Grouping mode
        if hasattr(self, '_grp_chk') and self._grp_chk.isChecked():
            summaries = grouper.summarize(data)
            data_display = []
            for grp in summaries:
                # Use first connection as representative
                rep = grp["connections"][0] if grp["connections"] else None
                if rep:
                    data_display.append((rep, grp["category"],
                        f"{grp['count']} conns, {grp['unique_ips']} IPs, {grp['unique_ports']} ports"))
            data_rows = data_display
        else:
            data_rows = [(c, categorizer.categorize(c.host, c.ra, c.rp, c.proc), None) for c in data]
        # Truncate
        data_rows = data_rows[-cfg["maxrows"]:]
        # Freeze UI during bulk update
        tbl = self._conn_tbl
        tbl.setUpdatesEnabled(False)
        tbl.blockSignals(True)
        try:
            tbl.setRowCount(len(data_rows))
            for i, (c, cat, grp_info) in enumerate(data_rows):
                rep_data = reputation.score(c.proc) if c.proc else {"grade": "?"}
                proc_display = f"[{grp_info}] {c.proc}" if grp_info else c.proc
                vals = [c.ts, c.src, c.dir, c.proto, c.la, c.lp, c.ra, c.rp,
                        c.host, proc_display, str(c.pid), c.org, c.state, c.country, c.cc,
                        cat, rep_data.get("grade", "?"), c.stat, ""]
                for j, v in enumerate(vals):
                    item = QTableWidgetItem(str(v))
                    if j == 17:  # status
                        if "BLOCK" in v.upper(): item.setForeground(QColor(S['rd']))
                        elif "ALLOW" in v.upper() or v == "-": item.setForeground(QColor(S['gn']) if "ALLOW" in v.upper() else QColor(S['t2']))
                        elif "BL:" in v: item.setForeground(QColor(S['am']))
                        elif "POLICY" in v: item.setForeground(QColor(S['am']))
                    elif j == 12:  # state
                        if v == "ESTABLISHED": item.setForeground(QColor(S['bl']))
                        elif "Blocked" in v: item.setForeground(QColor(S['rd']))
                    elif j == 15:  # category
                        cat_colors = {"Streaming": S['cy'], "Gaming": S['gn'], "Social Media": S['am'],
                                      "Ads/Tracking": S['rd'], "System": S['t2'], "Web": S['bl']}
                        item.setForeground(QColor(cat_colors.get(v, S['t3'])))
                    elif j == 16:  # reputation grade
                        grade_colors = {"A": S['gn'], "B": S['bl'], "C": S['am'], "D": S['rd'], "F": S['rd']}
                        item.setForeground(QColor(grade_colors.get(v, S['t3'])))
                    tbl.setItem(i, j, item)
                tbl.setRowHeight(i, 24)
        finally:
            tbl.blockSignals(False)
            tbl.setUpdatesEnabled(True)
        # Update dashboard stats
        self._dash_conn.setValue(str(len(data)))
        blk_count = sum(1 for c in data if "BLOCK" in c.stat.upper() or "BL:" in c.stat)
        self._dash_blk.setValue(str(blk_count))

    def _update_dashboard(self):
        # Only update if Dashboard tab is visible
        if hasattr(self, '_tabs') and self._tabs.currentIndex() != 0: return
        # Top processes
        top_procs = bw.get_top_processes(8)
        self._top_proc_tbl.setUpdatesEnabled(False)
        self._top_proc_tbl.setRowCount(len(top_procs))
        for i, (name, (s, r)) in enumerate(top_procs):
            self._top_proc_tbl.setItem(i, 0, QTableWidgetItem(name))
            self._top_proc_tbl.setItem(i, 1, QTableWidgetItem(bw.format_bytes(s)))
            self._top_proc_tbl.setItem(i, 2, QTableWidgetItem(bw.format_bytes(r)))
            self._top_proc_tbl.setRowHeight(i, 22)
        self._top_proc_tbl.setUpdatesEnabled(True)
        # Top countries
        country_counts = defaultdict(int)
        for c in self._conn_data:
            if c.cc and c.cc not in ("", "-", "LAN"): country_counts[(c.cc, c.country)] += 1
        top_cc = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        self._top_country_tbl.setUpdatesEnabled(False)
        self._top_country_tbl.setRowCount(len(top_cc))
        for i, ((cc, country), cnt) in enumerate(top_cc):
            self._top_country_tbl.setItem(i, 0, QTableWidgetItem(cc))
            self._top_country_tbl.setItem(i, 1, QTableWidgetItem(country))
            self._top_country_tbl.setItem(i, 2, QTableWidgetItem(str(cnt)))
            self._top_country_tbl.setRowHeight(i, 22)
        self._top_country_tbl.setUpdatesEnabled(True)
        # Threat list
        recent_threats = threats.get_events(5)
        self._threat_list.clear()
        for t in reversed(recent_threats):
            self._threat_list.addItem(f"[{t.severity.upper()}] {t.type}: {t.source_ip} - {t.details[:60]}")
        # Rule count - fetch in background to avoid PowerShell blocking UI
        self._pool.submit(self._update_rule_count_bg)
        # Traffic categories
        cat_summary = categorizer.get_summary(list(self._conn_data))
        cat_colors = {"Streaming": S['cy'], "Gaming": S['gn'], "Social Media": S['am'],
                      "Ads/Tracking": S['rd'], "System": S['t2'], "Web": S['bl']}
        self._cat_tbl.setUpdatesEnabled(False)
        self._cat_tbl.setRowCount(min(len(cat_summary), 10))
        for i, (cat, count) in enumerate(list(cat_summary.items())[:10]):
            item = QTableWidgetItem(cat)
            item.setForeground(QColor(cat_colors.get(cat, S['t3'])))
            self._cat_tbl.setItem(i, 0, item)
            self._cat_tbl.setItem(i, 1, QTableWidgetItem(str(count)))
            self._cat_tbl.setRowHeight(i, 22)
        self._cat_tbl.setUpdatesEnabled(True)

    def _update_rule_count_bg(self):
        try:
            rc = fw.get_rule_count()
            QTimer.singleShot(0, lambda: self._dash_rules.setValue(str(rc)))
        except: pass

    def _update_security(self):
        # Only update if Security tab is visible
        if hasattr(self, '_tabs') and self._tabs.currentIndex() != 5: return
        stats = threats.get_stats()
        self._sec_total.setValue(str(stats["total"]))
        self._sec_high.setValue(str(stats["high"]))
        self._sec_blocked.setValue(str(stats["blocked"]))
        # Update tray icon on active threats
        if stats["high"] > 0 and self._monitoring:
            self._update_tray_state("threat")
        elif self._monitoring and self._tray_state == "threat":
            self._update_tray_state("monitoring")
        events = threats.get_events(200)
        self._threat_tbl.setUpdatesEnabled(False)
        self._threat_tbl.blockSignals(True)
        self._threat_tbl.setRowCount(len(events))
        for i, e in enumerate(reversed(events)):
            self._threat_tbl.setItem(i, 0, QTableWidgetItem(e.ts))
            item_type = QTableWidgetItem(e.type)
            item_type.setForeground(QColor(S['rd']) if e.severity == "high" else QColor(S['am']))
            self._threat_tbl.setItem(i, 1, item_type)
            item_sev = QTableWidgetItem(e.severity.upper())
            item_sev.setForeground(QColor(S['rd']) if e.severity == "high" else QColor(S['am']))
            self._threat_tbl.setItem(i, 2, item_sev)
            self._threat_tbl.setItem(i, 3, QTableWidgetItem(e.source_ip))
            self._threat_tbl.setItem(i, 4, QTableWidgetItem(e.details))
            self._threat_tbl.setItem(i, 5, QTableWidgetItem(e.action_taken))
            self._threat_tbl.setRowHeight(i, 24)
        self._threat_tbl.blockSignals(False)
        self._threat_tbl.setUpdatesEnabled(True)
        # Blocklist hits
        self._bl_hits_list.clear()
        with blocklist_lk:
            for domain, count in sorted(blocklist_hits.items(), key=lambda x: x[1], reverse=True)[:20]:
                self._bl_hits_list.addItem(f"{domain}: {count} hits")

    # ================================================================
    #  CONNECTION SELECTION & CONTEXT MENU
    # ================================================================
    def _on_select(self, row, col, prev_row, prev_col):
        if row < 0: return
        vals = self._get_row_vals(row)
        if not vals: return
        proc = vals[9]; ip = vals[6]
        proc_lower = proc.lower() if proc else "?"
        # Get reputation data for the process
        rep_data = reputation.score(proc) if proc and proc != "?" else {"grade": "?", "score": 0, "reasons": []}
        hist = reputation._history.get(proc_lower, {})
        path = hist.get("path", "")
        sig = reputation._sig_cache.get(path, "")
        sig_str = f"  Signature: {sig}\n" if sig else ""
        vt = reputation._vt_cache.get(path)
        vt_str = ""
        if vt:
            if vt.get("scanned"):
                vt_str = f"  VirusTotal: {vt['malicious']} malicious, {vt['suspicious']} suspicious, {vt['harmless']} clean\n"
            else:
                vt_str = "  VirusTotal: Not found in database\n"
        # GeoIP novelty check
        known_countries = anomaly_det._known_countries.get(proc_lower, set())
        geo_str = ""
        if len(known_countries) > 1:
            geo_str = f"  Countries seen: {', '.join(sorted(known_countries))}\n"
        # Build rich detail text
        detail_lines = [
            f"=== {proc} (PID: {vals[10]}) ===",
            f"  Path: {path or vals[11]}",
            f"  Category: {vals[15]}",
            f"  Reputation: {rep_data['grade']} ({rep_data['score']}/100)",
            sig_str.rstrip(),
            vt_str.rstrip(),
            "",
            f"--- Network ---",
            f"  Remote: {ip}:{vals[7]}",
            f"  Hostname: {vals[8]}",
            f"  Local: {vals[4]}:{vals[5]}",
            f"  Protocol: {vals[3]} | Direction: {vals[2]} | State: {vals[12]}",
            "",
            f"--- Intelligence ---",
            f"  Organization: {vals[11]}",
            f"  Country: {vals[13]} ({vals[14]})",
            f"  Status: {vals[17]}",
            geo_str.rstrip(),
        ]
        # Connection stats
        if hist:
            detail_lines.append("")
            detail_lines.append("--- Process Stats ---")
            detail_lines.append(f"  Total connections: {hist.get('conn_count', 0)}")
            detail_lines.append(f"  Unique IPs: {len(hist.get('unique_ips', set()))}")
            detail_lines.append(f"  Unique ports: {len(hist.get('unique_ports', set()))}")
            detail_lines.append(f"  Blocked: {hist.get('blocked', 0)}")
            age = (time.time() - hist.get('first_seen', time.time())) / 3600
            if age < 1: detail_lines.append(f"  First seen: {age*60:.0f} minutes ago")
            elif age < 24: detail_lines.append(f"  First seen: {age:.1f} hours ago")
            else: detail_lines.append(f"  First seen: {age/24:.1f} days ago")
        if rep_data.get("reasons"):
            detail_lines.append("")
            detail_lines.append("--- Reputation Factors ---")
            for r in rep_data["reasons"]:
                detail_lines.append(f"  - {r}")
        self._detail.setPlainText("\n".join(l for l in detail_lines if l is not None))
        self._sbar.setText(f"Selected: {proc} -> {ip}:{vals[7]} [{vals[13]}] ({vals[15]})")

    def _ctx_menu(self, pos):
        row = self._conn_tbl.rowAt(pos.y())
        if row < 0: return
        vals = self._get_row_vals(row)
        if not vals: return
        menu = QMenu(self)
        ip = vals[6]; port = vals[7]; proc = vals[9]
        menu.addAction(f"Block IP: {ip}", lambda: self._action_block_ip(ip, "Outbound"))
        menu.addAction(f"Block IP Inbound: {ip}", lambda: self._action_block_ip(ip, "Inbound"))
        menu.addAction(f"Block Port: {port}", lambda: self._action_block_port(port, vals[3]))
        menu.addSeparator()
        ci = self._find_ci(row)
        if ci and ci.path and ci.path != "-":
            menu.addAction(f"Block Program: {proc}", lambda: self._action_block_program(ci.path, "Outbound"))
            menu.addAction(f"Allow Program: {proc}", lambda: self._action_allow_program(ci.path))
            menu.addAction(f"Set Policy: Block {proc}", lambda: self._set_app_policy(proc, "block"))
            menu.addAction(f"Set Policy: Allow {proc}", lambda: self._set_app_policy(proc, "allow"))
        menu.addSeparator()
        menu.addAction(f"Allow IP: {ip}", lambda: self._action_allow_ip(ip))
        menu.addSeparator()
        if vals[10] and vals[10] != "0":
            menu.addAction(f"Kill Process (PID {vals[10]})", lambda: self._kill_process(int(vals[10])))
        menu.addAction(f"Kill All Connections to {ip}", lambda: self._kill_connections(ip))
        menu.addSeparator()
        menu.addAction("Copy IP", lambda: QApplication.clipboard().setText(ip))
        menu.addAction("Copy Row", lambda: self._copy_row(row))
        menu.addAction("WHOIS Lookup", lambda: self._whois_lookup(ip))
        # Reputation
        menu.addAction(f"View Reputation: {proc}", lambda: self._show_reputation(proc))
        menu.addAction(f"Find Rules for {ip}", lambda: self._find_rules_for_ip(ip))
        menu.addSeparator()
        menu.addAction("Create Custom Rule...", lambda: self._open_create_rule_prefilled(vals))
        menu.exec(self._conn_tbl.viewport().mapToGlobal(pos))

    def _get_row_vals(self, row):
        vals = []
        for j in range(self._conn_tbl.columnCount()):
            item = self._conn_tbl.item(row, j)
            vals.append(item.text() if item else "")
        return vals

    def _find_ci(self, row):
        vals = self._get_row_vals(row)
        if not vals: return None
        for c in self._conn_data:
            if c.ra == vals[6] and c.rp == vals[7] and str(c.pid) == vals[10]: return c
        return None

    # ================================================================
    #  FIREWALL ACTIONS
    # ================================================================
    def _action_block_ip(self, ip, direction="Outbound"):
        self._sbar.setText(f"Blocking IP {ip} ({direction})...")
        def _do():
            try:
                ok, out = fw.block_ip(ip, direction)
                if ok:
                    with blk_lk: blk.add(ip)
                    # Verify rule was actually created
                    verified = self._verify_rule_exists(ip)
                    status = f"Blocked IP {ip} ({direction})" + (" [verified]" if verified else " [unverified]")
                else:
                    status = f"FAILED to block IP {ip} ({direction}): {out[:80]}"
                QTimer.singleShot(0, lambda: self._sbar.setText(status))
                QTimer.singleShot(0, lambda: (self._suppress_ip(ip), self._refresh_rules_panel()) if ok else None)
            except Exception as e:
                QTimer.singleShot(0, lambda: self._sbar.setText(f"Error blocking IP {ip}: {e}"))
        self._pool.submit(_do)

    def _verify_rule_exists(self, search_term):
        """Verify a firewall rule containing the search term exists."""
        try:
            ok, out = _ps(f"Get-NetFirewallRule -DisplayName '{PFX}*' | "
                         f"Get-NetFirewallAddressFilter | "
                         f"Where-Object {{ $_.RemoteAddress -like '*{search_term}*' }} | "
                         f"Select-Object -First 1 -ExpandProperty RemoteAddress", 10)
            return ok and search_term in (out or "")
        except:
            return False

    def _action_block_port(self, port, proto="TCP"):
        self._sbar.setText(f"Blocking port {port}/{proto}...")
        def _do():
            try:
                ok, out = fw.block_port(port, proto)
                QTimer.singleShot(0, lambda: self._sbar.setText(f"{'Blocked' if ok else 'FAILED to block'} port {port}/{proto}{'' if ok else ': ' + out[:80]}"))
                if ok:
                    self._suppressed.add(f"port|{port}")
                    QTimer.singleShot(0, self._refresh_rules_panel)
            except Exception as e:
                QTimer.singleShot(0, lambda: self._sbar.setText(f"Error blocking port {port}: {e}"))
        self._pool.submit(_do)

    def _action_block_program(self, path, direction="Outbound"):
        self._sbar.setText(f"Blocking {Path(path).name}...")
        def _do():
            try:
                ok, out = fw.block_program(path, direction)
                if ok:
                    self._suppressed.add(f"proc|{Path(path).name}")
                QTimer.singleShot(0, lambda: self._sbar.setText(f"{'Blocked' if ok else 'FAILED to block'} {Path(path).name}{'' if ok else ': ' + out[:80]}"))
                if ok: QTimer.singleShot(0, self._refresh_rules_panel)
            except Exception as e:
                QTimer.singleShot(0, lambda: self._sbar.setText(f"Error blocking {Path(path).name}: {e}"))
        self._pool.submit(_do)

    def _action_allow_ip(self, ip):
        self._sbar.setText(f"Allowing IP {ip}...")
        with blk_lk: blk.discard(ip)
        def _do():
            try:
                ok, out = fw.allow_ip(ip)
                if ok:
                    self._suppressed.add(f"ip|{ip}")
                QTimer.singleShot(0, lambda: self._sbar.setText(f"{'Allowed' if ok else 'FAILED to allow'} IP {ip}{'' if ok else ': ' + out[:80]}"))
                if ok: QTimer.singleShot(0, self._refresh_rules_panel)
            except Exception as e:
                QTimer.singleShot(0, lambda: self._sbar.setText(f"Error allowing IP {ip}: {e}"))
        self._pool.submit(_do)

    def _action_allow_program(self, path):
        self._sbar.setText(f"Allowing {Path(path).name}...")
        def _do():
            try:
                ok, out = fw.allow_program(path)
                if ok:
                    self._suppressed.add(f"proc|{Path(path).name}")
                QTimer.singleShot(0, lambda: self._sbar.setText(f"{'Allowed' if ok else 'FAILED to allow'} {Path(path).name}{'' if ok else ': ' + out[:80]}"))
                if ok: QTimer.singleShot(0, self._refresh_rules_panel)
            except Exception as e:
                QTimer.singleShot(0, lambda: self._sbar.setText(f"Error allowing {Path(path).name}: {e}"))
        self._pool.submit(_do)

    def _set_app_policy(self, proc_name, policy, known_path=None):
        profiles = cfg.get("app_profiles", {})
        profiles[proc_name.lower()] = policy
        cfg["app_profiles"] = profiles
        cfg.save()
        self._suppressed.add(f"proc|{proc_name}")
        self._sbar.setText(f"Policy set: {proc_name} -> {policy.upper()}")
        # Create firewall rules in background to avoid UI freeze
        def _apply():
            try:
                # Use known_path if provided, otherwise search _conn_data
                path = known_path
                if not path or path == "-":
                    for c in self._conn_data:
                        if c.proc.lower() == proc_name.lower() and c.path and c.path != "-":
                            path = c.path
                            break
                if path and path != "-":
                    if policy == "block":
                        fw.block_program(path, "Outbound")
                        fw.block_program(path, "Inbound")
                    elif policy == "allow":
                        fw.allow_program(path, "Outbound")
                        fw.allow_program(path, "Inbound")
                    QTimer.singleShot(0, lambda: self._sbar.setText(f"Rule created: {proc_name} -> {policy.upper()}"))
                else:
                    QTimer.singleShot(0, lambda: self._sbar.setText(f"Could not find path for {proc_name} - policy saved but no rule created"))
                QTimer.singleShot(0, self._refresh_rules_panel)
            except Exception as e:
                QTimer.singleShot(0, lambda: self._sbar.setText(f"Error creating rule for {proc_name}: {e}"))
        self._pool.submit(_apply)

    def _kill_process(self, pid):
        ok = fw.kill_connection(pid)
        self._sbar.setText(f"{'Killed' if ok else 'Failed to kill'} PID {pid}")

    def _kill_connections(self, ip):
        killed = fw.kill_connections_by_ip(ip)
        self._sbar.setText(f"Killed {killed} connection(s) to {ip}")

    def _suppress_ip(self, ip):
        self._suppressed.add(f"ip|{ip}")
        self._dismiss_matching_toasts(ip)

    def _dismiss_matching_toasts(self, ip=None):
        for t in list(self._toasts):
            if ip and t.ci.ra == ip:
                t._close_toast()

    # ================================================================
    #  TOAST / NOTIFICATION HANDLING
    # ================================================================
    def _is_suppressed(self, ci):
        if f"ip|{ci.ra}" in self._suppressed: return True
        if f"proc|{ci.proc}" in self._suppressed: return True
        if f"port|{ci.rp}" in self._suppressed: return True
        # Already has a policy set — no need for more toasts
        if ci.proc and ci.proc.lower() in cfg.get("app_profiles", {}): return True
        dedup = f"block|{ci.ra}|{ci.rp}|{ci.proc}"
        now = time.time()
        if dedup in self._toast_dedup:
            if now - self._toast_dedup[dedup] < self._toast_cooldown: return True
        self._toast_dedup[dedup] = now
        return False

    def _on_new_block(self, ci):
        if self._auto_block and ci.ra and ci.ra not in ("*", "", "-"):
            # Only create rule if we haven't already auto-blocked this IP
            if ci.ra not in self._auto_blocked_ips:
                self._auto_blocked_ips.add(ci.ra)
                self._suppressed.add(f"ip|{ci.ra}")
                def _ab():
                    try:
                        fw.block_ip(ci.ra, "Outbound")
                        with blk_lk: blk.add(ci.ra)
                    except: pass
                self._pool.submit(_ab)
        if not cfg["toast"] or self._is_suppressed(ci): return
        toast = ToastNotification(ci, self)
        toast.action_taken.connect(self._handle_toast_action)
        self._toasts.append(toast)
        toast.show()
        if cfg["toast_sec"] > 0:
            toast.start_dismiss_timer(cfg["toast_sec"] * 1000)

    def _handle_toast_action(self, action_dict, ci):
        atype = action_dict.get("type", "")
        if atype == "block_ip":
            self._action_block_ip(ci.ra)
            self._suppressed.add(f"ip|{ci.ra}")
        elif atype == "allow_ip":
            self._action_allow_ip(ci.ra)
            self._suppressed.add(f"ip|{ci.ra}")
        elif atype == "block_app":
            if ci.path and ci.path != "-":
                self._set_app_policy(ci.proc, "block", ci.path)
            self._suppressed.add(f"proc|{ci.proc}")
        elif atype == "allow_app":
            if ci.path and ci.path != "-":
                self._set_app_policy(ci.proc, "allow", ci.path)
            self._suppressed.add(f"proc|{ci.proc}")
        elif atype == "allow_once":
            self._toast_dedup[f"ask|{ci.proc}"] = time.time() + 300
        elif atype == "custom":
            self._apply_custom_rule(action_dict, ci)
        # Dismiss all other toasts that match the same IP or process
        self._dismiss_related_toasts(ci)

    def _dismiss_related_toasts(self, ci):
        """Close any remaining visible toasts for the same IP or process."""
        for toast in list(self._toasts):
            if toast.isVisible() and toast.ci is not ci:
                if toast.ci.ra == ci.ra or toast.ci.proc == ci.proc:
                    toast._close_toast()

    def _apply_custom_rule(self, action_dict, ci):
        direction = action_dict.get("direction", "Outbound")
        action = action_dict.get("action", "Block")
        rule_type = action_dict.get("rule_type", "Block IP")
        safe_ip = ci.ra.replace(":", "-").replace("/", "_")
        if rule_type == "Block IP":
            nm = f"{PFX}Custom_{safe_ip}_{direction[:3]}"
            fw.create_rule(nm, direction, action, remote_addr=ci.ra, desc="Custom rule from toast")
        elif rule_type == "Block Port":
            nm = f"{PFX}Custom_Port{ci.rp}_{ci.proto}_{direction[:3]}"
            fw.create_rule(nm, direction, action, remote_port=ci.rp, protocol=ci.proto, desc="Custom rule from toast")
        elif rule_type == "Block Process" and ci.path and ci.path != "-":
            nm = f"{PFX}Custom_{Path(ci.path).stem[:25]}_{direction[:3]}"
            fw.create_rule(nm, direction, action, program=ci.path, desc="Custom rule from toast")
        elif rule_type == "Block IP+Port":
            nm = f"{PFX}Custom_{safe_ip}_P{ci.rp}_{direction[:3]}"
            fw.create_rule(nm, direction, action, remote_addr=ci.ra, remote_port=ci.rp, protocol=ci.proto, desc="Custom rule from toast")
        # Suppress future toasts for this target
        self._suppressed.add(f"ip|{ci.ra}")
        if ci.proc and ci.proc not in ("?", "-", "System"):
            self._suppressed.add(f"proc|{ci.proc}")
        self._refresh_rules_panel()

    # ================================================================
    #  HISTORY TAB
    # ================================================================
    def _search_history(self):
        query = self._hist_search.text().strip()
        proc_f = self._hist_proc.currentText()
        country_f = self._hist_country.currentText()
        time_f = self._hist_time.currentText()
        hours = {"All":0, "1 hour":1, "24 hours":24, "7 days":168, "30 days":720}.get(time_f, 0)
        self._hist_offset = 0
        results = conn_db.search(query=query, limit=500, offset=0,
                                  proc_filter="" if proc_f == "All" else proc_f,
                                  country_filter="" if country_f == "All" else country_f,
                                  hours=hours)
        self._hist_tbl.setUpdatesEnabled(False)
        self._hist_tbl.blockSignals(True)
        self._hist_tbl.setRowCount(len(results))
        for i, row in enumerate(results):
            for j, val in enumerate(row):
                self._hist_tbl.setItem(i, j, QTableWidgetItem(str(val or "")))
            self._hist_tbl.setRowHeight(i, 24)
        self._hist_tbl.blockSignals(False)
        self._hist_tbl.setUpdatesEnabled(True)
        self._hist_count.setText(f"{len(results)} results")
        self._hist_page_lbl.setText(f"Page {self._hist_offset // 500 + 1}")
        self._hist_total.setText(f"Total records: {conn_db.count()}")

    def _hist_page(self, delta):
        self._hist_offset = max(0, self._hist_offset + delta * 500)
        query = self._hist_search.text().strip()
        proc_f = self._hist_proc.currentText()
        country_f = self._hist_country.currentText()
        time_f = self._hist_time.currentText()
        hours = {"All":0, "1 hour":1, "24 hours":24, "7 days":168, "30 days":720}.get(time_f, 0)
        results = conn_db.search(query=query, limit=500, offset=self._hist_offset,
                                  proc_filter="" if proc_f == "All" else proc_f,
                                  country_filter="" if country_f == "All" else country_f,
                                  hours=hours)
        self._hist_tbl.setUpdatesEnabled(False)
        self._hist_tbl.blockSignals(True)
        self._hist_tbl.setRowCount(len(results))
        for i, row in enumerate(results):
            for j, val in enumerate(row):
                self._hist_tbl.setItem(i, j, QTableWidgetItem(str(val or "")))
            self._hist_tbl.setRowHeight(i, 24)
        self._hist_tbl.blockSignals(False)
        self._hist_tbl.setUpdatesEnabled(True)
        self._hist_page_lbl.setText(f"Page {self._hist_offset // 500 + 1}")

    def _refresh_history_filters(self):
        self._hist_proc.clear(); self._hist_proc.addItem("All")
        for p in conn_db.get_unique_procs(): self._hist_proc.addItem(p)
        self._hist_country.clear(); self._hist_country.addItem("All")
        for cc, country in conn_db.get_unique_countries(): self._hist_country.addItem(f"{country} ({cc})")

    # ================================================================
    #  APPLICATIONS TAB
    # ================================================================
    def _refresh_apps(self):
        apps = {}
        for c in self._conn_data:
            if c.proc and c.proc not in ("?", "System", "-"):
                if c.proc not in apps:
                    apps[c.proc] = {"path": c.path, "conns": 0, "first": _known_procs.get(c.proc, "-")}
                apps[c.proc]["conns"] += 1
        app_profiles = cfg.get("app_profiles", {})
        proc_bw = dict(bw.get_top_processes(100))

        self._app_tbl.setUpdatesEnabled(False)
        self._app_tbl.blockSignals(True)
        self._app_tbl.setRowCount(len(apps))
        for i, (proc, info) in enumerate(sorted(apps.items())):
            self._app_tbl.setItem(i, 0, QTableWidgetItem(proc))
            self._app_tbl.setItem(i, 1, QTableWidgetItem(info["path"]))
            self._app_tbl.setItem(i, 2, QTableWidgetItem(str(info["conns"])))
            if proc in proc_bw:
                s, r = proc_bw[proc]
                self._app_tbl.setItem(i, 3, QTableWidgetItem(f"{bw.format_bytes(s+r)}"))
            else:
                self._app_tbl.setItem(i, 3, QTableWidgetItem("-"))
            self._app_tbl.setItem(i, 4, QTableWidgetItem(info["first"][:19] if info["first"] != "-" else "-"))
            # Reputation
            rep = reputation.score(proc)
            rep_item = QTableWidgetItem(f"{rep['grade']} ({rep['score']})")
            grade_colors = {"A": S['gn'], "B": S['bl'], "C": S['am'], "D": S['rd'], "F": S['rd']}
            rep_item.setForeground(QColor(grade_colors.get(rep['grade'], S['t3'])))
            rep_item.setToolTip("\n".join(rep.get("reasons", [])))
            self._app_tbl.setItem(i, 5, rep_item)
            policy = app_profiles.get(proc.lower(), "monitor")
            policy_item = QTableWidgetItem(policy.upper())
            if policy == "block": policy_item.setForeground(QColor(S['rd']))
            elif policy == "allow": policy_item.setForeground(QColor(S['gn']))
            else: policy_item.setForeground(QColor(S['t3']))
            self._app_tbl.setItem(i, 6, policy_item)

            # Action buttons
            btn_w = QWidget(); btn_l = QHBoxLayout(btn_w); btn_l.setContentsMargins(2,0,2,0); btn_l.setSpacing(2)
            btn_a = QPushButton("Allow"); btn_a.setFixedHeight(22); btn_a.setStyleSheet(f"background:{S['gn']};color:white;padding:1px 6px;font-size:9px;")
            btn_a.clicked.connect(lambda _, p=proc: self._set_app_policy(p, "allow"))
            btn_b = QPushButton("Block"); btn_b.setFixedHeight(22); btn_b.setStyleSheet(f"background:{S['rd']};color:white;padding:1px 6px;font-size:9px;")
            btn_b.clicked.connect(lambda _, p=proc: self._set_app_policy(p, "block"))
            btn_l.addWidget(btn_a); btn_l.addWidget(btn_b)
            self._app_tbl.setCellWidget(i, 7, btn_w)
            self._app_tbl.setRowHeight(i, 28)
        self._app_tbl.blockSignals(False)
        self._app_tbl.setUpdatesEnabled(True)

    def _block_all_unknown_apps(self):
        app_profiles = cfg.get("app_profiles", {})
        to_block = []
        for c in self._conn_data:
            if c.proc and c.proc not in ("?", "System", "-"):
                if c.proc.lower() not in app_profiles:
                    app_profiles[c.proc.lower()] = "block"
                    if c.path and c.path != "-":
                        to_block.append(c.path)
        cfg["app_profiles"] = app_profiles; cfg.save()
        self._sbar.setText(f"Blocking {len(to_block)} unknown applications...")
        def _do():
            for path in to_block:
                fw.block_program(path, "Outbound")
            QTimer.singleShot(0, lambda: (self._sbar.setText("All unknown applications blocked"), self._refresh_apps()))
        self._pool.submit(_do)

    def _allow_all_apps(self):
        cfg["app_profiles"] = {}; cfg.save()
        self._sbar.setText("All application policies cleared")
        self._refresh_apps()

    # ================================================================
    #  RULES PANEL (Connections tab sidebar)
    # ================================================================
    def _refresh_rules_panel(self):
        self._pool.submit(self._refresh_rules_bg)

    def _refresh_rules_bg(self):
        rules = fw.get_pywall_rules()
        from PyQt6.QtCore import QMetaObject, Q_ARG
        QTimer.singleShot(0, lambda: self._populate_rules_panel(rules))

    def _populate_rules_panel(self, rules):
        self._rules_tbl.setUpdatesEnabled(False)
        self._rules_tbl.blockSignals(True)
        self._rules_tbl.setRowCount(len(rules))
        for i, r in enumerate(rules):
            items = [r.name.replace(PFX,""), r.direction[:3], r.action,
                     r.remote_addr[:30], r.remote_port, Path(r.program).name if r.program else ""]
            for j, v in enumerate(items):
                item = QTableWidgetItem(v)
                if j == 2: item.setForeground(QColor(S['rd']) if v == "Block" else QColor(S['gn']))
                self._rules_tbl.setItem(i, j, item)
            self._rules_tbl.setRowHeight(i, 24)
        self._rules_tbl.blockSignals(False)
        self._rules_tbl.setUpdatesEnabled(True)
        self._pool.submit(self._update_rule_count_bg)

    def _rule_ctx(self, pos):
        row = self._rules_tbl.rowAt(pos.y())
        if row < 0: return
        name_item = self._rules_tbl.item(row, 0)
        if not name_item: return
        name = PFX + name_item.text()
        menu = QMenu(self)
        menu.addAction("Delete Rule", lambda: self._delete_pw_rule(name))
        menu.addAction("Copy Name", lambda: QApplication.clipboard().setText(name))
        menu.exec(self._rules_tbl.viewport().mapToGlobal(pos))

    def _delete_pw_rule(self, name):
        fw.delete_rule(name)
        self._refresh_rules_panel()

    def _open_create_rule(self):
        dlg = CreateRuleDialog(self)
        dlg.rule_created.connect(self._refresh_rules_panel)
        dlg.exec()

    def _open_create_rule_prefilled(self, vals):
        dlg = CreateRuleDialog(self, prefill={
            "remote_addr": vals[6], "remote_port": vals[7],
            "protocol": vals[3], "direction": "Outbound",
            "action": "Block",
        })
        dlg.rule_created.connect(self._refresh_rules_panel)
        dlg.exec()

    # ================================================================
    #  QUICK ACTIONS (Dashboard)
    # ================================================================
    def _quick_block_all_outbound(self):
        reply = QMessageBox.question(self, "Block All Outbound",
            "Set default outbound action to BLOCK for all profiles?\n\n"
            "This will block ALL outbound traffic except what is explicitly allowed.\n"
            "You should create allow rules for essential apps first.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._sbar.setText("Applying outbound block policy...")
            def _do():
                for p in ("Domain", "Private", "Public"):
                    fw.set_default_action(p, "Outbound", "Block")
                QTimer.singleShot(0, lambda: self._sbar.setText("Default outbound action set to BLOCK for all profiles"))
            self._pool.submit(_do)

    def _quick_reset_default(self):
        reply = QMessageBox.question(self, "Reset Defaults",
            "Reset default actions to Windows defaults?\n(Inbound: Block, Outbound: Allow)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._sbar.setText("Resetting firewall defaults...")
            def _do():
                for p in ("Domain", "Private", "Public"):
                    fw.set_default_action(p, "Inbound", "Block")
                    fw.set_default_action(p, "Outbound", "Allow")
                QTimer.singleShot(0, lambda: self._sbar.setText("Firewall defaults restored"))
            self._pool.submit(_do)

    def _flush_pywall_rules(self):
        rules = fw.get_pywall_rules()
        if not rules:
            self._sbar.setText("No PyWall rules to remove"); return
        reply = QMessageBox.question(self, "Flush PyWall Rules",
            f"Remove all {len(rules)} PyWall-created rules?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            count = len(rules)
            self._sbar.setText(f"Removing {count} PyWall rules...")
            def _do():
                for r in rules: fw.delete_rule(r.name)
                QTimer.singleShot(0, lambda: (self._sbar.setText(f"Removed {count} PyWall rules"), self._refresh_rules_panel()))
            self._pool.submit(_do)

    def _toggle_profile(self, profile, state):
        self._sbar.setText(f"{'Enabling' if state else 'Disabling'} {profile} profile...")
        def _do():
            fw.set_profile_status(profile, bool(state))
            QTimer.singleShot(0, self._check_fw_status)
        self._pool.submit(_do)

    # ================================================================
    #  EXPORT / IMPORT / UTILITY
    # ================================================================
    def _export_rules(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Rules", str(CDIR / "pywall_rules.json"), "JSON (*.json)")
        if not path: return
        rules = fw.get_pywall_rules()
        data = []
        for r in rules:
            data.append({"name":r.name,"desc":r.desc,"direction":r.direction,"action":r.action,
                         "enabled":r.enabled,"profile":r.profile,"remote_addr":r.remote_addr,
                         "local_addr":r.local_addr,"remote_port":r.remote_port,"local_port":r.local_port,
                         "protocol":r.protocol,"program":r.program})
        with open(path, "w") as f: json.dump(data, f, indent=2)
        self._sbar.setText(f"Exported {len(data)} rules to {Path(path).name}")

    def _import_rules(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Rules", "", "JSON (*.json)")
        if not path: return
        try:
            with open(path) as f: data = json.load(f)
            created = 0
            for r in data:
                ok, _ = fw.create_rule(
                    name=r.get("name",""), direction=r.get("direction","Outbound"),
                    action=r.get("action","Block"), remote_addr=r.get("remote_addr",""),
                    remote_port=r.get("remote_port",""), local_addr=r.get("local_addr",""),
                    local_port=r.get("local_port",""), protocol=r.get("protocol",""),
                    program=r.get("program",""), profile=r.get("profile","Any"),
                    desc=r.get("desc",""), enabled=r.get("enabled",True))
                if ok: created += 1
            self._sbar.setText(f"Imported {created}/{len(data)} rules from {Path(path).name}")
            self._refresh_rules_panel()
        except Exception as e:
            QMessageBox.critical(self, "Import Error", str(e))

    def _copy_row(self, row):
        vals = self._get_row_vals(row)
        QApplication.clipboard().setText("\t".join(vals))

    def _whois_lookup(self, ip):
        self._sbar.setText(f"Looking up WHOIS for {ip}...")
        self._pool.submit(self._whois_bg, ip)

    def _whois_bg(self, ip):
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if r.status_code == 200:
                d = r.json()
                info = f"IP: {ip}\nOrg: {d.get('org','-')}\nCity: {d.get('city','-')}\nRegion: {d.get('region','-')}\nCountry: {d.get('country','-')}\nASN: {d.get('org','-')}"
                QTimer.singleShot(0, lambda: QMessageBox.information(self, f"WHOIS: {ip}", info))
            else:
                QTimer.singleShot(0, lambda: self._sbar.setText(f"WHOIS lookup failed for {ip}"))
        except Exception as e:
            QTimer.singleShot(0, lambda: self._sbar.setText(f"WHOIS error: {e}"))

    def _show_reputation(self, proc_name):
        rep = reputation.score(proc_name)
        h = reputation._history.get(proc_name.lower(), {})
        path = h.get("path", "-")
        sig = reputation._sig_cache.get(path, "Not checked")
        vt = reputation._vt_cache.get(path)
        vt_str = "Not checked"
        if vt:
            if vt.get("scanned"):
                vt_str = f"{vt['malicious']} malicious, {vt['suspicious']} suspicious, {vt['harmless']} harmless"
            else:
                vt_str = "Not found in VirusTotal database"
        info = (f"Process: {proc_name}\n"
                f"Reputation Grade: {rep['grade']} ({rep['score']}/100)\n\n"
                f"Factors:\n" + "\n".join(f"  - {r}" for r in rep.get("reasons", [])) + "\n\n"
                f"Statistics:\n"
                f"  Connections: {h.get('conn_count', 0)}\n"
                f"  Unique IPs: {len(h.get('unique_ips', set()))}\n"
                f"  Unique Ports: {len(h.get('unique_ports', set()))}\n"
                f"  Countries: {len(h.get('countries', set()))}\n"
                f"  Blocked: {h.get('blocked', 0)}\n\n"
                f"Binary Analysis:\n"
                f"  Path: {path}\n"
                f"  Signature: {sig}\n"
                f"  VirusTotal: {vt_str}")
        QMessageBox.information(self, f"Reputation: {proc_name}", info)

    def _find_rules_for_ip(self, ip):
        """Switch to Rules tab and search for rules affecting an IP."""
        # Find the Rules tab index
        for i in range(self._tabs.count()):
            if self._tabs.tabText(i) == "Rules":
                self._tabs.setCurrentIndex(i)
                break
        # Set search text
        if hasattr(self, '_rules_mgr') and hasattr(self._rules_mgr, '_search'):
            self._rules_mgr._search.setText(ip)
            self._sbar.setText(f"Showing rules matching '{ip}'")

    def _export_threats(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Threats", str(CDIR / "threats.csv"), "CSV (*.csv)")
        if not path: return
        events = threats.get_events()
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Time","Type","Severity","Source IP","Details","Action","Blocked"])
            for e in events:
                w.writerow([e.ts, e.type, e.severity, e.source_ip, e.details, e.action_taken, e.blocked])
        self._sbar.setText(f"Exported {len(events)} threat events")

    def _threat_ctx(self, pos):
        row = self._threat_tbl.rowAt(pos.y())
        if row < 0: return
        ip_item = self._threat_tbl.item(row, 3)
        if not ip_item: return
        ip = ip_item.text()
        menu = QMenu(self)
        menu.addAction(f"Block IP: {ip}", lambda: self._action_block_ip(ip))
        menu.addAction("Copy IP", lambda: QApplication.clipboard().setText(ip))
        menu.addAction("WHOIS Lookup", lambda: self._whois_lookup(ip))
        menu.exec(self._threat_tbl.viewport().mapToGlobal(pos))

    def _clear(self):
        self._conn_data.clear(); self._conn_tbl.setRowCount(0)
        self._dash_conn.setValue("0"); self._dash_blk.setValue("0")
        self._sbar.setText("Connection table cleared")

    # ================================================================
    #  SETTINGS / ABOUT / CLOSE
    # ================================================================
    def _open_settings(self):
        dlg = SettingsDialog(self)
        dlg.exec()

    def _open_about(self):
        dlg = AboutDialog(self)
        dlg.exec()

    def changeEvent(self, event):
        if event.type() == event.Type.WindowStateChange:
            if self.windowState() & Qt.WindowState.WindowMinimized:
                # Minimize to tray instead of taskbar
                QTimer.singleShot(0, self._minimize_to_tray)
                event.ignore()
                return
        super().changeEvent(event)

    def _minimize_to_tray(self):
        self.hide()
        self._tray.showMessage(APP, "Minimized to tray. Click icon to restore.", QSystemTrayIcon.MessageIcon.Information, 1500)

    def closeEvent(self, event):
        if self._restart_pending:
            self._real_close()
            event.accept()
        elif cfg["tray"]:
            event.ignore(); self.hide()
            self._tray.showMessage(APP, "Running in system tray", QSystemTrayIcon.MessageIcon.Information, 2000)
        else:
            self._real_close()

    def _cleanup_workers(self):
        """Stop all background workers and prune history."""
        if self._monitoring:
            try: self._conn_w.stop()
            except: pass
            try: self._evt_w.stop()
            except: pass
        try: self._dns.stop()
        except: pass
        try: self._who.stop()
        except: pass
        try: self._geo.stop()
        except: pass
        try: conn_db.prune(cfg["history_days"])
        except: pass

    def _real_close(self):
        self._cleanup_workers()
        QApplication.quit()

# ================================================================
#  ENTRY POINT
# ================================================================
def _cli_main():
    """Command-line interface for headless PyWall operations."""
    parser = argparse.ArgumentParser(prog="pywall", description=f"{APP} v{VER} - Windows Firewall Management")
    sub = parser.add_subparsers(dest="cmd")

    # Block/Allow IP
    p_block_ip = sub.add_parser("block-ip", help="Block an IP address")
    p_block_ip.add_argument("ip"); p_block_ip.add_argument("--dir", default="Outbound", choices=["Inbound","Outbound","Both"])
    p_allow_ip = sub.add_parser("allow-ip", help="Allow an IP address")
    p_allow_ip.add_argument("ip"); p_allow_ip.add_argument("--dir", default="Inbound", choices=["Inbound","Outbound","Both"])

    # Block/Allow port
    p_block_port = sub.add_parser("block-port", help="Block a port")
    p_block_port.add_argument("port"); p_block_port.add_argument("--proto", default="TCP", choices=["TCP","UDP"])
    p_allow_port = sub.add_parser("allow-port", help="Allow a port")
    p_allow_port.add_argument("port"); p_allow_port.add_argument("--proto", default="TCP", choices=["TCP","UDP"])

    # Block/Allow program
    p_block_prog = sub.add_parser("block-program", help="Block a program")
    p_block_prog.add_argument("path")
    p_allow_prog = sub.add_parser("allow-program", help="Allow a program")
    p_allow_prog.add_argument("path")

    # List/export/import
    sub.add_parser("list-rules", help="List all PyWall rules")
    p_export = sub.add_parser("export", help="Export full config to JSON")
    p_export.add_argument("file", nargs="?", default="pywall_config.json")
    p_import = sub.add_parser("import", help="Import config from JSON")
    p_import.add_argument("file")

    # Health check
    sub.add_parser("health-check", help="Run rule conflict analysis")

    # Status
    sub.add_parser("status", help="Show current firewall status")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help(); return

    if args.cmd == "block-ip":
        dirs = ["Inbound","Outbound"] if args.dir == "Both" else [args.dir]
        for d in dirs:
            ok, out = fw.block_ip(args.ip, d)
            print(f"{'OK' if ok else 'FAIL'}: Block {args.ip} ({d}) - {out.strip()[:120]}")
    elif args.cmd == "allow-ip":
        dirs = ["Inbound","Outbound"] if args.dir == "Both" else [args.dir]
        for d in dirs:
            ok, out = fw.allow_ip(args.ip, d)
            print(f"{'OK' if ok else 'FAIL'}: Allow {args.ip} ({d}) - {out.strip()[:120]}")
    elif args.cmd == "block-port":
        ok, out = fw.block_port(args.port, args.proto)
        print(f"{'OK' if ok else 'FAIL'}: Block port {args.port}/{args.proto} - {out.strip()[:120]}")
    elif args.cmd == "allow-port":
        ok, out = fw.allow_port(args.port, args.proto)
        print(f"{'OK' if ok else 'FAIL'}: Allow port {args.port}/{args.proto} - {out.strip()[:120]}")
    elif args.cmd == "block-program":
        ok, out = fw.block_program(args.path)
        print(f"{'OK' if ok else 'FAIL'}: Block {args.path} - {out.strip()[:120]}")
    elif args.cmd == "allow-program":
        ok, out = fw.allow_program(args.path)
        print(f"{'OK' if ok else 'FAIL'}: Allow {args.path} - {out.strip()[:120]}")
    elif args.cmd == "list-rules":
        rules = fw.get_all_rules(force_refresh=True)
        pw_rules = [r for r in rules if r.source == "pywall"]
        print(f"PyWall Rules ({len(pw_rules)} of {len(rules)} total):\n")
        for r in pw_rules:
            status = "ON " if r.enabled else "OFF"
            print(f"  [{status}] {r.action:5s} {r.direction:8s} {r.name}")
            if r.remote_addr and r.remote_addr not in ("*","Any"):
                print(f"         IP: {r.remote_addr[:60]}")
            if r.program:
                print(f"         Program: {Path(r.program).name}")
    elif args.cmd == "export":
        data = exporter.export_all()
        with open(args.file, "w") as f: json.dump(data, f, indent=2)
        print(f"Exported config to {args.file}")
    elif args.cmd == "import":
        if not Path(args.file).exists():
            print(f"File not found: {args.file}"); return
        with open(args.file) as f: data = json.load(f)
        exporter.import_all(data)
        print(f"Imported config from {args.file}")
    elif args.cmd == "health-check":
        issues = conflict_detector.analyze()
        if not issues:
            print("No issues found. Rules look clean!")
        else:
            print(f"Found {len(issues)} issue(s):\n")
            for i, issue in enumerate(issues, 1):
                print(f"  {i}. [{issue['severity'].upper()}] {issue['desc']}")
                print(f"     Rules: {', '.join(issue.get('rules', []))}")
                print(f"     Fix: {issue.get('suggestion', '')}\n")
    elif args.cmd == "status":
        rules = fw.get_all_rules(force_refresh=True)
        pw_rules = [r for r in rules if r.source == "pywall"]
        enabled = sum(1 for r in pw_rules if r.enabled)
        blocks = sum(1 for r in pw_rules if r.action == "Block" and r.enabled)
        allows = sum(1 for r in pw_rules if r.action == "Allow" and r.enabled)
        print(f"{APP} v{VER}")
        print(f"Admin: {'Yes' if IS_ADMIN else 'No'}")
        print(f"Total rules: {len(rules)} ({len(pw_rules)} PyWall)")
        print(f"Active: {enabled} ({blocks} block, {allows} allow)")

def main():
    # Check for CLI mode
    if len(sys.argv) > 1 and sys.argv[1] in ("block-ip","allow-ip","block-port","allow-port",
            "block-program","allow-program","list-rules","export","import",
            "health-check","status","--help","-h"):
        _cli_main()
        return

    # Hide console window for GUI mode
    _hide_console()

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName(APP)

    # Tray icon availability check
    if not QSystemTrayIcon.isSystemTrayAvailable():
        cfg["tray"] = False

    window = MainWindow()
    window.show()
    exit_code = app.exec()

    # Always clean up workers when the event loop exits
    window._cleanup_workers()

    # If a theme change was requested, restart after the app has fully exited
    if getattr(window, '_restart_pending', False):
        subprocess.Popen([sys.executable] + sys.argv,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
