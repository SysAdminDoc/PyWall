#!/usr/bin/env python3
"""
PyWall v4.1.26 - Windows Firewall & Network Command Center
Combined hosts file management + Windows Firewall control + live connection
monitoring. Block domains via hosts file OR firewall rules. Full local system control.
"""
import multiprocessing
multiprocessing.freeze_support()

import sys, os, subprocess, json, sqlite3, re, shutil, time, threading, hashlib, csv, io, html
import tempfile, webbrowser, socket, datetime, ipaddress, logging
import argparse, signal, hmac, secrets, fnmatch
from pathlib import Path
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from queue import Queue, Empty
from threading import Lock, Event as TEvent
import urllib.request, urllib.error, urllib.parse


def _branding_icon_path() -> Path:
    candidates = []
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.append(exe_dir / "icon.png")
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "icon.png")
    current = Path(__file__).resolve()
    candidates.extend([current.parent / "icon.png", current.parent.parent / "icon.png", current.parent.parent.parent / "icon.png"])
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return Path("icon.png")


# ─── DPI Awareness ───────────────────────────────────────────────────────────
os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
if hasattr(sys, 'getwindowsversion'):
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
    except: pass

# ─── Bootstrap ───────────────────────────────────────────────────────────────
NOWIN = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)

def _is_frozen():
    return getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS")

def _missing_dependency_message(missing):
    packages = ", ".join(missing)
    return (
        f"Missing required runtime dependencies: {packages}\n"
        "Install them before launching PyWall:\n"
        f"  {sys.executable} -m pip install -r requirements.txt"
    )

def _check_dependencies():
    deps = [('PyQt5', 'PyQt5'), ('psutil', 'psutil'), ('maxminddb', 'maxminddb')]
    if sys.platform == 'win32':
        deps.append(('pywin32', 'win32serviceutil'))
    missing = []
    for pkg, mod in deps:
        try: __import__(mod)
        except ImportError: missing.append(pkg)
    if missing:
        print(_missing_dependency_message(missing), file=sys.stderr)
        sys.exit(2)

def _kill_remnants():
    """Kill leftover PyWall python/powershell processes from prior runs."""
    if sys.platform != 'win32': return
    my_pid = os.getpid()
    my_script = os.path.abspath(__file__).lower()
    try:
        import psutil as _ps_mod
        for proc in _ps_mod.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['pid'] == my_pid: continue
                name = (proc.info['name'] or '').lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                # Kill python processes running this script
                if 'python' in name and my_script in cmdline:
                    proc.kill()
                # Kill orphaned powershell spawned by PyWall.
                elif 'powershell' in name and (('pywall' in cmdline or 'hostsguard' in cmdline) or 'get-dnsclientcache' in cmdline
                        or 'get-netfirewallrule' in cmdline or 'get-winevent' in cmdline):
                    proc.kill()
            except: continue
    except ImportError:
        # psutil not yet installed — use tasklist/taskkill fallback
        try:
            r = subprocess.run(['wmic', 'process', 'where',
                f'CommandLine like "%{os.path.basename(__file__)}%" and ProcessId != "{my_pid}"',
                'get', 'ProcessId'], capture_output=True, text=True, timeout=10, creationflags=NOWIN)
            for line in r.stdout.splitlines():
                pid = line.strip()
                if pid.isdigit() and int(pid) != my_pid:
                    subprocess.run(['taskkill', '/F', '/PID', pid], capture_output=True, timeout=5, creationflags=NOWIN)
        except: pass
    except: pass

def _bootstrap():
    """Elevate to admin + install missing deps. Must run BEFORE heavy imports."""
    if sys.version_info < (3, 8):
        print("Python 3.8+ required"); sys.exit(1)
    _check_dependencies()
    if sys.platform == 'win32':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            try:
                hwnd = ctypes.windll.kernel32.GetConsoleWindow()
                hwnd.setWindowIcon(branding_icon)
                if hwnd: ctypes.windll.user32.ShowWindow(hwnd, 0)
            except: pass
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                " ".join([f'"{os.path.abspath(__file__)}"'] + [f'"{a}"' for a in sys.argv[1:]]), None, 1)
            os._exit(0)
    # We're admin now — kill remnants from prior crashed runs
    _kill_remnants()
_bootstrap()

import psutil
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

log = logging.getLogger("PyWall"); logging.basicConfig(level=logging.WARNING)

# ─── Constants ───────────────────────────────────────────────────────────────
APP_NAME = "PyWall"
APP_VERSION = "4.1.26"
FW_PFX = "PW_"  # Firewall rule prefix
LEGACY_FW_PFX = ("HG_",)
FW_RULE_PREFIXES = (FW_PFX,) + LEGACY_FW_PFX
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts" if sys.platform == 'win32' else "/etc/hosts"
BLOCK_IPS = {"0.0.0.0", "127.0.0.1", "::0", "::1"}
CONFIG_DIR = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), APP_NAME)
LEGACY_CONFIG_DIR = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), "HostsGuard")
if not os.path.exists(CONFIG_DIR) and os.path.isdir(LEGACY_CONFIG_DIR):
    try: shutil.copytree(LEGACY_CONFIG_DIR, CONFIG_DIR, dirs_exist_ok=True)
    except Exception as e: log.warning(f"Config migration skipped: {e}")
DB_PATH = os.path.join(CONFIG_DIR, "pywall.db")
LEGACY_DB_PATH = os.path.join(CONFIG_DIR, "hostsguard.db")
if not os.path.exists(DB_PATH) and os.path.exists(LEGACY_DB_PATH):
    try: shutil.copy2(LEGACY_DB_PATH, DB_PATH)
    except Exception as e: log.warning(f"DB migration skipped: {e}")
CONN_DB_PATH = os.path.join(CONFIG_DIR, "connections.db")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
FAVICON_DIR = os.path.join(CONFIG_DIR, "favicons")
REPORT_DIR = os.path.join(CONFIG_DIR, "reports")
IDS_RULES_PATH = os.path.join(CONFIG_DIR, "ids_rules.yaral")
FEED_CACHE_DIR = os.path.join(CONFIG_DIR, "feed_cache")
PLUGINS_DIR = os.path.join(CONFIG_DIR, "plugins")
TRANSLATION_DIR = os.path.join(CONFIG_DIR, "translations")
PLUGIN_LOG_PATH = os.path.join(CONFIG_DIR, "plugin_events.log")
FW_TAMPER_LOG_PATH = os.path.join(CONFIG_DIR, "firewall_tamper.log")
PLUGIN_MANIFEST_NAMES = ("pywall-plugin.json", "plugin.json")
PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,79}$")
PLUGIN_ALLOWED_HOOKS = {
    "connection_observed",
    "dns_domain_seen",
    "threat_detected",
    "notification",
    "report_generated",
    "feed_import",
    "geoip_lookup",
    "service_snapshot",
}
PLUGIN_ALLOWED_PERMISSION_KEYS = {"network", "files", "firewall", "notifications", "reports", "config"}
os.makedirs(CONFIG_DIR, exist_ok=True); os.makedirs(FAVICON_DIR, exist_ok=True); os.makedirs(FEED_CACHE_DIR, exist_ok=True); os.makedirs(PLUGINS_DIR, exist_ok=True)
SERVICE_NAME = "PyWallService"
SERVICE_DISPLAY_NAME = "PyWall Background Service"
SERVICE_DESCRIPTION = "Headless PyWall connection monitor and threat auto-blocker."
SERVICE_STATE_DIR = os.path.join(os.environ.get("PROGRAMDATA", CONFIG_DIR), APP_NAME) if sys.platform == "win32" else CONFIG_DIR
try: os.makedirs(SERVICE_STATE_DIR, exist_ok=True)
except: SERVICE_STATE_DIR = CONFIG_DIR
SERVICE_LOG_PATH = os.path.join(SERVICE_STATE_DIR, "service.log")
IPC_PIPE_NAME = r"\\.\pipe\PyWallService"
IPC_TOKEN_PATH = os.path.join(SERVICE_STATE_DIR, "service.token")
SERVICE_STATE_PATH = os.path.join(SERVICE_STATE_DIR, "service_state.json")
QUOTA_STATE_PATH = os.path.join(CONFIG_DIR, "quota_state.json")
GEOIP_HTTPS_ENDPOINT = "https://ipwho.is/{ip}"
CONFIG_SCHEMA_VERSION = 1
CONFIG_DEFAULTS = {
    "schema_version": CONFIG_SCHEMA_VERSION,
    "theme": "Charcoal",
    "tray": True,
    "toast": True,
    "toast_sec": 10,
    "start_monitoring": False,
    "learning_mode_enabled": True,
    "learning_mode_window_minutes": 10.0,
    "history_days": 30,
    "threat_auto_block": False,
    "service_auto_block": True,
    "service_poll_seconds": 2.0,
    "bandwidth_quotas": {},
    "tls_sni_enabled": False,
    "tls_sni_log_path": "",
    "tls_sni_read_existing": False,
    "detect_doh": True,
    "doh_action": "warn",
    "ids_rules_enabled": True,
    "ids_rules_path": IDS_RULES_PATH,
    "event_correlation_enabled": True,
    "sysmon_event_correlation_enabled": False,
    "geoip_provider": "ipwhois",
    "geoip_https_endpoint": GEOIP_HTTPS_ENDPOINT,
    "geoip_mmdb_path": "",
    "plugins_enabled": False,
    "plugin_enabled_ids": [],
    "plugin_disabled_ids": [],
    "auto_block_inbound": True,
    "detect_portscan": True,
    "detect_bruteforce": True,
    "vt_api_key": "",
    "notif_severity_threshold": "low",
    "notif_snooze_minutes": 5,
    "notif_digest_enabled": False,
    "notif_digest_interval_minutes": 15,
}

@dataclass
class ConfigLoadResult:
    data:dict
    mtime:float|None=None
    recovered:bool=False
    backup_path:str=""
    warnings:list=field(default_factory=list)

def _coerce_config_value(key, value):
    default = CONFIG_DEFAULTS[key]
    if key == "schema_version":
        try: value = int(value)
        except: raise ValueError("must be an integer")
        if value < 1: raise ValueError("must be >= 1")
        return min(value, CONFIG_SCHEMA_VERSION)
    if isinstance(default, bool):
        if isinstance(value, bool): return value
        if isinstance(value, str) and value.lower() in ("true","1","yes","on"): return True
        if isinstance(value, str) and value.lower() in ("false","0","no","off"): return False
        raise ValueError("must be true or false")
    if isinstance(default, int) and not isinstance(default, bool):
        try: value = int(value)
        except: raise ValueError("must be an integer")
        return max(0, value)
    if isinstance(default, float):
        try: value = float(value)
        except: raise ValueError("must be a number")
        return max(1.0, value)
    if isinstance(default, dict):
        if isinstance(value, dict): return value
        raise ValueError("must be an object")
    if isinstance(default, list):
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        raise ValueError("must be a list")
    text = str(value if value is not None else "")
    if key == "doh_action" and text.lower() not in ("warn","block","ignore"):
        raise ValueError("must be warn, block, or ignore")
    if key == "geoip_provider" and text.lower() not in ("ipwhois","maxmind","disabled"):
        raise ValueError("must be ipwhois, maxmind, or disabled")
    if key == "geoip_https_endpoint" and text and not text.lower().startswith("https://"):
        raise ValueError("must start with https://")
    if key == "notif_severity_threshold" and text.lower() not in ("low","medium","high"):
        raise ValueError("must be low, medium, or high")
    return text.lower() if key in ("doh_action","geoip_provider","notif_severity_threshold") else text

def _validate_runtime_config(raw):
    warnings=[]; out=dict(CONFIG_DEFAULTS)
    if not isinstance(raw, dict):
        raise ValueError("config root must be an object")
    for key,value in raw.items():
        if key not in CONFIG_DEFAULTS:
            warnings.append(f"unknown config field ignored by runtime: {key}")
            out[key]=value
            continue
        try:
            out[key]=_coerce_config_value(key,value)
        except ValueError as e:
            warnings.append(f"invalid config field {key}: {e}; using default")
            out[key]=CONFIG_DEFAULTS[key]
    out["schema_version"]=CONFIG_SCHEMA_VERSION
    return out,warnings

def _write_json_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)

def _config_backup_path(path, reason="corrupt"):
    stamp=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{path}.{reason}.{stamp}.bak"

def load_runtime_config(path=CONFIG_PATH, recover=True):
    if not os.path.exists(path):
        data=dict(CONFIG_DEFAULTS)
        if recover:
            try: _write_json_atomic(path,data)
            except: pass
        try: mtime=os.path.getmtime(path)
        except: mtime=None
        return ConfigLoadResult(data=data,mtime=mtime,warnings=["config missing; defaults created" if recover else "config missing"])
    try:
        with open(path,"r",encoding="utf-8") as f: raw=json.load(f)
        data,warnings=_validate_runtime_config(raw)
        if data != raw and recover:
            try: _write_json_atomic(path,data)
            except Exception as e: warnings.append(f"config rewrite failed: {e}")
        try: mtime=os.path.getmtime(path)
        except: mtime=None
        return ConfigLoadResult(data=data,mtime=mtime,warnings=warnings)
    except Exception as e:
        warnings=[f"config recovery: {e}"]
        backup=""
        if recover:
            try:
                backup=_config_backup_path(path)
                shutil.copy2(path,backup)
                _write_json_atomic(path,dict(CONFIG_DEFAULTS))
            except Exception as be:
                warnings.append(f"config backup/write failed: {be}")
        try: mtime=os.path.getmtime(path)
        except: mtime=None
        return ConfigLoadResult(data=dict(CONFIG_DEFAULTS),mtime=mtime,recovered=bool(backup),backup_path=backup,warnings=warnings)

_active_translator = None

def _tr(text):
    return QCoreApplication.translate("PyWall", str(text or ""))

def load_translation(app, locale_name=None):
    global _active_translator
    locale_name = locale_name or QLocale.system().name()
    translator = QTranslator(app)
    loaded = translator.load(f"pywall_{locale_name}", TRANSLATION_DIR)
    if not loaded and "_" in locale_name:
        loaded = translator.load(f"pywall_{locale_name.split('_',1)[0]}", TRANSLATION_DIR)
    if loaded:
        app.installTranslator(translator)
        _active_translator = translator
    return bool(loaded)

def _a11y(widget, name, desc="", tooltip=None):
    try: widget.setAccessibleName(_tr(name))
    except: pass
    if desc:
        try: widget.setAccessibleDescription(_tr(desc))
        except: pass
    if tooltip:
        try: widget.setToolTip(_tr(tooltip))
        except: pass
    return widget

# ─── Notification Fatigue Controller ─────────────────────────────────────────
SEVERITY_LEVELS = {"low": 0, "medium": 1, "high": 2}

@dataclass
class NotifDigestEntry:
    key:str
    severity:str
    title:str
    message:str
    ts:float

class NotificationController:
    def __init__(self, config=None):
        self._lock = Lock()
        self._cooldowns = {}
        self._snoozed = {}
        self._digest = []
        self._launch_time = time.time()
        self._last_digest_time = time.time()
        self.reload_config(config or {})

    def reload_config(self, config):
        self._threshold = SEVERITY_LEVELS.get(str(config.get("notif_severity_threshold", "low")).lower(), 0)
        self._snooze_sec = max(60, int(config.get("notif_snooze_minutes", 5) or 5) * 60)
        self._digest_enabled = bool(config.get("notif_digest_enabled", False))
        self._digest_interval = max(60, int(config.get("notif_digest_interval_minutes", 15) or 15) * 60)
        self._warmup_sec = 15

    def should_notify(self, key, severity="low", title="", message=""):
        level = SEVERITY_LEVELS.get(severity, 0)
        now = time.time()
        with self._lock:
            if now - self._launch_time < self._warmup_sec:
                return False
            if key in self._snoozed and now < self._snoozed[key]:
                return False
            if level < self._threshold:
                if self._digest_enabled:
                    self._digest.append(NotifDigestEntry(key=key, severity=severity, title=title, message=message, ts=now))
                return False
            if key in self._cooldowns and now - self._cooldowns[key] < self._snooze_sec:
                if self._digest_enabled:
                    self._digest.append(NotifDigestEntry(key=key, severity=severity, title=title, message=message, ts=now))
                return False
            self._cooldowns[key] = now
            return True

    def snooze(self, key, minutes=None):
        with self._lock:
            self._snoozed[key] = time.time() + (minutes or self._snooze_sec // 60) * 60

    def drain_digest(self):
        now = time.time()
        with self._lock:
            if now - self._last_digest_time < self._digest_interval:
                return []
            self._last_digest_time = now
            items = list(self._digest)
            self._digest.clear()
            return items

    def pending_digest_count(self):
        with self._lock:
            return len(self._digest)

@dataclass
class PluginManifest:
    plugin_id:str
    name:str
    version:str
    manifest_path:str
    enabled:bool=False
    hooks:list=field(default_factory=list)
    permissions:dict=field(default_factory=dict)
    trust_state:str="unknown"
    publisher:str=""
    signature:str=""
    executable:bool=False
    disabled_reason:str=""
    errors:list=field(default_factory=list)

    def as_dict(self):
        return {
            "id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "manifest_path": self.manifest_path,
            "enabled": self.enabled,
            "hooks": list(self.hooks),
            "permissions": dict(self.permissions),
            "trust_state": self.trust_state,
            "publisher": self.publisher,
            "executable": self.executable,
            "disabled_reason": self.disabled_reason,
            "errors": list(self.errors),
        }

@dataclass
class PluginScanResult:
    plugins:list=field(default_factory=list)
    errors:list=field(default_factory=list)

    def summary(self):
        total=len(self.plugins)
        invalid=sum(1 for p in self.plugins if p.errors)
        return {
            "total": total,
            "valid": total - invalid,
            "invalid": invalid,
            "enabled": sum(1 for p in self.plugins if p.enabled),
            "executable": sum(1 for p in self.plugins if p.executable),
            "signed": sum(1 for p in self.plugins if p.trust_state == "signed"),
            "unsigned": sum(1 for p in self.plugins if p.trust_state == "unsigned"),
            "unknown": sum(1 for p in self.plugins if p.trust_state == "unknown"),
            "errors": list(self.errors),
        }

def _safe_plugin_id(value):
    text=str(value or "").strip().lower()
    return text if PLUGIN_ID_RE.match(text) else ""

def _plugin_log(msg, level="INFO"):
    line=f"{datetime.datetime.now().isoformat(timespec='seconds')} [{level}] {msg}"
    try:
        with open(PLUGIN_LOG_PATH,"a",encoding="utf-8") as f: f.write(line + "\n")
    except: pass
    logger=getattr(log, level.lower(), None) or getattr(log, "info", None)
    if logger: logger(msg)

class PluginRegistry:
    def __init__(self, plugin_dir=PLUGINS_DIR, config=None):
        self.plugin_dir=plugin_dir
        self.config=config

    def _config(self):
        if self.config is not None:
            return self.config
        return load_runtime_config().data

    def scan(self, log_errors=True):
        try: os.makedirs(self.plugin_dir, exist_ok=True)
        except Exception as e:
            msg=f"Plugin directory unavailable: {e}"
            if log_errors: _plugin_log(msg,"WARNING")
            return PluginScanResult(errors=[msg])
        cfg=self._config()
        plugins=[]; errors=[]
        for manifest_path in self._manifest_paths():
            manifest=self._load_manifest(manifest_path,cfg)
            plugins.append(manifest)
            if manifest.errors:
                msg=f"Plugin {manifest.plugin_id or manifest.manifest_path} invalid: {'; '.join(manifest.errors)}"
                errors.append(msg)
                if log_errors: _plugin_log(msg,"WARNING")
        return PluginScanResult(plugins=plugins, errors=errors)

    def can_execute(self, plugin_id, hook):
        wanted=_safe_plugin_id(plugin_id)
        if not wanted: return False
        for plugin in self.scan(log_errors=False).plugins:
            if plugin.plugin_id == wanted:
                return bool(plugin.executable and hook in plugin.hooks)
        return False

    def _manifest_paths(self):
        root=Path(self.plugin_dir)
        if not root.exists(): return []
        paths=[]
        try:
            for name in PLUGIN_MANIFEST_NAMES:
                path=root / name
                if path.is_file(): paths.append(path)
            for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
                if not child.is_dir(): continue
                for name in PLUGIN_MANIFEST_NAMES:
                    path=child / name
                    if path.is_file():
                        paths.append(path)
                        break
        except Exception as e:
            _plugin_log(f"Plugin scan failed: {e}","WARNING")
        return paths

    def _load_manifest(self, path, cfg):
        errors=[]
        try:
            with open(path,"r",encoding="utf-8") as f: raw=json.load(f)
            if not isinstance(raw,dict):
                raise ValueError("manifest root must be an object")
        except Exception as e:
            return PluginManifest("", path.parent.name, "0.0.0", str(path), errors=[f"manifest read failed: {e}"], disabled_reason="invalid manifest")
        plugin_id=_safe_plugin_id(raw.get("id") or path.parent.name)
        if not plugin_id: errors.append("id must match [A-Za-z0-9_.-] and be 2-80 chars")
        name=str(raw.get("name") or plugin_id or path.parent.name).strip() or "Unnamed Plugin"
        version=str(raw.get("version") or "0.0.0").strip() or "0.0.0"
        enabled=bool(raw.get("enabled", False))
        hooks=self._parse_hooks(raw.get("hooks"), errors)
        permissions=self._parse_permissions(raw.get("permissions"), errors)
        trust=raw.get("trust") if isinstance(raw.get("trust"),dict) else {}
        publisher=str(raw.get("publisher") or trust.get("publisher") or "").strip()
        signature=str(raw.get("signature") or trust.get("signature") or "").strip()
        trust_state="signed" if signature else "unsigned" if publisher else "unknown"
        enabled_ids={_safe_plugin_id(x) for x in cfg.get("plugin_enabled_ids",[]) or []}
        disabled_ids={_safe_plugin_id(x) for x in cfg.get("plugin_disabled_ids",[]) or []}
        global_enabled=bool(cfg.get("plugins_enabled",False))
        if errors:
            executable=False; disabled_reason="invalid manifest"
        elif not global_enabled:
            executable=False; disabled_reason="plugins disabled in config"
        elif plugin_id in disabled_ids:
            executable=False; disabled_reason="disabled in config"
        elif not enabled:
            executable=False; disabled_reason="manifest disabled"
        elif plugin_id not in enabled_ids:
            executable=False; disabled_reason="not allowlisted in config"
        else:
            executable=True; disabled_reason=""
        return PluginManifest(plugin_id,name,version,str(path),enabled,hooks,permissions,trust_state,publisher,signature,executable,disabled_reason,errors)

    def _parse_hooks(self, value, errors):
        if not isinstance(value,list) or not value:
            errors.append("hooks must declare at least one event hook")
            return []
        hooks=[]
        for raw_hook in value:
            hook=str(raw_hook or "").strip()
            if hook not in PLUGIN_ALLOWED_HOOKS:
                errors.append(f"unsupported hook: {hook or '<empty>'}")
            elif hook not in hooks:
                hooks.append(hook)
        return hooks

    def _parse_permissions(self, value, errors):
        if not isinstance(value,dict):
            errors.append("permissions must declare network and files entries")
            return {}
        permissions={}
        if "network" not in value:
            errors.append("permissions.network must be declared")
        if "files" not in value:
            errors.append("permissions.files must be declared")
        for raw_key, raw_value in value.items():
            key=str(raw_key or "").strip()
            if key not in PLUGIN_ALLOWED_PERMISSION_KEYS:
                errors.append(f"unsupported permission: {key or '<empty>'}")
                continue
            if key in ("network","files"):
                if raw_value in (None, False):
                    permissions[key]=[]
                elif isinstance(raw_value,list):
                    permissions[key]=[str(v).strip() for v in raw_value if str(v).strip()]
                else:
                    errors.append(f"permissions.{key} must be a list")
            else:
                if isinstance(raw_value,bool):
                    permissions[key]=raw_value
                else:
                    errors.append(f"permissions.{key} must be true or false")
        permissions.setdefault("network",[])
        permissions.setdefault("files",[])
        return permissions

def _service_log(msg, level="INFO"):
    line = f"{datetime.datetime.now().isoformat(timespec='seconds')} [{level}] {msg}"
    try:
        with open(SERVICE_LOG_PATH, "a", encoding="utf-8") as f: f.write(line + "\n")
    except: pass
    getattr(log, level.lower(), log.info)(msg)

try:
    import win32serviceutil, win32service, servicemanager, win32pipe, win32file, pywintypes
    import win32security, ntsecuritycon
except ImportError:
    win32serviceutil = win32service = servicemanager = win32pipe = win32file = pywintypes = None
    win32security = ntsecuritycon = None

if win32serviceutil is not None:
    class PyWallWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_event.set()

        def SvcDoRun(self):
            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} starting")
            try:
                run_headless_service(stop_event=self._stop_event, auto_block=True)
            except Exception as e:
                _service_log(f"Service crashed: {e}", "ERROR")
                servicemanager.LogErrorMsg(f"{SERVICE_DISPLAY_NAME} crashed: {e}")
                raise
            finally:
                servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} stopped")
else:
    PyWallWindowsService = None

IGNORED_DOMAINS = {'localhost','localhost.localdomain','local','broadcasthost','ip6-localhost','ip6-loopback','wpad','isatap'}
DOMAIN_RE = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')
IPV4_RE = re.compile(r'^(25[0-5]|2[0-4]\d|[01]?\d\d?\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
WILDCARD_RE = re.compile(r'^\*\.?(.*)')
PRIV_RE = re.compile(r'^(0\.0\.0\.0|127\.|::1$|::$|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|fe80:|fd)')
PORTS = {20:"FTP-D",21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",123:"NTP",
         135:"RPC",143:"IMAP",389:"LDAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",
         1433:"MSSQL",3306:"MySQL",3389:"RDP",5353:"mDNS",5432:"Postgres",5900:"VNC",8080:"Alt-HTTP"}

WINDOWS_HEADER = ["# Copyright (c) 1993-2009 Microsoft Corp.","#","# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.","#",
    "# This file contains the mappings of IP addresses to host names.","#","#\t127.0.0.1       localhost","#\t::1             localhost",""]
MULTI_TLDS = {'co.uk','co.jp','co.kr','co.nz','co.za','co.in','com.au','com.br','com.cn','com.mx','com.tw','com.hk','com.sg',
    'com.ar','com.tr','net.au','org.au','org.uk','ac.uk','gov.uk','ne.jp','or.jp','co.il','co.th','co.id','com.my','com.ph',
    'com.vn','com.pk','com.ng','com.eg','com.ua','com.co','com.pe','com.ec','co.ke'}

RESEARCH_SITES = [("VirusTotal","https://www.virustotal.com/gui/domain/{domain}"),("who.is","https://who.is/whois/{domain}"),
    ("URLScan.io","https://urlscan.io/search/#{domain}"),("Shodan","https://www.shodan.io/search?query={domain}"),
    ("SecurityTrails","https://securitytrails.com/domain/{domain}"),("MXToolbox","https://mxtoolbox.com/SuperTool.aspx?action=dns%3a{domain}&run=toolpage"),
    ("AbuseIPDB","https://www.abuseipdb.com/check/{domain}"),("ThreatCrowd","https://www.threatcrowd.org/domain.php?domain={domain}"),
    ("DNSDumpster","https://dnsdumpster.com/?q={domain}")]

_CATEGORIES = {
    "Streaming": {"netflix","hulu","disney","twitch","youtube","spotify","deezer","tidal","plex","crunchyroll","roku","primevideo"},
    "Social Media": {"facebook","instagram","twitter","x.com","tiktok","snapchat","reddit","linkedin","pinterest","threads"},
    "Gaming": {"steam","valve","epicgames","riotgames","blizzard","battle.net","xbox","playstation","ea.com","ubisoft"},
    "Cloud Storage": {"dropbox","onedrive","gdrive","icloud","box.com","mega.nz","googledrive","sharepoint"},
    "Messaging": {"discord","slack","telegram","whatsapp","signal","teams","zoom","webex","skype"},
    "Development": {"github","gitlab","bitbucket","stackoverflow","npmjs","pypi","docker","aws","azure","gcp"},
    "Security": {"virustotal","malwarebytes","norton","kaspersky","avast","mcafee","crowdstrike"},
    "Microsoft": {"microsoft.com","windows.net","msedge","bing.com","live.com","outlook","office"},
    "Google": {"google","googleapis","gstatic","youtube","doubleclick","googlevideo","gvt1","gvt2"},
    "CDN": {"akamai","cloudflare","fastly","cloudfront","edgecast","jsdelivr","unpkg"},
}

# ─── Blocklist Sources ───────────────────────────────────────────────────────
BLOCKLIST_SOURCES = {
    "Major / Unified": [
        ("HaGezi Ultimate","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/ultimate.txt"),
        ("HaGezi TIF","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/tif.txt"),
        ("StevenBlack Unified","https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
        ("OISD Full","https://hosts.oisd.nl/"),("OISD DBL","https://dbl.oisd.nl/"),
        ("MVPS Hosts","https://winhelp2002.mvps.org/hosts.txt"),
        ("SomeoneWhoCares","https://someonewhocares.org/hosts/zero/hosts"),
        ("HOSTShield Combined","https://github.com/SysAdminDoc/HOSTShield/releases/download/v.1/CombinedAll.txt"),
        ("The Great Wall","https://raw.githubusercontent.com/Sekhan/TheGreatWall/master/TheGreatWall.txt"),],
    "Ads / Tracking": [
        ("Disconnect Tracking","https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt"),
        ("Disconnect Ads","https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"),
        ("DevDan Ads Extended","https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt"),
        ("EasyList Hosts","https://v.firebog.net/hosts/Easylist.txt"),("EasyPrivacy Hosts","https://v.firebog.net/hosts/Easyprivacy.txt"),
        ("Prigent Ads","https://v.firebog.net/hosts/Prigent-Ads.txt"),
        ("Yoyo Ad Servers","https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
        ("Anudeep Ad Servers","https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt"),
        ("AdAway","https://adaway.org/hosts.txt"),("AdGuard DNS","https://v.firebog.net/hosts/AdguardDNS.txt"),
        ("NoCoin","https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"),
        ("HOSTShield Ads","https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdsTrackingAnalytics.txt"),
        ("Adobe Hosts","https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/AdobeHosts.txt"),],
    "Telemetry / Privacy": [
        ("Windows Spy Blocker","https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"),
        ("Frogeye 1st Party","https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt"),
        ("Frogeye Multi Party","https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt"),
        ("NoTrack Tracking","https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt"),
        ("Perflyst Android","https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt"),
        ("Perflyst SmartTV","https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt"),],
    "Malware / Phishing": [
        ("NoTrack Malware","https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt"),
        ("Spam404","https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt"),
        ("DandelionSprout","https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt"),
        ("Prigent Malware","https://v.firebog.net/hosts/Prigent-Malware.txt"),("Prigent Crypto","https://v.firebog.net/hosts/Prigent-Crypto.txt"),
        ("RPiList Malware","https://v.firebog.net/hosts/RPiList-Malware.txt"),("RPiList Phishing","https://v.firebog.net/hosts/RPiList-Phishing.txt"),
        ("Phishing Army","https://phishing.army/download/phishing_army_blocklist.txt"),("URLHaus","https://urlhaus.abuse.ch/downloads/hostfile/"),
        ("Stamparm Maltrail","https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt"),
        ("Disconnect Malware","https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt"),
        ("Badd Boyz","https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts"),],
    "Vendor / Platform": [
        ("Amazon Native","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.amazon.txt"),
        ("Apple Native","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.apple.txt"),
        ("Windows/Office","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.winoffice.txt"),
        ("Samsung Native","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.samsung.txt"),
        ("TikTok Extended","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.tiktok.extended.txt"),
        ("LG WebOS","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.lgwebos.txt"),
        ("Roku Native","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.roku.txt"),
        ("Xiaomi Native","https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/native.xiaomi.txt"),
        ("HOSTShield Apple","https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Apple.txt"),
        ("HOSTShield MS","https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Microsoft.txt"),
        ("HOSTShield TikTok","https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Tiktok.txt"),],
}

# ─── Theme (Catppuccin Mocha + Pro refinements) ─────────────────────────────
C = {"bg":"#0e0e16","base":"#1a1a2e","mantle":"#141422","crust":"#0e0e16","surface0":"#282842",
    "surface1":"#3a3a5c","surface2":"#4a4a6a","text":"#e2e4f0","subtext":"#a0a4c0","overlay":"#6a6e8e",
    "blue":"#7aa2f7","green":"#9ece6a","red":"#f7768e","peach":"#ff9e64","yellow":"#e0af68",
    "mauve":"#bb9af7","teal":"#73daca","sky":"#7dcfff","lavender":"#b4befe","rosewater":"#f5e0dc",
    "accent":"#7aa2f7","card_bg":"rgba(26,26,46,0.85)","card_border":"rgba(58,58,92,0.5)",
    "glow":"rgba(122,162,247,0.08)","sel_bg":"rgba(122,162,247,0.15)"}

def _dp(px):
    """Scale pixel value for DPI. Called after QApplication exists."""
    try:
        s = QApplication.primaryScreen()
        if s: return max(1, int(px * s.logicalDotsPerInch() / 96.0))
    except: pass
    return px

DARK_STYLE = f"""
* {{ font-family:'Segoe UI Variable','Segoe UI','Inter','SF Pro Display',sans-serif; }}
QMainWindow {{ background:{C['bg']}; }}
QWidget {{ background:transparent; color:{C['text']}; }}

/* ── Menu ── */
QMenuBar {{ background:{C['crust']}; color:{C['subtext']}; border-bottom:1px solid {C['surface0']}; padding:3px 0; }}
QMenuBar::item {{ padding:7px 14px; border-radius:5px; }} QMenuBar::item:selected {{ background:{C['surface0']}; color:{C['text']}; }}
QMenu {{ background:{C['mantle']}; border:1px solid {C['surface1']}; border-radius:10px; padding:6px; }}
QMenu::item {{ padding:8px 28px; border-radius:5px; color:{C['subtext']}; }} QMenu::item:selected {{ background:{C['surface0']}; color:{C['text']}; }}
QMenu::separator {{ height:1px; background:{C['surface0']}; margin:5px 10px; }}

/* ── Buttons ── */
QPushButton {{ background:{C['surface0']}; color:{C['subtext']}; border:1px solid {C['surface1']}; padding:7px 18px;
    border-radius:8px; font-weight:600; font-size:12px; }}
QPushButton:hover {{ background:{C['surface1']}; color:{C['text']}; border-color:{C['surface2']}; }}
QPushButton:pressed {{ background:{C['surface0']}; }}
QPushButton:disabled {{ background:{C['surface0']}; color:{C['overlay']}; border-color:{C['surface0']}; }}
QPushButton[class="primary"] {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #5b7ee5,stop:1 {C['blue']}); color:#fff; border:none; font-weight:700; }}
QPushButton[class="primary"]:hover {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #6b8ef5,stop:1 #8ab4ff); }}
QPushButton[class="danger"] {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #d5496a,stop:1 {C['red']}); color:#fff; border:none; font-weight:700; }}
QPushButton[class="danger"]:hover {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #e5697a,stop:1 #ff8ea5); }}
QPushButton[class="success"] {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #7ab85a,stop:1 {C['green']}); color:#111; border:none; font-weight:700; }}
QPushButton[class="success"]:hover {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #8ac86a,stop:1 #b0e090); }}
QPushButton[class="warning"] {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #d08040,stop:1 {C['peach']}); color:#111; border:none; font-weight:700; }}
QPushButton[class="dim"] {{ background:{C['surface0']}; color:{C['overlay']}; border:1px solid {C['surface1']}; font-weight:600; }}
QPushButton[class="dim"]:hover {{ color:{C['text']}; background:{C['surface1']}; }}

/* ── Inputs ── */
QLineEdit,QTextEdit,QPlainTextEdit {{ background:{C['mantle']}; color:{C['text']}; border:1px solid {C['surface0']}; border-radius:8px; padding:8px 12px;
    selection-background-color:{C['blue']}; selection-color:#111; }}
QLineEdit:focus,QTextEdit:focus,QPlainTextEdit:focus {{ border-color:{C['blue']}; background:#1c1c30; }}
QComboBox {{ background:{C['mantle']}; color:{C['text']}; border:1px solid {C['surface0']}; border-radius:8px; padding:7px 12px; min-width:90px; }}
QComboBox:focus {{ border-color:{C['blue']}; }}
QComboBox::drop-down {{ border:none; width:28px; }} QComboBox::down-arrow {{ image:none; border-left:5px solid transparent; border-right:5px solid transparent; border-top:6px solid {C['subtext']}; margin-right:8px; }}
QComboBox QAbstractItemView {{ background:{C['mantle']}; color:{C['text']}; border:1px solid {C['surface1']}; selection-background-color:{C['blue']}; selection-color:#111; outline:none; border-radius:6px; padding:4px; }}

/* ── Tabs ── */
QTabWidget::pane {{ border:none; background:{C['base']}; }}
QTabBar {{ background:{C['crust']}; qproperty-drawBase:0; }}
QTabBar::tab {{ background:transparent; color:{C['overlay']}; padding:11px 20px; border:none; border-bottom:2px solid transparent; font-weight:700; font-size:11px; letter-spacing:0.3px; }}
QTabBar::tab:selected {{ color:{C['blue']}; border-bottom-color:{C['blue']}; background:rgba(122,162,247,0.06); }}
QTabBar::tab:hover:!selected {{ color:{C['text']}; background:rgba(122,162,247,0.04); }}
QTabBar::tab:first {{ margin-left:8px; }}

/* ── Tables ── */
QTableWidget,QTableView {{ background:{C['mantle']}; alternate-background-color:rgba(20,20,34,0.5); color:{C['text']}; border:1px solid {C['surface0']}; border-radius:10px;
    gridline-color:rgba(58,58,92,0.3); selection-background-color:{C['sel_bg']}; selection-color:{C['text']}; outline:none; }}
QTableWidget::item,QTableView::item {{ padding:5px 10px; border:none; }} QTableWidget::item:selected,QTableView::item:selected {{ background:{C['sel_bg']}; }}
QHeaderView {{ background:transparent; }}
QHeaderView::section {{ background:{C['crust']}; color:{C['overlay']}; border:none; border-bottom:1px solid {C['surface0']}; border-right:1px solid rgba(58,58,92,0.3);
    padding:9px 12px; font-weight:700; font-size:10px; text-transform:uppercase; letter-spacing:0.8px; }}
QHeaderView::section:first {{ border-top-left-radius:10px; }} QHeaderView::section:last {{ border-top-right-radius:10px; border-right:none; }}

/* ── Scrollbars ── */
QScrollBar:vertical {{ background:transparent; width:7px; margin:4px 0; }} QScrollBar::handle:vertical {{ background:{C['surface1']}; border-radius:3px; min-height:40px; }}
QScrollBar::handle:vertical:hover {{ background:{C['surface2']}; }} QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{ background:transparent; height:7px; margin:0 4px; }} QScrollBar::handle:horizontal {{ background:{C['surface1']}; border-radius:3px; }}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal {{ width:0; }}

/* ── Groups, Progress, Checks ── */
QGroupBox {{ border:1px solid {C['surface0']}; border-radius:12px; margin-top:1.5em; padding:18px 14px 14px; font-weight:700; background:{C['mantle']}; }}
QGroupBox::title {{ subcontrol-origin:margin; left:16px; padding:0 10px; color:{C['blue']}; font-size:11px; letter-spacing:0.5px; }}
QProgressBar {{ background:{C['surface0']}; border:none; border-radius:6px; text-align:center; color:#fff; font-weight:700; min-height:12px; }}
QProgressBar::chunk {{ background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5b7ee5,stop:1 {C['teal']}); border-radius:6px; }}
QCheckBox {{ color:{C['text']}; spacing:8px; }} QCheckBox::indicator {{ width:18px; height:18px; border:2px solid {C['surface1']}; border-radius:5px; background:{C['mantle']}; }}
QCheckBox::indicator:hover {{ border-color:{C['overlay']}; }} QCheckBox::indicator:checked {{ background:{C['blue']}; border-color:{C['blue']}; }}

/* ── Misc ── */
QToolTip {{ background:{C['surface0']}; color:{C['text']}; border:1px solid {C['surface1']}; padding:7px 10px; border-radius:8px; font-size:11px; }}
QStatusBar {{ background:{C['crust']}; color:{C['overlay']}; border-top:1px solid {C['surface0']}; }}
QSplitter::handle {{ background:{C['surface0']}; width:2px; border-radius:1px; }}
QLabel {{ color:{C['text']}; background:transparent; }}
QScrollArea {{ background:transparent; border:none; }}
"""

# ─── Data Structures ────────────────────────────────────────────────────────
@dataclass
class CI:
    key:str=""; ts:str=""; src:str=""; dir:str=""; proto:str=""
    la:str=""; lp:str=""; ra:str=""; rp:str=""
    host:str="-"; proc:str="?"; pid:int=0; svc:str="-"
    parent:str="-"; package:str="-"; signer:str="-"
    state:str=""; path:str=""; org:str="-"; cmd:str=""
    stat:str="-"; country:str="-"; cc:str=""
    category:str=""; bytes_sent:int=0; bytes_recv:int=0
    event_source:str=""; event_id:int=0; event_record_id:int=0; rule_name:str=""; filter_id:str=""

@dataclass
class LearningReviewGroup:
    key:str=""; proc:str=""; path:str=""; signer:str="-"; parent:str="-"
    package:str="-"; svc:str="-"; first_seen:str=""; last_seen:str=""
    count:int=0; endpoints:list=field(default_factory=list); hosts:list=field(default_factory=list); ips:list=field(default_factory=list)

    def record(self, ci):
        now=datetime.datetime.now().isoformat(timespec="seconds")
        if not self.first_seen: self.first_seen=now
        self.last_seen=now; self.count+=1
        endpoint=f"{ci.ra}:{ci.rp}" if ci.rp else str(ci.ra or "")
        if endpoint and endpoint not in self.endpoints: self.endpoints.append(endpoint)
        if ci.ra and ci.ra not in self.ips: self.ips.append(ci.ra)
        if ci.host and ci.host not in ("-","...") and ci.host not in self.hosts: self.hosts.append(ci.host)

    def as_dict(self):
        return {
            "key": self.key,
            "proc": self.proc,
            "path": self.path,
            "signer": self.signer,
            "parent": self.parent,
            "package": self.package,
            "svc": self.svc,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "count": self.count,
            "endpoints": list(self.endpoints),
            "hosts": list(self.hosts),
            "ips": list(self.ips),
        }

class LearningReviewCollector:
    def __init__(self, enabled=True, window_seconds=600, started=None):
        self.enabled=bool(enabled)
        self.window_seconds=max(float(window_seconds or 0),0.0)
        self.started=float(started if started is not None else time.time())
        self.closed=False
        self._groups={}

    def active(self, now=None):
        if not self.enabled or self.closed: return False
        if self.window_seconds <= 0: return True
        now=float(now if now is not None else time.time())
        return now - self.started <= self.window_seconds

    def seconds_remaining(self, now=None):
        if self.window_seconds <= 0: return 0
        now=float(now if now is not None else time.time())
        return max(0, int(self.window_seconds - (now - self.started)))

    def stop(self):
        self.closed=True

    def clear(self):
        self._groups.clear()

    def observe(self, conns, now=None):
        if not self.active(now): return 0
        added=0
        for ci in conns or []:
            if not self._should_collect(ci): continue
            key=self._group_key(ci)
            group=self._groups.get(key)
            if group is None:
                group=LearningReviewGroup(key=key, proc=ci.proc or "?", path=ci.path or "", signer=ci.signer or "-",
                    parent=ci.parent or "-", package=ci.package or "-", svc=ci.svc or "-")
                self._groups[key]=group; added+=1
            group.record(ci)
        return added

    def groups(self):
        return sorted((g.as_dict() for g in self._groups.values()), key=lambda g:(-g["count"], g["proc"].lower(), g["path"].lower()))

    def remove(self, key):
        return self._groups.pop(key, None)

    def _should_collect(self, ci):
        if getattr(ci,"dir","") != "Out": return False
        if getattr(ci,"stat","-") not in ("","-"): return False
        ip=str(getattr(ci,"ra","") or "")
        if not ip or ip in ("*","0.0.0.0","127.0.0.1","::1"): return False
        if PRIV_RE.match(ip): return False
        proc=str(getattr(ci,"proc","") or "").strip()
        if not proc or proc in ("?","System Idle Process"): return False
        return True

    def _group_key(self, ci):
        parts=[
            str(getattr(ci,"signer","") or "-").lower(),
            str(getattr(ci,"path","") or "").lower(),
            str(getattr(ci,"parent","") or "-").lower(),
            str(getattr(ci,"proc","") or "?").lower(),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]

@dataclass
class FWRule:
    name:str=""; desc:str=""; direction:str="Outbound"; action:str="Block"
    enabled:bool=True; profile:str="Any"; group:str=""
    remote_addr:str="Any"; local_addr:str="Any"; remote_port:str="Any"
    local_port:str="Any"; protocol:str="Any"; program:str=""; source:str="system"

@dataclass
class FirewallTamperEvent:
    ts:str=""; change:str=""; rule_name:str=""
    before:dict=field(default_factory=dict); after:dict=field(default_factory=dict)
    details:str=""

    def as_dict(self):
        return {
            "ts": self.ts,
            "change": self.change,
            "rule_name": self.rule_name,
            "before": dict(self.before or {}),
            "after": dict(self.after or {}),
            "details": self.details,
        }

@dataclass
class ThreatEvent:
    ts:str=""; type:str=""; severity:str="medium"; source_ip:str=""
    details:str=""; action_taken:str=""; blocked:bool=False
    mitre_tactic:str=""; mitre_technique:str=""; mitre_url:str=""

@dataclass
class QuotaEvent:
    key:str=""; period:str=""; app:str=""; path:str=""
    limit:int=0; used:int=0; blocked:bool=False; message:str=""

@dataclass
class DoHEvent:
    endpoint:str=""; host:str=""; app:str=""; action:str="warn"
    blocked:bool=False; message:str=""

@dataclass
class IDSRule:
    name:str=""; severity:str="medium"; description:str=""; condition:str=""
    action:str="warn"; mitre_tactic:str=""; mitre_technique:str=""; mitre_url:str=""

# ─── LRU Cache ──────────────────────────────────────────────────────────────
class LRU:
    def __init__(s,c=5000): s._d=OrderedDict(); s._l=Lock(); s._c=c
    def get(s,k,d=None):
        with s._l:
            if k in s._d: s._d.move_to_end(k); return s._d[k]
            return d
    def put(s,k,v):
        with s._l: s._d[k]=v; s._d.move_to_end(k)
        while len(s._d)>s._c: s._d.popitem(last=False)
    def __contains__(s,k):
        with s._l: return k in s._d
    def __len__(s):
        with s._l: return len(s._d)
    def clear(s):
        with s._l: s._d.clear()
dns_c=LRU(5000); who_c=LRU(5000); geo_c=LRU(5000); prc_c=LRU(1000); signer_c=LRU(2000)
_svc_pid_cache={}; _svc_pid_cache_ts=0; _svc_pid_cache_lock=Lock()

# ─── Domain Helpers ──────────────────────────────────────────────────────────
def looks_like_domain(t):
    if len(t)>253 or t.startswith(('-','.')) or t.endswith(('-','.')): return False
    if IPV4_RE.match(t) or (':' in t): return False
    return bool(DOMAIN_RE.match(t))

def get_root_domain(domain):
    parts = domain.lower().strip().rstrip('.').split('.')
    if len(parts) <= 2: return domain
    maybe = '.'.join(parts[-2:])
    if maybe in MULTI_TLDS and len(parts) >= 3: return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def normalize_line(line):
    s = line.strip()
    if not s or s.startswith('#'): return None, None, False
    s = s.split('#', 1)[0].strip(); parts = s.split()
    tok = parts[1] if len(parts) >= 2 else parts[0] if parts else None
    if not tok: return None, None, False
    ip_tok = parts[0] if len(parts) >= 2 else None
    m = WILDCARD_RE.match(tok); dom = (m.group(1) if m else tok).lower()
    if dom in ('localhost','::1'): return None, dom, False
    if ip_tok and ip_tok in ('127.0.0.1','::1') and dom == 'localhost': return None, dom, False
    if looks_like_domain(dom):
        norm = f"0.0.0.0 {dom}"; changed = bool(m) or len(parts)==1 or dom!=tok.lower() or (ip_tok and ip_tok!="0.0.0.0")
        return norm, dom, changed
    return None, None, False

def _feed_cache_path(name, url):
    slug=re.sub(r"[^a-zA-Z0-9_.-]+","_",str(name or "feed")).strip("._")[:60] or "feed"
    digest=hashlib.sha256(str(url or name or slug).encode("utf-8")).hexdigest()[:16]
    return os.path.join(FEED_CACHE_DIR, f"{slug}_{digest}.txt")

def _parse_import_text(text, normalize=True):
    lines=str(text or "").splitlines()
    if not normalize: return list(lines)
    out=[]
    for line in lines:
        norm,_,_=normalize_line(line)
        if norm: out.append(norm)
    return out

def clean_hosts_content(lines, whitelist_set):
    stats = {"total":len(lines),"blanks":0,"comments":0,"whitelist":0,"dupes":0,"invalid":0,"transformed":0}
    seen, kept = set(), []
    for line in lines:
        s = line.strip()
        if not s: stats["blanks"]+=1; continue
        if s.startswith('#'): stats["comments"]+=1; continue
        norm, dom, changed = normalize_line(line)
        if dom and (dom in whitelist_set or dom.lstrip('.') in whitelist_set): stats["whitelist"]+=1; continue
        if norm is None: stats["invalid"]+=1; continue
        if norm in seen: stats["dupes"]+=1; continue
        seen.add(norm); kept.append(norm)
        if changed: stats["transformed"]+=1
    header = WINDOWS_HEADER + [f"# --- {len(kept)} active entries managed by PyWall v{APP_VERSION} ---"]
    result = header + sorted(kept) + [""]; stats["active"] = len(kept)
    return result, stats

def categorize_traffic(host, ip, port):
    """Categorize a connection based on hostname/IP/port."""
    if not host or host in ('-','...'): text = ip or ''
    else: text = host.lower()
    for cat, keywords in _CATEGORIES.items():
        for kw in keywords:
            if kw in text: return cat
    if ip and PRIV_RE.match(ip): return "LAN"
    p = int(port) if port and port.isdigit() else 0
    if p in (80,443,8080,8443): return "Web"
    if p in (53,5353): return "DNS"
    if p in (25,110,143,465,587,993,995): return "Email"
    return ""

DOH_IPS = {
    "1.1.1.1","1.0.0.1","2606:4700:4700::1111","2606:4700:4700::1001",
    "8.8.8.8","8.8.4.4","2001:4860:4860::8888","2001:4860:4860::8844",
    "9.9.9.9","149.112.112.112","2620:fe::fe","2620:fe::9",
    "94.140.14.14","94.140.15.15","208.67.222.222","208.67.220.220",
}
DOH_HOST_PATTERNS = ("dns.google","cloudflare-dns.com","mozilla.cloudflare-dns.com","dns.quad9.net","dns.adguard.com","doh.opendns.com","dns.nextdns.io","doh.")

def detect_doh_endpoint(host, ip, port):
    try: p = int(str(port).split(",")[0])
    except: p = 0
    if p not in (443, 853): return False
    text = (host or "").lower()
    return (ip in DOH_IPS) or any(pat in text for pat in DOH_HOST_PATTERNS)

def open_research(domain):
    root = get_root_domain(domain)
    menu = QMenu()
    menu.setStyleSheet(_CTX_STYLE)
    for name, url_tpl in RESEARCH_SITES:
        a = menu.addAction(f"  {name}"); a.setData(url_tpl.format(domain=root))
    menu.addSeparator()
    a2 = menu.addAction(f"  VirusTotal (exact: {domain})"); a2.setData(f"https://www.virustotal.com/gui/domain/{domain}")
    chosen = menu.exec_(QCursor.pos())
    if chosen and chosen.data(): webbrowser.open(chosen.data())

def _ps(cmd, t=20):
    """Execute PowerShell command, return (ok, stdout)."""
    try:
        r = subprocess.run(["powershell","-NoProfile","-NoLogo","-NonInteractive","-ExecutionPolicy","Bypass","-Command",cmd],
            capture_output=True, text=True, timeout=t, creationflags=NOWIN)
        return (r.returncode==0, r.stdout.strip())
    except Exception as e: return (False, str(e))

def _ps_literal(value, field="value", max_len=1024):
    text = str(value if value is not None else "")
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_len:
        raise ValueError(f"{field} is too long")
    if any(ch in text for ch in ("\x00", "\r", "\n")):
        raise ValueError(f"{field} contains control characters")
    return "'" + text.replace("'", "''") + "'"

def _service_names_by_pid(force=False):
    global _svc_pid_cache, _svc_pid_cache_ts
    if sys.platform != "win32" or not hasattr(psutil, "win_service_iter"):
        return {}
    now=time.time()
    with _svc_pid_cache_lock:
        if not force and _svc_pid_cache and now-_svc_pid_cache_ts<30:
            return dict(_svc_pid_cache)
    out=defaultdict(list)
    try:
        for svc in psutil.win_service_iter():
            try:
                info=svc.as_dict()
                pid=int(info.get("pid") or 0)
                if pid>0:
                    name=info.get("name") or info.get("display_name") or ""
                    if name: out[pid].append(str(name))
            except: continue
    except: out={}
    resolved={pid:",".join(sorted(set(names))) for pid,names in out.items()}
    with _svc_pid_cache_lock:
        _svc_pid_cache=resolved; _svc_pid_cache_ts=now
    return dict(resolved)

def _service_names_for_pid(pid):
    try: pid=int(pid or 0)
    except: return "-"
    if pid<=0: return "-"
    return _service_names_by_pid().get(pid,"-")

def _package_identity_from_path(path):
    text=str(path or "").strip()
    if not text or text=="-": return "-"
    norm=text.replace("/","\\")
    for marker in ("\\WindowsApps\\","\\AppData\\Local\\Packages\\"):
        if marker.lower() in norm.lower():
            tail=norm.lower().split(marker.lower(),1)[1]
            segment=norm[len(norm)-len(tail):].split("\\",1)[0]
            if not segment: return "-"
            parts=segment.split("_")
            if marker == "\\WindowsApps\\" and len(parts)>=5:
                return f"{parts[0]}_{parts[-1]}"
            return segment
    return "-"

def _parent_identity_from_process(proc):
    try:
        parent=proc.parent()
        if parent: return f"{parent.name()} ({parent.pid})"
    except: pass
    return "-"

def _cert_common_name(subject):
    text=str(subject or "").strip()
    if not text: return ""
    for part in text.split(","):
        item=part.strip()
        if item.upper().startswith("CN="):
            return item[3:].strip()[:80]
    return text[:80]

def _signer_label_from_json(raw):
    try: data=json.loads(raw) if raw else {}
    except: data={}
    if isinstance(data,list): data=data[0] if data else {}
    if not isinstance(data,dict): return "-"
    status=str(data.get("Status") or "").strip()
    subject=str(data.get("Subject") or "").strip()
    if status.lower()=="valid":
        cn=_cert_common_name(subject)
        return f"Valid: {cn}" if cn else "Valid"
    if status.lower()=="notsigned": return "Unsigned"
    return status or "-"

def _authenticode_signer_label(path):
    text=str(path or "").strip()
    if sys.platform!="win32" or not text or text=="-" or not os.path.exists(text):
        return "-"
    try:
        lit=_ps_literal(text,"path",4096)
    except ValueError:
        return "-"
    cmd=("$sig=Get-AuthenticodeSignature -LiteralPath "+lit+" -EA SilentlyContinue; "
         "if ($null -eq $sig) { '' } else { "
         "[PSCustomObject]@{Status=$sig.Status.ToString();Subject=$sig.SignerCertificate.Subject;Issuer=$sig.SignerCertificate.Issuer} | ConvertTo-Json -Compress }")
    ok,out=_ps(cmd,20)
    return _signer_label_from_json(out) if ok else "-"

def _cached_signer_label(path):
    text=str(path or "").strip()
    if not text or text=="-": return "-"
    cached=signer_c.get(text)
    return cached if cached is not None else "..."

def _fw_enum(value, allowed, field, default=None):
    text = str(value if value is not None else default or "").strip()
    if not text and default is not None: text = default
    match = {v.lower(): v for v in allowed}.get(text.lower())
    if not match:
        raise ValueError(f"Invalid {field}: {value}")
    return match

def _fw_profile(value):
    text = str(value or "Any").strip()
    if text in ("", "*", "Any"): return "Any"
    allowed = {"Domain", "Private", "Public"}
    parts = []
    for part in text.split(","):
        item = _fw_enum(part.strip(), allowed, "profile")
        if item not in parts: parts.append(item)
    return ",".join(parts) if parts else "Any"

def _fw_protocol(value):
    text = str(value or "Any").strip()
    if text in ("", "*", "Any"): return ""
    allowed = {"TCP", "UDP", "ICMPv4", "ICMPv6"}
    if text.upper() in ("TCP", "UDP"): return text.upper()
    if text.lower() in ("icmpv4", "icmpv6"): return "ICMPv" + text[-1]
    if text.isdigit() and 0 <= int(text) <= 255: return text
    raise ValueError(f"Invalid protocol: {value}")

def _fw_ports(value, field):
    text = str(value or "").strip()
    if text in ("", "*", "Any"): return ""
    safe_words = {"RPC", "RPC-EPMap", "IPHTTPS", "Teredo"}
    out = []
    for raw in text.split(","):
        part = raw.strip()
        if not part: raise ValueError(f"Invalid {field}: empty segment")
        if part in safe_words:
            out.append(part); continue
        if "-" in part:
            start, end = [p.strip() for p in part.split("-", 1)]
            if not (start.isdigit() and end.isdigit()):
                raise ValueError(f"Invalid {field}: {part}")
            lo, hi = int(start), int(end)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"Invalid {field}: {part}")
            out.append(f"{lo}-{hi}"); continue
        if not part.isdigit() or not (1 <= int(part) <= 65535):
            raise ValueError(f"Invalid {field}: {part}")
        out.append(str(int(part)))
    return ",".join(out)

def _fw_address(value, field):
    text = str(value or "").strip()
    if text in ("", "*", "Any"): return ""
    keywords = {"LocalSubnet", "DefaultGateway", "DHCP", "DNS", "WINS", "Internet", "Intranet", "IntranetRemoteAccess", "PlayToDevice"}
    out = []
    for raw in text.split(","):
        part = raw.strip()
        if not part: raise ValueError(f"Invalid {field}: empty segment")
        if part in keywords:
            out.append(part); continue
        if "-" in part and "/" not in part:
            start, end = [p.strip() for p in part.split("-", 1)]
            try:
                ipaddress.ip_address(start); ipaddress.ip_address(end)
            except ValueError:
                raise ValueError(f"Invalid {field}: {part}")
            out.append(f"{start}-{end}"); continue
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise ValueError(f"Invalid {field}: {part}")
        out.append(part)
    return ",".join(out)

def _fw_program(value):
    text = _nt_to_dos(str(value or "").strip())
    if not text or text in ("-", "N/A"): return ""
    if any(ch in text for ch in ("\x00", "\r", "\n", '"')):
        raise ValueError("program path contains invalid characters")
    return text

def _build_new_firewall_rule_cmd(name,direction="Outbound",action="Block",remote_addr="",remote_port="",local_addr="",local_port="",protocol="",program="",profile="Any",desc="",enabled=True):
    direction = _fw_enum(direction, {"Inbound", "Outbound"}, "direction", "Outbound")
    action = _fw_enum(action, {"Allow", "Block"}, "action", "Block")
    profile = _fw_profile(profile)
    proto = _fw_protocol(protocol)
    parts = ["New-NetFirewallRule", "-DisplayName", _ps_literal(name, "rule name", 256), "-Direction", direction, "-Action", action,
        "-Enabled", "True" if enabled else "False", "-Profile", profile]
    remote_addr = _fw_address(remote_addr, "remote address")
    local_addr = _fw_address(local_addr, "local address")
    remote_port = _fw_ports(remote_port, "remote port")
    local_port = _fw_ports(local_port, "local port")
    program = _fw_program(program)
    if remote_addr: parts.extend(["-RemoteAddress", _ps_literal(remote_addr, "remote address")])
    if local_addr: parts.extend(["-LocalAddress", _ps_literal(local_addr, "local address")])
    if remote_port: parts.extend(["-RemotePort", _ps_literal(remote_port, "remote port")])
    if local_port: parts.extend(["-LocalPort", _ps_literal(local_port, "local port")])
    if proto: parts.extend(["-Protocol", proto])
    if program: parts.extend(["-Program", _ps_literal(program, "program path")])
    if desc: parts.extend(["-Description", _ps_literal(str(desc)[:200], "description", 200)])
    parts.extend(["-ErrorAction", "Stop"])
    return " ".join(parts)

def _build_rule_exists_cmd(name):
    return f"(Get-NetFirewallRule -DisplayName {_ps_literal(name, 'rule name', 256)} -ErrorAction SilentlyContinue) -ne $null"

def _build_remove_firewall_rule_cmd(name):
    return f"Remove-NetFirewallRule -DisplayName {_ps_literal(name, 'rule name', 256)} -ErrorAction SilentlyContinue"

def _build_set_firewall_rule_enabled_cmd(name, enabled=True):
    return f"Set-NetFirewallRule -DisplayName {_ps_literal(name, 'rule name', 256)} -Enabled {'True' if enabled else 'False'} -ErrorAction Stop"

def _export_firewall_config(path):
    if not path: return False, "No export path provided"
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        return _ps(f"netsh advfirewall export {_ps_literal(path, 'firewall export path')}", 30)
    except Exception as e:
        return False, str(e)

def _import_firewall_config(path):
    if not path: return False, "No import path provided"
    try:
        return _ps(f"netsh advfirewall import {_ps_literal(path, 'firewall import path')}", 30)
    except Exception as e:
        return False, str(e)

def _timestamped_fw_export_path(prefix="fw_before_reset"):
    d = os.path.join(CONFIG_DIR, "fw_backups")
    os.makedirs(d, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(d, f"{prefix}_{stamp}.wfw")

def _is_managed_rule_name(name):
    return any(str(name or "").startswith(pfx) for pfx in FW_RULE_PREFIXES)

def _fw_rule_snapshot(rule):
    return {
        "name": str(rule.name or ""),
        "desc": str(rule.desc or ""),
        "direction": str(rule.direction or "Outbound"),
        "action": str(rule.action or "Block"),
        "enabled": bool(rule.enabled),
        "profile": str(rule.profile or "Any"),
        "group": str(rule.group or ""),
        "remote_addr": str(rule.remote_addr or ""),
        "local_addr": str(rule.local_addr or ""),
        "remote_port": str(rule.remote_port or ""),
        "local_port": str(rule.local_port or ""),
        "protocol": str(rule.protocol or ""),
        "program": str(rule.program or ""),
    }

def _fw_rule_diff(before, after):
    changed=[]
    before=before or {}; after=after or {}
    for key in ("enabled","direction","action","profile","remote_addr","local_addr","remote_port","local_port","protocol","program","desc"):
        if before.get(key) != after.get(key):
            changed.append(f"{key}: {before.get(key)} -> {after.get(key)}")
    return "; ".join(changed)

def _firewall_tamper_log(event):
    try:
        os.makedirs(os.path.dirname(FW_TAMPER_LOG_PATH), exist_ok=True)
        with open(FW_TAMPER_LOG_PATH,"a",encoding="utf-8") as f:
            f.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")
    except: pass
    log.warning(f"Firewall tamper detected: {event.details}")

# NT device path -> DOS path mapping
_drive_map = None
def _nt_to_dos(path):
    global _drive_map
    if not path or path=="-": return path
    if not path.lower().startswith("\\device\\"): return path
    if _drive_map is None:
        _drive_map = {}
        try:
            import ctypes; buf = ctypes.create_unicode_buffer(512)
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                drive = f"{letter}:"
                if ctypes.windll.kernel32.QueryDosDeviceW(drive, buf, 512): _drive_map[buf.value.lower()] = drive
        except: pass
    for device, drive in _drive_map.items():
        if path.lower().startswith(device.lower()): return drive + path[len(device):]
    return path


# ─── Favicon Cache ───────────────────────────────────────────────────────────
class FaviconCache(QObject):
    favicon_ready = pyqtSignal(str)
    def __init__(self):
        super().__init__(); self._mem={}; self._pending=set(); self._lock=Lock()
        self._default=QPixmap(16,16); self._default.fill(QColor(C['surface1']))
        p=QPainter(self._default); p.setPen(QColor(C['overlay'])); p.drawText(self._default.rect(),Qt.AlignCenter,"?"); p.end()
    def get(self,domain):
        root=get_root_domain(domain)
        if root in self._mem: return self._mem[root]
        path=os.path.join(FAVICON_DIR, hashlib.md5(root.encode()).hexdigest()+".png")
        if os.path.exists(path) and os.path.getsize(path)>0:
            px=QPixmap(path)
            if not px.isNull(): self._mem[root]=px; return px
        self._enqueue(root); return self._default
    def _enqueue(self,root):
        with self._lock:
            if root in self._pending: return
            self._pending.add(root)
        threading.Thread(target=self._fetch,args=(root,),daemon=True).start()
    def _fetch(self,root):
        path=os.path.join(FAVICON_DIR,hashlib.md5(root.encode()).hexdigest()+".png")
        try:
            req=urllib.request.Request(f"https://www.google.com/s2/favicons?domain={root}&sz=32",headers={'User-Agent':'Mozilla/5.0'})
            with urllib.request.urlopen(req,timeout=8) as resp: data=resp.read()
            if len(data)>50:
                with open(path,'wb') as f: f.write(data)
                px=QPixmap(); px.loadFromData(data)
                if not px.isNull(): self._mem[root]=px; self.favicon_ready.emit(root)
        except: pass
        finally:
            with self._lock: self._pending.discard(root)
_fav_cache = None  # Initialized after QApplication — see main()
def _init_fav_cache():
    global _fav_cache
    if _fav_cache is None: _fav_cache = FaviconCache()

# ─── Hosts Database ─────────────────────────────────────────────────────────
class HostsDB:
    def __init__(self):
        self.conn=sqlite3.connect(DB_PATH,check_same_thread=False); self.conn.execute("PRAGMA journal_mode=WAL"); self.lock=Lock()
        with self.lock:
            _hosts_db_migrate(self.conn)
    def _now(self): return datetime.datetime.now().isoformat()
    def add_domain(self,domain,status='blocked',source='manual'):
        with self.lock: n=self._now(); self.conn.execute("INSERT OR REPLACE INTO domains (domain,status,category,source,date_added,date_modified) VALUES (?,?,?,?,?,?)",(domain.lower().strip(),status,'',source,n,n)); self.conn.commit()
    def update_status(self,domain,status):
        with self.lock: self.conn.execute("UPDATE domains SET status=?,date_modified=? WHERE domain=?",(status,self._now(),domain.lower())); self.conn.commit()
    def remove_domain(self,domain):
        with self.lock: self.conn.execute("DELETE FROM domains WHERE domain=?",(domain.lower(),)); self.conn.commit()
    def get_domains(self,status=None,search=None):
        with self.lock:
            q,p="SELECT * FROM domains WHERE 1=1",[]
            if status: q+=" AND status=?"; p.append(status)
            if search: q+=" AND domain LIKE ?"; p.append(f"%{search}%")
            return self.conn.execute(q+" ORDER BY domain",p).fetchall()
    def add_root_domain(self,domain,status,source='manual'):
        root=get_root_domain(domain)
        with self.lock:
            n=self._now(); rows=self.conn.execute("SELECT domain FROM dns_feed WHERE domain LIKE ?",(f"%{root}",)).fetchall(); ct=0
            for (d,) in rows:
                if d.endswith(root): self.conn.execute("INSERT OR REPLACE INTO domains (domain,status,category,source,date_added,date_modified) VALUES (?,?,?,?,?,?)",(d,status,'',source,n,n)); ct+=1
            self.conn.execute("INSERT OR REPLACE INTO domains (domain,status,category,source,date_added,date_modified) VALUES (?,?,?,?,?,?)",(root,status,'',source,n,n)); ct+=1
            self.conn.commit(); return ct
    def feed_upsert(self,domain,proc=''):
        domain=domain.lower().strip()
        with self.lock:
            n=self._now()
            if self.conn.execute("SELECT 1 FROM dns_feed WHERE domain=?",(domain,)).fetchone():
                self.conn.execute("UPDATE dns_feed SET last_seen=?,hit_count=hit_count+1,last_process=? WHERE domain=?",(n,proc,domain)); self.conn.commit(); return False
            self.conn.execute("INSERT INTO dns_feed VALUES (?,?,?,1,?,0)",(domain,n,n,proc)); self.conn.commit(); return True
    def feed_get(self,search=None,show_hidden=False,status_filter=None,limit=2000):
        with self.lock:
            q="SELECT f.domain,f.first_seen,f.last_seen,f.hit_count,f.last_process,f.hidden,COALESCE(d.status,'unmanaged') FROM dns_feed f LEFT JOIN domains d ON f.domain=d.domain WHERE 1=1"
            p=[]
            if not show_hidden: q+=" AND f.hidden=0"
            if search: q+=" AND f.domain LIKE ?"; p.append(f"%{search}%")
            if status_filter and status_filter not in ('all',None):
                if status_filter=='unmanaged': q+=" AND d.status IS NULL"
                elif status_filter=='hidden': q+=" AND f.hidden=1"
                else: q+=" AND d.status=?"; p.append(status_filter)
            q+=" ORDER BY f.last_seen DESC LIMIT ?"; p.append(limit)
            return self.conn.execute(q,p).fetchall()
    def feed_hide(self,d):
        with self.lock: self.conn.execute("UPDATE dns_feed SET hidden=1 WHERE domain=?",(d.lower(),)); self.conn.commit()
    def feed_unhide(self,d):
        with self.lock: self.conn.execute("UPDATE dns_feed SET hidden=0 WHERE domain=?",(d.lower(),)); self.conn.commit()
    def feed_delete(self,d):
        with self.lock: self.conn.execute("DELETE FROM dns_feed WHERE domain=?",(d.lower(),)); self.conn.commit()
    def feed_hide_bulk(self,ds):
        with self.lock: self.conn.executemany("UPDATE dns_feed SET hidden=1 WHERE domain=?",[(d.lower(),) for d in ds]); self.conn.commit()
    def feed_hide_root(self,domain):
        root=get_root_domain(domain)
        with self.lock: self.conn.execute("UPDATE dns_feed SET hidden=1 WHERE domain LIKE ?",(f"%{root}",)); self.conn.commit()
    def feed_count(self,hidden=False):
        with self.lock: return self.conn.execute(f"SELECT COUNT(*) FROM dns_feed WHERE hidden={'1' if hidden else '0'}").fetchone()[0]
    def feed_source_success(self,name,url,item_count,sha256_value,cache_path):
        with self.lock:
            n=self._now()
            self.conn.execute("INSERT OR REPLACE INTO feed_sources (source_name,url,fetched_at,item_count,sha256,last_good_cache_path,failure_reason,status) VALUES (?,?,?,?,?,?,?,?)",
                (str(name),str(url),n,int(item_count or 0),str(sha256_value or ""),str(cache_path or ""),"","ok"))
            self.conn.commit()
            return self.feed_source_get(name)
    def feed_source_failure(self,name,url,reason):
        with self.lock:
            n=self._now(); existing=self.feed_source_get(name) or {}
            cache=existing.get("last_good_cache_path","")
            self.conn.execute("INSERT OR REPLACE INTO feed_sources (source_name,url,fetched_at,item_count,sha256,last_good_cache_path,failure_reason,status) VALUES (?,?,?,?,?,?,?,?)",
                (str(name),str(url),n,int(existing.get("item_count",0) or 0),str(existing.get("sha256","") or ""),cache,str(reason or ""),"failed"))
            self.conn.commit()
            return self.feed_source_get(name)
    def feed_source_get(self,name):
        row=self.conn.execute("SELECT source_name,url,fetched_at,item_count,sha256,last_good_cache_path,failure_reason,status FROM feed_sources WHERE source_name=?",(str(name),)).fetchone()
        if not row: return None
        keys=("source_name","url","fetched_at","item_count","sha256","last_good_cache_path","failure_reason","status")
        return dict(zip(keys,row))
    def feed_sources_get(self,limit=200):
        with self.lock:
            rows=self.conn.execute("SELECT source_name,url,fetched_at,item_count,sha256,last_good_cache_path,failure_reason,status FROM feed_sources ORDER BY fetched_at DESC LIMIT ?",(int(limit or 200),)).fetchall()
            keys=("source_name","url","fetched_at","item_count","sha256","last_good_cache_path","failure_reason","status")
            return [dict(zip(keys,row)) for row in rows]
    def log_event(self,domain,action,proc='',details=''):
        with self.lock:
            self.conn.execute("INSERT INTO log (timestamp,domain,action,process_name,details) VALUES (?,?,?,?,?)",(self._now(),domain.lower(),action,proc,details))
            self.conn.execute("UPDATE domains SET hit_count=hit_count+1 WHERE domain=?",(domain.lower(),)); self.conn.commit()
    def get_log(self,limit=500,domain_filter=None,action_filter=None,since=None):
        with self.lock:
            q,p="SELECT * FROM log WHERE 1=1",[]
            if domain_filter: q+=" AND domain LIKE ?"; p.append(f"%{domain_filter}%")
            if action_filter and action_filter!='all': q+=" AND action=?"; p.append(action_filter)
            if since: q+=" AND timestamp>=?"; p.append(since)
            q+=" ORDER BY timestamp DESC LIMIT ?"; p.append(limit); return self.conn.execute(q,p).fetchall()
    def clear_log(self):
        with self.lock: self.conn.execute("DELETE FROM log"); self.conn.commit()
    def log_diagnostic(self,domain,sid):
        with self.lock: self.conn.execute("INSERT INTO diagnostic_log (timestamp,domain,session_id) VALUES (?,?,?)",(self._now(),domain.lower(),sid)); self.conn.commit()
    def get_stats(self):
        with self.lock:
            c=self.conn.cursor(); today=datetime.datetime.now().strftime('%Y-%m-%d')
            return {'blocked':c.execute("SELECT COUNT(*) FROM domains WHERE status='blocked'").fetchone()[0],
                'whitelisted':c.execute("SELECT COUNT(*) FROM domains WHERE status='whitelisted'").fetchone()[0],
                'feed_total':c.execute("SELECT COUNT(*) FROM dns_feed WHERE hidden=0").fetchone()[0],
                'feed_hidden':c.execute("SELECT COUNT(*) FROM dns_feed WHERE hidden=1").fetchone()[0],
                'today_hits':c.execute("SELECT COUNT(*) FROM log WHERE action='blocked' AND timestamp LIKE ?",(f"{today}%",)).fetchone()[0],
                'top_blocked':c.execute("SELECT domain,COUNT(*) FROM log WHERE action='blocked' GROUP BY domain ORDER BY 2 DESC LIMIT 10").fetchall()}

# ─── Connection History Database ─────────────────────────────────────────────
CONN_DB_VERSION = 2

def _conn_db_migrate(conn):
    ver = conn.execute("PRAGMA user_version").fetchone()[0]
    if ver >= CONN_DB_VERSION:
        return
    if ver < 1:
        conn.execute("CREATE TABLE IF NOT EXISTS connections (id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,src TEXT,dir TEXT,proto TEXT,la TEXT,lp TEXT,ra TEXT,rp TEXT,host TEXT,proc TEXT,pid INTEGER,svc TEXT DEFAULT '-',parent TEXT DEFAULT '-',package TEXT DEFAULT '-',signer TEXT DEFAULT '-',state TEXT,org TEXT,stat TEXT,country TEXT,cc TEXT,category TEXT,bytes_sent INTEGER DEFAULT 0,bytes_recv INTEGER DEFAULT 0,event_source TEXT DEFAULT '',event_id INTEGER DEFAULT 0,event_record_id INTEGER DEFAULT 0,rule_name TEXT DEFAULT '',filter_id TEXT DEFAULT '',UNIQUE(ts,proto,la,lp,ra,rp,pid) ON CONFLICT IGNORE)")
        conn.execute("CREATE TABLE IF NOT EXISTS connection_sessions (key TEXT PRIMARY KEY,first_seen TEXT,last_seen TEXT,src TEXT,dir TEXT,proto TEXT,la TEXT,lp TEXT,ra TEXT,rp TEXT,host TEXT,proc TEXT,pid INTEGER,svc TEXT DEFAULT '-',parent TEXT DEFAULT '-',package TEXT DEFAULT '-',signer TEXT DEFAULT '-',state TEXT,org TEXT,stat TEXT,country TEXT,cc TEXT,category TEXT,bytes_sent INTEGER DEFAULT 0,bytes_recv INTEGER DEFAULT 0,samples INTEGER DEFAULT 0,active INTEGER DEFAULT 1,event_source TEXT DEFAULT '',event_id INTEGER DEFAULT 0,event_record_id INTEGER DEFAULT 0,rule_name TEXT DEFAULT '',filter_id TEXT DEFAULT '')")
    if ver < 2:
        cols={r[1] for r in conn.execute("PRAGMA table_info(connections)").fetchall()}
        for name,ddl in {"svc":"TEXT DEFAULT '-'","parent":"TEXT DEFAULT '-'","package":"TEXT DEFAULT '-'","signer":"TEXT DEFAULT '-'","bytes_sent":"INTEGER DEFAULT 0","bytes_recv":"INTEGER DEFAULT 0","event_source":"TEXT DEFAULT ''","event_id":"INTEGER DEFAULT 0","event_record_id":"INTEGER DEFAULT 0","rule_name":"TEXT DEFAULT ''","filter_id":"TEXT DEFAULT ''"}.items():
            if name not in cols: conn.execute(f"ALTER TABLE connections ADD COLUMN {name} {ddl}")
        sess_cols={r[1] for r in conn.execute("PRAGMA table_info(connection_sessions)").fetchall()}
        for name,ddl in {"svc":"TEXT DEFAULT '-'","parent":"TEXT DEFAULT '-'","package":"TEXT DEFAULT '-'","signer":"TEXT DEFAULT '-'","bytes_sent":"INTEGER DEFAULT 0","bytes_recv":"INTEGER DEFAULT 0","samples":"INTEGER DEFAULT 0","active":"INTEGER DEFAULT 1","event_source":"TEXT DEFAULT ''","event_id":"INTEGER DEFAULT 0","event_record_id":"INTEGER DEFAULT 0","rule_name":"TEXT DEFAULT ''","filter_id":"TEXT DEFAULT ''"}.items():
            if name not in sess_cols: conn.execute(f"ALTER TABLE connection_sessions ADD COLUMN {name} {ddl}")
    for idx in ["CREATE INDEX IF NOT EXISTS idx_ts ON connections(ts)","CREATE INDEX IF NOT EXISTS idx_proc ON connections(proc)","CREATE INDEX IF NOT EXISTS idx_ra ON connections(ra)"]:
        conn.execute(idx)
    for idx in ["CREATE INDEX IF NOT EXISTS idx_sess_last ON connection_sessions(last_seen)","CREATE INDEX IF NOT EXISTS idx_sess_proc ON connection_sessions(proc)","CREATE INDEX IF NOT EXISTS idx_sess_ra ON connection_sessions(ra)","CREATE INDEX IF NOT EXISTS idx_sess_active ON connection_sessions(active)"]:
        conn.execute(idx)
    conn.execute(f"PRAGMA user_version={CONN_DB_VERSION}")
    conn.commit()

HOSTS_DB_VERSION = 1

def _hosts_db_migrate(conn):
    ver = conn.execute("PRAGMA user_version").fetchone()[0]
    if ver >= HOSTS_DB_VERSION:
        return
    if ver < 1:
        conn.execute("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY,status TEXT DEFAULT 'blocked',category TEXT DEFAULT '',source TEXT DEFAULT 'manual',date_added TEXT,date_modified TEXT,hit_count INTEGER DEFAULT 0,notes TEXT DEFAULT '')")
        conn.execute("CREATE TABLE IF NOT EXISTS dns_feed (domain TEXT PRIMARY KEY,first_seen TEXT,last_seen TEXT,hit_count INTEGER DEFAULT 1,last_process TEXT DEFAULT '',hidden INTEGER DEFAULT 0)")
        conn.execute("CREATE TABLE IF NOT EXISTS feed_sources (source_name TEXT PRIMARY KEY,url TEXT,fetched_at TEXT,item_count INTEGER DEFAULT 0,sha256 TEXT DEFAULT '',last_good_cache_path TEXT DEFAULT '',failure_reason TEXT DEFAULT '',status TEXT DEFAULT 'unknown')")
        conn.execute("CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,domain TEXT,action TEXT,process_name TEXT DEFAULT '',details TEXT DEFAULT '')")
        conn.execute("CREATE TABLE IF NOT EXISTS diagnostic_log (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,domain TEXT,session_id TEXT)")
        for idx in ["CREATE INDEX IF NOT EXISTS idx_log_ts ON log(timestamp)","CREATE INDEX IF NOT EXISTS idx_feed_last ON dns_feed(last_seen)","CREATE INDEX IF NOT EXISTS idx_feed_hidden ON dns_feed(hidden)","CREATE INDEX IF NOT EXISTS idx_feed_src_url ON feed_sources(url)","CREATE INDEX IF NOT EXISTS idx_feed_src_status ON feed_sources(status)"]:
            conn.execute(idx)
    conn.execute(f"PRAGMA user_version={HOSTS_DB_VERSION}")
    conn.commit()

CONN_EXPORT_COLUMNS = ["ts","src","dir","proto","la","lp","ra","rp","host","proc","pid","svc","parent","package","signer","state","org","country","stat","bytes_sent","bytes_recv","event_source","event_id","event_record_id","rule_name","filter_id"]

class ConnDB:
    def __init__(self):
        self._lock=Lock(); self._conn=sqlite3.connect(CONN_DB_PATH,check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL"); self._conn.execute("PRAGMA synchronous=NORMAL")
        _conn_db_migrate(self._conn)
    def insert_batch(self,items):
        with self._lock:
            try:
                self._conn.executemany("INSERT OR IGNORE INTO connections (ts,src,dir,proto,la,lp,ra,rp,host,proc,pid,svc,parent,package,signer,state,org,stat,country,cc,category,bytes_sent,bytes_recv,event_source,event_id,event_record_id,rule_name,filter_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [(c.ts,c.src,c.dir,c.proto,c.la,c.lp,c.ra,c.rp,c.host,c.proc,c.pid,c.svc,c.parent,c.package,c.signer,c.state,c.org,c.stat,c.country,c.cc,c.category,c.bytes_sent,c.bytes_recv,c.event_source,c.event_id,c.event_record_id,c.rule_name,c.filter_id) for c in items])
                self._upsert_sessions(items)
                self._conn.commit()
            except: pass
    def _upsert_sessions(self,items):
        now=datetime.datetime.now().isoformat(timespec="seconds")
        self._conn.execute("UPDATE connection_sessions SET active=0")
        for c in items:
            self._conn.execute("INSERT OR IGNORE INTO connection_sessions (key,first_seen,last_seen,src,dir,proto,la,lp,ra,rp,host,proc,pid,svc,parent,package,signer,state,org,stat,country,cc,category,bytes_sent,bytes_recv,samples,active,event_source,event_id,event_record_id,rule_name,filter_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (c.key,now,now,c.src,c.dir,c.proto,c.la,c.lp,c.ra,c.rp,c.host,c.proc,c.pid,c.svc,c.parent,c.package,c.signer,c.state,c.org,c.stat,c.country,c.cc,c.category,0,0,0,1,c.event_source,c.event_id,c.event_record_id,c.rule_name,c.filter_id))
            self._conn.execute("UPDATE connection_sessions SET last_seen=?,src=?,dir=?,proto=?,la=?,lp=?,ra=?,rp=?,host=?,proc=?,pid=?,svc=?,parent=?,package=?,signer=?,state=?,org=?,stat=?,country=?,cc=?,category=?,bytes_sent=bytes_sent+?,bytes_recv=bytes_recv+?,samples=samples+1,active=1,event_source=CASE WHEN ?!='' THEN ? ELSE event_source END,event_id=CASE WHEN ?>0 THEN ? ELSE event_id END,event_record_id=CASE WHEN ?>0 THEN ? ELSE event_record_id END,rule_name=CASE WHEN ?!='' THEN ? ELSE rule_name END,filter_id=CASE WHEN ?!='' THEN ? ELSE filter_id END WHERE key=?",
                (now,c.src,c.dir,c.proto,c.la,c.lp,c.ra,c.rp,c.host,c.proc,c.pid,c.svc,c.parent,c.package,c.signer,c.state,c.org,c.stat,c.country,c.cc,c.category,c.bytes_sent,c.bytes_recv,c.event_source,c.event_source,c.event_id,c.event_id,c.event_record_id,c.event_record_id,c.rule_name,c.rule_name,c.filter_id,c.filter_id,c.key))
    def search(self,query="",limit=500,offset=0,evidence="all"):
        with self._lock:
            try:
                w,p=[],[]
                if query: w.append("(host LIKE ? OR proc LIKE ? OR ra LIKE ? OR org LIKE ? OR svc LIKE ? OR parent LIKE ? OR package LIKE ? OR signer LIKE ? OR event_source LIKE ? OR rule_name LIKE ? OR filter_id LIKE ?)"); p.extend([f"%{query}%"]*11)
                if evidence=="event": w.append("event_source!=''")
                elif evidence=="psutil": w.append("(event_source IS NULL OR event_source='')")
                where=" WHERE "+" AND ".join(w) if w else ""
                sql=f"SELECT ts,src,dir,proto,la,lp,ra,rp,host,proc,pid,svc,parent,package,signer,state,org,country,stat,bytes_sent,bytes_recv,event_source,event_id,event_record_id,rule_name,filter_id FROM connections{where} ORDER BY id DESC LIMIT ? OFFSET ?"
                p.extend([limit,offset]); return self._conn.execute(sql,p).fetchall()
            except: return []
    def search_sessions(self,query="",limit=500,offset=0,evidence="all"):
        with self._lock:
            try:
                w,p=[],[]
                if query: w.append("(host LIKE ? OR proc LIKE ? OR ra LIKE ? OR org LIKE ? OR svc LIKE ? OR parent LIKE ? OR package LIKE ? OR signer LIKE ? OR event_source LIKE ? OR rule_name LIKE ? OR filter_id LIKE ?)"); p.extend([f"%{query}%"]*11)
                if evidence=="event": w.append("event_source!=''")
                elif evidence=="psutil": w.append("(event_source IS NULL OR event_source='')")
                where=" WHERE "+" AND ".join(w) if w else ""
                sql=f"SELECT first_seen,last_seen,active,proto,la,lp,ra,rp,host,proc,pid,svc,parent,package,signer,samples,bytes_sent,bytes_recv,stat,event_source,event_id,rule_name,filter_id FROM connection_sessions{where} ORDER BY active DESC,last_seen DESC LIMIT ? OFFSET ?"
                p.extend([limit,offset]); rows=self._conn.execute(sql,p).fetchall(); out=[]
                for fs,ls,active,proto,la,lp,ra,rp,host,proc,pid,svc,parent,package,signer,samples,bs,br,stat,event_source,event_id,rule_name,filter_id in rows:
                    dur=0
                    try: dur=int((datetime.datetime.fromisoformat(ls)-datetime.datetime.fromisoformat(fs)).total_seconds())
                    except: pass
                    out.append((fs,ls,dur,active,proto,la,lp,ra,rp,host,proc,pid,svc,parent,package,signer,samples,bs,br,stat,event_source,event_id,rule_name,filter_id))
                return out
            except: return []
    def get_stats(self):
        with self._lock:
            try:
                total=self._conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
                blocked=self._conn.execute("SELECT COUNT(*) FROM connections WHERE stat LIKE '%BLOCK%'").fetchone()[0]
                unique_ips=self._conn.execute("SELECT COUNT(DISTINCT ra) FROM connections").fetchone()[0]
                sent=self._conn.execute("SELECT COALESCE(SUM(bytes_sent),0) FROM connections").fetchone()[0]
                recv=self._conn.execute("SELECT COALESCE(SUM(bytes_recv),0) FROM connections").fetchone()[0]
                sessions=self._conn.execute("SELECT COUNT(*) FROM connection_sessions").fetchone()[0]
                active_sessions=self._conn.execute("SELECT COUNT(*) FROM connection_sessions WHERE active=1").fetchone()[0]
                return {"total":total,"blocked":blocked,"unique_ips":unique_ips,"bytes_sent":sent,"bytes_recv":recv,"sessions":sessions,"active_sessions":active_sessions}
            except: return {"total":0,"blocked":0,"unique_ips":0,"bytes_sent":0,"bytes_recv":0,"sessions":0,"active_sessions":0}
    def usage_report(self,days=1,limit=1000):
        with self._lock:
            try:
                cutoff=(datetime.datetime.now()-datetime.timedelta(days=max(1,int(days or 1)))).isoformat(timespec="seconds")
                sql=("SELECT COALESCE(NULLIF(proc,''),'Unknown') app,COUNT(*) sessions,COALESCE(SUM(active),0) active_sessions,"
                     "COALESCE(SUM(samples),0) samples,COALESCE(SUM(bytes_sent),0) bytes_sent,COALESCE(SUM(bytes_recv),0) bytes_recv,"
                     "MIN(first_seen) first_seen,MAX(last_seen) last_seen FROM connection_sessions WHERE last_seen>=? "
                     "GROUP BY app ORDER BY (COALESCE(SUM(bytes_sent),0)+COALESCE(SUM(bytes_recv),0)) DESC,app LIMIT ?")
                rows=self._conn.execute(sql,(cutoff,max(1,int(limit or 1000)))).fetchall()
                out=[]
                for app,sessions,active,samples,sent,recv,first,last in rows:
                    sent=int(sent or 0); recv=int(recv or 0)
                    out.append({"app":app or "Unknown","sessions":int(sessions or 0),"active_sessions":int(active or 0),
                        "samples":int(samples or 0),"bytes_sent":sent,"bytes_recv":recv,"bytes_total":sent+recv,
                        "first_seen":first or "","last_seen":last or ""})
                return out
            except: return []
    def prune(self,days=30):
        with self._lock:
            try:
                cutoff=(datetime.datetime.now()-datetime.timedelta(days=days)).strftime("%Y-%m-%d")
                self._conn.execute("DELETE FROM connections WHERE ts < ?",(cutoff,)); self._conn.commit()
            except: pass
    def count(self):
        with self._lock:
            try: return self._conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
            except: return 0
    def export_history(self,fmt="csv",query="",since=None,until=None,evidence="all",limit=50000):
        with self._lock:
            try:
                w,p=[],[]
                if query: w.append("(host LIKE ? OR proc LIKE ? OR ra LIKE ? OR org LIKE ? OR svc LIKE ? OR parent LIKE ? OR package LIKE ? OR signer LIKE ?)"); p.extend([f"%{query}%"]*8)
                if since: w.append("ts>=?"); p.append(since)
                if until: w.append("ts<=?"); p.append(until)
                if evidence=="event": w.append("event_source!=''")
                elif evidence=="psutil": w.append("(event_source IS NULL OR event_source='')")
                where=" WHERE "+" AND ".join(w) if w else ""
                sql=f"SELECT {','.join(CONN_EXPORT_COLUMNS)} FROM connections{where} ORDER BY id DESC LIMIT ?"
                p.append(limit); rows=self._conn.execute(sql,p).fetchall()
            except: return ""
        if fmt=="json":
            return json.dumps([dict(zip(CONN_EXPORT_COLUMNS,r)) for r in rows],indent=2,default=str)
        buf=io.StringIO()
        w=csv.writer(buf); w.writerow(CONN_EXPORT_COLUMNS)
        for r in rows: w.writerow(r)
        return buf.getvalue()
    def schema_version(self):
        with self._lock:
            try: return self._conn.execute("PRAGMA user_version").fetchone()[0]
            except: return 0


# ─── Firewall Engine ─────────────────────────────────────────────────────────
class FirewallEngine:
    def __init__(self):
        self._rule_cache=[]; self._cache_lock=Lock(); self._cache_time=0; self._cache_ttl=120
        self._known_names=set(); self._known_names_loaded=False
        self._tamper_lock=Lock(); self._managed_baseline=None; self._tamper_events=[]; self._local_changes={}
    def _invalidate(self):
        with self._cache_lock: self._cache_time=0
    def _mark_local_change(self,name):
        if not name: return
        with self._tamper_lock:
            self._local_changes[str(name)] = time.time() + 45
    def _consume_local_change(self,name):
        now=time.time()
        with self._tamper_lock:
            for stale,expiry in list(self._local_changes.items()):
                if expiry < now: self._local_changes.pop(stale,None)
            expiry=self._local_changes.get(str(name))
            if expiry and expiry >= now:
                self._local_changes.pop(str(name),None)
                return True
        return False
    def rule_exists(self,name):
        with self._cache_lock:
            if self._known_names_loaded: return name in self._known_names
        try: cmd = _build_rule_exists_cmd(name)
        except ValueError: return False
        ok,out=_ps(cmd,8)
        return ok and out.strip().lower()=="true"
    def create_rule(self,name,direction="Outbound",action="Block",remote_addr="",remote_port="",local_addr="",local_port="",protocol="",program="",profile="Any",desc="",enabled=True):
        try: cmd = _build_new_firewall_rule_cmd(name,direction,action,remote_addr,remote_port,local_addr,local_port,protocol,program,profile,desc,enabled)
        except ValueError as e: return False, str(e)
        ok,out=_ps(cmd,20)
        if ok:
            self._mark_local_change(name); self._invalidate(); self._known_names.add(name)
        return ok,out
    def delete_rule(self,name):
        try: cmd = _build_remove_firewall_rule_cmd(name)
        except ValueError as e: return False, str(e)
        ok,out=_ps(cmd,15)
        if ok:
            self._mark_local_change(name); self._invalidate(); self._known_names.discard(name)
        return ok,out
    def enable_rule(self,name,enabled=True):
        try: cmd = _build_set_firewall_rule_enabled_cmd(name,enabled)
        except ValueError: return False
        ok,_=_ps(cmd,10)
        if ok:
            self._mark_local_change(name); self._invalidate()
        return ok
    def get_all_rules(self,force_refresh=False):
        with self._cache_lock:
            if not force_refresh and self._rule_cache and (time.time()-self._cache_time)<self._cache_ttl: return list(self._rule_cache)
        rules=self._fetch_all()
        self._detect_tamper(rules)
        with self._cache_lock: self._rule_cache=rules; self._cache_time=time.time(); self._known_names={r.name for r in rules}; self._known_names_loaded=True
        return rules
    def _fetch_all(self):
        cmd=('Get-NetFirewallRule -EA SilentlyContinue | ForEach-Object { $af=$_|Get-NetFirewallAddressFilter -EA SilentlyContinue; $pf=$_|Get-NetFirewallPortFilter -EA SilentlyContinue; $ap=$_|Get-NetFirewallApplicationFilter -EA SilentlyContinue;'
            '[PSCustomObject]@{DN=$_.DisplayName;Desc=$_.Description;Dir=[int]$_.Direction;Act=[int]$_.Action;En=[int]$_.Enabled;Prof=$_.Profile.ToString();Grp=$_.Group;RA=$af.RemoteAddress;LA=$af.LocalAddress;RP=$pf.RemotePort;LP=$pf.LocalPort;Proto=$pf.Protocol;Prog=$ap.Program} } | ConvertTo-Json -Compress')
        ok,out=_ps(cmd,120); rules=[]
        if ok and out:
            try:
                data=json.loads(out)
                if isinstance(data,dict): data=[data]
                def _j(v):
                    if v is None: return ""
                    if isinstance(v,list): return ",".join(str(x) for x in v)
                    return str(v)
                for r in data:
                    try:
                        src="pywall" if _is_managed_rule_name(r.get("DN","")) else "system"
                        rules.append(FWRule(name=_j(r.get("DN","")),desc=_j(r.get("Desc","")),
                            direction="Inbound" if r.get("Dir") in (1,"1") else "Outbound",
                            action="Block" if r.get("Act") in (2,"2") else "Allow",
                            enabled=r.get("En") in (1,"1",True), profile=_j(r.get("Prof","Any")) or "Any",
                            group=_j(r.get("Grp","")), remote_addr=_j(r.get("RA","")), local_addr=_j(r.get("LA","")),
                            remote_port=_j(r.get("RP","")), local_port=_j(r.get("LP","")),
                            protocol=_j(r.get("Proto","Any")) or "Any", program=_j(r.get("Prog","")), source=src))
                    except: continue
            except Exception as e: log.warning(f"Rule parse error: {e}")
        return rules
    def _managed_snapshots(self,rules):
        return {r.name:_fw_rule_snapshot(r) for r in (rules or []) if r.name and _is_managed_rule_name(r.name)}
    def _detect_tamper(self,rules):
        current=self._managed_snapshots(rules)
        with self._tamper_lock:
            previous=self._managed_baseline
            if previous is None:
                self._managed_baseline=current
                return []
        events=[]
        for name in sorted(set(previous) - set(current)):
            if self._consume_local_change(name): continue
            events.append(self._record_tamper("deleted",name,previous.get(name),{}))
        for name in sorted(set(current) - set(previous)):
            if self._consume_local_change(name): continue
            events.append(self._record_tamper("created",name,{},current.get(name)))
        for name in sorted(set(previous) & set(current)):
            before=previous.get(name) or {}; after=current.get(name) or {}
            if before == after: continue
            if self._consume_local_change(name): continue
            if before.get("enabled") is True and after.get("enabled") is False:
                change="disabled"
            elif before.get("enabled") is False and after.get("enabled") is True:
                change="enabled"
            else:
                change="modified"
            events.append(self._record_tamper(change,name,before,after))
        with self._tamper_lock:
            self._managed_baseline=current
        return events
    def _record_tamper(self,change,name,before,after):
        diff=_fw_rule_diff(before,after)
        if change=="created": details=f"Managed rule externally created: {name}"
        elif change=="deleted": details=f"Managed rule externally deleted: {name}"
        else: details=f"Managed rule externally {change}: {name}; {diff}"
        event=FirewallTamperEvent(datetime.datetime.now().isoformat(timespec="seconds"),change,name,before or {},after or {},details)
        with self._tamper_lock:
            self._tamper_events.append(event)
            self._tamper_events=self._tamper_events[-200:]
        _firewall_tamper_log(event)
        return event
    def get_tamper_events(self,limit=50):
        with self._tamper_lock:
            return list(self._tamper_events[-int(limit or 50):])
    def tamper_summary(self):
        events=self.get_tamper_events(200)
        latest=events[-1] if events else None
        return {
            "pending": len(events),
            "latest": latest.as_dict() if latest else {},
            "log_path": FW_TAMPER_LOG_PATH,
        }
    def accept_current_rules(self):
        rules=self._fetch_all()
        current=self._managed_snapshots(rules)
        with self._tamper_lock:
            self._managed_baseline=current
            self._tamper_events=[]
            self._local_changes={}
        with self._cache_lock:
            self._rule_cache=rules; self._cache_time=time.time(); self._known_names={r.name for r in rules}; self._known_names_loaded=True
        return True, f"Accepted {len(current)} managed firewall rules as current baseline"
    def restore_last_tamper(self):
        events=self.get_tamper_events(1)
        if not events: return False, "No firewall tamper events to restore"
        event=events[-1]
        if event.change=="created":
            ok,out=self.delete_rule(event.rule_name)
            if ok: self.accept_current_rules()
            return ok,out
        before=event.before or {}
        if not before.get("name"): return False, "Tamper event has no prior rule snapshot"
        if self.rule_exists(before["name"]):
            self.delete_rule(before["name"])
        ok,out=self.create_rule(before["name"], before.get("direction","Outbound"), before.get("action","Block"),
            remote_addr=before.get("remote_addr",""), remote_port=before.get("remote_port",""),
            local_addr=before.get("local_addr",""), local_port=before.get("local_port",""),
            protocol=before.get("protocol",""), program=before.get("program",""),
            profile=before.get("profile","Any"), desc=before.get("desc",""), enabled=before.get("enabled",True))
        if ok: self.accept_current_rules()
        return ok,out
    def block_ip(self,ip,direction="Outbound"):
        safe=ip.replace(":","-").replace("/","_"); nm=f"{FW_PFX}Block_{safe}_{direction[:3]}"
        if self.rule_exists(nm): return True,"Rule already exists"
        return self.create_rule(nm,direction,"Block",remote_addr=ip,desc=f"Blocked by PyWall at {datetime.datetime.now():%Y-%m-%d %H:%M}")
    def allow_ip(self,ip,direction="Outbound"):
        safe=ip.replace(":","-").replace("/","_"); nm=f"{FW_PFX}Allow_{safe}_{direction[:3]}"
        if self.rule_exists(nm): return True,"Rule already exists"
        return self.create_rule(nm,direction,"Allow",remote_addr=ip,desc="Allowed by PyWall")
    def block_program(self,prog_path,direction="Outbound"):
        safe=Path(prog_path).stem[:30]; nm=f"{FW_PFX}Block_{safe}_{direction[:3]}"
        if self.rule_exists(nm): return True,"Rule already exists"
        return self.create_rule(nm,direction,"Block",program=prog_path,desc="Program blocked by PyWall")
    def allow_program(self,prog_path,direction="Outbound"):
        safe=Path(prog_path).stem[:30]; nm=f"{FW_PFX}Allow_{safe}_{direction[:3]}"
        if self.rule_exists(nm): return True,"Rule already exists"
        return self.create_rule(nm,direction,"Allow",program=prog_path,desc="Program allowed by PyWall learning review")
    def block_port(self,port,proto="TCP",direction="Outbound"):
        nm=f"{FW_PFX}Block_Port{port}_{proto}_{direction[:3]}"
        if self.rule_exists(nm): return True,"Rule already exists"
        return self.create_rule(nm,direction,"Block",remote_port=str(port),protocol=proto,desc="Port blocked by PyWall")
    def get_profile_status(self):
        ok,out=_ps("Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress",15)
        result={"Domain":True,"Private":True,"Public":True}
        if ok and out:
            try:
                data=json.loads(out)
                if isinstance(data,dict): data=[data]
                for p in data: result[p["Name"]]=bool(p["Enabled"])
            except: pass
        return result
    def kill_connection(self,pid):
        try: psutil.Process(pid).terminate(); return True
        except: return False
fw = FirewallEngine()

# ─── Hosts File Manager ─────────────────────────────────────────────────────
class HostsFileManager:
    def __init__(self): self.path=HOSTS_PATH; self.entries=[]; self.raw=[]
    def read(self):
        self.entries=[]; self.raw=[]
        try:
            with open(self.path,'r',encoding='utf-8',errors='replace') as f: self.raw=f.readlines()
        except: return
        for line in self.raw:
            s=line.strip()
            if not s: continue
            en=not s.startswith('#'); clean=s.lstrip('#').strip()
            m=re.match(r'^(\S+)\s+(\S+)',clean)
            if m: self.entries.append((m.group(1),m.group(2).lower(),en))
    def get_blocked(self): return {d for ip,d,en in self.entries if en and ip in BLOCK_IPS}
    def backup(self):
        d=os.path.join(CONFIG_DIR,"backups"); os.makedirs(d,exist_ok=True)
        dst=os.path.join(d,f"hosts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        try: shutil.copy2(self.path,dst); return dst
        except: return None
    def _flush(self):
        if sys.platform=='win32':
            try: subprocess.run(['ipconfig','/flushdns'],capture_output=True,timeout=10,creationflags=NOWIN)
            except: pass
    def add_block(self,domain):
        self.backup(); domain=domain.lower().strip()
        try:
            with open(self.path,'a',encoding='utf-8') as f: f.write(f"\n0.0.0.0 {domain}\n")
            self._flush()
        except: pass
    def add_blocks_bulk(self,domains):
        self.backup()
        try:
            with open(self.path,'a',encoding='utf-8') as f:
                for d in domains: f.write(f"0.0.0.0 {d.lower().strip()}\n")
            self._flush()
        except: pass
    def remove_block(self,domain):
        domain=domain.lower().strip(); self.backup()
        try:
            with open(self.path,'r',encoding='utf-8',errors='replace') as f: content=f.readlines()
            out=[]
            for line in content:
                m=re.match(r'^(\S+)\s+(\S+)',line.strip())
                if m and m.group(1) in BLOCK_IPS and m.group(2).lower()==domain: out.append(f"# WHITELISTED: {line.strip()}\n")
                else: out.append(line)
            with open(self.path,'w',encoding='utf-8') as f: f.writelines(out)
            self._flush()
        except: pass
    def remove_entry(self,domain):
        domain=domain.lower().strip(); self.backup()
        try:
            with open(self.path,'r',encoding='utf-8',errors='replace') as f: content=f.readlines()
            out=[]
            for line in content:
                clean=line.strip().lstrip('#').strip()
                m=re.match(r'^(?:WHITELISTED:\s*)?(\S+)\s+(\S+)',clean)
                if m and m.group(1) in BLOCK_IPS and m.group(2).lower()==domain: continue
                out.append(line)
            with open(self.path,'w',encoding='utf-8') as f: f.writelines(out)
            self._flush()
        except: pass
    def restore_block(self,domain):
        domain=domain.lower().strip(); self.backup()
        try:
            with open(self.path,'r',encoding='utf-8',errors='replace') as f: content=f.readlines()
            out=[]; found=False
            for line in content:
                s=line.strip()
                if s.startswith('#') and domain in s.lower():
                    clean=s.lstrip('#').strip()
                    if clean.startswith('WHITELISTED:'): clean=clean[len('WHITELISTED:'):].strip()
                    m=re.match(r'^(\S+)\s+(\S+)',clean)
                    if m and m.group(1) in BLOCK_IPS and m.group(2).lower()==domain: out.append(f"0.0.0.0 {domain}\n"); found=True; continue
                out.append(line)
            if not found: out.append(f"\n0.0.0.0 {domain}\n")
            with open(self.path,'w',encoding='utf-8') as f: f.writelines(out)
            self._flush()
        except: pass
    def write_full(self,content):
        self.backup()
        try:
            with open(self.path,'w',encoding='utf-8',newline='\n') as f: f.write(content)
            self._flush(); return None
        except Exception as e: return str(e)
    def read_raw(self):
        try:
            with open(self.path,'r',encoding='utf-8',errors='replace') as f: return f.read()
        except: return ""

# ─── Bandwidth Tracker ───────────────────────────────────────────────────────
class BandwidthTracker:
    def __init__(self):
        self._lock=Lock(); self._prev=psutil.net_io_counters(); self._prev_time=time.time()
        self._rate_up=0.0; self._rate_dn=0.0; self._total_sent=0; self._total_recv=0
    def update(self):
        with self._lock:
            now=time.time(); dt=max(now-self._prev_time,0.1); cur=psutil.net_io_counters()
            ds=cur.bytes_sent-self._prev.bytes_sent; dr=cur.bytes_recv-self._prev.bytes_recv
            self._rate_up=ds/dt; self._rate_dn=dr/dt; self._total_sent+=ds; self._total_recv+=dr
            self._prev=cur; self._prev_time=now
    def rates(self):
        with self._lock: return (self._rate_up,self._rate_dn)
    def format_rate(self,bps):
        for u in ("B/s","KB/s","MB/s","GB/s"):
            if bps<1024: return f"{bps:.1f} {u}"
            bps/=1024
        return f"{bps:.1f} TB/s"
bw_tracker = BandwidthTracker()

def _fmt_bytes(n):
    try: n = int(n or 0)
    except: n = 0
    for unit in ("B","KB","MB","GB","TB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def _fmt_duration(seconds):
    try: seconds = max(0, int(seconds or 0))
    except: seconds = 0
    h, rem = divmod(seconds, 3600); m, s = divmod(rem, 60)
    if h: return f"{h}h {m:02d}m"
    if m: return f"{m}m {s:02d}s"
    return f"{s}s"

def _parse_bytes_limit(value):
    if isinstance(value, (int, float)): return max(0, int(value))
    if not isinstance(value, str): return 0
    text = value.strip().lower().replace(" ", "")
    m = re.match(r'^(\d+(?:\.\d+)?)(b|byte|bytes|kb|kib|mb|mib|gb|gib|tb|tib)?$', text)
    if not m: return 0
    n = float(m.group(1)); unit = m.group(2) or "b"
    mult = {"b":1,"byte":1,"bytes":1,"kb":1024,"kib":1024,"mb":1024**2,"mib":1024**2,
            "gb":1024**3,"gib":1024**3,"tb":1024**4,"tib":1024**4}.get(unit, 1)
    return max(0, int(n * mult))

class BandwidthQuotaEnforcer:
    def __init__(s, owner="PyWall"):
        s.owner = owner; s._lock = Lock(); s._quotas = {}; s._config_mtime = None
        s._state = None; s._last_config_reload = ""; s._last_event = ""; s._blocked_count = 0

    def load_config(s, cfg, mtime=None):
        raw = cfg.get("bandwidth_quotas", {}) if isinstance(cfg, dict) else {}
        quotas = {}
        if isinstance(raw, list):
            pairs = [(x.get("app") or x.get("match") or x.get("process") or x.get("path"), x) for x in raw if isinstance(x, dict)]
        elif isinstance(raw, dict):
            pairs = list(raw.items())
        else:
            pairs = []
        for match, spec in pairs:
            if not match: continue
            spec = spec if isinstance(spec, dict) else {"limit": spec}
            if spec.get("enabled", True) is False: continue
            limit = _parse_bytes_limit(spec.get("limit", spec.get("bytes", spec.get("quota"))))
            if limit <= 0: continue
            key = s._norm(match)
            quotas[key] = {
                "key": key, "match": str(match), "limit": limit,
                "window": str(spec.get("window", "day")).lower(),
                "direction": str(spec.get("direction", "both")).lower(),
                "action": str(spec.get("action", "block")).lower(),
            }
        with s._lock:
            s._quotas = quotas; s._config_mtime = mtime
            s._last_config_reload = datetime.datetime.now().isoformat(timespec="seconds") if quotas else "none"

    def reload_config_if_changed(s, force=False):
        result=load_runtime_config()
        if not force and s._config_mtime == result.mtime: return
        s.load_config(result.data,result.mtime)
        if result.warnings: log.warning("; ".join(result.warnings))

    def check(s, conns, db=None):
        s.reload_config_if_changed()
        with s._lock: quotas = list(s._quotas.items())
        if not quotas or not conns: return []
        s._ensure_state()
        buckets = {}
        now = datetime.datetime.now()
        for c in conns:
            for key, quota in quotas:
                if not s._matches(quota, c): continue
                delta = s._conn_delta(c, quota.get("direction", "both"))
                if delta <= 0: continue
                period = s._period(quota.get("window", "day"), now)
                bucket = buckets.setdefault((period, key), {"quota": quota, "delta": 0, "samples": []})
                bucket["delta"] += delta; bucket["samples"].append(c)
        if not buckets: return []
        pending = []
        with s._lock:
            usage = s._state.setdefault("usage", {})
            blocked = s._state.setdefault("blocked", {})
            for state_key, bucket in buckets.items():
                period, key = state_key; quota = bucket["quota"]
                sk = f"{period}|{key}"
                used = int(usage.get(sk, 0) or 0) + int(bucket["delta"])
                usage[sk] = used
                if used >= quota["limit"] and sk not in blocked:
                    blocked[sk] = {"at": now.isoformat(timespec="seconds"), "used": used, "limit": quota["limit"], "match": quota["match"], "blocked": False}
                    pending.append((sk, period, key, quota, used, bucket["samples"]))
            s._state["saved_at"] = now.isoformat(timespec="seconds")
            s._save_state_locked()
        events = []
        for sk, period, key, quota, used, samples in pending:
            ev = s._enforce(sk, period, key, quota, used, samples, db)
            events.append(ev)
        if events:
            with s._lock:
                blocked = s._state.setdefault("blocked", {})
                for ev in events:
                    rec = blocked.get(f"{ev.period}|{ev.key}", {})
                    rec.update({"blocked": ev.blocked, "message": ev.message, "used": ev.used})
                    blocked[f"{ev.period}|{ev.key}"] = rec
                    s._last_event = f"{ev.app}: {_fmt_bytes(ev.used)}/{_fmt_bytes(ev.limit)}"
                s._blocked_count = sum(1 for x in blocked.values() if x.get("blocked"))
                s._save_state_locked()
        return events

    def snapshot(s):
        s._ensure_state()
        with s._lock:
            return {"configured": len(s._quotas), "blocked": s._blocked_count, "last_event": s._last_event, "last_config_reload": s._last_config_reload, "state_path": QUOTA_STATE_PATH}

    def _enforce(s, sk, period, key, quota, used, samples, db):
        app = s._label(quota, samples); path = s._first_path(samples)
        limit = quota["limit"]; messages = []; ok_any = False
        if quota.get("action") not in ("notify", "warn", "log"):
            if path:
                ok, out = fw.block_program(path, "Outbound"); ok_any = ok_any or ok
                messages.append(f"program={'ok' if ok else out}")
            for ip in s._remote_ips(samples)[:6]:
                ok, out = fw.block_ip(ip, "Outbound"); ok_any = ok_any or ok
                messages.append(f"{ip}={'ok' if ok else out}")
        else:
            messages.append("notify only")
        msg = "; ".join(messages) if messages else "no active program path or remote IP to block"
        ev = QuotaEvent(key=key, period=period, app=app, path=path, limit=limit, used=used, blocked=ok_any, message=msg)
        if db:
            try: db.log_event(app, "quota_block" if ok_any else "quota_exceeded", s.owner, f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}; {msg}")
            except: pass
        return ev

    def _ensure_state(s):
        with s._lock:
            if s._state is not None: return
            try:
                with open(QUOTA_STATE_PATH, "r", encoding="utf-8") as f: state = json.load(f)
                if not isinstance(state, dict): state = {}
            except: state = {}
            state.setdefault("usage", {}); state.setdefault("blocked", {})
            s._state = state; s._blocked_count = sum(1 for x in state.get("blocked", {}).values() if isinstance(x, dict) and x.get("blocked"))

    def _save_state_locked(s):
        try:
            tmp = QUOTA_STATE_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f: json.dump(s._state, f, indent=2, sort_keys=True)
            os.replace(tmp, QUOTA_STATE_PATH)
        except Exception as e: log.warning(f"Quota state save failed: {e}")

    def _conn_delta(s, c, direction):
        sent = int(getattr(c, "bytes_sent", 0) or 0); recv = int(getattr(c, "bytes_recv", 0) or 0)
        if direction in ("sent", "send", "upload", "out", "outbound"): return sent
        if direction in ("recv", "receive", "download", "in", "inbound"): return recv
        return sent + recv

    def _matches(s, quota, c):
        key = quota["key"]
        proc = s._norm(getattr(c, "proc", ""))
        path = s._norm(getattr(c, "path", ""))
        base = s._norm(os.path.basename(path)) if path else ""
        values = [v for v in (proc, base, path) if v and v not in ("-", "?")]
        return any(fnmatch.fnmatchcase(v, key) for v in values)

    def _period(s, window, now):
        if window in ("week", "weekly"):
            iso = now.isocalendar(); return f"week:{iso.year}-W{iso.week:02d}"
        if window in ("forever", "lifetime", "total"): return "lifetime"
        return f"day:{now.date().isoformat()}"

    def _label(s, quota, samples):
        for c in samples:
            if getattr(c, "proc", "") not in ("", "-", "?"): return c.proc
        return quota.get("match", quota.get("key", "app"))

    def _first_path(s, samples):
        for c in samples:
            path = getattr(c, "path", "")
            if path and path not in ("-", "N/A"): return path
        return ""

    def _remote_ips(s, samples):
        out = []
        for c in samples:
            ip = getattr(c, "ra", "")
            if ip and ip not in ("*", "-") and not PRIV_RE.match(ip) and ip not in out: out.append(ip)
        return out

    def _norm(s, value):
        return str(value or "").strip().lower().replace("/", "\\")

class DoHDetector:
    def __init__(s, owner="PyWall"):
        s.owner=owner; s._lock=Lock(); s._enabled=True; s._action="warn"; s._config_mtime=None
        s._seen={}; s._detected=0; s._blocked=0
    def configure(s,cfg=None,mtime=None):
        cfg = cfg if isinstance(cfg, dict) else {}
        enabled = bool(cfg.get("detect_doh", True))
        action = str(cfg.get("doh_action", "block" if cfg.get("doh_block", False) else "warn")).lower()
        if action not in ("warn","block","ignore"): action = "warn"
        with s._lock:
            s._enabled=enabled; s._action=action; s._config_mtime=mtime
    def reload_config_if_changed(s,force=False):
        result=load_runtime_config()
        with s._lock:
            if not force and s._config_mtime == result.mtime: return
        s.configure(result.data, result.mtime)
    def check(s,conns,db=None):
        s.reload_config_if_changed()
        with s._lock: enabled,action=s._enabled,s._action
        if not enabled or action=="ignore": return []
        now=time.time(); events=[]
        for c in conns:
            if not detect_doh_endpoint(c.host, c.ra, c.rp): continue
            key=f"{c.ra}|{c.rp}|{c.proc}"
            with s._lock:
                if key in s._seen and now-s._seen[key]<300: continue
                s._seen[key]=now; s._detected+=1
            blocked=False; msg="warned"
            if action=="block" and c.ra and not PRIV_RE.match(c.ra):
                ok,out=fw.block_ip(c.ra,"Outbound"); blocked=ok; msg="blocked" if ok else out
                if ok:
                    with s._lock: s._blocked+=1
            target = c.host if c.host not in ("","-","...") else c.ra
            ev=DoHEvent(endpoint=c.ra,host=c.host,app=c.proc,action=action,blocked=blocked,message=msg)
            events.append(ev)
            if db:
                try: db.log_event(target,"doh_block" if blocked else "doh_warn",s.owner,f"{c.proc} -> {c.ra}:{c.rp}; {msg}")
                except: pass
        return events
    def snapshot(s):
        with s._lock: return {"enabled":s._enabled,"action":s._action,"detected":s._detected,"blocked":s._blocked}

class IDSRuleEngine:
    def __init__(s, owner="PyWall"):
        s.owner=owner; s._lock=Lock(); s._enabled=True; s._path=IDS_RULES_PATH; s._rules=[]; s._rules_mtime=None; s._config_mtime=None; s._seen={}; s._hits=0; s._blocked=0
    def configure(s,cfg=None,mtime=None):
        cfg = cfg if isinstance(cfg, dict) else {}
        enabled=bool(cfg.get("ids_rules_enabled", True)); path=str(cfg.get("ids_rules_path", IDS_RULES_PATH) or IDS_RULES_PATH)
        with s._lock:
            if path != s._path: s._rules=[]; s._rules_mtime=None
            s._enabled=enabled; s._path=path; s._config_mtime=mtime
    def reload(s):
        result=load_runtime_config()
        with s._lock:
            same_config = s._config_mtime == result.mtime
        if not same_config:
            s.configure(result.data, result.mtime)
        with s._lock:
            enabled,path,last=s._enabled,s._path,s._rules_mtime
        if not enabled or not path or not os.path.exists(path): return
        try: rmtime=os.path.getmtime(path)
        except: return
        if last == rmtime: return
        try:
            with open(path,"r",encoding="utf-8",errors="replace") as f: rules=s._parse_rules(f.read())
            with s._lock: s._rules=rules; s._rules_mtime=rmtime
        except Exception as e: log.warning(f"IDS rule load failed: {e}")
    def check(s,conns,db=None):
        s.reload()
        with s._lock: rules=list(s._rules); enabled=s._enabled
        if not enabled or not rules or not conns: return []
        now=time.time(); hits=[]
        for ci in conns:
            for rule in rules:
                if not s._match_rule(rule,ci): continue
                key=f"{rule.name}|{ci.proc}|{ci.ra}|{ci.rp}"
                with s._lock:
                    if key in s._seen and now-s._seen[key]<300: continue
                    s._seen[key]=now; s._hits+=1
                blocked=False; msg="matched"
                if rule.action=="block" and ci.ra and not PRIV_RE.match(ci.ra):
                    ok,out=fw.block_ip(ci.ra,"Outbound"); blocked=ok; msg="blocked" if ok else out
                    if ok:
                        with s._lock: s._blocked+=1
                threats.add_ids_hit(rule,ci,blocked)
                target=ci.host if ci.host not in ("","-","...") else ci.ra
                if db:
                    try: db.log_event(target,"ids_block" if blocked else "ids_match",s.owner,f"{rule.name}: {msg}")
                    except: pass
                hits.append({"rule":rule.name,"app":ci.proc,"endpoint":ci.ra,"blocked":blocked,"message":msg})
        return hits
    def _parse_rules(s,text):
        rules=[]; cur=None; in_cond=False
        for raw in text.splitlines():
            line=raw.strip()
            if not line or line.startswith(("#","//")): continue
            m=re.match(r'^rule\s+([A-Za-z0-9_.-]+)\s*\{?$',line,re.I)
            if m:
                cur={"name":m.group(1),"meta":{},"cond":[]}; in_cond=False; continue
            if cur is None: continue
            if line.startswith("}"):
                cond=" ".join(cur["cond"]).strip().rstrip(";")
                if cond: rules.append(s._build_rule(cur["name"],cur["meta"],cond))
                cur=None; in_cond=False; continue
            if line.lower().startswith("condition:"):
                in_cond=True; rest=line.split(":",1)[1].strip()
                if rest: cur["cond"].append(rest.rstrip(";"))
                continue
            if in_cond:
                cur["cond"].append(line.rstrip(";")); continue
            if "=" in line:
                k,v=line.split("=",1); cur["meta"][k.strip().lower()]=v.strip().strip("\"'")
        return rules
    def _build_rule(s,name,meta,cond):
        return IDSRule(name=name,severity=meta.get("severity","medium").lower(),description=meta.get("description",""),
            condition=cond,action=meta.get("action","warn").lower(),mitre_tactic=meta.get("mitre_tactic",""),
            mitre_technique=meta.get("mitre_technique",meta.get("mitre","")),mitre_url=meta.get("mitre_url",""))
    def _match_rule(s,rule,ci):
        for term in re.split(r'\s+and\s+',rule.condition,flags=re.I):
            if term and not s._match_term(term.strip(),ci): return False
        return True
    def _match_term(s,term,ci):
        fields={"host":ci.host,"proc":ci.proc,"process":ci.proc,"path":ci.path,"ip":ci.ra,"ra":ci.ra,"rp":ci.rp,
            "port":ci.rp,"country":ci.country,"org":ci.org,"category":ci.category,"stat":ci.stat,"proto":ci.proto,"dir":ci.dir}
        for op in ("contains","matches","==","!=","in"):
            if op in term:
                left,right=term.split(op,1); field=left.strip().lower(); val=str(fields.get(field,""))
                rhs=right.strip().strip("\"'")
                if op=="contains": return rhs.lower() in val.lower()
                if op=="matches":
                    try: return re.search(rhs,val,re.I) is not None
                    except: return False
                if op=="==": return val.lower()==rhs.lower()
                if op=="!=": return val.lower()!=rhs.lower()
                if op=="in":
                    vals=[x.strip().strip("\"'") for x in rhs.strip("()[]").split(",")]
                    return val.lower() in {x.lower() for x in vals}
        return False
    def snapshot(s):
        with s._lock: return {"enabled":s._enabled,"path":s._path,"rules":len(s._rules),"hits":s._hits,"blocked":s._blocked}

def export_usage_reports(report_dir=None):
    report_dir = report_dir or REPORT_DIR
    os.makedirs(report_dir, exist_ok=True)
    cdb = ConnDB(); today = datetime.datetime.now().strftime("%Y-%m-%d")
    exports = []
    columns = ["period","app","sessions","active_sessions","samples","bytes_sent","bytes_recv","bytes_total","sent","recv","total","first_seen","last_seen"]
    for period, days in (("daily",1),("weekly",7)):
        rows = cdb.usage_report(days=days)
        csv_path = os.path.join(report_dir, f"pywall-usage-{period}-{today}.csv")
        html_path = os.path.join(report_dir, f"pywall-usage-{period}-{today}.html")
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=columns); w.writeheader()
            for row in rows:
                w.writerow({
                    "period": period, "app": row["app"], "sessions": row["sessions"], "active_sessions": row["active_sessions"],
                    "samples": row["samples"], "bytes_sent": row["bytes_sent"], "bytes_recv": row["bytes_recv"], "bytes_total": row["bytes_total"],
                    "sent": _fmt_bytes(row["bytes_sent"]), "recv": _fmt_bytes(row["bytes_recv"]), "total": _fmt_bytes(row["bytes_total"]),
                    "first_seen": row["first_seen"], "last_seen": row["last_seen"],
                })
        body = []
        for row in rows:
            body.append("<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in [
                row["app"], row["sessions"], row["active_sessions"], row["samples"], _fmt_bytes(row["bytes_sent"]),
                _fmt_bytes(row["bytes_recv"]), _fmt_bytes(row["bytes_total"]), row["first_seen"], row["last_seen"]]) + "</tr>")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write("<!doctype html><html><head><meta charset='utf-8'><title>PyWall Usage Report</title>"
                    "<style>body{font-family:Segoe UI,Arial,sans-serif;background:#11111b;color:#cdd6f4;margin:24px}"
                    "table{border-collapse:collapse;width:100%;background:#181825}th,td{border:1px solid #313244;padding:8px;text-align:left}"
                    "th{background:#1e1e2e;color:#89b4fa}td:nth-child(n+2){font-family:Consolas,monospace}</style></head><body>")
            f.write(f"<h1>PyWall {period.title()} Usage Report</h1><p>Generated {html.escape(datetime.datetime.now().isoformat(timespec='seconds'))}. "
                    f"Rows include sessions last seen in the previous {days} day(s).</p>")
            f.write("<table><thead><tr><th>App</th><th>Sessions</th><th>Active</th><th>Samples</th><th>Sent</th><th>Received</th><th>Total</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>")
            f.write("".join(body) if body else "<tr><td colspan='9'>No connection sessions found for this period.</td></tr>")
            f.write("</tbody></table></body></html>")
        exports.append({"period": period, "csv": csv_path, "html": html_path, "rows": len(rows)})
    return exports

MITRE_MAPPINGS = {
    "PORT_SCAN": {
        "tactic": "Discovery",
        "technique": "T1046 Network Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "T1110 Brute Force",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "BEACON": {
        "tactic": "Command and Control",
        "technique": "T1071 Application Layer Protocol",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
}

def _mitre_for_event(etype):
    return MITRE_MAPPINGS.get(etype, {"tactic": "Unmapped", "technique": "Unmapped", "url": ""})

# ─── Threat Detector ─────────────────────────────────────────────────────────
class ThreatDetector:
    def __init__(self):
        self._lock=Lock(); self._port_hits=defaultdict(list); self._block_hits=defaultdict(list); self._beacon_hits=defaultdict(list); self._beacon_alerts={}
        self._events=[]; self._max=500
    def record(self,ip,port,blocked=False):
        with self._lock:
            now=time.time()
            if port:
                self._port_hits[ip]=[t for t in self._port_hits[ip] if now-t<60]+[now]
                if len(self._port_hits[ip])>=15:
                    self._add_event("PORT_SCAN","high",ip,f"Port scan detected: {len(self._port_hits[ip])} ports in 60s")
                    self._port_hits[ip].clear()
            if blocked:
                self._block_hits[ip]=[t for t in self._block_hits[ip] if now-t<60]+[now]
                if len(self._block_hits[ip])>=10:
                    self._add_event("BRUTE_FORCE","high",ip,f"Brute force: {len(self._block_hits[ip])} blocked in 60s")
                    self._block_hits[ip].clear()
    def record_beacon(self,ci):
        ip=getattr(ci,"ra","")
        if not ip or ip in ("*","-") or PRIV_RE.match(ip) or getattr(ci,"dir","")!="Out": return
        low,reason=self._low_rep_reason(ci)
        if not low: return
        now=time.time(); key=f"{getattr(ci,'proc','?')}|{ip}|{getattr(ci,'rp','')}"
        with self._lock:
            hits=self._beacon_hits[key]
            if hits and now-hits[-1] < 10: return
            hits.append(now); hits[:]=[t for t in hits if now-t<1800][-10:]
            if len(hits)<5: return
            recent=hits[-5:]; intervals=[recent[i]-recent[i-1] for i in range(1,len(recent))]
            avg=sum(intervals)/len(intervals)
            if avg<20: return
            drift=max(abs(x-avg) for x in intervals)/avg if avg else 1
            if drift>0.35: return
            if key in self._beacon_alerts and now-self._beacon_alerts[key]<1800: return
            self._beacon_alerts[key]=now
            self._add_event("BEACON","high",ip,f"Periodic outbound beacon from {ci.proc} to {ip}:{ci.rp} every ~{int(avg)}s ({reason})")
    def _low_rep_reason(self,ci):
        stat=(getattr(ci,"stat","") or "").upper(); cat=getattr(ci,"category","") or ""
        host=getattr(ci,"host","") or ""; org=getattr(ci,"org","") or ""
        if "BLOCK" in stat or "DOH" in stat: return True,"flagged endpoint"
        if cat=="Ads / Tracking": return True,"ads/tracking category"
        if host in ("","-","...") and org in ("","-","..."): return True,"unattributed endpoint"
        return False,""
    def add_ids_hit(self,rule,ci,blocked=False):
        mitre={"tactic":rule.mitre_tactic or "Detection","technique":rule.mitre_technique or "IDS-lite Rule","url":rule.mitre_url or ""}
        suffix="; blocked" if blocked else ""
        with self._lock:
            self._add_event("IDS_RULE",rule.severity,ci.ra,f"{rule.name}: {rule.description or rule.condition} ({ci.proc} -> {ci.ra}:{ci.rp}){suffix}",mitre)
    def _add_event(self,etype,severity,ip,details,mitre=None):
        mitre=mitre or _mitre_for_event(etype)
        evt=ThreatEvent(ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),type=etype,severity=severity,source_ip=ip,details=details,action_taken="Logged",
            mitre_tactic=mitre.get("tactic",""),mitre_technique=mitre.get("technique",""),mitre_url=mitre.get("url",""))
        self._events.append(evt)
        if len(self._events)>self._max: self._events.pop(0)
    def get_events(self,n=100):
        with self._lock: return list(self._events[-n:])
    def get_stats(self):
        with self._lock: return {"total":len(self._events),"high":sum(1 for e in self._events if e.severity=="high")}
    def clear(self):
        with self._lock: self._events.clear()
threats = ThreatDetector()


# ─── Worker Threads ──────────────────────────────────────────────────────────
class DNSResolveWorker(QThread):
    ready=pyqtSignal(str,str)
    def __init__(s): super().__init__(); s._q=Queue(); s._stop=TEvent()
    def add(s,ip):
        if ip and ip not in dns_c and not PRIV_RE.match(ip): s._q.put(ip)
    def run(s):
        while not s._stop.is_set():
            try:
                ip=s._q.get(timeout=1)
                if ip in dns_c: continue
                try: h=socket.gethostbyaddr(ip)[0]; dns_c.put(ip,h); s.ready.emit(ip,h)
                except: dns_c.put(ip,"-")
            except Empty: pass
    def stop(s): s._stop.set()

class WhoWorker(QThread):
    ready=pyqtSignal(str,str)
    def __init__(s): super().__init__(); s._q=Queue(); s._stop=TEvent()
    def add(s,ip):
        if ip and ip not in who_c and not PRIV_RE.match(ip): s._q.put(ip)
    def run(s):
        while not s._stop.is_set():
            try:
                ip=s._q.get(timeout=1)
                if ip in who_c: continue
                try:
                    req=urllib.request.Request(f"https://ipinfo.io/{ip}/json",headers={'User-Agent':'Mozilla/5.0'})
                    with urllib.request.urlopen(req,timeout=8) as resp:
                        d=json.loads(resp.read()); org=d.get("org","-"); who_c.put(ip,org); s.ready.emit(ip,org)
                except: who_c.put(ip,"-")
            except Empty: pass
    def stop(s): s._stop.set()

class GeoIPWorker(QThread):
    ready=pyqtSignal(str,str,str); status_changed=pyqtSignal(str)
    def __init__(s):
        super().__init__(); s._q=Queue(); s._stop=TEvent(); s._batch=[]; s._lock=Lock()
        s._provider="ipwhois"; s._mmdb_path=""; s._https_endpoint=GEOIP_HTTPS_ENDPOINT; s._config_mtime=None
        s._reader=None; s._reader_path=""; s._last_status=""; s._lookups=0; s._unknown=0
    def add(s,ip):
        if ip and ip not in geo_c and not PRIV_RE.match(ip): s._q.put(ip)
    def run(s):
        while not s._stop.is_set():
            s._reload_config_if_changed()
            try:
                while not s._q.empty() and len(s._batch)<100:
                    ip=s._q.get_nowait()
                    if ip not in geo_c: s._batch.append(ip)
            except: pass
            if s._batch:
                batch=[ip for ip in s._batch[:100] if ip and not PRIV_RE.match(ip)]
                for ip in batch:
                    if ip in geo_c: continue
                    cc,country=s._lookup(ip)
                    geo_c.put(ip,(cc,country))
                    if cc or country != "-": s.ready.emit(ip,cc,country)
                s._batch.clear()
            s._stop.wait(2)
    def _reload_config_if_changed(s):
        result=load_runtime_config()
        with s._lock:
            if s._config_mtime == result.mtime: return
        s.configure(result.data, result.mtime)
        if result.warnings:
            s._emit_status("; ".join(result.warnings[:2]))
    def configure(s,cfg=None,mtime=None):
        cfg=cfg if isinstance(cfg,dict) else {}
        provider=str(cfg.get("geoip_provider","ipwhois") or "ipwhois").strip().lower()
        if provider not in ("ipwhois","maxmind","disabled"): provider="ipwhois"
        endpoint=str(cfg.get("geoip_https_endpoint",GEOIP_HTTPS_ENDPOINT) or GEOIP_HTTPS_ENDPOINT).strip()
        if not endpoint.lower().startswith("https://"): endpoint=GEOIP_HTTPS_ENDPOINT
        mmdb=str(cfg.get("geoip_mmdb_path","") or "").strip()
        with s._lock:
            if mmdb != s._mmdb_path: s._close_reader()
            s._provider=provider; s._mmdb_path=mmdb; s._https_endpoint=endpoint; s._config_mtime=mtime
    def _lookup(s,ip):
        with s._lock:
            provider=s._provider; endpoint=s._https_endpoint; mmdb=s._mmdb_path
        if provider=="disabled":
            s._unknown += 1
            return "","-"
        if provider=="maxmind":
            hit=s._lookup_mmdb(ip,mmdb)
            if hit: return hit
            s._unknown += 1
            return "","-"
        hit=s._lookup_mmdb(ip,mmdb) if mmdb else None
        if hit: return hit
        hit=s._lookup_https(ip,endpoint)
        if hit: return hit
        s._unknown += 1
        return "","-"
    def _lookup_mmdb(s,ip,path):
        if not path or not os.path.exists(path): return None
        try:
            import maxminddb
            with s._lock:
                if s._reader is None or s._reader_path != path:
                    s._close_reader()
                    s._reader=maxminddb.open_database(path)
                    s._reader_path=path
                reader=s._reader
            rec=reader.get(ip) or {}
            country=rec.get("country") or rec.get("registered_country") or {}
            cc=str(country.get("iso_code") or "").upper()
            names=country.get("names") if isinstance(country.get("names"),dict) else {}
            name=str(names.get("en") or country.get("name") or cc or "-")
            if cc or name!="-":
                s._lookups += 1
                return cc,name
        except Exception as e:
            s._emit_status(f"GeoIP MMDB unavailable: {e}")
        return None
    def _lookup_https(s,ip,endpoint):
        if not endpoint.lower().startswith("https://"):
            s._emit_status("GeoIP HTTPS endpoint rejected")
            return None
        try:
            import urllib.request as ur
            url=endpoint.format(ip=urllib.parse.quote(ip,safe=":."))
            req=ur.Request(url,headers={'User-Agent':f'{APP_NAME}/{APP_VERSION}'})
            with ur.urlopen(req,timeout=8) as resp:
                data=json.loads(resp.read())
            if not isinstance(data,dict) or data.get("success") is False: return None
            cc=str(data.get("country_code") or data.get("countryCode") or data.get("country_code2") or "").upper()
            country=str(data.get("country") or data.get("country_name") or cc or "-")
            if cc or country!="-":
                s._lookups += 1
                return cc,country
        except Exception as e:
            s._emit_status(f"GeoIP HTTPS lookup failed: {e}")
        return None
    def _emit_status(s,msg):
        if msg == s._last_status: return
        s._last_status=msg; s.status_changed.emit(msg)
    def _close_reader(s):
        try:
            if s._reader is not None: s._reader.close()
        except: pass
        s._reader=None; s._reader_path=""
    def snapshot(s):
        with s._lock:
            return {"provider":s._provider,"mmdb_path":s._mmdb_path,"https_endpoint":s._https_endpoint,"lookups":s._lookups,"unknown":s._unknown}
    def stop(s):
        s._stop.set(); s._close_reader()

class SignerWorker(QThread):
    ready=pyqtSignal(str,str)
    def __init__(s):
        super().__init__(); s._q=Queue(); s._stop=TEvent(); s._lock=Lock(); s._queued=set()
    def add(s,path):
        text=str(path or "").strip()
        if sys.platform!="win32" or not text or text=="-" or signer_c.get(text) is not None:
            return
        with s._lock:
            if text in s._queued: return
            s._queued.add(text)
        s._q.put(text)
    def run(s):
        while not s._stop.is_set():
            try: path=s._q.get(timeout=1)
            except Empty: continue
            with s._lock: s._queued.discard(path)
            if signer_c.get(path) is not None: continue
            label=_authenticode_signer_label(path)
            signer_c.put(path,label)
            s.ready.emit(path,label)
    def snapshot(s):
        with s._lock: queued=len(s._queued)
        return {"queued":queued,"cached":len(signer_c)}
    def stop(s): s._stop.set()

class TLSLogWorker(QThread):
    status_changed=pyqtSignal(str); feed_updated=pyqtSignal()
    def __init__(s,db):
        super().__init__(); s.db=db; s._stop=TEvent(); s._lock=Lock()
        s._enabled=False; s._path=""; s._offset=None; s._read_existing=False
        s._config_mtime=None; s._seen=0; s._last_domain=""; s._last_status=""
    def configure(s,cfg=None,mtime=None):
        cfg = cfg if isinstance(cfg, dict) else {}
        enabled = bool(cfg.get("tls_sni_enabled", False))
        path = str(cfg.get("tls_sni_log_path", "") or "").strip()
        read_existing = bool(cfg.get("tls_sni_read_existing", False))
        with s._lock:
            if path != s._path or read_existing != s._read_existing:
                s._offset = 0 if read_existing else None
            s._enabled=enabled; s._path=path; s._read_existing=read_existing; s._config_mtime=mtime
    def run(s):
        while not s._stop.is_set():
            try:
                s._reload_config_if_changed(); s._poll()
            except Exception as e:
                s._emit_status(f"TLS SNI hook error: {e}")
            s._stop.wait(2.0)
    def _reload_config_if_changed(s):
        result=load_runtime_config()
        with s._lock:
            if s._config_mtime == result.mtime: return
        s.configure(result.data, result.mtime)
        if result.warnings: s._emit_status("; ".join(result.warnings[:2]))
    def _poll(s):
        with s._lock:
            enabled,path,offset=s._enabled,s._path,s._offset
        if not enabled or not path: return
        if not os.path.exists(path):
            s._emit_status("TLS SNI log missing"); return
        with open(path,"r",encoding="utf-8",errors="replace") as f:
            if offset is None:
                f.seek(0, os.SEEK_END); s._set_offset(f.tell()); return
            f.seek(offset); lines=f.readlines(256000); s._set_offset(f.tell())
        new_ct=0
        for line in lines:
            domain=s._extract_sni(line)
            if not domain: continue
            is_new=s.db.feed_upsert(domain,"tls-sni")
            if is_new:
                s.db.log_event(domain,"tls_sni","TLSLogWorker",f"SNI observed from {os.path.basename(path)}")
                new_ct+=1
            s._last_domain=domain; s._seen+=1
        if new_ct:
            s.feed_updated.emit(); s._emit_status(f"TLS SNI captured {new_ct} new domains")
    def _set_offset(s,offset):
        with s._lock: s._offset=offset
    def _emit_status(s,msg):
        if msg == s._last_status: return
        s._last_status=msg; s.status_changed.emit(msg)
    def _extract_sni(s,line):
        line=(line or "").strip()
        if not line: return ""
        try:
            domain=s._extract_obj(json.loads(line))
            if domain: return domain
        except: pass
        for pat in (r'(?:sni|server_name|servername|host|hostname|domain)\s*[:=]\s*["\']?([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
                    r'\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b'):
            for m in re.finditer(pat,line,re.I):
                domain=s._clean_domain(m.group(1))
                if domain: return domain
        return ""
    def _extract_obj(s,obj):
        if isinstance(obj,dict):
            for k,v in obj.items():
                if str(k).lower() in ("sni","server_name","servername","tls_sni","host","hostname","domain"):
                    domain=s._clean_domain(v)
                    if domain: return domain
            for v in obj.values():
                domain=s._extract_obj(v)
                if domain: return domain
        elif isinstance(obj,list):
            for v in obj:
                domain=s._extract_obj(v)
                if domain: return domain
        elif isinstance(obj,str):
            return s._clean_domain(obj)
        return ""
    def _clean_domain(s,value):
        text=str(value or "").strip().strip("\"'[]()")
        if "://" in text:
            try: text=urllib.parse.urlparse(text).hostname or ""
            except: text=""
        if ":" in text and not text.count(".") >= 1: return ""
        text=text.split(":")[0].strip(".").lower()
        if text.startswith("*."): text=text[2:]
        return text if looks_like_domain(text) else ""
    def snapshot(s):
        with s._lock:
            return {"enabled":s._enabled,"path":s._path,"seen":s._seen,"last_domain":s._last_domain}
    def stop(s): s._stop.set()

class DNSMonitorThread(QThread):
    dns_event=pyqtSignal(dict); blocked_event=pyqtSignal(dict)
    status_changed=pyqtSignal(str); new_domain=pyqtSignal(str); feed_updated=pyqtSignal()
    def __init__(self,hm,db):
        super().__init__(); self.hm,self.db=hm,db; self.running=False; self.blocked_set=set(); self._seen=set()
    def refresh_blocked(self): self.hm.read(); self.blocked_set=self.hm.get_blocked()
    def run(self):
        self.running=True; self.refresh_blocked()
        self.status_changed.emit("Monitoring started")
        if sys.platform!='win32': self.status_changed.emit("Requires Windows"); return
        self._scan(); self.feed_updated.emit()
        self.status_changed.emit(f"Monitoring — {self.db.feed_count()} domains captured")
        while self.running: self._scan(); self.refresh_blocked(); time.sleep(3)
    def _scan(self):
        try:
            r=subprocess.run(['powershell','-NoProfile','-Command',
                'Get-DnsClientCache -EA SilentlyContinue | Select Entry,RecordName,Data,Status,Type | ConvertTo-Json -Compress'],
                capture_output=True,text=True,timeout=15,creationflags=NOWIN)
            if not r.stdout.strip(): return
            data=json.loads(r.stdout)
            if isinstance(data,dict): data=[data]
            new_ct=0
            for e in data:
                d=(e.get('Entry') or e.get('RecordName') or '').lower().strip().rstrip('.')
                if not d or d in IGNORED_DOMAINS or '.' not in d: continue
                is_new=self.db.feed_upsert(d,'')
                if is_new: new_ct+=1; self.new_domain.emit(d)
                if d not in self._seen:
                    self._seen.add(d); ev={'domain':d,'timestamp':datetime.datetime.now().isoformat(),'process':'','pid':0}
                    self.dns_event.emit(ev)
                    if d in self.blocked_set: self.db.log_event(d,'blocked','','Blocked by hosts'); self.blocked_event.emit(ev)
            if new_ct>0: self.feed_updated.emit()
            if len(self._seen)>10000: self._seen=set(list(self._seen)[-2000:])
        except: pass
    def manual_scan(self):
        if self.running: threading.Thread(target=self._manual,daemon=True).start()
    def _manual(self):
        self.status_changed.emit("Scanning..."); self._scan(); self.feed_updated.emit()
        self.status_changed.emit(f"Scan complete — {self.db.feed_count()} domains")
    def stop(self): self.running=False

class ConnWorker(QThread):
    ready=pyqtSignal(list); need_dns=pyqtSignal(str); need_who=pyqtSignal(str); need_geo=pyqtSignal(str); need_signer=pyqtSignal(str)
    def __init__(s,hosts_db): super().__init__(); s._stop=TEvent(); s._hosts_db=hosts_db; s._io_prev={}
    def run(s):
        while not s._stop.is_set():
            try:
                conns=s._scan(); s.ready.emit(conns); bw_tracker.update()
            except: pass
            s._stop.wait(2.0)
    def _scan(s):
        out=[]; now=datetime.datetime.now().strftime("%H:%M:%S"); seen_pids=set()
        blocked_domains={d[0] for d in s._hosts_db.get_domains(status='blocked')}
        for c in psutil.net_connections(kind='all'):
            try:
                proto="TCP" if c.type==socket.SOCK_STREAM else "UDP"
                la=c.laddr.ip if c.laddr else ""; lp=str(c.laddr.port) if c.laddr else ""
                ra=c.raddr.ip if c.raddr else ""; rp=str(c.raddr.port) if c.raddr else ""
                d="Listen" if not ra else "Out"; pid=c.pid or 0
                if pid>0: seen_pids.add(pid)
                pn,pp,svc,parent,package=s._proc(pid); signer=_cached_signer_label(pp)
                if signer=="..." and pp and pp!="-": s.need_signer.emit(pp)
                st=c.status if hasattr(c,'status') and c.status else "?"
                bs,br=s._proc_io(pid)
                key=f"L|{proto}|{la}:{lp}|{ra}:{rp}|{pid}"
                h=dns_c.get(ra,"..."); o=who_c.get(ra,"...")
                geo=geo_c.get(ra); cc=""; country="-"
                if geo: cc,country=geo
                elif ra and PRIV_RE.match(ra): cc="LAN"; country="Local"
                rs="-"
                # Check if hostname is in hosts blocked domains
                if h and h not in ("...","-"):
                    root=get_root_domain(h)
                    if h in blocked_domains or root in blocked_domains: rs="HOSTS:BLOCK"
                cat=categorize_traffic(h if h and h not in ("...","-") else "",ra,rp)
                if detect_doh_endpoint(h,ra,rp):
                    rs = "DOH:WARN" if rs=="-" else f"{rs};DOH:WARN"
                    cat = "DNS-over-HTTPS"
                if ra and ra!="*" and d!="Listen":
                    threats.record(ra,rp,blocked=(rs!="-"))
                    if dns_c.get(ra) is None: s.need_dns.emit(ra)
                    if who_c.get(ra) is None: s.need_who.emit(ra)
                    if geo_c.get(ra) is None: s.need_geo.emit(ra)
                ci=CI(key=key,ts=now,src="Live",dir=d,proto=proto,la=la,lp=lp,ra=ra or "*",rp=rp or "*",
                    host=h or "-",proc=pn,pid=pid,svc=svc,parent=parent,package=package,signer=signer,
                    state=st,path=pp,org=o or "-",stat=rs,country=country,cc=cc,category=cat,bytes_sent=bs,bytes_recv=br)
                if ra and ra!="*" and d!="Listen": threats.record_beacon(ci)
                out.append(ci)
            except: continue
        for pid in list(s._io_prev):
            if pid not in seen_pids: s._io_prev.pop(pid,None)
        return out
    def _proc_io(s,pid):
        if pid<=0: return (0,0)
        try:
            io=psutil.Process(pid).io_counters()
            cur=(int(getattr(io,"write_bytes",0) or 0),int(getattr(io,"read_bytes",0) or 0))
            prev=s._io_prev.get(pid); s._io_prev[pid]=cur
            if not prev: return (0,0)
            return (max(0,cur[0]-prev[0]),max(0,cur[1]-prev[1]))
        except: return (0,0)
    def _proc(s,pid):
        if pid<=0: return ("System","-","-","-","-")
        c=prc_c.get(pid)
        if c: return c
        try:
            p=psutil.Process(pid); nm=p.name()
            pp="-"
            try: pp=_nt_to_dos(p.exe())
            except: pass
            svc=_service_names_for_pid(pid)
            parent=_parent_identity_from_process(p)
            package=_package_identity_from_path(pp)
            r=(nm,pp,svc,parent,package); prc_c.put(pid,r); return r
        except: return ("?","-","-","-","-")
    def stop(s): s._stop.set()

class EvtWorker(QThread):
    ready=pyqtSignal(list); new_block=pyqtSignal(object); need_signer=pyqtSignal(str)
    def __init__(s):
        super().__init__(); s._stop=TEvent(); s._last_id=0; s._last_sysmon_id=0
        s._config_mtime=None; s._enabled=True; s._sysmon_enabled=False
    def run(s):
        while not s._stop.is_set():
            try:
                s._reload_config_if_changed()
                if s._enabled: s._poll()
            except: pass
            s._stop.wait(3)
    def _reload_config_if_changed(s):
        result=load_runtime_config()
        if s._config_mtime == result.mtime: return
        cfg=result.data
        s._enabled=bool(cfg.get("event_correlation_enabled",True))
        s._sysmon_enabled=bool(cfg.get("sysmon_event_correlation_enabled",False))
        s._config_mtime=result.mtime
    def _poll(s):
        s._poll_wfp()
        if s._sysmon_enabled: s._poll_sysmon()
    def _poll_wfp(s):
        cmd=("Get-WinEvent -FilterHashtable @{LogName='Security';Id=5157} -MaxEvents 50 -EA SilentlyContinue | "
             "Select-Object RecordId, TimeCreated, @{N='SrcAddr';E={$_.Properties[3].Value}}, @{N='SrcPort';E={$_.Properties[4].Value}}, "
             "@{N='DstAddr';E={$_.Properties[5].Value}}, @{N='DstPort';E={$_.Properties[6].Value}}, @{N='Proto';E={$_.Properties[7].Value}}, "
             "@{N='PID';E={$_.Properties[0].Value}}, @{N='AppPath';E={$_.Properties[1].Value}}, @{N='FilterId';E={$_.Properties[8].Value}}, "
             "@{N='LayerName';E={$_.Properties[9].Value}} | ConvertTo-Json -Compress")
        ok,out=_ps(cmd,20)
        if not ok or not out: return
        try:
            data=json.loads(out)
            if isinstance(data,dict): data=[data]
        except: return
        evts=[]
        for e in data:
            try: rid=int(e.get("RecordId",0) or 0)
            except: rid=0
            if rid<=s._last_id: continue
            s._last_id=max(s._last_id,rid)
            proto={6:"TCP",17:"UDP"}.get(e.get("Proto"),str(e.get("Proto","")))
            sa=str(e.get("SrcAddr","")); sp=str(e.get("SrcPort","")); da=str(e.get("DstAddr","")); dp=str(e.get("DstPort",""))
            pid=int(e.get("PID",0)); app=_nt_to_dos(str(e.get("AppPath",""))); proc=Path(app).name if app and app!="-" else "?"
            svc=_service_names_for_pid(pid); parent="-"; package=_package_identity_from_path(app); signer=_cached_signer_label(app)
            if pid>0:
                try: parent=_parent_identity_from_process(psutil.Process(pid))
                except: pass
            if signer=="..." and app and app!="-": s.need_signer.emit(app)
            ts_raw=e.get("TimeCreated",""); ts=""
            if ts_raw:
                try:
                    if "/Date(" in str(ts_raw):
                        ms=int(str(ts_raw).split("(")[1].split(")")[0].split("-")[0].split("+")[0])
                        ts=datetime.datetime.fromtimestamp(ms/1000).strftime("%H:%M:%S")
                    else: ts=str(ts_raw)[-8:]
                except: ts=str(ts_raw)[-8:]
            key=f"E|{proto}|{sa}:{sp}|{da}:{dp}|{rid}"
            cat=categorize_traffic(dns_c.get(da,"-"),da,dp)
            filter_id=str(e.get("FilterId","") or "")
            rule_name=str(e.get("LayerName","") or "")
            ci=CI(key=key,ts=ts,src="Event",dir="Out",proto=proto,la=sa,lp=sp,ra=da,rp=dp,host=dns_c.get(da,"-"),
                proc=proc,pid=pid,svc=svc,parent=parent,package=package,signer=signer,
                state="Blocked",path=app,org=who_c.get(da,"-"),stat="FW:BLOCKED",country="-",cc="",category=cat,
                event_source="Security",event_id=5157,event_record_id=int(rid or 0),rule_name=rule_name,filter_id=filter_id)
            evts.append(ci); s.new_block.emit(ci)
        if evts: s.ready.emit(evts)
    def _poll_sysmon(s):
        cmd=("$events=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3} -MaxEvents 50 -EA SilentlyContinue; "
             "$events | ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "
             "[PSCustomObject]@{RecordId=$_.RecordId;TimeCreated=$_.TimeCreated;Image=$d.Image;ProcessId=$d.ProcessId;SourceIp=$d.SourceIp;SourcePort=$d.SourcePort;"
             "DestinationIp=$d.DestinationIp;DestinationPort=$d.DestinationPort;Protocol=$d.Protocol;Initiated=$d.Initiated;RuleName=$d.RuleName} } | ConvertTo-Json -Compress")
        ok,out=_ps(cmd,20)
        if not ok or not out: return
        try:
            data=json.loads(out)
            if isinstance(data,dict): data=[data]
        except: return
        evts=[]
        for e in data:
            try: rid=int(e.get("RecordId",0) or 0)
            except: rid=0
            if rid<=s._last_sysmon_id: continue
            s._last_sysmon_id=max(s._last_sysmon_id,rid)
            app=_nt_to_dos(str(e.get("Image","") or "")); pid=int(e.get("ProcessId",0) or 0); proc=Path(app).name if app else "?"
            proto=str(e.get("Protocol","") or "").upper(); sa=str(e.get("SourceIp","") or ""); sp=str(e.get("SourcePort","") or "")
            da=str(e.get("DestinationIp","") or ""); dp=str(e.get("DestinationPort","") or "")
            initiated=str(e.get("Initiated","") or "").lower() != "false"; direction="Out" if initiated else "In"
            svc=_service_names_for_pid(pid); parent="-"; package=_package_identity_from_path(app); signer=_cached_signer_label(app)
            if pid>0:
                try: parent=_parent_identity_from_process(psutil.Process(pid))
                except: pass
            if signer=="..." and app: s.need_signer.emit(app)
            ts_raw=e.get("TimeCreated",""); ts=str(ts_raw)[-8:] if ts_raw else datetime.datetime.now().strftime("%H:%M:%S")
            key=f"S|{proto}|{sa}:{sp}|{da}:{dp}|{rid}"
            cat=categorize_traffic(dns_c.get(da,"-"),da,dp)
            evts.append(CI(key=key,ts=ts,src="Sysmon",dir=direction,proto=proto,la=sa,lp=sp,ra=da,rp=dp,host=dns_c.get(da,"-"),
                proc=proc,pid=pid,svc=svc,parent=parent,package=package,signer=signer,state="Observed",path=app,org=who_c.get(da,"-"),
                stat="EVENT:SYSMON",country="-",cc="",category=cat,event_source="Sysmon",event_id=3,event_record_id=int(rid or 0),
                rule_name=str(e.get("RuleName","") or ""),filter_id=""))
        if evts: s.ready.emit(evts)
    def stop(s): s._stop.set()

class ImportWorker(QThread):
    progress=pyqtSignal(int,int,str); log_msg=pyqtSignal(str,bool); finished=pyqtSignal(list); cancelled=pyqtSignal()
    def __init__(self,sources,normalize=True,db=None):
        super().__init__(); self.sources=sources; self.normalize=normalize; self.db=db; self._stop=False
    def cancel(self): self._stop=True
    def run(self):
        acc=[]
        for i,(name,url) in enumerate(self.sources):
            if self._stop: self.cancelled.emit(); return
            self.progress.emit(i,len(self.sources),name)
            try:
                req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 PyWall/4.1'})
                with urllib.request.urlopen(req,timeout=20) as resp: raw_bytes=resp.read()
                text=raw_bytes.decode('utf-8',errors='ignore')
                parsed=_parse_import_text(text,self.normalize)
                acc.extend(parsed)
                digest=hashlib.sha256(raw_bytes).hexdigest()
                cache_path=_feed_cache_path(name,url)
                os.makedirs(os.path.dirname(cache_path),exist_ok=True)
                with open(cache_path,"wb") as f: f.write(raw_bytes)
                if self.db: self.db.feed_source_success(name,url,len(parsed),digest,cache_path)
                self.log_msg.emit(f"Fetched {name}: {len(parsed)} entries ({digest[:12]})",False)
            except Exception as e:
                reason=str(e)
                meta=self.db.feed_source_failure(name,url,reason) if self.db else None
                cache_path=(meta or {}).get("last_good_cache_path","")
                if cache_path and os.path.exists(cache_path):
                    try:
                        with open(cache_path,"rb") as f: raw_bytes=f.read()
                        parsed=_parse_import_text(raw_bytes.decode('utf-8',errors='ignore'),self.normalize)
                        acc.extend(parsed)
                        self.log_msg.emit(f"Failed: {name} - using cached feed ({len(parsed)} entries)",True)
                        continue
                    except Exception as ce:
                        reason=f"{reason}; cache read failed: {ce}"
                self.log_msg.emit(f"Failed: {name} - {reason}",True)
        self.finished.emit(acc)

class RuleScanWorker(QThread):
    ready=pyqtSignal(list)
    def __init__(s,filt=""): super().__init__(); s.filt=filt
    def run(s):
        try:
            rules=fw.get_all_rules(force_refresh=True)
            if s.filt:
                fl=s.filt.lower(); rules=[r for r in rules if fl in (r.name or "").lower() or fl in (r.program or "").lower()]
            s.ready.emit(rules)
        except Exception as e:
            log.warning(f"RuleScanWorker error: {e}"); s.ready.emit([])

def _ipc_allowed_sids():
    if sys.platform != "win32" or win32security is None: return []
    sids = []
    for attr in ("WinLocalSystemSid", "WinBuiltinAdministratorsSid"):
        try: sids.append(win32security.CreateWellKnownSid(getattr(win32security, attr), None))
        except Exception as e: _service_log(f"IPC SID lookup failed for {attr}: {e}", "WARNING")
    try:
        user = os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USERNAME", "")
        if user:
            sid, _, _ = win32security.LookupAccountName(None, user)
            if sid not in sids: sids.append(sid)
    except Exception as e:
        _service_log(f"IPC current-user SID lookup failed: {e}", "WARNING")
    return sids

def _build_ipc_security_descriptor():
    if sys.platform != "win32" or win32security is None or ntsecuritycon is None: return None
    sids = _ipc_allowed_sids()
    if not sids: return None
    mask = (ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE |
        ntsecuritycon.FILE_GENERIC_EXECUTE | ntsecuritycon.DELETE | ntsecuritycon.READ_CONTROL | ntsecuritycon.WRITE_DAC)
    sd = win32security.SECURITY_DESCRIPTOR()
    dacl = win32security.ACL()
    for sid in sids:
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, mask, sid)
    sd.SetSecurityDescriptorDacl(True, dacl, False)
    return sd

def _build_ipc_security_attributes():
    if win32security is None: return None
    sd = _build_ipc_security_descriptor()
    if sd is None: return None
    try:
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        return sa
    except Exception as e:
        _service_log(f"IPC security attributes unavailable: {e}", "WARNING")
        return None

def _secure_ipc_token_file(path=IPC_TOKEN_PATH):
    if sys.platform != "win32" or win32security is None: return False
    sd = _build_ipc_security_descriptor()
    if sd is None: return False
    try:
        win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)
        return True
    except Exception as e:
        _service_log(f"IPC token ACL update failed: {e}", "WARNING")
        return False

def _get_ipc_token(create=False):
    try:
        if os.path.exists(IPC_TOKEN_PATH):
            _secure_ipc_token_file(IPC_TOKEN_PATH)
            with open(IPC_TOKEN_PATH, "r", encoding="utf-8") as f:
                token = f.read().strip()
                if token: return token
        if not create: return ""
        os.makedirs(os.path.dirname(IPC_TOKEN_PATH), exist_ok=True)
        token = secrets.token_urlsafe(32)
        with open(IPC_TOKEN_PATH, "w", encoding="utf-8") as f:
            f.write(token)
        _secure_ipc_token_file(IPC_TOKEN_PATH)
        return token
    except Exception as e:
        _service_log(f"IPC token unavailable: {e}", "ERROR")
        return ""

def _service_ipc_request(command="status", payload=None, timeout=2.0):
    if sys.platform != "win32" or win32file is None or win32pipe is None:
        return {"ok": False, "error": "Named-pipe IPC requires pywin32 on Windows"}
    token = _get_ipc_token(create=False)
    if not token:
        return {"ok": False, "error": "Service token not found"}
    request = json.dumps({"token": token, "command": command, "payload": payload or {}}).encode("utf-8")
    deadline = time.time() + max(timeout, 0.1)
    handle = None
    while time.time() < deadline:
        try:
            handle = win32file.CreateFile(
                IPC_PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None)
            break
        except pywintypes.error as e:
            if getattr(e, "winerror", None) in (2, 231):
                time.sleep(0.05); continue
            return {"ok": False, "error": str(e)}
    if handle is None:
        return {"ok": False, "error": "Service pipe unavailable"}
    try:
        try: win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        except: pass
        win32file.WriteFile(handle, request)
        parts = []
        while True:
            try:
                _, data = win32file.ReadFile(handle, 65536)
                parts.append(data)
                if data.endswith(b"\n"): break
            except pywintypes.error as e:
                if getattr(e, "winerror", None) == 109: break
                raise
        raw = b"".join(parts).decode("utf-8", errors="replace").strip()
        return json.loads(raw) if raw else {"ok": False, "error": "Empty IPC response"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try: win32file.CloseHandle(handle)
        except: pass

class ServiceIPCServer:
    def __init__(self, monitor):
        self.monitor = monitor
        self._stop = TEvent()
        self._thread = None
        self._token = ""

    def start(self):
        if sys.platform != "win32" or win32pipe is None or win32file is None:
            _service_log("Named-pipe IPC disabled; pywin32 pipe modules unavailable", "WARNING")
            return
        self._token = _get_ipc_token(create=True)
        if not self._token:
            _service_log("Named-pipe IPC disabled; token could not be created", "ERROR")
            return
        self._thread = threading.Thread(target=self._run, name="PyWallServiceIPC", daemon=True)
        self._thread.start()
        _service_log(f"Named-pipe IPC listening at {IPC_PIPE_NAME}")

    def stop(self):
        self._stop.set()
        try: _service_ipc_request("ping", timeout=0.5)
        except: pass
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self):
        while not self._stop.is_set():
            pipe = None
            try:
                pipe = win32pipe.CreateNamedPipe(
                    IPC_PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    5, 65536, 65536, 1000, _build_ipc_security_attributes())
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except pywintypes.error as e:
                    if getattr(e, "winerror", None) != 535:
                        raise
                if self._stop.is_set(): break
                _, data = win32file.ReadFile(pipe, 65536)
                response = self._handle(data)
                win32file.WriteFile(pipe, (json.dumps(response) + "\n").encode("utf-8"))
                try: win32pipe.DisconnectNamedPipe(pipe)
                except: pass
            except Exception as e:
                if not self._stop.is_set():
                    _service_log(f"IPC request failed: {e}", "WARNING")
                    time.sleep(0.2)
            finally:
                if pipe is not None:
                    try: win32file.CloseHandle(pipe)
                    except: pass

    def _handle(self, raw):
        try:
            req = json.loads(raw.decode("utf-8", errors="replace").strip())
        except Exception:
            return {"ok": False, "error": "Invalid JSON"}
        if not hmac.compare_digest(str(req.get("token", "")), self._token):
            return {"ok": False, "error": "Unauthorized"}
        cmd = req.get("command", "status")
        if cmd == "ping":
            return {"ok": True, "pong": True}
        if cmd == "status":
            return {"ok": True, "status": self.monitor.snapshot()}
        return {"ok": False, "error": f"Unknown command: {cmd}"}

class HeadlessMonitor(QObject):
    def __init__(self, auto_block=True, poll_seconds=2.0):
        super().__init__()
        self.auto_block = auto_block
        self.poll_seconds = max(float(poll_seconds or 2.0), 1.0)
        self.db = HostsDB()
        self.hm = HostsFileManager()
        self.conn_db = ConnDB()
        self._quota = BandwidthQuotaEnforcer("PyWallService")
        self._doh = DoHDetector("PyWallService")
        self._ids = IDSRuleEngine("PyWallService")
        self._dns_w = DNSResolveWorker()
        self._who_w = WhoWorker()
        self._geo_w = GeoIPWorker()
        self._sign_w = SignerWorker()
        self._tls_w = TLSLogWorker(self.db)
        self._plugins = PluginRegistry()
        self._dns_mon = DNSMonitorThread(self.hm, self.db)
        self._conn_w = ConnWorker(self.db)
        self._evt_w = EvtWorker()
        self._timer = QTimer(self)
        self._ipc = ServiceIPCServer(self)
        self._restored_state = self._load_service_state()
        self._processed_threats = set()
        self._blocked_ips = set(self._restored_state.get("auto_blocked_ip_values", []))
        self._last_summary = 0
        self._last_status = "starting"
        self._last_connection_count = 0
        self._started = time.time()
        self._config_mtime = None
        self._last_config_reload = ""
        self._last_config_warnings = []
        self._last_config_recovered = False
        self._last_config_backup_path = ""

    def start(self):
        _service_log(f"Headless monitor starting; auto_block={self.auto_block}")
        if self._restored_state:
            _service_log(f"Restored prior service state: saved_at={self._restored_state.get('saved_at','?')}, clean_shutdown={self._restored_state.get('clean_shutdown')}")
        self._reload_config_if_changed(force=True)
        plugins = self._plugins.scan()
        _service_log(f"Plugin guardrails scanned: {plugins.summary()}")
        self._save_service_state(clean_shutdown=False)
        self._dns_w.start(); self._who_w.start(); self._geo_w.start(); self._sign_w.start(); self._tls_w.start()
        self._dns_mon.status_changed.connect(self._on_status)
        self._geo_w.status_changed.connect(self._on_status)
        self._tls_w.status_changed.connect(self._on_status)
        self._dns_mon.blocked_event.connect(self._on_dns_blocked)
        self._conn_w.ready.connect(self._on_connections)
        self._conn_w.need_dns.connect(self._dns_w.add)
        self._conn_w.need_who.connect(self._who_w.add)
        self._conn_w.need_geo.connect(self._geo_w.add)
        self._conn_w.need_signer.connect(self._sign_w.add)
        self._evt_w.need_signer.connect(self._sign_w.add)
        self._evt_w.new_block.connect(self._on_fw_blocked)
        self._evt_w.ready.connect(self._on_event_connections)
        self._dns_mon.start(); self._conn_w.start(); self._evt_w.start()
        self._ipc.start()
        self._timer.timeout.connect(self._tick)
        self._timer.start(int(self.poll_seconds * 1000))

    def stop(self):
        _service_log("Headless monitor stopping")
        self._timer.stop()
        self._ipc.stop()
        for worker in (self._dns_mon, self._conn_w, self._evt_w, self._dns_w, self._who_w, self._geo_w, self._sign_w, self._tls_w):
            try: worker.stop()
            except: pass
        for worker in (self._dns_mon, self._conn_w, self._evt_w, self._dns_w, self._who_w, self._geo_w, self._sign_w, self._tls_w):
            try: worker.wait(5000)
            except: pass
        try: self.conn_db.prune(30)
        except: pass
        self._save_service_state(clean_shutdown=True)
        _service_log("Headless monitor stopped")

    def _on_status(self, msg):
        self._last_status = msg
        _service_log(msg)

    def _on_dns_blocked(self, ev):
        domain = ev.get("domain", "")
        self.db.log_event(domain, "blocked", ev.get("process", ""), "Blocked by hosts file in service mode")

    def _on_connections(self, conns):
        self._last_connection_count = len(conns)
        live = [c for c in conns if c.ra and c.ra != "*" and c.dir != "Listen"]
        if live: self.conn_db.insert_batch(live)
        for ev in self._quota.check(live, db=self.db):
            _service_log(f"Quota exceeded for {ev.app}: {_fmt_bytes(ev.used)} / {_fmt_bytes(ev.limit)}; blocked={ev.blocked}; {ev.message}")
        for ev in self._doh.check(live, db=self.db):
            _service_log(f"DoH {ev.action}: {ev.app} -> {ev.endpoint}; blocked={ev.blocked}; {ev.message}")
        for hit in self._ids.check(live, db=self.db):
            _service_log(f"IDS {hit['rule']}: {hit['app']} -> {hit['endpoint']}; blocked={hit['blocked']}; {hit['message']}")
        self._enforce_threats()

    def snapshot(self):
        stats = self.conn_db.get_stats()
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "status": self._last_status,
            "uptime_sec": int(time.time() - self._started),
            "auto_block": self.auto_block,
            "live_connections": self._last_connection_count,
            "history_total": stats["total"],
            "history_blocked": stats["blocked"],
            "sessions": stats.get("sessions",0),
            "active_sessions": stats.get("active_sessions",0),
            "unique_ips": stats["unique_ips"],
            "bytes_sent": stats.get("bytes_sent",0),
            "bytes_recv": stats.get("bytes_recv",0),
            "auto_blocked_ips": len(self._blocked_ips),
            "threats": threats.get_stats(),
            "pipe": IPC_PIPE_NAME,
            "config_path": CONFIG_PATH,
            "last_config_reload": self._last_config_reload,
            "config_schema_version": CONFIG_SCHEMA_VERSION,
            "config_warnings": list(self._last_config_warnings),
            "config_recovered": self._last_config_recovered,
            "config_backup_path": self._last_config_backup_path,
            "bandwidth_quotas": self._quota.snapshot(),
            "doh": self._doh.snapshot(),
            "ids": self._ids.snapshot(),
            "geoip": self._geo_w.snapshot(),
            "tls_sni": self._tls_w.snapshot(),
            "plugins": self._plugins.scan(log_errors=False).summary(),
            "firewall_tamper": fw.tamper_summary(),
            "identity_fields": ["service", "parent_process", "uwp_package", "signer_trust"],
            "signer": self._sign_w.snapshot(),
            "state_path": SERVICE_STATE_PATH,
            "previous_clean_shutdown": self._restored_state.get("clean_shutdown") if self._restored_state else None,
            "previous_saved_at": self._restored_state.get("saved_at") if self._restored_state else "",
        }

    def _load_service_state(self):
        try:
            if not os.path.exists(SERVICE_STATE_PATH):
                return {}
            with open(SERVICE_STATE_PATH, "r", encoding="utf-8") as f:
                state = json.load(f)
            return state if isinstance(state, dict) else {}
        except Exception as e:
            _service_log(f"Service state restore failed: {e}", "WARNING")
            return {}

    def _save_service_state(self, clean_shutdown=False):
        try:
            state = self.snapshot()
            state.update({
                "saved_at": datetime.datetime.now().isoformat(timespec="seconds"),
                "clean_shutdown": bool(clean_shutdown),
                "auto_blocked_ip_values": sorted(self._blocked_ips),
            })
            tmp = SERVICE_STATE_PATH + ".tmp"
            os.makedirs(os.path.dirname(SERVICE_STATE_PATH), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, sort_keys=True)
            os.replace(tmp, SERVICE_STATE_PATH)
        except Exception as e:
            _service_log(f"Service state save failed: {e}", "WARNING")

    def _reload_config_if_changed(self, force=False):
        result = load_runtime_config()
        if not force and self._config_mtime == result.mtime:
            return
        cfg = result.data
        self._last_config_warnings = list(result.warnings)
        self._last_config_recovered = bool(result.recovered)
        self._last_config_backup_path = result.backup_path
        if result.recovered:
            _service_log(f"Config recovered from corrupt file; backup={result.backup_path}", "WARNING")
        for warning in result.warnings:
            _service_log(f"Config warning: {warning}", "WARNING")
        old_auto = self.auto_block
        old_poll = self.poll_seconds
        if "service_auto_block" in cfg:
            self.auto_block = bool(cfg.get("service_auto_block"))
        elif "threat_auto_block" in cfg:
            self.auto_block = bool(cfg.get("threat_auto_block"))
        if "service_poll_seconds" in cfg:
            try: self.poll_seconds = max(float(cfg.get("service_poll_seconds")), 1.0)
            except: pass
        if self._timer.isActive() and self.poll_seconds != old_poll:
            self._timer.setInterval(int(self.poll_seconds * 1000))
        self._quota.load_config(cfg, result.mtime)
        self._doh.configure(cfg, result.mtime)
        self._ids.configure(cfg, result.mtime)
        self._geo_w.configure(cfg, result.mtime)
        self._tls_w.configure(cfg, result.mtime)
        self._config_mtime = result.mtime
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        self._last_config_reload = f"recovered: {stamp}" if result.recovered else f"warnings: {stamp}" if result.warnings else stamp
        _service_log(f"Config reloaded: auto_block {old_auto}->{self.auto_block}, poll {old_poll}->{self.poll_seconds}s, quotas {self._quota.snapshot().get('configured',0)}, doh={self._doh.snapshot().get('action')}, ids={self._ids.snapshot().get('rules',0)}, geoip={self._geo_w.snapshot().get('provider')}, tls_sni={self._tls_w.snapshot().get('enabled')}")

    def _on_fw_blocked(self, ci):
        self.db.log_event(ci.host if ci.host not in ("-","...") else ci.ra, "fw_blocked", ci.proc, f"FW blocked: {ci.ra}:{ci.rp}")
    def _on_event_connections(self, evts):
        if evts: self.conn_db.insert_batch(evts)

    def _tick(self):
        self._reload_config_if_changed()
        self._enforce_threats()
        now = time.time()
        if now - self._last_summary >= 60:
            self._last_summary = now
            try: fw.get_all_rules(force_refresh=True)
            except Exception as e: _service_log(f"Firewall tamper scan failed: {e}", "WARNING")
            stats = self.conn_db.get_stats()
            qstats = self._quota.snapshot()
            dstats = self._doh.snapshot()
            istats = self._ids.snapshot()
            gstats = self._geo_w.snapshot()
            tamper=fw.tamper_summary()
            _service_log(f"Service heartbeat: {stats['total']} events, {stats.get('active_sessions',0)} active sessions, {stats['blocked']} blocked, {len(self._blocked_ips)} auto-blocked IPs, {qstats.get('blocked',0)} quota blocks, {dstats.get('detected',0)} DoH hits, {istats.get('hits',0)} IDS hits, tamper {tamper.get('pending',0)}, geoip {gstats.get('provider')} {gstats.get('lookups',0)}/{gstats.get('unknown',0)}, {_fmt_bytes(stats.get('bytes_sent',0))}/{_fmt_bytes(stats.get('bytes_recv',0))} sent/recv")
            self._save_service_state(clean_shutdown=False)

    def _enforce_threats(self):
        for evt in threats.get_events(100):
            key = f"{evt.ts}|{evt.type}|{evt.source_ip}"
            if key in self._processed_threats: continue
            self._processed_threats.add(key)
            mitre = f"{evt.mitre_tactic} / {evt.mitre_technique}" if evt.mitre_technique else "Unmapped"
            self.db.log_event(evt.source_ip, "threat", "PyWallService", f"{evt.type} [{mitre}]: {evt.details}")
            if self.auto_block and evt.severity == "high":
                self._block_ip_all_directions(evt.source_ip, evt.type)

    def _block_ip_all_directions(self, ip, reason):
        if not ip or ip in self._blocked_ips or PRIV_RE.match(ip): return
        ok_any = False
        messages = []
        for direction in ("Inbound", "Outbound"):
            ok, out = fw.block_ip(ip, direction)
            ok_any = ok_any or ok
            messages.append(f"{direction}={'ok' if ok else out}")
        self._blocked_ips.add(ip)
        action = "fw_blocked" if ok_any else "error"
        self.db.log_event(ip, action, "PyWallService", f"Auto-block {reason}: {'; '.join(messages)}")
        _service_log(f"Auto-blocked {ip} for {reason}: {'; '.join(messages)}")

def run_headless_service(stop_event=None, auto_block=True, poll_seconds=2.0):
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([APP_NAME, "service-run"])
    monitor = HeadlessMonitor(auto_block=auto_block, poll_seconds=poll_seconds)
    guard = QTimer()

    def _check_stop():
        if stop_event is not None and stop_event.is_set():
            app.quit()

    if stop_event is not None:
        guard.timeout.connect(_check_stop)
        guard.start(1000)
    monitor.start()
    try:
        return app.exec_()
    finally:
        guard.stop()
        monitor.stop()

def _run_service_foreground(auto_block=True, poll_seconds=2.0):
    stop_event = threading.Event()
    def _stop(*_):
        stop_event.set()
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try: signal.signal(sig, _stop)
            except: pass
    return run_headless_service(stop_event=stop_event, auto_block=auto_block, poll_seconds=poll_seconds)

def _service_status_text():
    if win32serviceutil is None or win32service is None:
        return None
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
    except Exception as e:
        return f"{SERVICE_NAME}: unavailable ({e})"
    names = {
        win32service.SERVICE_STOPPED: "STOPPED",
        win32service.SERVICE_START_PENDING: "START_PENDING",
        win32service.SERVICE_STOP_PENDING: "STOP_PENDING",
        win32service.SERVICE_RUNNING: "RUNNING",
        win32service.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
        win32service.SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
        win32service.SERVICE_PAUSED: "PAUSED",
    }
    return f"{SERVICE_NAME}: {names.get(status, status)}"

def _build_cli_parser():
    parser = argparse.ArgumentParser(prog="PyWall.py", description=f"{APP_NAME} v{APP_VERSION}")
    sub = parser.add_subparsers(dest="command")
    service = sub.add_parser("service", help="Install, control, or run the Windows background service")
    service.add_argument("action", choices=["install","remove","start","stop","restart","status","run"])
    service.add_argument("--startup", choices=["auto","manual","disabled","delayed"], default="auto")
    service.add_argument("--no-auto-block", action="store_true", help="Monitor without creating firewall blocks for high-severity threats")
    service.add_argument("--poll-seconds", type=float, default=2.0)
    run = sub.add_parser("service-run", help="Run the headless monitor in the foreground")
    run.add_argument("--no-auto-block", action="store_true")
    run.add_argument("--poll-seconds", type=float, default=2.0)
    report = sub.add_parser("report", help="Export daily and weekly app usage reports")
    report.add_argument("--output", default=REPORT_DIR, help="Report output directory")
    return parser

def _dispatch_cli(argv):
    if not argv: return None
    if argv[0] not in ("service", "service-run", "report", "-h", "--help"): return None
    parser = _build_cli_parser()
    args = parser.parse_args(argv)
    if args.command == "report":
        for item in export_usage_reports(args.output):
            print(f"{item['period']}: {item['rows']} apps -> {item['csv']} | {item['html']}")
        return 0
    if args.command == "service-run" or (args.command == "service" and args.action == "run"):
        return _run_service_foreground(auto_block=not args.no_auto_block, poll_seconds=args.poll_seconds)
    if args.command == "service":
        if sys.platform != "win32":
            print("Windows service control is only available on Windows.", file=sys.stderr)
            return 2
        if PyWallWindowsService is None or win32serviceutil is None:
            print("pywin32 is required for Windows service control. Run python -m pip install -r requirements.txt.", file=sys.stderr)
            return 2
        if args.action == "status":
            print(_service_status_text())
            return 0
        old_argv = sys.argv[:]
        try:
            sys.argv = [old_argv[0], args.action]
            if args.action == "install":
                sys.argv.extend(["--startup", args.startup])
            win32serviceutil.HandleCommandLine(PyWallWindowsService)
            return 0
        except SystemExit as e:
            return e.code if isinstance(e.code, int) else 0
        finally:
            sys.argv = old_argv
    parser.print_help()
    return 0


# ─── UI Helpers ──────────────────────────────────────────────────────────────
class GlassCard(QFrame):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"GlassCard{{background:{C['card_bg']};border:1px solid {C['card_border']};border-radius:14px;}}")

class StatCard(GlassCard):
    def __init__(self,label,value="0",color=C['blue'],icon_char=None):
        super().__init__()
        self.setMinimumSize(_dp(140),_dp(80)); self.setMaximumHeight(_dp(90))
        lo=QVBoxLayout(self); lo.setContentsMargins(_dp(16),_dp(10),_dp(16),_dp(10)); lo.setSpacing(_dp(3))
        top=QHBoxLayout(); top.setSpacing(_dp(6))
        self.val=QLabel(str(value))
        self.val.setStyleSheet(f"font-size:{_dp(26)}px;font-weight:800;color:{color};letter-spacing:-1px;font-family:'Segoe UI Variable Display','Segoe UI',sans-serif;")
        top.addWidget(self.val); top.addStretch()
        if icon_char:
            ic=QLabel(icon_char); ic.setStyleSheet(f"font-size:{_dp(18)}px;color:{color};opacity:0.5;"); top.addWidget(ic)
        lo.addLayout(top)
        self.lbl=QLabel(label.upper())
        self.lbl.setStyleSheet(f"font-size:{_dp(9)}px;color:{C['overlay']};letter-spacing:1.8px;font-weight:700;")
        lo.addWidget(self.lbl)
    def set_value(self,v): self.val.setText(str(v))

def _btn(text,cls,cb,w=None,h=None):
    h=h or _dp(28)
    b=QPushButton(text); b.setProperty("class",cls); b.setFixedHeight(h)
    b.setCursor(Qt.PointingHandCursor)
    if w: b.setFixedWidth(_dp(w) if isinstance(w,int) else w)
    _a11y(b,text,tooltip=text)
    b.clicked.connect(cb); return b

def _make_toolbar_btn(text,cls,cb):
    b=QPushButton(text); b.setProperty("class",cls); b.setCursor(Qt.PointingHandCursor)
    b.setFixedHeight(_dp(30)); _a11y(b,text,tooltip=text); b.clicked.connect(cb); return b

def _a11y_item(text, tooltip=None):
    item=QTableWidgetItem(str(text) if text is not None else "")
    label=str(text) if text is not None else ""
    item.setToolTip(str(tooltip or label))
    try: item.setData(Qt.AccessibleTextRole,label)
    except: pass
    return item

def _status_item(text, color=None, meaning=None):
    item=_a11y_item(text, meaning or text)
    if color is not None: item.setForeground(QColor(color) if isinstance(color,str) else color)
    try: item.setData(Qt.AccessibleDescriptionRole, meaning or text)
    except: pass
    return item

def _a11y_table(table, name, desc=""):
    _a11y(table,name,desc or name)
    try:
        table.setToolTip(_tr(desc or name))
        table.setAlternatingRowColors(True)
    except: pass
    return table

_CTX_STYLE = f"QMenu{{background:{C['mantle']};color:{C['text']};border:1px solid {C['surface1']};border-radius:10px;padding:6px;}}QMenu::item{{padding:7px 22px;border-radius:5px;}}QMenu::item:selected{{background:{C['surface0']};}}QMenu::separator{{height:1px;background:{C['surface0']};margin:4px 8px;}}"

def _set_domain_item(table,row,col,domain):
    item=_a11y_item(domain, f"Domain {domain}")
    if _fav_cache:
        px=_fav_cache.get(domain)
        if px and not px.isNull(): item.setIcon(QIcon(px))
    table.setItem(row,col,item)

def _make_actions_widget(domain,actions,show_research=True,show_root=False,root_actions=None):
    aw=QWidget(); al=QHBoxLayout(aw); al.setContentsMargins(2,1,2,1); al.setSpacing(3)
    for text,cls,cb in actions: al.addWidget(_btn(text,cls,cb))
    if show_research: al.addWidget(_btn("R","dim",lambda _,d=domain:open_research(d),w=24))
    if show_root and root_actions:
        root=get_root_domain(domain)
        if root!=domain:
            rm=QPushButton(".."); rm.setFixedHeight(24); rm.setFixedWidth(26); rm.setProperty("class","dim")
            rm.setToolTip(f"Root: {root}"); rm.setStyleSheet(rm.styleSheet()+"font-size:11px;padding:1px 4px;")
            menu=QMenu(); menu.setStyleSheet(_CTX_STYLE)
            for label,rcb in root_actions: a=menu.addAction(f"{label} ({root})"); a.triggered.connect(rcb)
            rm.clicked.connect(lambda _: menu.exec_(QCursor.pos())); al.addWidget(rm)
    return aw


# ─── Dashboard Tab ───────────────────────────────────────────────────────────
class DashboardTab(QWidget):
    def __init__(self,db,conn_db):
        super().__init__(); self.db=db; self.cdb=conn_db; self._build()
        self.tmr=QTimer(self); self.tmr.timeout.connect(self.refresh); self.tmr.start(5000)
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(_dp(24),_dp(24),_dp(24),_dp(24)); lo.setSpacing(_dp(16))
        sl=QHBoxLayout(); sl.setSpacing(_dp(12))
        self.c1=StatCard("DNS Seen","0",C['blue'],"\u25C9"); self.c2=StatCard("Hosts Blocked","0",C['red'],"\u2718")
        self.c3=StatCard("Whitelisted","0",C['green'],"\u2714"); self.c4=StatCard("Blocks Today","0",C['peach'],"\u26A0")
        self.c5=StatCard("Connections","0",C['sky'],"\u21C4"); self.c6=StatCard("FW Blocked","0",C['mauve'],"\u2620")
        for c in [self.c1,self.c2,self.c3,self.c4,self.c5,self.c6]: sl.addWidget(c)
        lo.addLayout(sl)
        sf=GlassCard(); sfl=QHBoxLayout(sf); sfl.setContentsMargins(_dp(20),_dp(10),_dp(20),_dp(10)); sfl.setSpacing(_dp(12))
        self.mi=QLabel("\u25CF"); self.mi.setStyleSheet(f"color:{C['green']};font-size:{_dp(14)}px;")
        self.ms=QLabel("Starting..."); self.ms.setStyleSheet(f"color:{C['subtext']};font-size:{_dp(12)}px;")
        self.bw_up=QLabel("-- B/s"); self.bw_up.setStyleSheet(f"color:{C['blue']};font-size:{_dp(11)}px;font-family:'Cascadia Code','Consolas',monospace;")
        self.bw_dn=QLabel("-- B/s"); self.bw_dn.setStyleSheet(f"color:{C['teal']};font-size:{_dp(11)}px;font-family:'Cascadia Code','Consolas',monospace;")
        sfl.addWidget(self.mi); sfl.addWidget(self.ms); sfl.addStretch()
        ul=QLabel("\u25B2"); ul.setStyleSheet(f"color:{C['blue']};font-size:{_dp(9)}px;"); sfl.addWidget(ul)
        sfl.addWidget(self.bw_up)
        dl=QLabel("\u25BC"); dl.setStyleSheet(f"color:{C['teal']};font-size:{_dp(9)}px;margin-left:{_dp(10)}px;"); sfl.addWidget(dl)
        sfl.addWidget(self.bw_dn)
        lo.addWidget(sf)
        cols=QHBoxLayout(); cols.setSpacing(_dp(14))
        rg=QGroupBox("Recent Blocked"); rl=QVBoxLayout(rg)
        self.rtbl=QTableWidget(0,3); self.rtbl.setHorizontalHeaderLabels(["Time","Domain","Process"])
        self.rtbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.rtbl.setColumnWidth(0,_dp(140)); self.rtbl.setColumnWidth(2,_dp(110))
        self.rtbl.setAlternatingRowColors(True); self.rtbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.rtbl.verticalHeader().setVisible(False); self.rtbl.setIconSize(QSize(_dp(16),_dp(16)))
        self.rtbl.setShowGrid(False); rl.addWidget(self.rtbl)
        cols.addWidget(rg,3)
        tg=QGroupBox("Top Blocked"); tl=QVBoxLayout(tg)
        self.ttbl=QTableWidget(0,2); self.ttbl.setHorizontalHeaderLabels(["Domain","Hits"])
        self.ttbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch); self.ttbl.setColumnWidth(1,_dp(65))
        self.ttbl.setAlternatingRowColors(True); self.ttbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ttbl.verticalHeader().setVisible(False); self.ttbl.setIconSize(QSize(_dp(16),_dp(16)))
        self.ttbl.setShowGrid(False); tl.addWidget(self.ttbl)
        cols.addWidget(tg,2)
        fg=QGroupBox("Firewall Status"); fl=QVBoxLayout(fg)
        self.fw_lbl=QLabel("Loading..."); self.fw_lbl.setWordWrap(True)
        self.fw_lbl.setStyleSheet(f"color:{C['subtext']};font-size:{_dp(11)}px;font-family:'Cascadia Code','Consolas',monospace;line-height:1.6;")
        fl.addWidget(self.fw_lbl); cols.addWidget(fg,2)
        lo.addLayout(cols,1)
    def refresh(self):
        try:
            s=self.db.get_stats(); cs=self.cdb.get_stats()
            self.c1.set_value(s['feed_total']); self.c2.set_value(s['blocked']); self.c3.set_value(s['whitelisted'])
            self.c4.set_value(s['today_hits']); self.c5.set_value(cs['total']); self.c6.set_value(cs['blocked'])
            up,dn=bw_tracker.rates()
            self.bw_up.setText(bw_tracker.format_rate(up)); self.bw_dn.setText(bw_tracker.format_rate(dn))
            rec=self.db.get_log(20,action_filter='blocked')
            self.rtbl.setRowCount(len(rec))
            for i,r in enumerate(rec):
                self.rtbl.setItem(i,0,QTableWidgetItem(r[1][:19].replace('T',' ') if r[1] else ''))
                _set_domain_item(self.rtbl,i,1,r[2] or ''); self.rtbl.setItem(i,2,QTableWidgetItem(r[4] or ''))
            top=s['top_blocked']; self.ttbl.setRowCount(len(top))
            for i,(d,ct) in enumerate(top):
                _set_domain_item(self.ttbl,i,0,d)
                it=QTableWidgetItem(str(ct)); it.setTextAlignment(Qt.AlignCenter); self.ttbl.setItem(i,1,it)
            # FW status - use cached data only (never block main thread with PS commands)
            lines=[]; lines.append(f"Threats detected: {threats.get_stats()['total']}")
            cached=fw._rule_cache
            if cached:
                hg_ct=sum(1 for r in cached if r.source=="pywall")
                lines.append(f"PyWall FW rules: {hg_ct}")
                lines.append(f"Total FW rules: {len(cached)}")
            else:
                lines.append("FW rules: loading...")
                # Trigger background cache population
                if not hasattr(self,'_fw_pop_started'):
                    self._fw_pop_started=True
                    threading.Thread(target=lambda:fw.get_all_rules(),daemon=True).start()
            if hasattr(self,'_last_prof') and self._last_prof:
                for p,en in self._last_prof.items(): lines.insert(0,f"{p}: {'ON' if en else 'OFF'}")
            # Refresh profile status on background thread every ~30s
            if not hasattr(self,'_prof_tick'): self._prof_tick=0
            self._prof_tick+=1
            if self._prof_tick%6==1:
                threading.Thread(target=self._bg_profile,daemon=True).start()
            self.fw_lbl.setText("\n".join(lines))
        except Exception as e: log.warning(f"Dashboard refresh error: {e}")
    def _bg_profile(self):
        try: self._last_prof=fw.get_profile_status()
        except: pass
    def update_status(self,msg):
        self.ms.setText(msg)
        active=any(w in msg.lower() for w in ('start','monitor','scan','captured','active'))
        self.mi.setStyleSheet(f"color:{C['green'] if active else C['red']};font-size:{_dp(14)}px;")


# ─── DNS Feed Tab ────────────────────────────────────────────────────────────
class DNSFeedTab(QWidget):
    def __init__(self,db,hm):
        super().__init__(); self.db=db; self.hm=hm; self.monitor=None; self._build()
        _fav_cache.favicon_ready.connect(lambda _: self._dr())
    def set_monitor(self,m): self.monitor=m; m.feed_updated.connect(self.refresh)
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(20,16,20,16); lo.setSpacing(12)
        tb=QHBoxLayout(); tb.setSpacing(8)
        self.search=QLineEdit(); self.search.setPlaceholderText("Filter domains..."); self.search.setMinimumWidth(280)
        self.search.textChanged.connect(self._dr); tb.addWidget(self.search)
        self.filt=QComboBox(); self.filt.addItems(["All Visible","Blocked","Whitelisted","Unmanaged","Hidden"])
        self.filt.currentTextChanged.connect(self._dr); tb.addWidget(self.filt)
        tb.addStretch()
        self.scan_btn=_make_toolbar_btn("Scan Now","primary",self._scan); tb.addWidget(self.scan_btn)
        tb.addWidget(_make_toolbar_btn("Hide Selected","dim",self.hide_sel))
        tb.addWidget(_make_toolbar_btn("Block Selected","danger",self.block_sel))
        tb.addWidget(_make_toolbar_btn("Allow Selected","success",self.wl_sel))
        lo.addLayout(tb)
        self.table=QTableWidget(0,7)
        self.table.setHorizontalHeaderLabels(["Domain","Status","Hits","Last Seen","Process","First Seen","Actions"])
        h=self.table.horizontalHeader(); h.setSectionResizeMode(0,QHeaderView.Stretch)
        for i,w in [(1,90),(2,50),(3,145),(4,110),(5,145),(6,310)]: self.table.setColumnWidth(i,w)
        self.table.setAlternatingRowColors(True); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.verticalHeader().setVisible(False)
        self.table.setIconSize(QSize(16,16)); self.table.setSortingEnabled(True); lo.addWidget(self.table,1)
        self.slbl=QLabel(""); self.slbl.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); lo.addWidget(self.slbl)
        self.tmr=QTimer(self); self.tmr.timeout.connect(self.refresh); self.tmr.start(3000)
    def _scan(self):
        if self.monitor:
            self.scan_btn.setEnabled(False); self.scan_btn.setText("Scanning...")
            self.monitor.manual_scan()
            QTimer.singleShot(3000,lambda:(self.scan_btn.setEnabled(True),self.scan_btn.setText("Scan Now")))
    def _dr(self): QTimer.singleShot(0,self.refresh)
    def refresh(self):
        s=self.search.text().strip() or None
        fm={"All Visible":"all","Blocked":"blocked","Whitelisted":"whitelisted","Unmanaged":"unmanaged","Hidden":"hidden"}
        sf=fm.get(self.filt.currentText(),"all")
        rows=self.db.feed_get(search=s,show_hidden=(sf=="hidden"),status_filter=sf if sf!="all" else None)
        self.table.setSortingEnabled(False); self.table.setRowCount(len(rows))
        for i,(dom,fs,ls,hits,proc,hid,status) in enumerate(rows):
            _set_domain_item(self.table,i,0,dom)
            si=QTableWidgetItem(status.capitalize()); si.setForeground(QColor({"blocked":C['red'],"whitelisted":C['green']}.get(status,C['overlay'])))
            self.table.setItem(i,1,si)
            hi=QTableWidgetItem(str(hits)); hi.setTextAlignment(Qt.AlignCenter); hi.setData(Qt.UserRole,hits); self.table.setItem(i,2,hi)
            self.table.setItem(i,3,QTableWidgetItem(ls[:19].replace('T',' ') if ls else ''))
            self.table.setItem(i,4,QTableWidgetItem(proc or ''))
            self.table.setItem(i,5,QTableWidgetItem(fs[:19].replace('T',' ') if fs else ''))
            acts=[]
            if status!='blocked': acts.append(("Block","danger",lambda _,d=dom:self._block(d)))
            if status!='whitelisted': acts.append(("Allow","success",lambda _,d=dom:self._wl(d)))
            acts.append(("Unhide" if hid else "Hide","dim",lambda _,d=dom,h=hid:self._toggle_hide(d,h)))
            acts.append(("x","danger",lambda _,d=dom:self._del(d)))
            root_acts=[("Block root",lambda d=dom:self._block_root(d)),("Allow root",lambda d=dom:self._wl_root(d)),("Hide root",lambda d=dom:self._hide_root(d)),
                ("FW Block root IP",lambda d=dom:self._fw_block(d))]
            self.table.setCellWidget(i,6,_make_actions_widget(dom,acts,show_root=True,root_actions=root_acts))
        self.table.setSortingEnabled(True)
        self.slbl.setText(f"{len(rows)} shown  |  {self.db.feed_count(False)} visible  |  {self.db.feed_count(True)} hidden")
    def _block(self,d): self.db.add_domain(d,'blocked',source='feed'); self.hm.add_block(d); self.db.log_event(d,'blocked','','From DNS feed'); self._dr()
    def _wl(self,d): self.db.add_domain(d,'whitelisted',source='feed'); self.hm.remove_block(d); self.db.log_event(d,'whitelisted','','From DNS feed'); self._dr()
    def _toggle_hide(self,d,h):
        if h: self.db.feed_unhide(d)
        else: self.db.feed_hide(d)
        self._dr()
    def _del(self,d): self.db.feed_delete(d); self.db.remove_domain(d); self.hm.remove_entry(d); self._dr()
    def _block_root(self,d): ct=self.db.add_root_domain(d,'blocked','feed'); self.hm.add_block(get_root_domain(d)); self.db.log_event(get_root_domain(d),'blocked','',f'Root block ({ct})'); self._dr()
    def _wl_root(self,d): ct=self.db.add_root_domain(d,'whitelisted','feed'); self.hm.remove_block(get_root_domain(d)); self.db.log_event(get_root_domain(d),'whitelisted','',f'Root WL ({ct})'); self._dr()
    def _hide_root(self,d): self.db.feed_hide_root(d); self._dr()
    def _fw_block(self,d):
        root=get_root_domain(d)
        try:
            ip=socket.gethostbyname(root)
            ok,_=fw.block_ip(ip,"Outbound"); self.db.log_event(root,'fw_blocked','',f'FW block IP {ip}')
        except: pass
        self._dr()
    def hide_sel(self):
        ds=[self.table.item(r,0).text() for r in set(i.row() for i in self.table.selectedIndexes()) if self.table.item(r,0)]
        if ds: self.db.feed_hide_bulk(ds); self._dr()
    def block_sel(self):
        ds=[self.table.item(r,0).text() for r in set(i.row() for i in self.table.selectedIndexes()) if self.table.item(r,0)]
        for d in ds: self.db.add_domain(d,'blocked',source='feed'); self.hm.add_block(d); self.db.log_event(d,'blocked','','Bulk feed')
        self._dr()
    def wl_sel(self):
        ds=[self.table.item(r,0).text() for r in set(i.row() for i in self.table.selectedIndexes()) if self.table.item(r,0)]
        for d in ds: self.db.add_domain(d,'whitelisted',source='feed'); self.hm.remove_block(d); self.db.log_event(d,'whitelisted','','Bulk feed')
        self._dr()


# ─── Editor Tab ──────────────────────────────────────────────────────────────
class EditorTab(QWidget):
    def __init__(self,db,hm):
        super().__init__(); self.db=db; self.hm=hm; self._build(); self._load_file()
    def _build(self):
        lo=QHBoxLayout(self); lo.setContentsMargins(0,0,0,0); lo.setSpacing(0)
        splitter=QSplitter(Qt.Horizontal)
        ep=QWidget(); epl=QVBoxLayout(ep); epl.setContentsMargins(20,16,8,16); epl.setSpacing(8)
        tb=QHBoxLayout(); tb.setSpacing(6)
        tb.addWidget(_make_toolbar_btn("Save Raw","primary",self._save_raw))
        tb.addWidget(_make_toolbar_btn("Save Cleaned","success",self._save_cleaned))
        tb.addWidget(_make_toolbar_btn("Reload","dim",self._load_file)); tb.addStretch()
        self.search_ed=QLineEdit(); self.search_ed.setPlaceholderText("Search..."); self.search_ed.setMaximumWidth(250)
        self.search_ed.returnPressed.connect(self._search_next); tb.addWidget(self.search_ed)
        tb.addWidget(_make_toolbar_btn("Find","dim",self._search_next)); epl.addLayout(tb)
        self.stats_lbl=QLabel(""); self.stats_lbl.setStyleSheet(f"color:{C['subtext']};font-size:11px;padding:4px 8px;background:{C['mantle']};border-radius:6px;")
        epl.addWidget(self.stats_lbl)
        self.editor=QPlainTextEdit(); self.editor.setFont(QFont("Consolas",11))
        self.editor.setStyleSheet(f"QPlainTextEdit{{background:{C['crust']};color:{C['text']};border:1px solid {C['surface0']};border-radius:8px;padding:8px;}}")
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap); epl.addWidget(self.editor,1); splitter.addWidget(ep)
        wp=QWidget(); wp.setStyleSheet(f"background:{C['mantle']};"); wl=QVBoxLayout(wp); wl.setContentsMargins(12,16,16,16); wl.setSpacing(8)
        wl.addWidget(QLabel("WHITELIST")); wb=QHBoxLayout()
        wb.addWidget(_make_toolbar_btn("Load File","dim",self._load_wl_file))
        wb.addWidget(_make_toolbar_btn("HOSTShield WL","primary",self._import_wl_web)); wl.addLayout(wb)
        self.wl_edit=QPlainTextEdit(); self.wl_edit.setFont(QFont("Consolas",10)); self.wl_edit.setPlaceholderText("google.com\nyoutube.com\n...")
        wl.addWidget(self.wl_edit,1); splitter.addWidget(wp)
        splitter.setStretchFactor(0,3); splitter.setStretchFactor(1,1); lo.addWidget(splitter)
    def _get_wl_set(self): return {l.strip().lower().lstrip('.') for l in self.wl_edit.toPlainText().splitlines() if l.strip() and not l.strip().startswith('#')}
    def _load_file(self): self.editor.setPlainText(self.hm.read_raw()); self._update_stats(self.editor.toPlainText().splitlines())
    def _update_stats(self,lines):
        _,s=clean_hosts_content(lines,self._get_wl_set())
        self.stats_lbl.setText(f"Lines: {s['total']}  |  Active: {s['active']}  |  Dupes: {s['dupes']}  |  WL: {s['whitelist']}  |  Invalid: {s['invalid']}")
    def _save_raw(self):
        err=self.hm.write_full(self.editor.toPlainText())
        if err: QMessageBox.warning(self,"Error",err)
        else: self.stats_lbl.setText("Saved raw"); self._update_stats(self.editor.toPlainText().splitlines())
    def _save_cleaned(self):
        lines=self.editor.toPlainText().splitlines(); cleaned,stats=clean_hosts_content(lines,self._get_wl_set())
        content='\n'.join(cleaned); err=self.hm.write_full(content)
        if err: QMessageBox.warning(self,"Error",err)
        else: self.editor.setPlainText(content); self.stats_lbl.setText(f"Cleaned — {stats['active']} active, {stats['dupes']} dupes removed")
    def _search_next(self):
        q=self.search_ed.text()
        if q: self.editor.find(q)
    def _load_wl_file(self):
        p,_=QFileDialog.getOpenFileName(self,"Load Whitelist","","Text (*.txt);;All (*)")
        if p:
            with open(p,'r',encoding='utf-8',errors='replace') as f: self.wl_edit.setPlainText(f.read())
    def _import_wl_web(self):
        try:
            req=urllib.request.Request("https://raw.githubusercontent.com/SysAdminDoc/HOSTShield/refs/heads/main/Whitelist.txt",headers={'User-Agent':'Mozilla/5.0'})
            with urllib.request.urlopen(req,timeout=15) as r: self.wl_edit.setPlainText(r.read().decode('utf-8',errors='ignore'))
        except Exception as e: self.stats_lbl.setText(f"Failed: {e}")
    def append_lines(self,lines):
        cur=self.editor.toPlainText()
        if cur and not cur.endswith('\n'): cur+='\n'
        self.editor.setPlainText(cur+'\n'.join(lines)+'\n'); self._update_stats(self.editor.toPlainText().splitlines())


# ─── Arsenal Tab ─────────────────────────────────────────────────────────────
class ArsenalTab(QWidget):
    def __init__(self,db,hm,editor_tab):
        super().__init__(); self.db=db; self.hm=hm; self.editor=editor_tab; self._worker=None; self._build()
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(20,16,20,16); lo.setSpacing(12)
        top=QHBoxLayout(); top.setSpacing(10)
        self.mode=QComboBox(); self.mode.addItems(["Normalized (0.0.0.0 domain)","Raw"])
        top.addWidget(QLabel("Import mode:")); top.addWidget(self.mode); top.addStretch()
        imp_all=QPushButton("Import All Selected"); imp_all.setProperty("class","primary"); imp_all.clicked.connect(self._import_all); top.addWidget(imp_all)
        lo.addLayout(top)
        self.progress=QProgressBar(); self.progress.setVisible(False); lo.addWidget(self.progress)
        self.prog_lbl=QLabel(""); self.prog_lbl.setStyleSheet(f"color:{C['subtext']};font-size:11px;"); self.prog_lbl.setVisible(False); lo.addWidget(self.prog_lbl)
        scroll=QScrollArea(); scroll.setWidgetResizable(True); scroll.setStyleSheet(f"QScrollArea{{border:none;background:{C['base']};}}")
        container=QWidget(); self.list_lo=QVBoxLayout(container); self.list_lo.setContentsMargins(0,0,0,0); self.list_lo.setSpacing(6)
        self.checks=[]
        for cat,sources in BLOCKLIST_SOURCES.items():
            hdr=QLabel(cat.upper()); hdr.setStyleSheet(f"color:{C['blue']};font-size:10px;font-weight:800;letter-spacing:1.5px;padding:12px 0 4px 4px;")
            self.list_lo.addWidget(hdr)
            for name,url in sources:
                row=QHBoxLayout(); row.setContentsMargins(8,2,8,2)
                cb=QCheckBox(name); cb.setChecked(True); row.addWidget(cb,1)
                single=QPushButton("Import"); single.setProperty("class","dim"); single.setFixedHeight(22); single.setFixedWidth(60)
                single.clicked.connect(lambda _,n=name,u=url:self._import_single(n,u)); row.addWidget(single)
                self.list_lo.addLayout(row); self.checks.append((name,url,cb))
        self.list_lo.addStretch(); scroll.setWidget(container); lo.addWidget(scroll,1)
        bot=QHBoxLayout()
        sa=QPushButton("Select All"); sa.clicked.connect(lambda:[c.setChecked(True) for _,_,c in self.checks]); bot.addWidget(sa)
        sn=QPushButton("Select None"); sn.clicked.connect(lambda:[c.setChecked(False) for _,_,c in self.checks]); bot.addWidget(sn)
        bot.addStretch()
        self.stop_btn=QPushButton("Stop"); self.stop_btn.setProperty("class","danger"); self.stop_btn.setVisible(False)
        self.stop_btn.clicked.connect(self._cancel); bot.addWidget(self.stop_btn); lo.addLayout(bot)
    def _import_all(self):
        sel=[(n,u) for n,u,cb in self.checks if cb.isChecked()]
        if sel: self._start(sel)
    def _import_single(self,name,url): self._start([(name,url)])
    def _start(self,sources):
        if self._worker and self._worker.isRunning(): return
        self._worker=ImportWorker(sources,self.mode.currentIndex()==0,self.db)
        self._worker.progress.connect(self._on_prog); self._worker.finished.connect(self._on_done)
        self._worker.log_msg.connect(self._on_log)
        self._worker.cancelled.connect(self._on_cancel)
        self.progress.setVisible(True); self.progress.setMaximum(len(sources)); self.progress.setValue(0)
        self.prog_lbl.setVisible(True); self.stop_btn.setVisible(True); self._worker.start()
    def _on_prog(self,i,total,name): self.progress.setValue(i); self.prog_lbl.setText(f"Importing {i+1}/{total}: {name}")
    def _on_log(self,msg,is_error): self.prog_lbl.setText(msg)
    def _on_done(self,lines):
        self.progress.setVisible(False); self.stop_btn.setVisible(False)
        if lines: self.editor.append_lines(lines); self.prog_lbl.setText(f"Done — {len(lines)} entries")
        else: self.prog_lbl.setText("No data.")
    def _on_cancel(self): self.progress.setVisible(False); self.stop_btn.setVisible(False); self.prog_lbl.setText("Cancelled")
    def _cancel(self):
        if self._worker: self._worker.cancel()


# ─── Domain Manager Tab ─────────────────────────────────────────────────────
class DomainTab(QWidget):
    def __init__(self,db,hm):
        super().__init__(); self.db=db; self.hm=hm; self._build()
        _fav_cache.favicon_ready.connect(lambda _: QTimer.singleShot(0,self.refresh))
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(20,16,20,16); lo.setSpacing(10)
        tb=QHBoxLayout(); tb.setSpacing(8)
        self.search=QLineEdit(); self.search.setPlaceholderText("Search managed domains..."); self.search.setMinimumWidth(250)
        self.search.textChanged.connect(self._dr); tb.addWidget(self.search)
        self.filt=QComboBox(); self.filt.addItems(["All","Blocked","Whitelisted"]); self.filt.currentTextChanged.connect(self._dr); tb.addWidget(self.filt)
        tb.addStretch()
        tb.addWidget(_make_toolbar_btn("+ Add Domain","primary",self._add))
        tb.addWidget(_make_toolbar_btn("Sync Hosts","warning",self._sync))
        tb.addWidget(_make_toolbar_btn("Delete Selected","danger",self._del_sel)); lo.addLayout(tb)
        self.table=QTableWidget(0,7)
        self.table.setHorizontalHeaderLabels(["Domain","Status","Category","Source","Hits","Added","Actions"])
        self.table.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        for i,w in [(1,90),(2,90),(3,75),(4,50),(5,90),(6,280)]: self.table.setColumnWidth(i,w)
        self.table.setAlternatingRowColors(True); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.verticalHeader().setVisible(False)
        self.table.setIconSize(QSize(16,16)); self.table.setSortingEnabled(True); lo.addWidget(self.table,1)
        self.slbl=QLabel(""); self.slbl.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); lo.addWidget(self.slbl)
    def _dr(self): QTimer.singleShot(0,self.refresh)
    def refresh(self):
        sm={"All":None,"Blocked":"blocked","Whitelisted":"whitelisted"}
        rows=self.db.get_domains(status=sm.get(self.filt.currentText()),search=self.search.text().strip() or None)
        self.table.setSortingEnabled(False); self.table.setRowCount(len(rows))
        for i,(dom,st,cat,src,da,dm,hc,notes) in enumerate(rows):
            _set_domain_item(self.table,i,0,dom)
            si=QTableWidgetItem(st.capitalize()); si.setForeground(QColor({"blocked":C['red'],"whitelisted":C['green']}.get(st,C['text'])))
            self.table.setItem(i,1,si); self.table.setItem(i,2,QTableWidgetItem(cat or ''))
            self.table.setItem(i,3,QTableWidgetItem(src or ''))
            hi=QTableWidgetItem(str(hc)); hi.setTextAlignment(Qt.AlignCenter); self.table.setItem(i,4,hi)
            self.table.setItem(i,5,QTableWidgetItem(da[:10] if da else ''))
            acts=[]
            if st=='blocked': acts.append(("Allow","success",lambda _,d=dom:self._toggle(d,'whitelisted')))
            else: acts.append(("Block","danger",lambda _,d=dom:self._toggle(d,'blocked')))
            acts.append(("Del","danger",lambda _,d=dom:self._delete(d)))
            root_acts=[("Block root",lambda d=dom:self._block_root(d)),("Allow root",lambda d=dom:self._wl_root(d))]
            self.table.setCellWidget(i,6,_make_actions_widget(dom,acts,show_root=True,root_actions=root_acts))
        self.table.setSortingEnabled(True); self.slbl.setText(f"{len(rows)} managed domains")
    def _toggle(self,d,st):
        self.db.update_status(d,st)
        if st=='whitelisted': self.hm.remove_block(d)
        else: self.hm.restore_block(d)
        self.db.log_event(d,st,'',f'Changed to {st}'); self._dr()
    def _delete(self,d): self.hm.remove_entry(d); self.db.remove_domain(d); self._dr()
    def _block_root(self,d): self.db.add_root_domain(d,'blocked','manual'); self.hm.add_block(get_root_domain(d)); self._dr()
    def _wl_root(self,d): self.db.add_root_domain(d,'whitelisted','manual'); self.hm.remove_block(get_root_domain(d)); self._dr()
    def _add(self):
        d,ok=QInputDialog.getText(self,"Add Domain","Domain to block:")
        if ok and d.strip():
            d=re.sub(r'^https?://','',d.strip().lower()).split('/')[0].strip()
            self.db.add_domain(d,'blocked','manual'); self.hm.add_block(d); self._dr()
    def _del_sel(self):
        ds=[self.table.item(r,0).text() for r in sorted(set(i.row() for i in self.table.selectedIndexes()),reverse=True) if self.table.item(r,0)]
        for d in ds: self.hm.remove_entry(d); self.db.remove_domain(d)
        self._dr()
    def _sync(self):
        bl=set(d[0] for d in self.db.get_domains(status='blocked')); wl=set(d[0] for d in self.db.get_domains(status='whitelisted'))
        lines=WINDOWS_HEADER+[f"# --- {len(bl)} blocked by PyWall ---"]
        for d in sorted(bl): lines.append(f"0.0.0.0 {d}")
        for d in sorted(wl): lines.append(f"# WHITELISTED: 0.0.0.0 {d}")
        err=self.hm.write_full('\n'.join(lines))
        self.slbl.setText(f"Synced {len(bl)} blocked + {len(wl)} whitelisted" if not err else f"Error: {err}")


# ─── Connections Tab (Live Network Monitor) ──────────────────────────────────
class ConnectionsTab(QWidget):
    def __init__(self,db,hm,conn_db):
        super().__init__(); self.db=db; self.hm=hm; self.cdb=conn_db; self._data=[]; self._filtered=[]
        self._filter_txt=""; self._filter_dir="All"; self._filter_pro="All"; self._filter_cat="All"
        cfg=load_runtime_config().data
        self.learning=LearningReviewCollector(cfg.get("learning_mode_enabled",True), float(cfg.get("learning_mode_window_minutes",10.0))*60.0)
        self._build()
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(12,12,12,12); lo.setSpacing(8)
        tb=QHBoxLayout(); tb.setSpacing(6)
        self.search=QLineEdit(); self.search.setPlaceholderText("Filter by IP, host, process...")
        self.search.setFixedWidth(220); self.search.textChanged.connect(lambda v:setattr(self,'_filter_txt',v)); tb.addWidget(self.search)
        d_cb=QComboBox(); d_cb.addItems(["All","Out","Listen"]); d_cb.currentTextChanged.connect(lambda v:setattr(self,'_filter_dir',v)); tb.addWidget(d_cb)
        p_cb=QComboBox(); p_cb.addItems(["All","TCP","UDP"]); p_cb.currentTextChanged.connect(lambda v:setattr(self,'_filter_pro',v)); tb.addWidget(p_cb)
        cat_cb=QComboBox(); cat_cb.addItems(["All"]+sorted(_CATEGORIES.keys())+["LAN","Web","DNS","Email",""])
        cat_cb.currentTextChanged.connect(lambda v:setattr(self,'_filter_cat',v)); tb.addWidget(cat_cb)
        tb.addStretch()
        self.count_lbl=QLabel("0 connections"); self.count_lbl.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); tb.addWidget(self.count_lbl)
        lo.addLayout(tb)
        splitter=QSplitter(Qt.Horizontal)
        self.table=QTableWidget(0,20)
        cols=["Time","Dir","Proto","Local","L.Port","Remote","R.Port","Hostname","Process","PID","Service","Parent","Package","Signer","Owner","Country","Category","Sent","Recv","Status"]
        self.table.setHorizontalHeaderLabels(cols); self.table.setSelectionBehavior(QTableWidget.SelectRows)
        _a11y_table(self.table,"Live connections table","Live connection rows with text status, process identity, signer, service, country, and byte counters")
        self.table.verticalHeader().setVisible(False); self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers); self.table.setIconSize(QSize(16,16))
        widths=[58,35,38,100,50,110,50,150,100,42,95,110,130,120,90,65,75,70,70,90]
        for i,w in enumerate(widths): self.table.setColumnWidth(i,w)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu); self.table.customContextMenuRequested.connect(self._ctx_menu)
        self.table.currentCellChanged.connect(self._on_select); splitter.addWidget(self.table)
        rp=QWidget(); rl=QVBoxLayout(rp); rl.setContentsMargins(6,0,0,0)
        rl.addWidget(QLabel("Connection Detail")); self.detail=QTextEdit(); self.detail.setReadOnly(True); self.detail.setMaximumHeight(200)
        self.detail.setStyleSheet(f"background:{C['mantle']};border:1px solid {C['surface0']};border-radius:6px;padding:6px;font-family:Consolas;font-size:11px;color:{C['subtext']};")
        self.detail.setPlainText("Click a connection for details.\nRight-click for actions."); rl.addWidget(self.detail)
        # Quick action buttons
        ab=QHBoxLayout()
        self.btn_fw_block=QPushButton("FW Block IP"); self.btn_fw_block.setProperty("class","danger"); self.btn_fw_block.clicked.connect(self._fw_block_sel); ab.addWidget(self.btn_fw_block)
        self.btn_hosts_block=QPushButton("Hosts Block"); self.btn_hosts_block.setProperty("class","warning"); self.btn_hosts_block.clicked.connect(self._hosts_block_sel); ab.addWidget(self.btn_hosts_block)
        self.btn_kill=QPushButton("Kill Process"); self.btn_kill.setProperty("class","dim"); self.btn_kill.clicked.connect(self._kill_sel); ab.addWidget(self.btn_kill)
        rl.addLayout(ab)
        # Timed first-run learning review
        rl.addWidget(QLabel("Learning Review"))
        self.learn_lbl=QLabel("Collecting unknown outbound apps")
        self.learn_lbl.setWordWrap(True); self.learn_lbl.setStyleSheet(f"color:{C['subtext']};font-size:11px;")
        rl.addWidget(self.learn_lbl)
        self.learn_tbl=QTableWidget(0,4); self.learn_tbl.setHorizontalHeaderLabels(["App","Signer / Parent","Seen","Endpoints"])
        _a11y_table(self.learn_tbl,"Learning review table","Grouped unknown outbound apps ready for batch allow or block decisions")
        self.learn_tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        for i,w in [(1,130),(2,45),(3,115)]: self.learn_tbl.setColumnWidth(i,w)
        self.learn_tbl.verticalHeader().setVisible(False); self.learn_tbl.setAlternatingRowColors(True)
        self.learn_tbl.setEditTriggers(QTableWidget.NoEditTriggers); self.learn_tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.learn_tbl.setMaximumHeight(185); rl.addWidget(self.learn_tbl)
        lb=QHBoxLayout()
        lb.addWidget(_make_toolbar_btn("Allow","success",lambda:self._learning_decide("allow")))
        lb.addWidget(_make_toolbar_btn("Block","danger",lambda:self._learning_decide("block")))
        lb.addWidget(_make_toolbar_btn("End","dim",self._learning_end))
        lb.addWidget(_make_toolbar_btn("Clear","dim",self._learning_clear))
        rl.addLayout(lb)
        # HG rules mini-panel
        rl.addWidget(QLabel("PyWall FW Rules"))
        self.rules_tbl=QTableWidget(0,4); self.rules_tbl.setHorizontalHeaderLabels(["Name","Action","Direction","Addr"])
        _a11y_table(self.rules_tbl,"PyWall firewall rules table","Managed firewall rules created by PyWall")
        self.rules_tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch); self.rules_tbl.verticalHeader().setVisible(False)
        self.rules_tbl.setEditTriggers(QTableWidget.NoEditTriggers); self.rules_tbl.setMaximumHeight(200)
        self.rules_tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        self.rules_tbl.customContextMenuRequested.connect(self._rules_ctx); rl.addWidget(self.rules_tbl)
        rl.addStretch(); splitter.addWidget(rp); splitter.setStretchFactor(0,3); splitter.setStretchFactor(1,1)
        lo.addWidget(splitter,1)
    def _get_sel_ci(self):
        r=self.table.currentRow()
        if 0<=r<len(self._filtered): return self._filtered[r]
        return None
    def _on_select(self,row,*_):
        ci=self._get_sel_ci()
        if not ci: return
        port_name=PORTS.get(int(ci.rp),ci.rp) if ci.rp and ci.rp.isdigit() else ci.rp
        self.detail.setPlainText(f"Process:  {ci.proc} (PID {ci.pid})\nService:  {ci.svc}\nParent:   {ci.parent}\nPackage:  {ci.package}\nSigner:   {ci.signer}\nPath:     {ci.path}\nRemote:   {ci.ra}:{ci.rp} ({port_name})\n"
            f"Hostname: {ci.host}\nOwner:    {ci.org}\nCountry:  {ci.country} ({ci.cc})\nCategory: {ci.category}\nProtocol: {ci.proto} | State: {ci.state}\nStatus:   {ci.stat}")
        self.detail.append(f"I/O delta: {_fmt_bytes(ci.bytes_sent)} sent / {_fmt_bytes(ci.bytes_recv)} received")
    def _ctx_menu(self,pos):
        ci=self._get_sel_ci()
        if not ci: return
        menu=QMenu(self)
        menu.setStyleSheet(_CTX_STYLE)
        menu.addAction(f"FW Block IP ({ci.ra})").triggered.connect(lambda:self._fw_block_ip(ci.ra))
        menu.addAction(f"FW Block Outbound ({ci.ra})").triggered.connect(lambda:self._fw_block_ip(ci.ra,"Outbound"))
        menu.addAction(f"FW Block Inbound ({ci.ra})").triggered.connect(lambda:self._fw_block_ip(ci.ra,"Inbound"))
        menu.addSeparator()
        if ci.host and ci.host not in ("-","..."):
            menu.addAction(f"Hosts Block ({ci.host})").triggered.connect(lambda:self._hosts_block_domain(ci.host))
            menu.addAction(f"Hosts Block root ({get_root_domain(ci.host)})").triggered.connect(lambda:self._hosts_block_domain(get_root_domain(ci.host)))
        menu.addSeparator()
        menu.addAction(f"FW Block Program ({ci.proc})").triggered.connect(lambda:self._fw_block_program(ci.path))
        menu.addAction(f"Kill Process ({ci.proc})").triggered.connect(lambda:fw.kill_connection(ci.pid))
        menu.addSeparator()
        if ci.host and ci.host not in ("-","..."): menu.addAction(f"Research ({ci.host})").triggered.connect(lambda:open_research(ci.host))
        menu.addAction(f"Copy IP ({ci.ra})").triggered.connect(lambda:QApplication.clipboard().setText(ci.ra))
        menu.exec_(self.table.viewport().mapToGlobal(pos))
    def _fw_block_ip(self,ip,direction="Outbound"):
        ok,out=fw.block_ip(ip,direction); self._refresh_rules()
    def _fw_block_program(self,path):
        if path and path!="-": ok,_=fw.block_program(path); self._refresh_rules()
    def _hosts_block_domain(self,d):
        self.db.add_domain(d,'blocked','connections'); self.hm.add_block(d); self.db.log_event(d,'blocked','','From connections')
    def _fw_block_sel(self):
        ci=self._get_sel_ci()
        if ci and ci.ra and ci.ra not in ("*",""): self._fw_block_ip(ci.ra)
    def _hosts_block_sel(self):
        ci=self._get_sel_ci()
        if ci and ci.host and ci.host not in ("-","..."): self._hosts_block_domain(ci.host)
    def _kill_sel(self):
        ci=self._get_sel_ci()
        if ci and ci.pid>0: fw.kill_connection(ci.pid)
    def _learning_refresh(self):
        groups=self.learning.groups()
        self.learn_tbl.setSortingEnabled(False); self.learn_tbl.setRowCount(len(groups))
        for i,g in enumerate(groups):
            app=QTableWidgetItem(g["proc"] or "?"); app.setData(Qt.UserRole,g["key"])
            if g.get("path"): app.setToolTip(g["path"])
            self.learn_tbl.setItem(i,0,app)
            identity=g.get("signer") if g.get("signer") not in ("","-","...") else g.get("parent","-")
            self.learn_tbl.setItem(i,1,QTableWidgetItem(identity or "-"))
            ct=QTableWidgetItem(str(g.get("count",0))); ct.setTextAlignment(Qt.AlignCenter); self.learn_tbl.setItem(i,2,ct)
            eps=", ".join((g.get("endpoints") or [])[:3])
            self.learn_tbl.setItem(i,3,QTableWidgetItem(eps))
        self.learn_tbl.setSortingEnabled(True)
        if self.learning.active():
            rem=self.learning.seconds_remaining()
            self.learn_lbl.setText(f"Collecting unknown outbound apps for batch review ({len(groups)} groups, {rem//60}m {rem%60}s left)")
        else:
            self.learn_lbl.setText(f"Learning review stopped ({len(groups)} groups pending)")
    def _learning_selected_keys(self):
        keys=[]
        for row in sorted(set(i.row() for i in self.learn_tbl.selectedIndexes())):
            item=self.learn_tbl.item(row,0)
            key=item.data(Qt.UserRole) if item else ""
            if key and key not in keys: keys.append(key)
        return keys
    def _learning_decide(self, action):
        keys=self._learning_selected_keys()
        if not keys:
            self.learn_lbl.setText("Select one or more learning groups first")
            return
        decided=0; failures=[]
        for key in keys:
            group=self.learning.remove(key)
            if not group: continue
            data=group.as_dict(); path=data.get("path") or ""
            if path and path!="-":
                ok,out=(fw.allow_program(path) if action=="allow" else fw.block_program(path))
            else:
                ok=True; out=""
                for ip in (data.get("ips") or [])[:5]:
                    step_ok,step_out=(fw.allow_ip(ip,"Outbound") if action=="allow" else fw.block_ip(ip,"Outbound"))
                    ok=ok and step_ok
                    if not step_ok: out=step_out
            if ok:
                decided+=1
                event_action="learning_allow" if action=="allow" else "learning_block"
                self.db.log_event(data.get("proc","learning"),event_action,"LearningReview",
                    f"{data.get('count',0)} samples; signer={data.get('signer','-')}; parent={data.get('parent','-')}; path={path or 'endpoint fallback'}")
            else:
                failures.append(f"{data.get('proc','?')}: {out}")
        self._refresh_rules(); self._learning_refresh()
        self.learn_lbl.setText(f"{action.capitalize()}ed {decided} learning group(s)" + (f"; {failures[0]}" if failures else ""))
    def _learning_end(self):
        self.learning.stop(); self._learning_refresh()
    def _learning_clear(self):
        self.learning.clear(); self._learning_refresh()
    def _rules_ctx(self,pos):
        r=self.rules_tbl.currentRow()
        if r<0: return
        name=self.rules_tbl.item(r,0)
        if not name: return
        menu=QMenu(self); menu.setStyleSheet(_CTX_STYLE)
        menu.addAction("Delete Rule").triggered.connect(lambda:self._del_rule(name.text()))
        menu.exec_(self.rules_tbl.viewport().mapToGlobal(pos))
    def _del_rule(self,name): fw.delete_rule(name); self._refresh_rules()
    def _refresh_rules(self):
        rules=[r for r in fw.get_all_rules() if r.source=="pywall"]
        self.rules_tbl.setRowCount(len(rules))
        for i,r in enumerate(rules):
            self.rules_tbl.setItem(i,0,QTableWidgetItem(r.name)); self.rules_tbl.setItem(i,1,QTableWidgetItem(r.action))
            self.rules_tbl.setItem(i,2,QTableWidgetItem(r.direction))
            addr=r.remote_addr if r.remote_addr not in ("Any","*") else r.program or "Any"
            self.rules_tbl.setItem(i,3,QTableWidgetItem(addr[:40]))
    def update_data(self,conns):
        self._data=conns; self.learning.observe(conns); self._learning_refresh(); self._update_table()
    def _update_table(self):
        f=self._filter_txt.lower(); fd=self._filter_dir; fp=self._filter_pro; fc=self._filter_cat
        filtered=[]
        for ci in self._data:
            if fd!="All" and ci.dir!=fd: continue
            if fp!="All" and ci.proto!=fp: continue
            if fc!="All" and ci.category!=fc: continue
            hay=" ".join([ci.host,ci.proc,ci.ra,ci.org or "",ci.country,ci.svc,ci.parent,ci.package,ci.signer]).lower()
            if f and f not in hay: continue
            filtered.append(ci)
        self._filtered=filtered
        self.table.setSortingEnabled(False); self.table.setRowCount(len(filtered))
        for i,ci in enumerate(filtered):
            sc={"-":C['text'],"HOSTS:BLOCK":C['peach'],"FW:BLOCKED":C['red'],"POLICY:BLOCK":C['red']}
            color=QColor(sc.get(ci.stat,C['red'] if "BLOCK" in ci.stat else C['text']))
            vals=[ci.ts,ci.dir,ci.proto,ci.la,ci.lp,ci.ra,ci.rp,ci.host,ci.proc,str(ci.pid),ci.svc,ci.parent,ci.package,ci.signer,ci.org,f"{ci.country}",ci.category,_fmt_bytes(ci.bytes_sent),_fmt_bytes(ci.bytes_recv),ci.stat]
            for j,v in enumerate(vals):
                it=QTableWidgetItem(v)
                if ci.stat!="-": it.setForeground(color)
                self.table.setItem(i,j,it)
        self.table.setSortingEnabled(True)
        self.count_lbl.setText(f"{len(filtered)}/{len(self._data)} connections | review {len(self.learning.groups())}")


class FirewallRuleTableModel(QAbstractTableModel):
    HEADERS=["Enabled","Name","Direction","Action","Protocol","Remote Addr","Program","Source"]
    def __init__(self,parent=None):
        super().__init__(parent); self._rules=[]
    def set_rules(self,rules):
        self.beginResetModel(); self._rules=list(rules or []); self.endResetModel()
    def rowCount(self,parent=QModelIndex()): return 0 if parent.isValid() else len(self._rules)
    def columnCount(self,parent=QModelIndex()): return 0 if parent.isValid() else len(self.HEADERS)
    def data(self,index,role=Qt.DisplayRole):
        if not index.isValid(): return None
        try: r=self._rules[index.row()]
        except: return None
        col=index.column()
        if role in (Qt.DisplayRole,Qt.ToolTipRole):
            return self._value(r,col,tooltip=(role==Qt.ToolTipRole))
        if role==Qt.ForegroundRole:
            if col==0: return QColor(C['green'] if r.enabled else C['red'])
            if col==3: return QColor(C['red'] if r.action=="Block" else C['green'])
        return None
    def headerData(self,section,orientation,role=Qt.DisplayRole):
        if role==Qt.DisplayRole and orientation==Qt.Horizontal and 0<=section<len(self.HEADERS): return self.HEADERS[section]
        return None
    def sort(self,column,order=Qt.AscendingOrder):
        rev=order==Qt.DescendingOrder
        self.layoutAboutToBeChanged.emit()
        self._rules.sort(key=lambda r:str(self._value(r,column,tooltip=True)).lower(), reverse=rev)
        self.layoutChanged.emit()
    def rule_at(self,row):
        return self._rules[row] if 0<=row<len(self._rules) else None
    def _value(self,r,col,tooltip=False):
        if col==0: return "ON" if r.enabled else "OFF"
        if col==1: return r.name or ""
        if col==2: return r.direction or ""
        if col==3: return r.action or ""
        if col==4: return r.protocol or ""
        if col==5:
            addr=(r.remote_addr or "") if (r.remote_addr or "") not in ("Any","*","") else "Any"
            return addr if tooltip else addr[:50]
        if col==6:
            if tooltip: return r.program or ""
            try: return Path(r.program).name if r.program else ""
            except: return r.program or ""
        if col==7: return r.source or ""
        return ""

# ─── Firewall Rules Tab ─────────────────────────────────────────────────────
class FirewallTab(QWidget):
    def __init__(self):
        super().__init__(); self._rules=[]; self._worker=None; self._ready=False; self._build(); self._ready=True
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(12,12,12,12); lo.setSpacing(8)
        hdr=QLabel("Windows Firewall Rules"); hdr.setStyleSheet(f"font-size:14px;font-weight:800;color:{C['blue']};")
        lo.addWidget(hdr)
        desc=QLabel("Manage all Windows Firewall rules. PyWall-created rules are prefixed with 'PW_' and legacy 'HG_' rules remain visible. Right-click to edit/delete.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); lo.addWidget(desc)
        tb=QHBoxLayout(); tb.setSpacing(6)
        self.search=QLineEdit(); self.search.setPlaceholderText("Search rules..."); self.search.setFixedWidth(250)
        self.search.returnPressed.connect(self._do_search); tb.addWidget(self.search)
        self.filt=QComboBox(); self.filt.addItems(["All Rules","PyWall Only","System Only","Block Only","Allow Only"])
        # NOTE: connect signal AFTER table creation below
        tb.addWidget(self.filt)
        tb.addStretch()
        tb.addWidget(_make_toolbar_btn("+ New Rule","primary",self._new_rule))
        tb.addWidget(_make_toolbar_btn("Refresh","dim",self._do_search))
        tb.addWidget(_make_toolbar_btn("Restore Drift","warning",self._restore_tamper))
        tb.addWidget(_make_toolbar_btn("Accept Drift","dim",self._accept_tamper))
        self.del_all_btn=_make_toolbar_btn("Delete All HG","danger",self._delete_all_hg); tb.addWidget(self.del_all_btn)
        lo.addLayout(tb)
        self.prog_lbl=QLabel(""); self.prog_lbl.setStyleSheet(f"color:{C['subtext']};font-size:11px;"); lo.addWidget(self.prog_lbl)
        self._model=FirewallRuleTableModel(self)
        self.table=QTableView()
        self.table.setModel(self._model)
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        for i,w in [(0,55),(2,75),(3,60),(4,60),(5,160),(6,180),(7,80)]: self.table.setColumnWidth(i,w)
        self.table.setAlternatingRowColors(True); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu); self.table.customContextMenuRequested.connect(self._ctx_menu)
        lo.addWidget(self.table,1)
        self.slbl=QLabel(""); self.slbl.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); lo.addWidget(self.slbl)
        # Connect filter signal AFTER table exists
        self.filt.currentTextChanged.connect(self._apply_filter)
    def _do_search(self):
        self.prog_lbl.setText("Loading rules...")
        self._worker=RuleScanWorker(self.search.text().strip()); self._worker.ready.connect(self._on_rules); self._worker.start()
    def _on_rules(self,rules):
        self._rules=rules or []; self._apply_filter(); self.prog_lbl.setText("")
    def _apply_filter(self):
        try:
            f=self.filt.currentText(); rules=list(self._rules)
            if "PyWall" in f: rules=[r for r in rules if r.source=="pywall"]
            elif "System" in f: rules=[r for r in rules if r.source=="system"]
            elif "Block" in f: rules=[r for r in rules if r.action=="Block"]
            elif "Allow" in f: rules=[r for r in rules if r.action=="Allow"]
            self.table.setSortingEnabled(False); self._model.set_rules(rules); self.table.setSortingEnabled(True)
            hg_ct=sum(1 for r in self._rules if r.source=="pywall")
            msg=f"{len(rules)} shown  |  {len(self._rules)} total  |  {hg_ct} PyWall rules"
            tamper=fw.tamper_summary()
            if tamper.get("pending"):
                latest=tamper.get("latest",{})
                msg += f"  |  WARNING: {tamper.get('pending')} managed-rule drift event(s); latest {latest.get('change','?')} {latest.get('rule_name','')}"
            self.slbl.setText(msg)
        except Exception as e:
            self.slbl.setText(f"Error loading rules: {e}"); log.warning(f"_apply_filter error: {e}")
    def _ctx_menu(self,pos):
        idx=self.table.currentIndex()
        if not idx.isValid(): return
        rule=self._model.rule_at(idx.row())
        if not rule: return
        name=rule.name
        if not name: return
        is_on=bool(rule.enabled)
        menu=QMenu(self); menu.setStyleSheet(_CTX_STYLE)
        menu.addAction("Disable" if is_on else "Enable").triggered.connect(lambda:self._toggle_rule(name,not is_on))
        menu.addAction("Delete Rule").triggered.connect(lambda:self._delete_rule(name))
        menu.addAction("Copy Name").triggered.connect(lambda:QApplication.clipboard().setText(name))
        menu.exec_(self.table.viewport().mapToGlobal(pos))
    def _toggle_rule(self,name,enabled):
        try: fw.enable_rule(name,enabled)
        except Exception as e: log.warning(f"Toggle rule error: {e}")
        self._do_search()
    def _delete_rule(self,name):
        try: fw.delete_rule(name)
        except Exception as e: log.warning(f"Delete rule error: {e}")
        self._do_search()
    def _delete_all_hg(self):
        hg=[r.name for r in self._rules if r.source=="pywall" and r.name]
        for name in hg:
            try: fw.delete_rule(name)
            except: pass
        self._do_search()
    def _restore_tamper(self):
        ok,out=fw.restore_last_tamper()
        self.slbl.setText(f"Restored latest managed-rule drift" if ok else f"Restore failed: {out}")
        self._do_search()
    def _accept_tamper(self):
        ok,out=fw.accept_current_rules()
        self.slbl.setText(out if ok else f"Accept failed: {out}")
        self._do_search()
    def _new_rule(self):
        dlg=NewRuleDialog(self)
        if dlg.exec_(): self._do_search()

class NewRuleDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent); self.setWindowTitle("New Firewall Rule"); self.setMinimumWidth(420)
        self.setStyleSheet(f"QDialog{{background:{C['base']};}}QLabel{{color:{C['text']};}}")
        lo=QVBoxLayout(self); lo.setSpacing(10); lo.setContentsMargins(20,20,20,20)
        lo.addWidget(QLabel("Rule Name:")); self.name_ed=QLineEdit(); self.name_ed.setPlaceholderText("e.g. Block Telemetry"); lo.addWidget(self.name_ed)
        hl=QHBoxLayout()
        vl1=QVBoxLayout(); vl1.addWidget(QLabel("Direction:")); self.dir_cb=QComboBox(); self.dir_cb.addItems(["Outbound","Inbound"]); vl1.addWidget(self.dir_cb); hl.addLayout(vl1)
        vl2=QVBoxLayout(); vl2.addWidget(QLabel("Action:")); self.act_cb=QComboBox(); self.act_cb.addItems(["Block","Allow"]); vl2.addWidget(self.act_cb); hl.addLayout(vl2)
        vl3=QVBoxLayout(); vl3.addWidget(QLabel("Protocol:")); self.proto_cb=QComboBox(); self.proto_cb.addItems(["Any","TCP","UDP"]); vl3.addWidget(self.proto_cb); hl.addLayout(vl3)
        lo.addLayout(hl)
        lo.addWidget(QLabel("Remote Address (IP/CIDR, empty=Any):")); self.addr_ed=QLineEdit(); lo.addWidget(self.addr_ed)
        lo.addWidget(QLabel("Remote Port (empty=Any):")); self.port_ed=QLineEdit(); lo.addWidget(self.port_ed)
        lo.addWidget(QLabel("Program Path (empty=Any):")); ph=QHBoxLayout()
        self.prog_ed=QLineEdit(); ph.addWidget(self.prog_ed)
        browse=QPushButton("..."); browse.setFixedWidth(36); browse.clicked.connect(self._browse); ph.addWidget(browse); lo.addLayout(ph)
        bb=QHBoxLayout(); bb.addStretch()
        ok=QPushButton("Create"); ok.setProperty("class","primary"); ok.clicked.connect(self._create); bb.addWidget(ok)
        cancel=QPushButton("Cancel"); cancel.clicked.connect(self.reject); bb.addWidget(cancel); lo.addLayout(bb)
    def _browse(self):
        p,_=QFileDialog.getOpenFileName(self,"Select Program","","Executables (*.exe);;All (*)")
        if p: self.prog_ed.setText(p)
    def _create(self):
        name=self.name_ed.text().strip()
        if not name: return
        full_name=f"{FW_PFX}{name}"
        proto=self.proto_cb.currentText(); proto_arg=proto if proto!="Any" else ""
        ok,out=fw.create_rule(full_name,self.dir_cb.currentText(),self.act_cb.currentText(),
            remote_addr=self.addr_ed.text().strip(),remote_port=self.port_ed.text().strip(),
            protocol=proto_arg,program=self.prog_ed.text().strip(),
            desc=f"Created by PyWall at {datetime.datetime.now():%Y-%m-%d %H:%M}")
        if ok: self.accept()


# ─── Log Tab ─────────────────────────────────────────────────────────────────
class LogTab(QWidget):
    def __init__(self,db,hm):
        super().__init__(); self.db=db; self.hm=hm; self._build()
        _fav_cache.favicon_ready.connect(lambda _: QTimer.singleShot(0,self.refresh))
        self.tmr=QTimer(self); self.tmr.timeout.connect(self.refresh); self.tmr.start(5000)
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(20,16,20,16); lo.setSpacing(10)
        tb=QHBoxLayout(); tb.setSpacing(8)
        self.search=QLineEdit(); self.search.setPlaceholderText("Filter log..."); self.search.setMinimumWidth(200)
        self.search.textChanged.connect(self._dr); tb.addWidget(self.search)
        self.filt=QComboBox(); self.filt.addItems(["all","blocked","whitelisted","fw_blocked","added","removed"])
        self.filt.currentTextChanged.connect(self._dr); tb.addWidget(self.filt)
        self.time_filt=QComboBox(); self.time_filt.addItems(["All Time","Last Hour","Last 24h","Last 7 Days"])
        self.time_filt.currentTextChanged.connect(self._dr); tb.addWidget(self.time_filt)
        tb.addStretch()
        tb.addWidget(_make_toolbar_btn("Export CSV","dim",self._export))
        tb.addWidget(_make_toolbar_btn("Clear Log","danger",self._clear)); lo.addLayout(tb)
        self.table=QTableWidget(0,6)
        self.table.setHorizontalHeaderLabels(["Timestamp","Domain","Action","Process","Details","Actions"])
        self.table.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        for i,w in [(0,155),(2,90),(3,100),(4,160),(5,200)]: self.table.setColumnWidth(i,w)
        self.table.setAlternatingRowColors(True); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.verticalHeader().setVisible(False)
        self.table.setIconSize(QSize(16,16)); self.table.setSortingEnabled(True); lo.addWidget(self.table,1)
        self.slbl=QLabel(""); self.slbl.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); lo.addWidget(self.slbl)
    def _dr(self): QTimer.singleShot(0,self.refresh)
    def _get_since(self):
        t=self.time_filt.currentText()
        if "Hour" in t: return (datetime.datetime.now()-datetime.timedelta(hours=1)).isoformat()
        if "24h" in t: return (datetime.datetime.now()-datetime.timedelta(hours=24)).isoformat()
        if "7 Days" in t: return (datetime.datetime.now()-datetime.timedelta(days=7)).isoformat()
        return None
    def refresh(self):
        rows=self.db.get_log(500,domain_filter=self.search.text().strip() or None,
            action_filter=self.filt.currentText(),since=self._get_since())
        self.table.setSortingEnabled(False); self.table.setRowCount(len(rows))
        for i,(rid,ts,dom,act,proc,det) in enumerate(rows):
            self.table.setItem(i,0,QTableWidgetItem(ts[:19].replace('T',' ') if ts else ''))
            _set_domain_item(self.table,i,1,dom or '')
            ai=QTableWidgetItem(act or ''); ai.setForeground(QColor({"blocked":C['red'],"whitelisted":C['green'],"fw_blocked":C['mauve']}.get(act,C['text'])))
            self.table.setItem(i,2,ai); self.table.setItem(i,3,QTableWidgetItem(proc or ''))
            self.table.setItem(i,4,QTableWidgetItem(det or ''))
            acts=[("Block","danger",lambda _,d=dom:self._act(d,'blocked')),("Allow","success",lambda _,d=dom:self._act(d,'whitelisted'))]
            root_acts=[("Block root",lambda d=dom:self._act_root(d,'blocked')),("Allow root",lambda d=dom:self._act_root(d,'whitelisted')),("Hide root",lambda d=dom:self.db.feed_hide_root(d))]
            self.table.setCellWidget(i,5,_make_actions_widget(dom or '',acts,show_root=True,root_actions=root_acts))
        self.table.setSortingEnabled(True); self.slbl.setText(f"{len(rows)} log entries")
    def _act(self,d,st):
        self.db.add_domain(d,st); (self.hm.add_block if st=='blocked' else self.hm.remove_block)(d); self.db.log_event(d,st,'','From log'); self._dr()
    def _act_root(self,d,st):
        self.db.add_root_domain(d,st,'log'); (self.hm.add_block if st=='blocked' else self.hm.remove_block)(get_root_domain(d)); self._dr()
    def _export(self):
        p,_=QFileDialog.getSaveFileName(self,"Export Log","pywall_log.csv","CSV (*.csv)")
        if p:
            rows=self.db.get_log(50000)
            with open(p,'w',newline='',encoding='utf-8') as f:
                w=csv.writer(f); w.writerow(["ID","Timestamp","Domain","Action","Process","Details"])
                for r in rows: w.writerow(r)
    def _clear(self): self.db.clear_log(); self._dr()


# ─── Diagnostic Tab ──────────────────────────────────────────────────────────
class DiagnosticTab(QWidget):
    def __init__(self,db,hm):
        super().__init__(); self.db=db; self.hm=hm; self._active=False; self._sid=""; self._start_time=None
        self._captured={}; self._build()
        _fav_cache.favicon_ready.connect(lambda _: QTimer.singleShot(0,self._refresh_table))
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(20,16,20,16); lo.setSpacing(10)
        lo.addWidget(QLabel("Diagnostic Mode")); desc=QLabel("Start a session to capture blocked domains. Useful when something stops working after blocking.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); lo.addWidget(desc)
        tb=QHBoxLayout(); tb.setSpacing(8)
        self.btn=QPushButton("Start Session"); self.btn.setProperty("class","primary"); self.btn.clicked.connect(self._toggle); tb.addWidget(self.btn)
        self.timer_lbl=QLabel(""); self.timer_lbl.setStyleSheet(f"color:{C['subtext']};font-size:12px;"); tb.addWidget(self.timer_lbl)
        tb.addStretch()
        tb.addWidget(_make_toolbar_btn("Whitelist All","success",self._wl_all))
        tb.addWidget(_make_toolbar_btn("Clear","dim",self._clear)); lo.addLayout(tb)
        self.table=QTableWidget(0,4)
        self.table.setHorizontalHeaderLabels(["Domain","Hits","Last Seen","Actions"])
        self.table.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        for i,w in [(1,60),(2,140),(3,310)]: self.table.setColumnWidth(i,w)
        self.table.setAlternatingRowColors(True); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.verticalHeader().setVisible(False)
        self.table.setIconSize(QSize(16,16)); lo.addWidget(self.table,1)
        self.tmr=QTimer(self); self.tmr.timeout.connect(self._tick); self.tmr.start(1000)
    def _toggle(self):
        if self._active: self._active=False; self.btn.setText("Start Session"); self.btn.setProperty("class","primary"); self.btn.style().polish(self.btn)
        else:
            self._active=True; self._sid=datetime.datetime.now().strftime("%Y%m%d%H%M%S"); self._start_time=time.time()
            self._captured={}; self.btn.setText("Stop Session"); self.btn.setProperty("class","danger"); self.btn.style().polish(self.btn)
    def on_blocked(self,ev):
        if not self._active: return
        d=ev.get('domain','')
        if d:
            if d in self._captured: self._captured[d]['hits']+=1; self._captured[d]['last']=datetime.datetime.now().isoformat()
            else: self._captured[d]={'hits':1,'last':datetime.datetime.now().isoformat()}
            self.db.log_diagnostic(d,self._sid); self._refresh_table()
    def _tick(self):
        if self._active and self._start_time:
            e=int(time.time()-self._start_time); self.timer_lbl.setText(f"Session: {e//60}m {e%60}s  |  Captured: {len(self._captured)}")
    def _refresh_table(self):
        items=sorted(self._captured.items(),key=lambda x:x[1]['hits'],reverse=True)
        self.table.setRowCount(len(items))
        for i,(d,info) in enumerate(items):
            _set_domain_item(self.table,i,0,d)
            hi=QTableWidgetItem(str(info['hits'])); hi.setTextAlignment(Qt.AlignCenter); self.table.setItem(i,1,hi)
            self.table.setItem(i,2,QTableWidgetItem(info['last'][:19].replace('T',' ')))
            acts=[("Whitelist","success",lambda _,dd=d:self._wl(dd)),("Temp Allow","warning",lambda _,dd=d:self._temp(dd))]
            root_acts=[("WL root",lambda dd=d:self._wl_root(dd)),("Temp root",lambda dd=d:self._temp_root(dd))]
            self.table.setCellWidget(i,3,_make_actions_widget(d,acts,show_root=True,root_actions=root_acts))
    def _wl(self,d): self.db.add_domain(d,'whitelisted','diagnostic'); self.hm.remove_block(d); self.db.log_event(d,'whitelisted','','Diagnostic')
    def _temp(self,d): self.hm.remove_block(d)
    def _wl_root(self,d): self.db.add_root_domain(d,'whitelisted','diagnostic'); self.hm.remove_block(get_root_domain(d))
    def _temp_root(self,d):
        root=get_root_domain(d)
        for dd in self._captured:
            if dd.endswith(root): self.hm.remove_block(dd)
    def _wl_all(self):
        for d in list(self._captured): self._wl(d)
        self._refresh_table()
    def _clear(self): self._captured={}; self._refresh_table()


# ─── Security Tab ────────────────────────────────────────────────────────────
class SecurityTab(QWidget):
    def __init__(self):
        super().__init__(); self._build()
        self.tmr=QTimer(self); self.tmr.timeout.connect(self.refresh); self.tmr.start(5000)
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(20,16,20,16); lo.setSpacing(12)
        hdr=QLabel("Threat Detection & Security"); hdr.setStyleSheet(f"font-size:14px;font-weight:800;color:{C['blue']};"); lo.addWidget(hdr)
        desc=QLabel("Monitors for port scans, brute force attempts, and suspicious network activity.")
        desc.setWordWrap(True); desc.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); lo.addWidget(desc)
        sl=QHBoxLayout(); sl.setSpacing(10)
        self.s1=StatCard("Total Threats","0",C['peach']); self.s2=StatCard("High Severity","0",C['red'])
        self.s3=StatCard("FW Profiles","--",C['sky'])
        for s in [self.s1,self.s2,self.s3]: sl.addWidget(s)
        sl.addStretch(); lo.addLayout(sl)
        # Firewall profile toggles
        pg=QGroupBox("Firewall Profiles"); pgl=QHBoxLayout(pg)
        self.prof_checks={}
        for p in ["Domain","Private","Public"]:
            cb=QCheckBox(p); cb.setChecked(True)
            cb.stateChanged.connect(lambda s,pn=p:self._toggle_profile(pn,bool(s))); pgl.addWidget(cb); self.prof_checks[p]=cb
        pgl.addStretch(); lo.addWidget(pg)
        tb=QHBoxLayout()
        tb.addWidget(_make_toolbar_btn("Refresh","dim",self.refresh))
        tb.addWidget(_make_toolbar_btn("Clear Events","danger",self._clear)); tb.addStretch(); lo.addLayout(tb)
        self.table=QTableWidget(0,6)
        self.table.setHorizontalHeaderLabels(["Time","Type","Severity","Source IP","MITRE","Details"])
        self.table.horizontalHeader().setSectionResizeMode(5,QHeaderView.Stretch)
        for i,w in [(0,140),(1,100),(2,80),(3,120),(4,210)]: self.table.setColumnWidth(i,w)
        self.table.setAlternatingRowColors(True); self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu); self.table.customContextMenuRequested.connect(self._ctx)
        lo.addWidget(self.table,1)
    def refresh(self):
        st=threats.get_stats(); self.s1.set_value(st['total']); self.s2.set_value(st['high'])
    def refresh(self):
        st=threats.get_stats(); self.s1.set_value(st['total']); self.s2.set_value(st['high'])
        # Use last known profile status (updated in background)
        if hasattr(self,'_last_prof') and self._last_prof:
            try:
                on_ct=sum(1 for v in self._last_prof.values() if v); self.s3.set_value(f"{on_ct}/3")
                for p,cb in self.prof_checks.items():
                    cb.blockSignals(True); cb.setChecked(self._last_prof.get(p,True)); cb.blockSignals(False)
            except: pass
        # Trigger background profile refresh
        threading.Thread(target=self._bg_profile,daemon=True).start()
        evts=threats.get_events(200)
        self.table.setRowCount(len(evts))
        for i,e in enumerate(evts):
            self.table.setItem(i,0,QTableWidgetItem(e.ts)); self.table.setItem(i,1,QTableWidgetItem(e.type))
            si=QTableWidgetItem(e.severity.upper()); si.setForeground(QColor(C['red'] if e.severity=='high' else C['peach']))
            self.table.setItem(i,2,si); self.table.setItem(i,3,QTableWidgetItem(e.source_ip))
            mi=QTableWidgetItem(e.mitre_technique or "Unmapped")
            if e.mitre_url: mi.setToolTip(e.mitre_url)
            self.table.setItem(i,4,mi); self.table.setItem(i,5,QTableWidgetItem(e.details))
    def _bg_profile(self):
        try: self._last_prof=fw.get_profile_status()
        except: pass
    def _toggle_profile(self,p,en):
        threading.Thread(target=lambda:_ps(f'Set-NetFirewallProfile -Name {p} -Enabled {"True" if en else "False"}',10),daemon=True).start()
    def _ctx(self,pos):
        r=self.table.currentRow()
        if r<0: return
        ip_item=self.table.item(r,3)
        if not ip_item: return
        ip=ip_item.text()
        menu=QMenu(self); menu.setStyleSheet(_CTX_STYLE)
        menu.addAction(f"FW Block {ip}").triggered.connect(lambda:fw.block_ip(ip,"Inbound"))
        menu.addAction(f"Copy IP").triggered.connect(lambda:QApplication.clipboard().setText(ip))
        menu.exec_(self.table.viewport().mapToGlobal(pos))
    def _clear(self): threats.clear(); self.refresh()


# ─── Connection History Tab ──────────────────────────────────────────────────
class HistoryTab(QWidget):
    def __init__(self,conn_db):
        super().__init__(); self.cdb=conn_db; self._offset=0; self._build()
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(12,12,12,12); lo.setSpacing(8)
        hdr=QLabel("Connection History"); hdr.setStyleSheet(f"font-size:14px;font-weight:800;color:{C['blue']};"); lo.addWidget(hdr)
        tb=QHBoxLayout(); tb.setSpacing(6)
        self.search=QLineEdit(); self.search.setPlaceholderText("Search by IP, host, process..."); self.search.setFixedWidth(250)
        self.search.returnPressed.connect(self._do_search); tb.addWidget(self.search)
        self.mode=QComboBox(); self.mode.addItems(["Events","Sessions"]); self.mode.currentTextChanged.connect(lambda _:self._do_search()); tb.addWidget(self.mode)
        self.evidence=QComboBox(); self.evidence.addItems(["All Evidence","Event Backed","psutil Only"]); self.evidence.currentTextChanged.connect(lambda _:self._do_search()); tb.addWidget(self.evidence)
        tb.addWidget(_make_toolbar_btn("Search","primary",self._do_search))
        tb.addWidget(_make_toolbar_btn("Export CSV","dim",lambda:self._export_filtered("csv")))
        tb.addWidget(_make_toolbar_btn("Export JSON","dim",lambda:self._export_filtered("json")))
        tb.addStretch()
        self.count_lbl=QLabel(""); self.count_lbl.setStyleSheet(f"color:{C['overlay']};font-size:11px;"); tb.addWidget(self.count_lbl)
        lo.addLayout(tb)
        self.table=QTableWidget(0,21)
        self._set_cols(["Time","Src","Dir","Proto","Local","L.Port","Remote","R.Port","Host","Process","PID","Service","Parent","Package","Signer","State","Owner","Country","Status","Sent","Recv","Evidence","Event","Rule","Filter"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers); self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True); self.table.setAlternatingRowColors(True)
        lo.addWidget(self.table,1)
        pg=QHBoxLayout()
        pg.addWidget(_make_toolbar_btn("Prev","dim",lambda:self._page(-1)))
        self.page_lbl=QLabel("Page 1"); self.page_lbl.setStyleSheet(f"color:{C['subtext']};"); pg.addWidget(self.page_lbl)
        pg.addWidget(_make_toolbar_btn("Next","dim",lambda:self._page(1))); pg.addStretch()
        self.total_lbl=QLabel(""); self.total_lbl.setStyleSheet(f"color:{C['overlay']};font-size:10px;"); pg.addWidget(self.total_lbl)
        lo.addLayout(pg)
    def _do_search(self):
        self._offset=0; self._load()
    def _page(self,d):
        self._offset=max(0,self._offset+d*500); self._load()
    def _set_cols(self,cols):
        self.table.setColumnCount(len(cols)); self.table.setHorizontalHeaderLabels(cols)
    def _evidence_filter(self):
        text=self.evidence.currentText()
        if text.startswith("Event"): return "event"
        if text.startswith("psutil"): return "psutil"
        return "all"
    def _load(self):
        if self.mode.currentText()=="Sessions":
            self._load_sessions(); return
        rows=self.cdb.search(self.search.text().strip(),500,self._offset,self._evidence_filter())
        self._set_cols(["Time","Src","Dir","Proto","Local","L.Port","Remote","R.Port","Host","Process","PID","Service","Parent","Package","Signer","State","Owner","Country","Status","Sent","Recv","Evidence","Event","Record","Rule","Filter"])
        self.table.setRowCount(len(rows))
        for i,r in enumerate(rows):
            for j,v in enumerate(r[:26]):
                if j in (19,20): v=_fmt_bytes(v)
                self.table.setItem(i,j,QTableWidgetItem(str(v) if v else ""))
        self.page_lbl.setText(f"Page {self._offset//500+1}")
        self.count_lbl.setText(f"{len(rows)} results"); self.total_lbl.setText(f"Total: {self.cdb.count()}")
    def _load_sessions(self):
        rows=self.cdb.search_sessions(self.search.text().strip(),500,self._offset,self._evidence_filter())
        self._set_cols(["First","Last","Duration","Active","Proto","Local","L.Port","Remote","R.Port","Host","Process","PID","Service","Parent","Package","Signer","Samples","Sent","Recv","Status","Evidence","Event","Rule","Filter"])
        self.table.setRowCount(len(rows))
        for i,r in enumerate(rows):
            vals=list(r[:24]); vals[2]=_fmt_duration(vals[2]); vals[3]="ON" if vals[3] else "OFF"; vals[17]=_fmt_bytes(vals[17]); vals[18]=_fmt_bytes(vals[18])
            for j,v in enumerate(vals): self.table.setItem(i,j,QTableWidgetItem(str(v) if v else ""))
        self.page_lbl.setText(f"Page {self._offset//500+1}")
        self.count_lbl.setText(f"{len(rows)} sessions"); self.total_lbl.setText(f"Sessions: {self.cdb.get_stats().get('sessions',0)}")
    def _export_filtered(self,fmt):
        ext="json" if fmt=="json" else "csv"
        path,_=QFileDialog.getSaveFileName(self,f"Export History ({ext.upper()})",os.path.join(REPORT_DIR,f"pywall-history-{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"),f"{ext.upper()} files (*.{ext})")
        if not path: return
        data=self.cdb.export_history(fmt=fmt,query=self.search.text().strip(),evidence=self._evidence_filter())
        try:
            os.makedirs(os.path.dirname(path),exist_ok=True)
            with open(path,"w",encoding="utf-8") as f: f.write(data)
            self.count_lbl.setText(f"Exported to {os.path.basename(path)}")
        except Exception as e: self.count_lbl.setText(f"Export failed: {e}")


# ─── Tools Tab ───────────────────────────────────────────────────────────────
class ToolsTab(QWidget):
    def __init__(self,db,hm):
        super().__init__(); self.db=db; self.hm=hm; self._build()
    def _build(self):
        lo=QVBoxLayout(self); lo.setContentsMargins(20,16,20,16); lo.setSpacing(10)
        # Background service tools
        g0=QGroupBox("Background Service"); g0l=QHBoxLayout(g0)
        self.service_lbl=QLabel("Service status unknown")
        self.service_lbl.setStyleSheet(f"color:{C['subtext']};font-size:11px;")
        g0l.addWidget(self.service_lbl,1)
        g0l.addWidget(_make_toolbar_btn("Refresh Service Status","primary",self._service_status))
        lo.addWidget(g0)
        # DNS + System tools
        g1=QGroupBox("DNS & System"); g1l=QHBoxLayout(g1)
        g1l.addWidget(_make_toolbar_btn("Flush DNS Cache","primary",self._flush))
        g1l.addWidget(_make_toolbar_btn("Backup Hosts File","dim",self._backup))
        g1l.addWidget(_make_toolbar_btn("Restore Backup","dim",self._restore))
        g1l.addWidget(_make_toolbar_btn("Emergency Unlock","danger",self._unlock)); g1l.addStretch(); lo.addWidget(g1)
        # Firewall tools
        g2=QGroupBox("Firewall Tools"); g2l=QHBoxLayout(g2)
        g2l.addWidget(_make_toolbar_btn("Enable All Profiles","success",self._fw_enable_all))
        g2l.addWidget(_make_toolbar_btn("Reset FW to Default","danger",self._fw_reset))
        g2l.addWidget(_make_toolbar_btn("Export FW Config","dim",self._fw_export))
        g2l.addWidget(_make_toolbar_btn("Restore FW Config","dim",self._fw_restore))
        g2l.addWidget(_make_toolbar_btn("Enable Audit Logging","dim",self._fw_audit)); g2l.addStretch(); lo.addWidget(g2)
        # Cache tools
        g3=QGroupBox("Cache & Data"); g3l=QHBoxLayout(g3)
        g3l.addWidget(_make_toolbar_btn("Clear Favicon Cache","dim",self._clear_favicons))
        g3l.addWidget(_make_toolbar_btn("Prune History (30d)","dim",self._prune_history))
        g3l.addWidget(_make_toolbar_btn("Export Usage Reports","primary",self._export_usage_reports))
        g3l.addWidget(_make_toolbar_btn("Open Config Folder","dim",self._open_config)); g3l.addStretch(); lo.addWidget(g3)
        # Plugin trust boundary tools
        gplug=QGroupBox("Plugin Guardrails"); gplugl=QHBoxLayout(gplug)
        self.plugin_lbl=QLabel("Plugins not scanned")
        self.plugin_lbl.setStyleSheet(f"color:{C['subtext']};font-size:11px;")
        gplugl.addWidget(self.plugin_lbl,1)
        gplugl.addWidget(_make_toolbar_btn("Scan Plugins","primary",self._scan_plugins))
        gplugl.addWidget(_make_toolbar_btn("Open Plugin Folder","dim",self._open_plugins))
        lo.addWidget(gplug)
        # Import tools
        g4=QGroupBox("External Import"); g4l=QVBoxLayout(g4)
        g4l.addWidget(QLabel("Paste domains to block (one per line):"))
        self.paste=QPlainTextEdit(); self.paste.setMaximumHeight(120); self.paste.setFont(QFont("Consolas",10))
        self.paste.setPlaceholderText("example.com\nad.tracker.net\n..."); g4l.addWidget(self.paste)
        bb=QHBoxLayout()
        bb.addWidget(_make_toolbar_btn("Import to Hosts","primary",self._import_paste))
        bb.addWidget(_make_toolbar_btn("Import to DB Only","dim",self._import_db)); bb.addStretch(); g4l.addLayout(bb); lo.addWidget(g4)
        self.slbl=QLabel(""); self.slbl.setStyleSheet(f"color:{C['subtext']};font-size:11px;"); lo.addWidget(self.slbl)
        lo.addStretch()
    def _service_status(self):
        resp=_service_ipc_request("status",timeout=1.5)
        if not resp.get("ok"):
            msg=f"Service offline: {resp.get('error','unknown')}"
            self.service_lbl.setText(msg); self.slbl.setText(msg); return
        s=resp.get("status",{})
        mins=int(s.get("uptime_sec",0))//60
        prev=s.get("previous_clean_shutdown")
        prev_txt="prev clean" if prev is True else "prev unclean" if prev is False else "prev new"
        cfg_state="cfg recovered" if s.get("config_recovered") else f"cfg warnings {len(s.get('config_warnings',[]) or [])}" if s.get("config_warnings") else "cfg ok"
        q=s.get("bandwidth_quotas",{}) if isinstance(s.get("bandwidth_quotas",{}),dict) else {}
        doh=s.get("doh",{}) if isinstance(s.get("doh",{}),dict) else {}
        ids=s.get("ids",{}) if isinstance(s.get("ids",{}),dict) else {}
        geo=s.get("geoip",{}) if isinstance(s.get("geoip",{}),dict) else {}
        tls=s.get("tls_sni",{}) if isinstance(s.get("tls_sni",{}),dict) else {}
        signer=s.get("signer",{}) if isinstance(s.get("signer",{}),dict) else {}
        plugins=s.get("plugins",{}) if isinstance(s.get("plugins",{}),dict) else {}
        tamper=s.get("firewall_tamper",{}) if isinstance(s.get("firewall_tamper",{}),dict) else {}
        msg=(f"RUNNING v{s.get('version','?')} | {s.get('status','')} | uptime {mins}m | "
             f"live {s.get('live_connections',0)} | sessions {s.get('active_sessions',0)}/{s.get('sessions',0)} | history {s.get('history_total',0)} | auto-blocked {s.get('auto_blocked_ips',0)} | "
             f"quotas {q.get('configured',0)}/{q.get('blocked',0)} | doh {doh.get('action','warn')} {doh.get('detected',0)}/{doh.get('blocked',0)} | ids {ids.get('rules',0)} {ids.get('hits',0)}/{ids.get('blocked',0)} | "
             f"geoip {geo.get('provider','ipwhois')} {geo.get('lookups',0)}/{geo.get('unknown',0)} | sni {'on' if tls.get('enabled') else 'off'} {tls.get('seen',0)} | "
             f"signers {signer.get('cached',0)}/{signer.get('queued',0)} | plugins {plugins.get('executable',0)}/{plugins.get('total',0)} invalid {plugins.get('invalid',0)} | tamper {tamper.get('pending',0)} | "
             f"bytes {_fmt_bytes(s.get('bytes_sent',0))}/{_fmt_bytes(s.get('bytes_recv',0))} | config {s.get('last_config_reload','')} {cfg_state} | {prev_txt}")
        self.service_lbl.setText(msg)
        self.slbl.setText("Service IPC query succeeded")
    def _flush(self):
        if sys.platform=='win32':
            subprocess.run(['ipconfig','/flushdns'],capture_output=True,timeout=10,creationflags=NOWIN)
        self.slbl.setText("DNS cache flushed")
    def _backup(self):
        p=self.hm.backup()
        self.slbl.setText(f"Backup: {p}" if p else "Backup failed")
    def _restore(self):
        d=os.path.join(CONFIG_DIR,"backups")
        p,_=QFileDialog.getOpenFileName(self,"Select Backup",d,"All (*)")
        if p:
            try: shutil.copy2(p,HOSTS_PATH); self.slbl.setText("Restored from backup")
            except Exception as e: self.slbl.setText(f"Restore failed: {e}")
    def _unlock(self):
        try:
            with open(HOSTS_PATH,'w',encoding='utf-8') as f: f.write('\n'.join(WINDOWS_HEADER)+'\n')
            self.slbl.setText("Hosts file reset to default")
        except Exception as e: self.slbl.setText(f"Failed: {e}")
    def _fw_enable_all(self):
        for p in ["Domain","Private","Public"]: _ps(f'Set-NetFirewallProfile -Name {p} -Enabled True',10)
        self.slbl.setText("All firewall profiles enabled")
    def _fw_reset(self):
        backup = _timestamped_fw_export_path()
        ok,out = _export_firewall_config(backup)
        if not ok:
            self.slbl.setText(f"Reset aborted; firewall export failed: {out[:160] if out else 'unknown error'}")
            return
        ok,out = _ps("netsh advfirewall reset",15)
        if ok:
            self.slbl.setText(f"Firewall reset to defaults; rollback saved: {backup}")
        else:
            self.slbl.setText(f"Reset failed after rollback export: {backup} ({out[:120] if out else 'unknown error'})")
    def _fw_export(self):
        p,_=QFileDialog.getSaveFileName(self,"Export FW Config","fw_export.wfw","WFW (*.wfw)")
        if p:
            ok,_=_export_firewall_config(p)
            self.slbl.setText(f"Exported to {p}" if ok else "Export failed")
    def _fw_restore(self):
        p,_=QFileDialog.getOpenFileName(self,"Restore FW Config",os.path.join(CONFIG_DIR,"fw_backups"),"WFW (*.wfw)")
        if p:
            ok,out=_import_firewall_config(p)
            self.slbl.setText(f"Restored firewall config from {p}" if ok else f"Restore failed: {out[:160] if out else 'unknown error'}")
    def _fw_audit(self):
        _ps("auditpol /set /subcategory:\"Filtering Platform Connection\" /failure:enable /success:enable",10)
        for p in ("domain","private","public"):
            _ps(f'netsh advfirewall set {p}profile logging allowedconnections enable droppedconnections enable',10)
        self.slbl.setText("Firewall audit logging enabled")
    def _clear_favicons(self):
        ct=0
        for f in Path(FAVICON_DIR).glob("*.png"):
            try: f.unlink(); ct+=1
            except: pass
        if _fav_cache: _fav_cache._mem.clear()
        self.slbl.setText(f"Cleared {ct} cached favicons")
    def _prune_history(self):
        cdb=ConnDB(); cdb.prune(30); self.slbl.setText("Pruned connection history older than 30 days")
    def _export_usage_reports(self):
        try:
            exports=export_usage_reports()
            names=", ".join(f"{x['period']} {x['rows']} apps" for x in exports)
            self.slbl.setText(f"Exported usage reports to {REPORT_DIR}: {names}")
        except Exception as e:
            self.slbl.setText(f"Usage report export failed: {e}")
    def _open_config(self):
        if sys.platform=='win32': os.startfile(CONFIG_DIR)
        else: subprocess.Popen(['xdg-open',CONFIG_DIR])
    def _scan_plugins(self):
        result=PluginRegistry().scan()
        summary=result.summary()
        self.plugin_lbl.setText(
            f"{summary['total']} found | {summary['executable']} executable | {summary['invalid']} invalid | "
            f"signed {summary['signed']} | unsigned {summary['unsigned']} | unknown {summary['unknown']}"
        )
        if result.errors:
            self.slbl.setText(result.errors[0][:180])
        else:
            self.slbl.setText("Plugin manifests scanned; no plugin code executed")
    def _open_plugins(self):
        os.makedirs(PLUGINS_DIR,exist_ok=True)
        if sys.platform=='win32': os.startfile(PLUGINS_DIR)
        else: subprocess.Popen(['xdg-open',PLUGINS_DIR])
    def _import_paste(self):
        lines=[l.strip().lower() for l in self.paste.toPlainText().splitlines() if l.strip() and not l.strip().startswith('#')]
        domains=[d for d in lines if looks_like_domain(d)]
        if domains:
            self.hm.add_blocks_bulk(domains)
            for d in domains: self.db.add_domain(d,'blocked','paste')
            self.slbl.setText(f"Imported {len(domains)} domains to hosts file")
        else: self.slbl.setText("No valid domains found")
    def _import_db(self):
        lines=[l.strip().lower() for l in self.paste.toPlainText().splitlines() if l.strip() and not l.strip().startswith('#')]
        domains=[d for d in lines if looks_like_domain(d)]
        if domains:
            for d in domains: self.db.add_domain(d,'blocked','paste')
            self.slbl.setText(f"Imported {len(domains)} domains to database only")
        else: self.slbl.setText("No valid domains found")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(_dp(1300),_dp(800)); self.resize(_dp(1520),_dp(920))
        self._monitoring=False; self._conn_monitoring=False
        self._config_result=load_runtime_config()
        self._notif=NotificationController(self._config_result.data)

        # Core objects
        self.db=HostsDB(); self.hm=HostsFileManager(); self.conn_db=ConnDB(); self._quota=BandwidthQuotaEnforcer("PyWallGUI"); self._doh=DoHDetector("PyWallGUI"); self._ids=IDSRuleEngine("PyWallGUI")

        # Background workers
        self._dns_w=DNSResolveWorker(); self._dns_w.start()
        self._who_w=WhoWorker(); self._who_w.start()
        self._geo_w=GeoIPWorker(); self._geo_w.start()
        self._sign_w=SignerWorker(); self._sign_w.start()
        self._tls_w=TLSLogWorker(self.db)
        self._conn_w=None; self._evt_w=None

        self._build_ui()
        self._build_tray()
        self._digest_timer=QTimer(self); self._digest_timer.timeout.connect(self._flush_digest); self._digest_timer.start(60000)
        self._geo_w.status_changed.connect(lambda msg:self._sbar_msg.setText(msg))
        self._tls_w.status_changed.connect(lambda msg:self._sbar_msg.setText(msg))
        self._tls_w.feed_updated.connect(self._feed.refresh)
        self._tls_w.start()
        if self._config_result.recovered:
            self._sbar_msg.setText(f"Config recovered; backup saved to {self._config_result.backup_path}")
        elif self._config_result.warnings:
            self._sbar_msg.setText(f"Config warning: {self._config_result.warnings[0]}")

        # Auto-start DNS monitor
        QTimer.singleShot(300,self._start_dns_monitor)
        # Auto-start connection monitor
        QTimer.singleShot(800,self._start_conn_monitor)

    def _build_ui(self):
        central=QWidget(); central.setStyleSheet(f"background:{C['bg']};"); self.setCentralWidget(central)
        root=QVBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Top Bar ──
        top=QWidget(); top.setFixedHeight(_dp(48))
        top.setStyleSheet(f"background:{C['crust']};border-bottom:1px solid {C['surface0']};")
        tb=QHBoxLayout(top); tb.setContentsMargins(_dp(20),0,_dp(20),0); tb.setSpacing(_dp(12))

        # Logo
        logo=QLabel(f"\u25C6  {APP_NAME}")
        logo.setFont(QFont("Segoe UI Variable Display",_dp(13),QFont.Bold))
        logo.setStyleSheet(f"color:{C['blue']};border:none;letter-spacing:-0.5px;"); tb.addWidget(logo)
        ver=QLabel(f"v{APP_VERSION}"); ver.setStyleSheet(f"color:{C['overlay']};font-size:{_dp(9)}px;border:none;padding-top:2px;"); tb.addWidget(ver)

        # Separator
        sep=QFrame(); sep.setFixedWidth(1); sep.setFixedHeight(_dp(24))
        sep.setStyleSheet(f"background:{C['surface0']};border:none;"); tb.addWidget(sep)

        # Status indicator
        self._status_dot=QLabel(); self._status_dot.setFixedSize(_dp(8),_dp(8))
        self._status_dot.setStyleSheet(f"background:{C['overlay']};border-radius:{_dp(4)}px;border:none;"); tb.addWidget(self._status_dot)
        self._status_lbl=QLabel("STARTING"); self._status_lbl.setStyleSheet(f"color:{C['overlay']};font-size:{_dp(10)}px;font-weight:700;border:none;letter-spacing:0.5px;"); tb.addWidget(self._status_lbl)

        # Admin badge
        try:
            import ctypes; is_admin=ctypes.windll.shell32.IsUserAnAdmin()!=0
        except: is_admin=False
        admin_lbl=QLabel("ADMIN" if is_admin else "LIMITED")
        ac=C['green'] if is_admin else C['peach']
        admin_lbl.setStyleSheet(f"color:{ac};font-size:{_dp(9)}px;font-weight:700;border:1px solid {ac};border-radius:{_dp(4)}px;padding:2px 6px;border:none;background:rgba({','.join(str(int(ac.lstrip('#')[i:i+2],16)) for i in (0,2,4))},0.12);"); tb.addWidget(admin_lbl)

        tb.addStretch()

        # Bandwidth display
        bw_frame=QWidget(); bw_frame.setStyleSheet(f"background:transparent;border:none;")
        bwl=QHBoxLayout(bw_frame); bwl.setContentsMargins(0,0,0,0); bwl.setSpacing(_dp(14))
        self._bw_up=QLabel("\u25B2 -- B/s"); self._bw_up.setStyleSheet(f"color:{C['blue']};font-size:{_dp(10)}px;font-weight:600;border:none;font-family:'Cascadia Code','Consolas',monospace;")
        self._bw_dn=QLabel("\u25BC -- B/s"); self._bw_dn.setStyleSheet(f"color:{C['teal']};font-size:{_dp(10)}px;font-weight:600;border:none;font-family:'Cascadia Code','Consolas',monospace;")
        bwl.addWidget(self._bw_up); bwl.addWidget(self._bw_dn); tb.addWidget(bw_frame)

        # Connection toggle
        self._conn_btn=QPushButton("CONNECTIONS: OFF")
        self._conn_btn.setCursor(Qt.PointingHandCursor); self._conn_btn.setFixedHeight(_dp(28))
        self._conn_btn.setStyleSheet(f"background:{C['surface0']};color:{C['overlay']};padding:4px 16px;border-radius:{_dp(6)}px;font-weight:700;font-size:{_dp(9)}px;border:none;letter-spacing:0.5px;")
        self._conn_btn.clicked.connect(self._toggle_conn_monitor); tb.addWidget(self._conn_btn)

        root.addWidget(top)

        # ── Tabs ──
        self._tabs=QTabWidget(); self._tabs.setDocumentMode(True)

        # Overview
        self._dashboard=DashboardTab(self.db,self.conn_db); self._tabs.addTab(self._dashboard,"Dashboard")
        # Hosts Management group
        self._feed=DNSFeedTab(self.db,self.hm); self._tabs.addTab(self._feed,"DNS Feed")
        self._domains=DomainTab(self.db,self.hm); self._tabs.addTab(self._domains,"Domains")
        self._editor=EditorTab(self.db,self.hm); self._tabs.addTab(self._editor,"Hosts File")
        self._arsenal=ArsenalTab(self.db,self.hm,self._editor); self._tabs.addTab(self._arsenal,"Blocklists")
        # Firewall / Network group
        self._conns=ConnectionsTab(self.db,self.hm,self.conn_db); self._tabs.addTab(self._conns,"Connections")
        self._fw_tab=FirewallTab(); self._tabs.addTab(self._fw_tab,"FW Rules")
        self._security=SecurityTab(); self._tabs.addTab(self._security,"Security")
        # Logs
        self._log=LogTab(self.db,self.hm); self._tabs.addTab(self._log,"Log")
        self._history=HistoryTab(self.conn_db); self._tabs.addTab(self._history,"History")
        # Utilities
        self._diag=DiagnosticTab(self.db,self.hm); self._tabs.addTab(self._diag,"Diagnostic")
        self._tools=ToolsTab(self.db,self.hm); self._tabs.addTab(self._tools,"Tools")

        # Lazy-load firewall on first tab switch
        self._fw_loaded=False
        self._tabs.currentChanged.connect(self._on_tab_change)
        root.addWidget(self._tabs)

        # ── Status Bar ──
        sbar=QStatusBar()
        sbar.setStyleSheet(f"QStatusBar{{background:{C['crust']};color:{C['overlay']};border-top:1px solid {C['surface0']};padding:4px {_dp(16)}px;}}QStatusBar QLabel{{font-size:{_dp(10)}px;color:{C['overlay']};background:transparent;}}")
        self._sbar_msg=QLabel("Ready")
        sbar.addWidget(self._sbar_msg)
        sbar.addPermanentWidget(QLabel(f"DB: {os.path.basename(DB_PATH)}  \u00B7  Hosts: {HOSTS_PATH}"))
        self.setStatusBar(sbar)

        # BW update timer
        self._bw_tmr=QTimer(self); self._bw_tmr.timeout.connect(self._update_bw); self._bw_tmr.start(2000)

    def _on_tab_change(self,idx):
        try:
            tab=self._tabs.widget(idx)
            if tab is self._fw_tab and not self._fw_loaded:
                self._fw_loaded=True; self._fw_tab._do_search()
            elif tab is self._history: self._history._load()
            elif tab is self._security: self._security.refresh()
        except Exception as e:
            log.warning(f"Tab change error: {e}")
            try:
                with open(os.path.join(CONFIG_DIR,"crash.log"),'a') as f:
                    import traceback; f.write(f"\n{'='*60}\n{datetime.datetime.now()}\nTab switch to idx={idx}\n{traceback.format_exc()}\n")
            except: pass

    def _update_bw(self):
        up,dn=bw_tracker.rates()
        self._bw_up.setText(f"\u25B2 {bw_tracker.format_rate(up)}"); self._bw_dn.setText(f"\u25BC {bw_tracker.format_rate(dn)}")

    # ── DNS Monitor ──
    def _start_dns_monitor(self):
        self._dns_mon=DNSMonitorThread(self.hm,self.db)
        self._dns_mon.status_changed.connect(self._on_dns_status)
        self._dns_mon.blocked_event.connect(self._on_blocked)
        self._dns_mon.feed_updated.connect(self._feed.refresh)
        self._feed.set_monitor(self._dns_mon)
        self._dns_mon.start()
        self._monitoring=True; self._update_status("DNS Monitor Active")

    def _on_dns_status(self,msg): self._sbar_msg.setText(msg); self._dashboard.update_status(msg)

    def _on_blocked(self,ev):
        self.db.log_event(ev.get('domain',''),'blocked',ev.get('process',''),'Blocked by hosts file')
        self._diag.on_blocked(ev)
        if not (hasattr(self,'_tray') and self._tray): return
        domain = ev.get('domain','')
        if self._notif.should_notify(f"block:{domain}", severity="low", title="Blocked", message=domain):
            self._tray.showMessage(APP_NAME, f"Blocked: {domain}", QSystemTrayIcon.Warning, 2000)

    # ── Connection Monitor ──
    def _start_conn_monitor(self):
        self._conn_w=ConnWorker(self.db); self._evt_w=EvtWorker()
        self._conn_w.ready.connect(self._on_conns)
        self._conn_w.need_dns.connect(self._dns_w.add); self._conn_w.need_who.connect(self._who_w.add)
        self._conn_w.need_geo.connect(self._geo_w.add)
        self._conn_w.need_signer.connect(self._sign_w.add)
        self._evt_w.ready.connect(self._on_evt_batch); self._evt_w.new_block.connect(self._on_fw_block)
        self._evt_w.need_signer.connect(self._sign_w.add)
        self._conn_w.start(); self._evt_w.start()
        self._conn_monitoring=True; self._update_status("All Monitors Active")
        self._conn_btn.setText("CONNECTIONS: ON")
        self._conn_btn.setStyleSheet(f"background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5b7ee5,stop:1 {C['blue']});color:#fff;padding:4px 16px;border-radius:{_dp(6)}px;font-weight:700;font-size:{_dp(9)}px;border:none;letter-spacing:0.5px;")

    def _stop_conn_monitor(self):
        if self._conn_w: self._conn_w.stop()
        if self._evt_w: self._evt_w.stop()
        self._conn_monitoring=False; self._update_status("DNS Monitor Only")
        self._conn_btn.setText("CONNECTIONS: OFF")
        self._conn_btn.setStyleSheet(f"background:{C['surface0']};color:{C['overlay']};padding:4px 16px;border-radius:{_dp(6)}px;font-weight:700;font-size:{_dp(9)}px;border:none;letter-spacing:0.5px;")

    def _toggle_conn_monitor(self):
        if self._conn_monitoring: self._stop_conn_monitor()
        else: self._start_conn_monitor()

    def _on_conns(self,conns):
        self._conns.update_data(conns)
        # Store to history DB
        live=[c for c in conns if c.ra and c.ra!="*" and c.dir!="Listen"]
        if live: self.conn_db.insert_batch(live)
        for ev in self._quota.check(live, db=self.db):
            self._on_quota_event(ev)
        for ev in self._doh.check(live, db=self.db):
            self._on_doh_event(ev)
        for hit in self._ids.check(live, db=self.db):
            self._on_ids_hit(hit)

    def _on_evt_batch(self,evts):
        if evts:
            self.conn_db.insert_batch(evts)
            try:
                if self._tabs.currentWidget() is self._history: self._history._load()
            except: pass

    def _on_quota_event(self,ev):
        self._update_status(f"Quota blocked {ev.app}" if ev.blocked else f"Quota hit {ev.app}")
        if not (hasattr(self,'_tray') and self._tray): return
        key=f"quota:{ev.period}:{ev.key}"
        title="Bandwidth quota blocked" if ev.blocked else "Bandwidth quota exceeded"
        msg=f"{title}: {ev.app} {_fmt_bytes(ev.used)} / {_fmt_bytes(ev.limit)}"
        if self._notif.should_notify(key, severity="medium", title=title, message=msg):
            self._tray.showMessage(APP_NAME, msg, QSystemTrayIcon.Warning, 4000)

    def _on_doh_event(self,ev):
        self._update_status(f"DoH blocked {ev.endpoint}" if ev.blocked else f"DoH warning {ev.endpoint}")
        if not (hasattr(self,'_tray') and self._tray): return
        key=f"doh:{ev.endpoint}:{ev.app}"
        title="DoH endpoint blocked" if ev.blocked else "DoH endpoint detected"
        msg=f"{title}: {ev.app} -> {ev.endpoint}"
        if self._notif.should_notify(key, severity="medium", title=title, message=msg):
            self._tray.showMessage(APP_NAME, msg, QSystemTrayIcon.Warning, 4000)

    def _on_ids_hit(self,hit):
        self._update_status(f"IDS {hit.get('rule','rule')}")
        if not (hasattr(self,'_tray') and self._tray): return
        key=f"ids:{hit.get('rule')}:{hit.get('endpoint')}:{hit.get('app')}"
        title="IDS rule blocked" if hit.get("blocked") else "IDS rule matched"
        msg=f"{title}: {hit.get('rule')} {hit.get('app')} -> {hit.get('endpoint')}"
        if self._notif.should_notify(key, severity="high", title=title, message=msg):
            self._tray.showMessage(APP_NAME, msg, QSystemTrayIcon.Warning, 4000)

    def _on_fw_block(self,ci):
        self.db.log_event(ci.host if ci.host not in ("-","...") else ci.ra,'fw_blocked',ci.proc,f'FW blocked: {ci.ra}:{ci.rp}')
        if not (hasattr(self,'_tray') and self._tray): return
        key=f"fw:{ci.ra}"
        msg=f"FW Blocked: {ci.proc} \u2192 {ci.ra}"
        if self._notif.should_notify(key, severity="low", title="FW Blocked", message=msg):
            self._tray.showMessage(APP_NAME, msg, QSystemTrayIcon.Warning, 2000)

    def _flush_digest(self):
        items=self._notif.drain_digest()
        if not items or not (hasattr(self,'_tray') and self._tray): return
        summary=f"{len(items)} suppressed alert{'s' if len(items)!=1 else ''}"
        by_type=defaultdict(int)
        for e in items: by_type[e.severity]+=1
        parts=[f"{n} {s}" for s,n in sorted(by_type.items(),key=lambda x:-x[1])]
        self._tray.showMessage(APP_NAME,f"Digest: {summary} ({', '.join(parts)})",QSystemTrayIcon.Information,5000)

    def _update_status(self,msg):
        active=self._monitoring or self._conn_monitoring
        c=C['green'] if active else C['red']
        self._status_dot.setStyleSheet(f"background:{c};border-radius:{_dp(4)}px;border:none;")
        self._status_lbl.setText(msg.upper()[:30]); self._status_lbl.setStyleSheet(f"color:{c};font-size:{_dp(10)}px;font-weight:700;border:none;letter-spacing:0.5px;")

    # ── System Tray ──
    def _build_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable(): self._tray=None; return
        self._tray=QSystemTrayIcon(self)
        px=QPixmap(32,32); px.fill(QColor(C['blue']))
        p=QPainter(px); p.setPen(QColor("#ffffff")); f=QFont("Segoe UI",16,QFont.Bold); p.setFont(f)
        p.drawText(px.rect(),Qt.AlignCenter,"H"); p.end()
        self._tray.setIcon(QIcon(px)); self._tray.setToolTip(f"{APP_NAME} v{APP_VERSION}")
        menu=QMenu()
        menu.addAction("Show").triggered.connect(self.show)
        menu.addAction("Dashboard").triggered.connect(lambda:(self.show(),self._tabs.setCurrentWidget(self._dashboard)))
        menu.addAction("Connections").triggered.connect(lambda:(self.show(),self._tabs.setCurrentWidget(self._conns)))
        menu.addSeparator(); menu.addAction("Quit").triggered.connect(self._real_close)
        self._tray.setContextMenu(menu); self._tray.activated.connect(lambda r:self.show() if r==QSystemTrayIcon.DoubleClick else None)
        self._tray.show()

    def closeEvent(self,event):
        if self._tray: event.ignore(); self.hide(); self._tray.showMessage(APP_NAME,"Running in tray",QSystemTrayIcon.Information,2000)
        else: self._real_close()

    def _real_close(self):
        if self._monitoring and hasattr(self,'_dns_mon'): self._dns_mon.stop()
        if self._conn_w: self._conn_w.stop()
        if self._evt_w: self._evt_w.stop()
        self._dns_w.stop(); self._who_w.stop(); self._geo_w.stop(); self._sign_w.stop(); self._tls_w.stop()
        try: self.conn_db.prune(30)
        except: pass
        QApplication.quit()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    cli_rc = _dispatch_cli(sys.argv[1:])
    if cli_rc is not None:
        sys.exit(cli_rc)

    # Global crash handler for unhandled exceptions in Qt slots
    _orig_hook = sys.excepthook
    def _crash_handler(exc_type, exc_val, exc_tb):
        import traceback
        tb_str=''.join(traceback.format_exception(exc_type, exc_val, exc_tb))
        try:
            crash_path=os.path.join(CONFIG_DIR,"crash.log")
            os.makedirs(CONFIG_DIR,exist_ok=True)
            with open(crash_path,'a') as f: f.write(f"\n{'='*60}\n{datetime.datetime.now()}\nUNHANDLED:\n{tb_str}\n")
        except: pass
        _orig_hook(exc_type, exc_val, exc_tb)
    sys.excepthook = _crash_handler

    # Only hide console if we spawned one (not if running inside an IDE)
    if sys.platform=='win32':
        try:
            import ctypes
            # Check if parent is an IDE (pythonw.exe has no console, IDE manages its own)
            hwnd=ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                # Only hide if we OWN the console (our PID matches console owner)
                pid=ctypes.c_ulong()
                ctypes.windll.user32.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
                if pid.value==os.getpid():
                    ctypes.windll.user32.ShowWindow(hwnd,0)
        except: pass

    try:
        app=QApplication(sys.argv)
        branding_icon = QIcon(str(_branding_icon_path()))
        app.setWindowIcon(branding_icon)
        app.setStyle("Fusion")
        app.setApplicationName(APP_NAME)
        app.setStyleSheet(DARK_STYLE)
        _init_fav_cache()  # Must happen AFTER QApplication exists
        w=MainWindow(); w.show()
        sys.exit(app.exec_())
    except Exception as e:
        # Write crash log
        crash_path=os.path.join(CONFIG_DIR,"crash.log")
        import traceback
        tb=traceback.format_exc()
        try:
            os.makedirs(CONFIG_DIR,exist_ok=True)
            with open(crash_path,'a') as f: f.write(f"\n{'='*60}\n{datetime.datetime.now()}\n{tb}\n")
        except: pass
        # Try to show a message box so the user sees the error
        try:
            from PyQt5.QtWidgets import QMessageBox, QApplication as QApp2
            if not QApp2.instance(): QApp2(sys.argv)
            QMessageBox.critical(None, f"{APP_NAME} - Crash", f"Fatal error:\n\n{e}\n\nDetails written to:\n{crash_path}")
        except: pass
        # Also print to stderr in case IDE captures it
        print(f"PYWALL CRASH: {e}\n{tb}", file=sys.stderr)
        sys.exit(1)

if __name__=="__main__":
    main()
