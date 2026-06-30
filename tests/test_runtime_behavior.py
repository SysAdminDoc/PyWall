#!/usr/bin/env python3
import ast
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace


SRC = pathlib.Path(__file__).resolve().parents[1] / "PyWall.py"
TREE = ast.parse(SRC.read_text(encoding="utf-8"))


BASE_NAMES = {
    "CI",
    "LearningReviewGroup",
    "LearningReviewCollector",
    "FWRule",
    "FirewallTamperEvent",
    "ThreatEvent",
    "IDSRule",
    "MITRE_MAPPINGS",
    "_mitre_for_event",
    "_is_managed_rule_name",
    "_ps_literal",
    "_fw_enum",
    "_fw_profile",
    "_fw_protocol",
    "_fw_ports",
    "_fw_address",
    "_fw_program",
    "_build_new_firewall_rule_cmd",
    "_build_remove_firewall_rule_cmd",
    "_build_set_firewall_rule_enabled_cmd",
    "_build_rule_exists_cmd",
    "_firewall_tamper_log",
    "_fw_rule_diff",
    "_fw_rule_snapshot",
    "CONFIG_SCHEMA_VERSION",
    "GEOIP_HTTPS_ENDPOINT",
    "PLUGIN_ALLOWED_HOOKS",
    "PLUGIN_ALLOWED_PERMISSION_KEYS",
    "PLUGIN_ID_RE",
    "PLUGIN_LOG_PATH",
    "PLUGIN_MANIFEST_NAMES",
    "FW_TAMPER_LOG_PATH",
    "DOMAIN_RE",
    "IPV4_RE",
    "WILDCARD_RE",
    "MULTI_TLDS",
    "CONFIG_DEFAULTS",
    "ConfigLoadResult",
    "PluginManifest",
    "PluginScanResult",
    "looks_like_domain",
    "get_root_domain",
    "normalize_line",
    "_feed_cache_path",
    "_parse_import_text",
    "_coerce_config_value",
    "_validate_runtime_config",
    "_write_json_atomic",
    "_config_backup_path",
    "_plugin_log",
    "_safe_plugin_id",
    "load_runtime_config",
}

class FakeSignal:
    def __init__(self, *args, **kwargs):
        self.events = []

    def emit(self, *args):
        self.events.append(args)

    def connect(self, callback):
        self.callback = callback

class FakeQThread:
    def __init__(self, *args, **kwargs):
        pass

    def isRunning(self):
        return False

    def start(self):
        self.run()

    def wait(self, timeout=0):
        return True


def load_runtime(*names):
    wanted = set(names) | BASE_NAMES
    nodes = []
    for node in TREE.body:
        node_name = None
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            node_name = node.name
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    node_name = target.id
                    break
        if node_name in wanted:
            nodes.append(node)
    ns = {
        "argparse": __import__("argparse"),
        "csv": __import__("csv"),
        "datetime": datetime,
        "defaultdict": defaultdict,
        "dataclass": dataclass,
        "field": __import__("dataclasses").field,
        "fnmatch": __import__("fnmatch"),
        "hmac": hmac,
        "html": __import__("html"),
        "hashlib": hashlib,
        "ipaddress": ipaddress,
        "io": __import__("io"),
        "json": json,
        "log": SimpleNamespace(warning=lambda *a, **k: None),
        "Lock": threading.Lock,
        "os": os,
        "Path": Path,
        "psutil": SimpleNamespace(Process=lambda pid: SimpleNamespace(terminate=lambda: True)),
        "re": re,
        "secrets": __import__("secrets"),
        "shutil": shutil,
        "signal": __import__("signal"),
        "socket": __import__("socket"),
        "sqlite3": sqlite3,
        "subprocess": subprocess,
        "sys": sys,
        "tempfile": tempfile,
        "threading": threading,
        "time": time,
        "TEvent": threading.Event,
        "urllib": __import__("urllib.request"),
        "webbrowser": __import__("webbrowser"),
        "QObject": object,
        "QTimer": object,
        "QThread": FakeQThread,
        "pyqtSignal": lambda *args, **kwargs: FakeSignal(),
        "APP_NAME": "PyWall",
        "APP_VERSION": "4.1.24",
        "BLOCK_IPS": {"0.0.0.0", "127.0.0.1", "::0", "::1"},
        "CONFIG_DIR": tempfile.gettempdir(),
        "CONFIG_PATH": os.path.join(tempfile.gettempdir(), "pywall-test-config.json"),
        "CONN_DB_PATH": os.path.join(tempfile.gettempdir(), "pywall-test-connections.db"),
        "DB_PATH": os.path.join(tempfile.gettempdir(), "pywall-test.db"),
        "FEED_CACHE_DIR": os.path.join(tempfile.gettempdir(), "pywall-feed-cache"),
        "PLUGINS_DIR": os.path.join(tempfile.gettempdir(), "pywall-plugins"),
        "PLUGIN_LOG_PATH": os.path.join(tempfile.gettempdir(), "plugin_events.log"),
        "FW_TAMPER_LOG_PATH": os.path.join(tempfile.gettempdir(), "firewall_tamper.log"),
        "FW_PFX": "PW_",
        "LEGACY_FW_PFX": ("HG_",),
        "FW_RULE_PREFIXES": ("PW_", "HG_"),
        "HOSTS_PATH": os.path.join(tempfile.gettempdir(), "hosts"),
        "IDS_RULES_PATH": os.path.join(tempfile.gettempdir(), "ids_rules.yaral"),
        "IPC_PIPE_NAME": r"\\.\pipe\PyWallService",
        "IPC_TOKEN_PATH": os.path.join(tempfile.gettempdir(), "service.token"),
        "GEOIP_HTTPS_ENDPOINT": "https://ipwho.is/{ip}",
        "NOWIN": 0,
        "PRIV_RE": re.compile(r"^(0\.0\.0\.0|127\.|::1$|::$|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|fe80:|fd)"),
        "SERVICE_NAME": "PyWallService",
        "SERVICE_STATE_PATH": os.path.join(tempfile.gettempdir(), "service_state.json"),
        "WINDOWS_HEADER": ["# hosts"],
        "_fmt_bytes": lambda n: f"{int(n or 0)} B",
        "_nt_to_dos": lambda p: p,
        "_parse_bytes_limit": lambda v: int(v),
        "_service_log": lambda *a, **k: None,
        "_ps": lambda cmd, t=20: (True, cmd),
        "win32file": None,
        "win32pipe": None,
        "win32service": None,
        "win32serviceutil": None,
        "pywintypes": None,
    }
    module = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, "<runtime-under-test>", "exec"), ns)
    return ns


class RuntimeBehaviorTests(unittest.TestCase):
    def test_firewall_engine_uses_mocked_powershell_and_rejects_bad_values(self):
        ns = load_runtime("FirewallEngine")
        calls = []

        def fake_ps(cmd, timeout=20):
            calls.append((cmd, timeout))
            return True, "ok"

        ns["_ps"] = fake_ps
        engine = ns["FirewallEngine"]()

        ok, out = engine.create_rule(
            "PW_Runtime",
            direction="Outbound",
            action="Block",
            remote_addr="203.0.113.10",
            remote_port="443",
            protocol="TCP",
            desc="unit test",
        )
        self.assertTrue(ok)
        self.assertEqual(out, "ok")
        self.assertIn("PW_Runtime", engine._known_names)
        self.assertIn("New-NetFirewallRule", calls[-1][0])
        self.assertIn("-RemoteAddress '203.0.113.10'", calls[-1][0])

        ok, err = engine.create_rule("PW_Bad", remote_port="443; Remove-Item C:\\")
        self.assertFalse(ok)
        self.assertIn("Invalid remote port", err)

        self.assertTrue(engine.enable_rule("PW_Runtime", enabled=False))
        self.assertIn("Set-NetFirewallRule -DisplayName 'PW_Runtime' -Enabled False", calls[-1][0])
        ok, _ = engine.delete_rule("PW_Runtime")
        self.assertTrue(ok)
        self.assertNotIn("PW_Runtime", engine._known_names)

    def test_firewall_engine_detects_external_tamper_and_suppresses_local_changes(self):
        ns = load_runtime("FirewallEngine")
        with tempfile.TemporaryDirectory() as td:
            ns["FW_TAMPER_LOG_PATH"] = os.path.join(td, "firewall_tamper.log")
            engine = ns["FirewallEngine"]()
            original = ns["FWRule"](
                name="PW_TestRule",
                direction="Outbound",
                action="Block",
                enabled=True,
                remote_addr="203.0.113.8",
                remote_port="443",
                protocol="TCP",
                source="pywall",
            )
            engine._detect_tamper([original])
            self.assertEqual(engine.tamper_summary()["pending"], 0)

            disabled = ns["FWRule"](
                name="PW_TestRule",
                direction="Outbound",
                action="Block",
                enabled=False,
                remote_addr="203.0.113.8",
                remote_port="443",
                protocol="TCP",
                source="pywall",
            )
            events = engine._detect_tamper([disabled])
            self.assertEqual(events[-1].change, "disabled")
            self.assertEqual(engine.tamper_summary()["pending"], 1)
            self.assertIn("enabled: True -> False", events[-1].details)
            self.assertIn("PW_TestRule", pathlib.Path(ns["FW_TAMPER_LOG_PATH"]).read_text(encoding="utf-8"))

            engine._fetch_all = lambda: [disabled]
            ok, msg = engine.accept_current_rules()
            self.assertTrue(ok)
            self.assertIn("Accepted", msg)
            self.assertEqual(engine.tamper_summary()["pending"], 0)

            engine._detect_tamper([disabled])
            engine._mark_local_change("PW_TestRule")
            engine._detect_tamper([original])
            self.assertEqual(engine.tamper_summary()["pending"], 0)

    def test_learning_review_collector_groups_unknown_outbound_apps(self):
        ns = load_runtime("LearningReviewCollector")
        collector = ns["LearningReviewCollector"](enabled=True, window_seconds=60, started=100.0)
        ci1 = ns["CI"](
            dir="Out",
            ra="198.51.100.50",
            rp="443",
            host="api.example.test",
            proc="app.exe",
            path=r"C:\Apps\App\app.exe",
            signer="Valid: Example Publisher",
            parent="explorer.exe (100)",
            stat="-",
        )
        ci2 = ns["CI"](
            dir="Out",
            ra="198.51.100.51",
            rp="443",
            host="cdn.example.test",
            proc="app.exe",
            path=r"C:\Apps\App\app.exe",
            signer="Valid: Example Publisher",
            parent="explorer.exe (100)",
            stat="-",
        )
        blocked = ns["CI"](dir="Out", ra="203.0.113.2", proc="bad.exe", stat="FW:BLOCKED")
        local = ns["CI"](dir="Out", ra="192.168.1.10", proc="lan.exe", stat="-")

        self.assertEqual(collector.observe([ci1, ci2, blocked, local], now=110.0), 1)
        groups = collector.groups()
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["count"], 2)
        self.assertEqual(groups[0]["signer"], "Valid: Example Publisher")
        self.assertEqual(groups[0]["ips"], ["198.51.100.50", "198.51.100.51"])
        self.assertFalse(collector.active(now=200.0))
        self.assertEqual(collector.observe([ns["CI"](dir="Out", ra="198.51.100.52", proc="late.exe")], now=200.0), 0)
        removed = collector.remove(groups[0]["key"])
        self.assertEqual(removed.proc, "app.exe")

    def test_conn_db_migrates_identity_columns_and_searches_sessions(self):
        ns = load_runtime("ConnDB")
        with tempfile.TemporaryDirectory() as td:
            db_path = os.path.join(td, "connections.db")
            con = sqlite3.connect(db_path)
            con.execute("CREATE TABLE connections (id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,src TEXT,dir TEXT,proto TEXT,la TEXT,lp TEXT,ra TEXT,rp TEXT,host TEXT,proc TEXT,pid INTEGER,state TEXT,org TEXT,stat TEXT,country TEXT,cc TEXT,category TEXT,bytes_sent INTEGER DEFAULT 0,bytes_recv INTEGER DEFAULT 0)")
            con.execute("CREATE TABLE connection_sessions (key TEXT PRIMARY KEY,first_seen TEXT,last_seen TEXT,src TEXT,dir TEXT,proto TEXT,la TEXT,lp TEXT,ra TEXT,rp TEXT,host TEXT,proc TEXT,pid INTEGER,state TEXT,org TEXT,stat TEXT,country TEXT,cc TEXT,category TEXT,bytes_sent INTEGER DEFAULT 0,bytes_recv INTEGER DEFAULT 0,samples INTEGER DEFAULT 0,active INTEGER DEFAULT 1)")
            con.commit()
            con.close()

            ns["CONN_DB_PATH"] = db_path
            db = ns["ConnDB"]()
            cols = {r[1] for r in db._conn.execute("PRAGMA table_info(connections)").fetchall()}
            sess_cols = {r[1] for r in db._conn.execute("PRAGMA table_info(connection_sessions)").fetchall()}
            for column in ("svc", "parent", "package", "signer", "bytes_sent", "bytes_recv"):
                self.assertIn(column, cols)
                self.assertIn(column, sess_cols)

            ci = ns["CI"](
                key="k1",
                ts="12:00:00",
                src="Live",
                dir="Out",
                proto="TCP",
                la="127.0.0.1",
                lp="50000",
                ra="198.51.100.20",
                rp="443",
                host="example.net",
                proc="svchost.exe",
                pid=42,
                svc="Dnscache",
                parent="services.exe (888)",
                package="-",
                signer="Valid: Microsoft Windows",
                state="ESTABLISHED",
                org="Example Org",
                stat="-",
                country="Exampleland",
                cc="EX",
                category="Web",
                bytes_sent=120,
                bytes_recv=240,
            )
            db.insert_batch([ci])
            self.assertEqual(db.search("Dnscache")[0][11], "Dnscache")
            session = db.search_sessions("Microsoft Windows")[0]
            self.assertEqual(session[12], "Dnscache")
            self.assertEqual(session[17], 120)
            self.assertEqual(session[18], 240)
            db._conn.close()

    def test_threat_detector_thresholds_emit_mitre_events(self):
        ns = load_runtime("ThreatDetector")
        detector = ns["ThreatDetector"]()

        for port in range(15):
            detector.record("198.51.100.30", str(1000 + port), blocked=False)
        events = detector.get_events()
        self.assertEqual(events[-1].type, "PORT_SCAN")
        self.assertEqual(events[-1].severity, "high")
        self.assertEqual(events[-1].mitre_technique, "T1046 Network Service Discovery")

        for _ in range(10):
            detector.record("198.51.100.31", "3389", blocked=True)
        events = detector.get_events()
        self.assertEqual(events[-1].type, "BRUTE_FORCE")
        self.assertEqual(events[-1].mitre_technique, "T1110 Brute Force")
        self.assertEqual(detector.get_stats()["high"], 2)

    def test_hosts_manager_comments_restores_and_removes_entries(self):
        ns = load_runtime("HostsFileManager")
        ns["HostsFileManager"]._flush = lambda self: None
        with tempfile.TemporaryDirectory() as td:
            hosts = os.path.join(td, "hosts")
            ns["HOSTS_PATH"] = hosts
            ns["CONFIG_DIR"] = td
            with open(hosts, "w", encoding="utf-8") as f:
                f.write("0.0.0.0 Example.COM\n# WHITELISTED: 0.0.0.0 white.test\n")

            hm = ns["HostsFileManager"]()
            hm.read()
            self.assertIn("example.com", hm.get_blocked())

            hm.remove_block("example.com")
            text = pathlib.Path(hosts).read_text(encoding="utf-8")
            self.assertIn("# WHITELISTED: 0.0.0.0 Example.COM", text)

            hm.restore_block("white.test")
            text = pathlib.Path(hosts).read_text(encoding="utf-8")
            self.assertIn("0.0.0.0 white.test", text)

            hm.remove_entry("white.test")
            text = pathlib.Path(hosts).read_text(encoding="utf-8")
            self.assertNotIn("white.test", text.lower())

    def test_service_ipc_request_uses_mocked_pywin32_pipe(self):
        ns = load_runtime("_service_ipc_request")
        captured = {}

        class FakePipe:
            request = b""

        class FakeWin32File:
            GENERIC_READ = 1
            GENERIC_WRITE = 2
            OPEN_EXISTING = 3

            @staticmethod
            def CreateFile(*args):
                captured["create_args"] = args
                return FakePipe()

            @staticmethod
            def WriteFile(handle, payload):
                handle.request = payload

            @staticmethod
            def ReadFile(handle, size):
                request = json.loads(handle.request.decode("utf-8"))
                captured["request"] = request
                return 0, json.dumps({"ok": True, "command": request["command"]}).encode("utf-8") + b"\n"

            @staticmethod
            def CloseHandle(handle):
                captured["closed"] = True

        class FakeWin32Pipe:
            PIPE_READMODE_MESSAGE = 4

            @staticmethod
            def SetNamedPipeHandleState(*args):
                captured["pipe_mode"] = args

        class FakeError(Exception):
            winerror = 2

        ns["win32file"] = FakeWin32File
        ns["win32pipe"] = FakeWin32Pipe
        ns["pywintypes"] = SimpleNamespace(error=FakeError)
        ns["_get_ipc_token"] = lambda create=False: "token-123"

        resp = ns["_service_ipc_request"]("status", timeout=0.2)
        self.assertEqual(resp, {"ok": True, "command": "status"})
        self.assertEqual(captured["request"]["token"], "token-123")
        self.assertTrue(captured["closed"])

    def test_service_ipc_server_rejects_bad_tokens_and_returns_status(self):
        ns = load_runtime("ServiceIPCServer")
        monitor = SimpleNamespace(snapshot=lambda: {"version": "test"})
        server = ns["ServiceIPCServer"](monitor)
        server._token = "secret"

        self.assertFalse(server._handle(b"not-json")["ok"])
        self.assertEqual(server._handle(json.dumps({"token": "bad"}).encode())["error"], "Unauthorized")
        self.assertTrue(server._handle(json.dumps({"token": "secret", "command": "ping"}).encode())["pong"])
        status = server._handle(json.dumps({"token": "secret", "command": "status"}).encode())
        self.assertEqual(status["status"]["version"], "test")

    def test_headless_service_config_reload_updates_all_runtime_workers(self):
        ns = load_runtime("HeadlessMonitor")

        class FakeConfigurable:
            def __init__(self, snap):
                self.snap = snap
                self.calls = []

            def load_config(self, cfg, mtime=None):
                self.calls.append(("load", cfg, mtime))

            def configure(self, cfg, mtime=None):
                self.calls.append(("configure", cfg, mtime))

            def snapshot(self):
                return dict(self.snap)

        class FakeTimer:
            def __init__(self):
                self.interval = None

            def isActive(self):
                return True

            def setInterval(self, value):
                self.interval = value

        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.json")
            cfg = {
                "service_auto_block": False,
                "service_poll_seconds": 5,
                "bandwidth_quotas": {"app.exe": {"limit": "1 MB"}},
                "doh_action": "warn",
                "ids_rules_enabled": False,
                "geoip_provider": "maxmind",
                "tls_sni_enabled": True,
            }
            pathlib.Path(cfg_path).write_text(json.dumps(cfg), encoding="utf-8")
            ns["CONFIG_PATH"] = cfg_path
            ns["load_runtime_config"].__defaults__ = (cfg_path, True)
            monitor = ns["HeadlessMonitor"].__new__(ns["HeadlessMonitor"])
            monitor.auto_block = True
            monitor.poll_seconds = 2.0
            monitor._timer = FakeTimer()
            monitor._config_mtime = None
            monitor._last_config_reload = ""
            monitor._quota = FakeConfigurable({"configured": 1})
            monitor._doh = FakeConfigurable({"action": "warn"})
            monitor._ids = FakeConfigurable({"rules": 0})
            monitor._geo_w = FakeConfigurable({"provider": "maxmind"})
            monitor._tls_w = FakeConfigurable({"enabled": True})

            monitor._reload_config_if_changed(force=True)

            self.assertFalse(monitor.auto_block)
            self.assertEqual(monitor.poll_seconds, 5.0)
            self.assertEqual(monitor._timer.interval, 5000)
            self.assertTrue(monitor._last_config_reload)
            self.assertEqual(monitor._quota.calls[-1][0], "load")
            for worker in (monitor._doh, monitor._ids, monitor._geo_w, monitor._tls_w):
                self.assertEqual(worker.calls[-1][0], "configure")
                self.assertEqual(worker.calls[-1][1]["geoip_provider"], "maxmind")

    def test_runtime_config_recovers_corrupt_files_and_reports_invalid_fields(self):
        ns = load_runtime("load_runtime_config")
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.json")
            pathlib.Path(cfg_path).write_text("{not-json", encoding="utf-8")
            result = ns["load_runtime_config"](cfg_path)

            self.assertTrue(result.recovered)
            self.assertTrue(os.path.exists(result.backup_path))
            recovered = json.loads(pathlib.Path(cfg_path).read_text(encoding="utf-8"))
            self.assertEqual(recovered["schema_version"], ns["CONFIG_SCHEMA_VERSION"])
            self.assertEqual(recovered["geoip_provider"], "ipwhois")

            pathlib.Path(cfg_path).write_text(json.dumps({
                "schema_version": "bad",
                "doh_action": "explode",
                "geoip_https_endpoint": "http://plain.example/{ip}",
                "service_poll_seconds": 0,
                "unknown_future_key": 42,
            }), encoding="utf-8")
            result = ns["load_runtime_config"](cfg_path)

            self.assertFalse(result.recovered)
            self.assertGreaterEqual(len(result.warnings), 3)
            self.assertEqual(result.data["schema_version"], ns["CONFIG_SCHEMA_VERSION"])
            self.assertEqual(result.data["doh_action"], "warn")
            self.assertEqual(result.data["geoip_https_endpoint"], "https://ipwho.is/{ip}")
            self.assertEqual(result.data["service_poll_seconds"], 1.0)
            self.assertEqual(result.data["unknown_future_key"], 42)

    def test_plugin_registry_validates_manifests_and_blocks_execution_by_default(self):
        ns = load_runtime("PluginRegistry")
        with tempfile.TemporaryDirectory() as td:
            plugin_dir = os.path.join(td, "plugins")
            log_path = os.path.join(td, "plugin_events.log")
            ns["PLUGIN_LOG_PATH"] = log_path
            good_dir = pathlib.Path(plugin_dir) / "notifier"
            bad_dir = pathlib.Path(plugin_dir) / "bad"
            good_dir.mkdir(parents=True)
            bad_dir.mkdir(parents=True)
            good_manifest = {
                "id": "Notifier.One",
                "name": "Unit Notifier",
                "version": "1.0.0",
                "enabled": True,
                "hooks": ["notification"],
                "permissions": {"network": ["https://ntfy.sh"], "files": [], "notifications": True},
                "trust": {"publisher": "Unit Publisher"},
            }
            bad_manifest = {
                "id": "bad",
                "name": "Bad Plugin",
                "version": "1.0.0",
                "enabled": True,
                "hooks": ["shell_escape"],
                "permissions": {"network": "all"},
            }
            (good_dir / "pywall-plugin.json").write_text(json.dumps(good_manifest), encoding="utf-8")
            (bad_dir / "plugin.json").write_text(json.dumps(bad_manifest), encoding="utf-8")

            cfg = dict(ns["CONFIG_DEFAULTS"])
            cfg["plugins_enabled"] = False
            cfg["plugin_enabled_ids"] = ["notifier.one"]
            registry = ns["PluginRegistry"](plugin_dir, cfg)
            result = registry.scan()

            summary = result.summary()
            self.assertEqual(summary["total"], 2)
            self.assertEqual(summary["invalid"], 1)
            good = next(p for p in result.plugins if p.plugin_id == "notifier.one")
            self.assertFalse(good.executable)
            self.assertEqual(good.disabled_reason, "plugins disabled in config")
            self.assertEqual(good.trust_state, "unsigned")
            self.assertFalse(registry.can_execute("notifier.one", "notification"))
            self.assertIn("unsupported hook", pathlib.Path(log_path).read_text(encoding="utf-8"))

            cfg["plugins_enabled"] = True
            registry = ns["PluginRegistry"](plugin_dir, cfg)
            self.assertTrue(registry.can_execute("Notifier.One", "notification"))
            self.assertFalse(registry.can_execute("Notifier.One", "feed_import"))

            cfg["plugin_disabled_ids"] = ["notifier.one"]
            registry = ns["PluginRegistry"](plugin_dir, cfg)
            self.assertFalse(registry.can_execute("Notifier.One", "notification"))

    def test_import_worker_records_feed_provenance_and_uses_last_good_cache(self):
        ns = load_runtime("HostsDB", "ImportWorker")

        class Capture:
            def __init__(self):
                self.events = []

            def emit(self, *args):
                self.events.append(args)

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return self.payload

        with tempfile.TemporaryDirectory() as td:
            ns["DB_PATH"] = os.path.join(td, "pywall.db")
            ns["FEED_CACHE_DIR"] = os.path.join(td, "feed_cache")
            db = ns["HostsDB"]()
            payload = b"0.0.0.0 ads.example\ntracker.example\n# comment\n"
            urlopen_orig = ns["urllib"].request.urlopen
            try:
                ns["urllib"].request.urlopen = lambda req, timeout=20: FakeResponse(payload)
                worker = ns["ImportWorker"]([("Unit Feed", "https://example.test/feed.txt")], True, db)
                worker.finished = Capture()
                worker.log_msg = Capture()
                worker.run()

                expected = ["0.0.0.0 ads.example", "0.0.0.0 tracker.example"]
                self.assertEqual(worker.finished.events[-1][0], expected)
                source = db.feed_source_get("Unit Feed")
                self.assertEqual(source["status"], "ok")
                self.assertEqual(source["item_count"], 2)
                self.assertEqual(source["sha256"], __import__("hashlib").sha256(payload).hexdigest())
                self.assertTrue(os.path.exists(source["last_good_cache_path"]))

                def fail_urlopen(req, timeout=20):
                    raise OSError("offline")

                ns["urllib"].request.urlopen = fail_urlopen
                retry = ns["ImportWorker"]([("Unit Feed", "https://example.test/feed.txt")], True, db)
                retry.finished = Capture()
                retry.log_msg = Capture()
                retry.run()

                self.assertEqual(retry.finished.events[-1][0], expected)
                failed = db.feed_source_get("Unit Feed")
                self.assertEqual(failed["status"], "failed")
                self.assertIn("offline", failed["failure_reason"])
                self.assertIn("using cached feed", retry.log_msg.events[-1][0])
            finally:
                ns["urllib"].request.urlopen = urlopen_orig
                try: db.conn.close()
                except: pass


if __name__ == "__main__":
    unittest.main()
