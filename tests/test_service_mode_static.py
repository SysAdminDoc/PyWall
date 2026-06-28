#!/usr/bin/env python3
import ast
import pathlib
import unittest


SRC = pathlib.Path(__file__).resolve().parents[1] / "PyWall.py"
TEXT = SRC.read_text(encoding="utf-8")
TREE = ast.parse(TEXT)


class ServiceModeStaticTests(unittest.TestCase):
    def test_service_symbols_exist(self):
        classes = {node.name for node in TREE.body if isinstance(node, ast.ClassDef)}
        funcs = {node.name for node in TREE.body if isinstance(node, ast.FunctionDef)}
        self.assertIn("HeadlessMonitor", classes)
        self.assertIn("ServiceIPCServer", classes)
        self.assertIn("run_headless_service", funcs)
        self.assertIn("_dispatch_cli", funcs)
        self.assertIn("_build_cli_parser", funcs)
        self.assertIn("_service_ipc_request", funcs)

    def test_version_is_current_delivery(self):
        versions = [
            node.value.value
            for node in TREE.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
            and target.id == "APP_VERSION"
            and isinstance(node.value, ast.Constant)
        ]
        self.assertEqual(versions, ["4.1.11"])

    def test_service_cli_actions_are_declared(self):
        for action in ("install", "remove", "start", "stop", "restart", "status", "run"):
            self.assertIn(f'"{action}"', TEXT)
        self.assertIn("service-run", TEXT)
        self.assertIn("--no-auto-block", TEXT)
        self.assertIn("IPC_PIPE_NAME", TEXT)
        self.assertIn("Refresh Service Status", TEXT)
        self.assertIn("_reload_config_if_changed", TEXT)
        self.assertIn("service_auto_block", TEXT)
        self.assertIn("service_poll_seconds", TEXT)
        self.assertIn("SERVICE_STATE_PATH", TEXT)
        self.assertIn("_load_service_state", TEXT)
        self.assertIn("_save_service_state", TEXT)
        self.assertIn("clean_shutdown", TEXT)
        self.assertIn("bytes_sent", TEXT)
        self.assertIn("bytes_recv", TEXT)
        self.assertIn("_proc_io", TEXT)
        self.assertIn("connection_sessions", TEXT)
        self.assertIn("search_sessions", TEXT)
        self.assertIn("_fmt_duration", TEXT)
        self.assertIn("BandwidthQuotaEnforcer", TEXT)
        self.assertIn("bandwidth_quotas", TEXT)
        self.assertIn("QUOTA_STATE_PATH", TEXT)
        self.assertIn("_parse_bytes_limit", TEXT)
        self.assertIn("REPORT_DIR", TEXT)
        self.assertIn("usage_report", TEXT)
        self.assertIn("export_usage_reports", TEXT)
        self.assertIn("Export Usage Reports", TEXT)
        self.assertIn('"report"', TEXT)
        self.assertIn("MITRE_MAPPINGS", TEXT)
        self.assertIn("mitre_tactic", TEXT)
        self.assertIn("mitre_technique", TEXT)
        self.assertIn("T1046 Network Service Discovery", TEXT)
        self.assertIn("T1110 Brute Force", TEXT)
        self.assertIn("TLSLogWorker", TEXT)
        self.assertIn("tls_sni_enabled", TEXT)
        self.assertIn("tls_sni_log_path", TEXT)
        self.assertIn("tls_sni_read_existing", TEXT)
        self.assertIn("tls_sni", TEXT)
        self.assertIn("DoHDetector", TEXT)
        self.assertIn("detect_doh_endpoint", TEXT)
        self.assertIn("doh_action", TEXT)
        self.assertIn("DOH:WARN", TEXT)
        self.assertIn("dns.google", TEXT)

    def test_stale_branding_markers_removed(self):
        self.assertNotIn("c" + "odex-branding", TEXT.lower())


if __name__ == "__main__":
    unittest.main()
