#!/usr/bin/env python3
import ast
import ipaddress
import json
import os
import pathlib
import re
import tempfile
import unittest


SRC = pathlib.Path(__file__).resolve().parents[1] / "PyWall.py"
README = pathlib.Path(__file__).resolve().parents[1] / "README.md"
TEXT = SRC.read_text(encoding="utf-8")
README_TEXT = README.read_text(encoding="utf-8")
TREE = ast.parse(TEXT)


def load_helpers(*names):
    nodes = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name in names]
    ns = {
        "datetime": __import__("datetime"),
        "ipaddress": ipaddress,
        "json": json,
        "os": os,
        "re": re,
        "sys": __import__("sys"),
        "CONFIG_DIR": tempfile.gettempdir(),
        "_nt_to_dos": lambda path: path,
        "_ps": lambda cmd, timeout=20: (True, cmd),
    }
    ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<helpers>", "exec"), ns)
    return ns


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
        self.assertEqual(versions, ["4.1.19"])

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
        self.assertIn("record_beacon", TEXT)
        self.assertIn("_beacon_hits", TEXT)
        self.assertIn("BEACON", TEXT)
        self.assertIn("T1071 Application Layer Protocol", TEXT)
        self.assertIn("IDSRuleEngine", TEXT)
        self.assertIn("IDS_RULE", TEXT)
        self.assertIn("ids_rules_path", TEXT)
        self.assertIn("ids_rules.yaral", TEXT)
        self.assertIn("ids_match", TEXT)
        self.assertIn("FirewallRuleTableModel", TEXT)
        self.assertIn("QTableView", TEXT)
        self.assertIn("set_rules", TEXT)
        self.assertIn("QAbstractTableModel", TEXT)

    def test_firewall_command_literals_escape_powershell_metacharacters(self):
        ns = load_helpers(
            "_ps_literal", "_fw_enum", "_fw_profile", "_fw_protocol", "_fw_ports",
            "_fw_address", "_fw_program", "_build_new_firewall_rule_cmd",
            "_build_remove_firewall_rule_cmd", "_build_set_firewall_rule_enabled_cmd",
            "_build_rule_exists_cmd",
        )
        cmd = ns["_build_new_firewall_rule_cmd"](
            "PW_Bob's;Rule",
            program=r"C:\Program Files\Bob's App\app.exe",
            remote_addr="203.0.113.7",
            remote_port="443,8443-8444",
            protocol="TCP",
            desc="owner's semicolon; stays literal",
        )
        self.assertIn("-DisplayName 'PW_Bob''s;Rule'", cmd)
        self.assertIn("-Program 'C:\\Program Files\\Bob''s App\\app.exe'", cmd)
        self.assertIn("-RemotePort '443,8443-8444'", cmd)
        self.assertIn("-Description 'owner''s semicolon; stays literal'", cmd)
        self.assertIn("Remove-NetFirewallRule -DisplayName 'PW_Bob''s;Rule'", ns["_build_remove_firewall_rule_cmd"]("PW_Bob's;Rule"))
        self.assertIn("Set-NetFirewallRule -DisplayName 'PW_Bob''s;Rule' -Enabled False", ns["_build_set_firewall_rule_enabled_cmd"]("PW_Bob's;Rule", False))
        self.assertIn("Get-NetFirewallRule -DisplayName 'PW_Bob''s;Rule'", ns["_build_rule_exists_cmd"]("PW_Bob's;Rule"))

    def test_firewall_command_builders_reject_unstructured_values(self):
        ns = load_helpers(
            "_ps_literal", "_fw_enum", "_fw_profile", "_fw_protocol", "_fw_ports",
            "_fw_address", "_fw_program", "_build_new_firewall_rule_cmd",
        )
        with self.assertRaises(ValueError):
            ns["_build_new_firewall_rule_cmd"]("PW_Test", remote_port="80; Remove-Item C:\\")
        with self.assertRaises(ValueError):
            ns["_build_new_firewall_rule_cmd"]("PW_Test", remote_addr="203.0.113.7;Stop")
        with self.assertRaises(ValueError):
            ns["_build_new_firewall_rule_cmd"]("PW_Test", protocol="TCP;Stop")
        with self.assertRaises(ValueError):
            ns["_build_new_firewall_rule_cmd"]("PW_Test\nbad")

    def test_service_ipc_security_hooks_are_wired(self):
        self.assertIn("def _build_ipc_security_descriptor", TEXT)
        self.assertIn("def _build_ipc_security_attributes", TEXT)
        self.assertIn("def _secure_ipc_token_file", TEXT)
        self.assertIn("_secure_ipc_token_file(IPC_TOKEN_PATH)", TEXT)
        self.assertIn("_build_ipc_security_attributes())", TEXT)
        self.assertIn("DACL_SECURITY_INFORMATION", TEXT)

    def test_firewall_reset_exports_rollback_before_reset(self):
        reset_idx = TEXT.index("def _fw_reset")
        reset_block = TEXT[reset_idx:TEXT.index("def _fw_export", reset_idx)]
        self.assertIn("_timestamped_fw_export_path()", reset_block)
        self.assertLess(reset_block.index("_export_firewall_config(backup)"), reset_block.index('netsh advfirewall reset'))
        self.assertIn("Reset aborted", reset_block)
        self.assertIn("rollback saved", reset_block)
        self.assertIn("def _fw_restore", TEXT)

    def test_readme_does_not_advertise_missing_components(self):
        stale_claims = (
            "PluginManager",
            "RuleScheduler",
            "NetworkProfileManager",
            "AnomalyDetector",
            "ReputationScorer",
            "Network Map",
            "Block All Unknown",
            "VirusTotal hash lookups",
            "Digital signature verification",
            "Full config export/import with diff preview",
        )
        for claim in stale_claims:
            self.assertNotIn(claim, README_TEXT)

    def test_runtime_dependencies_are_pinned_and_not_auto_installed(self):
        requirements = (pathlib.Path(__file__).resolve().parents[1] / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("psutil==7.2.2", requirements)
        self.assertIn("PyQt5==5.15.11", requirements)
        self.assertIn("maxminddb==3.1.1", requirements)
        self.assertIn('pywin32==312; sys_platform == "win32"', requirements)
        self.assertNotIn("requests", requirements)
        self.assertNotIn("pip', 'install", TEXT)
        self.assertNotIn('"pip", "install"', TEXT)
        self.assertIn("pip install -r requirements.txt", TEXT)
        self.assertIn("_check_dependencies()", TEXT)
        bootstrap = TEXT[TEXT.index("def _bootstrap"):TEXT.index("\n_bootstrap()", TEXT.index("def _bootstrap"))]
        self.assertLess(bootstrap.index("_check_dependencies()"), bootstrap.index("IsUserAnAdmin"))

    def test_missing_dependency_message_points_to_local_requirements(self):
        ns = load_helpers("_missing_dependency_message")
        msg = ns["_missing_dependency_message"](["PyQt5", "psutil"])
        self.assertIn("Missing required runtime dependencies: PyQt5, psutil", msg)
        self.assertIn("-m pip install -r requirements.txt", msg)

    def test_connection_identity_enrichment_is_wired(self):
        for token in (
            "svc:str",
            "parent:str",
            "package:str",
            "signer:str",
            "signer_c=LRU",
            "class SignerWorker",
            "Get-AuthenticodeSignature",
            "need_signer=pyqtSignal(str)",
            "_service_names_for_pid",
            "_package_identity_from_path",
            "_parent_identity_from_process",
            "_cached_signer_label",
            "identity_fields",
            "signers {signer.get('cached',0)}/{signer.get('queued',0)}",
        ):
            self.assertIn(token, TEXT)
        self.assertIn("self._conn_w.need_signer.connect(self._sign_w.add)", TEXT)
        self.assertIn("self._evt_w.need_signer.connect(self._sign_w.add)", TEXT)

    def test_connection_identity_fields_are_persisted_and_displayed(self):
        for token in (
            "svc TEXT DEFAULT '-'",
            "parent TEXT DEFAULT '-'",
            "package TEXT DEFAULT '-'",
            "signer TEXT DEFAULT '-'",
            "svc,parent,package,signer",
            "OR svc LIKE ? OR parent LIKE ? OR package LIKE ? OR signer LIKE ?",
            '"Service","Parent","Package","Signer"',
            "ci.svc,ci.parent,ci.package,ci.signer",
        ):
            self.assertIn(token, TEXT)

    def test_identity_helper_outputs_are_stable(self):
        ns = load_helpers("_package_identity_from_path", "_cert_common_name", "_signer_label_from_json")
        self.assertEqual(
            ns["_package_identity_from_path"](r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2502.2.0_x64__8wekyb3d8bbwe\Calculator.exe"),
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
        )
        self.assertEqual(
            ns["_package_identity_from_path"](r"C:\Users\me\AppData\Local\Packages\Microsoft.WindowsCalculator_8wekyb3d8bbwe\LocalState"),
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
        )
        self.assertEqual(ns["_cert_common_name"]("O=Example, CN=Example Publisher, C=US"), "Example Publisher")
        self.assertEqual(
            ns["_signer_label_from_json"]('{"Status":"Valid","Subject":"CN=Microsoft Windows, O=Microsoft Corporation"}'),
            "Valid: Microsoft Windows",
        )

    def test_geoip_uses_https_or_local_database(self):
        for token in (
            'GEOIP_HTTPS_ENDPOINT = "https://ipwho.is/{ip}"',
            "geoip_provider",
            "geoip_mmdb_path",
            "geoip_https_endpoint",
            "maxminddb.open_database",
            "not endpoint.lower().startswith(\"https://\")",
            "geoip {geo.get('provider','ipwhois')}",
            '"geoip": self._geo_w.snapshot()',
        ):
            self.assertIn(token, TEXT)
        self.assertNotIn("http://ip-api.com", TEXT)
        self.assertNotIn("ip-api.com/batch", TEXT)

    def test_stale_branding_markers_removed(self):
        self.assertNotIn("c" + "odex-branding", TEXT.lower())


if __name__ == "__main__":
    unittest.main()
