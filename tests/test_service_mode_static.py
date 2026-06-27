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
        self.assertIn("run_headless_service", funcs)
        self.assertIn("_dispatch_cli", funcs)
        self.assertIn("_build_cli_parser", funcs)

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
        self.assertEqual(versions, ["4.1.1"])

    def test_service_cli_actions_are_declared(self):
        for action in ("install", "remove", "start", "stop", "restart", "status", "run"):
            self.assertIn(f'"{action}"', TEXT)
        self.assertIn("service-run", TEXT)
        self.assertIn("--no-auto-block", TEXT)

    def test_stale_branding_markers_removed(self):
        self.assertNotIn("c" + "odex-branding", TEXT.lower())


if __name__ == "__main__":
    unittest.main()
