# Changelog

All notable changes to PyWall will be documented in this file.

## [v4.1.17] - 2026-06-30

- Added: Live and history connection rows now include svchost service names, parent process, UWP/package identity, and signer trust.
- Added: Authenticode signer lookups run on a background worker so connection polling does not block on signature checks.
- Changed: Connection history/session storage now migrates and searches app identity fields.

## [v4.1.16] - 2026-06-30

- Changed: Runtime dependencies are pinned in `requirements.txt` and startup now exits with a clear setup command instead of installing packages from an elevated process.
- Removed: Unused `requests` dependency.

## [v4.1.15] - 2026-06-30

- Added: Firewall reset now writes a timestamped `.wfw` rollback export before running the destructive reset.
- Added: Tools tab can restore/import a saved firewall configuration.
- Changed: Firewall rule PowerShell commands now use validated structured builders with escaped literals for names, paths, descriptions, ports, and addresses.
- Changed: Service IPC token files and named pipes now apply restrictive ACLs for LocalSystem, Administrators, and the current user where pywin32 security APIs are available.
- Changed: README feature/component inventory now matches the implemented runtime surface instead of advertising planned plugin, scheduler, network-profile, anomaly, and reputation components.

## [v4.1.14] - 2026-06-28

- Added: `FirewallRuleTableModel` for model-backed firewall rule rendering.
- Changed: Firewall Rules tab now uses `QTableView` instead of row-by-row `QTableWidget` population for large rule sets.

## [v4.1.13] - 2026-06-28

- Added: IDS-lite YARA-style connection metadata rule engine with warn/block actions.
- Changed: GUI and service monitors now evaluate configured IDS rules against live connection rows and emit threat events.

## [v4.1.12] - 2026-06-28

- Added: Periodic outbound beacon detection for flagged, ads/tracking, or unattributed endpoints.
- Changed: Beacon hits emit high-severity ATT&CK-mapped threat events for service auto-blocking and GUI review.

## [v4.1.11] - 2026-06-28

- Added: DNS-over-HTTPS/DoT endpoint detector with warn/block/ignore config.
- Changed: Live connections, GUI toasts, service status, and service logs now surface DoH detections.

## [v4.1.10] - 2026-06-28

- Added: Opt-in TLS SNI log tailer for mitmproxy/Lumen-style JSONL, CSV, and text logs.
- Changed: GUI and service monitors can ingest SNI domains into the DNS feed without forcing MITM setup.

## [v4.1.9] - 2026-06-28

- Added: MITRE ATT&CK tactic/technique metadata on threat detector events.
- Changed: Threat Detection table and service logs now show ATT&CK mapping for port-scan and brute-force hits.

## [v4.1.8] - 2026-06-28

- Added: Daily and weekly app usage report exporter with CSV and HTML outputs under `%APPDATA%/PyWall/reports`.
- Changed: Tools tab and CLI can generate reports from the same `connection_sessions` aggregation path.

## [v4.1.7] - 2026-06-28

- Added: Config-driven per-app bandwidth quotas with persisted period counters, tray/service notifications, and firewall enforcement.
- Changed: Service status snapshots now report configured and enforced quota counts.

## [v4.1.6] - 2026-06-28

- Added: Per-connection session aggregation with first/last seen, duration, active state, samples, and cumulative byte totals.
- Changed: Connection History now switches between raw event rows and aggregated session rows.

## [v4.1.5] - 2026-06-27

- Added: Per-process sent/received byte deltas from `psutil.Process.io_counters()` in live connections, connection history, and service status snapshots.
- Changed: Connection history schema migrates existing databases with `bytes_sent` and `bytes_recv` columns.

## [v4.1.4] - 2026-06-27

- Added: Service heartbeat state persistence in `%ProgramData%/PyWall/service_state.json`, including clean-shutdown detection and restored auto-block dedupe state after crash or reboot.
- Changed: GUI service status reports whether the previous service shutdown was clean, unclean, or new.

## [v4.1.3] - 2026-06-27

- Added: Headless service reloads supported `config.json` changes while running, including `service_auto_block`, `threat_auto_block`, and `service_poll_seconds`.
- Changed: Service IPC status now reports config path and last reload state for the GUI Tools tab.

## [v4.1.2] - 2026-06-27

- Added: Token-authenticated pywin32 named-pipe IPC between the headless service and GUI Tools tab for live service status.
- Changed: Service log and IPC token state now use `%ProgramData%/PyWall/` on Windows so service and user sessions share the same IPC metadata.

## [v4.1.1] - 2026-06-27

- Added: Windows Service mode with foreground `service-run`, pywin32 service install/start/stop/status commands, headless monitoring, service logging, and high-severity threat auto-blocking.
- Changed: Align runtime branding/version strings with PyWall and keep legacy `HG_` firewall rules visible as PyWall-managed rules.

## [v4.1.0] - %Y->- (HEAD -> main, origin/main, origin/HEAD)

- Changed: Update README.md
- Added: Add screenshot to README
- Added: Add screenshot to README
- Added: Add files via upload
- Changed: Update and rename PyWall.py to PyWall_v.1.0.py
- Added: Add files via upload
