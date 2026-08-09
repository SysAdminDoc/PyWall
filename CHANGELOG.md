# Changelog

All notable changes to PyWall will be documented in this file.

## Unreleased

- Added: Persistent per-rule local-time schedules with cross-midnight support, shared by the firewall tab and headless service mode.
- Added: Firewall Rules UI for creating, toggling, removing, and applying scheduled enable/disable windows.
- Added: Preview-first bulk firewall rule editing with validated action, enabled state, profile, and description updates.
- Added: Firewall dependency graph view showing shared groups, programs, endpoints, ports, and protocols before rule changes.
- Added: Extended connection selection with deduplicated batch firewall and hosts-file actions for unknown public endpoints.
- Added: HTTPS-only plugin marketplace pointer/version checks with no automatic download or execution path.
- Added: Default-disabled GeoIP country fencing with allow/deny policies, warn/block actions, deduplicated firewall enforcement, and service evidence.
- Added: Default-disabled scheduled SMTP delivery for daily/weekly usage CSV and HTML reports with persisted cadence and attachment size limits.
- Added: Default-disabled HTTPS Pushover and ntfy notification adapters with severity filtering, bearer support, and redacted provider tokens.
- Added: Default-disabled MaxMind-compatible database updater with HTTPS-only downloads, SHA-256 verification, format validation, persisted cadence, and atomic replacement.
- Added: Default-disabled bearer-token REST API for loopback automation, safe firewall actions, managed-rule push, fleet operations, and AES-GCM encrypted config export.
- Added: HTTPS fleet agent client/manager with read-only status, explicit managed-rule distribution, aggregated threat timeline, and PowerShell module commands.

## [v4.2.0] - 2026-06-30

- Added: SQLite schema migrations using `PRAGMA user_version` for `ConnDB` (v2) and `HostsDB` (v1), replacing inline column checks.
- Added: `ConnDB.export_history()` exports filtered connection history to CSV or JSON. History tab has Export CSV/JSON buttons.
- Added: `NotificationController` centralizes tray notification decisions with configurable severity threshold (`notif_severity_threshold`), per-key snooze (`notif_snooze_minutes`), and optional periodic digest (`notif_digest_enabled`).
- Added: Accessibility names, descriptions, and tooltips on top bar controls, status indicator, connection toggle, bandwidth labels, tab widget, and connection status cells.
- Added: Qt translation loading from `translations/` directory at startup via `load_translation()`.
- Added: `create_forensic_bundle()` produces timestamped ZIP incident archives with filtered history, redacted config, service/crash/tamper logs, and firewall rules export.
- Added: `signer_trust_state()` and `signer_family()` classify Authenticode labels. `group_connections_by_signer()` aggregates live connections by publisher family.
- Added: Connections tab "Signer Groups" view mode with color-coded trust column.
- Added: `DisplayFilter` parser for Wireshark-style field expressions (`proc contains "chrome" and rp in ("443","80")`), applied in History and Connections tabs.
- Changed: Status cells include descriptive text tooltips alongside color for accessibility.

## [v4.1.25] - 2026-06-30

- Added: Connection history now stores event evidence fields (`event_source`, event ID, record ID, rule/layer name, and filter ID) for WFP/Sysmon-backed rows.
- Added: History view can filter all rows, event-backed rows, or psutil-only rows.
- Added: `EvtWorker` can persist Security Event ID 5157 evidence by default and optional Sysmon Event ID 3 network observations when configured.

## [v4.1.24] - 2026-06-30

- Added: Timed learning review for unknown outbound apps that groups candidates by signer, executable path, parent process, and process name without per-connection prompts.
- Added: Connections tab batch review controls to allow or block selected learning groups through program rules or endpoint fallback rules.
- Changed: Runtime config now exposes `learning_mode_enabled` and `learning_mode_window_minutes`.

## [v4.1.23] - 2026-06-30

- Added: Managed firewall rule tamper detection for external create/delete/enable/disable/field changes to `PW_` and legacy `HG_` rules.
- Added: Tamper events are logged to `firewall_tamper.log` with before/after snapshots and surfaced in the firewall tab and service status.
- Added: Firewall tab actions can restore the latest drift event or accept the current managed-rule state as the new baseline.

## [v4.1.22] - 2026-06-30

- Added: Passive plugin manifest registry for `%APPDATA%/PyWall/plugins` with declared hooks, network/file permissions, trust-state reporting, and default-deny execution gates.
- Added: Tools and service status now summarize plugin manifest counts, invalid manifests, executable plugins, and signed/unsigned/unknown trust state.
- Changed: Runtime config now validates plugin enable/disable lists and records manifest validation failures in `plugin_events.log`.

## [v4.1.21] - 2026-06-30

- Added: Blocklist imports now record feed provenance, source URL, fetch timestamp, item count, SHA-256 checksum, last-good cache path, status, and failure reason.
- Added: Built-in feed imports cache raw last-good downloads under `%APPDATA%/PyWall/feed_cache` and fall back to them when a later update fails.
- Changed: Blocklists tab now surfaces import success/failure/cache fallback messages from the worker.

## [v4.1.20] - 2026-06-30

- Added: Versioned `config.json` validation with `schema_version`, typed defaults, warnings for unknown/invalid fields, and corrupt-file backup/recovery.
- Changed: GUI and service status now surface config recovery/warning state instead of silently falling back.
- Changed: Runtime reload paths now share the same validated config loader.

## [v4.1.19] - 2026-06-30

- Added: Behavior-level unit tests for firewall PowerShell command execution, service IPC, SQLite migrations, threat thresholds, hosts cleanup, and service config reload.
- Changed: The test harness now exercises selected non-GUI runtime classes through AST-loaded seams without triggering GUI bootstrap or elevation.

## [v4.1.18] - 2026-06-30

- Added: GeoIP enrichment now supports HTTPS lookup by default and optional local MaxMind-compatible `.mmdb` databases via `maxminddb`.
- Changed: Plaintext GeoIP batch lookups were removed; failures now cache unknown country data without blocking connection polling.
- Changed: Service snapshots and Tools status now report the active GeoIP provider and lookup/unknown counts.

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
