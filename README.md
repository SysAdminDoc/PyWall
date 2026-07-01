<p align="center">
  <img src="https://img.shields.io/badge/PyWall-v4.2.0-3B82F6?style=for-the-badge&labelColor=1A1A24" alt="PyWall v4.2.0"/>
</p>

<h1 align="center">PyWall</h1>

<p align="center">
  <strong>A real-time Windows Firewall manager and network monitor.</strong><br/>
  Single-file Python app. WFC-style rule editor. Toast notifications. Threat detection. Service mode.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?logo=windows&logoColor=white" alt="Windows"/>
  <img src="https://img.shields.io/badge/License-MIT-22C55E" alt="License"/>
  <img src="https://img.shields.io/badge/Lines-~5.4k-F59E0B" alt="Lines"/>
</p>

---

## What Is This

PyWall is a desktop application that sits between you and Windows Firewall. It monitors every network connection in real time, shows you exactly what's talking to the internet, and lets you create or manage firewall rules without ever opening `wf.msc`.

It's a single `.py` file. No installer. No build step. Drop it anywhere and run it.

---

## Quick Start

```bash
# Clone and run (admin recommended)
git clone https://github.com/SysAdminDoc/PyWall.git
cd PyWall
python -m pip install -r requirements.txt
python PyWall.py
```

Dependencies are pinned in `requirements.txt` and must be installed before launch. PyWall auto-elevates to admin and configures Windows firewall audit logging automatically.

---

## Features

### Live Connection Monitor

Real-time table of every TCP/UDP connection on the system with process name, PID, svchost service names, parent process, UWP/package identity where visible, signer trust, remote IP, hostname, port, protocol, country, traffic category, and reputation score. Connections are resolved in the background via DNS, WHOIS, HTTPS/local GeoIP, and signer workers. Traffic is auto-categorized into groups like Streaming, Gaming, Social Media, Ads/Tracking, and more.

### WFC-Style Rules Panel

Full management of **all** Windows Firewall rules (not just ones PyWall created) through a split-pane interface with a sidebar for quick actions:

- Filter by source (PyWall / System), direction, action, enabled state
- Real-time search across rule names, programs, addresses, and ports
- Quick actions: Allow, Block, Enable, Disable, Delete, Duplicate, Properties
- Show invalid rules (missing exe) and detect duplicates
- Browse-to-Allow / Browse-to-Block shortcuts
- Open file location for any rule's program
- Rule editor with **auto-detected dropdowns** populated from live connections
- Destructive firewall reset first writes a timestamped `.wfw` rollback export and exposes restore/import from the Tools tab
- Managed `PW_` and legacy `HG_` rules are checked for external create/delete/enable/disable drift on refresh, logged with before/after snapshots, and can be restored or accepted from the firewall tab

### Toast Notifications

Desktop notifications for blocked connections and new apps. Each toast has one-click Block/Allow/Edit buttons. Expand for custom rule options (direction, action, type). All actions save immediately with no confirmation popups.

### Auto-Block

Toggle in the toolbar. Automatically creates block rules for flagged connections. Multi-layer deduplication prevents duplicate rules:

1. `FWManager._known_names` -- in-memory set of all rule names, synced on create/delete
2. `rule_exists()` gate on every quick-block helper
3. `_auto_blocked_ips` -- UI-level IP set seeded from existing rules on monitor start
4. `_auto_blocked_threats` -- separate dedup for the threat detector path

### Threat Detection

- Port scan detection (configurable unique-port threshold within a time window)
- Brute force detection (repeated blocked connection attempts)
- MITRE ATT&CK mapping on detector hits (`T1046` network service discovery and `T1110` brute force)
- Optional TLS SNI ingestion from mitmproxy/Lumen-style JSONL, CSV, or text logs
- DNS-over-HTTPS endpoint detection with configurable `warn`, `block`, or `ignore` action
- Periodic outbound beacon detection for low-reputation or unattributed endpoints
- IDS-lite YARA-style rule file for connection metadata matches
- Custom IP/domain blocklist enforcement
- VirusTotal and related research links from domain context menus

### Blocklist Imports

Built-in blocklist imports record source URL, fetch timestamp, parsed item count, SHA-256 checksum, last-good cache path, and failure reason. If a feed update fails, PyWall keeps the last-good cached feed available and reports the fallback in the Blocklists status line.

### Plugin Guardrails

Plugin manifests can be staged under `%APPDATA%/PyWall/plugins`, but plugin code is not executed by default. The Tools tab scans `pywall-plugin.json` or `plugin.json` manifests, validates declared hooks and network/file permissions, classifies signed/unsigned/unknown trust state, writes invalid manifest details to `plugin_events.log`, and only marks a plugin executable when `plugins_enabled`, the manifest `enabled` flag, and `plugin_enabled_ids` all opt in.

### Application Control

Live connection rows show process names, paths, PIDs, service/package/parent/signer identity, remote endpoints, traffic category, byte deltas, and context actions to block the selected IP, program, or domain.

### Learning Review

On startup, PyWall can collect unknown outbound apps for a timed review window without prompting on every connection. The Connections tab groups candidates by signer, executable path, parent process, and process name, then lets you allow or block selected groups in one batch; the default behavior is collect-only until you choose an action.

### Signer Trust Groups

Live connections can be viewed grouped by Authenticode signer family. Each group shows the trust state (signed/unsigned/changed), member apps, unique IP count, and aggregate traffic. Unsigned and expired-signer apps are highlighted for review.

### History & Timeline

SQLite-backed connection log with full-text search and Wireshark-style display filters (e.g. `proc contains "chrome" and rp in ("443","80") and bytes_sent >= 1000`). Per-process sent/received byte deltas and app identity fields are captured from `psutil`/Windows metadata and rolled into per-connection sessions with first/last seen, duration, samples, cumulative totals, event source/event ID/filter metadata where available, and one-click daily/weekly CSV + HTML usage reports. History can be exported to filtered CSV or JSON. Auto-pruning by configurable retention period. Schema migrations use `PRAGMA user_version` for safe upgrades.

### Forensic Export

One-click incident bundle from the Tools tab: produces a timestamped ZIP archive containing filtered connection history (CSV + JSON), redacted config snapshot, service and crash logs, firewall tamper log, and firewall rules export.

### Notification Controls

Configurable notification fatigue controls: severity threshold filtering (low/medium/high), per-alert snooze with cooldown, startup warmup suppression, and optional periodic digest of suppressed alerts.

### Bandwidth Quotas

Optional app quotas in `config.json` enforce daily, weekly, or lifetime byte caps by process name or executable path. When an app crosses its cap, PyWall records the event, shows a tray toast in GUI mode, creates an outbound program block when the executable path is known, and falls back to blocking active remote IPs.

### Themes

Seven built-in themes:

| Dark | Light |
|------|-------|
| Midnight | Light |
| Charcoal (default) | Frost |
| Slate | |
| Nord | |
| Graphite | |

### System Tray

Minimizing the window sends it to the system tray. Dynamic tray icon changes color based on state (idle / monitoring / warning / threat). The console window is hidden automatically in GUI mode.

### Crash Recovery

If PyWall is terminated while monitoring, it auto-resumes on next launch.

---

## Service Mode

PyWall can run its DNS, connection, event-log, history, enrichment, and high-severity threat auto-blocking monitors without opening the GUI. The GUI can query a running service through the local pywin32 named pipe `\\.\pipe\PyWallService`, the service reloads supported `config.json` changes while running, and service heartbeat state is restored after crash or reboot.

```bash
python PyWall.py service-run
python PyWall.py service-run --no-auto-block
python PyWall.py service install --startup auto
python PyWall.py service start
python PyWall.py service status
python PyWall.py service stop
python PyWall.py service remove
python PyWall.py report
```

Service logs and the IPC token are written to `%ProgramData%/PyWall/`. High-severity detector hits are blocked in both inbound and outbound directions with `PW_` firewall rules; existing `HG_` rules from older builds remain visible as PyWall-managed rules.

---

## Configuration

Settings live in `%APPDATA%/PyWall/config.json`. PyWall writes `schema_version`, validates known fields on load, preserves unknown future fields with warnings, and backs up corrupt JSON to `config.json.corrupt.<timestamp>.bak` before replacing it with defaults.

| Setting | Default | Description |
|---------|---------|-------------|
| `schema_version` | `1` | Runtime config schema version |
| `theme` | `Charcoal` | UI theme |
| `tray` | `true` | Minimize to tray on close |
| `toast` | `true` | Desktop notifications |
| `toast_sec` | `10` | Auto-dismiss delay (seconds, 0 = manual) |
| `start_monitoring` | `false` | Auto-start monitor on launch |
| `learning_mode_enabled` | `true` | Collect unknown outbound apps for a non-modal review window on startup |
| `learning_mode_window_minutes` | `10.0` | Timed learning review collection window |
| `history_days` | `30` | Connection history retention |
| `threat_auto_block` | `false` | Auto-block detected threats |
| `service_auto_block` | `true` | Override service-mode high-severity auto-blocking without restart |
| `service_poll_seconds` | `2` | Override service-mode monitor/config polling interval without restart |
| `bandwidth_quotas` | `{}` | App quota map, for example `{ "chrome.exe": { "limit": "5 GB", "window": "day" } }` |
| `tls_sni_enabled` | `false` | Opt in to tailing an external TLS SNI log file |
| `tls_sni_log_path` | `""` | Path to a mitmproxy/Lumen JSONL, CSV, or text log containing SNI/host/domain fields |
| `tls_sni_read_existing` | `false` | Start reading the SNI log from the beginning instead of tailing only new lines |
| `detect_doh` | `true` | Detect known DNS-over-HTTPS endpoints on HTTPS/TLS DNS ports |
| `doh_action` | `warn` | DoH response: `warn`, `block`, or `ignore` |
| `ids_rules_enabled` | `true` | Enable IDS-lite connection metadata rules |
| `ids_rules_path` | `%APPDATA%/PyWall/ids_rules.yaral` | YARA-style rule file path |
| `event_correlation_enabled` | `true` | Store Windows Filtering Platform event evidence from Security Event ID 5157 |
| `sysmon_event_correlation_enabled` | `false` | Optionally store Sysmon Event ID 3 network observations when Sysmon is installed |
| `geoip_provider` | `ipwhois` | GeoIP source: `ipwhois`, `maxmind`, or `disabled`; plaintext providers are not used |
| `geoip_https_endpoint` | `https://ipwho.is/{ip}` | HTTPS GeoIP endpoint template used by the default provider |
| `geoip_mmdb_path` | `""` | Optional local MaxMind-compatible `.mmdb` database path; used before network lookup or exclusively with `geoip_provider: "maxmind"` |
| `plugins_enabled` | `false` | Global plugin execution gate; manifests are scanned but not executable unless this is true |
| `plugin_enabled_ids` | `[]` | Explicit allowlist of plugin IDs that may execute declared hooks |
| `plugin_disabled_ids` | `[]` | Explicit denylist that overrides manifest and allowlist settings |
| `auto_block_inbound` | `true` | Block unsolicited inbound connections |
| `detect_portscan` | `true` | Port scan detection |
| `detect_bruteforce` | `true` | Brute force detection |
| `vt_api_key` | `""` | VirusTotal API key |
| `notif_severity_threshold` | `low` | Minimum alert severity to show: `low`, `medium`, or `high` |
| `notif_snooze_minutes` | `5` | Cooldown minutes between repeated alerts for the same key |
| `notif_digest_enabled` | `false` | Accumulate suppressed alerts and show a periodic digest |
| `notif_digest_interval_minutes` | `15` | Interval between digest notifications |

IDS-lite rule example:

```text
rule suspicious_powershell {
  severity = high
  action = block
  mitre_tactic = Command and Control
  mitre = T1071 Application Layer Protocol
  condition:
    proc contains "powershell" and rp in ("443","4444")
}
```

---

## Requirements

| Requirement | Details |
|-------------|---------|
| OS | Windows 10 or 11 |
| Python | 3.10+ |
| Privileges | Administrator (auto-elevates on launch) |

### Dependencies

| Package | Purpose |
|---------|---------|
| `PyQt5` | GUI |
| `psutil` | Process and connection enumeration |
| `maxminddb` | Optional local MaxMind-compatible GeoIP database reader |
| `pywin32` | Windows Service install/start/stop/status control |

If dependencies are missing, startup exits with the exact `pip install -r requirements.txt` command to run.

---

## Architecture

```
PyWall.py  (~5,400 lines, single file)
```

**Runtime files** (auto-created in `%APPDATA%/PyWall/`):

```
pywall.db       Domain/feed/log SQLite database
connections.db  Connection history SQLite database
config.json     Settings, app profiles, blocklists
feed_cache/    Last-good raw blocklist downloads with feed provenance in `pywall.db`
plugins/       Passive plugin manifests; plugin code is default-denied until explicitly enabled
plugin_events.log  Manifest validation and plugin guardrail diagnostics
firewall_tamper.log  Managed-rule drift events with before/after snapshots
service.log     Background service status and auto-block log (%ProgramData%/PyWall on Windows)
service.token   ACL-restricted local named-pipe IPC token (%ProgramData%/PyWall on Windows)
service_state.json  Last service heartbeat, clean-shutdown marker, and restored auto-block dedupe state
quota_state.json  Persisted app quota counters and enforced-cap records
fw_backups/    Timestamped `.wfw` rollback exports before firewall reset
reports/       Daily and weekly CSV/HTML app usage reports
```

### Internal Components

| Component | Role |
|-----------|------|
| `FWManager` | PowerShell-backed firewall CRUD with in-memory rule name cache and managed-rule tamper detection |
| `ConnWorker` | Background thread polling `psutil.net_connections()` |
| `EvtWorker` | Windows Security Event ID 5157 and optional Sysmon Event ID 3 monitor with event evidence fields |
| `DNSWorker` / `WhoWorker` / `GeoIPWorker` | Async resolution with LRU caches |
| `ThreatDetector` | Port scan, brute force, and periodic beacon heuristics |
| `MITRE_MAPPINGS` | ATT&CK tactic/technique metadata attached to detector events |
| `TLSLogWorker` | Opt-in mitmproxy/Lumen-style TLS SNI log tailer that feeds observed domains into the DNS feed |
| `DoHDetector` | Known endpoint detector with warn/block policy for DNS-over-HTTPS and DNS-over-TLS connections |
| `IDSRuleEngine` | YARA-style metadata rule loader/evaluator for live connection rows |
| `TrafficCategorizer` | Hostname/process classification into categories |
| `LearningReviewCollector` | Timed, non-modal collector that groups unknown outbound apps by signer/path/parent for batch allow/block decisions |
| `BandwidthQuotaEnforcer` | Config-driven app byte caps with persisted counters, tray/service notifications, and firewall enforcement |
| `export_usage_reports` | Daily and weekly app usage report writer for CSV and HTML |
| `PluginRegistry` | Passive manifest scanner with hook/permission validation, trust-state reporting, and default-deny execution gates |
| `HeadlessMonitor` | Service-mode DNS, connection, event, history, config reload, restored state, IPC, and threat auto-block loop |
| `ServiceIPCServer` | Token-authenticated pywin32 named-pipe status server |
| `PyWallWindowsService` | pywin32 Windows Service wrapper |
| `FirewallRuleTableModel` | QAbstractTableModel-backed firewall rule table for large rule sets |
| `NotificationController` | Centralized tray notification gating with severity filter, snooze, warmup, and digest |
| `DisplayFilter` | Wireshark-style field-based filter parser for history and live connection views |
| `create_forensic_bundle` | Timestamped ZIP incident archive with history, config, logs, and firewall rules |
| `MainWindow` | PyQt5 GUI: 10 tabs, toasts, tray, WFC-style rule editor |

---

## Contributing

Some areas that could use work:

- **Rule scheduling** -- engine and UI for scheduled enable/disable windows
- **Plugin system** -- execution hooks and plugin implementations on top of the existing manifest guardrails
- **Localization** -- translation catalog files for `translations/` directory (i18n plumbing is in place)
- **Unit tests** -- test coverage for FWManager and detection logic

PRs welcome. Open an issue first for larger changes.

---

## License

[MIT](LICENSE)

---

## Acknowledgments

- [psutil](https://github.com/giampaolo/psutil) -- process and network utilities
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) -- Qt5 Python bindings
- [ipwho.is](https://ipwho.is/) -- HTTPS GeoIP lookups
- [MaxMind DB](https://maxmind.github.io/MaxMind-DB/) -- optional local GeoIP database format
- [VirusTotal](https://www.virustotal.com) -- file reputation API
- Inspired by [Windows Firewall Control](https://www.binisoft.org/wfc) by Malwarebytes
