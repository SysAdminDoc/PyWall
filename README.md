<p align="center">
  <img src="https://img.shields.io/badge/PyWall-v4.1.9-3B82F6?style=for-the-badge&labelColor=1A1A24" alt="PyWall v4.1.9"/>
</p>

<h1 align="center">PyWall</h1>

<p align="center">
  <strong>A real-time Windows Firewall manager and network monitor.</strong><br/>
  Single-file Python app. WFC-style rule editor. Toast notifications. Threat detection. Plugin system.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?logo=windows&logoColor=white" alt="Windows"/>
  <img src="https://img.shields.io/badge/License-MIT-22C55E" alt="License"/>
  <img src="https://img.shields.io/badge/Lines-~2.6k-F59E0B" alt="Lines"/>
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
python PyWall.py
```

Dependencies (`PyQt5`, `psutil`, `requests`, and `pywin32` on Windows) auto-install on first launch. PyWall also auto-elevates to admin and configures Windows firewall audit logging automatically.

---

## Features

### Live Connection Monitor

Real-time table of every TCP/UDP connection on the system with process name, remote IP, hostname, port, protocol, country, traffic category, and reputation score. Connections are resolved in the background via DNS, WHOIS, and GeoIP workers. Traffic is auto-categorized into groups like Streaming, Gaming, Social Media, Ads/Tracking, and more.

### WFC-Style Rules Panel

Full management of **all** Windows Firewall rules (not just ones PyWall created) through a split-pane interface with a sidebar for quick actions:

- Filter by source (PyWall / System), direction, action, enabled state
- Real-time search across rule names, programs, addresses, and ports
- Quick actions: Allow, Block, Enable, Disable, Delete, Duplicate, Properties
- Show invalid rules (missing exe) and detect duplicates
- Browse-to-Allow / Browse-to-Block shortcuts
- Open file location for any rule's program
- Rule editor with **auto-detected dropdowns** populated from live connections

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
- Custom IP/domain blocklist enforcement
- VirusTotal hash lookups (bring your own API key)
- Digital signature verification
- GeoIP novelty alerts (first connection to a new country)
- Unusual-hour connection detection

### Network Map

Animated visualization with traffic flow particles. Nodes represent active connections sized by activity. Color-coded by traffic category.

### Application Control

Per-app Allow / Block / Ask policies. See which apps are making connections, their paths, and command lines. Block All Unknown mode for lockdown environments.

### History & Timeline

SQLite-backed connection log with full-text search and filters (process, country, time range). Per-process sent/received byte deltas are captured from `psutil` I/O counters and rolled into per-connection sessions with first/last seen, duration, samples, cumulative totals, and one-click daily/weekly CSV + HTML usage reports. Auto-pruning by configurable retention period.

### Bandwidth Quotas

Optional app quotas in `config.json` enforce daily, weekly, or lifetime byte caps by process name or executable path. When an app crosses its cap, PyWall records the event, shows a tray toast in GUI mode, creates an outbound program block when the executable path is known, and falls back to blocking active remote IPs.

### Scheduling

Time-based rule scheduling -- enable or disable rules on a cron-like schedule. Network profile auto-switching. DNS-level blocking. Bandwidth quota monitoring.

### Plugin System

Drop `.py` files into `%APPDATA%/PyWall/plugins/`. Plugins receive events: `start`, `stop`, `connection`, `block`. Four example plugins included:

| Plugin | Description |
|--------|-------------|
| Webhook Notifier | Send alerts to Slack, Discord, or Teams |
| CSV Logger | Daily CSV logs of connections and blocks |
| IP Reputation | Check IPs against AbuseIPDB |
| Connection Stats | Track per-session statistics |

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

Settings live in `%APPDATA%/PyWall/config.json`. Key options:

| Setting | Default | Description |
|---------|---------|-------------|
| `theme` | `Charcoal` | UI theme |
| `tray` | `true` | Minimize to tray on close |
| `toast` | `true` | Desktop notifications |
| `toast_sec` | `10` | Auto-dismiss delay (seconds, 0 = manual) |
| `start_monitoring` | `false` | Auto-start monitor on launch |
| `history_days` | `30` | Connection history retention |
| `threat_auto_block` | `false` | Auto-block detected threats |
| `service_auto_block` | `true` | Override service-mode high-severity auto-blocking without restart |
| `service_poll_seconds` | `2` | Override service-mode monitor/config polling interval without restart |
| `bandwidth_quotas` | `{}` | App quota map, for example `{ "chrome.exe": { "limit": "5 GB", "window": "day" } }` |
| `auto_block_inbound` | `true` | Block unsolicited inbound connections |
| `detect_portscan` | `true` | Port scan detection |
| `detect_bruteforce` | `true` | Brute force detection |
| `vt_api_key` | `""` | VirusTotal API key |

Full config export/import with diff preview is available in Settings.

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
| `requests` | GeoIP, WHOIS, VirusTotal, plugin HTTP |
| `pywin32` | Windows Service install/start/stop/status control |

Runtime dependencies auto-install on first run if missing when PyWall is not running from a frozen executable.

---

## Architecture

```
PyWall.py  (~2,600 lines, single file)
```

**Runtime files** (auto-created in `%APPDATA%/PyWall/`):

```
pywall.db       Domain/feed/log SQLite database
connections.db  Connection history SQLite database
config.json     Settings, app profiles, blocklists
service.log     Background service status and auto-block log (%ProgramData%/PyWall on Windows)
service.token   Local named-pipe IPC token (%ProgramData%/PyWall on Windows)
service_state.json  Last service heartbeat, clean-shutdown marker, and restored auto-block dedupe state
quota_state.json  Persisted app quota counters and enforced-cap records
reports/       Daily and weekly CSV/HTML app usage reports
plugins/        User and example plugin scripts
```

### Internal Components

| Component | Role |
|-----------|------|
| `FWManager` | PowerShell-backed firewall CRUD with in-memory rule name cache |
| `ConnWorker` | Background thread polling `psutil.net_connections()` |
| `EvtWorker` | Windows Security Event Log monitor (audit events) |
| `DNSWorker` / `WhoWorker` / `GeoIPWorker` | Async resolution with LRU caches |
| `ThreatDetector` | Port scan and brute force heuristics |
| `MITRE_MAPPINGS` | ATT&CK tactic/technique metadata attached to detector events |
| `AnomalyDetector` | GeoIP novelty, unusual hours, baseline deviation |
| `ReputationScorer` | Multi-signal scoring (VT, signatures, blocklists, GeoIP) |
| `TrafficCategorizer` | Hostname/process classification into categories |
| `RuleScheduler` | Cron-like rule enable/disable scheduling |
| `BandwidthQuotaEnforcer` | Config-driven app byte caps with persisted counters, tray/service notifications, and firewall enforcement |
| `export_usage_reports` | Daily and weekly app usage report writer for CSV and HTML |
| `NetworkProfileManager` | Auto-switching between Domain/Private/Public |
| `PluginManager` | Dynamic plugin loading and event dispatch |
| `HeadlessMonitor` | Service-mode DNS, connection, event, history, config reload, restored state, IPC, and threat auto-block loop |
| `ServiceIPCServer` | Token-authenticated pywin32 named-pipe status server |
| `PyWallWindowsService` | pywin32 Windows Service wrapper |
| `MainWindow` | PyQt5 GUI: 10 tabs, toasts, tray, WFC-style rule editor |

---

## Contributing

Some areas that could use work:

- **QTableView migration** -- QTableWidget to QAbstractTableModel for large rule sets
- **DoH detection** -- warn or block DNS-over-HTTPS endpoints
- **More plugins** -- GeoIP fencing, bandwidth alerting, scheduled reports
- **Localization** -- i18n support
- **Unit tests** -- test coverage for FWManager and detection logic

PRs welcome. Open an issue first for larger changes.

---

## License

[MIT](LICENSE)

---

## Acknowledgments

- [psutil](https://github.com/giampaolo/psutil) -- process and network utilities
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) -- Qt5 Python bindings
- [ip-api.com](http://ip-api.com) -- GeoIP lookups
- [VirusTotal](https://www.virustotal.com) -- file reputation API
- Inspired by [Windows Firewall Control](https://www.binisoft.org/wfc) by Malwarebytes
