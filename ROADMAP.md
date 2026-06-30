# PyWall Roadmap

Windows Firewall GUI + network monitor (~2.6k lines PyQt5, single file). Roadmap targets background-service mode, per-process accounting, deeper threat intel, and multi-host management.

## Planned Features

### UI & Workflow
- Per-rule scheduling UI parity with `RuleScheduler`
- Full rule dependency graph view ("if I delete this, what breaks?")
- Bulk rule edit (pattern match, set action, apply)
- Multi-select toasts ("Block all 5 unknown connections")

### Plugins
- Plugin marketplace pointer + update check
- GeoIP fencing plugin (country allowlist)
- Scheduled report email plugin
- Pushover / ntfy.sh notifier plugin
- MaxMind DB auto-updater plugin

### Multi-host
- Connect to remote PyWall agent (read-only fleet view)
- Rule push from central host to workstation fleet
- Aggregated threat timeline

### CLI & API
- Local REST API (token-auth) for automation
- PowerShell module wrapper for `block-ip`, `allow-port`, etc.
- Config export encrypted with passphrase

## Competitive Research
- **Windows Firewall Control (Malwarebytes)** — closest peer; closed source, fewer detectors. Lesson: PyWall's differentiator is the open plugin model and threat detectors.
- **TinyWall** — free alternative, allowlist mode. Lesson: adopt its "learning mode" UX for bootstrap.
- **GlassWire** — commercial network viz + alerts. Lesson: their history timeline is the bar for per-app accounting.
- **OpenSnitch (Linux)** — per-connection prompt dialog. Lesson: add an "Ask on every new connection" mode for lockdown users.

## Nice-to-Haves
- IPv6 parity audit
- Wireguard / OpenVPN interface awareness
- Hyper-V vSwitch rule view
- Localization pass (i18n)
- Auto-signed Authenticode release for enterprise rollout
- Dark theme per-tab accents (beyond the 7 built-ins)

## Open-Source Research (Round 2)

### Related OSS Projects
- https://github.com/henrypp/simplewall — WFP-based (not just netsh) gold-standard firewall GUI. C but patterns transfer.
- https://github.com/DevLM7/PyFire--Intelligent_Firewall_Manager — Python + Tkinter/ttkbootstrap firewall dashboard, SQLite-logged.
- https://github.com/p-yukusai/PyWall — Namesake; PyQt5 + shell context menu for block/allow.
- https://github.com/bennettyardley/python-firewall — pydivert/WinDivert packet-level filtering.
- https://github.com/Martin-314/Windows-Firewall — flet-based netsh wrapper.
- https://github.com/pdulvp/easy-firewall — Minimal app-blocker UI (Java, but clean UX).
- https://github.com/evilsocket/opensnitch — Linux interactive firewall; the UX bar to beat.
- https://github.com/netkiller/firewall — Python firewall library with netfilter/iptables bindings.

### Features to Borrow
- WFP (Windows Filtering Platform) driver-level filtering instead of netsh rules (simplewall) — stops netsh's rule-count perf cliff.
- Interactive "allow/deny on first connection attempt" prompt (opensnitch) — the killer feature of OpenSnitch.
- SQLite log of every connection + rule fire for forensics (PyFire).
- Protocol pie chart + live-connection list (PyFire).
- WinDivert packet capture for deep inspection (bennettyardley) — DNS/HTTP CONNECT sniff.
- Windows shell context menu: right-click .exe → Block Internet (PyWall).
- VirusTotal / URLhaus lookup on unknown remote IP at connect time.
- Process ancestry shown in connection row (svchost invoked by wuauclt, etc.).

### Patterns & Architectures Worth Studying

## Research-Driven Additions

- [ ] P2 - Add accessibility and i18n foundations for dense security tables
  Why: Current UI is color-heavy and lacks translation/accessibility plumbing while competitors ship localization.
  Evidence: No `setAccessibleName` or Qt translation flow in `PyWall.py`; simplewall/Fort/Sniffnet/OpenSnitch localization.
  Touches: GUI tab builders, theme/style constants, resource loading, README.
  Acceptance: Main controls and status cells have accessible names/tooltips/text equivalents, high-contrast status rendering is usable without color, and strings are routed through a Qt translation catalog stub.
  Complexity: M

- [ ] P2 - Formalize SQLite schema migrations and history exports
  Why: History schema changes are inline column checks, which will become brittle as app identity, sessions, quotas, and reports land.
  Evidence: `PyWall.py:645-689`; GlassWire history and Sniffnet PCAP/report export patterns.
  Touches: `ConnDB`, `HostsDB`, history/export UI, tests.
  Acceptance: Databases use `PRAGMA user_version`, migrations are idempotent and tested from old schemas, and history can export filtered rows to CSV/JSON without losing byte/app identity fields.
  Complexity: M

### Patterns & Architectures Worth Studying (continued)
- **WFP callout driver** (simplewall) — requires signed driver, but pays off with kernel-time decisions vs user-space netsh polling.
- **pydivert hook layer** (bennettyardley) — ships as a DLL, no driver install, but higher latency than WFP.
- **Rule engine with priority + direction + profile keys** (simplewall) — matches Windows firewall's 3-profile model properly.
- **Interactive prompt with timeout default** (opensnitch) — blocks by default if user doesn't answer in N seconds.
- **Plugin system for enrichment** (already in project) — pair with the new threat-feed integrations cleanly.

## Research-Driven Additions

- [ ] P1 - Add first-run learning review without noisy per-connection prompts
  Why: Competitors prove learning mode is valuable, but PyWall's no-confirmation philosophy needs a batch review model instead of modal prompts.
  Evidence: TinyWall learning mode; OpenSnitch interactive prompts; GlassWire ask-to-connect; existing roadmap notes for multi-select toasts.
  Touches: `ConnectionsTab`, toast/review queue UI, `FirewallEngine`, config defaults, tests.
  Acceptance: A first-run mode collects unknown outbound apps for a timed window, groups them by signer/path/parent where available, and lets the user allow/block selected groups with clear default behavior.
  Complexity: L

- [ ] P1 - Add optional Sysmon/WFP event correlation for connection evidence
  Why: psutil polling can miss short-lived connections and lacks event IDs; Windows event 5157 and Sysmon Event ID 3 provide auditable evidence.
  Evidence: `EvtWorker` 5157 polling in `PyWall.py`; Microsoft event 5157 docs; Sysmon network connection docs; Sniffnet display-filter issue signal.
  Touches: `EvtWorker`, `ConnDB`, history/security tabs, report/export code, tests with mocked events.
  Acceptance: When enabled, history rows can include event source, event ID, rule/filter metadata where available, and a filter for psutil-only versus event-backed observations.
  Complexity: L

- [ ] P2 - Add notification fatigue controls and digesting
  Why: Security tools lose trust when alerts are either too noisy or too silent; peer products expose discreet alerts, unseen-host notifications, and batch decisions.
  Evidence: GlassWire discreet alerts; Sniffnet unseen-host notification issue; OpenSnitch/Portmaster prompt batching issue signal.
  Touches: toast code paths in `MainWindow`, config, tray/status UI, service log summaries, tests.
  Acceptance: Users can set severity thresholds, snooze repeated app/IP alerts, receive a periodic digest, and still force high-severity threat notifications.
  Complexity: M

- [ ] P2 - Add signed-app trust and rule grouping
  Why: Parent process, signer, and group-aware rules reduce brittle per-path decisions and match peer app-firewall expectations.
  Evidence: Little Snitch/LuLu signed-app trust patterns; Fort Firewall app groups and parent-process issue signal; Windows WinVerifyTrust API.
  Touches: connection enrichment, rule dialog, history schema, firewall/app grouping UI, tests.
  Acceptance: Connection and rule views can group by signer/app family, show unsigned/changed signer state, and create allow/block rules from a group without losing per-path detail.
  Complexity: L

- [ ] P2 - Add forensic export bundles for incidents
  Why: Current CSV/HTML usage reports are useful for accounting, but incident handoff needs rules, config, logs, events, and filtered history together.
  Evidence: `export_usage_reports` in `PyWall.py`; Sniffnet PCAP/export model; GlassWire history/timeline model.
  Touches: export/report code, `ConnDB`, `HostsDB`, service/crash logs, tools UI, tests.
  Acceptance: A date-filtered incident bundle exports JSON/CSV history, matching firewall rules, config snapshot with secrets redacted, service/crash logs, and source metadata into one timestamped archive.
  Complexity: M

- [ ] P3 - Add Wireshark-style filter grammar for history and live views
  Why: Large connection/history tables need repeatable filters beyond simple text search once identity, events, and groups are added.
  Evidence: Sniffnet display-filter issue; existing `ConnDB.search` simple LIKE query in `PyWall.py`; Wireshark display-filter UX.
  Touches: `ConnectionsTab`, `HistoryTab`, `ConnDB.search`, filter parser, docs/tests.
  Acceptance: Users can filter by fields such as `proc`, `ra`, `rp`, `country`, `stat`, `event_id`, and `bytes_total`, with invalid filters showing inline errors instead of empty silent results.
  Complexity: L
