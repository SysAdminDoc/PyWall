# PyWall Roadmap

Windows Firewall GUI + network monitor (~2.6k lines PyQt5, single file). Roadmap targets background-service mode, per-process accounting, deeper threat intel, and multi-host management.

## Planned Features

### Detection
- DNS-over-HTTPS detection with warn or block
- Beacon detection (periodic outbound to low-reputation IP)
- IDS-lite YARA-style rule file for connection metadata

### UI & Workflow
- QAbstractTableModel migration for big rule sets (README TODO)
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

- [ ] P0 - Harden PowerShell firewall command construction
  Why: Rule names, paths, descriptions, ports, and addresses are interpolated into PowerShell strings before running elevated firewall commands.
  Evidence: `PyWall.py:704-724`; Microsoft `New-NetFirewallRule`.
  Touches: `PyWall.py` (`_ps`, `FirewallEngine`), `tests/`.
  Acceptance: Firewall rule creation/deletion/enabling uses escaped/structured arguments, rejects invalid values, and has regression tests for quotes, semicolons, pipes, and paths with spaces.
  Complexity: M

- [ ] P0 - Lock down service IPC pipe and token storage
  Why: The service pipe currently relies on a bearer token and default named-pipe security attributes.
  Evidence: `PyWall.py:1185-1305`; Microsoft named pipe security docs.
  Touches: `PyWall.py` (`_get_ipc_token`, `ServiceIPCServer`, `_service_ipc_request`), service-mode tests.
  Acceptance: Token file and pipe ACLs are restricted to LocalSystem/Administrators/the active user, unauthorized clients are denied before command handling, and tests cover token/ACL failure paths where platform APIs are mockable.
  Complexity: M

- [ ] P0 - Add automatic rollback before destructive firewall actions
  Why: `Reset FW to Default` runs immediately and can remove user/system firewall policy without an automatic restore point.
  Evidence: `PyWall.py:2596`; GlassWire/TinyWall lockdown and recovery patterns.
  Touches: `PyWall.py` (`ToolsTab._fw_reset`, `_fw_export`), config/log paths, tests.
  Acceptance: Reset first exports a timestamped `.wfw`, logs the path, exposes a restore action/status message, and aborts reset if export fails.
  Complexity: S

- [ ] P1 - Reconcile advertised components with implemented code
  Why: README claims plugin, scheduling, network profile automation, anomaly, and reputation manager classes that are not present in `PyWall.py`.
  Evidence: `README.md:97`, `README.md:222-227`; `rtk rg "PluginManager|RuleScheduler|NetworkProfileManager|AnomalyDetector|ReputationScorer" PyWall.py`.
  Touches: `PyWall.py`, `README.md`, `tests/`.
  Acceptance: Each advertised component has a minimal implemented path and test, or the README is narrowed to match actual behavior in the same commit.
  Complexity: M

- [ ] P1 - Pin dependencies and remove elevated runtime installs
  Why: Unpinned dependencies plus `_bootstrap()` pip installs from an elevated GUI/service process create supply-chain and reproducibility risk.
  Evidence: `requirements.txt`; `PyWall.py:85-117`; PyPI pages for psutil, PyQt5, requests, pywin32.
  Touches: `requirements.txt`, `PyWall.py`, `README.md`, packaging docs/tests.
  Acceptance: Dependencies are version-pinned, startup fails with a clear local setup message when packages are missing, frozen builds never attempt pip, and tests cover missing-dependency branches.
  Complexity: S

- [ ] P1 - Add Windows app identity enrichment for svchost, UWP, signer, and parent process
  Why: Competitors expose service/package/parent identity, while PyWall rows mostly show process/path/PID and can mislead for shared hosts.
  Evidence: Fort Firewall service-name and parent-process rules; simplewall Windows services/UWP support; `PyWall.py:1043-1096`.
  Touches: `ConnWorker`, connection table/detail views, history schema, service snapshots, tests.
  Acceptance: Live/history rows show service name for svchost, UWP package/app identity where available, parent process, and signer trust without blocking polling.
  Complexity: L

- [ ] P1 - Move GeoIP enrichment to HTTPS/local database providers
  Why: Batch GeoIP currently sends remote IPs over plaintext HTTP, leaking connection metadata.
  Evidence: `PyWall.py:991`; Sniffnet MaxMind/IPinfo model.
  Touches: `GeoIPWorker`, config, cache/database paths, README, tests.
  Acceptance: Default GeoIP uses HTTPS or a configured local MaxMind MMDB, plaintext providers are disabled by default, and failures degrade to cached/unknown country without GUI freezes.
  Complexity: M

- [ ] P1 - Expand test coverage around firewall, service, DB, and detectors
  Why: Current tests are static symbol checks and do not exercise the behaviors most likely to break user trust.
  Evidence: `tests/test_service_mode_static.py`; `PyWall.py` firewall/service/database classes.
  Touches: `tests/`, `PyWall.py` seams for dependency injection.
  Acceptance: Unit tests mock PowerShell, pywin32 pipe APIs, SQLite migrations, threat detector thresholds, hosts cleanup, and service config reload; test suite runs with `python -m unittest discover -s tests`.
  Complexity: M

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
