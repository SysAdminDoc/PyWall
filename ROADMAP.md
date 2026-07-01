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

### Patterns & Architectures Worth Studying (continued)
- **WFP callout driver** (simplewall) — requires signed driver, but pays off with kernel-time decisions vs user-space netsh polling.
- **pydivert hook layer** (bennettyardley) — ships as a DLL, no driver install, but higher latency than WFP.
- **Rule engine with priority + direction + profile keys** (simplewall) — matches Windows firewall's 3-profile model properly.
- **Interactive prompt with timeout default** (opensnitch) — blocks by default if user doesn't answer in N seconds.
- **Plugin system for enrichment** (already in project) — pair with the new threat-feed integrations cleanly.
