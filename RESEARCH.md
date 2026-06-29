# Research - PyWall

## Executive Summary
PyWall is a Windows-only PyQt5 firewall manager and network monitor built around one large `PyWall.py` module, Windows Firewall PowerShell/netsh calls, psutil connection polling, SQLite history, hosts-file management, and an optional pywin32 service/pipe path. Its strongest current shape is a local-control security tool with unusually broad functionality for a small repo; the highest-value direction is making that surface trustworthy before adding more breadth. Top opportunities, in order: harden PowerShell rule execution, lock down service IPC, add automatic firewall-reset rollback, reconcile README/runtime drift, stop elevated runtime dependency installs, replace plaintext GeoIP enrichment, add app/service identity, grow behavioral tests, validate config/feed state, add plugin trust boundaries, detect tampering, and make evidence export/notification workflows usable under stress.

## Product Map
- Core workflows: monitor live TCP/UDP connections; block/allow IPs, ports, programs, and hosts entries; inspect Windows Firewall rules; review connection history/sessions; run headless service monitoring and high-severity auto-blocking.
- User personas: Windows power users, security hobbyists, small-business admins, and operators who want local firewall visibility without a commercial suite or cloud control plane.
- Platforms and distribution: Windows 10/11, Python 3.10+, PyQt5 GUI, pywin32 service integration, optional PyInstaller-style executable; MIT license.
- Key integrations and data flows: `psutil.net_connections()` and per-process I/O counters, PowerShell NetSecurity/netsh/auditpol, Windows Security event 5157 polling, SQLite DBs, hosts file writes, ipinfo/ip-api/favicon HTTP enrichment, VirusTotal links/API fields, local named pipe `\\.\pipe\PyWallService`.

## Competitive Landscape
- simplewall: WFP-based Windows filtering, portable mode, logging, IPv6, service/UWP/WSL support, and localization. Learn its system-rule separation and Windows identity coverage; avoid a signed-driver pivot until PyWall's current PowerShell and IPC trust boundaries are hardened.
- Fort Firewall: WFP app firewall with parent-process rules, svchost service filtering, app groups, speed limits, traffic stats, custom lookup services, and localization. Learn its identity/quota model and filter ergonomics; avoid driver/HVCI complexity as the first dependency.
- Portmaster: local core plus UI, per-app settings, Secure DNS, blocklist updates, app/network history, signed update flow, and profile requests from users. Learn the service/UI split and policy-profile UX; avoid paid-network/VPN features that do not fit PyWall's local-control posture.
- OpenSnitch: interactive first-connection prompts, rule schema validation requests, centralized node GUI, SIEM integration, blocklists, and translations. Learn timeout/default decisions and schema validation; avoid prompt fatigue without batch review and quiet learning controls.
- TinyWall: no-popup allowlist mode, learning mode, tamper protection, password lockdown, timed rules, LAN restrictions, IPv6, UWP, and boot-time filtering. Learn the no-noise onboarding and tamper model; avoid silent lockouts without rollback and audit trails.
- GlassWire: visual history graph, discreet alerts, ask-to-connect, lockdown, device/network change alerts, and remote monitoring. Learn timeline/evidence UX and notification hierarchy; avoid paywall-shaped breadth before data correctness.
- Sniffnet: adapter filters, protocol/service labels, ASN/GeoIP, PCAP import/export, custom notifications, unseen-host requests, multi-platform packages, and broad translations. Learn exportable evidence and filter grammar; avoid multi-platform expansion before Windows semantics are solid.
- LuLu and Little Snitch: polished outbound prompt workflows, signed-code trust, rule grouping, profiles, and low-friction app identity. Learn signer-aware rules and reviewable prompts; avoid macOS-only assumptions.

## Security, Privacy, and Reliability
- Verified: `_ps()` runs a raw PowerShell command string (`PyWall.py:520-526`), and `FirewallEngine.create_rule/delete_rule/enable_rule` interpolate names, paths, descriptions, ports, addresses, and booleans (`PyWall.py:786-805`). Existing roadmap P0 already covers structured escaping and tests; keep it first.
- Verified: `_get_ipc_token()` writes a bearer token to disk without explicit ACLs (`PyWall.py:1812-1823`), while `ServiceIPCServer._run()` creates the named pipe with default security attributes (`PyWall.py:1897-1905`). Existing roadmap P0 already covers pipe/token ACLs.
- Verified: `ToolsTab._fw_reset()` executes `netsh advfirewall reset` without a pre-reset export (`PyWall.py:3312-3318`). Existing roadmap P0 already covers automatic rollback.
- Verified: `GeoIPWorker` posts remote IP batches to plaintext `http://ip-api.com/batch` (`PyWall.py:1493-1517`), while README links ip-api over HTTP (`README.md:299`). Existing roadmap P1 already covers HTTPS/local GeoIP.
- Verified: `_bootstrap()` auto-elevates and then pip-installs missing dependencies (`PyWall.py:85-115`), and `requirements.txt` is unpinned. Existing roadmap P1 already covers pinning and removing elevated runtime installs.
- Verified: README advertises scheduling, plugin, network-profile, anomaly, and reputation manager classes not present in `PyWall.py` (`README.md:259-266`; `rtk rg "RuleScheduler|PluginManager|NetworkProfileManager|AnomalyDetector|ReputationScorer" PyWall.py`). Existing roadmap P1 already covers reconciling claims with code.
- Verified: `screenshot.png` renders a HostsGuard v2.1.0 screen, not PyWall; README no longer embeds it, but the tracked artifact can mislead future release work.
- Likely: user-supplied plugin/feed functionality will become a high-risk boundary once the advertised plugin system is implemented; add manifest permissions, provenance checks, and disabled-by-default execution before marketplace/update features.
- Likely: external changes to Windows Firewall rules can invalidate PyWall's in-memory rule cache (`FirewallEngine._known_names`, `PyWall.py:775-813`) without a tamper/audit path; TinyWall/WFC/simplewall patterns support adding drift detection.

## Architecture Assessment
- `PyWall.py` has about 3,700 lines and mixes bootstrap, service, DB, workers, firewall engine, and all GUI tabs. Split only when implementing hardening/tests; broad refactors should follow seams already visible in `FirewallEngine`, `ServiceIPCServer`, `ConnDB`, workers, and tab classes.
- Firewall rule table migration to `FirewallRuleTableModel` is done (`PyWall.py:2819-2864`), but other dense surfaces still use `QTableWidget` (`PyWall.py:2352`, `2437`, `2704`, `2999`, `3129`, `3191`). Existing roadmap already covers accessibility/i18n; future table work should prioritize connection/history/security views.
- `ConnDB` uses inline column checks and no `PRAGMA user_version` (`PyWall.py:679-692`). Existing roadmap already covers formal migrations and history exports; config JSON needs the same versioned validation/recovery treatment.
- App identity is shallow: `ConnWorker` stores process name/path/PID from psutil (`PyWall.py:1666-1734`), but there is no svchost service name, UWP package identity, parent process, signer trust, or group identity. Existing roadmap P1 already covers identity enrichment.
- Tests are static AST/string checks only (`tests/test_service_mode_static.py:12-94`). Existing roadmap already covers behavioral firewall/service/DB/detector tests; new roadmap additions should add config, feed, plugin, tamper, and export tests.
- Observability exists as service/crash logs and status labels, but there is no structured event stream for rule mutations, config recovery, feed updates, plugin execution, or external tamper events.

## Rejected Ideas
- WFP driver backend now: simplewall/Fort prove the value, but signed-driver/HVCI deployment risk should wait until PyWall's PowerShell backend, IPC, tests, and rollback paths are hardened.
- Full remote fleet control now: OpenSnitch/GlassWire/Portmaster show demand, and ROADMAP already lists multi-host items; authenticated transport and service hardening must land first.
- VPN/privacy network: Portmaster SPN and commercial privacy bundles do not fit PyWall's local Windows Firewall manager shape.
- Mobile client: GlassWire has Android, but PyWall's control plane is Windows-specific and the current gaps are local trust, packaging, and evidence quality.
- Default TLS interception: opt-in TLS SNI logs fit PyWall; default MITM would contradict the privacy/local-control philosophy and add certificate risk.
- Hosted CI/build workflows: many peers use CI, but repo rules require local builds/releases and no GitHub Actions.
- Full packet capture as the next step: Sniffnet PCAP import/export is valuable, but PyWall currently has no packet capture backend; start with evidence export and optional Sysmon/WFP event correlation before adding capture drivers.

## Sources
### Project
- https://github.com/SysAdminDoc/PyWall

### OSS and Adjacent Tools
- https://github.com/henrypp/simplewall
- https://github.com/tnodir/fort
- https://github.com/safing/portmaster
- https://github.com/evilsocket/opensnitch
- https://github.com/GyulyVGC/sniffnet
- https://github.com/objective-see/LuLu
- https://github.com/DevLM7/PyFire--Intelligent_Firewall_Manager
- https://github.com/bennettyardley/python-firewall

### Commercial and Closed-Source Peers
- https://tinywall.pados.hu/features.php
- https://www.glasswire.com/features/
- https://www.malwarebytes.com/windows-firewall-control
- https://www.netlimiter.com/products/netlimiter
- https://www.obdev.at/products/littlesnitch/index.html

### Community and Issue Signal
- https://github.com/henrypp/simplewall/issues?q=feature
- https://github.com/tnodir/fort/issues?q=feature
- https://github.com/evilsocket/opensnitch/issues?q=feature
- https://github.com/GyulyVGC/sniffnet/issues?q=feature
- https://github.com/safing/portmaster/issues?q=feature

### Platform APIs and Standards
- https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust

### Dependencies and Security
- https://pypi.org/project/psutil/
- https://pypi.org/project/PyQt5/
- https://pypi.org/project/requests/
- https://pypi.org/project/pywin32/
- https://osv.dev/list?ecosystem=PyPI&q=requests

## Open Questions
- None block prioritization. Firewall, service, event-log, and packaging items still need implementation-time validation on an admin Windows 10/11 host.
