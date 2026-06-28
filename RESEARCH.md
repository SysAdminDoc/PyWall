# Research - PyWall

## Executive Summary
PyWall is a Windows-only PyQt5 firewall and network monitor that already combines Windows Firewall rule management, live connection/history views, DNS/hosts blocking, threat heuristics, and a new headless service mode. The highest-value direction is to make the current trust boundary harder and more honest before adding more surface: harden command/IPC paths, reconcile README claims with implemented components, replace fragile large-table widgets with model-backed views, and turn service/history data into reliable app identity and forensic workflows. Top opportunities: harden PowerShell rule creation, lock down service IPC, add automatic rollback before destructive firewall actions, remove README/component drift, pin dependencies and stop elevated runtime installs, resolve svchost/UWP/parent-process identity, move GeoIP off plaintext third-party HTTP, expand tests around firewall/service behavior, add accessibility/i18n foundations, and formalize DB migrations.

## Product Map
- Core workflows: monitor live TCP/UDP connections, create/delete/enable Windows Firewall rules, manage hosts-file/domain blocklists, review SQLite history, run headless service monitoring/auto-blocking.
- User personas: Windows power users, IT admins, privacy/security hobbyists, small-fleet operators who want local control without a commercial firewall suite.
- Platforms and distribution: Windows 10/11, Python 3.10+, PyQt5 GUI, optional PyInstaller spec, Windows Service via pywin32; source-first distribution today.
- Key integrations and data flows: psutil connection/process sampling, PowerShell NetSecurity/netsh/auditpol, Windows Security event-log blocked events, SQLite logs, ipinfo/ip-api/Google favicon enrichment, local named pipe `\\.\pipe\PyWallService`.

## Competitive Landscape
- simplewall: WFP-backed filtering, portable mode, logging, IPv6, localization, WSL/Store/service support. Learn its strict separation from Windows Firewall rule CRUD and its system-rule UX; avoid requiring a signed driver until the current PowerShell backend is hardened.
- Fort Firewall: WFP driver, parent-process rules, svchost service filtering, application groups, speed limits, traffic statistics, Crowdin localization. Learn its app-identity and quota model; avoid HVCI/driver deployment complexity as the first move.
- Portmaster: local core service plus UI, per-app settings, Secure DNS, signed updates, blocklist/GeoIP updates, network history and bandwidth visibility. Learn the service/UI split and privacy-by-default defaults; avoid Electron-weight UI and paid-network features.
- OpenSnitch: interactive outbound prompts, centralized multi-node GUI, blocklists, SIEM integration, translations. Learn first-connection decision workflows and remote-node observability; avoid chatty prompts without timeout/default policies.
- TinyWall: no-popup security-fatigue stance, learning mode, tamper protection, password lockdown, timed rules, boot-time filtering, IPv6, WSL/UWP support. Learn no-popup onboarding and lockdown modes; avoid hidden denials without strong recovery affordances.
- GlassWire: graph/history, discreet alerts, device/network change alerts, ask-to-connect, lockdown, remote management, bidirectional firewall profiles. Learn timeline and visual forensic affordances; avoid paywall-shaped bloat before data correctness.
- Sniffnet: PCAP import/export, adapter filters, ASN/GeoIP, protocol/service labels, custom notifications, blacklists, multi-platform signed packages, broad translations. Learn exportable evidence and protocol labeling; avoid expanding beyond Windows until core security paths are stable.
- p-yukusai/PyWall and Easy Firewall: shell/context-menu app blocking around native Windows Firewall. Learn right-click executable/folder workflows; avoid installer/shell extension work until PyWall's current advertised plugin/scheduler gap is closed.

## Security, Privacy, and Reliability
- Verified: `PyWall.py:707-716`, `PyWall.py:720`, and `PyWall.py:724` build PowerShell commands with interpolated display names, paths, descriptions, ports, and addresses; malformed values can break rules or execute unintended PowerShell. Add escaping/argument construction and regression tests before expanding rule editing.
- Verified: `PyWall.py:1185-1196` stores a service IPC token as a plain file and `PyWall.py:1274-1280` creates the named pipe with default security attributes. Add explicit local-admin/current-user ACLs on the token and pipe.
- Verified: `PyWall.py:2596` runs `netsh advfirewall reset` directly from the GUI; `PyWall.py:2600` can export config, but reset does not auto-export first. Add automatic pre-reset export, rollback action, and status/log evidence.
- Verified: `PyWall.py:991` uses plaintext `http://ip-api.com/batch`; move GeoIP to HTTPS provider support and/or MaxMind local MMDB to avoid leaking connection metadata over cleartext.
- Verified: `requirements.txt` has unpinned runtime dependencies and `_bootstrap()` in `PyWall.py:85-117` installs packages from an elevated process. Pin app dependencies, document setup, and disable runtime install in normal GUI/service launch.
- Verified: `README.md:97` and `README.md:222-227` advertise scheduling, network profile auto-switching, anomaly/reputation managers, and plugin management classes that are not present in `PyWall.py`. Either implement minimum viable components or revise docs in the same delivery.

## Architecture Assessment
- `PyWall.py` is a single large module; `FirewallEngine`, `ServiceIPCServer`, `HeadlessMonitor`, `ConnDB`, enrichment workers, and GUI tabs should be split only when touching those areas for tests or hardening.
- `QTableWidget` is used across live connections, firewall rules, history, logs, diagnostics, and security tabs (`PyWall.py:1690`, `1775`, `2042`, `2179`, `2493`); existing roadmap already calls for model-backed views, and research supports making that a performance/reliability priority.
- App identity is shallow: live rows show process/path/PID, but there is no svchost service resolution, UWP package identity, parent-process ancestry, signer display, or related executable grouping comparable to Fort/TinyWall/simplewall.
- Testing is currently one static AST suite in `tests/test_service_mode_static.py`; there are no unit tests for PowerShell command construction, IPC authorization, DB migrations, hosts cleanup, threat detectors, or GUI model behavior.
- Migration strategy is ad hoc (`ConnDB` checks columns inline); add `PRAGMA user_version` migrations and tests before adding more history/session tables.
- Accessibility/i18n foundations are absent: no Qt translation catalog flow, no visible `setAccessibleName` usage, and dense table status is color-heavy.

## Rejected Ideas
- WFP driver backend now: already present in the existing roadmap and valuable later, but signed-driver/HVCI complexity should wait until PowerShell command safety and service IPC are hardened.
- Full multi-host rule push now: existing roadmap covers fleet work; it depends on authenticated remote transport, schema stability, and service trust hardening.
- Commercial-style VPN/privacy network: Portmaster's SPN is a separate paid network product and does not fit PyWall's local Windows Firewall manager shape.
- Mobile client: GlassWire has Android, but PyWall's core control plane is Windows-specific and current gaps are local reliability/security.
- Deep TLS MITM by default: existing roadmap correctly marks opt-in MITM/SNI exploration; default interception would contradict PyWall's local-control/privacy posture.
- GitHub Actions build automation: many competitors use hosted CI, but project rules require local builds/releases, so workflow creation is not recommended.

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
- https://github.com/p-yukusai/PyWall
- https://github.com/DevLM7/PyFire--Intelligent_Firewall_Manager
- https://github.com/bennettyardley/python-firewall
- https://github.com/pdulvp/easy-firewall

### Commercial
- https://tinywall.pados.hu/features.php
- https://www.glasswire.com/features/
- https://www.malwarebytes.com/windows-firewall-control
- https://www.netlimiter.com/products/netlimiter

### Platform and Dependencies
- https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157
- https://pypi.org/project/psutil/
- https://pypi.org/project/PyQt5/
- https://pypi.org/project/requests/
- https://pypi.org/project/pywin32/

## Open Questions
- None that block prioritization; implementation should verify current Windows behavior on a real admin Windows 10/11 host before shipping firewall, service, and event-log changes.
