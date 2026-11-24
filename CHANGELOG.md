# Changelog

All notable changes to the **Multi-Vendor Control-Plane & RIB Simulator** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses pre-release semantic versioning (`v0.2.0-beta.x`).

---

## [v0.2.0-beta.5] - 2026-11-24

### Added
- **4 New Network Vendors** (`vendorProfiles.ts`, `formatters.ts`, `importer.ts`, `firewallImporter.ts`):
  - **Check Point Gaia** (`checkpoint-gaia`) — `clish` / `mgmt_cli` routing, interfaces, static routes, and firewall access-rule import/export.
  - **HPE Aruba AOS-CX** (`aruba-aos-cx`) — interfaces, OSPF, BGP, static routes, ACLs, and running-config round-trip.
  - **Cisco IOS-XR** (`cisco-ios-xr`) — `router ospf`, `router bgp`, `router static`, `ipv4 access-list`, and running-config round-trip.
  - **VyOS** (`vyos`) — `set interfaces`, `set protocols static/ospf/bgp`, `set firewall`, and running-config round-trip.
- **Multi-Vendor Firewall Security Rule Importer** (`src/engine/firewallImporter.ts`):
  - Imports firewall policies/ACLs into `aclRules` across all supported vendors (FortiGate `config firewall policy`, Palo Alto PAN-OS `set rulebase security rules`, Check Point Gaia `mgmt_cli add access-rule`, Cisco IOS-XE / NX-OS / IOS-XR / ASA / Arista / Aruba `access-list` & `ip access-list`, Juniper JunOS `set security policies`, VyOS `set firewall`, MikroTik `/ip firewall filter`, and Forcepoint), with address/service object resolution while preserving manual ACL editing in the Inspector.
- **Universal Config Whitespace & Smart-Quote Normalization** (`normalizeConfigLine`, `autoFormatRunningConfig`):
  - Automatically normalizes CRLF, tabs, non-breaking spaces, smart quotes (`“ ” ‘ ’`), and inconsistent indentation across all vendors during paste/import, plus a **Format** button in the Running Config modal.
- **OSPF Segment-Wide L2 DR/BDR Election**:
  - Evaluates `ospfPriority` (including `0` = `DROTHER`) and Router ID tie-breakers across all OSPF peers sharing the same Layer 2 broadcast segment (`FULL/DR`, `FULL/BDR`, `FULL/DROTHER`, `2WAY/DROTHER`), with Inspector controls and config round-trip.
- **Full Policy-Based Routing (PBR) Criteria & FortiGate Round-Trip**:
  - Extended `PbrRuleConfig` and Inspector UI with separate **In If** (`ingressInterface`) and **Out If** (`interfaceName`), **Src CIDR**, **Dst CIDR**, **Protocol**, and **Dst Port**.
  - Added FortiGate `config router policy` running-config formatting and import parsing.
- **Multi-Arch Docker Release Pipeline** (`.github/workflows/ci-release.yml`):
  - Builds and publishes `linux/amd64` and `linux/arm64` images to GHCR on `v*` tags.
- **Cross-Module Bug-Hunting Test Suite** (`src/engine/__tests__/moduleAudit.test.ts`):
  - Added automated audit coverage across `ipMath`, `radixTrie`, `security`, `diff`, `exportBundle`, `vendorProfiles`, `formatters`, `importer`, `firewallImporter`, `presets`, `useSimStore`, and `solver` (**9 test files, 104 tests**).

### Fixed
- **Policy-Based Routing (PBR) Engine (`solver.ts`, `useSimStore.ts`)**:
  - Fixed ingress/egress interface conflation where `rule.interfaceName` was matched against ingress and then used as egress (causing hairpin drops).
  - Fixed `tracePacket` dropping packets with no RIB route before evaluating PBR rules.
  - Added direct adjacency + recursive next-hop resolution and dead-link / `shutdown` interface fallback to the next PBR rule or main RIB.
  - Preserved and applied `pbrRules` in `applyParsedNodeConfig`.
- **Silent RIB Wipeout on Missing `maxPaths` (`solver.ts`, `formatters.ts`)**:
  - Fixed `Math.max(1, node.maxPaths)` evaluating to `NaN` when legacy/imported JSON omits `maxPaths`, which previously caused `.slice(0, NaN)` to return `[]` and drop all active routes.
- **ECMP Diff Blind Spot (`diff.ts`)**:
  - Fixed `computeRibDiff` overwriting multiple active ECMP entries for the same `vrf|prefix/prefixLen`, ensuring ECMP path additions, losses, and next-hop changes are always detected.
- **YAML Empty-Array Serialization (`exportBundle.ts`)**:
  - Fixed `topologyToYaml` emitting empty arrays (`staticRoutes`, `links`, `networks`, etc.) as empty strings `""` instead of valid YAML `[]`.
- **Protocol Edge Cases (`solver.ts`)**:
  - Fixed 5 control-plane edge cases across OSPF, BGP, and failover handling.

### Changed
- **Vite Bundle Code Splitting (`vite.config.ts`)**:
  - Split heavy UI dependencies (`antd`, `@xyflow/react`) into dedicated vendor chunks for faster loads.

---

## [v0.2.0-beta.4] - 2026-11-23

### Added
- UI version badge in `TopBar` driven by `VITE_APP_VERSION`.
- Architecture & Engine reference documentation (`docs/ARCHITECTURE.md`).

### Fixed
- Hardened simulation store and Web Worker synchronization (`useSimStore.ts`, `simWorker.ts`).
- Resolved React Error #300 hook-order issue in `CliOutputPanel`.

---

## [v0.2.0-beta.3] - 2026-11-23

### Fixed
- Fixed React Error #300 hook ordering in `CliOutputPanel` when switching presets.

---

## [v0.2.0-beta.2] - 2026-11-22

### Added
- Expanded routing engine, CLI output panel, and simulation store components.
- Added application screenshot to `README.md`.
- Increased CI timeout on full-preset failover validation tests.

---

## [v0.2.0-beta.1] - 2026-11-21

### Added
- Initial beta release of the Multi-Vendor Control-Plane & RIB Simulator with multi-vendor topology modeling, OSPF/BGP/EIGRP/IS-IS/RIP/Static routing, packet tracing, presets, and CLI output views.
