# Changelog

All notable changes to the **Multi-Vendor Control-Plane & RIB Simulator** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses pre-release semantic versioning (`v0.2.0-beta.x`).

---

## [v0.2.0-beta.6] - 2026-11-25

### Added
- **Major Cloud Expansion (22 Total Vendors)**:
  - Added **AWS Cloud WAN** (`aws-cloudwan`), **Oracle Cloud DRG** (`oci-cloud`), and **Cloudflare Magic WAN** (`cloudflare-mwan`) alongside upgraded **AWS Transit Gateway**, **Azure Virtual WAN**, and **Google Cloud Router** profiles.
  - **First-Class AWS VPC & TGW Route Tables**: Explicit target types (`igw`, `nat`, `tgw`, `pcx`, `vgw`, `vpce`, `blackhole`, `local`), automatic AWS NAT Gateway SNAT in `tracePacket`, Direct Connect > IPsec VPN preference, Appliance Mode, and `aws ec2 create-route` / Terraform HCL (`aws_route`, `aws_ec2_transit_gateway_route`, `aws_network_acl_rule`) import/export.
  - **First-Class Azure User Defined Routes (UDRs)**: Explicit Azure next-hop types (`VirtualAppliance`, `None`, `Internet`, `VnetLocal`, `VirtualNetworkGateway`), `UDR Overrides BGP` and `Disable BGP Route Propagation` controls, and `azurerm_route_table` / `azurerm_route` / `az network route-table` import/export.
  - **First-Class Google Cloud (GCP) VPC & Cloud Router**: Explicit next-hop types (`default-internet-gateway`, `cloud-nat`, `ilb`, `next-hop-address`, `vpn-tunnel`, `interconnect`, `vpc-peering`), numeric route priority (`0–65535`), `GLOBAL`/`REGIONAL` dynamic routing mode, **Private Google Access (PGA)** (`199.36.153.8/30`, `199.36.153.4/30`) + **On-Prem PGA BGP advertisement**, **Private Service Connect (PSC) / PSA** endpoints, **Network Connectivity Center (NCC) Hub**, and **Network Tags**.
  - **Native Cloud CLI & Aligned Output Tables**: Dynamic column-aligned CLI tables for `aws ec2 search-transit-gateway-routes`, `az network vhub route-table show`, `gcloud compute routers get-status`, `oci network drg-route-table`, and `cf-magic-wan routes list`.
  - **Cloud Routing Policy Inspector UI**: Tailored Inspector cards and route-table editors for AWS, Azure, GCP, OCI, and Cloudflare.
- **New Multi-Cloud Transit & Inspection Preset** (`multi-cloud-transit`):
  - On-prem FortiGate NGFW ↔ AWS TGW (Direct Connect + IPsec + NAT GW + Blackhole) + AWS Cloud WAN + Azure vHub (ExpressRoute + UDRs) + GCP Cloud Router (Interconnect + Cloud NAT + PGA + PSC + NCC) + OCI DRG + Cloudflare Magic WAN, with 13 built-in path tests.
- **Expanded Full Showcase Preset** (`full-showcase`):
  - Rebuilt into a 20-node, 20-link multi-vendor & multi-cloud enterprise fabric with VRFs, MPLS, DIA, Cloudflare SIA, FortiGate PBR, AWS/Azure/GCP, Juniper SRX, Check Point Gaia, Aruba AOS-CX, VyOS, ACLs, Zones, SNAT/DNAT, HA pairs, and 12 built-in path tests.
- **Example Path Traces Across All 9 Presets**:
  - Added verified `pathTests` to `enterprise-edge`, `multi-vrf-policy`, `hybrid-cloud-sdwan`, `dc-vpc-hsci`, `full-showcase`, and `multi-cloud-transit` (**66 total verified path traces**).

### Changed
- **Auto-Arrange & Preset Layout Overhaul (`useSimStore.ts`, `presets.ts`)**:
  - Rebuilt `autoLayoutTopology` with cloud-aware card widths (`420px` cloud / `340px` appliance), generous tier spacing (`330px` / `270px`), barycenter neighbor sorting, centered tiers, and handle reset.
  - Eliminated all cramped/overlapping node layouts across all 9 presets (including fixing 54 overlapping pairs in `global-multinational` and cramped branch rows in `cisco-mpls-dmvpn`).

### Fixed
- **Engine & Cloud Solver (`solver.ts`)**:
  - Fixed Azure `VnetLocal` UDR and AWS `local` static routes dropping in `tracePacket`.
  - Fixed Azure `udrOverridesBgp: false` AD tie against IPsec eBGP (`25` -> `30`).
  - Fixed IPv6-only interfaces skipping connected/local route installation and emitting false `Invalid CIDR` warnings.
  - Fixed `inferHostIpFromInterface` generating out-of-subnet IPs for `/29` and `/30` interfaces and added IPv6 fallback.
  - Enforced STP-blocked L2 ports in `tracePacket` and passed the actual delivery interface ID on `returnTrace`.
- **Importers, Formatters & Validator (`importer.ts`, `firewallImporter.ts`, `formatters.ts`)**:
  - Fixed FortiGate `config router bgp` leaving `bgp.enabled = false`.
  - Fixed `parseCloudConfig` overwriting Azure/GCP hostnames from secondary resources and nested `advertised_ip_ranges` descriptions.
  - Added `cloudflare_magic_transit_site` and `aws networkmanager` detection, fixed VyOS vs JunOS detection collision, and added Terraform HCL validation + brace-depth formatting in `validateRunningConfig` / `autoFormatRunningConfig`.
  - Fixed Azure CLI singular `--source-address-prefix` / `--destination-address-prefix` regex, MikroTik greedy unquoted `comment=`, PAN-OS ACL export dropping zones/services, and added NX-OS / IOS-XR / Aruba AOS-CX ACL header parsing.
- **UI, Store & Canvas (`useSimStore.ts`, `TopologyCanvas.tsx`, `CliOutputPanel.tsx`, `InspectorPanel.tsx`, `TopBar.tsx`)**:
  - Fixed `addNode` enabling OSPF on cloud vendors where the OSPF UI is hidden (cloud nodes now default to BGP enabled, OSPF disabled).
  - Fixed duplicate `Delete`/`Backspace` handler corrupting the Undo stack and leaking stale trace state on `deleteNode` / `createWorkspace`.
  - Fixed `South of...` (`traceSrcInterfaceId`) clear button being silently ignored and Path Test "Show on Canvas" dropping `srcInterfaceId`.
  - Replaced comma-stripping cloud CIDR `<Input>` fields with `<Select mode="tags" />` for smooth multi-CIDR entry.
  - Fixed `checkpoint-gaia` shield icon, `aws-cloudwan`/`cloudflare-mwan` label collision box sizing, blank `CliOutputPanel` tabs on node switch, duplicate copy timer, `â†”` mojibake, and `Escape` clearing traces while modals are open.

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
