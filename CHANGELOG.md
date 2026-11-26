# Changelog

All notable changes to the **Multi-Vendor Control-Plane & RIB Simulator** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses pre-release semantic versioning (`v0.2.0-beta.x`).

---

## [v0.2.0-beta.8] - 2026-11-26

### Fixed
- **Control-Plane Solver & Packet Tracer (`solver.ts`, `policy.ts`, `security.ts`, `standards.ts`)**:
  - **OSPF / OSPFv3**: Fixed redistributed LSA self-installation and convergence oscillation; moved `totally-stubby` and `nssa no-summary` filtering after Area 0 `intra` → `inter` promotion; restricted `areaRanges` summarization to intra-area LSAs; excluded `adminDown` nodes from virtual-links and sham-links; added `leakedFromVrf: 'default'` and MPLS tunnel encap/decap for non-default VRF OSPF sham-links (even without `mplsVpn.enabled`); added local-origin triangle-loop prevention across normal, virtual-link, and sham-link propagation.
  - **BGP**: Excluded `adminDown` nodes from `solveBgp`; required reciprocal non-shutdown `remotePeerBack`; added address-family (`peerAf`) and local-VRF scoping to `remotePeerBack` and `solveTopology` neighbor status (fixing dual-stack and overlapping PE-PE/PE-CE VRF peering); canonicalized IPv6 peer IPs; supported `localAs` & `confederationId` in session matching and aligned `isEbgp` status; moved AS-path loop prevention after `asOverride` & `removePrivateAs` and added `confederationId` + `asSet` loop checks; blocked `local-as` across confederation eBGP; pruned stale withdrawn routes on `maxPrefixes` / best-path withdrawal and gated `defaultOriginate` behind `maxPrefixes`; added `medMissing` tracking so `bgp.medMissingAsWorst` works end-to-end.
  - **EIGRP / IS-IS / Overlays / Switching / HA**: Added 3-hop triangle-loop prevention in EIGRP and IS-IS; updated IS-IS L2→L1 leaked entries when a lower-metric L2 path converges and required `rLsp.prefixLen >= lp.prefixLen`; prevented EVPN and MPLS-VPN from re-advertising overlay-learned routes in 3+ VTEP/PE fabrics; cascaded `shutdown: true` from down parent links/interfaces to child sub-interfaces; rejected shutdown explicit interfaces and recursive `Null0`/`blackhole` in `resolveNextHop`; canonicalized `lagBundles` keys for oppositely directed LAG links; partitioned STP (`computeStpAndLldp`) into independent connected L2 islands; scoped PIM-SM OIFs by VRF and skipped `adminDown` nodes; implemented Forcepoint Cluster `mode: 'standby'` Active/Standby election, FHRP cross-VRF keying & IPv6 `/128` VIPs, VRF leak bounce-back prevention & chained `leakedFromVrf` preservation, SD-WAN OMP same-`siteId` loop prevention & multi-color failover, and `cloudflare-mwan` cloud classification.
  - **Policy & Security**: Allowed valid lazy regex quantifiers (`+?`, `*?`, `{m,n}?`) in `safeCompileRegex`; translated Cisco/FRR `_` AS-path delimiter in `evaluateRouteMap`; validated NAT `translatedIp` address family matches `dstIp`/`srcIp`.
- **Importers, Firewall Rules & Formatters (`importer.ts`, `firewallImporter.ts`, `formatters.ts`)**:
  - Parsed full 32-bit dotted-quad OSPF areas via `ipToUint32` across all 6 vendor parsers and formatted them with `uint32ToIp`.
  - Fixed Cisco/NX-OS/IOS-XE secondary IP addresses, VRF CIDR static routes (`ip route vrf <vrf> <cidr> <nh>`), `Null0`/`blackhole` static routes, VRF-scoped `passive-interface default`, unindented global `ip route` exiting `vrf context`, indented ` !` separators inside `router bgp`, `address-family ipv4/ipv6 unicast vrf`, classful RIP/EIGRP `network` prefixes (including `0.0.0.0/0`), LISP `pitr`/`petr`/`pxtr` round-trip, `maximum-paths`, OSPF `redistribute` metric/type after `subnets`, placeholder FHRP groups when `priority` precedes `ip`, and `autoFormatRunningConfig` indentation for YAML, Cisco SD-WAN, `ip access-list`, `mpls ip`, `ip route`, and `router rip` `version 1|2`.
  - Fixed Junos IS-IS vendor classification (preventing VyOS misclassification), placeholder `0.0.0.0/0` → `''` cleanup, PAN-OS bracket `virtual-router ... interface [ ... ]` and `description` keyword leakage in ACLs, Cisco ACL inline `! ...` comment stripping, FortiGate default static route (`0.0.0.0/0`), Check Point Gaia duplicate BGP peers, MikroTik quoted `/ip vrf add interfaces="..."`, GCP Terraform `target_tags`, AWS `transit_gateway_id` and `route_*` blackhole routes, and VRF-scoped OSPF/BGP redistribution & aggregate round-trip in `formatRunningConfig`.
  - Fixed LFIB/STP/LLDP CLI column spacing and IPv6 `::/0` formatting across all CLI formatters.
- **Store, Canvas & Inspector UI (`useSimStore.ts`, `TopologyCanvas.tsx`, `InspectorPanel.tsx`, `TopBar.tsx`, `CliOutputPanel.tsx`)**:
  - Added atomic `deleteSelection(nodeIds, linkIds)` for single-step Undo on canvas `Delete`/`Backspace` multi-delete; matched traced/return canvas edges by hop `egressInterface` (skipping `adminDown` links and coloring return loops red).
  - Propagated interface rename and cleaned up interface delete across all name-based references (`updateSource`, `staticRoutes[].interfaceName`, `pbrRules`, `sdwanSla`, `unnumberedSource`, `parentInterface`, `tlocExtension`, `mlag.localInterface`); prevented duplicate interface IDs in `hydrateMatchingNodes`/`applyParsedNodeConfig` and duplicate interface names on **Add Interface**.
  - Preserved `vendor`, `vrfRouterIds`, `maxPaths`, `mpls`, `switching`, `multicast`, `timing`, `telemetry`, `sdwanSla`, `nat64Rules`, `vplsInstances`, and `oam` in `applyParsedNodeConfig`/`hydrateMatchingNodes`, and allowed deleting optional interface CLI attributes in the Running Config editor.
  - Cleaned up all orphaned VRF/Prefix-List/Route-Map/Track references on delete/rename, rejected duplicate Track IDs, fixed Ant Design `<Input>` reset on invalid blur (`inputResetNonce`), preserved bulk-imported links & reported 0-match hydrate errors in `TopBar`, and cleared stale `traceSrcInterfaceId`/`traceSrcIp` on VRF change and inline RIB **Trace**.
- **Tests**: Expanded unit/integration test coverage to **114 passing tests** across 9 test files.

---

## [v0.2.0-beta.7] - 2026-11-25

### Changed
- **Node.js 24 LTS & CI/Docker Upgrade**:
  - Upgraded `Dockerfile` to `node:24-alpine` and `.github/workflows/ci-release.yml` to `actions/checkout@v5`, `actions/setup-node@v5`, and `node-version: 24`.
  - Updated `README.md` and `docs/ARCHITECTURE.md` to reflect all **22 Vendor & Cloud Profiles**, Node.js 24+, and the expanded **109-test** suite.

### Fixed
- **Control-Plane Solver & Packet Tracer (`solver.ts`)**:
  - **OSPF / OSPFv3**: Propagated IPv6 `adj.remoteIp6` next-hops on dual-stack links; enabled ECMP & lower-cost ABR election for Stub / Totally-Stubby / NSSA default routes (`0.0.0.0/0`); computed `remoteIsAbr` on the advertising router to prevent non-ABR inter-area leaking.
  - **BGP**: Evaluated `aggregate-address` inside the convergence loop so BGP-learned routes originate aggregates instead of being blackholed by `summaryOnly`; fixed RFC 4456 Route Reflector client reflection, default Router-ID Cluster-ID loop prevention, and reflected `NEXT_HOP` preservation; added RFC 5065 `confedAsPath` loop prevention; added IPv6 numeric peer-IP tie-breaking (`ip6ToBigInt`), AF isolation, and `::/0` `defaultOriginate`; fixed BGP redistribution route-map `matchTag` & community actions; evaluated outbound eBGP route-maps pre-prepend (`^$`) and blocked `setLocalPref` leaks across eBGP.
  - **EIGRP / IS-IS / RIP / Static**: Sorted internal EIGRP routes ahead of external routes (`AD 90` vs `AD 170`); filtered IPv6 routes out of EIGRP/RIP redistribution and generated per-VRF EIGRP summary `Null0` routes for connected subnets; fixed IS-IS ECMP keying, L1→L2 prefix promotion, and IPv6 link guards; added `leakedFromVrf: 'default'` for non-default VRF static `globalNextHop` and OMP/LISP/EVPN overlay routes; added IPv6 `cidr6` support to L2 switch bridging.
  - **Data Plane & Security**: Moved loop detection after DNAT/NAT64 (keyed by `nodeId|vrf|dstIp`) to allow legitimate hairpins; filtered `blackhole`/`Null0` routes out of loose uRPF (RFC 3704); added recursive next-hop resolution for FlowSpec `redirect`; allowed PBR `blackhole`/`Null0` next-hops; prevented SD-WAN SLA steering from overriding PBR/FlowSpec redirects and added IPv6 SLA support; added MPLS L3VPN encapsulation and non-default VRF restoration on overlay decapsulation; preserved path latency/jitter/loss/MTU/IPFIX on cloud gateway delivery; used ephemeral client ports (`49152`) on return-path traces and added two-way IPsec underlay reachability warnings.
- **Standards, Diff, Vendor Profiles & Presets (`standards.ts`, `diff.ts`, `vendorProfiles.ts`, `presets.ts`)**:
  - Filtered `adminDown` nodes and `shutdown` interfaces from STP; replaced lexicographic `localeCompare` with numeric priority & IPv4 Router-ID tie-breakers in STP and EVPN DF; added IPv6 `parseCidr6` support for SRv6 PHP; added LPM sorting and `adminDown` guard for RSVP-TE LFIB; scoped multicast RPF lookups by VRF; guarded FlowSpec on `bgp.enabled` and EVPN DF on `evpn.enabled !== false`.
  - Expanded RIB diff fingerprinting (`diff.ts`) to capture BGP attributes, IS-IS level, tag, TLOC, EVPN VNI, and cloud next-hop changes.
  - Exposed `'lisp'` in `adProtocols` for `cisco-ios-xe` and `cisco-nx-os`.
  - Fixed `global-multinational` `tlocExtension` placement on `uk-sdwan1` (converging `uk-sdwan2` OMP routes) and `full-showcase` HSRP `shf-2` out-of-subnet VIP.
- **Importers, Firewall Rules & Formatters (`importer.ts`, `firewallImporter.ts`, `formatters.ts`)**:
  - Added Arista EOS `mlag configuration` & `mlag <id>` round-trip, L2 interface retention, and `arista-eos` vendor detection.
  - Added Cisco/FRR `ip prefix-list`, route-map (`match ip address prefix-list`, `set metric`, `set as-path prepend`, `set distance`, multi-community `set community`), `ptp mode`, and static route `track`/`tag` parsing; deferred `neighbor ... route-map` resolution and VRF-scoped `add-path`/`disable-connected-check`; fixed `validateRunningConfig` false positive on `ip flow-export destination`.
  - Fixed JunOS subinterface (`ge-0/0/0.100`) formatting/import, `.unit` IPv6 shorthand, OSPF/IS-IS/RIP ordering, and `formatJunosFibCli` alignment; fixed FortiGate nested `config` blocks, `passive-interface` ordering, and static `distance`; fixed PAN-OS named `peer-as` & BGP `router-id`; fixed VyOS alphabetical `nexthop-self`, interface ordering, and IS-IS/RIP detection; fixed Check Point & MikroTik ordering/quoted interfaces; preserved GCP `vpn-tunnel` `interfaceName`, stopped per-route `priority` from overwriting `defaultRoutePriority`, and preserved Azure `blackholeCidrs` on round-trip.
  - Fixed quoted space-containing names in PAN-OS/FortiGate/Check Point ACLs, trailing FortiGate policy flush, Cisco standard ACLs/source ports/sequence numbers, two-pass JunOS address-book resolution, VyOS `tcp_udp` & rule-number `seq`, multi-line MikroTik `/ip firewall filter`, and AWS `from_port = 0` / egress `dstCidr` / single-line GCP `allow`/`deny` blocks.
- **Store, Canvas & Inspector UI (`useSimStore.ts`, `TopologyCanvas.tsx`, `InspectorPanel.tsx`, `CliOutputPanel.tsx`, `TopBar.tsx`)**:
  - Remapped internal `interfaceId` references in `duplicateNode`, `hydrateMatchingNodes`, and `applyParsedNodeConfig`; stripped dangling interface IDs in `deleteInterface`; normalized `Loopback` → `Lo` in `hydrateMatchingNodes`; preserved `traceSrcIp` in `setTraceParams`; terminated failed `Worker` instances before respawning.
  - Fixed canvas node and edge selection + `Delete`/`Backspace` deletion (with 18px invisible hit-target on `SubnetEdge`).
  - Fixed InspectorPanel Track Objects ID collisions, BGP Network Delete button alignment, Links tab deleted-interface guard, EIGRP `K:` input snap-back, and upgraded SD-WAN `Preferred Members`, BGP `Confed Peers`, and BGP `Communities` to `<Select mode="tags" />`.
  - Fixed `CliOutputPanel` running-config draft sync on save and `TopBar` multi-file import toast reporting `0 file(s)`.

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
