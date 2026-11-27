# Architecture & Engine Reference

## Project Structure

```text
src/
├── App.tsx                     # Root application layout (TopBar, TopologyCanvas, InspectorPanel, CliOutputPanel)
├── components/
│   ├── TopBar.tsx              # Presets, workspaces (new/save-copy/rename/delete), trace bar, Path Tests drawer, import/export
│   ├── TopologyCanvas.tsx      # React Flow canvas, floating handles, directional outbound/return packet animations, Path Audit bar
│   ├── InspectorPanel.tsx      # Vendor-gated device, interface, static/PBR, protocol, VRF, policy, ACL/NAT, and link editors
│   └── CliOutputPanel.tsx      # Vendor CLI show-output, RIB, diff, neighbor, editable running-config + live validation, and JSON viewer
├── data/
│   └── presets.ts              # Built-in preset topologies and verification pathTests
├── engine/
│   ├── solver.ts               # Control-plane solver (solveTopology), packet tracer (tracePacket), runPathTestSuite, runFailoverMatrix
│   ├── standards.ts            # RSTP/LLDP, LAG negotiation (LACP/PAgP/Static), MPLS/SR LFIB, PIM-SM, FlowSpec, NAT64, EVPN
│   ├── policy.ts               # Prefix-list matching, route-map evaluation, RPKI ROA origin validation
│   ├── security.ts             # Zone/port/CIDR ACL evaluation, pre-routing DNAT, post-routing SNAT
│   ├── ipMath.ts               # IPv4/IPv6 CIDR parsing, subnet math, address-family detection
│   ├── radixTrie.ts            # IPv4 & IPv6 longest-prefix-match (LPM) tries
│   ├── vendorProfiles.ts       # VENDOR_METADATA, VENDOR_DEFAULT_AD, VENDOR_CAPABILITIES
│   ├── formatters.ts           # Vendor CLI outputs (show ip route, etc.) and running-config generators
│   ├── importer.ts             # Multi-vendor CLI / Terraform HCL / YAML / JSON config parser and live running-config validator (validateRunningConfig)
│   ├── firewallImporter.ts     # Multi-vendor & cloud firewall/ACL rule importer (PAN-OS, FortiGate, Check Point, Cisco, Junos, VyOS, MikroTik, AWS/Azure/GCP)
│   ├── diff.ts                 # Snapshot RIB diff computation
│   ├── exportBundle.ts         # Automation .zip bundle builder
│   └── __tests__/              # Vitest test suites
├── store/
│   └── useSimStore.ts          # Zustand store, undo/redo history, localStorage workspaces, Web Worker solve trigger
├── types/
│   └── network.ts              # Core TypeScript interfaces (TopologyState, NodeConfig, InterfaceConfig, LinkConfig, etc.)
└── workers/
    └── simWorker.ts            # Web Worker running solveTopology off the main thread
```

---

## Control-Plane Convergence (`solveTopology`)

`solveTopology` in [`src/engine/solver.ts`](src/engine/solver.ts) computes converged per-node, per-VRF RIBs and diagnostics:

1. **HA / Cluster State**: Evaluates PAN-OS HA/HSCI, FortiGate FGCP, and Forcepoint NGFW Cluster active/standby roles.
2. **L2 Switching & LAGs** ([`src/engine/standards.ts`](src/engine/standards.ts)):
   - Validates LACP (`active`/`passive`), PAgP (`desirable`/`auto`), and Static (`on`) member pairs via `negotiateLagPair`.
   - Runs IEEE 802.1w RSTP (`computeStpAndLldp`) while keeping negotiated Port-Channel bundle members forwarding together.
3. **Adjacencies (`buildAdjacencies`)**:
   - Aggregates active LAG member links onto logical `Port-channel<N>` / `po<N>` / `ae<N>` / `bond<N>` interfaces.
   - Multiplexes 802.1Q sub-interfaces (e.g., `Gi0/0.100`, `Port-channel1.100`) over shared physical links while enforcing `allowedVlans`, `dot1xState`, `macsecEnabled`, and MTU checks.
   - Bridges L3 endpoints across Layer 2 switches/trunks sharing the same VLAN.
4. **Protocol Engines**:
   - Iteratively converges Connected, Static (with IP SLA tracking), OSPF/OSPFv3, EIGRP, IS-IS, RIPv2, BGP (with multipath ECMP up to `node.maxPaths`), VRF route leaking, redistributions, and Cisco SD-WAN OMP/TLOC overlays.
   - Ranks candidate routes per `(af, vrf, prefix)` using vendor-specific Administrative Distances (`VENDOR_DEFAULT_AD`) and protocol metrics.
5. **Post-Convergence Tables**: Generates MPLS/SR LFIBs, PIM-SM mroutes, and EVPN DF/BMP state.

---

## Packet Tracing & Asymmetric Routing (`tracePacket`)

`tracePacket` walks the converged forwarding tables hop-by-hop:

- **Ingress Checks & Overlay Decap**: Overlay decapsulation on remote tunnel endpoints (restoring inner destination IP and VRF) runs before pre-routing DNAT, NAT64, RFC 3704 uRPF (strict/loose), FlowSpec, ACL, and SNAT so security policies evaluate inner traffic accurately.
- **Forwarding Lookup**: IPv4/IPv6 LPM via `BinaryRadixTrie` / `BinaryRadixTrie6`, followed by PBR/PBF/FBF, FlowSpec, and SD-WAN SLA steering.
- **Security & Encapsulation**: Zone-aware ACL evaluation, post-routing SNAT, and overlay encapsulation/decapsulation (MPLS L3VPN, LISP, VXLAN EVPN, OMP, GRE, IPsec, MACsec) with non-default VRF restoration.
- **MPLS / DIA Cloud Handling**: `mpls-cloud` and `internet-cloud` nodes bypass uRPF/FlowSpec/ACL drops and automatically accept & deliver traffic when no more-specific transit route exists in their RIB.
- **Return Path & Asymmetry**: On delivery, `tracePacket` traces the reverse flow (`returnTrace`) and sets `asymmetricPath: true` if the return node sequence differs from the forward path. [`TopologyCanvas.tsx`](src/components/TopologyCanvas.tsx) animates outbound hops (`#f59e0b` / VRF color) and return hops (`#06b6d4` cyan) with directional `<animateMotion>` markers.

---

## Verification & Testing

Run the full TypeScript build and Vitest suite:

```bash
npm run build
npm test
```

The test suites under `src/engine/__tests__/` cover:

- Multi-vendor control-plane convergence, AD overrides, HA/clustering, and packet traces (`solver.test.ts`, `multinational.test.ts`, `multinationalPaths.test.ts`)
- Policy engine (`policy.test.ts`), SD-WAN (`sdwan.test.ts`), advanced overlays (`advancedFeatures.test.ts`)
- Standards, 802.1Q sub-interfaces, LACP/PAgP Port-Channels, MPLS/DIA auto-accept, `cisco-mpls-dmvpn`, and `bgp-ecmp-lab` (`standards.test.ts`)
- Cross-module bug-hunt regression suite and full 9-preset beta validation (`moduleAudit.test.ts`, `betaValidation.test.ts` — 121 tests total)

---

## Persistence, System Requirements & Limits

- **Workspace Storage** ([`src/store/useSimStore.ts`](../src/store/useSimStore.ts)):
  - Custom workspaces (`SavedWorkspace[]`) are persisted in browser `localStorage` under `rib-sim-workspaces-v1` (theme under `rib-sim-theme-v1`).
  - Storage is local to the browser and origin (host + port) and bounded by the browser's `localStorage` quota (~5–10 MB). Use **Export `.json`** or **Share** URLs for portable backups.
- **Resource Usage & Engine Bounds**:
  - Because Tailwind runs an analytical control-plane solver inside [`simWorker.ts`](../src/workers/simWorker.ts) without QEMU/VM virtualization, a 4 GB+ RAM machine easily handles 100–200+ nodes.
  - `solveTopology` caps global protocol convergence at **16 iterations**, and the Zustand store caps undo/redo history at **30** `structuredClone` snapshots.
  - `runFailoverMatrix` re-runs `solveTopology` once per link in the topology, so very large meshes (200+ links) will take proportionally longer when running N-1 failover.
