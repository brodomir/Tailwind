# Tailwind — Multi-Vendor Network Control-Plane Simulator

Tailwind is a browser-based, multi-vendor network routing, switching, security, and path-verification simulator. It converges control-plane routing tables (RIB/FIB) in a Web Worker, visualizes topologies on an interactive canvas, traces forward and return packet paths with asymmetric-routing detection, and generates/imports vendor-native CLI configurations.

---

## Key Features

- **15 Vendor & Cloud Profiles** ([`src/engine/vendorProfiles.ts`](src/engine/vendorProfiles.ts)):
  - **Appliances / Routers / Firewalls**: Cisco IOS-XE, Cisco NX-OS, Cisco SD-WAN (Viptela), Palo Alto PAN-OS, Palo Alto Prisma SD-WAN (ION), Forcepoint NGFW (FRR), Arista EOS, Juniper Junos, MikroTik RouterOS, Fortinet FortiGate.
  - **Cloud / WAN Abstractions**: MPLS WAN Cloud (`mpls-cloud`), Internet Transit / DIA (`internet-cloud`), AWS Transit Gateway (`aws-cloud`), Azure Virtual WAN (`azure-cloud`), Google Cloud Router (`gcp-cloud`).
  - **Vendor-Gated Capabilities**: Inspector controls, protocol options, LAG modes (LACP / PAgP / Static), FHRP (HSRP / VARP / VRRP), cluster modes (vPC, MLAG, FGCP, PAN-OS HA/HSCI, Forcepoint CVI), and terminology adapt automatically to each vendor.
- **Control-Plane Protocols**:
  - **IGPs & Static**: Connected, Static (with IP SLA tracking), OSPF / OSPFv3 (areas, stub/NSSA, auth, custom timers, sham-links), EIGRP (dual feasible successors, variance, custom timers), IS-IS (L1/L2), RIPv2.
  - **BGP**: eBGP / iBGP, route reflectors, confederations, ECMP multipath (`maxPaths`), communities, AS-path regex, AIGP (RFC 7311), RPKI ROA validation, FlowSpec, Graceful Restart, BFD.
  - **Overlays, WAN & Switching**: Cisco SD-WAN (OMP / TLOC / TLOC-Extension / AAR SLA), LISP (EID/RLOC), VXLAN BGP EVPN, MPLS LDP / SR-MPLS / MPLS L3VPN, 802.1Q sub-interface multiplexing, LACP / PAgP / Static Port-Channels, IEEE 802.1w RSTP, LLDP, PIM-SM.
  - **VRFs, Policy & Security**: Multi-VRF routing & route leaking, Prefix-Lists, Route-Maps (including route tags), PBR / PBF / FBF, Zone-based ACLs, pre-routing DNAT, post-routing SNAT, NAT64, uRPF, 802.1X, 802.1AE MACsec.
- **Live Packet Tracer & Path Test Matrix**:
  - Forward and return path computation (`returnTrace`), asymmetric routing detection (`ASYMMETRIC ROUTING` badges and directional `<animateMotion>` packet animation on the canvas), path SLA (latency, jitter, loss, PMTUD), and N-1 link failover matrix.
- **Workspaces, Import & Export**:
  - Built-in preset topologies (including **Cisco MPLS + DMVPN** with 2 DCs, 9 dual-router branches, ECMP, Internet breakout, and asymmetric routing demo, plus **Dual-Homed BGP & OSPF ECMP**).
  - Save/rename custom workspaces in `localStorage`, share topologies via compressed URL hash, paste or upload `.cfg` / `.txt` / `.yaml` / `.json` configs, and export `.zip` automation bundles, `.svg` diagrams, or `.json`.

---

## Quick Start

### Prerequisites

- Node.js 20+ and npm (for local dev/build) or any modern Chromium/Firefox/Edge/Safari browser (for Docker/static hosting)

### System Requirements & Limits

- **No VM / QEMU Overhead**: Tailwind simulates control-plane routing mathematically in a browser Web Worker rather than booting router VMs, so it runs comfortably on any standard machine (4 GB+ RAM).
- **Typical Topology Footprint**: A 25-node multi-vendor topology converges in milliseconds and uses ~100–250 MB of browser tab memory. At **150–250+ nodes**, React Flow canvas rendering and the **N-1 Failover** matrix (which re-runs the solver once per link) become the primary performance factors.
- **Engine & Browser Limits**:
  - Control-plane convergence is capped at **16 iterations** per solve.
  - Undo/redo history retains up to **30 topology snapshots**.
  - Saved workspaces are subject to your browser's `localStorage` quota (typically **5–10 MB** per origin).

### Workspace Persistence

Custom workspaces are stored locally in your browser's **`localStorage`** under the key **`rib-sim-workspaces-v1`** (and theme preference under `rib-sim-theme-v1`). Because `localStorage` is scoped per browser and origin (for example, `localhost:5173` vs `localhost:8080` in Docker), workspaces are not written to disk or synced across browsers. Use **Export `.json`** or **Share** (compressed URL hash) to back up or transfer workspaces.

### Install & Run Locally

```bash
npm install
npm run dev
```

### Build & Test

```bash
npm run build   # Type-checks (tsc -b) and builds production bundle (vite build)
npm test        # Runs the Vitest suite (vitest run)
```

---

## Docker Deployment

Because Tailwind is a 100% client-side static Vite/React application, you can package it with a two-stage `Dockerfile`:

```dockerfile
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

```bash
docker build -t tailwind-net-sim .
docker run -d -p 8080:80 --name tailwind tailwind-net-sim
```

---

## Documentation

- [Architecture & Engine Reference](docs/ARCHITECTURE.md)
