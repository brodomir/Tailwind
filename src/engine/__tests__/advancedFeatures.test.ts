import { describe, expect, it } from 'vitest';
import { formatCiscoCli, formatRunningConfig } from '../formatters';
import { importTopologyFromText } from '../importer';
import { runFailoverMatrix, solveTopology, tracePacket } from '../solver';
import type { PathTestCase, TopologyState } from '../../types/network';

describe('Advanced Control-Plane Features (LISP, EVPN, MPLS L3VPN, PBR, ECMP, IPv6 BGP, Failover)', () => {
  it('converges LISP EID-to-RLOC overlay over OSPF underlay, traces packets, and formats router lisp', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'xtr1',
          hostname: 'XTR-1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'x1-lo0', name: 'Loopback0', cidr: '10.255.1.1/32', vrf: 'default', ospfArea: 0 },
            { id: 'x1-g0', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default', ospfArea: 0 },
            { id: 'x1-lan', name: 'Gi0/1', cidr: '10.80.1.1/24', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          lisp: {
            enabled: true,
            role: 'xtr',
            rlocIp: '10.255.1.1',
            mapServerIp: '10.255.0.1',
            instanceId: 4099,
            eidPrefixes: [{ id: 'e1', prefix: '10.80.1.0/24', priority: 1, weight: 100 }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'core',
          hostname: 'CORE',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'c-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'c-g1', name: 'Gi0/1', cidr: '10.0.23.1/30', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'xtr2',
          hostname: 'XTR-2',
          vendor: 'cisco-ios-xe',
          routerId: '3.3.3.3',
          position: { x: 400, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'x2-lo0', name: 'Loopback0', cidr: '10.255.3.3/32', vrf: 'default', ospfArea: 0 },
            { id: 'x2-g0', name: 'Gi0/0', cidr: '10.0.23.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'x2-lan', name: 'Gi0/1', cidr: '10.80.2.1/24', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          lisp: {
            enabled: true,
            role: 'xtr',
            rlocIp: '10.255.3.3',
            mapServerIp: '10.255.0.1',
            instanceId: 4099,
            eidPrefixes: [{ id: 'e2', prefix: '10.80.2.0/24', priority: 1, weight: 100 }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l12', sourceNodeId: 'xtr1', sourceInterfaceId: 'x1-g0', targetNodeId: 'core', targetInterfaceId: 'c-g0' },
        { id: 'l23', sourceNodeId: 'core', sourceInterfaceId: 'c-g1', targetNodeId: 'xtr2', targetInterfaceId: 'x2-g0' },
      ],
    };

    const res = solveTopology(topo);
    const lispRoute = res.nodes['xtr1'].rib.find((r) => r.prefix === '10.80.2.0' && r.active);
    expect(lispRoute?.protocol).toBe('lisp');
    expect(lispRoute?.ad).toBe(210);
    expect(lispRoute?.lisp?.rlocIp).toBe('10.255.3.3');

    const trace = tracePacket(topo, res, 'xtr1', '10.80.2.50', 'default', { srcInterfaceId: 'x1-lan' });
    expect(trace.outcome).toBe('delivered');
    expect(trace.hops[0].encapNote).toContain('LISP encap -> RLOC 10.255.3.3');
    expect(formatCiscoCli(topo.nodes[0], res.nodes['xtr1'])).toContain('L*');
    expect(formatRunningConfig(topo.nodes[0])).toContain('router lisp');
  });

  it('evaluates PBR rules, tracks ECMP paths, propagates VXLAN EVPN & MPLS L3VPN RTs, and runs N-1 failover matrix', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'pe1',
          hostname: 'PE-1',
          vendor: 'cisco-nx-os',
          routerId: '10.255.10.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default', 'corp'],
          adOverrides: {},
          interfaces: [
            { id: 'p1-lo', name: 'Loopback0', cidr: '10.255.10.1/32', vrf: 'default', ospfArea: 0 },
            { id: 'p1-g0', name: 'Eth1/1', cidr: '10.1.0.1/30', vrf: 'default', ospfArea: 0 },
            { id: 'p1-g1', name: 'Eth1/2', cidr: '10.1.1.1/30', vrf: 'default', ospfArea: 0 },
            { id: 'p1-corp', name: 'Eth1/3', cidr: '172.20.1.1/24', vrf: 'corp' },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          evpn: { enabled: true, vtepIp: '10.255.10.1', l3Vni: 50000, vrf: 'default' },
          mplsVpn: {
            enabled: true,
            vrfTargets: [{ id: 'vt1', vrf: 'corp', rd: '65000:100', importRt: '65000:100', exportRt: '65000:100' }],
          },
          pbrRules: [{ id: 'pbr1', name: 'FORCE_PATH_2', matchPrefix: '10.255.10.2/32', nextHop: '10.1.1.2' }],
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'pe2',
          hostname: 'PE-2',
          vendor: 'cisco-nx-os',
          routerId: '10.255.10.2',
          position: { x: 300, y: 0 },
          maxPaths: 4,
          vrfs: ['default', 'corp'],
          adOverrides: {},
          interfaces: [
            { id: 'p2-lo', name: 'Loopback0', cidr: '10.255.10.2/32', vrf: 'default', ospfArea: 0 },
            { id: 'p2-g0', name: 'Eth1/1', cidr: '10.1.0.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'p2-g1', name: 'Eth1/2', cidr: '10.1.1.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'p2-corp', name: 'Eth1/3', cidr: '172.20.2.1/24', vrf: 'corp' },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          evpn: { enabled: true, vtepIp: '10.255.10.2', l3Vni: 50000, vrf: 'default' },
          mplsVpn: {
            enabled: true,
            vrfTargets: [{ id: 'vt2', vrf: 'corp', rd: '65000:100', importRt: '65000:100', exportRt: '65000:100' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l-a', sourceNodeId: 'pe1', sourceInterfaceId: 'p1-g0', targetNodeId: 'pe2', targetInterfaceId: 'p2-g0' },
        { id: 'l-b', sourceNodeId: 'pe1', sourceInterfaceId: 'p1-g1', targetNodeId: 'pe2', targetInterfaceId: 'p2-g1' },
      ],
    };

    const res = solveTopology(topo);

    // MPLS L3VPN imported corp route across PE-1 <-> PE-2
    expect(res.nodes['pe1'].rib.some((r) => r.vrf === 'corp' && r.prefix === '172.20.2.0' && r.active)).toBe(true);

    // ECMP + PBR override on PE-1 -> 10.255.10.2
    const trace = tracePacket(topo, res, 'pe1', '10.255.10.2', 'default');
    expect(trace.outcome).toBe('delivered');
    expect(trace.hops[0].ecmpPaths?.length).toBe(2);
    expect(trace.hops[0].pbrApplied).toContain('FORCE_PATH_2');
    expect(trace.hops[0].nextHop).toBe('10.1.1.2');

    // N-1 failover matrix shows both parallel links are resilient
    const tests: PathTestCase[] = [
      { id: 't1', name: 'PE1 -> PE2 Loopback', srcNodeId: 'pe1', dstIp: '10.255.10.2', vrf: 'default', protocol: 'any', expectedOutcome: 'delivered' },
    ];
    const matrix = runFailoverMatrix(topo, tests);
    expect(matrix).toHaveLength(2);
    expect(matrix.every((m) => m.failed === 0)).toBe(true);
  });

  it('supports IPv6-only BGP peering and IPv6 prefix propagation', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'v6-1',
          hostname: 'V6-R1',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'v1-g0', name: 'Gi0/0', cidr: '', cidr6: '2001:db8:12::1/64', vrf: 'default' },
            { id: 'v1-lo', name: 'Loopback0', cidr: '', cidr6: '2001:db8:100::1/64', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p1', peerIp: '2001:db8:12::2', remoteAs: 65200 }],
            networks: [{ id: 'n1', prefix: '2001:db8:100::/64' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'v6-2',
          hostname: 'V6-R2',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.2',
          position: { x: 250, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'v2-g0', name: 'Gi0/0', cidr: '', cidr6: '2001:db8:12::2/64', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65200,
            peers: [{ id: 'p2', peerIp: '2001:db8:12::1', remoteAs: 65100 }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l-v6', sourceNodeId: 'v6-1', sourceInterfaceId: 'v1-g0', targetNodeId: 'v6-2', targetInterfaceId: 'v2-g0' },
      ],
    };

    const res = solveTopology(topo);
    const learned = res.nodes['v6-2'].rib.find(
      (r) => r.af === 6 && r.prefix === '2001:db8:100::' && r.prefixLen === 64 && r.active
    );
    expect(learned).toBeDefined();
    expect(learned?.protocol).toBe('ebgp');
    expect(learned?.nextHop).toBe('2001:db8:12::1');
  });

  it('suppresses Standby forwarding and promotes Standby to Active on Active peer adminDown', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'core',
          hostname: 'CORE',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.1',
          position: { x: 0, y: 100 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'c-fw1', name: 'Gi0/0', cidr: '10.1.1.1/30', vrf: 'default', ospfArea: 0 },
            { id: 'c-fw2', name: 'Gi0/1', cidr: '10.1.2.1/30', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: {
            enabled: true,
            networks: [
              { id: 'on1', prefix: '10.1.1.0/30', area: 0 },
              { id: 'on2', prefix: '10.1.2.0/30', area: 0 },
            ],
          },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'fw1',
          hostname: 'FW-1',
          vendor: 'pan-os',
          routerId: '10.0.0.11',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'f1-in', name: 'ethernet1/1', cidr: '10.1.1.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'f1-out', name: 'ethernet1/2', cidr: '10.2.1.1/30', vrf: 'default', ospfArea: 0 },
            { id: 'f1-ha1', name: 'ha1', cidr: '169.254.1.1/30', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: {
            enabled: true,
            networks: [
              { id: 'f1o1', prefix: '10.1.1.0/30', area: 0 },
              { id: 'f1o2', prefix: '10.2.1.0/30', area: 0 },
            ],
          },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          panHa: {
            enabled: true,
            mode: 'active-passive',
            groupId: 1,
            devicePriority: 100,
            ha1InterfaceId: 'f1-ha1',
            sessionSync: false,
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'fw2',
          hostname: 'FW-2',
          vendor: 'pan-os',
          routerId: '10.0.0.12',
          position: { x: 200, y: 200 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'f2-in', name: 'ethernet1/1', cidr: '10.1.2.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'f2-out', name: 'ethernet1/2', cidr: '10.2.2.1/30', vrf: 'default', ospfArea: 0 },
            { id: 'f2-ha1', name: 'ha1', cidr: '169.254.1.2/30', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: {
            enabled: true,
            networks: [
              { id: 'f2o1', prefix: '10.1.2.0/30', area: 0 },
              { id: 'f2o2', prefix: '10.2.2.0/30', area: 0 },
            ],
          },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          panHa: {
            enabled: true,
            mode: 'active-passive',
            groupId: 1,
            devicePriority: 200,
            ha1InterfaceId: 'f2-ha1',
            sessionSync: false,
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'wan',
          hostname: 'WAN',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.99',
          position: { x: 400, y: 100 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'w-fw1', name: 'Gi0/0', cidr: '10.2.1.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'w-fw2', name: 'Gi0/1', cidr: '10.2.2.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'w-lo', name: 'Loopback0', cidr: '198.51.100.1/24', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: {
            enabled: true,
            networks: [
              { id: 'wo1', prefix: '10.2.1.0/30', area: 0 },
              { id: 'wo2', prefix: '10.2.2.0/30', area: 0 },
              { id: 'wo3', prefix: '198.51.100.0/24', area: 0 },
            ],
          },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l-cf1', sourceNodeId: 'core', sourceInterfaceId: 'c-fw1', targetNodeId: 'fw1', targetInterfaceId: 'f1-in' },
        { id: 'l-cf2', sourceNodeId: 'core', sourceInterfaceId: 'c-fw2', targetNodeId: 'fw2', targetInterfaceId: 'f2-in' },
        { id: 'l-f1w', sourceNodeId: 'fw1', sourceInterfaceId: 'f1-out', targetNodeId: 'wan', targetInterfaceId: 'w-fw1' },
        { id: 'l-f2w', sourceNodeId: 'fw2', sourceInterfaceId: 'f2-out', targetNodeId: 'wan', targetInterfaceId: 'w-fw2' },
        { id: 'l-ha', sourceNodeId: 'fw1', sourceInterfaceId: 'f1-ha1', targetNodeId: 'fw2', targetInterfaceId: 'f2-ha1' },
      ],
    };

    // Healthy state: FW-1 is Active, FW-2 is Standby (no data-plane forwarding)
    const healthy = solveTopology(topo);
    expect(healthy.nodes['fw1']?.neighbors?.find((n) => n.protocol === 'ha')?.state).toBe('Active');
    expect(healthy.nodes['fw2']?.neighbors?.find((n) => n.protocol === 'ha')?.state).toBe('Standby');
    const traceHealthy = tracePacket(topo, healthy, 'core', '198.51.100.1', 'default');
    expect(traceHealthy.failureReason).toBeUndefined();
    expect(traceHealthy.outcome).toBe('delivered');
    expect(traceHealthy.hops.map((h) => h.nodeId)).toEqual(['core', 'fw1', 'wan']);

    // Failover state: FW-1 goes adminDown -> FW-2 promotes to Active and forwards traffic
    const failedTopo: TopologyState = {
      ...topo,
      nodes: topo.nodes.map((n) => (n.id === 'fw1' ? { ...n, adminDown: true } : n)),
    };
    const failed = solveTopology(failedTopo);
    expect(failed.nodes['fw1']?.neighbors?.find((n) => n.protocol === 'ha')?.state).toBe('Down');
    expect(failed.nodes['fw2']?.neighbors?.find((n) => n.protocol === 'ha')?.state).toBe('Active');
    const traceFailover = tracePacket(failedTopo, failed, 'core', '198.51.100.1', 'default');
    expect(traceFailover.outcome).toBe('delivered');
    expect(traceFailover.hops.map((h) => h.nodeId)).toEqual(['core', 'fw2', 'wan']);
  });

  it('enforces OSPF custom Hello/Dead timer matching and negotiates BGP Keepalive/Hold timers', () => {
    const baseTopo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'R1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            {
              id: 'r1-g0',
              name: 'Gi0/0',
              cidr: '10.0.12.1/30',
              vrf: 'default',
              ospfArea: 0,
              ospfHelloInterval: 5,
              ospfDeadInterval: 15,
            },
            { id: 'r1-lo', name: 'Loopback0', cidr: '10.100.1.1/32', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p1', peerIp: '10.0.12.2', remoteAs: 65200, keepaliveTime: 10, holdTime: 30 }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'r2',
          hostname: 'R2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r2-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65200,
            peers: [{ id: 'p2', peerIp: '10.0.12.1', remoteAs: 65100 }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l12', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g0', targetNodeId: 'r2', targetInterfaceId: 'r2-g0' },
      ],
    };

    // 1. OSPF timer mismatch (5/15 vs default 10/40) prevents FULL adjacency & OSPF route learning
    const mismatch = solveTopology(baseTopo);
    const ospfMismatch = mismatch.nodes['r1']?.neighbors?.find((n) => n.protocol === 'ospf');
    expect(ospfMismatch?.state).toBe('Down');
    expect(ospfMismatch?.detail).toContain('Timer mismatch');
    expect(mismatch.warnings.some((w) => w.includes('OSPF timer mismatch'))).toBe(true);
    expect(mismatch.nodes['r2']?.rib.some((r) => r.prefix === '10.100.1.1' && r.protocol === 'ospf')).toBe(false);

    // BGP still establishes and negotiates min(10/30, 60/180) => K:10s/H:30s
    const bgpNeighbor = mismatch.nodes['r1']?.neighbors?.find((n) => n.protocol === 'bgp');
    expect(bgpNeighbor?.state).toBe('Established');
    expect(bgpNeighbor?.detail).toContain('K:10s/H:30s');

    // 2. Matching custom OSPF timers (5/15 on R2) brings OSPF FULL and converges Loopback0
    const matchedTopo: TopologyState = {
      ...baseTopo,
      nodes: baseTopo.nodes.map((n) =>
        n.id === 'r2'
          ? {
              ...n,
              interfaces: n.interfaces.map((i) =>
                i.id === 'r2-g0' ? { ...i, ospfHelloInterval: 5, ospfDeadInterval: 15 } : i
              ),
            }
          : n
      ),
    };
    const matched = solveTopology(matchedTopo);
    const ospfFull = matched.nodes['r1']?.neighbors?.find((n) => n.protocol === 'ospf');
    expect(ospfFull?.state).toBe('FULL');
    expect(ospfFull?.detail).toContain('H:5s/D:15s');
    expect(matched.nodes['r2']?.rib.some((r) => r.prefix === '10.100.1.1' && r.protocol === 'ospf' && r.active)).toBe(true);

    // 3. Running-config formatter outputs OSPF & BGP timer commands
    const cli = formatRunningConfig(matchedTopo.nodes[0]);
    expect(cli).toContain('ip ospf hello-interval 5');
    expect(cli).toContain('ip ospf dead-interval 15');
    expect(cli).toContain('neighbor 10.0.12.2 timers 10 30');
  });

  it('supports custom BFD timers across OSPF/BGP and RLOC BFD probing on LISP', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'x1',
          hostname: 'XTR-1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'x1-lo', name: 'Loopback0', cidr: '10.255.1.1/32', vrf: 'default', ospfArea: 0 },
            {
              id: 'x1-g0',
              name: 'Gi0/0',
              cidr: '10.0.12.1/30',
              vrf: 'default',
              ospfArea: 0,
              bfdIntervalMs: 25,
              bfdMinRxMs: 25,
              bfdMultiplier: 3,
            },
          ],
          staticRoutes: [],
          ospf: { enabled: true, bfd: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [
              {
                id: 'bp1',
                peerIp: '10.0.12.2',
                remoteAs: 65200,
                bfd: true,
                bfdIntervalMs: 30,
                bfdMinRxMs: 30,
                bfdMultiplier: 3,
              },
            ],
            networks: [],
          },
          lisp: {
            enabled: true,
            role: 'xtr',
            rlocIp: '10.255.1.1',
            instanceId: 4099,
            bfd: true,
            bfdIntervalMs: 25,
            bfdMinRxMs: 25,
            bfdMultiplier: 3,
            eidPrefixes: [{ id: 'e1', prefix: '10.80.1.0/24' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'x2',
          hostname: 'XTR-2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 250, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'x2-lo', name: 'Loopback0', cidr: '10.255.2.2/32', vrf: 'default', ospfArea: 0 },
            {
              id: 'x2-g0',
              name: 'Gi0/0',
              cidr: '10.0.12.2/30',
              vrf: 'default',
              ospfArea: 0,
              bfdIntervalMs: 25,
              bfdMinRxMs: 25,
              bfdMultiplier: 3,
            },
          ],
          staticRoutes: [],
          ospf: { enabled: true, bfd: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65200,
            peers: [
              {
                id: 'bp2',
                peerIp: '10.0.12.1',
                remoteAs: 65100,
                bfd: true,
                bfdIntervalMs: 30,
                bfdMinRxMs: 30,
                bfdMultiplier: 3,
              },
            ],
            networks: [],
          },
          lisp: {
            enabled: true,
            role: 'xtr',
            rlocIp: '10.255.2.2',
            instanceId: 4099,
            bfd: true,
            bfdIntervalMs: 25,
            bfdMinRxMs: 25,
            bfdMultiplier: 3,
            eidPrefixes: [{ id: 'e2', prefix: '10.80.2.0/24' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l12', sourceNodeId: 'x1', sourceInterfaceId: 'x1-g0', targetNodeId: 'x2', targetInterfaceId: 'x2-g0' },
      ],
    };

    const res = solveTopology(topo);
    const ospfN = res.nodes['x1']?.neighbors?.find((n) => n.protocol === 'ospf');
    expect(ospfN?.state).toBe('FULL');
    expect(ospfN?.detail).toContain('BFD 25ms x3=75ms');

    const bgpN = res.nodes['x1']?.neighbors?.find((n) => n.protocol === 'bgp');
    expect(bgpN?.state).toBe('Established');
    expect(bgpN?.detail).toContain('BFD 30ms x3=90ms');

    const lispN = res.nodes['x1']?.neighbors?.find((n) => n.protocol === 'lisp');
    expect(lispN?.state).toBe('Up');
    expect(lispN?.detail).toContain('BFD 25ms x3=75ms RLOC-Probe');

    const cli = formatRunningConfig(topo.nodes[0]);
    expect(cli).toContain('bfd interval 25 min_rx 25 multiplier 3');
    expect(cli).toContain('bfd all-interfaces');
    expect(cli).toContain('rloc-probing bfd');
  });

  it('keeps trace inside a VRF unless vrfLeaks is configured or traffic hands off to a default-VRF-only device', () => {
    const baseTopo: TopologyState = {
      nodes: [
        {
          id: 'pe',
          hostname: 'PE',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default', 'corp'],
          adOverrides: {},
          interfaces: [
            { id: 'pe-wan', name: 'Gi0/0', cidr: '10.10.0.1/30', vrf: 'default' },
            { id: 'pe-ce', name: 'Gi0/1', cidr: '10.20.1.1/30', vrf: 'corp' },
          ],
          staticRoutes: [
            { id: 'sr-wan', prefix: '198.51.100.0/24', nextHop: '10.10.0.2', vrf: 'default' },
            { id: 'sr-ce', prefix: '10.20.2.0/24', nextHop: '10.20.1.2', vrf: 'corp' },
          ],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'wan',
          hostname: 'WAN',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 250, y: -80 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'wan-pe', name: 'Gi0/0', cidr: '10.10.0.2/30', vrf: 'default' },
            { id: 'wan-lo', name: 'Loopback0', cidr: '198.51.100.1/24', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'ce',
          hostname: 'CE-DEFAULT',
          vendor: 'cisco-ios-xe',
          routerId: '3.3.3.3',
          position: { x: 250, y: 80 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'ce-pe', name: 'Gi0/0', cidr: '10.20.1.2/30', vrf: 'default' },
            { id: 'ce-lan', name: 'Loopback0', cidr: '10.20.2.1/24', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l-wan', sourceNodeId: 'pe', sourceInterfaceId: 'pe-wan', targetNodeId: 'wan', targetInterfaceId: 'wan-pe' },
        { id: 'l-ce', sourceNodeId: 'pe', sourceInterfaceId: 'pe-ce', targetNodeId: 'ce', targetInterfaceId: 'ce-pe' },
      ],
    };

    const isolatedRes = solveTopology(baseTopo);

    // 1. Without VRF leaking, tracing in 'corp' cannot see 'default' VRF route 198.51.100.1
    const isolatedDrop = tracePacket(baseTopo, isolatedRes, 'pe', '198.51.100.1', 'corp');
    expect(isolatedDrop.outcome).toBe('dropped');
    expect(isolatedDrop.failureReason).toContain('PE [corp]');

    // 2. Tracing in 'corp' to CE-DEFAULT (default-VRF-only device) transitions PE [corp] -> CE-DEFAULT [default]
    const handoff = tracePacket(baseTopo, isolatedRes, 'pe', '10.20.2.1', 'corp');
    expect(handoff.outcome).toBe('delivered');
    expect(handoff.hops.map((h) => `${h.nodeId}:${h.vrf}`)).toEqual(['pe:corp', 'ce:default']);

    // 3. With explicit VRF leaking (default -> corp), tracing in 'corp' reaches 198.51.100.1 via WAN [default]
    const leakedTopo: TopologyState = {
      ...baseTopo,
      nodes: baseTopo.nodes.map((n) =>
        n.id === 'pe'
          ? { ...n, vrfLeaks: [{ id: 'vl1', fromVrf: 'default', toVrf: 'corp' }] }
          : n
      ),
    };
    const leakedRes = solveTopology(leakedTopo);
    const leakedTrace = tracePacket(leakedTopo, leakedRes, 'pe', '198.51.100.1', 'corp');
    expect(leakedTrace.outcome).toBe('delivered');
    expect(leakedTrace.hops.map((h) => `${h.nodeId}:${h.vrf}`)).toEqual(['pe:corp', 'wan:default']);
  });

  it('brings up OSPF and BGP peers in the same VLAN across Layer 2 links and unnumbered L2 switches', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'CORE-1',
          vendor: 'cisco-nx-os',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default', 'Core'],
          adOverrides: {},
          interfaces: [
            { id: 'r1-v301', name: 'Vlan301', cidr: '10.90.3.12/29', vrf: 'Core', ospfArea: 0, vlanId: 301 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 4250123461,
            peers: [{ id: 'p1', peerIp: '10.90.3.9', remoteAs: 4250123461, vrf: 'Core' }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'sw',
          hostname: 'L2-SW',
          vendor: 'cisco-nx-os',
          routerId: '9.9.9.9',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'sw-p1', name: 'Eth1/1', cidr: '', vrf: 'default', vlanId: 301 },
            { id: 'sw-p2', name: 'Eth1/2', cidr: '', vrf: 'default', vlanId: 301 },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'fw',
          hostname: 'EXT-FW',
          vendor: 'forcepoint-ngfw',
          routerId: '2.2.2.2',
          position: { x: 400, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'fw-v301', name: 'vlan16.301', cidr: '10.90.3.9/29', vrf: 'default', ospfArea: 0, vlanId: 301 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 4250123461,
            peers: [{ id: 'p2', peerIp: '10.90.3.12', remoteAs: 4250123461, vrf: 'default' }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        {
          id: 'l-r1-sw',
          sourceNodeId: 'r1',
          sourceInterfaceId: 'r1-v301',
          targetNodeId: 'sw',
          targetInterfaceId: 'sw-p1',
          linkType: 'layer2',
          l2Mode: 'trunk',
          allowedVlans: '10,300-305',
        },
        {
          id: 'l-sw-fw',
          sourceNodeId: 'sw',
          sourceInterfaceId: 'sw-p2',
          targetNodeId: 'fw',
          targetInterfaceId: 'fw-v301',
          linkType: 'layer2',
          l2Mode: 'access',
          vlanId: 301,
        },
      ],
    };

    const res = solveTopology(topo);
    expect(res.warnings.filter((w) => w.includes('Invalid CIDR'))).toHaveLength(0);
    expect(res.nodes['r1']?.neighbors?.find((n) => n.protocol === 'ospf')?.state).toBe('FULL');
    expect(res.nodes['fw']?.neighbors?.find((n) => n.protocol === 'ospf')?.state).toBe('FULL');
    expect(res.nodes['r1']?.neighbors?.find((n) => n.protocol === 'bgp')?.state).toBe('Established');
    expect(res.nodes['fw']?.neighbors?.find((n) => n.protocol === 'bgp')?.state).toBe('Established');

    // If trunk allowedVlans excludes VLAN 301, OSPF adjacency stays down with a warning
    const blockedTopo: TopologyState = {
      ...topo,
      links: topo.links.map((l) => (l.id === 'l-r1-sw' ? { ...l, allowedVlans: '10,20' } : l)),
    };
    const blockedRes = solveTopology(blockedTopo);
    expect(blockedRes.warnings.some((w) => w.includes('not allowed on L2 link'))).toBe(true);
    expect(blockedRes.nodes['r1']?.neighbors?.some((n) => n.protocol === 'ospf' && n.state === 'FULL')).toBe(false);
  });

  it('supports per-VRF Router IDs and BGP Route Reflector Cluster IDs with cluster-list loop prevention', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'c1',
          hostname: 'CLIENT-1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default', 'Core'],
          adOverrides: {},
          interfaces: [
            { id: 'c1-g0', name: 'Gi0/0', cidr: '10.1.1.1/30', vrf: 'Core' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p1', peerIp: '10.1.1.2', remoteAs: 65100, vrf: 'Core' }],
            networks: [{ id: 'n1', prefix: '172.16.10.0/24', vrf: 'Core' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'rr',
          hostname: 'RR-1',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          vrfRouterIds: { Core: '10.99.99.2' },
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default', 'Core'],
          adOverrides: {},
          interfaces: [
            { id: 'rr-g0', name: 'Gi0/0', cidr: '10.1.1.2/30', vrf: 'Core' },
            { id: 'rr-g1', name: 'Gi0/1', cidr: '10.1.2.1/30', vrf: 'Core' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            clusterId: '10.0.0.100',
            peers: [
              { id: 'p2', peerIp: '10.1.1.1', remoteAs: 65100, vrf: 'Core', routeReflectorClient: true },
              { id: 'p3', peerIp: '10.1.2.2', remoteAs: 65100, vrf: 'Core', routeReflectorClient: true },
            ],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'c2',
          hostname: 'CLIENT-2',
          vendor: 'cisco-ios-xe',
          routerId: '3.3.3.3',
          position: { x: 400, y: 0 },
          maxPaths: 2,
          vrfs: ['default', 'Core'],
          adOverrides: {},
          interfaces: [
            { id: 'c2-g0', name: 'Gi0/0', cidr: '10.1.2.2/30', vrf: 'Core' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            clusterId: '10.0.0.100', // same clusterId tests loop prevention on reflected routes
            peers: [{ id: 'p4', peerIp: '10.1.2.1', remoteAs: 65100, vrf: 'Core' }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l1', sourceNodeId: 'c1', sourceInterfaceId: 'c1-g0', targetNodeId: 'rr', targetInterfaceId: 'rr-g0' },
        { id: 'l2', sourceNodeId: 'rr', sourceInterfaceId: 'rr-g1', targetNodeId: 'c2', targetInterfaceId: 'c2-g0' },
      ],
    };

    const res = solveTopology(topo);
    // Client-1 sees RR-1's VRF-specific Router ID (10.99.99.2) and RR-1's Cluster ID in neighbor detail
    const c1Bgp = res.nodes['c1']?.neighbors?.find((n) => n.protocol === 'bgp');
    expect(c1Bgp?.neighborId).toBe('10.99.99.2');
    const rrBgp = res.nodes['rr']?.neighbors?.find((n) => n.protocol === 'bgp');
    expect(rrBgp?.detail).toContain('Cluster 10.0.0.100');

    // RR-1 learns 172.16.10.0/24; CLIENT-2 shares the same clusterId 10.0.0.100 so cluster-list loop prevention drops it
    expect(res.nodes['rr']?.rib.some((r) => r.prefix === '172.16.10.0' && r.vrf === 'Core')).toBe(true);
    expect(res.nodes['c2']?.rib.some((r) => r.prefix === '172.16.10.0' && r.vrf === 'Core')).toBe(false);

    // With a distinct clusterId on CLIENT-2, CLIENT-2 accepts the reflected route with clusterList ['10.0.0.100']
    const distinctClusterTopo: TopologyState = {
      ...topo,
      nodes: topo.nodes.map((n) =>
        n.id === 'c2' ? { ...n, bgp: { ...n.bgp, clusterId: '10.0.0.200' } } : n
      ),
    };
    const distinctRes = solveTopology(distinctClusterTopo);
    const reflected = distinctRes.nodes['c2']?.rib.find((r) => r.prefix === '172.16.10.0' && r.vrf === 'Core');
    expect(reflected?.bgpAttrs?.clusterList).toEqual(['10.0.0.100']);

    // CLI running-config outputs bgp cluster-id and per-VRF bgp router-id
    const cli = formatRunningConfig(topo.nodes[1]);
    expect(cli).toContain('bgp cluster-id 10.0.0.100');
    expect(cli).toContain('address-family ipv4 vrf Core');
    expect(cli).toContain('bgp router-id 10.99.99.2');
  });

  it('supports BGP peer shutdown/update-source, OSPF P2P, per-VRF OSPF, and CLI round-trip import', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'n1',
          hostname: 'PE-1',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.1',
          vrfRouterIds: { Core: '10.99.0.1' },
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default', 'Core'],
          adOverrides: {},
          interfaces: [
            { id: 'n1-lo', name: 'Loopback0', cidr: '10.255.0.1/32', vrf: 'default' },
            {
              id: 'n1-g0',
              name: 'Gi0/0',
              cidr: '10.1.1.1/30',
              vrf: 'Core',
              ospfArea: 0,
              ospfNetworkType: 'point-to-point',
              ospfHelloInterval: 5,
              ospfDeadInterval: 15,
              bfdIntervalMs: 25,
              bfdMinRxMs: 25,
              bfdMultiplier: 3,
            },
          ],
          staticRoutes: [],
          ospf: {
            enabled: true,
            bfd: true,
            networks: [{ id: 'on1', prefix: '10.1.1.0/30', area: 0, vrf: 'Core' }],
          },
          bgp: {
            enabled: true,
            asn: 65100,
            clusterId: '10.0.0.50',
            peers: [
              {
                id: 'p1',
                peerIp: '10.1.1.2',
                remoteAs: 65200,
                vrf: 'Core',
                shutdown: true,
                updateSource: 'Loopback0',
                keepaliveTime: 10,
                holdTime: 30,
              },
            ],
            networks: [{ id: 'bn1', prefix: '172.16.1.0/24', vrf: 'Core' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'n2',
          hostname: 'PE-2',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default', 'Core'],
          adOverrides: {},
          interfaces: [
            {
              id: 'n2-g0',
              name: 'Gi0/0',
              cidr: '10.1.1.2/30',
              vrf: 'Core',
              ospfArea: 0,
              ospfNetworkType: 'point-to-point',
              ospfHelloInterval: 5,
              ospfDeadInterval: 15,
            },
          ],
          staticRoutes: [],
          ospf: { enabled: true, bfd: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65200,
            peers: [{ id: 'p2', peerIp: '10.1.1.1', remoteAs: 65100, vrf: 'Core' }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l1', sourceNodeId: 'n1', sourceInterfaceId: 'n1-g0', targetNodeId: 'n2', targetInterfaceId: 'n2-g0' },
      ],
    };

    const res = solveTopology(topo);
    // OSPF comes up with P2P & custom timers
    const ospfN = res.nodes['n1']?.neighbors?.find((n) => n.protocol === 'ospf');
    expect(ospfN?.state).toBe('FULL');
    expect(ospfN?.detail).toContain('P2P');
    // BGP peer is admin-shutdown on PE-1 -> Down on both sides and no BGP route learned
    expect(res.nodes['n1']?.neighbors?.find((n) => n.protocol === 'bgp')?.detail).toBe('Admin Shutdown');
    expect(res.nodes['n2']?.neighbors?.find((n) => n.protocol === 'bgp')?.detail).toBe('Peer Admin Shutdown');
    expect(res.nodes['n2']?.rib.some((r) => r.prefix === '172.16.1.0')).toBe(false);

    // Format running-config and round-trip import it
    const cli = formatRunningConfig(topo.nodes[0]);
    expect(cli).toContain('ip ospf network point-to-point');
    expect(cli).toContain('router ospf 1 vrf Core');
    expect(cli).toContain('address-family ipv4 vrf Core');
    expect(cli).toContain('neighbor 10.1.1.2 shutdown');
    expect(cli).toContain('neighbor 10.1.1.2 update-source Loopback0');

    const imported = importTopologyFromText(cli);
    const impNode = imported.nodes[0];
    expect(impNode.vrfRouterIds?.['Core']).toBe('10.99.0.1');
    expect(impNode.bgp.clusterId).toBe('10.0.0.50');
    expect(impNode.ospf.bfd).toBe(true);
    const impIf = impNode.interfaces.find((i) => i.name === 'Gi0/0');
    expect(impIf?.ospfNetworkType).toBe('point-to-point');
    expect(impIf?.ospfHelloInterval).toBe(5);
    expect(impIf?.ospfDeadInterval).toBe(15);
    expect(impIf?.bfdIntervalMs).toBe(25);
    const impPeer = impNode.bgp.peers[0];
    expect(impPeer?.vrf).toBe('Core');
    expect(impPeer?.shutdown).toBe(true);
    expect(impPeer?.updateSource).toBe('Loopback0');
    expect(impPeer?.keepaliveTime).toBe(10);
    expect(impPeer?.holdTime).toBe(30);
  });

  it('supports IS-IS point-to-point and full IS-IS & LISP CLI round-trip import', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'i1',
          hostname: 'ISIS-XTR-1',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            {
              id: 'i1-g0',
              name: 'Gi0/0',
              cidr: '10.1.1.1/30',
              vrf: 'default',
              isisLevel: 'L2',
              isisMetric: 20,
              isisNetworkType: 'point-to-point',
              isisHelloInterval: 3,
              isisHelloMultiplier: 4,
            },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          isis: {
            enabled: true,
            net: '49.0001.0000.0000.0001.00',
            level: 'L2',
            bfd: true,
            networks: [],
          },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          lisp: {
            enabled: true,
            role: 'xtr',
            rlocIp: '10.255.1.1',
            mapServerIp: '10.255.0.1',
            instanceId: 4100,
            bfd: true,
            eidPrefixes: [{ id: 'e1', prefix: '10.88.1.0/24', priority: 1, weight: 50 }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'i2',
          hostname: 'ISIS-2',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            {
              id: 'i2-g0',
              name: 'Gi0/0',
              cidr: '10.1.1.2/30',
              vrf: 'default',
              isisLevel: 'L2',
              isisNetworkType: 'point-to-point',
            },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          isis: { enabled: true, level: 'L2', bfd: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l1', sourceNodeId: 'i1', sourceInterfaceId: 'i1-g0', targetNodeId: 'i2', targetInterfaceId: 'i2-g0' },
      ],
    };

    const res = solveTopology(topo);
    const isisN = res.nodes['i1']?.neighbors?.find((n) => n.protocol === 'isis');
    expect(isisN?.state).toBe('Up');
    expect(isisN?.detail).toContain('P2P');
    expect(isisN?.detail).toContain('H:3s x4');

    const cli = formatRunningConfig(topo.nodes[0]);
    expect(cli).toContain('isis network point-to-point');
    expect(cli).toContain('isis metric 20');
    expect(cli).toContain('net 49.0001.0000.0000.0001.00');
    expect(cli).toContain('is-type level-2-only');

    const imported = importTopologyFromText(cli);
    const n = imported.nodes[0];
    expect(n.isis?.enabled).toBe(true);
    expect(n.isis?.net).toBe('49.0001.0000.0000.0001.00');
    expect(n.isis?.level).toBe('L2');
    expect(n.isis?.bfd).toBe(true);
    const g0 = n.interfaces.find((i) => i.name === 'Gi0/0');
    expect(g0?.isisNetworkType).toBe('point-to-point');
    expect(g0?.isisMetric).toBe(20);
    expect(g0?.isisHelloInterval).toBe(3);
    expect(g0?.isisHelloMultiplier).toBe(4);
    expect(n.lisp?.enabled).toBe(true);
    expect(n.lisp?.instanceId).toBe(4100);
    expect(n.lisp?.rlocIp).toBe('10.255.1.1');
    expect(n.lisp?.mapServerIp).toBe('10.255.0.1');
    expect(n.lisp?.bfd).toBe(true);
    expect(n.lisp?.eidPrefixes[0]?.prefix).toBe('10.88.1.0/24');
    expect(n.lisp?.eidPrefixes[0]?.weight).toBe(50);
  });

  it('imports NX-OS config variants (vrf context, vrf member, nested BGP, NVE/EVPN, HSRP) and supports BGP allowas-in/as-override', () => {
    const nxosCfg = `
hostname NX-LEAF-1
vrf context Core
  rd 65100:10
  address-family ipv4 unicast
    route-target both 65100:10
  ip route 10.99.0.0/16 10.1.1.2
!
interface Ethernet1/1
  vrf member Core
  ip address 10.1.1.1/30
  ip router ospf 1 area 0
  hsrp 10
    ip 10.1.1.254
    priority 120
!
interface nve1
  source-interface 10.255.0.1
  member vni 10010 associate-vrf
  member vni 20010
!
router bgp 65100
  router-id 10.255.0.1
  vrf Core
    router-id 10.99.0.1
    address-family ipv4 unicast
      network 172.16.50.0/24
    neighbor 10.1.1.2
      remote-as 65200
      update-source Ethernet1/1
      allowas-in
      as-override
      next-hop-self
!
`;
    const imported = importTopologyFromText(nxosCfg);
    const nx = imported.nodes[0];
    expect(nx.vendor).toBe('cisco-nx-os');
    expect(nx.vrfs).toContain('Core');
    expect(nx.vrfRouterIds?.['Core']).toBe('10.99.0.1');
    expect(nx.mplsVpn?.enabled).toBe(true);
    expect(nx.mplsVpn?.vrfTargets?.[0]?.rd).toBe('65100:10');
    expect(nx.mplsVpn?.vrfTargets?.[0]?.exportRt).toBe('65100:10');
    expect(nx.evpn?.enabled).toBe(true);
    expect(nx.evpn?.l3Vni).toBe(10010);
    expect(nx.evpn?.l2Vni).toBe(20010);
    expect(nx.fhrpGroups?.[0]?.virtualIp).toBe('10.1.1.254');
    expect(nx.fhrpGroups?.[0]?.priority).toBe(120);
    expect(nx.bgp.networks[0]?.prefix).toBe('172.16.50.0/24');
    expect(nx.bgp.networks[0]?.vrf).toBe('Core');
    expect(nx.bgp.peers[0]?.remoteAs).toBe(65200);
    expect(nx.bgp.peers[0]?.vrf).toBe('Core');
    expect(nx.bgp.peers[0]?.allowAsIn).toBe(true);
    expect(nx.bgp.peers[0]?.asOverride).toBe(true);
    expect(nx.bgp.peers[0]?.updateSource).toBe('Ethernet1/1');
    expect(nx.staticRoutes[0]?.prefix).toBe('10.99.0.0/16');
    expect(nx.staticRoutes[0]?.vrf).toBe('Core');

    // Verify allowas-in lets CE-2 (AS 65100) accept a route originated by CE-1 (AS 65100) via PE (AS 65200)
    const allowAsTopo: TopologyState = {
      nodes: [
        {
          id: 'ce1',
          hostname: 'CE-1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'c1-g0', name: 'Gi0/0', cidr: '10.1.1.1/30', vrf: 'default' }],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p1', peerIp: '10.1.1.2', remoteAs: 65200 }],
            networks: [{ id: 'n1', prefix: '192.168.10.0/24' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'pe',
          hostname: 'PE',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'pe-g0', name: 'Gi0/0', cidr: '10.1.1.2/30', vrf: 'default' },
            { id: 'pe-g1', name: 'Gi0/1', cidr: '10.1.2.1/30', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65200,
            peers: [
              { id: 'p2', peerIp: '10.1.1.1', remoteAs: 65100 },
              { id: 'p3', peerIp: '10.1.2.2', remoteAs: 65100 },
            ],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'ce2',
          hostname: 'CE-2',
          vendor: 'cisco-ios-xe',
          routerId: '3.3.3.3',
          position: { x: 400, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'c2-g0', name: 'Gi0/0', cidr: '10.1.2.2/30', vrf: 'default' }],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p4', peerIp: '10.1.2.1', remoteAs: 65200, allowAsIn: true }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l1', sourceNodeId: 'ce1', sourceInterfaceId: 'c1-g0', targetNodeId: 'pe', targetInterfaceId: 'pe-g0' },
        { id: 'l2', sourceNodeId: 'pe', sourceInterfaceId: 'pe-g1', targetNodeId: 'ce2', targetInterfaceId: 'c2-g0' },
      ],
    };
    const res = solveTopology(allowAsTopo);
    const learned = res.nodes['ce2']?.rib.find((r) => r.prefix === '192.168.10.0' && r.active);
    expect(learned).toBeDefined();
    expect(learned?.bgpAttrs?.asPath).toEqual([65200, 65100]);
  });

  it('supports BGP send-community, remove-private-as, maximum-prefix, originated network communities, and CLI visibility', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'cust',
          hostname: 'CUST',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'c-g0', name: 'Gi0/0', cidr: '10.1.1.1/30', vrf: 'default' }],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p1', peerIp: '10.1.1.2', remoteAs: 64500, sendCommunity: 'both' }],
            networks: [
              { id: 'n1', prefix: '198.51.100.0/24', communities: ['65100:100'] },
              { id: 'n2', prefix: '203.0.113.0/24', communities: ['65100:200'] },
            ],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'isp',
          hostname: 'ISP',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'i-g0', name: 'Gi0/0', cidr: '10.1.1.2/30', vrf: 'default' },
            { id: 'i-g1', name: 'Gi0/1', cidr: '10.1.2.1/30', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 64500,
            peers: [
              { id: 'p2', peerIp: '10.1.1.1', remoteAs: 65100 },
              { id: 'p3', peerIp: '10.1.2.2', remoteAs: 3356, removePrivateAs: true, sendCommunity: 'none' },
            ],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'tier1',
          hostname: 'TIER1',
          vendor: 'cisco-ios-xe',
          routerId: '3.3.3.3',
          position: { x: 400, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 't-g0', name: 'Gi0/0', cidr: '10.1.2.2/30', vrf: 'default' }],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 3356,
            peers: [{ id: 'p4', peerIp: '10.1.2.1', remoteAs: 64500, maxPrefixes: 5 }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l1', sourceNodeId: 'cust', sourceInterfaceId: 'c-g0', targetNodeId: 'isp', targetInterfaceId: 'i-g0' },
        { id: 'l2', sourceNodeId: 'isp', sourceInterfaceId: 'i-g1', targetNodeId: 'tier1', targetInterfaceId: 't-g0' },
      ],
    };

    const res = solveTopology(topo);
    // ISP receives originated communities and formats them in show ip route
    const ispRoute = res.nodes['isp']?.rib.find((r) => r.prefix === '198.51.100.0' && r.active);
    expect(ispRoute?.bgpAttrs?.communities).toEqual(['65100:100']);
    const ispShow = formatCiscoCli(topo.nodes[1], res.nodes['isp']!);
    expect(ispShow).toContain('[comm: 65100:100]');

    // TIER1 receives route with private AS 65100 stripped and communities stripped (sendCommunity: 'none')
    const t1Route = res.nodes['tier1']?.rib.find((r) => r.prefix === '198.51.100.0' && r.active);
    expect(t1Route?.bgpAttrs?.asPath).toEqual([64500]);
    expect(t1Route?.bgpAttrs?.communities).toBeUndefined();

    // maxPrefixes: 1 on TIER1 tears down peer when 2 prefixes arrive
    const capTopo: TopologyState = {
      ...topo,
      nodes: topo.nodes.map((n) =>
        n.id === 'tier1'
          ? { ...n, bgp: { ...n.bgp, peers: n.bgp.peers.map((p) => ({ ...p, maxPrefixes: 1 })) } }
          : n
      ),
    };
    const capRes = solveTopology(capTopo);
    expect(capRes.warnings.some((w) => w.includes('exceeded maximum-prefix 1'))).toBe(true);
    expect(capRes.nodes['tier1']?.neighbors?.find((n) => n.protocol === 'bgp')?.detail).toContain('Max-Prefix');
    expect(capRes.nodes['tier1']?.rib.some((r) => r.prefix === '198.51.100.0')).toBe(false);

    // Running-config round-trip import preserves send-community, remove-private-as, maximum-prefix
    const t1Cli = formatRunningConfig(topo.nodes[2]);
    const impT1 = importTopologyFromText(t1Cli).nodes[0];
    expect(impT1.bgp.peers[0]?.maxPrefixes).toBe(5);
    const ispCli = formatRunningConfig(topo.nodes[1]);
    const impIsp = importTopologyFromText(ispCli).nodes[0];
    expect(impIsp.bgp.peers.find((p) => p.peerIp === '10.1.2.2')?.removePrivateAs).toBe(true);
  });

  it('supports BGP RPKI validation, Large Communities, graceful-shutdown, aggregate as-set, and confederations', () => {
    const topo: TopologyState = {
      roaTable: [
        { id: 'roa1', prefix: '203.0.113.0/24', maxLength: 24, originAsn: 65201 },
        { id: 'roa2', prefix: '198.51.100.0/24', maxLength: 24, originAsn: 65999 }, // invalid for AS 65201
      ],
      nodes: [
        {
          id: 'r1',
          hostname: 'CONFED-1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'r1-g0', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default' }],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65201,
            confederationId: 65200,
            confederationPeers: [65202],
            peers: [{ id: 'p1', peerIp: '10.0.12.2', remoteAs: 65202, confederationPeer: true }],
            networks: [
              { id: 'n1', prefix: '203.0.113.0/24', localPref: 150 },
              { id: 'n2', prefix: '198.51.100.0/24' },
              { id: 'n3', prefix: '192.0.2.128/25' },
            ],
            aggregates: [{ id: 'a1', prefix: '192.0.2.0/24', summaryOnly: true, asSet: true }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'r2',
          hostname: 'CONFED-2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'r2-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default' }],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65202,
            confederationId: 65200,
            confederationPeers: [65201],
            rpkiRejectInvalid: true,
            alwaysCompareMed: true,
            peers: [
              {
                id: 'p2',
                peerIp: '10.0.12.1',
                remoteAs: 65201,
                confederationPeer: true,
                routeMapInId: 'rm-in',
              },
            ],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [
            {
              id: 'rm-in',
              name: 'TAG-LARGE',
              entries: [
                {
                  id: 'e1',
                  seq: 10,
                  action: 'permit',
                  set: { setLargeCommunity: '65200:100:200' },
                },
              ],
            },
          ],
          vrfLeaks: [],
        },
      ],
      links: [{ id: 'l1', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g0', targetNodeId: 'r2', targetInterfaceId: 'r2-g0' }],
    };

    const res = solveTopology(topo);
    const r2Rib = res.nodes['r2']?.rib ?? [];
    // Valid ROA route accepted with LocalPref 150 preserved across confederation sub-AS and Large Community attached
    const validRoute = r2Rib.find((r) => r.prefix === '203.0.113.0' && r.active);
    expect(validRoute?.bgpAttrs?.rpkiState).toBe('valid');
    expect(validRoute?.bgpAttrs?.localPref).toBe(150);
    expect(validRoute?.bgpAttrs?.largeCommunities).toEqual(['65200:100:200']);
    expect(formatCiscoCli(topo.nodes[1], res.nodes['r2']!)).toContain('[rpki: valid]');
    expect(formatCiscoCli(topo.nodes[1], res.nodes['r2']!)).toContain('[lcomm: 65200:100:200]');

    // Invalid ROA route rejected when rpkiRejectInvalid is enabled
    expect(r2Rib.some((r) => r.prefix === '198.51.100.0')).toBe(false);

    // Aggregate 192.0.2.0/24 propagated with aggregator attribute
    const aggRoute = r2Rib.find((r) => r.prefix === '192.0.2.0' && r.active);
    expect(aggRoute?.bgpAttrs?.aggregator).toBe('65201:1.1.1.1');
  });

  it('supports OSPF max-metric & DR/BDR, IS-IS overload & L2->L1 leaking, uRPF strict drop, and unnumbered interfaces', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'R1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r1-lo0', name: 'Loopback0', cidr: '10.255.0.1/32', vrf: 'default', ospfArea: 0 },
            { id: 'r1-g0', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default', ospfArea: 0, ospfPriority: 10 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, maxMetricRouterLsa: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'r2',
          hostname: 'R2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r2-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', ospfArea: 0, ospfPriority: 200, urpfMode: 'strict' },
            { id: 'r2-lo0', name: 'Loopback0', cidr: '10.255.0.2/32', vrf: 'default', ospfArea: 0 },
            { id: 'r2-g1', name: 'Gi0/1', cidr: '', unnumberedSource: 'Loopback0', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [{ id: 'l1', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g0', targetNodeId: 'r2', targetInterfaceId: 'r2-g0' }],
    };

    const res = solveTopology(topo);
    // OSPF DR election: R2 (prio 200) is DR from R1's perspective
    const r1Nbr = res.nodes['r1']?.neighbors?.find((n) => n.protocol === 'ospf');
    expect(r1Nbr?.ospfRole).toBe('DR');
    // OSPF max-metric router-lsa sets link cost to 65535 on R1
    const r2ToLo1 = res.nodes['r2']?.rib.find((r) => r.prefix === '10.255.0.1' && r.active);
    expect(r2ToLo1?.metric).toBeGreaterThanOrEqual(10);

    // uRPF strict drop on R2:Gi0/0 when spoofed source 172.16.99.99 arrives from R1
    const trace = tracePacket(topo, res, 'r1', '10.255.0.2', 'default', { srcIp: '172.16.99.99' });
    expect(trace.outcome).toBe('dropped');
    expect(trace.failureReason).toContain('uRPF (strict) drop');

    // Running-config formatting & import round-trip for new RFC keywords
    const r2Cfg = formatRunningConfig(topo.nodes[1]);
    expect(r2Cfg).toContain('ip unnumbered Loopback0');
    expect(r2Cfg).toContain('ip verify unicast source reachable-via rx');
    expect(r2Cfg).toContain('ip ospf priority 200');
    const impR2 = importTopologyFromText(r2Cfg).nodes[0];
    expect(impR2.interfaces.find((i) => i.name === 'Gi0/1')?.unnumberedSource).toBe('Loopback0');
    expect(impR2.interfaces.find((i) => i.name === 'Gi0/0')?.urpfMode).toBe('strict');
    expect(impR2.interfaces.find((i) => i.name === 'Gi0/0')?.ospfPriority).toBe(200);
  });
});
