import { describe, expect, it } from 'vitest';
import { formatPrimaryCli, formatRunningConfig, formatSecondaryCli } from '../formatters';
import { solveTopology, tracePacket } from '../solver';
import type { TopologyState } from '../../types/network';

function buildSdwanTlocExtTopology(): TopologyState {
  return {
    nodes: [
      {
        id: 'hq-edge1',
        hostname: 'HQ-EDGE-1',
        vendor: 'cisco-sdwan',
        routerId: '10.1.0.1',
        position: { x: 100, y: 120 },
        maxPaths: 4,
        vrfs: ['default'],
        adOverrides: {},
        interfaces: [
          {
            id: 'hq-ge0',
            name: 'ge0/0',
            cidr: '10.100.2.1/30',
            vrf: 'default',
            tlocColor: 'mpls',
            tlocEncap: 'ipsec',
          },
          {
            id: 'hq-lan',
            name: 'ge0/1',
            cidr: '10.10.50.1/24',
            vrf: 'default',
          },
        ],
        staticRoutes: [],
        ospf: { enabled: false, networks: [] },
        bgp: {
          enabled: true,
          asn: 65100,
          peers: [{ id: 'hqp-1', peerIp: '10.100.2.2', remoteAs: 65500 }],
          networks: [{ id: 'hqn-1', prefix: '10.100.2.0/30' }],
        },
        redistributions: [],
        prefixLists: [],
        routeMaps: [],
        vrfLeaks: [],
        sdwan: {
          enabled: true,
          systemIp: '10.1.0.1',
          siteId: 1,
          vSmartPeers: ['10.255.0.100'],
          advertiseConnected: true,
          advertiseStatic: true,
        },
      },
      {
        id: 'mpls-core',
        hostname: 'MPLS-WAN',
        vendor: 'mpls-cloud',
        routerId: '10.250.0.1',
        position: { x: 350, y: 120 },
        maxPaths: 4,
        vrfs: ['default'],
        adOverrides: {},
        interfaces: [
          { id: 'mc-1', name: 'ge-0/0/0', cidr: '10.100.2.2/30', vrf: 'default' },
          { id: 'mc-2', name: 'ge-0/0/1', cidr: '10.100.1.2/30', vrf: 'default' },
        ],
        staticRoutes: [],
        ospf: { enabled: false, networks: [] },
        bgp: {
          enabled: true,
          asn: 65500,
          peers: [
            { id: 'mp-1', peerIp: '10.100.2.1', remoteAs: 65100 },
            { id: 'mp-2', peerIp: '10.100.1.1', remoteAs: 65200 },
          ],
          networks: [],
        },
        redistributions: [],
        prefixLists: [],
        routeMaps: [],
        vrfLeaks: [],
      },
      {
        id: 'br-edge1',
        hostname: 'BR-EDGE-1',
        vendor: 'cisco-sdwan',
        routerId: '10.2.0.1',
        position: { x: 600, y: 80 },
        maxPaths: 4,
        vrfs: ['default'],
        adOverrides: {},
        interfaces: [
          {
            id: 'br1-ge0',
            name: 'ge0/0',
            cidr: '10.100.1.1/30',
            vrf: 'default',
            tlocColor: 'mpls',
            tlocEncap: 'ipsec',
          },
          {
            id: 'br1-ext',
            name: 'ge0/2',
            cidr: '10.100.10.1/30',
            vrf: 'default',
            tlocExtension: 'ge0/0',
          },
        ],
        staticRoutes: [],
        ospf: { enabled: false, networks: [] },
        bgp: {
          enabled: true,
          asn: 65200,
          peers: [{ id: 'brp-1', peerIp: '10.100.1.2', remoteAs: 65500 }],
          networks: [{ id: 'brn-1', prefix: '10.100.1.0/30' }],
        },
        redistributions: [],
        prefixLists: [],
        routeMaps: [],
        vrfLeaks: [],
        sdwan: {
          enabled: true,
          systemIp: '10.2.0.1',
          siteId: 100,
          vSmartPeers: ['10.255.0.100'],
          advertiseConnected: true,
          advertiseStatic: true,
        },
      },
      {
        id: 'br-edge2',
        hostname: 'BR-EDGE-2',
        vendor: 'cisco-sdwan',
        routerId: '10.2.0.2',
        position: { x: 600, y: 240 },
        maxPaths: 4,
        vrfs: ['default'],
        adOverrides: {},
        interfaces: [
          {
            id: 'br2-ext',
            name: 'ge0/2',
            cidr: '10.100.10.2/30',
            vrf: 'default',
          },
          {
            id: 'br2-lan',
            name: 'ge0/1',
            cidr: '10.20.10.1/24',
            vrf: 'default',
          },
        ],
        staticRoutes: [],
        ospf: { enabled: false, networks: [] },
        bgp: { enabled: false, asn: 65200, peers: [], networks: [] },
        redistributions: [],
        prefixLists: [],
        routeMaps: [],
        vrfLeaks: [],
        sdwan: {
          enabled: true,
          systemIp: '10.2.0.2',
          siteId: 100,
          vSmartPeers: ['10.255.0.100'],
          advertiseConnected: true,
          advertiseStatic: true,
        },
      },
    ],
    links: [
      {
        id: 'l-hq-mpls',
        sourceNodeId: 'hq-edge1',
        sourceInterfaceId: 'hq-ge0',
        targetNodeId: 'mpls-core',
        targetInterfaceId: 'mc-1',
        latencyMs: 10,
      },
      {
        id: 'l-br1-mpls',
        sourceNodeId: 'br-edge1',
        sourceInterfaceId: 'br1-ge0',
        targetNodeId: 'mpls-core',
        targetInterfaceId: 'mc-2',
        latencyMs: 12,
      },
      {
        id: 'l-br1-br2-ext',
        sourceNodeId: 'br-edge1',
        sourceInterfaceId: 'br1-ext',
        targetNodeId: 'br-edge2',
        targetInterfaceId: 'br2-ext',
        latencyMs: 1,
      },
    ],
  };
}

describe('Cisco SD-WAN (Viptela) OMP & TLOC Extensions', () => {
  it('propagates OMP routes with AD 251 across direct TLOCs and TLOC-Extension peers', () => {
    const topo = buildSdwanTlocExtTopology();
    const res = solveTopology(topo);

    const br1Omp = res.nodes['br-edge1'].rib.find(
      (r) => r.prefix === '10.10.50.0' && r.protocol === 'omp' && r.active
    );
    expect(br1Omp).toBeDefined();
    expect(br1Omp?.ad).toBe(251);
    expect(br1Omp?.tloc?.color).toBe('mpls');

    const br2Omp = res.nodes['br-edge2'].rib.find(
      (r) => r.prefix === '10.10.50.0' && r.protocol === 'omp' && r.active
    );
    expect(br2Omp).toBeDefined();
    expect(br2Omp?.ad).toBe(251);
    expect(br2Omp?.nextHop).toBe('10.100.10.1');
    expect(br2Omp?.tloc?.viaTlocExtension).toBe('BR-EDGE-1:ge0/0');

    expect(
      res.nodes['br-edge2'].neighbors?.some(
        (n) => n.protocol === 'omp' && n.state === 'Up' && n.detail?.includes('TLOC-Ext')
      )
    ).toBe(true);
  });

  it('traces traffic from a TLOC-Extension SD-WAN edge to HQ LAN and formats Viptela CLI', () => {
    const topo = buildSdwanTlocExtTopology();
    const res = solveTopology(topo);

    const trace = tracePacket(topo, res, 'br-edge2', '10.10.50.10', 'default', {
      srcIp: '10.20.10.10',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(trace.outcome).toBe('delivered');
    expect(trace.hops.map((h) => h.nodeId)).toEqual([
      'br-edge2',
      'br-edge1',
      'mpls-core',
      'hq-edge1',
    ]);

    const ompCli = formatPrimaryCli(topo.nodes[3], res.nodes['br-edge2']);
    expect(ompCli).toContain('show omp routes');
    expect(ompCli).toContain('10.10.50.0/24');
    expect(ompCli).toContain('tloc-ext BR-EDGE-1:ge0/0');

    const tlocCli = formatSecondaryCli(topo.nodes[2], res.nodes['br-edge1']);
    expect(tlocCli).toContain('show omp tlocs');
    expect(tlocCli).toContain('mpls');

    const cfgCli = formatRunningConfig(topo.nodes[2]);
    expect(cfgCli).toContain('tloc-extension ge0/0');
  });

  it('steers FortiGate SD-WAN traffic away from SLA-violating WAN links and formats config system sdwan', () => {
    const fgtTopo: TopologyState = {
      nodes: [
        {
          id: 'fgt-1',
          hostname: 'FGT-SDWAN-1',
          vendor: 'fortigate',
          routerId: '10.50.0.1',
          position: { x: 100, y: 120 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'fgt-p1', name: 'port1', cidr: '10.1.1.1/30', vrf: 'default' },
            { id: 'fgt-p2', name: 'port2', cidr: '10.1.2.1/30', vrf: 'default' },
          ],
          staticRoutes: [
            { id: 'fsr-1', vrf: 'default', prefix: '172.16.0.0/16', nextHop: '10.1.1.2' },
          ],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65100, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
          sdwanSla: {
            enabled: true,
            rules: [
              {
                id: 'frule-1',
                name: 'CORP-APP-SLA',
                dstCidr: '172.16.0.0/16',
                mode: 'sla-failover',
                preferredMembers: ['port1', 'port2'],
                maxLatencyMs: 50,
                maxLossPct: 0.5,
              },
            ],
          },
        },
        {
          id: 'dc-core',
          hostname: 'DC-CORE',
          vendor: 'cisco-ios-xe',
          routerId: '172.16.0.1',
          position: { x: 400, y: 120 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'dc-g0', name: 'Gi0/0', cidr: '10.1.1.2/30', vrf: 'default' },
            { id: 'dc-g1', name: 'Gi0/1', cidr: '10.1.2.2/30', vrf: 'default' },
            { id: 'dc-lan', name: 'Loopback0', cidr: '172.16.10.1/24', vrf: 'default' },
          ],
          staticRoutes: [
            { id: 'dsr-1', vrf: 'default', prefix: '10.1.1.0/30', nextHop: '10.1.1.1' },
          ],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65200, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        {
          id: 'fl-1',
          sourceNodeId: 'fgt-1',
          sourceInterfaceId: 'fgt-p1',
          targetNodeId: 'dc-core',
          targetInterfaceId: 'dc-g0',
          latencyMs: 120,
          lossPct: 2,
        },
        {
          id: 'fl-2',
          sourceNodeId: 'fgt-1',
          sourceInterfaceId: 'fgt-p2',
          targetNodeId: 'dc-core',
          targetInterfaceId: 'dc-g1',
          latencyMs: 12,
          lossPct: 0,
        },
      ],
    };

    const res = solveTopology(fgtTopo);
    const trace = tracePacket(fgtTopo, res, 'fgt-1', '172.16.10.10', 'default', {
      srcIp: '10.1.2.1',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(trace.outcome).toBe('delivered');
    expect(trace.hops[0].egressInterface).toBe('port2');
    expect(trace.hops[0].sdwanSteered).toContain('CORP-APP-SLA: port2');

    const cfg = formatRunningConfig(fgtTopo.nodes[0]);
    expect(cfg).toContain('config system sdwan');
    expect(cfg).toContain('CORP-APP-SLA');
  });

  it('supports Palo Alto Prisma SD-WAN (ION) best-quality path steering and CLI', () => {
    const prismaTopo: TopologyState = {
      nodes: [
        {
          id: 'ion-1',
          hostname: 'PRISMA-ION-BR1',
          vendor: 'prisma-sdwan',
          routerId: '10.60.0.1',
          position: { x: 100, y: 120 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'ion-e1', name: 'eth1', cidr: '10.2.1.1/30', vrf: 'default' },
            { id: 'ion-e2', name: 'eth2', cidr: '10.2.2.1/30', vrf: 'default' },
          ],
          staticRoutes: [
            { id: 'isr-1', vrf: 'default', prefix: '10.200.0.0/16', nextHop: '10.2.1.2' },
          ],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65300, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
          sdwanSla: {
            enabled: true,
            rules: [
              {
                id: 'prule-1',
                name: 'SAAS-BEST-QUALITY',
                mode: 'best-quality',
                preferredMembers: ['eth1', 'eth2'],
                maxLatencyMs: 80,
              },
            ],
          },
        },
        {
          id: 'hub-1',
          hostname: 'PRISMA-HUB',
          vendor: 'prisma-sdwan',
          routerId: '10.200.0.1',
          position: { x: 400, y: 120 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'hub-e1', name: 'eth1', cidr: '10.2.1.2/30', vrf: 'default' },
            { id: 'hub-e2', name: 'eth2', cidr: '10.2.2.2/30', vrf: 'default' },
            { id: 'hub-lo', name: 'lo0', cidr: '10.200.1.1/24', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65300, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        {
          id: 'pl-1',
          sourceNodeId: 'ion-1',
          sourceInterfaceId: 'ion-e1',
          targetNodeId: 'hub-1',
          targetInterfaceId: 'hub-e1',
          latencyMs: 65,
          jitterMs: 8,
        },
        {
          id: 'pl-2',
          sourceNodeId: 'ion-1',
          sourceInterfaceId: 'ion-e2',
          targetNodeId: 'hub-1',
          targetInterfaceId: 'hub-e2',
          latencyMs: 14,
          jitterMs: 1,
        },
      ],
    };

    const res = solveTopology(prismaTopo);
    const trace = tracePacket(prismaTopo, res, 'ion-1', '10.200.1.50', 'default', {
      srcIp: '10.2.2.1',
    });
    expect(trace.outcome).toBe('delivered');
    expect(trace.hops[0].egressInterface).toBe('eth2');
    expect(trace.hops[0].sdwanSteered).toContain('SAAS-BEST-QUALITY: eth2');

    const cli = formatPrimaryCli(prismaTopo.nodes[0], res.nodes['ion-1']);
    expect(cli).toContain('dump interface status');
    expect(cli).toContain('SAAS-BEST-QUALITY');
  });
});

