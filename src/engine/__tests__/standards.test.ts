import { describe, expect, it } from 'vitest';
import { useSimStore } from '../../store/useSimStore';
import { PRESET_TOPOLOGIES } from '../../data/presets';
import { TopologyState } from '../../types/network';
import { formatCiscoCli, formatRunningConfig } from '../formatters';
import { importTopologyFromText } from '../importer';
import { runPathTestSuite, solveTopology, tracePacket } from '../solver';

describe('Additional IETF & IEEE Standards (MPLS/SR, RSTP/LLDP, PIM-SM, FlowSpec, NAT64, QoS)', () => {
  it('computes MPLS LDP / SR-MPLS LFIB with PHP, attaches mplsLabels in tracePacket, and formats show mpls forwarding-table', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'pe1',
          hostname: 'PE1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'pe1-g0', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          mpls: {
            ldpEnabled: true,
            segmentRouting: { enabled: true, srgbStart: 16000, srgbEnd: 23999, prefixSid: 1 },
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'p1',
          hostname: 'P1',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'p1-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'p1-lo0', name: 'Loopback0', cidr: '10.255.0.2/32', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          mpls: {
            ldpEnabled: true,
            segmentRouting: { enabled: true, srgbStart: 16000, srgbEnd: 23999, prefixSid: 2 },
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l1', sourceNodeId: 'pe1', sourceInterfaceId: 'pe1-g0', targetNodeId: 'p1', targetInterfaceId: 'p1-g0' },
      ],
    };

    const res = solveTopology(topo);
    const pe1Lfib = res.nodes['pe1']?.lfib ?? [];
    const loEntry = pe1Lfib.find((e) => e.prefix === '10.255.0.2/32');
    expect(loEntry?.protocol).toBe('sr-mpls');
    expect(loEntry?.inLabel).toBe(16002);
    expect(loEntry?.outLabel).toBe('POP');

    const trace = tracePacket(topo, res, 'pe1', '10.255.0.2', 'default');
    expect(trace.outcome).toBe('delivered');
    expect(trace.hops[0]?.mplsLabels).toEqual([16002]);
    expect(formatCiscoCli(topo.nodes[0], res.nodes['pe1']!)).toContain('show mpls forwarding-table');
  });

  it('elects IEEE 802.1w RSTP Root Bridge, blocks redundant L2 loop port, and discovers LLDP neighbors', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'sw1',
          hostname: 'SW1-ROOT',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'sw1-1', name: 'Gi0/1', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'active' },
            { id: 'sw1-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          switching: { stpEnabled: true, stpMode: 'rstp', stpPriority: 4096, lldpEnabled: true },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'sw2',
          hostname: 'SW2',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'sw2-1', name: 'Gi0/1', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'active' },
            { id: 'sw2-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          switching: { stpEnabled: true, stpMode: 'rstp', stpPriority: 32768, lldpEnabled: true },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'sw3',
          hostname: 'SW3',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.3',
          position: { x: 100, y: 150 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'sw3-1', name: 'Gi0/1', cidr: '', vrf: 'default' },
            { id: 'sw3-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          switching: { stpEnabled: true, stpMode: 'rstp', stpPriority: 32768, lldpEnabled: true },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l12', linkType: 'layer2', sourceNodeId: 'sw1', sourceInterfaceId: 'sw1-1', targetNodeId: 'sw2', targetInterfaceId: 'sw2-1' },
        { id: 'l13', linkType: 'layer2', sourceNodeId: 'sw1', sourceInterfaceId: 'sw1-2', targetNodeId: 'sw3', targetInterfaceId: 'sw3-1' },
        { id: 'l23', linkType: 'layer2', sourceNodeId: 'sw2', sourceInterfaceId: 'sw2-2', targetNodeId: 'sw3', targetInterfaceId: 'sw3-2' },
      ],
    };

    const res = solveTopology(topo);
    expect(res.nodes['sw1']?.stpState?.isRoot).toBe(true);
    expect(res.nodes['sw3']?.stpState?.ports.some((p) => p.role === 'Alternate' && p.state === 'Blocking')).toBe(true);
    expect(res.nodes['sw1']?.lldpNeighbors?.length).toBe(2);
    const cli = formatCiscoCli(topo.nodes[2], res.nodes['sw3']!);
    expect(cli).toContain('show spanning-tree');
    expect(cli).toContain('show lldp neighbors');
  });

  it('computes PIM-SM mroute, enforces BGP FlowSpec drop, translates NAT64, marks DSCP, and round-trips CLI config', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'EDGE-1',
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
              cidr6: '2001:db8:1::1/64',
              vrf: 'default',
              pimSparse: true,
              dhcpHelperIps: ['10.200.0.10'],
              qosPolicy: { dscpMark: 46 },
            },
            { id: 'r1-g1', name: 'Gi0/1', cidr: '10.10.1.1/24', vrf: 'default', pimSparse: true },
          ],
          staticRoutes: [{ id: 's1', vrf: 'default', prefix: '198.51.100.0/24', nextHop: '10.0.12.2' }],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65001,
            peers: [],
            networks: [],
            flowspecRules: [
              { id: 'fs1', dstCidr: '198.51.100.0/24', protocol: 'tcp', dstPort: 23, action: 'drop' },
            ],
          },
          multicast: {
            pimEnabled: true,
            rpAddress: '10.0.12.2',
            igmpGroups: [{ id: 'ig1', group: '239.1.1.1', interfaceId: 'r1-g1' }],
          },
          nat64Rules: [{ id: 'n64', prefix6: '64:ff9b::/96', pool4Cidr: '10.0.12.0/30' }],
          switching: { stpEnabled: true, stpMode: 'rstp', stpPriority: 8192, lldpEnabled: true },
          mpls: { ldpEnabled: true },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'r2',
          hostname: 'CORE-2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r2-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', pimSparse: true },
            { id: 'r2-lo0', name: 'Loopback0', cidr: '198.51.100.1/32', vrf: 'default' },
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
        { id: 'l1', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g0', targetNodeId: 'r2', targetInterfaceId: 'r2-g0' },
      ],
    };

    const res = solveTopology(topo);
    // PIM-SM mroute
    const mroute = res.nodes['r1']?.mroute ?? [];
    expect(mroute[0]).toMatchObject({
      source: '*',
      group: '239.1.1.1',
      rpfInterface: 'Gi0/0',
      oifList: ['Gi0/1'],
    });
    expect(formatCiscoCli(topo.nodes[0], res.nodes['r1']!)).toContain('show ip mroute');

    // FlowSpec drop on TCP/23
    const fsDrop = tracePacket(topo, res, 'r1', '198.51.100.1', 'default', { protocol: 'tcp', dstPort: 23 });
    expect(fsDrop.outcome).toBe('blocked');
    expect(fsDrop.failureReason).toContain('FlowSpec drop');

    // NAT64 translates 64:ff9b::c633:6401 (198.51.100.1) to IPv4 and delivers to CORE-2
    const nat64Trace = tracePacket(topo, res, 'r1', '64:ff9b::c633:6401', 'default', {
      srcInterfaceId: 'r1-g0',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(nat64Trace.outcome).toBe('delivered');
    expect(nat64Trace.hops[0]?.natApplied).toContain('NAT64');
    expect(nat64Trace.hops[0]?.dscp).toBe(46);

    // Running-config formatting & import round-trip
    const cfg = formatRunningConfig(topo.nodes[0]);
    expect(cfg).toContain('mpls ip');
    expect(cfg).toContain('lldp run');
    expect(cfg).toContain('ip pim rp-address 10.0.12.2');
    expect(cfg).toContain('ip helper-address 10.200.0.10');
    const imp = importTopologyFromText(cfg).nodes[0];
    expect(imp.mpls?.ldpEnabled).toBe(true);
    expect(imp.switching?.lldpEnabled).toBe(true);
    expect(imp.switching?.stpPriority).toBe(8192);
    expect(imp.multicast?.rpAddress).toBe('10.0.12.2');
    expect(imp.interfaces.find((i) => i.name === 'Gi0/0')?.dhcpHelperIps).toEqual(['10.200.0.10']);
  });

  it('enforces 802.1X unauthorized, 802.1AE MACsec MTU/mismatch, ECN marking, EVPN ESI DF election, BMP, and IPFIX', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'pe1',
          hostname: 'PE1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            {
              id: 'pe1-g0',
              name: 'Gi0/0',
              cidr: '10.0.12.1/30',
              vrf: 'default',
              macsecEnabled: true,
              evpnEsi: '0011.2233.4455.6677.8899',
              qosPolicy: { dscpMark: 26, ecnEnabled: true },
            },
            { id: 'pe1-g1', name: 'Gi0/1', cidr: '10.0.13.1/30', vrf: 'default', dot1xState: 'unauthorized' },
          ],
          staticRoutes: [{ id: 's1', vrf: 'default', prefix: '10.255.0.2/32', nextHop: '10.0.12.2' }],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p1', peerIp: '10.0.12.2', remoteAs: 65100 }],
            networks: [],
          },
          timing: { ptpMode: 'boundary', ptpDomain: 24, ntpServer: '10.200.0.1' },
          telemetry: { bmpServerIp: '10.200.0.50', ipfixCollectorIp: '10.200.0.60' },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'pe2',
          hostname: 'PE2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            {
              id: 'pe2-g0',
              name: 'Gi0/0',
              cidr: '10.0.12.2/30',
              vrf: 'default',
              macsecEnabled: true,
              evpnEsi: '0011.2233.4455.6677.8899',
            },
            { id: 'pe2-lo0', name: 'Loopback0', cidr: '10.255.0.2/32', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p2', peerIp: '10.0.12.1', remoteAs: 65100 }],
            networks: [{ id: 'n2', prefix: '10.255.0.2/32' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'pe3',
          hostname: 'PE3',
          vendor: 'cisco-ios-xe',
          routerId: '3.3.3.3',
          position: { x: 0, y: 150 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'pe3-g0', name: 'Gi0/0', cidr: '10.0.13.2/30', vrf: 'default' }],
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
        { id: 'l1', sourceNodeId: 'pe1', sourceInterfaceId: 'pe1-g0', targetNodeId: 'pe2', targetInterfaceId: 'pe2-g0', latencyMs: 30 },
        { id: 'l2', sourceNodeId: 'pe1', sourceInterfaceId: 'pe1-g1', targetNodeId: 'pe3', targetInterfaceId: 'pe3-g0' },
      ],
    };

    const res = solveTopology(topo);
    // 802.1X unauthorized warning
    expect(res.warnings.some((w) => w.includes('802.1X port unauthorized'))).toBe(true);
    // EVPN ESI DF Election: PE1 (1.1.1.1) is DF, PE2 (2.2.2.2) is Backup
    expect(res.nodes['pe1']?.evpnDfState?.[0]).toMatchObject({ role: 'DF' });
    expect(res.nodes['pe2']?.evpnDfState?.[0]).toMatchObject({ role: 'Backup' });
    // BMP summary
    expect(res.nodes['pe1']?.bmpSummary).toMatchObject({ serverIp: '10.200.0.50', peerCount: 1 });

    // Packet trace over MACsec + ECN-congested link + IPFIX export
    const trace = tracePacket(topo, res, 'pe1', '10.255.0.2', 'default', {
      srcInterfaceId: 'pe1-g0',
      protocol: 'tcp',
      dstPort: 443,
      packetSize: 1400,
    });
    expect(trace.outcome).toBe('delivered');
    expect(trace.pathMtu).toBe(1468); // 1500 - 32B MACsec
    expect(trace.hops[0]?.macsecSecured).toBe(true);
    expect(trace.hops[0]?.ecnMarked).toBe(true);
    expect(trace.ipfixRecord).toMatchObject({ exporterIp: '10.200.0.60', dstPort: 443, bytes: 1400 });

    // Running-config round-trip import
    const cfg = formatRunningConfig(topo.nodes[0]);
    expect(cfg).toContain('macsec');
    expect(cfg).toContain('ntp server 10.200.0.1');
    expect(cfg).toContain('bmp server 1 10.200.0.50');
    expect(cfg).toContain('ip flow-export destination 10.200.0.60 4739');
    const imp = importTopologyFromText(cfg).nodes[0];
    expect(imp.interfaces.find((i) => i.name === 'Gi0/0')?.macsecEnabled).toBe(true);
    expect(imp.timing?.ntpServer).toBe('10.200.0.1');
    expect(imp.telemetry?.bmpServerIp).toBe('10.200.0.50');
    expect(imp.telemetry?.ipfixCollectorIp).toBe('10.200.0.60');
  });

  it('validates IPsec IKEv2/crypto-profile mismatch, BGP AIGP (RFC 7311) tie-breaking, and GLBP', () => {
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
            { id: 'r1-g0', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default', ospfArea: 0 },
            { id: 'r1-g1', name: 'Gi0/1', cidr: '10.10.1.1/24', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p1', peerIp: '10.255.0.2', remoteAs: 65100, aigp: true }],
            networks: [{ id: 'n1', prefix: '198.51.100.0/24' }],
          },
          fhrpGroups: [
            {
              id: 'gl1',
              protocol: 'glbp',
              groupId: 10,
              interfaceId: 'r1-g1',
              virtualIp: '10.10.1.254',
              priority: 120,
            },
          ],
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
            { id: 'r2-lo0', name: 'Loopback0', cidr: '10.255.0.2/32', vrf: 'default', ospfArea: 0 },
            { id: 'r2-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65100,
            peers: [{ id: 'p2', peerIp: '10.255.0.1', remoteAs: 65100, aigp: true }],
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
          id: 'l-ipsec',
          linkType: 'ipsec',
          sourceNodeId: 'r1',
          sourceInterfaceId: 'r1-g0',
          targetNodeId: 'r2',
          targetInterfaceId: 'r2-g0',
          ipsecConfig: {
            ikeVersion: 'IKEv2',
            remoteIkeVersion: 'IKEv1',
            cryptoProfile: 'AES256-GCM',
          },
        },
      ],
    };

    // Mismatched IKEv2 vs IKEv1 tears down IPsec tunnel and warns
    const mismatchRes = solveTopology(topo);
    expect(mismatchRes.warnings.some((w) => w.includes('IPsec IKE version mismatch'))).toBe(true);
    expect(mismatchRes.nodes['r2']?.rib.some((r) => r.prefix === '198.51.100.0')).toBe(false);

    // Matching IKEv2 brings tunnel up and propagates AIGP metric
    const okTopo: TopologyState = {
      ...topo,
      links: topo.links.map((l) => ({
        ...l,
        ipsecConfig: { ikeVersion: 'IKEv2', remoteIkeVersion: 'IKEv2', cryptoProfile: 'AES256-GCM' },
      })),
    };
    const okRes = solveTopology(okTopo);
    const bgpRoute = okRes.nodes['r2']?.rib.find((r) => r.prefix === '198.51.100.0' && r.active);
    expect(bgpRoute?.bgpAttrs?.aigpMetric).toBeDefined();
    expect(okRes.nodes['r1']?.neighbors?.some((n) => n.protocol === 'glbp' && n.state === 'Active')).toBe(true);
  });

  it('supports store UX actions: duplicateNode, setRoaTable, and setProtocolOverlay', () => {
    const store = useSimStore.getState();
    const initialCount = store.topology.nodes.length;
    const firstId = store.topology.nodes[0]?.id;
    expect(firstId).toBeDefined();

    store.duplicateNode(firstId!);
    const afterClone = useSimStore.getState();
    expect(afterClone.topology.nodes.length).toBe(initialCount + 1);
    expect(afterClone.topology.nodes.some((n) => n.hostname.endsWith('-copy'))).toBe(true);

    store.setProtocolOverlay('bgp-asn');
    expect(useSimStore.getState().protocolOverlay).toBe('bgp-asn');

    store.setRoaTable([
      { id: 'roa-ui-1', prefix: '203.0.113.0/24', maxLength: 24, originAsn: 65100 },
    ]);
    expect(useSimStore.getState().topology.roaTable?.length).toBe(1);

    // Restore clean state via undo
    useSimStore.getState().undo();
    useSimStore.getState().undo();
    useSimStore.getState().setProtocolOverlay('none');
  });

  it('propagates route tags across Static, EIGRP, OSPF, IS-IS, RIP and filters via route-map matchTag/setTag', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'TAG-R1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'r1-g0', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default', ospfArea: 0 }],
          staticRoutes: [
            { id: 'sr1', vrf: 'default', prefix: '198.51.100.0/24', nextHop: '10.0.12.2', tag: 100 },
            { id: 'sr2', vrf: 'default', prefix: '203.0.113.0/24', nextHop: '10.0.12.2', tag: 200 },
          ],
          ospf: { enabled: true, networks: [] },
          eigrp: { enabled: true, asn: 100, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [
            { id: 'rd-e', from: 'static', to: 'eigrp', routeMapId: 'rm-tag-eigrp' },
            { id: 'rd-o', from: 'static', to: 'ospf', routeMapId: 'rm-tag-ospf' },
          ],
          prefixLists: [],
          routeMaps: [
            {
              id: 'rm-tag-eigrp',
              name: 'TAG_TO_EIGRP',
              entries: [
                { id: 'e1', seq: 10, action: 'permit', matchTag: 100, set: { setTag: 777 } },
              ],
            },
            {
              id: 'rm-tag-ospf',
              name: 'BLOCK_TAG_100_IN_OSPF',
              entries: [
                { id: 'o1', seq: 10, action: 'deny', matchTag: 100, set: {} },
                { id: 'o2', seq: 20, action: 'permit', matchTag: 200, set: { setTag: 888 } },
              ],
            },
          ],
          vrfLeaks: [],
        },
        {
          id: 'r2',
          hostname: 'TAG-R2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'r2-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', ospfArea: 0 }],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          eigrp: { enabled: true, asn: 100, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l1', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g0', targetNodeId: 'r2', targetInterfaceId: 'r2-g0' },
      ],
    };

    const res = solveTopology(topo);
    const r2Rib = res.nodes['r2']?.rib ?? [];
    // 198.51.100.0/24 reached R2 via EIGRP with setTag: 777 (and was blocked in OSPF by matchTag: 100 deny)
    const eigrpRoute = r2Rib.find((r) => r.prefix === '198.51.100.0' && r.active);
    expect(eigrpRoute?.protocol).toBe('eigrp');
    expect(eigrpRoute?.tag).toBe(777);
    expect(r2Rib.some((r) => r.prefix === '198.51.100.0' && r.protocol === 'ospf')).toBe(false);

    // 203.0.113.0/24 reached R2 via OSPF with setTag: 888
    const ospfRoute = r2Rib.find((r) => r.prefix === '203.0.113.0' && r.active);
    expect(ospfRoute?.protocol).toBe('ospf');
    expect(ospfRoute?.tag).toBe(888);

    // CLI output and running-config round-trip
    expect(formatCiscoCli(topo.nodes[1], res.nodes['r2']!)).toContain('[tag 777]');
    const cfg = formatRunningConfig(topo.nodes[0]);
    expect(cfg).toContain('match tag 100');
    expect(cfg).toContain('set tag 777');
    const imp = importTopologyFromText(cfg).nodes[0];
    expect(imp.routeMaps.find((m) => m.name === 'TAG_TO_EIGRP')?.entries[0]?.matchTag).toBe(100);
    expect(imp.routeMaps.find((m) => m.name === 'TAG_TO_EIGRP')?.entries[0]?.set.setTag).toBe(777);
  });

  it('multiplexes 802.1Q sub-interfaces across VRFs over one physical link, enforces allowedVlans, inherits physical SLA in tracePacket, and round-trips encapsulation dot1Q', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'R1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default', 'CORP', 'GUEST', 'BLOCKED'],
          adOverrides: {},
          interfaces: [
            { id: 'r1-g0', name: 'Gi0/0', cidr: '', vrf: 'default' },
            { id: 'r1-g0-100', name: 'Gi0/0.100', cidr: '10.100.0.1/30', vrf: 'CORP' },
            { id: 'r1-g0-200', name: 'Gi0/0.200', cidr: '10.200.0.1/30', vrf: 'GUEST' },
            { id: 'r1-g0-300', name: 'Gi0/0.300', cidr: '10.30.0.1/30', vrf: 'BLOCKED' },
          ],
          staticRoutes: [
            { id: 'sr-corp', vrf: 'CORP', prefix: '172.16.100.0/24', nextHop: '10.100.0.2' },
            { id: 'sr-guest', vrf: 'GUEST', prefix: '172.16.200.0/24', nextHop: '10.200.0.2' },
          ],
          ospf: { enabled: false, networks: [] },
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
          vrfs: ['default', 'CORP', 'GUEST', 'BLOCKED'],
          adOverrides: {},
          interfaces: [
            { id: 'r2-g0', name: 'Gi0/0', cidr: '', vrf: 'default' },
            { id: 'r2-g0-100', name: 'Gi0/0.100', cidr: '10.100.0.2/30', vrf: 'CORP' },
            { id: 'r2-g0-200', name: 'Gi0/0.200', cidr: '10.200.0.2/30', vrf: 'GUEST' },
            { id: 'r2-g0-300', name: 'Gi0/0.300', cidr: '10.30.0.2/30', vrf: 'BLOCKED' },
            { id: 'r2-lo100', name: 'Loopback100', cidr: '172.16.100.1/24', vrf: 'CORP' },
            { id: 'r2-lo200', name: 'Loopback200', cidr: '172.16.200.1/24', vrf: 'GUEST' },
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
        {
          id: 'l-trunk',
          sourceNodeId: 'r1',
          sourceInterfaceId: 'r1-g0',
          targetNodeId: 'r2',
          targetInterfaceId: 'r2-g0',
          allowedVlans: '100,200',
          latencyMs: 12,
        },
      ],
    };

    const res = solveTopology(topo);
    expect(res.warnings.some((w) => w.includes('Invalid CIDR'))).toBe(false);
    expect(res.warnings.some((w) => w.includes('VLAN 300 not allowed'))).toBe(true);

    const corpTrace = tracePacket(topo, res, 'r1', '172.16.100.1', 'CORP');
    expect(corpTrace.outcome).toBe('delivered');
    expect(corpTrace.hops[0]?.egressInterface).toBe('Gi0/0.100');
    expect(corpTrace.totalLatencyMs).toBe(12);

    const guestTrace = tracePacket(topo, res, 'r1', '172.16.200.1', 'GUEST');
    expect(guestTrace.outcome).toBe('delivered');
    expect(guestTrace.hops[0]?.egressInterface).toBe('Gi0/0.200');
    expect(guestTrace.totalLatencyMs).toBe(12);

    const cfg = formatRunningConfig(topo.nodes[0]);
    expect(cfg).toContain('encapsulation dot1Q 100');
    expect(cfg).toContain('encapsulation dot1Q 200');
    const imp = importTopologyFromText(cfg).nodes[0];
    const sub100 = imp.interfaces.find((i) => i.name === 'Gi0/0.100');
    expect(sub100?.vlanId).toBe(100);
    expect(sub100?.parentInterface).toBe('Gi0/0');
  });

  it('aggregates LACP/PAgP/Static Port-Channels, detects negotiation/protocol mismatches, prevents STP blocking on LAG members, and round-trips channel-protocol', () => {
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
          switching: { stpEnabled: true, stpPriority: 4096 },
          interfaces: [
            { id: 'r1-g1', name: 'Gi0/1', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'active' },
            { id: 'r1-g2', name: 'Gi0/2', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'active' },
            { id: 'r1-po1', name: 'Port-channel1', cidr: '10.50.0.1/30', vrf: 'default', ospfArea: 0 },
            { id: 'r1-g3', name: 'Gi0/3', cidr: '', vrf: 'default', lacpGroup: 2, lacpMode: 'desirable', lagProtocol: 'pagp' },
            { id: 'r1-g4', name: 'Gi0/4', cidr: '', vrf: 'default', lacpGroup: 3, lacpMode: 'passive' },
            { id: 'r1-g5', name: 'Gi0/5', cidr: '', vrf: 'default', lacpGroup: 4, lacpMode: 'active' },
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
          id: 'r2',
          hostname: 'R2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          switching: { stpEnabled: true, stpPriority: 32768 },
          interfaces: [
            { id: 'r2-g1', name: 'Gi0/1', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'passive' },
            { id: 'r2-g2', name: 'Gi0/2', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'passive' },
            { id: 'r2-po1', name: 'Port-channel1', cidr: '10.50.0.2/30', vrf: 'default', ospfArea: 0 },
            { id: 'r2-lo0', name: 'Loopback0', cidr: '192.0.2.1/32', vrf: 'default', ospfArea: 0 },
            { id: 'r2-g3', name: 'Gi0/3', cidr: '', vrf: 'default', lacpGroup: 2, lacpMode: 'auto', lagProtocol: 'pagp' },
            { id: 'r2-po2', name: 'Port-channel2', cidr: '10.50.2.2/30', vrf: 'default' },
            { id: 'r2-g4', name: 'Gi0/4', cidr: '', vrf: 'default', lacpGroup: 3, lacpMode: 'passive' },
            { id: 'r2-g5', name: 'Gi0/5', cidr: '', vrf: 'default', lacpGroup: 4, lacpMode: 'desirable', lagProtocol: 'pagp' },
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
      links: [
        { id: 'l1', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g1', targetNodeId: 'r2', targetInterfaceId: 'r2-g1', linkType: 'layer2', latencyMs: 5 },
        { id: 'l2', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g2', targetNodeId: 'r2', targetInterfaceId: 'r2-g2', linkType: 'layer2', latencyMs: 9 },
        { id: 'l3', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g3', targetNodeId: 'r2', targetInterfaceId: 'r2-g3', latencyMs: 3 },
        { id: 'l4', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g4', targetNodeId: 'r2', targetInterfaceId: 'r2-g4' },
        { id: 'l5', sourceNodeId: 'r1', sourceInterfaceId: 'r1-g5', targetNodeId: 'r2', targetInterfaceId: 'r2-g5' },
      ],
    };

    const res = solveTopology(topo);
    expect(res.warnings.some((w) => w.includes('Invalid CIDR'))).toBe(false);
    expect(res.warnings.some((w) => w.includes('both ends passive'))).toBe(true);
    expect(res.warnings.some((w) => w.includes('LAG protocol mismatch'))).toBe(true);

    // STP should keep both Gi0/1 and Gi0/2 on R2 as Root Forwarding (no Alternate/Blocking warning on Port-channel1 members)
    const r2Stp = res.nodes['r2']?.stpState;
    expect(r2Stp?.ports.find((p) => p.interfaceName === 'Gi0/1')?.state).toBe('Forwarding');
    expect(r2Stp?.ports.find((p) => p.interfaceName === 'Gi0/2')?.state).toBe('Forwarding');

    // OSPF converges over Port-channel1 and tracePacket inherits lowest active member latency (5ms)
    const trace = tracePacket(topo, res, 'r1', '192.0.2.1');
    expect(trace.outcome).toBe('delivered');
    expect(trace.hops[0]?.egressInterface).toBe('Port-channel1');
    expect(trace.totalLatencyMs).toBe(5);

    // CLI formatting & import round-trip for PAgP & LACP
    const cfg = formatRunningConfig(topo.nodes[0]);
    expect(cfg).toContain('channel-protocol pagp');
    expect(cfg).toContain('channel-group 2 mode desirable');
    const imp = importTopologyFromText(cfg).nodes[0];
    const g3 = imp.interfaces.find((i) => i.name === 'Gi0/3');
    expect(g3?.lacpGroup).toBe(2);
    expect(g3?.lacpMode).toBe('desirable');
    expect(g3?.lagProtocol).toBe('pagp');
  });

  it('automatically accepts and allows any traffic on MPLS (mpls-cloud) and DIA (internet-cloud) nodes', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'edge',
          hostname: 'EDGE-RTR',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'e-wan', name: 'Gi0/0', cidr: '198.51.100.1/30', vrf: 'default' },
            { id: 'e-mpls', name: 'Gi0/1', cidr: '10.99.0.1/30', vrf: 'default' },
          ],
          staticRoutes: [
            { id: 'sr-dia', vrf: 'default', prefix: '0.0.0.0/0', nextHop: '198.51.100.2' },
            { id: 'sr-mpls', vrf: 'default', prefix: '10.200.0.0/16', nextHop: '10.99.0.2' },
          ],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'dia',
          hostname: 'DIA-INET',
          vendor: 'internet-cloud',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'd-0', name: 'wan1', cidr: '198.51.100.2/30', vrf: 'default' }],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65001, peers: [], networks: [] },
          aclRules: [
            { id: 'acl-deny', seq: 10, name: 'DENY_ALL', action: 'deny', protocol: 'any', srcCidr: 'any', dstCidr: 'any' },
          ],
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'mpls',
          hostname: 'MPLS-WAN',
          vendor: 'mpls-cloud',
          routerId: '3.3.3.3',
          position: { x: 200, y: 120 },
          maxPaths: 2,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [{ id: 'm-0', name: 'pe-ce1', cidr: '10.99.0.2/30', vrf: 'default' }],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65500, peers: [], networks: [] },
          aclRules: [
            { id: 'acl-deny-m', seq: 10, name: 'DENY_ALL', action: 'deny', protocol: 'any', srcCidr: 'any', dstCidr: 'any' },
          ],
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l-dia', sourceNodeId: 'edge', sourceInterfaceId: 'e-wan', targetNodeId: 'dia', targetInterfaceId: 'd-0', latencyMs: 8 },
        { id: 'l-mpls', sourceNodeId: 'edge', sourceInterfaceId: 'e-mpls', targetNodeId: 'mpls', targetInterfaceId: 'm-0', latencyMs: 15 },
      ],
    };

    const res = solveTopology(topo);

    const diaTrace = tracePacket(topo, res, 'edge', '8.8.8.8');
    expect(diaTrace.outcome).toBe('delivered');
    expect(diaTrace.hops.at(-1)?.hostname).toBe('DIA-INET');
    expect(diaTrace.hops.at(-1)?.aclStatus).toBe('allowed');
    expect(diaTrace.totalLatencyMs).toBe(8);

    const mplsTrace = tracePacket(topo, res, 'edge', '10.200.50.10');
    expect(mplsTrace.outcome).toBe('delivered');
    expect(mplsTrace.hops.at(-1)?.hostname).toBe('MPLS-WAN');
    expect(mplsTrace.hops.at(-1)?.aclStatus).toBe('allowed');
    expect(mplsTrace.totalLatencyMs).toBe(15);
  });

  it('converges the Cisco MPLS + DMVPN preset (2 DCs, 9 Dual-Router Branches, ECMP, Internet Breakout) and passes all pathTests + MPLS->DMVPN failover', () => {
    const preset = PRESET_TOPOLOGIES.find((p) => p.id === 'cisco-mpls-dmvpn')!;
    expect(preset).toBeDefined();
    expect(preset.topology.nodes.length).toBe(25); // MPLS, Inet Breakout, DMVPN, 4 DC routers, 18 branch routers (9x2)
    expect(preset.pathTests?.length).toBe(10);

    const res = solveTopology(preset.topology);
    expect(res.warnings).toEqual([]);

    const matrix = runPathTestSuite(preset.topology, res, preset.pathTests!);
    expect(matrix.results.filter((r) => !r.passed)).toEqual([]);
    expect(matrix.failed).toBe(0);
    expect(matrix.passed).toBe(10);

    // Asymmetric routing verification: BR8-A -> DC1 goes out via DMVPN-IPSEC-CLOUD and returns via MPLS-WAN-CORE
    const asymTrace = matrix.results.find((r) => r.test.id === 'md-pt-10')?.trace;
    expect(asymTrace?.asymmetricPath).toBe(true);
    expect(asymTrace?.hops.some((h) => h.hostname === 'DMVPN-IPSEC-CLOUD')).toBe(true);
    expect(asymTrace?.returnTrace?.hops.some((h) => h.hostname === 'MPLS-WAN-CORE')).toBe(true);

    // ECMP verification: DC1 -> BR1 has 2 equal-cost paths on MPLS-WAN-CORE (BR1-RTR-A and BR1-RTR-B)
    const ecmpTrace = matrix.results.find((r) => r.test.id === 'md-pt-5')?.trace;
    const mplsHop = ecmpTrace?.hops.find((h) => h.hostname === 'MPLS-WAN-CORE');
    expect(mplsHop?.ecmpPaths?.length).toBeGreaterThanOrEqual(2);

    // Failover check: shut down BR1-A's MPLS uplink -> traffic to DC1 fails over to DMVPN IPsec
    const failoverTopo: TopologyState = {
      ...preset.topology,
      links: preset.topology.links.map((l) =>
        l.id === 'md-br1a-m' ? { ...l, adminDown: true } : l
      ),
    };
    const failoverRes = solveTopology(failoverTopo);
    const foTrace = tracePacket(failoverTopo, failoverRes, 'br-1-a', '10.1.0.1', 'default', {
      srcIp: '10.11.0.10',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(foTrace.outcome).toBe('delivered');
    expect(foTrace.hops.some((h) => h.hostname === 'DMVPN-IPSEC-CLOUD')).toBe(true);

    // Store live-update check: Show on Canvas -> shutdown Gi0/0 -> restore Gi0/0
    const store = useSimStore.getState();
    store.loadPreset('cisco-mpls-dmvpn');
    const pt1 = useSimStore.getState().pathTests.find((t) => t.id === 'md-pt-1')!;
    const initialTrace = tracePacket(
      useSimStore.getState().topology,
      useSimStore.getState().simResult,
      pt1.srcNodeId,
      pt1.dstIp,
      pt1.vrf,
      { srcIp: pt1.srcIp, protocol: pt1.protocol, dstPort: pt1.dstPort }
    );
    useSimStore.getState().setTraceParams(pt1.srcNodeId, pt1.dstIp, pt1.vrf, pt1.protocol, pt1.dstPort, undefined, pt1.srcIp);
    useSimStore.getState().setTraceResult(initialTrace);
    expect(useSimStore.getState().traceResult?.hops.some((h) => h.hostname === 'MPLS-WAN-CORE')).toBe(true);

    // Down BR1-A Gi0/0 (MPLS) -> trace stays on 10.1.0.1 and fails over to DMVPN-IPSEC-CLOUD
    useSimStore.getState().updateInterface('br-1-a', 'br-1-a-g0', { shutdown: true });
    expect(useSimStore.getState().traceResult?.dstIp).toBe('10.1.0.1');
    expect(useSimStore.getState().traceResult?.outcome).toBe('delivered');
    expect(useSimStore.getState().traceResult?.hops.some((h) => h.hostname === 'DMVPN-IPSEC-CLOUD')).toBe(true);

    // Bring BR1-A Gi0/0 back up -> traffic restores to MPLS-WAN-CORE
    useSimStore.getState().updateInterface('br-1-a', 'br-1-a-g0', { shutdown: false });
    expect(useSimStore.getState().traceResult?.dstIp).toBe('10.1.0.1');
    expect(useSimStore.getState().traceResult?.outcome).toBe('delivered');
    expect(useSimStore.getState().traceResult?.hops.some((h) => h.hostname === 'MPLS-WAN-CORE')).toBe(true);
  });

  it('passes all pathTests on the Dual-Homed BGP & OSPF ECMP preset (bgp-ecmp-lab)', () => {
    const preset = PRESET_TOPOLOGIES.find((p) => p.id === 'bgp-ecmp-lab')!;
    expect(preset).toBeDefined();
    expect(preset.pathTests?.length).toBe(3);
    const res = solveTopology(preset.topology);
    const matrix = runPathTestSuite(preset.topology, res, preset.pathTests!);
    expect(matrix.results.filter((r) => !r.passed)).toEqual([]);
    expect(matrix.failed).toBe(0);
    expect(matrix.passed).toBe(3);
  });
});
