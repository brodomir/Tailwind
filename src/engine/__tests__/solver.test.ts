import { describe, expect, it } from 'vitest';
import { PRESET_TOPOLOGIES } from '../../data/presets';
import { computeRibDiff } from '../diff';
import { buildAutomationBundleZip, topologyToYaml } from '../exportBundle';
import { formatCiscoCli, formatPanOsRouteCli, formatForcepointFrrCli, formatForcepointSgCli, formatPrimaryCli, formatRunningConfig, formatSecondaryCli } from '../formatters';
import { importTopologyFromText } from '../importer';
import { ip6ToBigInt, ipToUint32 } from '../ipMath';
import { BinaryRadixTrie, BinaryRadixTrie6 } from '../radixTrie';
import { runPathTestSuite, solveTopology, tracePacket } from '../solver';
import { TopologyState } from '../../types/network';

describe('BinaryRadixTrie', () => {
  it('performs longest prefix match in O(32)', () => {
    const trie = new BinaryRadixTrie<string>();
    trie.insert(ipToUint32('0.0.0.0'), 0, 'default');
    trie.insert(ipToUint32('10.0.0.0'), 8, '10/8');
    trie.insert(ipToUint32('10.50.0.0'), 24, '10.50.0/24');

    expect(trie.longestPrefixMatch(ipToUint32('10.50.0.42'))).toBe('10.50.0/24');
    expect(trie.longestPrefixMatch(ipToUint32('10.99.1.1'))).toBe('10/8');
    expect(trie.longestPrefixMatch(ipToUint32('172.16.1.1'))).toBe('default');
  });
});

describe('Multi-Vendor Control-Plane Solver', () => {
  it('converges Enterprise Edge preset and respects Vendor AD differences', () => {
    const enterprise = PRESET_TOPOLOGIES[0].topology;
    const result = solveTopology(enterprise);

    expect(result.warnings).toHaveLength(0);
    expect(result.convergedIterations).toBeGreaterThanOrEqual(2);

    const panRib = result.nodes['pan-fw1'].rib;
    const panBgpDefault = panRib.find(
      (r) => r.prefix === '0.0.0.0' && r.prefixLen === 0 && r.active
    );
    expect(panBgpDefault?.protocol).toBe('ebgp');
    expect(panBgpDefault?.ad).toBe(20);

    const panOspfDmz = panRib.find(
      (r) => r.prefix === '172.16.30.0' && r.prefixLen === 24 && r.active
    );
    expect(panOspfDmz?.protocol).toBe('ospf');
    expect(panOspfDmz?.ospfType).toBe('inter');
    expect(panOspfDmz?.ad).toBe(30);

    const ciscoOspfDmz = result.nodes['core-sw1'].rib.find(
      (r) => r.prefix === '172.16.30.0' && r.prefixLen === 24 && r.active
    );
    expect(ciscoOspfDmz?.protocol).toBe('ospf');
    expect(ciscoOspfDmz?.ad).toBe(110);

    const ciscoRedistStatic = result.nodes['core-sw1'].rib.find(
      (r) => r.prefix === '192.168.99.0' && r.prefixLen === 24 && r.active
    );
    expect(ciscoRedistStatic?.protocol).toBe('ospf');
    expect(ciscoRedistStatic?.ospfType).toBe('ext1');
  });

  it('traces packet end-to-end across multi-vendor hops', () => {
    const enterprise = PRESET_TOPOLOGIES[0].topology;
    const result = solveTopology(enterprise);

    const traceToIsp = tracePacket(enterprise, result, 'core-sw1', '8.8.8.8');
    expect(traceToIsp.outcome).toBe('delivered');
    expect(traceToIsp.hops.map((h) => h.nodeId)).toEqual([
      'core-sw1',
      'pan-fw1',
      'isp-rtr',
    ]);

    const traceToLan = tracePacket(enterprise, result, 'isp-rtr', '10.50.0.50');
    expect(traceToLan.outcome).toBe('dropped');
  });

  it('runs 9-step BGP tie-breaker (Local-Pref > AS-Path > MED)', () => {
    const bgpPreset = PRESET_TOPOLOGIES[1].topology;
    const result = solveTopology(bgpPreset);

    const edgeRib = result.nodes['edge-1'].rib;
    const activeRoute = edgeRib.find(
      (r) => r.prefix === '198.18.0.0' && r.prefixLen === 16 && r.active
    );
    expect(activeRoute?.protocol).toBe('ebgp');
    expect(activeRoute?.nextHop).toBe('100.64.1.1');
    expect(activeRoute?.bgpAttrs?.localPref).toBe(120);
  });

  it('formats authentic vendor CLI outputs', () => {
    const enterprise = PRESET_TOPOLOGIES[0].topology;
    const result = solveTopology(enterprise);

    const ciscoCli = formatCiscoCli(
      enterprise.nodes.find((n) => n.id === 'core-sw1')!,
      result.nodes['core-sw1']
    );
    expect(ciscoCli).toContain('CORE-IOS-SW1# show ip route');
    expect(ciscoCli).toContain('O E1');

    const panCli = formatPanOsRouteCli(
      enterprise.nodes.find((n) => n.id === 'pan-fw1')!,
      result.nodes['pan-fw1']
    );
    expect(panCli).toContain('admin@PAN-EDGE-FW1> show routing route');
    expect(panCli).toContain('VIRTUAL ROUTER: default');

    const fpCli = formatForcepointFrrCli(
      enterprise.nodes.find((n) => n.id === 'fp-ngfw1')!,
      result.nodes['fp-ngfw1']
    );
    expect(fpCli).toContain('vtysh -c "show ip route"');
  });

  it('supports multi-VRF route-leaking and BGP route-map policy filtering', () => {
    const multiVrf = PRESET_TOPOLOGIES[2].topology;
    const result = solveTopology(multiVrf);

    const panRib = result.nodes['mv-pan'].rib;

    const defaultZero = panRib.find(
      (r) => r.vrf === 'default' && r.prefix === '0.0.0.0' && r.prefixLen === 0 && r.active
    );
    expect(defaultZero?.protocol).toBe('ebgp');
    expect(defaultZero?.bgpAttrs?.localPref).toBe(250);
    expect(defaultZero?.bgpAttrs?.asPath).toEqual([64520, 64520]);

    const deniedPrefix = panRib.find(
      (r) => r.vrf === 'default' && r.prefix === '192.0.2.0' && r.active
    );
    expect(deniedPrefix).toBeUndefined();

    const leakedToDmz = panRib.find(
      (r) => r.vrf === 'DMZ' && r.prefix === '0.0.0.0' && r.prefixLen === 0 && r.active
    );
    expect(leakedToDmz?.leakedFromVrf).toBe('default');

    const leakedToDefault = panRib.find(
      (r) => r.vrf === 'default' && r.prefix === '172.30.200.0' && r.active
    );
    expect(leakedToDefault?.leakedFromVrf).toBe('DMZ');

    const panCli = formatPanOsRouteCli(
      multiVrf.nodes.find((n) => n.id === 'mv-pan')!,
      result.nodes['mv-pan']
    );
    expect(panCli).toContain('VIRTUAL ROUTER: default');
    expect(panCli).toContain('VIRTUAL ROUTER: DMZ');
  });

  it('computes unified RIB diff and builds YAML/ZIP automation exports', () => {
    const baseTopo = structuredClone(PRESET_TOPOLOGIES[0].topology);
    const before = solveTopology(baseTopo);

    const modifiedTopo = structuredClone(baseTopo);
    const pan = modifiedTopo.nodes.find((n) => n.id === 'pan-fw1')!;
    pan.adOverrides.ospf = 150;
    const after = solveTopology(modifiedTopo);

    const diff = computeRibDiff(before, after);
    expect(diff.modified).toBeGreaterThan(0);
    expect(diff.items.some((i) => i.nodeId === 'pan-fw1' && i.after?.ad === 150)).toBe(true);

    const yaml = topologyToYaml(baseTopo);
    expect(yaml).toContain('hostname: PAN-EDGE-FW1');
    expect(yaml).toContain('vendor: pan-os');

    const zipBlob = buildAutomationBundleZip(baseTopo, before);
    expect(zipBlob.size).toBeGreaterThan(500);
  });

  it('supports IPv6 128-bit Radix Trie, EIGRP, IS-IS, Forcepoint PBR, and YAML/CLI import', () => {
    const trie6 = new BinaryRadixTrie6<string>();
    trie6.insert(ip6ToBigInt('2001:db8::'), 32, '32');
    trie6.insert(ip6ToBigInt('2001:db8:1::'), 48, '48');
    expect(trie6.longestPrefixMatch(ip6ToBigInt('2001:db8:1::42'))).toBe('48');
    expect(trie6.longestPrefixMatch(ip6ToBigInt('2001:db8:9::1'))).toBe('32');

    const topo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'R1-IOS',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            {
              id: 'r1-i1',
              name: 'GigabitEthernet0/0',
              cidr: '10.0.12.1/30',
              cidr6: '2001:db8:12::1/64',
              vrf: 'default',
              isisLevel: 'L1',
            },
          ],
          staticRoutes: [
            { id: 's6', vrf: 'default', prefix: '2001:db8:99::/48', nextHop: '2001:db8:12::2' },
          ],
          ospf: { enabled: false, networks: [] },
          eigrp: { enabled: true, asn: 100, networks: [] },
          isis: { enabled: true, level: 'L1', networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
        {
          id: 'r2',
          hostname: 'FP-GW2',
          vendor: 'forcepoint-ngfw',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            {
              id: 'r2-i1',
              name: 'eth0.1',
              cidr: '10.0.12.2/30',
              cidr6: '2001:db8:12::2/64',
              vrf: 'default',
              isisLevel: 'L1',
            },
            {
              id: 'r2-i2',
              name: 'eth0.2',
              cidr: '10.22.0.1/24',
              cidr6: '2001:db8:99::1/64',
              vrf: 'default',
              isisLevel: 'L1',
            },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          eigrp: { enabled: true, asn: 100, networks: [] },
          isis: { enabled: true, level: 'L1', networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
          pbrRules: [
            {
              id: 'pbr-1',
              name: 'VIP-MULTI-LINK',
              matchPrefix: '10.22.0.0/24',
              nextHop: '0.0.0.0',
              multiLinkPool: 'ISP-POOL-A',
            },
          ],
        },
      ],
      links: [
        {
          id: 'l1',
          sourceNodeId: 'r1',
          sourceInterfaceId: 'r1-i1',
          targetNodeId: 'r2',
          targetInterfaceId: 'r2-i1',
        },
      ],
    };

    const res = solveTopology(topo);
    const eigrpRoute = res.nodes['r1'].rib.find(
      (r) => r.prefix === '10.22.0.0' && r.active
    );
    expect(eigrpRoute?.protocol).toBe('eigrp');
    expect(eigrpRoute?.ad).toBe(90);

    const trace6 = tracePacket(topo, res, 'r1', '2001:db8:99::10');
    expect(trace6.outcome).toBe('delivered');
    expect(trace6.hops.map((h) => h.nodeId)).toEqual(['r1', 'r2']);

    const fpSg = formatForcepointSgCli(topo.nodes[1], res.nodes['r2']);
    expect(fpSg).toContain('VIP-MULTI-LINK');
    expect(fpSg).toContain('ISP-POOL-A');

    const yaml = topologyToYaml(topo);
    const reimported = importTopologyFromText(yaml);
    expect(reimported.nodes).toHaveLength(2);
  });

  it('parses real Cisco running-config and PAN-OS set commands', () => {
    const ciscoCfg = `
hostname CORE-RTR-99
ip vrf CORP
!
interface GigabitEthernet0/1
 ip vrf forwarding CORP
 ip address 10.99.1.1 255.255.255.252
 ip ospf 1 area 0
!
router bgp 65199
 bgp router-id 10.99.0.1
 neighbor 10.99.1.2 remote-as 65200
!
ip route vrf CORP 172.16.0.0 255.255.0.0 10.99.1.2 5
`;
    const ciscoTopo = importTopologyFromText(ciscoCfg);
    const ciscoNode = ciscoTopo.nodes[0];
    expect(ciscoNode.hostname).toBe('CORE-RTR-99');
    expect(ciscoNode.vrfs).toContain('CORP');
    expect(ciscoNode.interfaces[0].cidr).toBe('10.99.1.1/30');
    expect(ciscoNode.interfaces[0].vrf).toBe('CORP');
    expect(ciscoNode.bgp.enabled).toBe(true);
    expect(ciscoNode.bgp.asn).toBe(65199);
    expect(ciscoNode.staticRoutes[0].prefix).toBe('172.16.0.0/16');
    expect(ciscoNode.staticRoutes[0].ad).toBe(5);

    const panCfg = `
set deviceconfig system hostname PA-FW-88
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.10/30
set network virtual-router vr-edge interface ethernet1/1
set network virtual-router vr-edge routing-table ip static-route default destination 0.0.0.0/0 nexthop ip-address 203.0.113.9
`;
    const panTopo = importTopologyFromText(panCfg);
    const panNode = panTopo.nodes[0];
    expect(panNode.vendor).toBe('pan-os');
    expect(panNode.hostname).toBe('PA-FW-88');
    expect(panNode.vrfs).toContain('vr-edge');
    expect(panNode.interfaces[0].cidr).toBe('203.0.113.10/30');
    expect(panNode.staticRoutes[0].vrf).toBe('vr-edge');
  });

  it('evaluates ACL security policies and pre-routing DNAT / post-routing SNAT during packet trace', () => {
    const topo = structuredClone(PRESET_TOPOLOGIES[0].topology);
    const pan = topo.nodes.find((n) => n.id === 'pan-fw1')!;
    pan.aclRules = [
      {
        id: 'a1',
        seq: 10,
        name: 'ALLOW-HTTPS',
        action: 'allow',
        srcCidr: '10.0.0.0/8',
        dstCidr: '8.8.8.0/24',
        protocol: 'tcp',
        dstPort: 443,
      },
      {
        id: 'a2',
        seq: 20,
        name: 'DENY-SSH',
        action: 'deny',
        srcCidr: 'any',
        dstCidr: 'any',
        protocol: 'tcp',
        dstPort: 22,
      },
    ];
    pan.natRules = [
      {
        id: 'n1',
        seq: 10,
        name: 'OUTBOUND-SNAT',
        type: 'snat',
        srcCidr: '10.0.0.0/8',
        dstCidr: '8.8.8.0/24',
        translatedIp: '203.0.113.2',
      },
    ];

    const res = solveTopology(topo);

    const httpsTrace = tracePacket(topo, res, 'core-sw1', '8.8.8.8', 'default', {
      srcIp: '10.50.0.10',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(httpsTrace.outcome).toBe('delivered');
    expect(httpsTrace.hops[1].aclMatched).toBe('ALLOW (ALLOW-HTTPS)');
    expect(httpsTrace.hops[1].natApplied).toContain('SNAT 10.50.0.10 → 203.0.113.2');

    const sshTrace = tracePacket(topo, res, 'core-sw1', '8.8.8.8', 'default', {
      srcIp: '10.50.0.10',
      protocol: 'tcp',
      dstPort: 22,
    });
    expect(sshTrace.outcome).toBe('blocked');
    expect(sshTrace.hops[1].status).toBe('blocked');
    expect(sshTrace.hops[1].aclMatched).toBe('DENY (DENY-SSH)');
    expect(sshTrace.blockedNodeId).toBe('pan-fw1');

    const suite = runPathTestSuite(topo, res, [
      {
        id: 't1',
        name: 'South of Vlan10 HTTPS to 8.8.8.8',
        srcNodeId: 'core-sw1',
        srcInterfaceId: 'core-vlan10',
        dstIp: '8.8.8.8',
        vrf: 'default',
        protocol: 'tcp',
        dstPort: 443,
        expectedOutcome: 'delivered',
      },
      {
        id: 't2',
        name: 'South of Vlan10 SSH blocked at PAN',
        srcNodeId: 'core-sw1',
        srcInterfaceId: 'core-vlan10',
        dstIp: '8.8.8.8',
        vrf: 'default',
        protocol: 'tcp',
        dstPort: 22,
        expectedOutcome: 'blocked',
        expectedBlockedNodeId: 'pan-fw1',
      },
    ]);
    expect(suite.passed).toBe(2);
    expect(suite.failed).toBe(0);
    expect(suite.results[0].trace.srcIp).toBe('203.0.113.2');
  });

  it('converges and traces packets across Cloud/WAN nodes and IPsec tunnels', () => {
    const hybrid = PRESET_TOPOLOGIES.find((p) => p.id === 'hybrid-cloud-sdwan');
    expect(hybrid).toBeDefined();
    const topo = structuredClone(hybrid!.topology);
    const res = solveTopology(topo);

    const azureTrace = tracePacket(topo, res, 'hc-fw', '10.100.1.1', 'default', {
      srcIp: '10.50.10.5',
      protocol: 'any',
    });
    expect(azureTrace.outcome).toBe('delivered');
    expect(azureTrace.hops.map((h) => h.nodeId)).toEqual(['hc-fw', 'hc-inet', 'hc-azure']);

    const gcpTrace = tracePacket(topo, res, 'hc-fw', '10.200.1.1', 'default', {
      srcIp: '10.50.10.5',
      protocol: 'any',
    });
    expect(gcpTrace.outcome).toBe('delivered');
    expect(gcpTrace.hops.map((h) => h.nodeId)).toEqual(['hc-fw', 'hc-mpls', 'hc-gcp']);
  });

  it('supports BGP default-originate and next-hop-self in solver and running-config', () => {
    const topo = structuredClone(PRESET_TOPOLOGIES[1].topology);
    const wanA = topo.nodes.find((n) => n.id === 'wan-a')!;
    wanA.bgp.peers[0].defaultOriginate = true;
    wanA.bgp.peers[0].nextHopSelf = true;
    wanA.prefixLists = [
      { id: 'pl-1', name: 'PL-DEFAULT', entries: [{ id: 'ple-1', seq: 10, action: 'permit', prefix: '0.0.0.0/0' }] },
    ];
    wanA.routeMaps = [
      {
        id: 'rm-1',
        name: 'RM-PREPEND',
        entries: [
          {
            id: 'rme-1',
            seq: 10,
            action: 'permit',
            matchPrefixListId: 'pl-1',
            set: { prependAsPath: [64501, 64501], setLocalPref: 150 },
          },
        ],
      },
    ];
    wanA.bgp.peers[0].routeMapOutId = 'rm-1';

    const res = solveTopology(topo);
    const edgeDefault = res.nodes['edge-1'].rib.find(
      (r) => r.prefix === '0.0.0.0' && r.prefixLen === 0 && r.active
    );
    expect(edgeDefault).toBeDefined();
    expect(edgeDefault?.protocol).toBe('ebgp');
    expect(edgeDefault?.nextHop).toBe('100.64.1.1');

    const cfg = formatRunningConfig(wanA);
    expect(cfg).toContain('neighbor 100.64.1.2 next-hop-self');
    expect(cfg).toContain('neighbor 100.64.1.2 default-originate');
    expect(cfg).toContain('neighbor 100.64.1.2 route-map RM-PREPEND out');
    expect(cfg).toContain('ip prefix-list PL-DEFAULT seq 10 permit 0.0.0.0/0');
    expect(cfg).toContain('route-map RM-PREPEND permit 10');
    expect(cfg).toContain('set as-path prepend 64501 64501');
  });

  it('enforces OSPF passive-interface, default-information originate, and RIPv2', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'R1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r1-i1', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default', ospfArea: 0, passive: true },
            { id: 'r1-lo0', name: 'Lo0', cidr: '10.1.1.1/32', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, defaultOriginate: true, networks: [] },
          rip: {
            enabled: true,
            version: 2,
            networks: [{ id: 'rn-1', prefix: '192.168.10.0/24', vrf: 'default' }],
          },
          bgp: { enabled: false, asn: 65001, peers: [], networks: [] },
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
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r2-i1', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          rip: { enabled: true, version: 2, networks: [] },
          bgp: { enabled: false, asn: 65002, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        {
          id: 'l12',
          sourceNodeId: 'r1',
          sourceInterfaceId: 'r1-i1',
          targetNodeId: 'r2',
          targetInterfaceId: 'r2-i1',
        },
      ],
    };

    const passiveRes = solveTopology(topo);
    expect(passiveRes.nodes['r2'].rib.some((r) => r.prefix === '10.1.1.1')).toBe(false);
    expect(passiveRes.nodes['r2'].rib.some((r) => r.protocol === 'rip')).toBe(false);

    topo.nodes[0].interfaces[0].passive = false;
    const activeRes = solveTopology(topo);
    expect(activeRes.nodes['r2'].rib.some((r) => r.prefix === '10.1.1.1' && r.protocol === 'ospf')).toBe(true);
    expect(activeRes.nodes['r2'].rib.some((r) => r.prefix === '0.0.0.0' && r.protocol === 'ospf')).toBe(true);
    const ripRoute = activeRes.nodes['r2'].rib.find((r) => r.prefix === '192.168.10.0' && r.active);
    expect(ripRoute?.protocol).toBe('rip');
    expect(ripRoute?.ad).toBe(120);

    topo.nodes[0].interfaces[0].passive = true;
    const cfg = formatRunningConfig(topo.nodes[0]);
    expect(cfg).toContain('passive-interface Gi0/0');
    expect(cfg).toContain('default-information originate');
    expect(cfg).toContain('router rip');

    topo.nodes[0].interfaces[0].passive = false;
    topo.nodes[0].interfaces[0].speedMbps = 10000;
    topo.nodes[1].interfaces[0].speedMbps = 10000;
    topo.nodes[1].ospf.referenceBandwidth = 100000;
    const bwRes = solveTopology(topo);
    const ospfLo = bwRes.nodes['r2'].rib.find((r) => r.prefix === '10.1.1.1' && r.active);
    expect(ospfLo?.metric).toBe(20);
  });

  it('supports BGP route-reflector-client, OSPFv3 IPv6, full-mesh redistribution, and FortiGate/FRR import', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'c1',
          hostname: 'CLIENT-1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'c1-i1', name: 'Gi0/0', cidr: '10.0.12.1/30', cidr6: '2001:db8:12::1/64', vrf: 'default', ospfArea: 0 },
            { id: 'c1-lo', name: 'Lo0', cidr: '10.11.11.1/32', cidr6: '2001:db8:11::1/128', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65000,
            peers: [{ id: 'p1', peerIp: '10.0.12.2', remoteAs: 65000 }],
            networks: [{ id: 'n1', prefix: '192.0.2.0/24' }],
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
          position: { x: 200, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'rr-i1', name: 'Gi0/0', cidr: '10.0.12.2/30', cidr6: '2001:db8:12::2/64', vrf: 'default', ospfArea: 0 },
            { id: 'rr-i2', name: 'Gi0/1', cidr: '10.0.23.1/30', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65000,
            peers: [
              { id: 'pr1', peerIp: '10.0.12.1', remoteAs: 65000, routeReflectorClient: true },
              { id: 'pr2', peerIp: '10.0.23.2', remoteAs: 65000, routeReflectorClient: true },
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
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'c2-i1', name: 'Gi0/0', cidr: '10.0.23.2/30', vrf: 'default', ospfArea: 0 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          eigrp: { enabled: true, asn: 100, networks: [] },
          bgp: {
            enabled: true,
            asn: 65000,
            peers: [{ id: 'p2', peerIp: '10.0.23.1', remoteAs: 65000 }],
            networks: [],
          },
          redistributions: [{ id: 'rd1', from: 'ospf', to: 'eigrp', metric: 50 }],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l1', sourceNodeId: 'c1', sourceInterfaceId: 'c1-i1', targetNodeId: 'rr', targetInterfaceId: 'rr-i1' },
        { id: 'l2', sourceNodeId: 'rr', sourceInterfaceId: 'rr-i2', targetNodeId: 'c2', targetInterfaceId: 'c2-i1' },
      ],
    };

    const res = solveTopology(topo);
    expect(res.nodes['c2'].rib.some((r) => r.prefix === '192.0.2.0' && r.protocol === 'ibgp')).toBe(true);
    expect(
      res.nodes['c2'].rib.some((r) => r.af === 6 && r.prefix === '2001:db8:11::1' && r.protocol === 'ospf')
    ).toBe(true);

    const fortiCfg = `
config system global
    set hostname "FGT-EDGE-1"
end
config system interface
    edit "port1"
        set ip 10.77.1.1 255.255.255.252
    next
end
config router bgp
    set as 65077
    set router-id 10.77.0.1
    config neighbor
        edit "10.77.1.2"
            set remote-as 65001
        next
    end
end
`;
    const fgt = importTopologyFromText(fortiCfg).nodes[0];
    expect(fgt.vendor).toBe('fortigate');
    expect(fgt.hostname).toBe('FGT-EDGE-1');
    expect(fgt.interfaces[0].cidr).toBe('10.77.1.1/30');
    expect(fgt.bgp.asn).toBe(65077);

    const frrCfg = `
! Forcepoint NGFW FRR
hostname FP-FW-1
interface eth0.10
 ip address 10.88.1.1/24
!
`;
    const fp = importTopologyFromText(frrCfg).nodes[0];
    expect(fp.vendor).toBe('forcepoint-ngfw');
    expect(fp.hostname).toBe('FP-FW-1');
  });

  it('supports adminDown links, BGP communities/AS-Path regex, OSPF stub & auth mismatch, HSRP VIPs, and security zones', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'r1',
          hostname: 'R1',
          vendor: 'cisco-ios-xe',
          routerId: '1.1.1.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r1-i1', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default', ospfArea: 0, ospfAuthKey: 'secret1', zone: 'inside' },
            { id: 'r1-i2', name: 'Gi0/1', cidr: '10.1.1.1/24', vrf: 'default', zone: 'dmz' },
          ],
          staticRoutes: [],
          ospf: { enabled: true, networks: [] },
          bgp: {
            enabled: true,
            asn: 65001,
            networks: [{ id: 'bn1', prefix: '10.1.1.0/24' }],
            peers: [{ id: 'bp1', peerIp: '10.0.12.2', remoteAs: 65002, routeMapOutId: 'rm-out' }],
          },
          redistributions: [{ id: 'rd1', from: 'connected', to: 'ospf' }],
          prefixLists: [],
          routeMaps: [
            {
              id: 'rm-out',
              name: 'TAG_OUT',
              entries: [{ id: 'rme1', seq: 10, action: 'permit', set: { setCommunity: '65001:100' } }],
            },
          ],
          vrfLeaks: [],
          fhrpGroups: [
            { id: 'f1', protocol: 'hsrp', groupId: 1, interfaceId: 'r1-i2', virtualIp: '10.1.1.254', priority: 120 },
          ],
          aclRules: [
            {
              id: 'acl1',
              seq: 10,
              name: 'BLOCK_INSIDE_DMZ',
              action: 'deny',
              srcZone: 'inside',
              dstZone: 'dmz',
              srcCidr: '0.0.0.0/0',
              dstCidr: '10.1.1.0/24',
              protocol: 'any',
            },
          ],
        },
        {
          id: 'r2',
          hostname: 'R2',
          vendor: 'cisco-ios-xe',
          routerId: '2.2.2.2',
          position: { x: 200, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r2-i1', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', ospfArea: 0, ospfAuthKey: 'wrong', zone: 'outside' },
            { id: 'r2-i2', name: 'Gi0/1', cidr: '10.0.23.1/30', vrf: 'default', ospfArea: 1 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, areaTypes: { 1: 'stub' }, networks: [] },
          bgp: {
            enabled: true,
            asn: 65002,
            networks: [],
            peers: [{ id: 'bp2', peerIp: '10.0.12.1', remoteAs: 65001, routeMapInId: 'rm-in' }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [
            {
              id: 'rm-in',
              name: 'FILTER_IN',
              entries: [{ id: 'rme2', seq: 10, action: 'permit', matchCommunity: '65001:100', matchAsPathRegex: '^65001$', set: {} }],
            },
          ],
          vrfLeaks: [],
          fhrpGroups: [
            { id: 'f2', protocol: 'hsrp', groupId: 1, interfaceId: 'r2-i2', virtualIp: '10.1.1.254', priority: 90 },
          ],
        },
        {
          id: 'r3',
          hostname: 'R3',
          vendor: 'cisco-ios-xe',
          routerId: '3.3.3.3',
          position: { x: 400, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'r3-i1', name: 'Gi0/0', cidr: '10.0.23.2/30', vrf: 'default', ospfArea: 1 },
          ],
          staticRoutes: [],
          ospf: { enabled: true, areaTypes: { 1: 'stub' }, networks: [] },
          bgp: { enabled: false, asn: 65003, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'l12', sourceNodeId: 'r1', sourceInterfaceId: 'r1-i1', targetNodeId: 'r2', targetInterfaceId: 'r2-i1' },
        { id: 'l23', sourceNodeId: 'r2', sourceInterfaceId: 'r2-i2', targetNodeId: 'r3', targetInterfaceId: 'r3-i1' },
      ],
    };

    const res = solveTopology(topo);

    expect(res.warnings.some((w) => w.includes('OSPF auth key mismatch'))).toBe(true);
    expect(res.nodes['r1'].rib.some((r) => r.prefix === '10.1.1.254' && r.prefixLen === 32 && r.protocol === 'local')).toBe(true);
    expect(res.nodes['r2'].rib.some((r) => r.prefix === '10.1.1.254' && r.prefixLen === 32)).toBe(false);
    expect(res.nodes['r2'].rib.some((r) => r.prefix === '10.1.1.0' && r.prefixLen === 24 && r.protocol === 'ebgp')).toBe(true);
    expect(res.nodes['r3'].rib.some((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0 && r.protocol === 'ospf')).toBe(true);
    expect(res.nodes['r3'].rib.some((r) => r.protocol === 'ospf' && r.ospfType === 'ext2')).toBe(false);

    const downTopo: TopologyState = {
      ...topo,
      links: [
        { ...topo.links[0], adminDown: true },
        topo.links[1],
      ],
    };
    const downRes = solveTopology(downTopo);
    expect(downRes.nodes['r2'].rib.some((r) => r.prefix === '10.1.1.0' && r.prefixLen === 24 && r.protocol === 'ebgp')).toBe(false);

    const trace = tracePacket(topo, res, 'r1', '10.1.1.10', 'default', {
      srcInterfaceId: 'r1-i1',
      srcIp: '10.0.12.1',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(trace.outcome).toBe('blocked');
    expect(trace.failureReason).toContain('BLOCK_INSIDE_DMZ');
  });

  it('supports BGP aggregates, no-export community, tracked static routes, VLAN mismatch, neighbors, returnTrace, and extended CLI import', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'a',
          hostname: 'A',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'a-1', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default', vlanId: 10 },
            { id: 'a-2', name: 'Lo0', cidr: '172.16.1.1/24', vrf: 'default' },
            { id: 'a-3', name: 'Lo1', cidr: '172.16.2.1/24', vrf: 'default' },
          ],
          tracks: [{ id: 't1', targetIp: '198.51.100.1' }],
          staticRoutes: [
            { id: 's1', vrf: 'default', prefix: '192.0.2.0/24', nextHop: '10.0.12.2', trackId: 't1' },
          ],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65010,
            peers: [{ id: 'p1', peerIp: '10.0.12.2', remoteAs: 65020, routeMapOutId: 'rm-noexp' }],
            networks: [
              { id: 'n1', prefix: '172.16.1.0/24' },
              { id: 'n2', prefix: '172.16.2.0/24' },
            ],
            aggregates: [{ id: 'ag1', prefix: '172.16.0.0/16', summaryOnly: true }],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [
            {
              id: 'rm-noexp',
              name: 'TAG_NOEXP',
              entries: [{ id: 'e1', seq: 10, action: 'permit', set: { setCommunity: 'no-export' } }],
            },
          ],
          vrfLeaks: [],
        },
        {
          id: 'b',
          hostname: 'B',
          vendor: 'cisco-ios-xe',
          routerId: '10.0.0.2',
          position: { x: 200, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'b-1', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default', vlanId: 10 },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: {
            enabled: true,
            asn: 65020,
            peers: [{ id: 'p2', peerIp: '10.0.12.1', remoteAs: 65010 }],
            networks: [],
          },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
        },
      ],
      links: [
        { id: 'lab', sourceNodeId: 'a', sourceInterfaceId: 'a-1', targetNodeId: 'b', targetInterfaceId: 'b-1' },
      ],
    };

    const res = solveTopology(topo);
    expect(res.nodes['a'].rib.some((r) => r.prefix === '192.0.2.0')).toBe(false);
    expect(res.nodes['a'].rib.some((r) => r.prefix === '172.16.0.0' && r.prefixLen === 16)).toBe(true);
    expect(res.nodes['b'].rib.some((r) => r.prefix === '172.16.1.0')).toBe(false);
    expect(res.nodes['a'].neighbors?.some((n) => n.protocol === 'bgp' && n.state === 'Established')).toBe(true);

    const trace = tracePacket(topo, res, 'b', '172.16.1.1', 'default', { srcIp: '10.0.12.2' });
    expect(trace.outcome).toBe('delivered');
    expect(trace.returnTrace?.outcome).toBe('delivered');

    const vlanMismatchTopo: TopologyState = {
      ...topo,
      nodes: topo.nodes.map((n) =>
        n.id === 'b'
          ? { ...n, interfaces: n.interfaces.map((i) => ({ ...i, vlanId: 20 })) }
          : n
      ),
    };
    const vmRes = solveTopology(vlanMismatchTopo);
    expect(vmRes.warnings.some((w) => w.includes('VLAN mismatch'))).toBe(true);

    const imp = importTopologyFromText(`
hostname R-IMP
interface Gi0/0.10
 encapsulation dot1Q 10
 zone-member security inside
 ip address 10.10.10.1 255.255.255.0
 standby 1 ip 10.10.10.254
 standby 1 priority 115
!
router ospf 1
 area 1 stub no-summary
 area 1 range 10.10.0.0 255.255.0.0
!
router bgp 65100
 neighbor 10.10.10.2 remote-as 65200
 neighbor 10.10.10.2 ebgp-multihop
 aggregate-address 10.10.0.0 255.255.0.0 summary-only
!
`).nodes[0];
    expect(imp.interfaces[0].vlanId).toBe(10);
    expect(imp.interfaces[0].zone).toBe('inside');
    expect(imp.fhrpGroups?.[0].virtualIp).toBe('10.10.10.254');
    expect(imp.ospf.areaTypes?.[1]).toBe('totally-stubby');
    expect(imp.ospf.areaRanges?.[0].prefix).toBe('10.10.0.0/16');
    expect(imp.bgp.peers[0].ebgpMultihop).toBe(true);
    expect(imp.bgp.aggregates?.[0].summaryOnly).toBe(true);
  });

  it('supports NX-OS vPC domain, peer-gateway, peer-switch, diagnostics, CLI formatting, and import', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'nx1',
          hostname: 'NX-LEAF-1',
          vendor: 'cisco-nx-os',
          routerId: '10.1.0.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'nx1-po1', name: 'port-channel1', cidr: '10.254.0.1/30', vrf: 'default' },
            { id: 'nx1-po10', name: 'port-channel10', cidr: '10.10.10.1/24', vrf: 'default', vpcId: 10 },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
          vpc: {
            enabled: true,
            domainId: 100,
            rolePriority: 100,
            systemPriority: 1000,
            peerKeepaliveDst: '10.254.0.2',
            peerKeepaliveSrc: '10.254.0.1',
            peerKeepaliveVrf: 'default',
            peerLinkInterfaceId: 'nx1-po1',
            peerGateway: true,
            peerSwitch: true,
            layer3PeerRouter: true,
            autoRecovery: true,
            ipArpSynchronize: true,
            delayRestore: 30,
          },
        },
        {
          id: 'nx2',
          hostname: 'NX-LEAF-2',
          vendor: 'cisco-nx-os',
          routerId: '10.1.0.2',
          position: { x: 200, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'nx2-po1', name: 'port-channel1', cidr: '10.254.0.2/30', vrf: 'default' },
            { id: 'nx2-po10', name: 'port-channel10', cidr: '10.10.10.2/24', vrf: 'default', vpcId: 10 },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
          vpc: {
            enabled: true,
            domainId: 100,
            rolePriority: 200,
            systemPriority: 1000,
            peerKeepaliveDst: '10.254.0.1',
            peerKeepaliveSrc: '10.254.0.2',
            peerKeepaliveVrf: 'default',
            peerLinkInterfaceId: 'nx2-po1',
            peerGateway: true,
            peerSwitch: true,
          },
        },
      ],
      links: [
        { id: 'l-pl', sourceNodeId: 'nx1', sourceInterfaceId: 'nx1-po1', targetNodeId: 'nx2', targetInterfaceId: 'nx2-po1' },
      ],
    };

    const res = solveTopology(topo);
    expect(res.warnings).toHaveLength(0);
    expect(res.nodes['nx1'].neighbors?.some((n) => n.protocol === 'vpc' && n.state === 'Up' && n.detail?.includes('Primary'))).toBe(true);
    expect(res.nodes['nx2'].neighbors?.some((n) => n.protocol === 'vpc' && n.state === 'Up' && n.detail?.includes('Secondary'))).toBe(true);

    const cfg = formatRunningConfig(topo.nodes[0]);
    expect(cfg).toContain('feature vpc');
    expect(cfg).toContain('vpc domain 100');
    expect(cfg).toContain('peer-gateway');
    expect(cfg).toContain('peer-switch');
    expect(cfg).toContain('layer3 peer-router');
    expect(cfg).toContain('vpc peer-link');
    expect(cfg).toContain('vpc 10');

    const imported = importTopologyFromText(cfg).nodes[0];
    expect(imported.vendor).toBe('cisco-nx-os');
    expect(imported.vpc?.enabled).toBe(true);
    expect(imported.vpc?.domainId).toBe(100);
    expect(imported.vpc?.peerGateway).toBe(true);
    expect(imported.vpc?.peerSwitch).toBe(true);
    expect(imported.vpc?.layer3PeerRouter).toBe(true);
    expect(imported.interfaces.some((i) => i.vpcId === 10)).toBe(true);

    const mismatchTopo: TopologyState = {
      ...topo,
      nodes: topo.nodes.map((n) =>
        n.id === 'nx2' ? { ...n, vpc: { ...n.vpc!, peerSwitch: false } } : n
      ),
    };
    const mmRes = solveTopology(mismatchTopo);
    expect(mmRes.warnings.some((w) => w.includes('peer-switch mismatch'))).toBe(true);
  });

  it('supports PAN-OS HA/HSCI session peering, FortiGate FGCP, Arista MLAG, and link latency/loss/jitter', () => {
    const topo: TopologyState = {
      nodes: [
        {
          id: 'pa1',
          hostname: 'PA-FW-1',
          vendor: 'pan-os',
          routerId: '10.2.0.1',
          position: { x: 0, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'pa1-ha1', name: 'ha1', cidr: '10.200.1.1/30', vrf: 'default' },
            { id: 'pa1-hsci', name: 'hsci', cidr: '10.200.2.1/30', vrf: 'default' },
            { id: 'pa1-lan', name: 'ethernet1/1', cidr: '10.50.0.1/24', vrf: 'default' },
          ],
          staticRoutes: [],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
          panHa: {
            enabled: true,
            mode: 'active-active',
            groupId: 5,
            devicePriority: 50,
            preempt: true,
            sessionSync: true,
            ha1InterfaceId: 'pa1-ha1',
            ha3HsciInterfaceId: 'pa1-hsci',
          },
        },
        {
          id: 'pa2',
          hostname: 'PA-FW-2',
          vendor: 'pan-os',
          routerId: '10.2.0.2',
          position: { x: 200, y: 0 },
          maxPaths: 4,
          vrfs: ['default'],
          adOverrides: {},
          interfaces: [
            { id: 'pa2-ha1', name: 'ha1', cidr: '10.200.1.2/30', vrf: 'default' },
            { id: 'pa2-hsci', name: 'hsci', cidr: '10.200.2.2/30', vrf: 'default' },
            { id: 'pa2-lan', name: 'ethernet1/2', cidr: '10.60.0.1/24', vrf: 'default' },
          ],
          staticRoutes: [
            { id: 'sr1', vrf: 'default', prefix: '10.50.0.0/24', nextHop: '10.200.2.1' },
          ],
          ospf: { enabled: false, networks: [] },
          bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
          redistributions: [],
          prefixLists: [],
          routeMaps: [],
          vrfLeaks: [],
          panHa: {
            enabled: true,
            mode: 'active-active',
            groupId: 5,
            devicePriority: 100,
            sessionSync: true,
            ha1InterfaceId: 'pa2-ha1',
            ha3HsciInterfaceId: 'pa2-hsci',
          },
        },
      ],
      links: [
        { id: 'l-ha1', sourceNodeId: 'pa1', sourceInterfaceId: 'pa1-ha1', targetNodeId: 'pa2', targetInterfaceId: 'pa2-ha1' },
        {
          id: 'l-hsci',
          sourceNodeId: 'pa1',
          sourceInterfaceId: 'pa1-hsci',
          targetNodeId: 'pa2',
          targetInterfaceId: 'pa2-hsci',
          latencyMs: 12,
          jitterMs: 2,
          lossPct: 1.5,
        },
      ],
    };

    const res = solveTopology(topo);
    expect(res.warnings).toHaveLength(0);
    expect(res.nodes['pa1'].neighbors?.some((n) => n.protocol === 'ha' && n.detail?.includes('HSCI'))).toBe(true);

    const panCfg = formatRunningConfig(topo.nodes[0]);
    expect(panCfg).toContain('set deviceconfig high-availability interface ha3 port hsci');
    expect(panCfg).toContain('set deviceconfig high-availability group state-synchronization enabled yes');

    const trace = tracePacket(topo, res, 'pa2', '10.50.0.10', 'default', { srcIp: '10.60.0.10' });
    expect(trace.outcome).toBe('delivered');
    expect(trace.totalLatencyMs).toBe(12);
    expect(trace.totalJitterMs).toBe(2);
    expect(trace.combinedLossPct).toBe(1.5);

    const blackholeTopo: TopologyState = {
      ...topo,
      links: topo.links.map((l) => (l.id === 'l-hsci' ? { ...l, lossPct: 100 } : l)),
    };
    const bhTrace = tracePacket(blackholeTopo, res, 'pa2', '10.50.0.10', 'default', { srcIp: '10.60.0.10' });
    expect(bhTrace.outcome).toBe('dropped');
    expect(bhTrace.failureReason).toContain('100% link loss');
  });

  it('supports MTU mismatch/PMTUD warnings, BGP soft-reconfiguration inbound, BFD, Graceful Restart, and DC vPC/HSCI preset', () => {
    const dcPreset = PRESET_TOPOLOGIES.find((p) => p.id === 'dc-vpc-hsci')!;
    const dcRes = solveTopology(dcPreset.topology);
    expect(dcRes.warnings).toHaveLength(0);
    expect(
      dcRes.nodes['dc-nx1'].neighbors?.some(
        (n) => n.protocol === 'bgp' && n.detail?.includes('BFD') && n.detail?.includes('Soft-Reconfig') && n.detail?.includes('GR')
      )
    ).toBe(true);

    const cfg = formatRunningConfig(dcPreset.topology.nodes[0]);
    expect(cfg).toContain('mtu 9000');
    expect(cfg).toContain('bfd all-interfaces');
    expect(cfg).toContain('bgp graceful-restart');
    expect(cfg).toContain('fall-over bfd');
    expect(cfg).toContain('soft-reconfiguration inbound');

    const imp = importTopologyFromText(cfg).nodes[0];
    expect(imp.interfaces[0].mtu).toBe(9000);
    expect(imp.bgp.peers[0].bfd).toBe(true);
    expect(imp.bgp.peers[0].softReconfigurationInbound).toBe(true);
    expect(imp.bgp.peers[0].gracefulRestart).toBe(true);

    const mtuMismatchTopo: TopologyState = {
      ...dcPreset.topology,
      nodes: dcPreset.topology.nodes.map((n) =>
        n.id === 'dc-nx2'
          ? { ...n, interfaces: n.interfaces.map((i) => ({ ...i, mtu: 1500 })) }
          : n
      ),
    };
    const mmRes = solveTopology(mtuMismatchTopo);
    expect(mmRes.warnings.some((w) => w.includes('MTU mismatch'))).toBe(true);

    const pmtudTrace = tracePacket(dcPreset.topology, dcRes, 'dc-nx1', '172.16.50.1', 'default', {
      packetSize: 1600,
    });
    expect(pmtudTrace.outcome).toBe('delivered');
    expect(pmtudTrace.pathMtu).toBe(1500);
    expect(pmtudTrace.mtuWarning).toContain('exceeds path MTU 1500B');
  });

  it('converges and traces the Full Showcase multi-vendor topology end-to-end', () => {
    const showcase = PRESET_TOPOLOGIES.find((p) => p.id === 'full-showcase')!;
    const res = solveTopology(showcase.topology);

    expect(res.warnings).toHaveLength(0);
    expect(res.nodes['sh-nx1'].neighbors?.some((n) => n.protocol === 'vpc' && n.state === 'Up')).toBe(true);
    expect(res.nodes['sh-ar1'].neighbors?.some((n) => n.protocol === 'mlag' && n.state === 'Up')).toBe(true);
    expect(res.nodes['sh-pa1'].neighbors?.some((n) => n.protocol === 'ha' && n.detail?.includes('HSCI'))).toBe(true);
    expect(res.nodes['sh-fgt1'].neighbors?.some((n) => n.protocol === 'ha' && n.state === 'Active')).toBe(true);
    expect(res.nodes['sh-ios1'].neighbors?.some((n) => n.protocol === 'hsrp' && n.state === 'Active')).toBe(true);

    expect(res.nodes['sh-pa1'].rib.some((r) => r.prefix === '10.10.0.0' && r.prefixLen === 16 && r.bgpAttrs?.localPref === 150)).toBe(true);
    expect(res.nodes['sh-pa1'].rib.some((r) => r.prefix === '10.10.1.0' && r.prefixLen === 24 && r.protocol === 'ebgp')).toBe(false);
    expect(res.nodes['sh-ios1'].rib.some((r) => r.prefix === '198.51.100.0' && r.protocol === 'static')).toBe(true);
    expect(res.nodes['sh-ios2'].rib.some((r) => r.af === 6 && r.prefix === '2001:db8:40::' && r.protocol === 'ospf')).toBe(true);
    expect(res.nodes['sh-ios2'].rib.some((r) => r.prefix === '10.50.1.0' && r.vrf === 'default' && r.leakedFromVrf === 'corp')).toBe(true);

    const httpsTrace = tracePacket(showcase.topology, res, 'sh-nx1', '8.8.8.8', 'default', {
      srcIp: '10.10.1.10',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(httpsTrace.outcome).toBe('delivered');
    expect(httpsTrace.totalLatencyMs).toBe(19);
    expect(httpsTrace.totalJitterMs).toBe(3);
    expect(httpsTrace.combinedLossPct).toBe(0.5);
    expect(httpsTrace.pathMtu).toBe(1400);

    const telnetTrace = tracePacket(showcase.topology, res, 'sh-nx1', '8.8.8.8', 'default', {
      srcIp: '10.10.1.10',
      protocol: 'tcp',
      dstPort: 23,
    });
    expect(telnetTrace.outcome).toBe('blocked');
    expect(telnetTrace.failureReason).toContain('DENY_TELNET');
  });

  it('converges and traces the Multinational Spine-Leaf + Global WAN topology end-to-end', () => {
    const multinational = PRESET_TOPOLOGIES.find((p) => p.id === 'global-multinational');
    expect(multinational).toBeDefined();
    if (!multinational) return;

    const res = solveTopology(multinational.topology);
    expect(res.warnings).toHaveLength(0);

    expect(res.nodes['us-nx1'].neighbors?.some((n) => n.protocol === 'vpc' && n.state === 'Up')).toBe(true);
    expect(res.nodes['us-ar1'].neighbors?.some((n) => n.protocol === 'mlag' && n.state === 'Up')).toBe(true);
    expect(res.nodes['us-pa1'].neighbors?.some((n) => n.protocol === 'ha' && n.detail?.includes('HSCI'))).toBe(true);
    expect(res.nodes['eu-fgt1'].neighbors?.some((n) => n.protocol === 'ha' && n.state === 'Active')).toBe(true);
    expect(res.nodes['ap-fp1'].neighbors?.some((n) => n.protocol === 'ha' && n.state === 'Active')).toBe(true);
    expect(res.nodes['eu-ios1'].neighbors?.some((n) => n.protocol === 'hsrp' && n.state === 'Active')).toBe(true);
    expect(res.nodes['ap-ios1'].neighbors?.some((n) => n.protocol === 'hsrp' && n.state === 'Active')).toBe(true);

    expect(res.nodes['us-pa1'].rib.some((r) => r.prefix === '10.10.0.0' && r.prefixLen === 16 && r.bgpAttrs?.localPref === 150)).toBe(true);
    expect(res.nodes['ap-ios1'].rib.some((r) => r.prefix === '198.51.100.0' && r.prefixLen === 24 && r.protocol === 'static')).toBe(true);
    expect(res.nodes['ap-ios1'].rib.some((r) => r.prefix === '10.30.99.0' && r.prefixLen === 24 && r.vrf === 'default' && r.leakedFromVrf === 'guest')).toBe(true);
    expect(res.nodes['ap-ios1'].rib.some((r) => r.prefix === '172.31.10.0' && r.prefixLen === 24)).toBe(true);

    const awsTrace = tracePacket(multinational.topology, res, 'ap-ios1', '172.31.10.10', 'default', {
      srcIp: '10.30.10.10',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(awsTrace.outcome).toBe('delivered');
    expect(awsTrace.totalLatencyMs).toBe(124);
    expect(awsTrace.pathMtu).toBe(1400);

    const telnetTrace = tracePacket(multinational.topology, res, 'gl-mpls', '10.10.100.1', 'default', {
      srcIp: '198.51.100.5',
      protocol: 'tcp',
      dstPort: 23,
    });
    expect(telnetTrace.outcome).toBe('blocked');
    expect(telnetTrace.failureReason).toContain('BLOCK_TELNET_WAN');
  });

  it('supports Juniper Junos and MikroTik RouterOS (preferences/AD, CLI formatting, and config import)', () => {
    const junosCfg = [
      'set system host-name JNP-EDGE-1',
      'set routing-options router-id 10.255.1.1',
      'set interfaces ge-0/0/0 unit 0 family inet address 10.60.0.1/30',
      'set interfaces lo0 unit 0 family inet address 10.60.10.1/32',
      'set protocols ospf area 0.0.0.0 interface ge-0/0/0.0',
      'set protocols ospf area 0.0.0.0 interface lo0.0',
      'set routing-options static route 172.30.0.0/16 next-hop 10.60.0.2',
      'set routing-options autonomous-system 65401',
      'set protocols bgp group WAN neighbor 10.60.0.2 peer-as 65402',
    ].join('\n');

    const mtCfg = [
      '/system identity set name=MT-CHR-2',
      '/ip address add address=10.60.0.2/30 interface=ether1',
      '/ip address add address=192.168.77.1/24 interface=bridge1',
      '/routing ospf instance add name=default-v2 router-id=10.255.2.2',
      '/routing ospf area add name=backbone area-id=0.0.0.0 instance=default-v2',
      '/routing ospf interface-template add area=backbone interfaces=ether1,bridge1',
      '/routing bgp template set default as=65402 router-id=10.255.2.2',
      '/routing bgp connection add name=to-jnp remote.address=10.60.0.1 remote.as=65401 templates=default',
    ].join('\n');

    const jNode = importTopologyFromText(junosCfg).nodes[0];
    const mNode = importTopologyFromText(mtCfg).nodes[0];
    expect(jNode.vendor).toBe('juniper-junos');
    expect(mNode.vendor).toBe('mikrotik-routeros');

    const topo: TopologyState = {
      nodes: [jNode, mNode],
      links: [
        {
          id: 'jm-1',
          sourceNodeId: jNode.id,
          sourceInterfaceId: jNode.interfaces[0].id,
          targetNodeId: mNode.id,
          targetInterfaceId: mNode.interfaces[0].id,
        },
      ],
    };

    const res = solveTopology(topo);
    const jRib = res.nodes[jNode.id].rib;
    const mRib = res.nodes[mNode.id].rib;

    // Junos static preference 5 & OSPF internal preference 10
    const jStatic = jRib.find((r) => r.prefix === '172.30.0.0' && r.active);
    const jOspf = jRib.find((r) => r.prefix === '192.168.77.0' && r.active);
    expect(jStatic?.ad).toBe(5);
    expect(jOspf?.protocol).toBe('ospf');
    expect(jOspf?.ad).toBe(10);

    // MikroTik learns Junos Lo0 via OSPF with AD 110
    const mOspf = mRib.find((r) => r.prefix === '10.60.10.1' && r.active);
    expect(mOspf?.protocol).toBe('ospf');
    expect(mOspf?.ad).toBe(110);

    // CLI & running config formatting
    const jCli = formatPrimaryCli(jNode, res.nodes[jNode.id]);
    const jFib = formatSecondaryCli(jNode, res.nodes[jNode.id]);
    const mCli = formatPrimaryCli(mNode, res.nodes[mNode.id]);
    expect(jCli).toContain('show route table inet.0');
    expect(jCli).toContain('[OSPF/10]');
    expect(jFib).toContain('show route forwarding-table');
    expect(mCli).toContain('/ip route print');
    expect(mCli).toContain('ADo');
    expect(formatRunningConfig(jNode)).toContain('set system host-name JNP-EDGE-1');
    expect(formatRunningConfig(mNode)).toContain('/system identity set name=MT-CHR-2');
  });
});

