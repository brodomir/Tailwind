import { describe, expect, it } from 'vitest';
import { evaluateRouteMap, matchPrefixList } from '../policy';
import { solveTopology } from '../solver';
import type { PrefixListConfig, RouteMapConfig, TopologyState } from '../../types/network';

describe('IP Prefix Lists & Route Maps (Policy Engine + RIB Updates)', () => {
  describe('Unit Policy Evaluation (matchPrefixList & evaluateRouteMap)', () => {
    const prefixList: PrefixListConfig = {
      id: 'pl-1',
      name: 'CORP_FILTER',
      entries: [
        { id: 'e2', seq: 20, action: 'permit', prefix: '10.0.0.0/8', ge: 24, le: 26 },
        { id: 'e1', seq: 10, action: 'deny', prefix: '10.99.0.0/16', ge: 24, le: 32 },
        { id: 'e3', seq: 30, action: 'permit', prefix: '192.168.1.0/24' },
      ],
    };

    it('evaluates seq order, exact match, ge/le ranges, and implicit deny', () => {
      // Seq 10 deny overrides seq 20 permit
      expect(matchPrefixList('10.99.1.0', 24, prefixList)).toBe(false);
      // Seq 20 ge 24 le 26
      expect(matchPrefixList('10.10.1.0', 24, prefixList)).toBe(true);
      expect(matchPrefixList('10.10.1.0', 26, prefixList)).toBe(true);
      expect(matchPrefixList('10.10.1.0', 27, prefixList)).toBe(false);
      expect(matchPrefixList('10.10.0.0', 16, prefixList)).toBe(false);
      // Seq 30 exact match (no ge/le)
      expect(matchPrefixList('192.168.1.0', 24, prefixList)).toBe(true);
      expect(matchPrefixList('192.168.1.0', 25, prefixList)).toBe(false);
      // Implicit deny
      expect(matchPrefixList('172.16.0.0', 16, prefixList)).toBe(false);

      // ge smaller than rule.prefixLen still enforces prefixLen >= rule.prefixLen
      const badGeList: PrefixListConfig = {
        id: 'pl-ge',
        name: 'GE_GUARD',
        entries: [{ id: 'g1', seq: 10, action: 'permit', prefix: '10.10.0.0/16', ge: 8, le: 24 }],
      };
      expect(matchPrefixList('10.0.0.0', 8, badGeList)).toBe(false);
      expect(matchPrefixList('10.10.1.0', 24, badGeList)).toBe(true);

      // IPv6 prefix-list matching
      const v6List: PrefixListConfig = {
        id: 'pl-v6',
        name: 'V6_FILTER',
        entries: [{ id: 'v1', seq: 10, action: 'permit', prefix: '2001:db8::/32', ge: 48, le: 64 }],
      };
      expect(matchPrefixList('2001:db8:1::', 48, v6List)).toBe(true);
      expect(matchPrefixList('2001:db8:1::', 32, v6List)).toBe(false);
      expect(matchPrefixList('2001:db9::', 48, v6List)).toBe(false);
    });

    it('matches prefix-list, community, and AS-path regex in evaluateRouteMap', () => {
      const rm: RouteMapConfig = {
        id: 'rm-1',
        name: 'INBOUND_POLICY',
        entries: [
          {
            id: 'r1',
            seq: 10,
            action: 'deny',
            matchAsPathRegex: '^65999',
            set: {},
          },
          {
            id: 'r2',
            seq: 20,
            action: 'permit',
            matchPrefixListId: 'pl-1',
            matchCommunity: '65200:100',
            set: { setLocalPref: 250, setMed: 50, prependAsPath: [65100] },
          },
        ],
      };

      const deniedByAs = evaluateRouteMap('10.10.1.0', 24, rm, [prefixList], {
        communities: ['65200:100'],
        asPath: [65999, 65200],
      });
      expect(deniedByAs.permitted).toBe(false);

      const permitted = evaluateRouteMap('10.10.1.0', 24, rm, [prefixList], {
        communities: ['65200:100'],
        asPath: [65200],
      });
      expect(permitted.permitted).toBe(true);
      expect(permitted.set.setLocalPref).toBe(250);
      expect(permitted.set.setMed).toBe(50);
      expect(permitted.set.prependAsPath).toEqual([65100]);
    });
  });

  describe('Solver RIB Updates via Inbound/Outbound BGP, Redistribution, and VRF Leak Policies', () => {
    it('filters and mutates BGP attributes & AD in the RIB via routeMapInId and routeMapOutId', () => {
      const topo: TopologyState = {
        nodes: [
          {
            id: 'r1',
            hostname: 'R1',
            vendor: 'cisco-ios-xe',
            routerId: '1.1.1.1',
            position: { x: 100, y: 100 },
            maxPaths: 4,
            vrfs: ['default'],
            adOverrides: {},
            interfaces: [
              { id: 'r1-g0', name: 'Gi0/0', cidr: '10.0.12.1/30', vrf: 'default' },
              { id: 'r1-g1', name: 'Gi0/1', cidr: '10.0.13.1/30', vrf: 'default' },
            ],
            staticRoutes: [],
            ospf: { enabled: false, networks: [] },
            bgp: {
              enabled: true,
              asn: 65100,
              peers: [
                {
                  id: 'p12',
                  peerIp: '10.0.12.2',
                  remoteAs: 65200,
                  routeMapInId: 'rm-in-r2',
                },
                {
                  id: 'p13',
                  peerIp: '10.0.13.2',
                  remoteAs: 65300,
                },
              ],
              networks: [],
            },
            redistributions: [],
            prefixLists: [
              {
                id: 'pl-in',
                name: 'ALLOW_10_24',
                entries: [
                  { id: 'e1', seq: 10, action: 'deny', prefix: '192.168.99.0/24' },
                  { id: 'e2', seq: 20, action: 'permit', prefix: '10.0.0.0/8', ge: 24, le: 24 },
                ],
              },
            ],
            routeMaps: [
              {
                id: 'rm-in-r2',
                name: 'PREF_R2_AND_SET_ATTRS',
                entries: [
                  {
                    id: 're1',
                    seq: 10,
                    action: 'permit',
                    matchPrefixListId: 'pl-in',
                    set: {
                      setLocalPref: 250,
                      setMed: 40,
                      setAd: 25,
                      prependAsPath: [65111],
                      setCommunity: '65100:999',
                    },
                  },
                ],
              },
            ],
            vrfLeaks: [],
          },
          {
            id: 'r2',
            hostname: 'R2',
            vendor: 'cisco-ios-xe',
            routerId: '2.2.2.2',
            position: { x: 360, y: 60 },
            maxPaths: 4,
            vrfs: ['default'],
            adOverrides: {},
            interfaces: [
              { id: 'r2-g0', name: 'Gi0/0', cidr: '10.0.12.2/30', vrf: 'default' },
              { id: 'r2-lo1', name: 'Lo1', cidr: '10.20.1.1/24', vrf: 'default' },
              { id: 'r2-lo2', name: 'Lo2', cidr: '10.20.2.1/25', vrf: 'default' },
              { id: 'r2-lo3', name: 'Lo3', cidr: '192.168.99.1/24', vrf: 'default' },
            ],
            staticRoutes: [],
            ospf: { enabled: false, networks: [] },
            bgp: {
              enabled: true,
              asn: 65200,
              peers: [
                {
                  id: 'p21',
                  peerIp: '10.0.12.1',
                  remoteAs: 65100,
                  routeMapOutId: 'rm-out-r1',
                },
              ],
              networks: [
                { id: 'n1', prefix: '10.20.1.0/24' },
                { id: 'n2', prefix: '10.20.2.0/25' },
                { id: 'n3', prefix: '192.168.99.0/24' },
              ],
            },
            redistributions: [],
            prefixLists: [
              {
                id: 'pl-out',
                name: 'OUT_FILTER',
                entries: [
                  { id: 'oe1', seq: 10, action: 'permit', prefix: '10.20.1.0/24' },
                  { id: 'oe2', seq: 20, action: 'permit', prefix: '192.168.99.0/24' },
                ],
              },
            ],
            routeMaps: [
              {
                id: 'rm-out-r1',
                name: 'TAG_OUTBOUND',
                entries: [
                  {
                    id: 'ore1',
                    seq: 10,
                    action: 'permit',
                    matchPrefixListId: 'pl-out',
                    set: { setCommunity: '65200:500' },
                  },
                ],
              },
            ],
            vrfLeaks: [],
          },
          {
            id: 'r3',
            hostname: 'R3',
            vendor: 'cisco-ios-xe',
            routerId: '3.3.3.3',
            position: { x: 360, y: 200 },
            maxPaths: 4,
            vrfs: ['default'],
            adOverrides: {},
            interfaces: [
              { id: 'r3-g0', name: 'Gi0/0', cidr: '10.0.13.2/30', vrf: 'default' },
              { id: 'r3-lo1', name: 'Lo1', cidr: '10.20.1.1/24', vrf: 'default' },
            ],
            staticRoutes: [],
            ospf: { enabled: false, networks: [] },
            bgp: {
              enabled: true,
              asn: 65300,
              peers: [{ id: 'p31', peerIp: '10.0.13.1', remoteAs: 65100 }],
              networks: [{ id: 'n31', prefix: '10.20.1.0/24' }],
            },
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
            sourceInterfaceId: 'r1-g0',
            targetNodeId: 'r2',
            targetInterfaceId: 'r2-g0',
          },
          {
            id: 'l13',
            sourceNodeId: 'r1',
            sourceInterfaceId: 'r1-g1',
            targetNodeId: 'r3',
            targetInterfaceId: 'r3-g0',
          },
        ],
      };

      const res = solveTopology(topo);
      const r1Rib = res.nodes['r1'].rib;

      // 10.20.1.0/24 from R2 wins via Local-Pref 250 over R3 (default 100), with mutated AD/MED/AS-path/community
      const winner = r1Rib.find((r) => r.prefix === '10.20.1.0' && r.prefixLen === 24 && r.active);
      expect(winner).toBeDefined();
      expect(winner?.nextHop).toBe('10.0.12.2');
      expect(winner?.ad).toBe(25);
      expect(winner?.bgpAttrs?.localPref).toBe(250);
      expect(winner?.bgpAttrs?.med).toBe(40);
      expect(winner?.bgpAttrs?.asPath).toEqual([65111, 65200]);
      expect(winner?.bgpAttrs?.communities).toContain('65100:999');

      // 10.20.2.0/25 was filtered outbound by R2's routeMapOutId
      expect(r1Rib.some((r) => r.prefix === '10.20.2.0' && r.prefixLen === 25)).toBe(false);

      // 192.168.99.0/24 was permitted outbound by R2, then denied inbound by R1's pl-in
      expect(r1Rib.some((r) => r.prefix === '192.168.99.0' && r.prefixLen === 24)).toBe(false);
    });

    it('filters OSPF redistribution and sets E1 metric-type, plus filters VRF route-leaking via prefix-lists', () => {
      const topo: TopologyState = {
        nodes: [
          {
            id: 'asbr',
            hostname: 'ASBR',
            vendor: 'cisco-ios-xe',
            routerId: '10.1.1.1',
            position: { x: 100, y: 120 },
            maxPaths: 4,
            vrfs: ['default', 'corp'],
            adOverrides: {},
            interfaces: [
              { id: 'a-g0', name: 'Gi0/0', cidr: '10.1.1.1/30', vrf: 'default', ospfArea: 0 },
              { id: 'a-lo1', name: 'Lo1', cidr: '172.16.10.1/24', vrf: 'default' },
              { id: 'a-lo2', name: 'Lo2', cidr: '172.16.99.1/24', vrf: 'default' },
              { id: 'a-c1', name: 'Gi0/1', cidr: '10.50.1.1/24', vrf: 'corp' },
              { id: 'a-c2', name: 'Gi0/2', cidr: '10.50.2.1/24', vrf: 'corp' },
            ],
            staticRoutes: [],
            ospf: { enabled: true, networks: [] },
            bgp: { enabled: false, asn: 65000, peers: [], networks: [] },
            redistributions: [
              { id: 'red-1', from: 'connected', to: 'ospf', routeMapId: 'rm-redist' },
            ],
            prefixLists: [
              {
                id: 'pl-redist',
                name: 'ALLOW_172_10',
                entries: [{ id: 're1', seq: 10, action: 'permit', prefix: '172.16.10.0/24' }],
              },
              {
                id: 'pl-leak',
                name: 'LEAK_ONLY_50_1',
                entries: [{ id: 'le1', seq: 10, action: 'permit', prefix: '10.50.1.0/24' }],
              },
            ],
            routeMaps: [
              {
                id: 'rm-redist',
                name: 'REDIST_E1',
                entries: [
                  {
                    id: 'rme1',
                    seq: 10,
                    action: 'permit',
                    matchPrefixListId: 'pl-redist',
                    set: { setOspfMetricType: 'E1' },
                  },
                ],
              },
            ],
            vrfLeaks: [{ id: 'vl-1', fromVrf: 'corp', toVrf: 'default', matchPrefixListId: 'pl-leak' }],
          },
          {
            id: 'abr',
            hostname: 'ABR',
            vendor: 'cisco-ios-xe',
            routerId: '10.1.1.2',
            position: { x: 360, y: 120 },
            maxPaths: 4,
            vrfs: ['default'],
            adOverrides: {},
            interfaces: [
              { id: 'b-g0', name: 'Gi0/0', cidr: '10.1.1.2/30', vrf: 'default', ospfArea: 0 },
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
          {
            id: 'l-ab',
            sourceNodeId: 'asbr',
            sourceInterfaceId: 'a-g0',
            targetNodeId: 'abr',
            targetInterfaceId: 'b-g0',
          },
        ],
      };

      const res = solveTopology(topo);

      // ABR receives 172.16.10.0/24 as OSPF E1, but NOT 172.16.99.0/24
      const abrRib = res.nodes['abr'].rib;
      const ext1 = abrRib.find((r) => r.prefix === '172.16.10.0' && r.protocol === 'ospf' && r.active);
      expect(ext1).toBeDefined();
      expect(ext1?.ospfType).toBe('ext1');
      expect(abrRib.some((r) => r.prefix === '172.16.99.0')).toBe(false);

      // ASBR default VRF receives leaked 10.50.1.0/24 from corp, but NOT 10.50.2.0/24
      const asbrRib = res.nodes['asbr'].rib;
      expect(
        asbrRib.some((r) => r.vrf === 'default' && r.prefix === '10.50.1.0' && r.leakedFromVrf === 'corp')
      ).toBe(true);
      expect(asbrRib.some((r) => r.vrf === 'default' && r.prefix === '10.50.2.0')).toBe(false);
    });
  });
});

