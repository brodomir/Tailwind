import { load } from 'js-yaml';
import {
  BgpPeerConfig,
  InterfaceConfig,
  NodeConfig,
  StaticRouteConfig,
  TopologyState,
} from '../types/network';
import { ipToUint32, parseCidr, uint32ToIp } from './ipMath';

let importIdSeq = 0;

function maskToPrefixLen(mask: string): number {
  const parts = mask.trim().split('.');
  if (parts.length !== 4) return 24;
  let bits = ipToUint32(mask);
  let len = 0;
  while (bits & 0x80000000) {
    len++;
    bits = (bits << 1) >>> 0;
  }
  return len;
}

function wildcardToPrefixLen(wildcard: string): number {
  const w = ipToUint32(wildcard);
  const mask = (~w) >>> 0;
  let bits = mask;
  let len = 0;
  while (bits & 0x80000000) {
    len++;
    bits = (bits << 1) >>> 0;
  }
  return len;
}

function parsePanOsSetConfig(lines: string[]): NodeConfig {
  let hostname = 'PAN-IMPORTED';
  let routerId = '10.250.0.1';
  const vrfs = new Set<string>(['default']);
  const ifaceMap = new Map<string, { cidr: string; vrf: string; ospfArea?: number }>();
  const staticRoutes: NodeConfig['staticRoutes'] = [];
  let ospfEnabled = false;
  let bgpEnabled = false;
  let bgpAsn = 65000;
  const bgpPeers: NodeConfig['bgp']['peers'] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line.startsWith('set ')) continue;

    const hostMatch = line.match(/^set\s+deviceconfig\s+system\s+hostname\s+(\S+)/);
    if (hostMatch) {
      hostname = hostMatch[1];
      continue;
    }

    const ifIpMatch = line.match(
      /^set\s+network\s+interface\s+\S+\s+(\S+)\s+layer3\s+ip\s+(\d+\.\d+\.\d+\.\d+\/\d+)/
    );
    if (ifIpMatch) {
      const name = ifIpMatch[1];
      const existing = ifaceMap.get(name) ?? { cidr: ifIpMatch[2], vrf: 'default' };
      existing.cidr = ifIpMatch[2];
      ifaceMap.set(name, existing);
      continue;
    }

    const vrIfMatch = line.match(
      /^set\s+network\s+virtual-router\s+(\S+)\s+interface\s+(\S+)/
    );
    if (vrIfMatch) {
      vrfs.add(vrIfMatch[1]);
      const existing = ifaceMap.get(vrIfMatch[2]);
      if (existing) existing.vrf = vrIfMatch[1];
      else {
        ifaceMap.set(vrIfMatch[2], { cidr: '0.0.0.0/0', vrf: vrIfMatch[1] });
      }
      continue;
    }

    const staticMatch = line.match(
      /^set\s+network\s+virtual-router\s+(\S+)\s+routing-table\s+ip\s+static-route\s+\S+\s+destination\s+(\S+)\s+nexthop\s+ip-address\s+(\d+\.\d+\.\d+\.\d+)/
    );
    if (staticMatch) {
      vrfs.add(staticMatch[1]);
      staticRoutes.push({
        id: `sr-${Date.now()}-${staticRoutes.length}`,
        vrf: staticMatch[1],
        prefix: staticMatch[2],
        nextHop: staticMatch[3],
      });
      continue;
    }

    const ospfMatch = line.match(
      /^set\s+network\s+virtual-router\s+(\S+)\s+protocol\s+ospf\s+.*router-id\s+(\d+\.\d+\.\d+\.\d+)/
    );
    if (ospfMatch) {
      vrfs.add(ospfMatch[1]);
      ospfEnabled = true;
      routerId = ospfMatch[2];
      continue;
    }

    const bgpMatch = line.match(
      /^set\s+network\s+virtual-router\s+(\S+)\s+protocol\s+bgp\s+.*local-as\s+(\d+)/
    );
    if (bgpMatch) {
      vrfs.add(bgpMatch[1]);
      bgpEnabled = true;
      bgpAsn = Number(bgpMatch[2]);
      continue;
    }

    const bgpPeerMatch = line.match(
      /^set\s+network\s+virtual-router\s+\S+\s+protocol\s+bgp\s+peer-group\s+(\S+)\s+peer\s+(\S+)\s+peer-address\s+ip\s+(\d+\.\d+\.\d+\.\d+)/
    );
    if (bgpPeerMatch) {
      bgpEnabled = true;
      bgpPeers.push({
        id: `peer-${Date.now()}-${bgpPeers.length}`,
        peerIp: bgpPeerMatch[3],
        remoteAs: bgpAsn,
      });
      continue;
    }

    const bgpPeerAsMatch = line.match(
      /^set\s+network\s+virtual-router\s+\S+\s+protocol\s+bgp\s+peer-group\s+\S+\s+peer\s+\S+\s+peer-as\s+(\d+)/
    );
    if (bgpPeerAsMatch && bgpPeers.length > 0) {
      bgpPeers[bgpPeers.length - 1].remoteAs = Number(bgpPeerAsMatch[1]);
    }
  }

  const interfaces: NodeConfig['interfaces'] = Array.from(ifaceMap.entries()).map(
    ([name, info], i) => ({
      id: `if-${Date.now()}-${i}`,
      name,
      cidr: info.cidr,
      vrf: info.vrf,
      ospfArea: info.ospfArea,
    })
  );

  return {
    id: `imp-${Date.now()}-${++importIdSeq}`,
    hostname,
    vendor: 'pan-os',
    routerId,
    position: { x: 260, y: 140 },
    maxPaths: 4,
    vrfs: Array.from(vrfs),
    adOverrides: {},
    interfaces,
    staticRoutes,
    ospf: { enabled: ospfEnabled, networks: [] },
    bgp: { enabled: bgpEnabled, asn: bgpAsn, peers: bgpPeers, networks: [] },
    redistributions: [],
    prefixLists: [],
    routeMaps: [],
    vrfLeaks: [],
  };
}

function parseCiscoStyleConfig(lines: string[]): NodeConfig {
  let hostname = 'IMPORTED-RTR1';
  let routerId = '10.250.0.1';
  const vrfs = new Set<string>(['default']);
  const interfaces: NodeConfig['interfaces'] = [];
  const staticRoutes: NodeConfig['staticRoutes'] = [];
  const ospfNetworks: NodeConfig['ospf']['networks'] = [];
  const ospfAreaTypes: Record<number, 'normal' | 'stub' | 'totally-stubby' | 'nssa'> = {};
  const ospfAreaRanges: NonNullable<NodeConfig['ospf']['areaRanges']> = [];
  const ospfVirtualLinks: NonNullable<NodeConfig['ospf']['virtualLinks']> = [];
  const bgpPeers: NodeConfig['bgp']['peers'] = [];
  const bgpNetworks: NodeConfig['bgp']['networks'] = [];
  const bgpAggregates: NonNullable<NodeConfig['bgp']['aggregates']> = [];
  const fhrpGroups: NonNullable<NodeConfig['fhrpGroups']> = [];
  const routeMaps: NodeConfig['routeMaps'] = [];

  let ospfEnabled = false;
  let ospfBfd = false;
  let ospfMaxMetricRouterLsa = false;
  const ospfNssaNoSummary: Record<number, boolean> = {};
  let bgpEnabled = false;
  let bgpAsn = 65000;
  let bgpClusterId: string | undefined;
  let bgpConfederationId: number | undefined;
  let bgpConfederationPeers: number[] | undefined;
  let bgpAlwaysCompareMed = false;
  let bgpDeterministicMed = false;
  let bgpBestpathAsPathIgnore = false;
  let bgpMedMissingAsWorst = false;
  let eigrpEnabled = false;
  let eigrpAsn = 100;
  let eigrpBfd = false;
  let eigrpVariance: number | undefined;
  let isisEnabled = false;
  let isisNet: string | undefined;
  let isisLevel: 'L1' | 'L2' | 'L1-L2' = 'L1-L2';
  let isisBfd = false;
  let isisOverloadBit = false;
  let isisMetricStyle: 'narrow' | 'wide' | undefined;
  let isisMultiTopologyV6 = false;
  let isNxOs = false;
  const vrfRouterIds: Record<string, string> = {};
  const mplsVrfTargets: NonNullable<NonNullable<NodeConfig['mplsVpn']>['vrfTargets']> = [];
  let evpnConfig: NodeConfig['evpn'] | undefined;
  let mplsConfig: NodeConfig['mpls'] | undefined;
  let switchingConfig: NodeConfig['switching'] | undefined;
  let multicastConfig: NodeConfig['multicast'] | undefined;
  let timingConfig: NodeConfig['timing'] | undefined;
  let telemetryConfig: NodeConfig['telemetry'] | undefined;

  let currentSection:
    | 'none'
    | 'interface'
    | 'nve'
    | 'vrf'
    | 'ospf'
    | 'bgp'
    | 'eigrp'
    | 'isis'
    | 'routemap'
    | 'vpc'
    | 'lisp' = 'none';
  let currentVrfContext = 'default';
  let currentOspfVrf = 'default';
  let currentBgpVrf = 'default';
  let currentBgpPeer: BgpPeerConfig | null = null;
  let currentHsrpGid: number | null = null;
  let lispEnabled = false;
  let lispBfd = false;
  let lispRole: 'xtr' | 'ms-mr' | 'pxtr' = 'xtr';
  let lispRlocIp = '';
  let lispMapServerIp: string | undefined;
  let lispInstanceId = 0;
  const lispEidPrefixes: NonNullable<NodeConfig['lisp']>['eidPrefixes'] = [];
  let currentIface: NodeConfig['interfaces'][0] | null = null;
  let currentRouteMapEntry: NodeConfig['routeMaps'][0]['entries'][0] | null = null;
  let vpcConfig: NodeConfig['vpc'] | undefined;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('!')) {
      if (trimmed === '!') {
        currentSection = 'none';
        currentIface = null;
        currentBgpPeer = null;
        currentHsrpGid = null;
      }
      continue;
    }

    const hostMatch = trimmed.match(/^hostname\s+(\S+)/i);
    if (hostMatch) {
      hostname = hostMatch[1];
      continue;
    }

    const vrfDefMatch =
      trimmed.match(/^(?:ip\s+)?vrf\s+(?:definition|context)\s+(\S+)/i) ??
      trimmed.match(/^ip\s+vrf\s+(\S+)/i);
    if (vrfDefMatch && !trimmed.toLowerCase().includes('forwarding') && !trimmed.toLowerCase().includes('member')) {
      currentSection = 'vrf';
      currentVrfContext = vrfDefMatch[1];
      vrfs.add(currentVrfContext);
      if (trimmed.toLowerCase().includes('context')) isNxOs = true;
      continue;
    }

    if (currentSection === 'vrf') {
      const rdMatch = trimmed.match(/^rd\s+(\S+)/i);
      if (rdMatch) {
        let entry = mplsVrfTargets.find((t) => t.vrf === currentVrfContext);
        if (!entry) {
          entry = { id: `vt-${Date.now()}-${mplsVrfTargets.length}`, vrf: currentVrfContext, rd: rdMatch[1], importRt: '', exportRt: '' };
          mplsVrfTargets.push(entry);
        } else {
          entry.rd = rdMatch[1];
        }
        continue;
      }
      const rtMatch = trimmed.match(/^route-target\s+(import|export|both)\s+(\S+)/i);
      if (rtMatch) {
        let entry = mplsVrfTargets.find((t) => t.vrf === currentVrfContext);
        if (!entry) {
          entry = { id: `vt-${Date.now()}-${mplsVrfTargets.length}`, vrf: currentVrfContext, rd: '65000:1', importRt: '', exportRt: '' };
          mplsVrfTargets.push(entry);
        }
        const dir = rtMatch[1].toLowerCase();
        if (dir === 'import' || dir === 'both') entry.importRt = rtMatch[2];
        if (dir === 'export' || dir === 'both') entry.exportRt = rtMatch[2];
        continue;
      }
      const vrfStaticCidr = trimmed.match(/^ip\s+route\s+(\d+\.\d+\.\d+\.\d+\/\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?/i);
      if (vrfStaticCidr) {
        staticRoutes.push({
          id: `sr-${Date.now()}-${staticRoutes.length}`,
          vrf: currentVrfContext,
          prefix: vrfStaticCidr[1],
          nextHop: vrfStaticCidr[2],
          ad: vrfStaticCidr[3] ? Number(vrfStaticCidr[3]) : undefined,
        });
        continue;
      }
    }

    const ifMatch = trimmed.match(/^interface\s+(\S+)/i);
    if (ifMatch) {
      currentHsrpGid = null;
      if (/^nve\d+$/i.test(ifMatch[1])) {
        currentSection = 'nve';
        isNxOs = true;
        evpnConfig = evpnConfig ?? { enabled: true, vtepIp: routerId };
        continue;
      }
      currentSection = 'interface';
      currentIface = {
        id: `if-${Date.now()}-${interfaces.length}`,
        name: ifMatch[1],
        cidr: '0.0.0.0/0',
        vrf: 'default',
      };
      interfaces.push(currentIface);
      continue;
    }

    if (currentSection === 'nve' && evpnConfig) {
      const srcIf = trimmed.match(/^source-interface\s+(\S+)/i);
      if (srcIf) {
        const matchedIf = interfaces.find((i) => i.name.toLowerCase() === srcIf[1].toLowerCase());
        const ip = matchedIf ? parseCidr(matchedIf.cidr)?.ip : undefined;
        evpnConfig.vtepIp = ip || srcIf[1];
        continue;
      }
      const vniAssoc = trimmed.match(/^member\s+vni\s+(\d+)\s+associate-vrf/i);
      if (vniAssoc) {
        evpnConfig.l3Vni = Number(vniAssoc[1]);
        continue;
      }
      const vniL2 = trimmed.match(/^member\s+vni\s+(\d+)$/i);
      if (vniL2) {
        evpnConfig.l2Vni = Number(vniL2[1]);
        continue;
      }
    }

    const ospfRouterMatch = trimmed.match(/^router\s+ospf\s+\d+(?:\s+vrf\s+(\S+))?/i);
    if (ospfRouterMatch) {
      currentSection = 'ospf';
      ospfEnabled = true;
      currentOspfVrf = ospfRouterMatch[1] || 'default';
      if (currentOspfVrf !== 'default') vrfs.add(currentOspfVrf);
      continue;
    }

    const bgpRouterMatch = trimmed.match(/^router\s+bgp\s+(\d+)/i);
    if (bgpRouterMatch) {
      currentSection = 'bgp';
      bgpEnabled = true;
      bgpAsn = Number(bgpRouterMatch[1]);
      currentBgpVrf = 'default';
      continue;
    }

    if (/^router\s+lisp$/i.test(trimmed)) {
      currentSection = 'lisp';
      lispEnabled = true;
      continue;
    }

    if (/^router\s+isis(?:\s+\S+)?$/i.test(trimmed)) {
      currentSection = 'isis';
      isisEnabled = true;
      continue;
    }

    const eigrpRouterMatch = trimmed.match(/^router\s+eigrp\s+(\d+)/i);
    if (eigrpRouterMatch) {
      currentSection = 'eigrp';
      eigrpEnabled = true;
      eigrpAsn = Number(eigrpRouterMatch[1]);
      continue;
    }

    if (currentSection === 'interface' && currentIface) {
      const encapDot1q = trimmed.match(/^encapsulation\s+dot1[qQ]\s+(\d+)/i);
      if (encapDot1q) {
        currentIface.vlanId = Number(encapDot1q[1]);
        const dotIdx = currentIface.name.lastIndexOf('.');
        if (dotIdx > 0 && !currentIface.parentInterface) {
          currentIface.parentInterface = currentIface.name.slice(0, dotIdx);
        }
        continue;
      }
      const vrfFwd = trimmed.match(/^(?:(?:ip\s+)?vrf\s+forwarding|vrf\s+member)\s+(\S+)/i);
      if (vrfFwd) {
        if (trimmed.toLowerCase().includes('vrf member')) isNxOs = true;
        vrfs.add(vrfFwd[1]);
        currentIface.vrf = vrfFwd[1];
        continue;
      }
      const ipMask = trimmed.match(/^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(\s+secondary)?/i);
      if (ipMask) {
        if (!ipMask[3]) {
          currentIface.cidr = `${ipMask[1]}/${maskToPrefixLen(ipMask[2])}`;
        }
        continue;
      }
      const ipCidr = trimmed.match(/^ip\s+address\s+(\d+\.\d+\.\d+\.\d+\/\d+)(\s+secondary)?/i);
      if (ipCidr) {
        if (!ipCidr[2]) {
          currentIface.cidr = ipCidr[1];
        }
        continue;
      }
      const unnumMatch = trimmed.match(/^ip\s+unnumbered\s+(\S+)/i);
      if (unnumMatch) {
        currentIface.unnumberedSource = unnumMatch[1];
        continue;
      }
      const urpfMatch = trimmed.match(/^ip\s+verify\s+unicast\s+source\s+reachable-via\s+(rx|any)/i);
      if (urpfMatch) {
        currentIface.urpfMode = urpfMatch[1].toLowerCase() === 'rx' ? 'strict' : 'loose';
        continue;
      }
      const ip6Cidr = trimmed.match(/^ipv6\s+address\s+([0-9a-fA-F:]+\/\d+)/i);
      if (ip6Cidr) {
        currentIface.cidr6 = ip6Cidr[1];
        continue;
      }
      const ospfArea = trimmed.match(/^ip\s+(?:ospf|router\s+ospf)\s+\S+\s+area\s+(\d+)/i);
      if (ospfArea) {
        if (trimmed.toLowerCase().includes('router ospf')) isNxOs = true;
        ospfEnabled = true;
        currentIface.ospfArea = Number(ospfArea[1]);
        continue;
      }
      const ospfCost = trimmed.match(/^ip\s+ospf\s+cost\s+(\d+)/i);
      if (ospfCost) {
        currentIface.ospfCost = Number(ospfCost[1]);
        continue;
      }
      const ospfPrio = trimmed.match(/^ip\s+ospf\s+priority\s+(\d+)/i);
      if (ospfPrio) {
        currentIface.ospfPriority = Number(ospfPrio[1]);
        continue;
      }
      const ospfNetMatch = trimmed.match(/^ip\s+ospf\s+network\s+(point-to-point|broadcast|non-broadcast|point-to-multipoint)$/i);
      if (ospfNetMatch) {
        currentIface.ospfNetworkType = ospfNetMatch[1].toLowerCase() as NonNullable<InterfaceConfig['ospfNetworkType']>;
        continue;
      }
      const ospfHello = trimmed.match(/^ip\s+ospf\s+hello-interval\s+(\d+)/i);
      if (ospfHello) {
        currentIface.ospfHelloInterval = Number(ospfHello[1]);
        continue;
      }
      const ospfDead = trimmed.match(/^ip\s+ospf\s+dead-interval\s+(\d+)/i);
      if (ospfDead) {
        currentIface.ospfDeadInterval = Number(ospfDead[1]);
        continue;
      }
      const eigrpHello = trimmed.match(/^ip\s+hello-interval\s+eigrp\s+\d+\s+(\d+)/i);
      if (eigrpHello) {
        currentIface.eigrpHelloInterval = Number(eigrpHello[1]);
        continue;
      }
      const eigrpHold = trimmed.match(/^ip\s+hold-time\s+eigrp\s+\d+\s+(\d+)/i);
      if (eigrpHold) {
        currentIface.eigrpHoldTime = Number(eigrpHold[1]);
        continue;
      }
      const isisHello = trimmed.match(/^isis\s+hello-interval\s+(\d+)/i);
      if (isisHello) {
        currentIface.isisHelloInterval = Number(isisHello[1]);
        continue;
      }
      const isisMult = trimmed.match(/^isis\s+hello-multiplier\s+(\d+)/i);
      if (isisMult) {
        currentIface.isisHelloMultiplier = Number(isisMult[1]);
        continue;
      }
      if (/^ip\s+router\s+isis(?:\s+\S+)?$/i.test(trimmed)) {
        isisEnabled = true;
        currentIface.isisLevel = currentIface.isisLevel ?? 'L2';
        continue;
      }
      const isisCircMatch = trimmed.match(/^isis\s+circuit-type\s+(level-1|level-2-only|level-1-2)/i);
      if (isisCircMatch) {
        isisEnabled = true;
        currentIface.isisLevel = isisCircMatch[1].toLowerCase() === 'level-1' ? 'L1' : 'L2';
        continue;
      }
      const isisMetricMatch = trimmed.match(/^isis\s+metric\s+(\d+)/i);
      if (isisMetricMatch) {
        currentIface.isisMetric = Number(isisMetricMatch[1]);
        continue;
      }
      const isisPrioMatch = trimmed.match(/^isis\s+priority\s+(\d+)/i);
      if (isisPrioMatch) {
        currentIface.isisPriority = Number(isisPrioMatch[1]);
        continue;
      }
      if (/^isis\s+network\s+point-to-point$/i.test(trimmed)) {
        currentIface.isisNetworkType = 'point-to-point';
        continue;
      }
      const bfdIf = trimmed.match(/^bfd\s+interval\s+(\d+)\s+min_rx\s+(\d+)\s+multiplier\s+(\d+)/i);
      if (bfdIf) {
        currentIface.bfdIntervalMs = Number(bfdIf[1]);
        currentIface.bfdMinRxMs = Number(bfdIf[2]);
        currentIface.bfdMultiplier = Number(bfdIf[3]);
        continue;
      }
      if (/^shutdown$/i.test(trimmed)) {
        currentIface.shutdown = true;
        continue;
      }
      const ospfAuthMatch = trimmed.match(/^ip\s+ospf\s+authentication-key\s+(\S+)/i);
      if (ospfAuthMatch) {
        currentIface.ospfAuthKey = ospfAuthMatch[1];
        continue;
      }
      const zoneMatch = trimmed.match(/^zone-member\s+security\s+(\S+)/i);
      if (zoneMatch) {
        currentIface.zone = zoneMatch[1];
        continue;
      }
      const vlanMatch = trimmed.match(/^encapsulation\s+dot1q\s+(\d+)/i);
      if (vlanMatch) {
        currentIface.vlanId = Number(vlanMatch[1]);
        continue;
      }
      const mtuMatch = trimmed.match(/^mtu\s+(\d+)/i);
      if (mtuMatch) {
        currentIface.mtu = Number(mtuMatch[1]);
        continue;
      }
      const nxHsrp = trimmed.match(/^hsrp\s+(\d+)$/i);
      if (nxHsrp) {
        isNxOs = true;
        currentHsrpGid = Number(nxHsrp[1]);
        continue;
      }
      if (currentHsrpGid !== null) {
        const nxHsrpIp = trimmed.match(/^ip\s+(\d+\.\d+\.\d+\.\d+)/i);
        if (nxHsrpIp) {
          const existing = fhrpGroups.find((g) => g.protocol === 'hsrp' && g.groupId === currentHsrpGid && g.interfaceId === currentIface!.id);
          if (existing) existing.virtualIp = nxHsrpIp[1];
          else {
            fhrpGroups.push({
              id: `fhrp-${Date.now()}-${fhrpGroups.length}`,
              protocol: 'hsrp',
              groupId: currentHsrpGid,
              interfaceId: currentIface.id,
              virtualIp: nxHsrpIp[1],
              priority: 100,
            });
          }
          continue;
        }
        const nxHsrpPrio = trimmed.match(/^priority\s+(\d+)/i);
        if (nxHsrpPrio) {
          const existing = fhrpGroups.find((g) => g.protocol === 'hsrp' && g.groupId === currentHsrpGid && g.interfaceId === currentIface!.id);
          if (existing) existing.priority = Number(nxHsrpPrio[1]);
          continue;
        }
      }
      const standbyIpMatch = trimmed.match(/^standby\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (standbyIpMatch) {
        const gid = Number(standbyIpMatch[1]);
        const existing = fhrpGroups.find((g) => g.protocol === 'hsrp' && g.groupId === gid && g.interfaceId === currentIface!.id);
        if (existing) existing.virtualIp = standbyIpMatch[2];
        else {
          fhrpGroups.push({
            id: `fhrp-${Date.now()}-${fhrpGroups.length}`,
            protocol: 'hsrp',
            groupId: gid,
            interfaceId: currentIface.id,
            virtualIp: standbyIpMatch[2],
            priority: 100,
          });
        }
        continue;
      }
      const protoMatch = trimmed.match(/^channel-protocol\s+(lacp|pagp)/i);
      if (protoMatch) {
        currentIface.lagProtocol = protoMatch[1].toLowerCase() as 'lacp' | 'pagp';
        continue;
      }
      const lacpMatch = trimmed.match(/^channel-group\s+(\d+)\s+mode\s+(active|passive|desirable|auto|on)/i);
      if (lacpMatch) {
        const mode = lacpMatch[2].toLowerCase() as NonNullable<InterfaceConfig['lacpMode']>;
        currentIface.lacpGroup = Number(lacpMatch[1]);
        currentIface.lacpMode = mode;
        if (!currentIface.lagProtocol) {
          currentIface.lagProtocol =
            mode === 'desirable' || mode === 'auto' ? 'pagp' : mode === 'on' ? 'static' : 'lacp';
        }
        continue;
      }
      if (/^ip\s+pim\s+sparse-mode$/i.test(trimmed)) {
        currentIface.pimSparse = true;
        multicastConfig = multicastConfig ?? { pimEnabled: true };
        continue;
      }
      const helperMatch = trimmed.match(/^ip\s+helper-address\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (helperMatch) {
        currentIface.dhcpHelperIps = [...(currentIface.dhcpHelperIps ?? []), helperMatch[1]];
        continue;
      }
      if (/^macsec$/i.test(trimmed)) { currentIface.macsecEnabled = true; continue; }
      if (/^ip\s+dhcp\s+snooping\s+trust$/i.test(trimmed)) { currentIface.dhcpSnoopingTrust = true; continue; }
      if (/^ip\s+verify\s+source$/i.test(trimmed)) { currentIface.ipSourceGuard = true; continue; }
      if (/^ipv6\s+nd\s+raguard/i.test(trimmed)) { currentIface.raGuard = true; continue; }
      const esiMatch = trimmed.match(/^evpn\s+ethernet-segment\s+esi\s+(\S+)/i);
      if (esiMatch) { currentIface.evpnEsi = esiMatch[1]; continue; }
      const standbyPrioMatch = trimmed.match(/^standby\s+(\d+)\s+priority\s+(\d+)/i);
      if (standbyPrioMatch) {
        const gid = Number(standbyPrioMatch[1]);
        const existing = fhrpGroups.find((g) => g.protocol === 'hsrp' && g.groupId === gid && g.interfaceId === currentIface!.id);
        if (existing) existing.priority = Number(standbyPrioMatch[2]);
        continue;
      }
      const vrrpIpMatch = trimmed.match(/^vrrp\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (vrrpIpMatch) {
        const gid = Number(vrrpIpMatch[1]);
        const existing = fhrpGroups.find(
          (g) => g.protocol === 'vrrp' && g.groupId === gid && g.interfaceId === currentIface!.id
        );
        if (existing) existing.virtualIp = vrrpIpMatch[2];
        else {
          fhrpGroups.push({
            id: `fhrp-${Date.now()}-${fhrpGroups.length}`,
            protocol: 'vrrp',
            groupId: gid,
            interfaceId: currentIface.id,
            virtualIp: vrrpIpMatch[2],
            priority: 100,
          });
        }
        continue;
      }
      const vrrpPrioMatch = trimmed.match(/^vrrp\s+(\d+)\s+priority\s+(\d+)/i);
      if (vrrpPrioMatch) {
        const gid = Number(vrrpPrioMatch[1]);
        const existing = fhrpGroups.find(
          (g) => g.protocol === 'vrrp' && g.groupId === gid && g.interfaceId === currentIface!.id
        );
        if (existing) existing.priority = Number(vrrpPrioMatch[2]);
        continue;
      }
      if (/^vpc\s+peer-link$/i.test(trimmed)) {
        vpcConfig = vpcConfig ?? { enabled: true, domainId: 1 };
        vpcConfig.peerLinkInterfaceId = currentIface.id;
        continue;
      }
      const vpcIfMatch = trimmed.match(/^vpc\s+(\d+)$/i);
      if (vpcIfMatch) {
        currentIface.vpcId = Number(vpcIfMatch[1]);
        continue;
      }
    }

    const vpcDomMatch = trimmed.match(/^vpc\s+domain\s+(\d+)/i);
    if (vpcDomMatch) {
      currentSection = 'vpc';
      vpcConfig = { ...(vpcConfig ?? { enabled: true, domainId: Number(vpcDomMatch[1]) }), enabled: true, domainId: Number(vpcDomMatch[1]) };
      continue;
    }

    if (currentSection === 'vpc' && vpcConfig) {
      const rp = trimmed.match(/^role\s+priority\s+(\d+)/i);
      if (rp) { vpcConfig.rolePriority = Number(rp[1]); continue; }
      const sp = trimmed.match(/^system-priority\s+(\d+)/i);
      if (sp) { vpcConfig.systemPriority = Number(sp[1]); continue; }
      const pk = trimmed.match(/^peer-keepalive\s+destination\s+(\d+\.\d+\.\d+\.\d+)(?:\s+source\s+(\d+\.\d+\.\d+\.\d+))?(?:\s+vrf\s+(\S+))?/i);
      if (pk) {
        vpcConfig.peerKeepaliveDst = pk[1];
        if (pk[2]) vpcConfig.peerKeepaliveSrc = pk[2];
        if (pk[3]) vpcConfig.peerKeepaliveVrf = pk[3];
        continue;
      }
      if (/^peer-gateway$/i.test(trimmed)) { vpcConfig.peerGateway = true; continue; }
      if (/^peer-switch$/i.test(trimmed)) { vpcConfig.peerSwitch = true; continue; }
      if (/^layer3\s+peer-router$/i.test(trimmed)) { vpcConfig.layer3PeerRouter = true; continue; }
      if (/^auto-recovery$/i.test(trimmed)) { vpcConfig.autoRecovery = true; continue; }
      if (/^ip\s+arp\s+synchronize$/i.test(trimmed)) { vpcConfig.ipArpSynchronize = true; continue; }
      const dr = trimmed.match(/^delay\s+restore\s+(\d+)/i);
      if (dr) { vpcConfig.delayRestore = Number(dr[1]); continue; }
    }

    const rmMatch = trimmed.match(/^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)/i);
    if (rmMatch) {
      currentSection = 'routemap';
      let rm = routeMaps.find((r) => r.name === rmMatch[1]);
      if (!rm) {
        rm = { id: `rm-${Date.now()}-${routeMaps.length}`, name: rmMatch[1], entries: [] };
        routeMaps.push(rm);
      }
      currentRouteMapEntry = {
        id: `rme-${Date.now()}-${rm.entries.length}`,
        seq: Number(rmMatch[3]),
        action: rmMatch[2].toLowerCase() as 'permit' | 'deny',
        set: {},
      };
      rm.entries.push(currentRouteMapEntry);
      continue;
    }

    if (currentSection === 'routemap' && currentRouteMapEntry) {
      const mc = trimmed.match(/^match\s+community\s+(\S+)/i);
      if (mc) { currentRouteMapEntry.matchCommunity = mc[1]; continue; }
      const ma = trimmed.match(/^match\s+as-path\s+(.+)/i);
      if (ma) { currentRouteMapEntry.matchAsPathRegex = ma[1].trim(); continue; }
      const mt = trimmed.match(/^match\s+tag\s+(\d+)/i);
      if (mt) { currentRouteMapEntry.matchTag = Number(mt[1]); continue; }
      const sc = trimmed.match(/^set\s+community\s+(\S+)/i);
      if (sc) { currentRouteMapEntry.set.setCommunity = sc[1]; continue; }
      const st = trimmed.match(/^set\s+tag\s+(\d+)/i);
      if (st) { currentRouteMapEntry.set.setTag = Number(st[1]); continue; }
      const slp = trimmed.match(/^set\s+local-preference\s+(\d+)/i);
      if (slp) { currentRouteMapEntry.set.setLocalPref = Number(slp[1]); continue; }
    }

    if (currentSection === 'ospf') {
      if (/^bfd\s+all-interfaces$/i.test(trimmed)) {
        ospfBfd = true;
        continue;
      }
      if (/^max-metric\s+router-lsa/i.test(trimmed)) {
        ospfMaxMetricRouterLsa = true;
        continue;
      }
      const ridMatch = trimmed.match(/^(?:ospf\s+)?router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (ridMatch) {
        if (currentOspfVrf === 'default') routerId = ridMatch[1];
        else vrfRouterIds[currentOspfVrf] = ridMatch[1];
        continue;
      }
      const netMatch = trimmed.match(
        /^network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\d+)/i
      );
      if (netMatch) {
        ospfNetworks.push({
          id: `on-${Date.now()}-${ospfNetworks.length}`,
          vrf: currentOspfVrf !== 'default' ? currentOspfVrf : undefined,
          prefix: `${netMatch[1]}/${wildcardToPrefixLen(netMatch[2])}`,
          area: Number(netMatch[3]),
        });
        continue;
      }
      const stubMatch = trimmed.match(/^area\s+(\d+)\s+stub(\s+no-summary)?/i);
      if (stubMatch) {
        ospfAreaTypes[Number(stubMatch[1])] = stubMatch[2] ? 'totally-stubby' : 'stub';
        continue;
      }
      const nssaMatch = trimmed.match(/^area\s+(\d+)\s+nssa(\s+no-summary)?/i);
      if (nssaMatch) {
        const aid = Number(nssaMatch[1]);
        ospfAreaTypes[aid] = 'nssa';
        if (nssaMatch[2]) ospfNssaNoSummary[aid] = true;
        continue;
      }
      const rangeMatch = trimmed.match(/^area\s+(\d+)\s+range\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (rangeMatch) {
        ospfAreaRanges.push({
          id: `oar-${Date.now()}-${ospfAreaRanges.length}`,
          area: Number(rangeMatch[1]),
          prefix: `${rangeMatch[2]}/${maskToPrefixLen(rangeMatch[3])}`,
        });
        continue;
      }
      const vlMatch = trimmed.match(/^area\s+(\d+)\s+virtual-link\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (vlMatch) {
        ospfVirtualLinks.push({
          id: `ovl-${Date.now()}-${ospfVirtualLinks.length}`,
          transitArea: Number(vlMatch[1]),
          peerRouterId: vlMatch[2],
        });
        continue;
      }
    }

    if (currentSection === 'eigrp') {
      if (/^bfd\s+all-interfaces$/i.test(trimmed)) {
        eigrpBfd = true;
        continue;
      }
      const varMatch = trimmed.match(/^variance\s+(\d+)/i);
      if (varMatch) {
        eigrpVariance = Number(varMatch[1]);
        continue;
      }
    }

    if (currentSection === 'isis') {
      if (/^set-overload-bit/i.test(trimmed)) {
        isisOverloadBit = true;
        continue;
      }
      const msMatch = trimmed.match(/^metric-style\s+(narrow|wide)/i);
      if (msMatch) {
        isisMetricStyle = msMatch[1].toLowerCase() as 'narrow' | 'wide';
        continue;
      }
      if (/^multi-topology/i.test(trimmed)) {
        isisMultiTopologyV6 = true;
        continue;
      }
      const netMatch = trimmed.match(/^net\s+(\S+)/i);
      if (netMatch) {
        isisNet = netMatch[1];
        continue;
      }
      const typeMatch = trimmed.match(/^is-type\s+(level-1|level-2-only|level-1-2)/i);
      if (typeMatch) {
        const t = typeMatch[1].toLowerCase();
        isisLevel = t === 'level-1' ? 'L1' : t === 'level-2-only' ? 'L2' : 'L1-L2';
        continue;
      }
      if (/^bfd\s+all-interfaces$/i.test(trimmed)) {
        isisBfd = true;
        continue;
      }
      const passiveIsis = trimmed.match(/^passive-interface\s+(\S+)/i);
      if (passiveIsis) {
        const target = interfaces.find((i) => i.name.toLowerCase() === passiveIsis[1].toLowerCase());
        if (target) target.passive = true;
        continue;
      }
    }

    if (currentSection === 'lisp') {
      if (/^rloc-probing\s+bfd$/i.test(trimmed)) {
        lispBfd = true;
        continue;
      }
      const iidMatch = trimmed.match(/^instance-id\s+(\d+)/i);
      if (iidMatch) {
        lispInstanceId = Number(iidMatch[1]);
        continue;
      }
      if (/^(?:map-server|map-resolver)$/i.test(trimmed)) {
        lispRole = 'ms-mr';
        continue;
      }
      if (/^proxy-(?:etr|itr)$/i.test(trimmed)) {
        lispRole = 'pxtr';
        continue;
      }
      const msMatch = trimmed.match(/^(?:map-server|map-resolver)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (msMatch) {
        lispMapServerIp = msMatch[1];
        continue;
      }
      const dbMatch = trimmed.match(
        /^database-mapping\s+(\d+\.\d+\.\d+\.\d+\/\d+)\s+(?:locator\s+)?(\d+\.\d+\.\d+\.\d+)(?:\s+priority\s+(\d+))?(?:\s+weight\s+(\d+))?/i
      );
      if (dbMatch) {
        lispRlocIp = dbMatch[2];
        lispEidPrefixes.push({
          id: `eid-${Date.now()}-${lispEidPrefixes.length}`,
          prefix: dbMatch[1],
          instanceId: lispInstanceId,
          priority: dbMatch[3] ? Number(dbMatch[3]) : undefined,
          weight: dbMatch[4] ? Number(dbMatch[4]) : undefined,
        });
        continue;
      }
      const eidMatch = trimmed.match(/^eid-prefix\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      if (eidMatch) {
        lispRole = 'ms-mr';
        lispEidPrefixes.push({
          id: `eid-${Date.now()}-${lispEidPrefixes.length}`,
          prefix: eidMatch[1],
          instanceId: lispInstanceId,
        });
        continue;
      }
    }

    if (currentSection === 'bgp') {
      const afVrfMatch =
        trimmed.match(/^address-family\s+ipv[46]\s+vrf\s+(\S+)/i) ??
        trimmed.match(/^vrf\s+(\S+)$/i);
      if (afVrfMatch) {
        currentBgpVrf = afVrfMatch[1];
        currentBgpPeer = null;
        vrfs.add(currentBgpVrf);
        continue;
      }
      if (/^exit-address-family$/i.test(trimmed)) {
        currentBgpVrf = 'default';
        currentBgpPeer = null;
        continue;
      }
      const clusterMatch = trimmed.match(/^(?:bgp\s+)?cluster-id\s+(\S+)/i);
      if (clusterMatch) {
        bgpClusterId = clusterMatch[1];
        continue;
      }
      const confedIdMatch = trimmed.match(/^bgp\s+confederation\s+identifier\s+(\d+)/i);
      if (confedIdMatch) {
        bgpConfederationId = Number(confedIdMatch[1]);
        continue;
      }
      const confedPeersMatch = trimmed.match(/^bgp\s+confederation\s+peers\s+(.+)/i);
      if (confedPeersMatch) {
        bgpConfederationPeers = confedPeersMatch[1]
          .split(/\s+/)
          .map(Number)
          .filter((n) => Number.isFinite(n) && n > 0);
        continue;
      }
      if (/^bgp\s+always-compare-med$/i.test(trimmed)) { bgpAlwaysCompareMed = true; continue; }
      if (/^bgp\s+deterministic-med$/i.test(trimmed)) { bgpDeterministicMed = true; continue; }
      if (/^bgp\s+bestpath\s+as-path\s+ignore$/i.test(trimmed)) { bgpBestpathAsPathIgnore = true; continue; }
      if (/^bgp\s+bestpath\s+med\s+missing-as-worst$/i.test(trimmed)) { bgpMedMissingAsWorst = true; continue; }
      const ridMatch = trimmed.match(/^(?:bgp\s+)?router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (ridMatch) {
        if (currentBgpVrf === 'default') routerId = ridMatch[1];
        else vrfRouterIds[currentBgpVrf] = ridMatch[1];
        continue;
      }
      // NX-OS nested neighbor block: `neighbor <ip>` followed by indented attributes
      const nxNbrBlock = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)$/i);
      if (nxNbrBlock) {
        isNxOs = true;
        let peer = bgpPeers.find(
          (p) => p.peerIp === nxNbrBlock[1] && (p.vrf || 'default') === currentBgpVrf
        );
        if (!peer) {
          peer = {
            id: `bp-${Date.now()}-${bgpPeers.length}`,
            vrf: currentBgpVrf !== 'default' ? currentBgpVrf : undefined,
            peerIp: nxNbrBlock[1],
            remoteAs: bgpAsn,
          };
          bgpPeers.push(peer);
        }
        currentBgpPeer = peer;
        continue;
      }
      if (currentBgpPeer) {
        const ras = trimmed.match(/^remote-as\s+(\d+)/i);
        if (ras) { currentBgpPeer.remoteAs = Number(ras[1]); continue; }
        const usrc = trimmed.match(/^update-source\s+(\S+)/i);
        if (usrc) { currentBgpPeer.updateSource = usrc[1]; continue; }
        if (/^ebgp-multihop(?:\s+\d+)?$/i.test(trimmed)) { currentBgpPeer.ebgpMultihop = true; continue; }
        if (/^shutdown$/i.test(trimmed)) { currentBgpPeer.shutdown = true; continue; }
        if (/^next-hop-self$/i.test(trimmed)) { currentBgpPeer.nextHopSelf = true; continue; }
        if (/^default-originate$/i.test(trimmed)) { currentBgpPeer.defaultOriginate = true; continue; }
        if (/^route-reflector-client$/i.test(trimmed)) { currentBgpPeer.routeReflectorClient = true; continue; }
        if (/^soft-reconfiguration\s+inbound$/i.test(trimmed)) { currentBgpPeer.softReconfigurationInbound = true; continue; }
        if (/^allowas-in(?:\s+\d+)?$/i.test(trimmed)) { currentBgpPeer.allowAsIn = true; continue; }
        if (/^as-override$/i.test(trimmed)) { currentBgpPeer.asOverride = true; continue; }
        if (/^remove-private-as$/i.test(trimmed)) { currentBgpPeer.removePrivateAs = true; continue; }
        const scMatch = trimmed.match(/^send-community(?:\s+(standard|extended|both))?$/i);
        if (scMatch) { currentBgpPeer.sendCommunity = (scMatch[1]?.toLowerCase() as 'standard' | 'extended' | 'both') ?? 'standard'; continue; }
        const mpMatch = trimmed.match(/^maximum-prefix\s+(\d+)/i);
        if (mpMatch) { currentBgpPeer.maxPrefixes = Number(mpMatch[1]); continue; }
        const tm = trimmed.match(/^timers\s+(\d+)\s+(\d+)/i);
        if (tm) { currentBgpPeer.keepaliveTime = Number(tm[1]); currentBgpPeer.holdTime = Number(tm[2]); continue; }
      }
      const nbrMatch = trimmed.match(
        /^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remote-as\s+(\d+)/i
      );
      if (nbrMatch) {
        currentBgpPeer = null;
        bgpPeers.push({
          id: `bp-${Date.now()}-${bgpPeers.length}`,
          vrf: currentBgpVrf !== 'default' ? currentBgpVrf : undefined,
          peerIp: nbrMatch[1],
          remoteAs: Number(nbrMatch[2]),
        });
        continue;
      }
      const netCidrMatch = trimmed.match(/^network\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      if (netCidrMatch) {
        bgpNetworks.push({
          id: `bn-${Date.now()}-${bgpNetworks.length}`,
          vrf: currentBgpVrf !== 'default' ? currentBgpVrf : undefined,
          prefix: netCidrMatch[1],
        });
        continue;
      }
      const netMaskMatch = trimmed.match(
        /^network\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\d+\.\d+\.\d+\.\d+)/i
      );
      if (netMaskMatch) {
        bgpNetworks.push({
          id: `bn-${Date.now()}-${bgpNetworks.length}`,
          vrf: currentBgpVrf !== 'default' ? currentBgpVrf : undefined,
          prefix: `${netMaskMatch[1]}/${maskToPrefixLen(netMaskMatch[2])}`,
        });
        continue;
      }
      const multihopMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+ebgp-multihop/i);
      if (multihopMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === multihopMatch[1]);
        if (peer) peer.ebgpMultihop = true;
        continue;
      }
      const bfdMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+fall-over\s+bfd/i);
      if (bfdMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === bfdMatch[1]);
        if (peer) peer.bfd = true;
        continue;
      }
      const softReconfigMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+soft-reconfiguration\s+inbound/i);
      if (softReconfigMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === softReconfigMatch[1]);
        if (peer) peer.softReconfigurationInbound = true;
        continue;
      }
      const grNbrMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+graceful-restart/i);
      if (grNbrMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === grNbrMatch[1]);
        if (peer) peer.gracefulRestart = true;
        continue;
      }
      const timersMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+timers\s+(\d+)\s+(\d+)/i);
      if (timersMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === timersMatch[1]);
        if (peer) {
          peer.keepaliveTime = Number(timersMatch[2]);
          peer.holdTime = Number(timersMatch[3]);
        }
        continue;
      }
      const shutNbrMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+shutdown$/i);
      if (shutNbrMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === shutNbrMatch[1]);
        if (peer) peer.shutdown = true;
        continue;
      }
      const updSrcMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+update-source\s+(\S+)/i);
      if (updSrcMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === updSrcMatch[1]);
        if (peer) peer.updateSource = updSrcMatch[2];
        continue;
      }
      const allowAsMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+allowas-in/i);
      if (allowAsMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === allowAsMatch[1]);
        if (peer) peer.allowAsIn = true;
        continue;
      }
      const asOvMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+as-override/i);
      if (asOvMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === asOvMatch[1]);
        if (peer) peer.asOverride = true;
        continue;
      }
      const sendCommMatch = trimmed.match(
        /^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+send-community(?:\s+(standard|extended|both))?/i
      );
      if (sendCommMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === sendCommMatch[1]);
        if (peer) {
          peer.sendCommunity =
            (sendCommMatch[2]?.toLowerCase() as 'standard' | 'extended' | 'both') ?? 'standard';
        }
        continue;
      }
      const remPrivMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remove-private-as/i);
      if (remPrivMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === remPrivMatch[1]);
        if (peer) peer.removePrivateAs = true;
        continue;
      }
      const maxPrefMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+maximum-prefix\s+(\d+)/i);
      if (maxPrefMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === maxPrefMatch[1]);
        if (peer) peer.maxPrefixes = Number(maxPrefMatch[2]);
        continue;
      }
      const localAsMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+local-as\s+(\d+)(\s+no-prepend)?(\s+replace-as)?/i);
      if (localAsMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === localAsMatch[1]);
        if (peer) {
          peer.localAs = Number(localAsMatch[2]);
          if (localAsMatch[3]) peer.localAsNoPrepend = true;
          if (localAsMatch[4]) peer.localAsReplaceAs = true;
        }
        continue;
      }
      const addPathMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+add-path\s+(send|receive|both)/i);
      if (addPathMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === addPathMatch[1]);
        if (peer) peer.addPath = addPathMatch[2].toLowerCase() as 'send' | 'receive' | 'both';
        continue;
      }
      const dccMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+disable-connected-check/i);
      if (dccMatch) {
        const peer = bgpPeers.find((p) => p.peerIp === dccMatch[1]);
        if (peer) peer.disableConnectedCheck = true;
        continue;
      }
      const aggMatch = trimmed.match(
        /^aggregate-address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(.*)$/i
      );
      if (aggMatch) {
        const tail = aggMatch[3].toLowerCase();
        bgpAggregates.push({
          id: `ba-${Date.now()}-${bgpAggregates.length}`,
          prefix: `${aggMatch[1]}/${maskToPrefixLen(aggMatch[2])}`,
          summaryOnly: tail.includes('summary-only'),
          asSet: tail.includes('as-set') || undefined,
        });
        continue;
      }
    }

    const stpModeMatch = trimmed.match(/^spanning-tree\s+mode\s+(rstp|mstp|pvst|rapid-pvst)/i);
    if (stpModeMatch) {
      const m = stpModeMatch[1].toLowerCase();
      switchingConfig = {
        ...switchingConfig,
        stpEnabled: true,
        stpMode: m === 'mstp' ? 'mstp' : m === 'pvst' ? 'pvst' : 'rstp',
      };
      continue;
    }
    const stpPrioMatch = trimmed.match(/^spanning-tree\s+vlan\s+\S+\s+priority\s+(\d+)/i);
    if (stpPrioMatch) {
      switchingConfig = { ...switchingConfig, stpEnabled: true, stpPriority: Number(stpPrioMatch[1]) };
      continue;
    }
    if (/^lldp\s+run$/i.test(trimmed)) {
      switchingConfig = { ...switchingConfig, lldpEnabled: true };
      continue;
    }
    if (/^mpls\s+ip$/i.test(trimmed)) {
      mplsConfig = { ...mplsConfig, ldpEnabled: true };
      continue;
    }
    const ldpRid = trimmed.match(/^mpls\s+ldp\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (ldpRid) {
      mplsConfig = { ...mplsConfig, ldpEnabled: true, ldpRouterId: ldpRid[1] };
      continue;
    }
    if (/^segment-routing\s+mpls$/i.test(trimmed)) {
      mplsConfig = { ...mplsConfig, segmentRouting: { ...(mplsConfig?.segmentRouting ?? { enabled: true }), enabled: true } };
      continue;
    }
    if (/^ip\s+multicast-routing$/i.test(trimmed)) {
      multicastConfig = { ...multicastConfig, pimEnabled: true };
      continue;
    }
    const pimRpMatch = trimmed.match(/^ip\s+pim\s+rp-address\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (pimRpMatch) {
      multicastConfig = { ...multicastConfig, pimEnabled: true, rpAddress: pimRpMatch[1] };
      continue;
    }
    const ntpMatch = trimmed.match(/^ntp\s+server\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (ntpMatch) {
      timingConfig = { ...timingConfig, ntpServer: ntpMatch[1] };
      continue;
    }
    const bmpMatch = trimmed.match(/^bmp\s+server\s+\d+\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (bmpMatch) {
      telemetryConfig = { ...telemetryConfig, bmpServerIp: bmpMatch[1] };
      continue;
    }
    const ipfixMatch = trimmed.match(/^ip\s+flow-export\s+destination\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (ipfixMatch) {
      telemetryConfig = { ...telemetryConfig, ipfixCollectorIp: ipfixMatch[1] };
      continue;
    }

    const staticVrfMatch = trimmed.match(
      /^ip\s+route\s+vrf\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(\s+global)?(?:\s+(\d+))?/i
    );
    if (staticVrfMatch) {
      vrfs.add(staticVrfMatch[1]);
      staticRoutes.push({
        id: `sr-${Date.now()}-${staticRoutes.length}`,
        vrf: staticVrfMatch[1],
        prefix: `${staticVrfMatch[2]}/${maskToPrefixLen(staticVrfMatch[3])}`,
        nextHop: staticVrfMatch[4],
        globalNextHop: Boolean(staticVrfMatch[5]),
        ad: staticVrfMatch[6] ? Number(staticVrfMatch[6]) : undefined,
      });
      continue;
    }

    const staticMatch = trimmed.match(
      /^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?/i
    );
    if (staticMatch) {
      staticRoutes.push({
        id: `sr-${Date.now()}-${staticRoutes.length}`,
        vrf: 'default',
        prefix: `${staticMatch[1]}/${maskToPrefixLen(staticMatch[2])}`,
        nextHop: staticMatch[3],
        ad: staticMatch[4] ? Number(staticMatch[4]) : undefined,
      });
      continue;
    }

    const showConn = trimmed.match(/^C\s+(\d+\.\d+\.\d+\.\d+\/\d+)\s+is directly connected,\s+(\S+)/);
    if (showConn) {
      const parsedConn = parseCidr(showConn[1]);
      const hostCidr =
        parsedConn && parsedConn.prefixLen < 31
          ? `${uint32ToIp((parsedConn.networkUint32 + 1) >>> 0)}/${parsedConn.prefixLen}`
          : showConn[1];
      interfaces.push({
        id: `if-${Date.now()}-${interfaces.length}`,
        name: showConn[2],
        cidr: hostCidr,
        vrf: 'default',
      });
      continue;
    }

    const showStatic = trimmed.match(
      /^S\*?\s+(\d+\.\d+\.\d+\.\d+\/\d+)\s+\[(\d+)\/\d+\]\s+via\s+(\d+\.\d+\.\d+\.\d+)/
    );
    if (showStatic) {
      staticRoutes.push({
        id: `sr-${Date.now()}-${staticRoutes.length}`,
        vrf: 'default',
        prefix: showStatic[1],
        nextHop: showStatic[3],
        ad: Number(showStatic[2]),
      });
    }
  }

  const validInterfaces = interfaces
    .filter(
      (i) =>
        i.cidr !== '0.0.0.0/0' ||
        Boolean(i.cidr6) ||
        Boolean(i.unnumberedSource) ||
        i.lacpGroup !== undefined ||
        interfaces.some((sub) => sub.parentInterface?.toLowerCase() === i.name.toLowerCase())
    )
    .map((i) => (i.cidr === '0.0.0.0/0' ? { ...i, cidr: '' } : i));
  if (validInterfaces.length === 0) {
    validInterfaces.push({
      id: `if-${Date.now()}-0`,
      name: 'GigabitEthernet0/0',
      cidr: '10.250.0.1/30',
      vrf: 'default',
    });
  }

  const isForcepoint = lines.some((l) => /forcepoint|frr|vtysh/i.test(l));
  const detectedNxOs = isNxOs || Boolean(vpcConfig) || lines.some((l) => /feature\s+vpc|nx-os|n9k/i.test(l));

  return {
    id: `imp-${Date.now()}-${++importIdSeq}`,
    hostname,
    vendor: isForcepoint ? 'forcepoint-ngfw' : detectedNxOs ? 'cisco-nx-os' : 'cisco-ios-xe',
    routerId,
    vrfRouterIds: Object.keys(vrfRouterIds).length ? vrfRouterIds : undefined,
    position: { x: 240, y: 140 },
    maxPaths: 4,
    vrfs: Array.from(vrfs),
    adOverrides: {},
    interfaces: validInterfaces,
    staticRoutes,
    ospf: {
      enabled: ospfEnabled,
      bfd: ospfBfd || undefined,
      maxMetricRouterLsa: ospfMaxMetricRouterLsa || undefined,
      areaTypes: Object.keys(ospfAreaTypes).length ? ospfAreaTypes : undefined,
      nssaNoSummary: Object.keys(ospfNssaNoSummary).length ? ospfNssaNoSummary : undefined,
      areaRanges: ospfAreaRanges.length ? ospfAreaRanges : undefined,
      virtualLinks: ospfVirtualLinks.length ? ospfVirtualLinks : undefined,
      networks: ospfNetworks,
    },
    eigrp: eigrpEnabled ? { enabled: true, asn: eigrpAsn, bfd: eigrpBfd || undefined, variance: eigrpVariance, networks: [] } : undefined,
    isis: isisEnabled ? { enabled: true, net: isisNet, bfd: isisBfd || undefined, overloadBit: isisOverloadBit || undefined, metricStyle: isisMetricStyle, multiTopologyV6: isisMultiTopologyV6 || undefined, level: isisLevel, networks: [] } : undefined,
    bgp: {
      enabled: bgpEnabled,
      asn: bgpAsn,
      clusterId: bgpClusterId,
      confederationId: bgpConfederationId,
      confederationPeers: bgpConfederationPeers,
      alwaysCompareMed: bgpAlwaysCompareMed || undefined,
      deterministicMed: bgpDeterministicMed || undefined,
      bestpathAsPathIgnore: bgpBestpathAsPathIgnore || undefined,
      medMissingAsWorst: bgpMedMissingAsWorst || undefined,
      peers: bgpPeers,
      networks: bgpNetworks,
      aggregates: bgpAggregates.length ? bgpAggregates : undefined,
    },
    lisp: lispEnabled
      ? {
        enabled: true,
        role: lispRole,
        rlocIp: lispRlocIp || routerId,
        mapServerIp: lispMapServerIp,
        instanceId: lispInstanceId,
        bfd: lispBfd || undefined,
        eidPrefixes: lispEidPrefixes,
      }
      : undefined,
    redistributions: [],
    prefixLists: [],
    routeMaps,
    vrfLeaks: [],
    mplsVpn: mplsVrfTargets.length ? { enabled: true, vrfTargets: mplsVrfTargets } : undefined,
    mpls: mplsConfig,
    switching: switchingConfig,
    multicast: multicastConfig,
    timing: timingConfig,
    telemetry: telemetryConfig,
    evpn: evpnConfig,
    fhrpGroups: fhrpGroups.length ? fhrpGroups : undefined,
    vpc: vpcConfig,
  };
}

function parseFortigateConfig(lines: string[]): NodeConfig {
  let hostname = 'FGT-IMPORTED';
  const routerId = '10.255.0.10';
  const vrfs = new Set<string>(['default']);
  const interfaces: InterfaceConfig[] = [];
  const staticRoutes: StaticRouteConfig[] = [];
  let bgpEnabled = false;
  let bgpAsn = 65000;
  let bgpRouterId = routerId;
  const bgpPeers: BgpPeerConfig[] = [];

  let block = '';
  let subBlock = '';
  let nestedUnknownDepth = 0;
  let curIf: InterfaceConfig | null = null;
  let curStatic: Partial<StaticRouteConfig> | null = null;
  let curPeer: Partial<BgpPeerConfig> | null = null;

  for (const raw of lines) {
    const t = raw.trim();
    if (!t || t.startsWith('#')) continue;
    if (/^config\s+system\s+global$/i.test(t)) { block = 'global'; nestedUnknownDepth = 0; continue; }
    if (/^config\s+system\s+interface$/i.test(t)) { block = 'interface'; nestedUnknownDepth = 0; continue; }
    if (/^config\s+router\s+static$/i.test(t)) { block = 'static'; nestedUnknownDepth = 0; continue; }
    if (/^config\s+router\s+bgp$/i.test(t)) { block = 'bgp'; nestedUnknownDepth = 0; continue; }
    if (/^config\s+neighbor$/i.test(t) && block === 'bgp') { subBlock = 'neighbor'; continue; }
    if (/^config\s+/i.test(t) && block) { nestedUnknownDepth++; continue; }
    if (t === 'end') {
      if (nestedUnknownDepth > 0) {
        nestedUnknownDepth--;
        continue;
      }
      if (subBlock) subBlock = '';
      else block = '';
      curIf = null;
      curStatic = null;
      curPeer = null;
      continue;
    }
    if (t === 'next') {
      if (block === 'static' && curStatic?.prefix && curStatic.nextHop) {
        staticRoutes.push({
          id: `sr-${Date.now()}-${staticRoutes.length}`,
          vrf: 'default',
          prefix: curStatic.prefix,
          nextHop: curStatic.nextHop,
        });
      }
      if (subBlock === 'neighbor' && curPeer?.peerIp && curPeer.remoteAs) {
        bgpPeers.push({
          id: `bgp-${Date.now()}-${bgpPeers.length}`,
          peerIp: curPeer.peerIp,
          remoteAs: curPeer.remoteAs,
        });
      }
      curIf = null;
      curStatic = null;
      curPeer = null;
      continue;
    }

    const editMatch = t.match(/^edit\s+"?([^"]+)"?$/i);
    if (editMatch) {
      if (block === 'interface') {
        curIf = { id: `if-${Date.now()}-${interfaces.length}`, name: editMatch[1], cidr: '0.0.0.0/0', vrf: 'default' };
        interfaces.push(curIf);
      } else if (block === 'static') {
        curStatic = {};
      } else if (subBlock === 'neighbor') {
        curPeer = { peerIp: editMatch[1] };
      }
      continue;
    }

    if (block === 'global') {
      const hm = t.match(/^set\s+hostname\s+"?([^"]+)"?/i);
      if (hm) hostname = hm[1];
    } else if (block === 'interface' && curIf) {
      const ipm = t.match(/^set\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (ipm) curIf.cidr = `${ipm[1]}/${maskToPrefixLen(ipm[2])}`;
      const vm = t.match(/^set\s+vrf\s+(\S+)/i);
      if (vm) { vrfs.add(vm[1]); curIf.vrf = vm[1]; }
    } else if (block === 'static' && curStatic) {
      const dm = t.match(/^set\s+dst\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      if (dm) curStatic.prefix = dm[1];
      const gm = t.match(/^set\s+gateway\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (gm) curStatic.nextHop = gm[1];
    } else if (block === 'bgp' && !subBlock) {
      const am = t.match(/^set\s+as\s+(\d+)/i);
      if (am) bgpAsn = Number(am[1]);
      const rm = t.match(/^set\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (rm) bgpRouterId = rm[1];
    } else if (subBlock === 'neighbor' && curPeer) {
      const ram = t.match(/^set\s+remote-as\s+(\d+)/i);
      if (ram) curPeer.remoteAs = Number(ram[1]);
    }
  }

  const validInterfaces = interfaces.filter((i) => i.cidr !== '0.0.0.0/0');
  if (validInterfaces.length === 0) {
    validInterfaces.push({ id: `if-${Date.now()}-0`, name: 'port1', cidr: '10.250.0.1/30', vrf: 'default' });
  }

  return {
    id: `imp-${Date.now()}-${++importIdSeq}`,
    hostname,
    vendor: 'fortigate',
    routerId: bgpRouterId,
    position: { x: 240, y: 140 },
    maxPaths: 4,
    vrfs: Array.from(vrfs),
    adOverrides: {},
    interfaces: validInterfaces,
    staticRoutes,
    ospf: { enabled: false, networks: [] },
    bgp: { enabled: bgpEnabled, asn: bgpAsn, peers: bgpPeers, networks: [] },
    redistributions: [],
    prefixLists: [],
    routeMaps: [],
    vrfLeaks: [],
  };
}

function parseJunosSetConfig(lines: string[]): NodeConfig {
  let hostname = 'JUNOS-IMPORTED';
  let routerId = '10.255.0.20';
  const vrfs = new Set<string>(['default']);
  const ifaceMap = new Map<string, { cidr: string; cidr6?: string; vrf: string; ospfArea?: number }>();
  const staticRoutes: StaticRouteConfig[] = [];
  let ospfEnabled = false;
  let bgpEnabled = false;
  let bgpAsn = 65000;
  const bgpPeers: BgpPeerConfig[] = [];

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    const hostMatch = line.match(/^set\s+system\s+host-name\s+"?([^"\s]+)"?/i);
    if (hostMatch) {
      hostname = hostMatch[1];
      continue;
    }

    const ridMatch = line.match(/^set\s+routing-options\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (ridMatch) {
      routerId = ridMatch[1];
      continue;
    }

    const asMatch = line.match(/^set\s+routing-options\s+autonomous-system\s+(\d+)/i);
    if (asMatch) {
      bgpEnabled = true;
      bgpAsn = Number(asMatch[1]);
      continue;
    }

    const ifV4Match = line.match(
      /^set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet\s+address\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i
    );
    if (ifV4Match) {
      const ifName = ifV4Match[2] === '0' ? ifV4Match[1] : `${ifV4Match[1]}.${ifV4Match[2]}`;
      const cur = ifaceMap.get(ifName) ?? { cidr: ifV4Match[3], vrf: 'default' };
      cur.cidr = ifV4Match[3];
      ifaceMap.set(ifName, cur);
      continue;
    }

    const ifV6Match = line.match(
      /^set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet6\s+address\s+([0-9a-fA-F:]+\/\d+)/i
    );
    if (ifV6Match) {
      const ifName = ifV6Match[2] === '0' ? ifV6Match[1] : `${ifV6Match[1]}.${ifV6Match[2]}`;
      const cur = ifaceMap.get(ifName) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      cur.cidr6 = ifV6Match[3];
      ifaceMap.set(ifName, cur);
      continue;
    }

    const riIfMatch = line.match(/^set\s+routing-instances\s+(\S+)\s+interface\s+(\S+)/i);
    if (riIfMatch) {
      const vrfName = riIfMatch[1];
      const rawIf = riIfMatch[2].replace(/\.0$/, '');
      vrfs.add(vrfName);
      const cur = ifaceMap.get(rawIf) ?? ifaceMap.get(riIfMatch[2]);
      if (cur) cur.vrf = vrfName;
      else ifaceMap.set(rawIf, { cidr: '0.0.0.0/0', vrf: vrfName });
      continue;
    }

    const ospfIfMatch = line.match(
      /^set\s+protocols\s+ospf\s+area\s+(\S+)\s+interface\s+(\S+)/i
    );
    if (ospfIfMatch) {
      ospfEnabled = true;
      const areaRaw = ospfIfMatch[1];
      const areaNum = areaRaw.includes('.') ? Number(areaRaw.split('.').pop()) : Number(areaRaw);
      const rawIf = ospfIfMatch[2].replace(/\.0$/, '');
      const cur = ifaceMap.get(rawIf) ?? ifaceMap.get(ospfIfMatch[2]);
      if (cur && Number.isFinite(areaNum)) cur.ospfArea = areaNum;
      continue;
    }

    const staticMatch = line.match(
      /^set\s+(?:routing-instances\s+(\S+)\s+)?routing-options\s+static\s+route\s+(\S+)\s+next-hop\s+(\d+\.\d+\.\d+\.\d+)/i
    );
    if (staticMatch) {
      const vrf = staticMatch[1] || 'default';
      vrfs.add(vrf);
      staticRoutes.push({
        id: `sr-${Date.now()}-${staticRoutes.length}`,
        vrf,
        prefix: staticMatch[2],
        nextHop: staticMatch[3],
      });
      continue;
    }

    const bgpPeerMatch = line.match(
      /^set\s+protocols\s+bgp\s+group\s+\S+\s+neighbor\s+(\d+\.\d+\.\d+\.\d+)(?:\s+peer-as\s+(\d+))?/i
    );
    if (bgpPeerMatch) {
      bgpEnabled = true;
      const existing = bgpPeers.find((p) => p.peerIp === bgpPeerMatch[1]);
      const remoteAs = bgpPeerMatch[2] ? Number(bgpPeerMatch[2]) : bgpAsn;
      if (existing) existing.remoteAs = remoteAs;
      else {
        bgpPeers.push({
          id: `bp-${Date.now()}-${bgpPeers.length}`,
          peerIp: bgpPeerMatch[1],
          remoteAs,
        });
      }
      continue;
    }
  }

  return {
    id: `imp-${Date.now()}-${++importIdSeq}`,
    hostname,
    vendor: 'juniper-junos',
    routerId,
    position: { x: 240, y: 180 },
    maxPaths: 4,
    vrfs: Array.from(vrfs),
    adOverrides: {},
    interfaces: Array.from(ifaceMap.entries()).map(([name, info], i) => ({
      id: `if-${Date.now()}-${i}`,
      name,
      cidr: info.cidr,
      cidr6: info.cidr6,
      vrf: info.vrf,
      ospfArea: info.ospfArea,
    })),
    staticRoutes,
    ospf: { enabled: ospfEnabled, networks: [] },
    bgp: { enabled: bgpEnabled, asn: bgpAsn, peers: bgpPeers, networks: [] },
    redistributions: [],
    prefixLists: [],
    routeMaps: [],
    vrfLeaks: [],
  };
}

function parseMikrotikConfig(lines: string[]): NodeConfig {
  let hostname = 'MIKROTIK-IMPORTED';
  let routerId = '10.255.0.30';
  const vrfs = new Set<string>(['default']);
  const ifaceMap = new Map<string, { cidr: string; cidr6?: string; vrf: string; ospfArea?: number }>();
  const staticRoutes: StaticRouteConfig[] = [];
  let ospfEnabled = false;
  let bgpEnabled = false;
  let bgpAsn = 65000;
  const bgpPeers: BgpPeerConfig[] = [];
  const ospfAreas = new Map<string, number>();

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    if (line.startsWith('/system identity set')) {
      const m = line.match(/name="?([^"\s]+)"?/i);
      if (m) hostname = m[1];
      continue;
    }

    if (line.startsWith('/ip vrf add')) {
      const nm = line.match(/name="?([^"\s]+)"?/i);
      const ifm = line.match(/interfaces=([^\s]+)/i);
      if (nm) {
        vrfs.add(nm[1]);
        if (ifm) {
          for (const ifName of ifm[1].split(',')) {
            const cur = ifaceMap.get(ifName) ?? { cidr: '0.0.0.0/0', vrf: nm[1] };
            cur.vrf = nm[1];
            ifaceMap.set(ifName, cur);
          }
        }
      }
      continue;
    }

    if (line.startsWith('/ip address add')) {
      const addr = line.match(/address=(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      const ifm = line.match(/interface="?([^"\s]+)"?/i);
      if (addr && ifm) {
        const cur = ifaceMap.get(ifm[1]) ?? { cidr: addr[1], vrf: 'default' };
        cur.cidr = addr[1];
        ifaceMap.set(ifm[1], cur);
      }
      continue;
    }

    if (line.startsWith('/ipv6 address add')) {
      const addr6 = line.match(/address=([0-9a-fA-F:]+\/\d+)/i);
      const ifm = line.match(/interface="?([^"\s]+)"?/i);
      if (addr6 && ifm) {
        const cur = ifaceMap.get(ifm[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
        cur.cidr6 = addr6[1];
        ifaceMap.set(ifm[1], cur);
      }
      continue;
    }

    if (line.startsWith('/ip route add')) {
      const dst = line.match(/dst-address=(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      const gw = line.match(/gateway=(\d+\.\d+\.\d+\.\d+)/i);
      const rt = line.match(/routing-table="?([^"\s]+)"?/i);
      const dist = line.match(/distance=(\d+)/i);
      if (dst && gw) {
        const vrf = rt && rt[1] !== 'main' ? rt[1] : 'default';
        vrfs.add(vrf);
        staticRoutes.push({
          id: `sr-${Date.now()}-${staticRoutes.length}`,
          vrf,
          prefix: dst[1],
          nextHop: gw[1],
          ad: dist ? Number(dist[1]) : undefined,
        });
      }
      continue;
    }

    if (line.startsWith('/routing ospf instance')) {
      ospfEnabled = true;
      const rid = line.match(/router-id=(\d+\.\d+\.\d+\.\d+)/i);
      if (rid) routerId = rid[1];
      continue;
    }

    if (line.startsWith('/routing ospf area add')) {
      ospfEnabled = true;
      const nm = line.match(/name="?([^"\s]+)"?/i);
      const aid = line.match(/area-id=(\S+)/i);
      if (nm && aid) {
        const areaNum = aid[1].includes('.') ? Number(aid[1].split('.').pop()) : Number(aid[1]);
        if (Number.isFinite(areaNum)) ospfAreas.set(nm[1], areaNum);
      }
      continue;
    }

    if (line.startsWith('/routing ospf interface-template add')) {
      ospfEnabled = true;
      const areaM = line.match(/area="?([^"\s]+)"?/i);
      const ifM = line.match(/interfaces=([^\s]+)/i);
      const areaNum = areaM ? (ospfAreas.get(areaM[1]) ?? (Number(areaM[1]) || 0)) : 0;
      if (ifM) {
        for (const ifName of ifM[1].split(',')) {
          const cur = ifaceMap.get(ifName);
          if (cur) cur.ospfArea = areaNum;
        }
      }
      continue;
    }

    if (line.startsWith('/routing bgp template') || line.startsWith('/routing bgp instance')) {
      bgpEnabled = true;
      const asM = line.match(/\bas=(\d+)/i);
      const rid = line.match(/router-id=(\d+\.\d+\.\d+\.\d+)/i);
      if (asM) bgpAsn = Number(asM[1]);
      if (rid) routerId = rid[1];
      continue;
    }

    if (line.startsWith('/routing bgp connection add')) {
      bgpEnabled = true;
      const remIp = line.match(/remote\.address=(\d+\.\d+\.\d+\.\d+)/i);
      const remAs = line.match(/remote\.as=(\d+)/i);
      if (remIp) {
        bgpPeers.push({
          id: `bp-${Date.now()}-${bgpPeers.length}`,
          peerIp: remIp[1],
          remoteAs: remAs ? Number(remAs[1]) : bgpAsn,
        });
      }
      continue;
    }
  }

  return {
    id: `imp-${Date.now()}-${++importIdSeq}`,
    hostname,
    vendor: 'mikrotik-routeros',
    routerId,
    position: { x: 240, y: 180 },
    maxPaths: 4,
    vrfs: Array.from(vrfs),
    adOverrides: {},
    interfaces: Array.from(ifaceMap.entries()).map(([name, info], i) => ({
      id: `if-${Date.now()}-${i}`,
      name,
      cidr: info.cidr,
      cidr6: info.cidr6,
      vrf: info.vrf,
      ospfArea: info.ospfArea,
    })),
    staticRoutes,
    ospf: { enabled: ospfEnabled, networks: [] },
    bgp: { enabled: bgpEnabled, asn: bgpAsn, peers: bgpPeers, networks: [] },
    redistributions: [],
    prefixLists: [],
    routeMaps: [],
    vrfLeaks: [],
  };
}

export function importTopologyFromText(raw: string): TopologyState {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error('Input is empty.');
  }

  if (trimmed.startsWith('{')) {
    let parsed: TopologyState;
    try {
      parsed = JSON.parse(trimmed) as TopologyState;
    } catch (err) {
      throw new Error(
        `Invalid JSON: ${err instanceof Error ? err.message : 'parse error'}`
      );
    }
    if (parsed && Array.isArray(parsed.nodes) && Array.isArray(parsed.links)) {
      return parsed;
    }
    throw new Error('JSON must contain "nodes" and "links" arrays.');
  }

  if (/(?:^|\n)nodes:\s*/.test(trimmed) && /(?:^|\n)links:\s*/.test(trimmed)) {
    const parsed = load(trimmed) as TopologyState;
    if (parsed && Array.isArray(parsed.nodes) && Array.isArray(parsed.links)) {
      return parsed;
    }
    throw new Error('YAML must contain "nodes" and "links" arrays.');
  }

  const lines = trimmed.split(/\r?\n/);
  const isForti = lines.some((l) => /^config\s+(system|router)\b/i.test(l.trim()));
  const isMikrotik =
    !isForti &&
    lines.some((l) =>
      /^\/(?:ip\s+(?:address|route|vrf)|ipv6\s+address|system\s+identity|routing\s+(?:ospf|bgp))\b/i.test(
        l.trim()
      )
    );
  const isJunosSet =
    !isForti &&
    !isMikrotik &&
    lines.some((l) =>
      /^set\s+(?:system\s+host-name|interfaces\s+\S+\s+unit|routing-options|routing-instances|protocols\s+(?:ospf|bgp))\b/i.test(
        l.trim()
      )
    );
  const isCiscoStyle = lines.some((l) =>
    /^(?:interface\s+\S+|router\s+(?:ospf|bgp|eigrp|isis|rip)|route-map\s+\S+)/i.test(l.trim())
  );
  const isPanSet =
    !isForti &&
    !isMikrotik &&
    !isJunosSet &&
    !isCiscoStyle &&
    lines.some((l) => l.trim().startsWith('set '));
  const node = isForti
    ? parseFortigateConfig(lines)
    : isMikrotik
      ? parseMikrotikConfig(lines)
      : isJunosSet
        ? parseJunosSetConfig(lines)
        : isPanSet
          ? parsePanOsSetConfig(lines)
          : parseCiscoStyleConfig(lines);
  return { nodes: [node], links: [] };
}
