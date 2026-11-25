import { load } from 'js-yaml';
import {
  BgpPeerConfig,
  InterfaceConfig,
  NodeConfig,
  StaticRouteConfig,
  TopologyState,
} from '../types/network';
import { ipToUint32, parseCidr, uint32ToIp } from './ipMath';
import {
  parseCheckpointGaiaAclRules,
  parseCiscoStyleAclRules,
  parseCloudAclRules,
  parseFortigateAclRules,
  parseJunosAclRules,
  parseMikrotikAclRules,
  parsePanOsAclRules,
  parseVyosAclRules,
} from './firewallImporter';

let importIdSeq = 0;
function nextImportId(prefix: string): string {
  return `${prefix}-${Date.now()}-${++importIdSeq}`;
}

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

function collapseSpacesPreservingQuotes(s: string): string {
  let out = '';
  let inQuote: '"' | "'" | null = null;
  let prevSpace = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inQuote) {
      out += ch;
      if (ch === inQuote) inQuote = null;
      prevSpace = false;
    } else if (ch === '"' || ch === "'") {
      inQuote = ch;
      out += ch;
      prevSpace = false;
    } else if (/\s/.test(ch)) {
      if (!prevSpace) {
        out += ' ';
        prevSpace = true;
      }
    } else {
      out += ch;
      prevSpace = false;
    }
  }
  return out.trim();
}

export function normalizeConfigLine(raw: string): string {
  const cleaned = raw
    .replace(/[\u00A0\u200B\uFEFF]/g, ' ')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/\t/g, ' ');
  const leadMatch = cleaned.match(/^(\s*)/);
  const leading = leadMatch ? leadMatch[1] : '';
  const body = collapseSpacesPreservingQuotes(cleaned);
  return body ? `${leading}${body}` : '';
}

export function autoFormatRunningConfig(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return raw;

  // JSON pretty-print
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      return raw;
    }
  }

  const lines = raw.split(/\r?\n/).map((l) => normalizeConfigLine(l));
  const nonEmpty = lines.map((l) => l.trim()).filter(Boolean);

  // 1. Terraform HCL (`resource "..." "..." { ... }`)
  const isHcl = nonEmpty.some((l) => /^resource\s+"[^"]+"\s+"[^"]+"\s*\{/i.test(l));
  if (isHcl) {
    const out: string[] = [];
    let depth = 0;
    for (const rawLine of lines) {
      const t = rawLine.trim();
      if (!t) {
        if (out.length > 0 && out[out.length - 1] !== '') out.push('');
        continue;
      }
      if (t.startsWith('}')) depth = Math.max(0, depth - 1);
      out.push(`${'  '.repeat(depth)}${t}`);
      const codeOnly = t.replace(/#.*$/, '');
      const opens = (codeOnly.match(/\{/g) || []).length;
      const closes = (codeOnly.match(/\}/g) || []).length;
      if (t.startsWith('}')) {
        depth = Math.max(0, depth + opens - Math.max(0, closes - 1));
      } else {
        depth = Math.max(0, depth + opens - closes);
      }
    }
    return out.join('\n').trim();
  }

  // 2. FortiGate (`config ... / edit ... / next / end`)
  const isForti = nonEmpty.some((l) => /^config\s+(?:system|router|firewall|vpn)\b/i.test(l));
  if (isForti) {
    const out: string[] = [];
    let depth = 0;
    for (const rawLine of lines) {
      const t = rawLine.trim();
      if (!t) continue;
      if (t.startsWith('#')) {
        out.push(t);
        continue;
      }
      if (/^end$/i.test(t)) {
        depth = Math.max(0, depth - 1);
        out.push(`${'    '.repeat(depth)}end`);
        continue;
      }
      if (/^next$/i.test(t)) {
        depth = Math.max(0, depth - 1);
        out.push(`${'    '.repeat(depth)}next`);
        continue;
      }
      if (/^config\s+/i.test(t)) {
        out.push(`${'    '.repeat(depth)}${t}`);
        depth++;
        continue;
      }
      if (/^edit\s+/i.test(t)) {
        out.push(`${'    '.repeat(depth)}${t}`);
        depth++;
        continue;
      }
      out.push(`${'    '.repeat(depth)}${t}`);
    }
    return out.join('\n');
  }

  // 2. Flat set-command or slash-command vendors (Junos, PAN-OS, VyOS, Check Point Gaia, MikroTik)
  const isFlatSetOrSlash =
    nonEmpty.every(
      (l) => l.startsWith('#') || l.startsWith('!') || /^set\s+/i.test(l) || l.startsWith('/')
    );
  if (isFlatSetOrSlash) {
    return lines
      .map((l) => l.trim())
      .filter(Boolean)
      .join('\n');
  }

  // 3. Cisco-style hierarchical CLI (IOS-XE, NX-OS, IOS-XR, Arista EOS, Aruba AOS-CX, Forcepoint FRR)
  const out: string[] = [];
  let inSection = false;
  let inSubSection = false;
  for (const rawLine of lines) {
    const t = rawLine.trim();
    if (!t) continue;
    if (t === '!') {
      inSection = false;
      inSubSection = false;
      if (out[out.length - 1] !== '!') out.push('!');
      continue;
    }
    if (t.startsWith('!')) {
      out.push(inSection ? ` ${t}` : t);
      continue;
    }
    if (
      /^(?:interface\s+|router\s+|vrf\s+(?:definition|context)\s+|ip\s+vrf\s+(?!forwarding)|route-map\s+|vpc\s+domain\s+|mlag\s+configuration|segment-routing\s+mpls)/i.test(
        t
      )
    ) {
      inSection = true;
      inSubSection = false;
      out.push(t);
      continue;
    }
    if (/^(?:exit-address-family|exit)$/i.test(t)) {
      if (inSubSection) {
        out.push(` ${t}`);
        inSubSection = false;
      } else {
        out.push(t);
        inSection = false;
      }
      continue;
    }
    if (inSection && (/^address-family\s+/i.test(t) || /^neighbor\s+\d+\.\d+\.\d+\.\d+$/i.test(t))) {
      out.push(` ${t}`);
      inSubSection = true;
      continue;
    }
    if (
      /^(?:hostname\s+|version\s+|ip\s+(?:route|prefix-list|access-list|multicast-routing|pim\s+rp-address|routing)|ipv6\s+(?:unicast-routing|route)|spanning-tree\s+|lldp\s+run|mpls\s+|track\s+|vrf-leak\s+|feature\s+|bmp\s+|ntp\s+|ptp\s+)/i.test(
        t
      )
    ) {
      inSection = false;
      inSubSection = false;
      out.push(t);
      continue;
    }
    if (inSubSection) out.push(`  ${t}`);
    else if (inSection) out.push(` ${t}`);
    else out.push(t);
  }
  return out.join('\n');
}

function parsePanOsSetConfig(lines: string[]): NodeConfig {
  let hostname = 'PAN-IMPORTED';
  let routerId = '10.250.0.1';
  const vrfs = new Set<string>(['default']);
  const ifaceMap = new Map<string, { cidr: string; vrf: string; ospfArea?: number; passive?: boolean }>();
  const staticRoutes: NodeConfig['staticRoutes'] = [];
  let ospfEnabled = false;
  let bgpEnabled = false;
  let bgpAsn = 65000;
  const bgpPeers: NodeConfig['bgp']['peers'] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!/^set\s+/i.test(line)) continue;

    const hostMatch = line.match(/^set\s+deviceconfig\s+system\s+hostname\s+"?([^"\s]+)"?/i);
    if (hostMatch) {
      hostname = hostMatch[1];
      continue;
    }

    const ifIpMatch = line.match(
      /^set\s+network\s+interface\s+\S+\s+"?([^"\s]+)"?\s+layer3\s+ip\s+"?(\d+\.\d+\.\d+\.\d+\/\d+)"?/i
    );
    if (ifIpMatch) {
      const name = ifIpMatch[1];
      const existing = ifaceMap.get(name) ?? { cidr: ifIpMatch[2], vrf: 'default' };
      existing.cidr = ifIpMatch[2];
      ifaceMap.set(name, existing);
      continue;
    }

    const vrIfMatch = line.match(
      /^set\s+network\s+virtual-router\s+"?([^"\s]+)"?\s+interface\s+"?([^"\s]+)"?/i
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
      /^set\s+network\s+virtual-router\s+"?([^"\s]+)"?\s+routing-table\s+ip\s+static-route\s+\S+\s+destination\s+(\S+)\s+nexthop\s+ip-address\s+(\d+\.\d+\.\d+\.\d+)/i
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

    const ospfIfMatch = line.match(
      /^set\s+network\s+virtual-router\s+"?([^"\s]+)"?\s+protocol\s+ospf\s+area\s+(\S+)\s+interface\s+"?([^"\s]+)"?(?:\s+passive\s+(?:enable\s+)?(yes|no))?/i
    );
    if (ospfIfMatch) {
      vrfs.add(ospfIfMatch[1]);
      ospfEnabled = true;
      const areaRaw = ospfIfMatch[2];
      const areaNum = areaRaw.includes('.') ? Number(areaRaw.split('.').pop()) : Number(areaRaw);
      const cur = ifaceMap.get(ospfIfMatch[3]) ?? { cidr: '0.0.0.0/0', vrf: ospfIfMatch[1] };
      if (Number.isFinite(areaNum)) cur.ospfArea = areaNum;
      if (ospfIfMatch[4]) cur.passive = ospfIfMatch[4].toLowerCase() === 'yes';
      ifaceMap.set(ospfIfMatch[3], cur);
      continue;
    }

    const ospfMatch = line.match(
      /^set\s+network\s+virtual-router\s+"?([^"\s]+)"?\s+protocol\s+ospf\s+.*router-id\s+(\d+\.\d+\.\d+\.\d+)/i
    );
    if (ospfMatch) {
      vrfs.add(ospfMatch[1]);
      ospfEnabled = true;
      routerId = ospfMatch[2];
      continue;
    }

    const bgpRidMatch = line.match(
      /^set\s+network\s+virtual-router\s+"?([^"\s]+)"?\s+protocol\s+bgp\s+.*router-id\s+(\d+\.\d+\.\d+\.\d+)/i
    );
    if (bgpRidMatch) {
      vrfs.add(bgpRidMatch[1]);
      bgpEnabled = true;
      routerId = bgpRidMatch[2];
      continue;
    }

    const bgpMatch = line.match(
      /^set\s+network\s+virtual-router\s+"?([^"\s]+)"?\s+protocol\s+bgp\s+.*local-as\s+(\d+)/i
    );
    if (bgpMatch) {
      vrfs.add(bgpMatch[1]);
      bgpEnabled = true;
      bgpAsn = Number(bgpMatch[2]);
      continue;
    }

    const bgpPeerMatch = line.match(
      /^set\s+network\s+virtual-router\s+\S+\s+protocol\s+bgp\s+peer-group\s+"?([^"\s]+)"?\s+peer\s+"?([^"\s]+)"?\s+peer-address\s+ip\s+(\d+\.\d+\.\d+\.\d+)/i
    );
    if (bgpPeerMatch) {
      bgpEnabled = true;
      const peerKey = `${bgpPeerMatch[1]}|${bgpPeerMatch[2]}`;
      const existing = bgpPeers.find((p) => p.id === peerKey);
      if (existing) {
        existing.peerIp = bgpPeerMatch[3];
      } else {
        bgpPeers.push({
          id: peerKey,
          peerIp: bgpPeerMatch[3],
          remoteAs: bgpAsn,
        });
      }
      continue;
    }

    const bgpPeerAsMatch = line.match(
      /^set\s+network\s+virtual-router\s+\S+\s+protocol\s+bgp\s+peer-group\s+"?([^"\s]+)"?\s+peer\s+"?([^"\s]+)"?\s+peer-as\s+(\d+)/i
    );
    if (bgpPeerAsMatch) {
      bgpEnabled = true;
      const peerKey = `${bgpPeerAsMatch[1]}|${bgpPeerAsMatch[2]}`;
      const existing = bgpPeers.find((p) => p.id === peerKey);
      if (existing) {
        existing.remoteAs = Number(bgpPeerAsMatch[3]);
      } else {
        bgpPeers.push({
          id: peerKey,
          peerIp: '',
          remoteAs: Number(bgpPeerAsMatch[3]),
        });
      }
    }
  }
  for (let i = bgpPeers.length - 1; i >= 0; i--) {
    if (!bgpPeers[i].peerIp) bgpPeers.splice(i, 1);
    else bgpPeers[i].id = `peer-${Date.now()}-${i}`;
  }

  const interfaces: NodeConfig['interfaces'] = Array.from(ifaceMap.entries()).map(
    ([name, info], i) => ({
      id: `if-${Date.now()}-${i}`,
      name,
      cidr: info.cidr,
      vrf: info.vrf,
      ospfArea: info.ospfArea,
      passive: info.passive,
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
  let ospfDefaultOriginate = false;
  let ospfReferenceBandwidth: number | undefined;
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
  let bgpRpkiRejectInvalid = false;
  let bgpGracefulRestart = false;
  let eigrpEnabled = false;
  let eigrpAsn = 100;
  let eigrpBfd = false;
  let eigrpVariance: number | undefined;
  let eigrpKValues: [number, number, number, number, number] | undefined;
  const eigrpNetworks: NonNullable<NodeConfig['eigrp']>['networks'] = [];
  let isisEnabled = false;
  let isisNet: string | undefined;
  let isisLevel: 'L1' | 'L2' | 'L1-L2' = 'L1-L2';
  let isisBfd = false;
  let isisOverloadBit = false;
  let isisMetricStyle: 'narrow' | 'wide' | undefined;
  let isisMultiTopologyV6 = false;
  const isisSummaries: NonNullable<NodeConfig['isis']>['summaries'] = [];
  const isisLeakL2ToL1: NonNullable<NodeConfig['isis']>['leakL2ToL1'] = [];
  const redistributions: NodeConfig['redistributions'] = [];
  const vrfLeaks: NodeConfig['vrfLeaks'] = [];
  const tracks: NonNullable<NodeConfig['tracks']> = [];
  let ripEnabled = false;
  let ripVersion: 1 | 2 = 2;
  let ripDefaultOriginate = false;
  const ripNetworks: NonNullable<NodeConfig['rip']>['networks'] = [];
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
    | 'rip'
    | 'routemap'
    | 'vpc'
    | 'mlag'
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
  const prefixLists: NodeConfig['prefixLists'] = [];
  const pendingPeerRouteMaps: { peer: BgpPeerConfig; name: string; dir: 'in' | 'out' }[] = [];
  const pendingRouteMapPrefixLists: { entry: NodeConfig['routeMaps'][0]['entries'][0]; name: string }[] = [];
  let vpcConfig: NodeConfig['vpc'] | undefined;
  let mlagConfig: NodeConfig['mlag'] | undefined;
  let pendingMlagPeerLinkName: string | undefined;

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

    if (/^router\s+rip$/i.test(trimmed)) {
      currentSection = 'rip';
      ripEnabled = true;
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
      if (/^ip\s+ospf\s+passive-interface$/i.test(trimmed)) {
        isNxOs = true;
        currentIface.passive = true;
        continue;
      }
      if (/^no\s+ip\s+ospf\s+passive-interface$/i.test(trimmed)) {
        isNxOs = true;
        currentIface.passive = false;
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
      const ifBwMatch = trimmed.match(/^bandwidth\s+(\d+)/i);
      if (ifBwMatch) {
        currentIface.eigrpBw = Number(ifBwMatch[1]);
        continue;
      }
      const ifDelayMatch = trimmed.match(/^delay\s+(\d+)/i);
      if (ifDelayMatch) {
        currentIface.eigrpDelay = Number(ifDelayMatch[1]) * 10;
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
      const mlagIfMatch = trimmed.match(/^mlag\s+(\d+)$/i);
      if (mlagIfMatch) {
        currentIface.mlagId = Number(mlagIfMatch[1]);
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

    if (/^mlag\s+configuration$/i.test(trimmed)) {
      currentSection = 'mlag';
      mlagConfig = mlagConfig ?? { enabled: true, domainId: 'MLAG' };
      mlagConfig.enabled = true;
      continue;
    }

    if (currentSection === 'mlag' && mlagConfig) {
      const domM = trimmed.match(/^domain-id\s+(\S+)/i);
      if (domM) { mlagConfig.domainId = domM[1]; continue; }
      const liM = trimmed.match(/^local-interface\s+(\S+)/i);
      if (liM) { mlagConfig.localInterface = liM[1]; continue; }
      const paM = trimmed.match(/^peer-address\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (paM) { mlagConfig.peerAddress = paM[1]; continue; }
      const plM = trimmed.match(/^peer-link\s+(\S+)/i);
      if (plM) { pendingMlagPeerLinkName = plM[1]; continue; }
      const rdM = trimmed.match(/^reload-delay(?:\s+\S+)?\s+(\d+)/i);
      if (rdM) { mlagConfig.reloadDelay = Number(rdM[1]); continue; }
    }

    const plGlobalMatch = trimmed.match(
      /^ip\s+prefix-list\s+(\S+)(?:\s+seq\s+(\d+))?\s+(permit|deny)\s+(\d+\.\d+\.\d+\.\d+\/\d+)(?:\s+ge\s+(\d+))?(?:\s+le\s+(\d+))?/i
    );
    if (plGlobalMatch) {
      let pl = prefixLists.find((p) => p.name === plGlobalMatch[1]);
      if (!pl) {
        pl = { id: `pl-${Date.now()}-${prefixLists.length}`, name: plGlobalMatch[1], entries: [] };
        prefixLists.push(pl);
      }
      pl.entries.push({
        id: `ple-${Date.now()}-${pl.entries.length}`,
        seq: plGlobalMatch[2] ? Number(plGlobalMatch[2]) : (pl.entries.length + 1) * 10,
        action: plGlobalMatch[3].toLowerCase() as 'permit' | 'deny',
        prefix: plGlobalMatch[4],
        ...(plGlobalMatch[5] ? { ge: Number(plGlobalMatch[5]) } : {}),
        ...(plGlobalMatch[6] ? { le: Number(plGlobalMatch[6]) } : {}),
      });
      continue;
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
      const mpl = trimmed.match(/^match\s+ip\s+address\s+prefix-list\s+(\S+)/i);
      if (mpl) { pendingRouteMapPrefixLists.push({ entry: currentRouteMapEntry, name: mpl[1] }); continue; }
      const mc = trimmed.match(/^match\s+community\s+(\S+)/i);
      if (mc) { currentRouteMapEntry.matchCommunity = mc[1]; continue; }
      const ma = trimmed.match(/^match\s+as-path\s+(.+)/i);
      if (ma) { currentRouteMapEntry.matchAsPathRegex = ma[1].trim(); continue; }
      const mt = trimmed.match(/^match\s+tag\s+(\d+)/i);
      if (mt) { currentRouteMapEntry.matchTag = Number(mt[1]); continue; }
      const sc = trimmed.match(/^set\s+community\s+(.+)/i);
      if (sc) { currentRouteMapEntry.set.setCommunity = sc[1].trim(); continue; }
      const st = trimmed.match(/^set\s+tag\s+(\d+)/i);
      if (st) { currentRouteMapEntry.set.setTag = Number(st[1]); continue; }
      const slp = trimmed.match(/^set\s+local-preference\s+(\d+)/i);
      if (slp) { currentRouteMapEntry.set.setLocalPref = Number(slp[1]); continue; }
      const smed = trimmed.match(/^set\s+metric\s+(\d+)/i);
      if (smed) { currentRouteMapEntry.set.setMed = Number(smed[1]); continue; }
      const sasp = trimmed.match(/^set\s+as-path\s+prepend\s+(.+)/i);
      if (sasp) {
        const asns = sasp[1].trim().split(/\s+/).map(Number).filter((n) => Number.isFinite(n) && n > 0);
        if (asns.length) currentRouteMapEntry.set.prependAsPath = asns;
        continue;
      }
      const sad = trimmed.match(/^set\s+distance\s+(\d+)/i);
      if (sad) { currentRouteMapEntry.set.setAd = Number(sad[1]); continue; }
    }

    if (
      currentSection === 'ospf' ||
      currentSection === 'eigrp' ||
      currentSection === 'isis' ||
      currentSection === 'rip'
    ) {
      if (/^passive-interface\s+default$/i.test(trimmed)) {
        for (const iface of interfaces) {
          iface.passive = true;
        }
        continue;
      }
      const noPassiveMatch = trimmed.match(/^no\s+passive-interface\s+(\S+)/i);
      if (noPassiveMatch) {
        const target = interfaces.find((i) => i.name.toLowerCase() === noPassiveMatch[1].toLowerCase());
        if (target) target.passive = false;
        continue;
      }
      const passiveIfMatch = trimmed.match(/^passive-interface\s+(\S+)/i);
      if (passiveIfMatch) {
        const target = interfaces.find((i) => i.name.toLowerCase() === passiveIfMatch[1].toLowerCase());
        if (target) target.passive = true;
        continue;
      }
    }

    if (currentSection === 'rip') {
      const verMatch = trimmed.match(/^version\s+(1|2)$/i);
      if (verMatch) {
        ripVersion = Number(verMatch[1]) as 1 | 2;
        continue;
      }
      if (/^default-information\s+originate$/i.test(trimmed)) {
        ripDefaultOriginate = true;
        continue;
      }
      const ripNetMatch = trimmed.match(/^network\s+(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?/i);
      if (ripNetMatch) {
        ripNetworks.push({
          id: `rip-${Date.now()}-${ripNetworks.length}`,
          prefix: ripNetMatch[2] ? `${ripNetMatch[1]}/${ripNetMatch[2]}` : `${ripNetMatch[1]}/24`,
        });
        continue;
      }
      const ripRedMatch = trimmed.match(/^redistribute\s+(connected|static|ospf|eigrp|isis|rip|bgp)(?:\s+\d+)?(?:\s+metric\s+(\d+))?/i);
      if (ripRedMatch) {
        redistributions.push({
          id: `red-${Date.now()}-${redistributions.length}`,
          from: ripRedMatch[1].toLowerCase() as NodeConfig['redistributions'][number]['from'],
          to: 'rip',
          metric: ripRedMatch[2] ? Number(ripRedMatch[2]) : undefined,
        });
        continue;
      }
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
      if (/^default-information\s+originate$/i.test(trimmed)) {
        ospfDefaultOriginate = true;
        continue;
      }
      const refBwMatch = trimmed.match(/^auto-cost\s+reference-bandwidth\s+(\d+)/i);
      if (refBwMatch) {
        ospfReferenceBandwidth = Number(refBwMatch[1]);
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
      const ospfRedMatch = trimmed.match(/^redistribute\s+(connected|static|ospf|eigrp|isis|rip|bgp)(?:\s+\d+)?(?:\s+metric\s+(\d+))?(?:\s+metric-type\s+(1|2))?/i);
      if (ospfRedMatch) {
        redistributions.push({
          id: `red-${Date.now()}-${redistributions.length}`,
          vrf: currentOspfVrf !== 'default' ? currentOspfVrf : undefined,
          from: ospfRedMatch[1].toLowerCase() as NodeConfig['redistributions'][number]['from'],
          to: 'ospf',
          metric: ospfRedMatch[2] ? Number(ospfRedMatch[2]) : undefined,
          metricType: ospfRedMatch[3] === '1' ? 'E1' : ospfRedMatch[3] === '2' ? 'E2' : undefined,
        });
        continue;
      }
    }

    if (currentSection === 'eigrp') {
      if (/^bfd\s+all-interfaces$/i.test(trimmed)) {
        eigrpBfd = true;
        continue;
      }
      const eigrpRidMatch = trimmed.match(/^eigrp\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (eigrpRidMatch) {
        routerId = eigrpRidMatch[1];
        continue;
      }
      const varMatch = trimmed.match(/^variance\s+(\d+)/i);
      if (varMatch) {
        eigrpVariance = Number(varMatch[1]);
        continue;
      }
      const kwMatch = trimmed.match(/^metric\s+weights\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/i);
      if (kwMatch) {
        eigrpKValues = [Number(kwMatch[1]), Number(kwMatch[2]), Number(kwMatch[3]), Number(kwMatch[4]), Number(kwMatch[5])];
        continue;
      }
      const eigrpNetMatch = trimmed.match(/^network\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+\.\d+\.\d+\.\d+))?/i);
      if (eigrpNetMatch) {
        eigrpNetworks.push({
          id: `en-${Date.now()}-${eigrpNetworks.length}`,
          prefix: eigrpNetMatch[2] ? `${eigrpNetMatch[1]}/${wildcardToPrefixLen(eigrpNetMatch[2])}` : `${eigrpNetMatch[1]}/24`,
        });
        continue;
      }
      const eigrpRedMatch = trimmed.match(/^redistribute\s+(connected|static|ospf|eigrp|isis|rip|bgp)(?:\s+\d+)?(?:\s+metric\s+(\d+))?/i);
      if (eigrpRedMatch) {
        redistributions.push({
          id: `red-${Date.now()}-${redistributions.length}`,
          from: eigrpRedMatch[1].toLowerCase() as NodeConfig['redistributions'][number]['from'],
          to: 'eigrp',
          metric: eigrpRedMatch[2] ? Number(eigrpRedMatch[2]) : undefined,
        });
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
      const isisSumMatch = trimmed.match(/^summary-address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (isisSumMatch) {
        isisSummaries.push({
          id: `isum-${Date.now()}-${isisSummaries.length}`,
          prefix: `${isisSumMatch[1]}/${maskToPrefixLen(isisSumMatch[2])}`,
        });
        continue;
      }
      const isisLeakMatch = trimmed.match(/^redistribute\s+isis\s+ip\s+level-2\s+into\s+level-1\s+prefix\s+(\S+)/i);
      if (isisLeakMatch) {
        isisLeakL2ToL1.push({
          id: `ileak-${Date.now()}-${isisLeakL2ToL1.length}`,
          prefix: isisLeakMatch[1],
        });
        continue;
      }
      const isisRedMatch = trimmed.match(/^redistribute\s+(connected|static|ospf|eigrp|isis|rip|bgp)(?:\s+\d+)?(?:\s+metric\s+(\d+))?/i);
      if (isisRedMatch) {
        redistributions.push({
          id: `red-${Date.now()}-${redistributions.length}`,
          from: isisRedMatch[1].toLowerCase() as NodeConfig['redistributions'][number]['from'],
          to: 'isis',
          metric: isisRedMatch[2] ? Number(isisRedMatch[2]) : undefined,
        });
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
      if (/^bgp\s+rpki\s+reject-invalid$/i.test(trimmed)) { bgpRpkiRejectInvalid = true; continue; }
      if (/^bgp\s+graceful-restart$/i.test(trimmed)) { bgpGracefulRestart = true; continue; }
      const bgpRedMatch = trimmed.match(/^redistribute\s+(connected|static|ospf|eigrp|isis|rip|bgp)(?:\s+\d+)?(?:\s+metric\s+(\d+))?/i);
      if (bgpRedMatch) {
        redistributions.push({
          id: `red-${Date.now()}-${redistributions.length}`,
          vrf: currentBgpVrf !== 'default' ? currentBgpVrf : undefined,
          from: bgpRedMatch[1].toLowerCase() as NodeConfig['redistributions'][number]['from'],
          to: 'bgp',
          metric: bgpRedMatch[2] ? Number(bgpRedMatch[2]) : undefined,
        });
        continue;
      }
      const findBgpPeer = (ip: string) =>
        bgpPeers.find((p) => p.peerIp === ip && (p.vrf || 'default') === currentBgpVrf) ??
        bgpPeers.find((p) => p.peerIp === ip);
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
        if (/^fall-over\s+bfd$/i.test(trimmed)) { currentBgpPeer.bfd = true; continue; }
        if (/^graceful-restart$/i.test(trimmed)) { currentBgpPeer.gracefulRestart = true; continue; }
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
        const peer = findBgpPeer(multihopMatch[1]);
        if (peer) peer.ebgpMultihop = true;
        continue;
      }
      if (/^neighbor\s+\d+\.\d+\.\d+\.\d+\s+next-hop-self$/i.test(trimmed)) {
        const ip = trimmed.split(/\s+/)[1];
        const peer = findBgpPeer(ip);
        if (peer) peer.nextHopSelf = true;
        continue;
      }
      if (/^neighbor\s+\d+\.\d+\.\d+\.\d+\s+default-originate$/i.test(trimmed)) {
        const ip = trimmed.split(/\s+/)[1];
        const peer = findBgpPeer(ip);
        if (peer) peer.defaultOriginate = true;
        continue;
      }
      if (/^neighbor\s+\d+\.\d+\.\d+\.\d+\s+route-reflector-client$/i.test(trimmed)) {
        const ip = trimmed.split(/\s+/)[1];
        const peer = findBgpPeer(ip);
        if (peer) peer.routeReflectorClient = true;
        continue;
      }
      const weightMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+weight\s+(\d+)/i);
      if (weightMatch) {
        const peer = findBgpPeer(weightMatch[1]);
        if (peer) peer.weight = Number(weightMatch[2]);
        continue;
      }
      const rmNbrMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+route-map\s+(\S+)\s+(in|out)$/i);
      if (rmNbrMatch) {
        const peer = findBgpPeer(rmNbrMatch[1]);
        if (peer) {
          pendingPeerRouteMaps.push({
            peer,
            name: rmNbrMatch[2],
            dir: rmNbrMatch[3].toLowerCase() as 'in' | 'out',
          });
        }
        continue;
      }
      const bfdMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+fall-over\s+bfd/i);
      if (bfdMatch) {
        const peer = findBgpPeer(bfdMatch[1]);
        if (peer) peer.bfd = true;
        continue;
      }
      const softReconfigMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+soft-reconfiguration\s+inbound/i);
      if (softReconfigMatch) {
        const peer = findBgpPeer(softReconfigMatch[1]);
        if (peer) peer.softReconfigurationInbound = true;
        continue;
      }
      const grNbrMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+graceful-restart/i);
      if (grNbrMatch) {
        const peer = findBgpPeer(grNbrMatch[1]);
        if (peer) peer.gracefulRestart = true;
        continue;
      }
      const timersMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+timers\s+(\d+)\s+(\d+)/i);
      if (timersMatch) {
        const peer = findBgpPeer(timersMatch[1]);
        if (peer) {
          peer.keepaliveTime = Number(timersMatch[2]);
          peer.holdTime = Number(timersMatch[3]);
        }
        continue;
      }
      const shutNbrMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+shutdown$/i);
      if (shutNbrMatch) {
        const peer = findBgpPeer(shutNbrMatch[1]);
        if (peer) peer.shutdown = true;
        continue;
      }
      const updSrcMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+update-source\s+(\S+)/i);
      if (updSrcMatch) {
        const peer = findBgpPeer(updSrcMatch[1]);
        if (peer) peer.updateSource = updSrcMatch[2];
        continue;
      }
      const allowAsMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+allowas-in/i);
      if (allowAsMatch) {
        const peer = findBgpPeer(allowAsMatch[1]);
        if (peer) peer.allowAsIn = true;
        continue;
      }
      const asOvMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+as-override/i);
      if (asOvMatch) {
        const peer = findBgpPeer(asOvMatch[1]);
        if (peer) peer.asOverride = true;
        continue;
      }
      const sendCommMatch = trimmed.match(
        /^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+send-community(?:\s+(standard|extended|both))?/i
      );
      if (sendCommMatch) {
        const peer = findBgpPeer(sendCommMatch[1]);
        if (peer) {
          peer.sendCommunity =
            (sendCommMatch[2]?.toLowerCase() as 'standard' | 'extended' | 'both') ?? 'standard';
        }
        continue;
      }
      const remPrivMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remove-private-as/i);
      if (remPrivMatch) {
        const peer = findBgpPeer(remPrivMatch[1]);
        if (peer) peer.removePrivateAs = true;
        continue;
      }
      const maxPrefMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+maximum-prefix\s+(\d+)/i);
      if (maxPrefMatch) {
        const peer = findBgpPeer(maxPrefMatch[1]);
        if (peer) peer.maxPrefixes = Number(maxPrefMatch[2]);
        continue;
      }
      const localAsMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+local-as\s+(\d+)(\s+no-prepend)?(\s+replace-as)?/i);
      if (localAsMatch) {
        const peer = findBgpPeer(localAsMatch[1]);
        if (peer) {
          peer.localAs = Number(localAsMatch[2]);
          if (localAsMatch[3]) peer.localAsNoPrepend = true;
          if (localAsMatch[4]) peer.localAsReplaceAs = true;
        }
        continue;
      }
      const addPathMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+add-path\s+(send|receive|both)/i);
      if (addPathMatch) {
        const peer = findBgpPeer(addPathMatch[1]);
        if (peer) peer.addPath = addPathMatch[2].toLowerCase() as 'send' | 'receive' | 'both';
        continue;
      }
      const dccMatch = trimmed.match(/^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+disable-connected-check/i);
      if (dccMatch) {
        const peer = findBgpPeer(dccMatch[1]);
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
          vrf: currentBgpVrf !== 'default' ? currentBgpVrf : undefined,
          prefix: `${aggMatch[1]}/${maskToPrefixLen(aggMatch[2])}`,
          summaryOnly: tail.includes('summary-only'),
          asSet: tail.includes('as-set') || undefined,
        });
        continue;
      }
    }

    const trackObjMatch = trimmed.match(/^track\s+(\S+)\s+ip\s+route\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (trackObjMatch) {
      tracks.push({ id: trackObjMatch[1], targetIp: trackObjMatch[2] });
      continue;
    }
    const vrfLeakMatch = trimmed.match(/^vrf-leak\s+(\S+)\s+to\s+(\S+)/i);
    if (vrfLeakMatch) {
      vrfs.add(vrfLeakMatch[1]);
      vrfs.add(vrfLeakMatch[2]);
      vrfLeaks.push({
        id: `vl-${Date.now()}-${vrfLeaks.length}`,
        fromVrf: vrfLeakMatch[1],
        toVrf: vrfLeakMatch[2],
      });
      continue;
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
    const ptpMatch = trimmed.match(/^ptp\s+mode\s+(boundary|grandmaster|transparent)(?:\s+domain\s+(\d+))?/i);
    if (ptpMatch) {
      timingConfig = {
        ...timingConfig,
        ptpMode: ptpMatch[1].toLowerCase() as 'boundary' | 'grandmaster' | 'transparent',
        ...(ptpMatch[2] ? { ptpDomain: Number(ptpMatch[2]) } : {}),
      };
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

    const parseStaticTail = (tail: string) => {
      const trackM = tail.match(/\btrack\s+(\S+)/i);
      const tagM = tail.match(/\btag\s+(\d+)/i);
      const stripped = tail
        .replace(/\btrack\s+\S+/gi, '')
        .replace(/\btag\s+\d+/gi, '')
        .replace(/\bglobal\b/gi, '')
        .trim();
      const adM = stripped.match(/^(\d+)\b/);
      return {
        ad: adM ? Number(adM[1]) : undefined,
        trackId: trackM ? trackM[1] : undefined,
        tag: tagM ? Number(tagM[1]) : undefined,
      };
    };

    const staticVrfMatch = trimmed.match(
      /^ip\s+route\s+vrf\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(.*)$/i
    );
    if (staticVrfMatch) {
      vrfs.add(staticVrfMatch[1]);
      const tail = staticVrfMatch[5] ?? '';
      const opts = parseStaticTail(tail);
      staticRoutes.push({
        id: `sr-${Date.now()}-${staticRoutes.length}`,
        vrf: staticVrfMatch[1],
        prefix: `${staticVrfMatch[2]}/${maskToPrefixLen(staticVrfMatch[3])}`,
        nextHop: staticVrfMatch[4],
        globalNextHop: /\bglobal\b/i.test(tail) || undefined,
        ad: opts.ad,
        trackId: opts.trackId,
        tag: opts.tag,
      });
      continue;
    }

    const staticCidrMatch = trimmed.match(
      /^ip\s+route\s+(\d+\.\d+\.\d+\.\d+\/\d+)\s+(\d+\.\d+\.\d+\.\d+)(.*)$/i
    );
    if (staticCidrMatch) {
      const opts = parseStaticTail(staticCidrMatch[3] ?? '');
      staticRoutes.push({
        id: `sr-${Date.now()}-${staticRoutes.length}`,
        vrf: 'default',
        prefix: staticCidrMatch[1],
        nextHop: staticCidrMatch[2],
        ad: opts.ad,
        trackId: opts.trackId,
        tag: opts.tag,
      });
      continue;
    }

    const staticMatch = trimmed.match(
      /^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(.*)$/i
    );
    if (staticMatch) {
      const opts = parseStaticTail(staticMatch[4] ?? '');
      staticRoutes.push({
        id: `sr-${Date.now()}-${staticRoutes.length}`,
        vrf: 'default',
        prefix: `${staticMatch[1]}/${maskToPrefixLen(staticMatch[2])}`,
        nextHop: staticMatch[3],
        ad: opts.ad,
        trackId: opts.trackId,
        tag: opts.tag,
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

  for (const pending of pendingPeerRouteMaps) {
    const rm = routeMaps.find((m) => m.name === pending.name);
    if (rm) {
      if (pending.dir === 'in') pending.peer.routeMapInId = rm.id;
      else pending.peer.routeMapOutId = rm.id;
    }
  }
  for (const pendingPl of pendingRouteMapPrefixLists) {
    const pl = prefixLists.find((p) => p.name === pendingPl.name);
    if (pl) pendingPl.entry.matchPrefixListId = pl.id;
  }
  if (mlagConfig && pendingMlagPeerLinkName) {
    const plIface = interfaces.find(
      (i) => i.name.toLowerCase() === pendingMlagPeerLinkName!.toLowerCase()
    );
    if (plIface) mlagConfig.peerLinkInterfaceId = plIface.id;
  }

  const validInterfaces = interfaces
    .filter(
      (i) =>
        i.cidr !== '0.0.0.0/0' ||
        Boolean(i.cidr6) ||
        Boolean(i.unnumberedSource) ||
        i.lacpGroup !== undefined ||
        i.mlagId !== undefined ||
        i.vpcId !== undefined ||
        i.id === vpcConfig?.peerLinkInterfaceId ||
        i.id === mlagConfig?.peerLinkInterfaceId ||
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

  const isForcepoint = lines.some((l) => /forcepoint|stonegate|\bvtysh\b|frr\s+version/i.test(l));
  const detectedArista =
    Boolean(mlagConfig) ||
    interfaces.some((i) => i.mlagId !== undefined) ||
    lines.some((l) => /^mlag\s+configuration\b|arista|\beos\b/i.test(l.trim()));
  const detectedNxOs = isNxOs || Boolean(vpcConfig) || lines.some((l) => /feature\s+vpc|nx-os|n9k/i.test(l));

  return {
    id: `imp-${Date.now()}-${++importIdSeq}`,
    hostname,
    vendor: isForcepoint
      ? 'forcepoint-ngfw'
      : detectedArista
        ? 'arista-eos'
        : detectedNxOs
          ? 'cisco-nx-os'
          : 'cisco-ios-xe',
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
      defaultOriginate: ospfDefaultOriginate || undefined,
      referenceBandwidth: ospfReferenceBandwidth,
      bfd: ospfBfd || undefined,
      maxMetricRouterLsa: ospfMaxMetricRouterLsa || undefined,
      areaTypes: Object.keys(ospfAreaTypes).length ? ospfAreaTypes : undefined,
      nssaNoSummary: Object.keys(ospfNssaNoSummary).length ? ospfNssaNoSummary : undefined,
      areaRanges: ospfAreaRanges.length ? ospfAreaRanges : undefined,
      virtualLinks: ospfVirtualLinks.length ? ospfVirtualLinks : undefined,
      networks: ospfNetworks,
    },
    eigrp: eigrpEnabled ? { enabled: true, asn: eigrpAsn, bfd: eigrpBfd || undefined, variance: eigrpVariance, kValues: eigrpKValues, networks: eigrpNetworks } : undefined,
    isis: isisEnabled ? { enabled: true, net: isisNet, bfd: isisBfd || undefined, overloadBit: isisOverloadBit || undefined, metricStyle: isisMetricStyle, multiTopologyV6: isisMultiTopologyV6 || undefined, level: isisLevel, summaries: isisSummaries.length ? isisSummaries : undefined, leakL2ToL1: isisLeakL2ToL1.length ? isisLeakL2ToL1 : undefined, networks: [] } : undefined,
    rip: ripEnabled ? { enabled: true, version: ripVersion, defaultOriginate: ripDefaultOriginate || undefined, networks: ripNetworks } : undefined,
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
      rpkiRejectInvalid: bgpRpkiRejectInvalid || undefined,
      gracefulRestart: bgpGracefulRestart || undefined,
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
    redistributions,
    prefixLists,
    routeMaps,
    vrfLeaks,
    tracks: tracks.length ? tracks : undefined,
    mplsVpn: mplsVrfTargets.length ? { enabled: true, vrfTargets: mplsVrfTargets } : undefined,
    mpls: mplsConfig,
    switching: switchingConfig,
    multicast: multicastConfig,
    timing: timingConfig,
    telemetry: telemetryConfig,
    evpn: evpnConfig,
    fhrpGroups: fhrpGroups.length ? fhrpGroups : undefined,
    vpc: vpcConfig,
    mlag: mlagConfig,
  };
}

function parseFortigateConfig(lines: string[]): NodeConfig {
  let hostname = 'FGT-IMPORTED';
  const routerId = '10.255.0.10';
  const vrfs = new Set<string>(['default']);
  const interfaces: InterfaceConfig[] = [];
  const staticRoutes: StaticRouteConfig[] = [];
  const pbrRules: NonNullable<NodeConfig['pbrRules']> = [];
  const pendingPassiveIfs = new Set<string>();
  let ospfEnabled = false;
  let ospfRouterId = '';
  let ripEnabled = false;
  let bgpEnabled = false;
  let bgpAsn = 65000;
  let bgpRouterId = routerId;
  const bgpPeers: BgpPeerConfig[] = [];

  let block = '';
  let subBlock = '';
  let nestedUnknownDepth = 0;
  let curIf: InterfaceConfig | null = null;
  let curStatic: Partial<StaticRouteConfig> | null = null;
  let curPbr: Partial<NonNullable<NodeConfig['pbrRules']>[number]> | null = null;
  let curPeer: Partial<BgpPeerConfig> | null = null;

  for (const raw of lines) {
    const t = raw.trim();
    if (!t || t.startsWith('#')) continue;
    if (/^config\s+system\s+global$/i.test(t)) { block = 'global'; nestedUnknownDepth = 0; continue; }
    if (/^config\s+system\s+interface$/i.test(t)) { block = 'interface'; nestedUnknownDepth = 0; continue; }
    if (/^config\s+router\s+static$/i.test(t)) { block = 'static'; nestedUnknownDepth = 0; continue; }
    if (/^config\s+router\s+policy$/i.test(t)) { block = 'policy'; nestedUnknownDepth = 0; continue; }
    if (/^config\s+router\s+ospf$/i.test(t)) { block = 'ospf'; ospfEnabled = true; nestedUnknownDepth = 0; continue; }
    if (/^config\s+router\s+rip$/i.test(t)) { block = 'rip'; ripEnabled = true; nestedUnknownDepth = 0; continue; }
    if (/^config\s+router\s+bgp$/i.test(t)) { block = 'bgp'; bgpEnabled = true; nestedUnknownDepth = 0; continue; }
    if (/^config\s+neighbor$/i.test(t) && block === 'bgp') { subBlock = 'neighbor'; continue; }
    if (/^config\s+/i.test(t) && block) { nestedUnknownDepth++; continue; }
    const flushFortiEntry = () => {
      if (block === 'static' && curStatic?.prefix && curStatic.nextHop) {
        staticRoutes.push({
          id: `sr-${Date.now()}-${staticRoutes.length}`,
          vrf: 'default',
          prefix: curStatic.prefix,
          nextHop: curStatic.nextHop,
          ...(curStatic.ad !== undefined ? { ad: curStatic.ad } : {}),
        });
      }
      if (subBlock === 'neighbor' && curPeer?.peerIp && curPeer.remoteAs) {
        bgpPeers.push({
          id: `bgp-${Date.now()}-${bgpPeers.length}`,
          peerIp: curPeer.peerIp,
          remoteAs: curPeer.remoteAs,
          nextHopSelf: curPeer.nextHopSelf,
          defaultOriginate: curPeer.defaultOriginate,
        });
      }
      if (block === 'policy' && curPbr?.nextHop) {
        pbrRules.push({
          id: `pbr-fgt-${Date.now()}-${pbrRules.length}`,
          name: curPbr.name || `PBR-${pbrRules.length + 1}`,
          srcCidr: curPbr.srcCidr,
          matchPrefix: curPbr.matchPrefix || '0.0.0.0/0',
          nextHop: curPbr.nextHop,
          ingressInterface: curPbr.ingressInterface,
          interfaceName: curPbr.interfaceName,
          protocol: curPbr.protocol,
          dstPort: curPbr.dstPort,
        });
      }
      curIf = null;
      curStatic = null;
      curPbr = null;
      curPeer = null;
    };
    if (/^end$/i.test(t)) {
      if (nestedUnknownDepth > 0) {
        nestedUnknownDepth--;
        continue;
      }
      flushFortiEntry();
      if (subBlock) subBlock = '';
      else block = '';
      continue;
    }
    if (nestedUnknownDepth > 0) continue;
    if (/^next$/i.test(t)) {
      flushFortiEntry();
      continue;
    }

    const editMatch = t.match(/^edit\s+"?([^"]+)"?$/i);
    if (editMatch) {
      const cleanEdit = editMatch[1].trim();
      if (block === 'interface') {
        curIf = { id: `if-${Date.now()}-${interfaces.length}`, name: cleanEdit, cidr: '0.0.0.0/0', vrf: 'default' };
        interfaces.push(curIf);
      } else if (block === 'static') {
        curStatic = {};
      } else if (block === 'policy') {
        curPbr = { name: `PBR-${cleanEdit}`, matchPrefix: '0.0.0.0/0' };
      } else if (subBlock === 'neighbor') {
        curPeer = { peerIp: cleanEdit };
      }
      continue;
    }

    if (block === 'global') {
      const hm = t.match(/^set\s+hostname\s+"?([^"]+)"?/i);
      if (hm) hostname = hm[1].trim();
    } else if (block === 'interface' && curIf) {
      const ipm = t.match(/^set\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (ipm) curIf.cidr = `${ipm[1]}/${maskToPrefixLen(ipm[2])}`;
      const ipCidr = t.match(/^set\s+ip\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      if (ipCidr) curIf.cidr = ipCidr[1];
      const vm = t.match(/^set\s+vrf\s+"?([^"\s]+)"?/i);
      if (vm) { vrfs.add(vm[1]); curIf.vrf = vm[1]; }
    } else if (block === 'static' && curStatic) {
      const dm = t.match(/^set\s+dst\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      if (dm) curStatic.prefix = dm[1];
      const dmMask = t.match(/^set\s+dst\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (dmMask) curStatic.prefix = `${dmMask[1]}/${maskToPrefixLen(dmMask[2])}`;
      const gm = t.match(/^set\s+gateway\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (gm) curStatic.nextHop = gm[1];
      const distM = t.match(/^set\s+distance\s+(\d+)/i);
      if (distM) curStatic.ad = Number(distM[1]);
    } else if (block === 'policy' && curPbr) {
      const inM = t.match(/^set\s+input-device\s+"?([^"\s]+)"?/i);
      if (inM) curPbr.ingressInterface = inM[1];
      const outM = t.match(/^set\s+output-device\s+"?([^"\s]+)"?/i);
      if (outM) curPbr.interfaceName = outM[1];
      const srcCidrM = t.match(/^set\s+src\s+"?(\d+\.\d+\.\d+\.\d+\/\d+)"?/i);
      if (srcCidrM) curPbr.srcCidr = srcCidrM[1];
      const srcMaskM = t.match(/^set\s+src\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (srcMaskM) curPbr.srcCidr = `${srcMaskM[1]}/${maskToPrefixLen(srcMaskM[2])}`;
      const dstCidrM = t.match(/^set\s+dst\s+"?(\d+\.\d+\.\d+\.\d+\/\d+)"?/i);
      if (dstCidrM) curPbr.matchPrefix = dstCidrM[1];
      const dstMaskM = t.match(/^set\s+dst\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (dstMaskM) curPbr.matchPrefix = `${dstMaskM[1]}/${maskToPrefixLen(dstMaskM[2])}`;
      const gwM = t.match(/^set\s+gateway\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (gwM) curPbr.nextHop = gwM[1];
      const protoM = t.match(/^set\s+protocol\s+(\d+)/i);
      if (protoM) {
        const pn = Number(protoM[1]);
        curPbr.protocol = pn === 6 ? 'tcp' : pn === 17 ? 'udp' : pn === 1 ? 'icmp' : 'any';
      }
      const spM = t.match(/^set\s+start-port\s+(\d+)/i);
      if (spM) curPbr.dstPort = Number(spM[1]);
    } else if ((block === 'ospf' || block === 'rip') && !subBlock) {
      const rm = t.match(/^set\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (rm) ospfRouterId = rm[1];
      const pm = t.match(/^set\s+passive-interface\s+(.+)/i);
      if (pm) {
        const names = pm[1].match(/"[^"]+"|\S+/g) ?? [];
        for (const rawName of names) {
          const cleanName = rawName.replace(/^"|"$/g, '').trim().toLowerCase();
          if (cleanName) pendingPassiveIfs.add(cleanName);
        }
      }
    } else if (block === 'bgp' && !subBlock) {
      const am = t.match(/^set\s+as\s+(\d+)/i);
      if (am) bgpAsn = Number(am[1]);
      const rm = t.match(/^set\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (rm) bgpRouterId = rm[1];
    } else if (subBlock === 'neighbor' && curPeer) {
      const ram = t.match(/^set\s+remote-as\s+(\d+)/i);
      if (ram) curPeer.remoteAs = Number(ram[1]);
      if (/^set\s+next-hop-self\s+enable$/i.test(t)) curPeer.nextHopSelf = true;
      if (/^set\s+capability-default-originate\s+enable$/i.test(t)) curPeer.defaultOriginate = true;
    }
  }

  for (const iface of interfaces) {
    if (pendingPassiveIfs.has(iface.name.toLowerCase())) {
      iface.passive = true;
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
    routerId: ospfRouterId || bgpRouterId,
    position: { x: 240, y: 140 },
    maxPaths: 4,
    vrfs: Array.from(vrfs),
    adOverrides: {},
    interfaces: validInterfaces,
    staticRoutes,
    pbrRules: pbrRules.length ? pbrRules : undefined,
    ospf: { enabled: ospfEnabled, networks: [] },
    rip: ripEnabled ? { enabled: true, version: 2, networks: [] } : undefined,
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
  const ifaceMap = new Map<string, { cidr: string; cidr6?: string; vrf: string; ospfArea?: number; isisLevel?: 'L1' | 'L2'; passive?: boolean }>();
  const staticRoutes: StaticRouteConfig[] = [];
  let ospfEnabled = false;
  let isisEnabled = false;
  let ripEnabled = false;
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
      /^set\s+interfaces\s+(\S+?)(?:\.(\d+)|\s+unit\s+(\d+))\s+family\s+inet\s+address\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i
    );
    if (ifV4Match) {
      const unit = ifV4Match[2] ?? ifV4Match[3] ?? '0';
      const ifName = unit === '0' ? ifV4Match[1] : `${ifV4Match[1]}.${unit}`;
      const cur = ifaceMap.get(ifName) ?? { cidr: ifV4Match[4], vrf: 'default' };
      cur.cidr = ifV4Match[4];
      ifaceMap.set(ifName, cur);
      continue;
    }

    const ifV6Match = line.match(
      /^set\s+interfaces\s+(\S+?)(?:\.(\d+)|\s+unit\s+(\d+))\s+family\s+inet6\s+address\s+([0-9a-fA-F:]+\/\d+)/i
    );
    if (ifV6Match) {
      const unit = ifV6Match[2] ?? ifV6Match[3] ?? '0';
      const ifName = unit === '0' ? ifV6Match[1] : `${ifV6Match[1]}.${unit}`;
      const cur = ifaceMap.get(ifName) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      cur.cidr6 = ifV6Match[4];
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
      /^set\s+protocols\s+ospf\s+area\s+(\S+)\s+interface\s+(\S+)(?:\s+(passive))?/i
    );
    if (ospfIfMatch) {
      ospfEnabled = true;
      const areaRaw = ospfIfMatch[1];
      const areaNum = areaRaw.includes('.') ? Number(areaRaw.split('.').pop()) : Number(areaRaw);
      const rawIf = ospfIfMatch[2].replace(/\.0$/, '');
      let cur = ifaceMap.get(rawIf) ?? ifaceMap.get(ospfIfMatch[2]);
      if (!cur) {
        cur = { cidr: '0.0.0.0/0', vrf: 'default' };
        ifaceMap.set(rawIf, cur);
      }
      if (Number.isFinite(areaNum)) cur.ospfArea = areaNum;
      if (ospfIfMatch[3]) cur.passive = true;
      continue;
    }

    const isisIfMatch = line.match(
      /^set\s+protocols\s+isis\s+interface\s+(\S+)(?:\s+(passive))?/i
    );
    if (isisIfMatch) {
      isisEnabled = true;
      const rawIf = isisIfMatch[1].replace(/\.0$/, '');
      let cur = ifaceMap.get(rawIf) ?? ifaceMap.get(isisIfMatch[1]);
      if (!cur) {
        cur = { cidr: '0.0.0.0/0', vrf: 'default' };
        ifaceMap.set(rawIf, cur);
      }
      cur.isisLevel = cur.isisLevel ?? 'L2';
      if (isisIfMatch[2]) cur.passive = true;
      continue;
    }

    const ripIfMatch = line.match(
      /^set\s+protocols\s+rip\s+group\s+\S+\s+neighbor\s+(\S+)(?:\s+(passive))?/i
    );
    if (ripIfMatch) {
      ripEnabled = true;
      const rawIf = ripIfMatch[1].replace(/\.0$/, '');
      let cur = ifaceMap.get(rawIf) ?? ifaceMap.get(ripIfMatch[1]);
      if (!cur) {
        cur = { cidr: '0.0.0.0/0', vrf: 'default' };
        ifaceMap.set(rawIf, cur);
      }
      if (ripIfMatch[2]) cur.passive = true;
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
      if (existing) {
        if (bgpPeerMatch[2]) existing.remoteAs = Number(bgpPeerMatch[2]);
      } else {
        const remoteAs = bgpPeerMatch[2] ? Number(bgpPeerMatch[2]) : bgpAsn;
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
      isisLevel: info.isisLevel,
      passive: info.passive,
    })),
    staticRoutes,
    ospf: { enabled: ospfEnabled, networks: [] },
    isis: isisEnabled ? { enabled: true, level: 'L1-L2', networks: [] } : undefined,
    rip: ripEnabled ? { enabled: true, version: 2, networks: [] } : undefined,
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
  const ifaceMap = new Map<string, { cidr: string; cidr6?: string; vrf: string; ospfArea?: number; isisLevel?: 'L1' | 'L2'; passive?: boolean }>();
  const staticRoutes: StaticRouteConfig[] = [];
  let ospfEnabled = false;
  let bgpEnabled = false;
  let bgpAsn = 65000;
  const bgpPeers: BgpPeerConfig[] = [];
  const ospfAreas = new Map<string, number>();

  for (const raw of lines) {
    const line = raw.trim().replace(/\s*=\s*/g, '=');
    if (!line || line.startsWith('#')) continue;

    if (/^\/system\s+identity\s+set\b/i.test(line)) {
      const m = line.match(/name="?([^"\s]+)"?/i);
      if (m) hostname = m[1];
      continue;
    }

    if (/^\/ip\s+vrf\s+add\b/i.test(line)) {
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

    if (/^\/ip\s+address\s+add\b/i.test(line)) {
      const addr = line.match(/address=(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      const ifm = line.match(/interface="?([^"\s]+)"?/i);
      if (addr && ifm) {
        const cur = ifaceMap.get(ifm[1]) ?? { cidr: addr[1], vrf: 'default' };
        cur.cidr = addr[1];
        ifaceMap.set(ifm[1], cur);
      }
      continue;
    }

    if (/^\/ipv6\s+address\s+add\b/i.test(line)) {
      const addr6 = line.match(/address=([0-9a-fA-F:]+\/\d+)/i);
      const ifm = line.match(/interface="?([^"\s]+)"?/i);
      if (addr6 && ifm) {
        const cur = ifaceMap.get(ifm[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
        cur.cidr6 = addr6[1];
        ifaceMap.set(ifm[1], cur);
      }
      continue;
    }

    if (/^\/ip\s+route\s+add\b/i.test(line)) {
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

    if (/^\/routing\s+ospf\s+instance\b/i.test(line)) {
      ospfEnabled = true;
      const rid = line.match(/router-id=(\d+\.\d+\.\d+\.\d+)/i);
      if (rid) routerId = rid[1];
      continue;
    }

    if (/^\/routing\s+ospf\s+area\s+add\b/i.test(line)) {
      ospfEnabled = true;
      const nm = line.match(/name="?([^"\s]+)"?/i);
      const aid = line.match(/area-id=(\S+)/i);
      if (nm && aid) {
        const areaNum = aid[1].includes('.') ? Number(aid[1].split('.').pop()) : Number(aid[1]);
        if (Number.isFinite(areaNum)) ospfAreas.set(nm[1], areaNum);
      }
      continue;
    }

    if (/^\/routing\s+ospf\s+interface-template\s+add\b/i.test(line)) {
      ospfEnabled = true;
      const areaM = line.match(/area="?([^"\s]+)"?/i);
      const ifM = line.match(/interfaces=(?:"([^"]+)"|([^\s]+))/i);
      const ifRaw = ifM ? (ifM[1] ?? ifM[2]) : undefined;
      const isPassive = /\bpassive=(?:yes|true)\b/i.test(line) || /\bpassive\b(?!\s*=)/i.test(line);
      const areaNum = areaM ? (ospfAreas.get(areaM[1]) ?? (Number(areaM[1]) || 0)) : 0;
      if (ifRaw) {
        for (const rawName of ifRaw.split(',')) {
          const ifName = rawName.trim();
          if (!ifName) continue;
          let cur = ifaceMap.get(ifName);
          if (!cur) {
            cur = { cidr: '0.0.0.0/0', vrf: 'default' };
            ifaceMap.set(ifName, cur);
          }
          cur.ospfArea = areaNum;
          if (isPassive) cur.passive = true;
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
      passive: info.passive,
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

function parseVyosConfig(lines: string[]): NodeConfig {
  let hostname = 'VYOS-IMPORTED';
  let routerId = '10.255.0.40';
  const vrfs = new Set<string>(['default']);
  const ifaceMap = new Map<string, { cidr: string; cidr6?: string; vrf: string; ospfArea?: number; isisLevel?: 'L1' | 'L2'; passive?: boolean; shutdown?: boolean }>();
  const staticRoutes: StaticRouteConfig[] = [];
  let ospfEnabled = false;
  let isisEnabled = false;
  let isisNet: string | undefined;
  let ripEnabled = false;
  let bgpEnabled = false;
  let bgpAsn = 65000;
  const bgpPeers: BgpPeerConfig[] = [];

  for (const raw of lines) {
    const line = raw.trim().replace(/'/g, '');
    if (!line || line.startsWith('#')) continue;
    const hm = line.match(/^set\s+system\s+host-name\s+(\S+)/i);
    if (hm) { hostname = hm[1]; continue; }
    const ifV4 = line.match(/^set\s+interfaces\s+\S+\s+(\S+)\s+address\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i);
    if (ifV4) {
      const cur = ifaceMap.get(ifV4[1]) ?? { cidr: ifV4[2], vrf: 'default' };
      cur.cidr = ifV4[2];
      ifaceMap.set(ifV4[1], cur);
      continue;
    }
    const ifV6 = line.match(/^set\s+interfaces\s+\S+\s+(\S+)\s+address\s+([0-9a-fA-F:]+\/\d+)/i);
    if (ifV6) {
      const cur = ifaceMap.get(ifV6[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      cur.cidr6 = ifV6[2];
      ifaceMap.set(ifV6[1], cur);
      continue;
    }
    const ifVrf = line.match(/^set\s+interfaces\s+\S+\s+(\S+)\s+vrf\s+(\S+)/i);
    if (ifVrf) {
      vrfs.add(ifVrf[2]);
      const cur = ifaceMap.get(ifVrf[1]) ?? { cidr: '0.0.0.0/0', vrf: ifVrf[2] };
      cur.vrf = ifVrf[2];
      ifaceMap.set(ifVrf[1], cur);
      continue;
    }
    const ifDis = line.match(/^set\s+interfaces\s+\S+\s+(\S+)\s+disable$/i);
    if (ifDis) {
      const cur = ifaceMap.get(ifDis[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      cur.shutdown = true;
      ifaceMap.set(ifDis[1], cur);
      continue;
    }
    const srM = line.match(/^set\s+(?:vrf\s+name\s+(\S+)\s+)?protocols\s+static\s+route\s+(\S+)\s+next-hop\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (srM) {
      const vrf = srM[1] || 'default';
      vrfs.add(vrf);
      staticRoutes.push({ id: `sr-${Date.now()}-${staticRoutes.length}`, vrf, prefix: srM[2], nextHop: srM[3] });
      continue;
    }
    const ospfRid = line.match(/^set\s+protocols\s+ospf\s+parameters\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (ospfRid) { ospfEnabled = true; routerId = ospfRid[1]; continue; }
    const ospfArea = line.match(/^set\s+protocols\s+ospf\s+interface\s+(\S+)\s+area\s+(\S+)/i);
    if (ospfArea) {
      ospfEnabled = true;
      const cur = ifaceMap.get(ospfArea[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      const aNum = ospfArea[2].includes('.') ? Number(ospfArea[2].split('.').pop()) : Number(ospfArea[2]);
      if (Number.isFinite(aNum)) cur.ospfArea = aNum;
      ifaceMap.set(ospfArea[1], cur);
      continue;
    }
    const ospfPas = line.match(/^set\s+protocols\s+ospf\s+interface\s+(\S+)\s+passive$/i);
    if (ospfPas) {
      ospfEnabled = true;
      const cur = ifaceMap.get(ospfPas[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      cur.passive = true;
      ifaceMap.set(ospfPas[1], cur);
      continue;
    }
    const isisNetM = line.match(/^set\s+protocols\s+isis\s+net\s+(\S+)/i);
    if (isisNetM) { isisEnabled = true; isisNet = isisNetM[1]; continue; }
    const isisIfM = line.match(/^set\s+protocols\s+isis\s+interface\s+(\S+)(?:\s+(passive))?/i);
    if (isisIfM) {
      isisEnabled = true;
      const cur = ifaceMap.get(isisIfM[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      cur.isisLevel = cur.isisLevel ?? 'L2';
      if (isisIfM[2]) cur.passive = true;
      ifaceMap.set(isisIfM[1], cur);
      continue;
    }
    const ripPasM = line.match(/^set\s+protocols\s+rip\s+passive-interface\s+(\S+)/i);
    if (ripPasM) {
      ripEnabled = true;
      const cur = ifaceMap.get(ripPasM[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      cur.passive = true;
      ifaceMap.set(ripPasM[1], cur);
      continue;
    }
    const bgpAsM = line.match(/^set\s+protocols\s+bgp\s+system-as\s+(\d+)/i);
    if (bgpAsM) { bgpEnabled = true; bgpAsn = Number(bgpAsM[1]); continue; }
    const bgpRidM = line.match(/^set\s+protocols\s+bgp\s+parameters\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (bgpRidM) { bgpEnabled = true; routerId = bgpRidM[1]; continue; }
    const bgpNbrM = line.match(/^set\s+protocols\s+bgp\s+neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remote-as\s+(\d+)/i);
    if (bgpNbrM) {
      bgpEnabled = true;
      const existing = bgpPeers.find((x) => x.peerIp === bgpNbrM[1]);
      if (existing) existing.remoteAs = Number(bgpNbrM[2]);
      else bgpPeers.push({ id: `bp-${Date.now()}-${bgpPeers.length}`, peerIp: bgpNbrM[1], remoteAs: Number(bgpNbrM[2]) });
      continue;
    }
    const bgpNhsM = line.match(/^set\s+protocols\s+bgp\s+neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+.*nexthop-self/i);
    if (bgpNhsM) {
      bgpEnabled = true;
      const p = bgpPeers.find((x) => x.peerIp === bgpNhsM[1]);
      if (p) p.nextHopSelf = true;
      else bgpPeers.push({ id: `bp-${Date.now()}-${bgpPeers.length}`, peerIp: bgpNhsM[1], remoteAs: bgpAsn, nextHopSelf: true });
    }
  }

  return {
    id: `imp-${Date.now()}-${++importIdSeq}`,
    hostname,
    vendor: 'vyos',
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
      isisLevel: info.isisLevel,
      passive: info.passive,
      shutdown: info.shutdown,
    })),
    staticRoutes,
    ospf: { enabled: ospfEnabled, networks: [] },
    isis: isisEnabled ? { enabled: true, net: isisNet, level: 'L1-L2', networks: [] } : undefined,
    rip: ripEnabled ? { enabled: true, version: 2, networks: [] } : undefined,
    bgp: { enabled: bgpEnabled, asn: bgpAsn, peers: bgpPeers, networks: [] },
    redistributions: [],
    prefixLists: [],
    routeMaps: [],
    vrfLeaks: [],
  };
}

function parseCheckpointGaiaConfig(lines: string[]): NodeConfig {
  let hostname = 'GAIA-IMPORTED';
  let routerId = '10.255.0.50';
  const ifaceMap = new Map<string, { cidr: string; vrf: string; ospfArea?: number; passive?: boolean; shutdown?: boolean }>();
  const staticRoutes: StaticRouteConfig[] = [];
  let ospfEnabled = false;
  let bgpEnabled = false;
  let bgpAsn = 65000;
  const bgpPeers: BgpPeerConfig[] = [];

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const hm = line.match(/^set\s+hostname\s+(\S+)/i);
    if (hm) { hostname = hm[1]; continue; }
    const rm = line.match(/^set\s+router-id\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (rm) { routerId = rm[1]; continue; }
    const ifM = line.match(/^set\s+interface\s+(\S+)\s+ipv4-address\s+(\d+\.\d+\.\d+\.\d+)\s+(?:mask-length\s+(\d+)|subnet-mask\s+(\d+\.\d+\.\d+\.\d+))/i);
    if (ifM) {
      const prefixLen = ifM[3] ? Number(ifM[3]) : maskToPrefixLen(ifM[4]);
      const cur = ifaceMap.get(ifM[1]) ?? { cidr: `${ifM[2]}/${prefixLen}`, vrf: 'default' };
      cur.cidr = `${ifM[2]}/${prefixLen}`;
      ifaceMap.set(ifM[1], cur);
      continue;
    }
    const stM = line.match(/^set\s+interface\s+(\S+)\s+state\s+(on|off)/i);
    if (stM) {
      const cur = ifaceMap.get(stM[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      if (stM[2].toLowerCase() === 'off') cur.shutdown = true;
      ifaceMap.set(stM[1], cur);
      continue;
    }
    const srM = line.match(/^set\s+static-route\s+(\S+)\s+nexthop\s+gateway\s+address\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (srM) {
      staticRoutes.push({ id: `sr-${Date.now()}-${staticRoutes.length}`, vrf: 'default', prefix: srM[1], nextHop: srM[2] });
      continue;
    }
    const ospfIfM = line.match(/^set\s+ospf\s+instance\s+\S+\s+interface\s+(\S+)\s+area\s+(\S+)/i);
    if (ospfIfM) {
      ospfEnabled = true;
      const cur = ifaceMap.get(ospfIfM[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      const aNum = ospfIfM[2].includes('.') ? Number(ospfIfM[2].split('.').pop()) : Number(ospfIfM[2]);
      if (Number.isFinite(aNum)) cur.ospfArea = aNum;
      ifaceMap.set(ospfIfM[1], cur);
      continue;
    }
    const ospfPasM = line.match(/^set\s+ospf\s+instance\s+\S+\s+interface\s+(\S+)\s+passive\s+(on|off)/i);
    if (ospfPasM) {
      ospfEnabled = true;
      const cur = ifaceMap.get(ospfPasM[1]) ?? { cidr: '0.0.0.0/0', vrf: 'default' };
      cur.passive = ospfPasM[2].toLowerCase() === 'on';
      ifaceMap.set(ospfPasM[1], cur);
      continue;
    }
    const asM = line.match(/^set\s+as\s+(\d+)/i);
    if (asM) { bgpEnabled = true; bgpAsn = Number(asM[1]); continue; }
    const peerM = line.match(/^set\s+bgp\s+external\s+remote-as\s+(\d+)\s+peer\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (peerM) {
      bgpEnabled = true;
      bgpPeers.push({ id: `bp-${Date.now()}-${bgpPeers.length}`, peerIp: peerM[2], remoteAs: Number(peerM[1]) });
      continue;
    }
  }

  return {
    id: `imp-${Date.now()}-${++importIdSeq}`,
    hostname,
    vendor: 'checkpoint-gaia',
    routerId,
    position: { x: 240, y: 180 },
    maxPaths: 4,
    vrfs: ['default'],
    adOverrides: {},
    interfaces: Array.from(ifaceMap.entries()).map(([name, info], i) => ({
      id: `if-${Date.now()}-${i}`,
      name,
      cidr: info.cidr,
      vrf: info.vrf,
      ospfArea: info.ospfArea,
      passive: info.passive,
      shutdown: info.shutdown,
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

function parseCloudConfig(lines: string[]): NodeConfig {
  const joined = lines.join('\n');
  let vendor: NodeConfig['vendor'] = 'aws-cloud';
  if (/azurerm_|^az\s+network\b/im.test(joined)) vendor = 'azure-cloud';
  else if (/google_compute_|google_network_connectivity_|^gcloud\s+compute\b/im.test(joined)) vendor = 'gcp-cloud';
  else if (/oci_core_|^oci\s+network\b/im.test(joined)) vendor = 'oci-cloud';
  else if (/cloudflare_magic_(?:wan|transit)_|^cf-magic-wan\b/im.test(joined)) vendor = 'cloudflare-mwan';
  else if (/aws_networkmanager_|^aws\s+networkmanager\b/im.test(joined)) vendor = 'aws-cloudwan';

  let hostname =
    vendor === 'azure-cloud'
      ? 'AZURE-VHUB'
      : vendor === 'gcp-cloud'
        ? 'GCP-ROUTER'
        : vendor === 'oci-cloud'
          ? 'OCI-DRG'
          : vendor === 'cloudflare-mwan'
            ? 'CF-MWAN'
            : vendor === 'aws-cloudwan'
              ? 'AWS-CWAN'
              : 'AWS-TGW';
  let region = '';
  let asn = vendor === 'azure-cloud' ? 65515 : vendor === 'gcp-cloud' ? 64514 : vendor === 'oci-cloud' ? 31898 : vendor === 'cloudflare-mwan' ? 13335 : 64512;
  let applianceMode = false;
  let disableBgpPropagation = false;
  let privateGoogleAccess = false;
  let pgaOnPremAdvertise = false;
  let nccHubEnabled = false;
  const pscEndpoints: string[] = [];
  let dynamicRoutingMode: 'regional' | 'global' = 'global';
  let defaultRoutePriority = 1000;
  const blackholeCidrs: string[] = [];
  const vrfs = new Set<string>(['default']);
  const interfaces: InterfaceConfig[] = [];
  const staticRoutes: StaticRouteConfig[] = [];
  const bgpPeers: BgpPeerConfig[] = [];

  let blockType = '';
  let curCidr = '';
  let curNextHop = '';
  let curAzureNhType: StaticRouteConfig['azureNextHopType'] | undefined;
  let curAwsTargetType: StaticRouteConfig['awsTargetType'] | undefined;
  let curGcpNhType: StaticRouteConfig['gcpNextHopType'] | undefined;
  let curGcpPriority: number | undefined;
  let curNetworkTag: string | undefined;
  let curInterfaceName: string | undefined;
  let curBlackhole = false;
  let curVrf = 'default';
  let curName = '';
  let braceDepth = 0;

  const normalizeAzureNhType = (rawType?: string): StaticRouteConfig['azureNextHopType'] | undefined => {
    if (!rawType) return undefined;
    const t = rawType.toLowerCase();
    if (t === 'virtualappliance') return 'VirtualAppliance';
    if (t === 'none') return 'None';
    if (t === 'internet') return 'Internet';
    if (t === 'vnetlocal') return 'VnetLocal';
    if (t === 'virtualnetworkgateway') return 'VirtualNetworkGateway';
    return undefined;
  };

  const flushBlock = () => {
    if (!blockType) return;
    if (blockType === 'att' && curCidr) {
      vrfs.add(curVrf);
      interfaces.push({
        id: nextImportId('if'),
        name: curName || `att-${interfaces.length + 1}`,
        cidr: curCidr,
        vrf: curVrf,
      });
    } else if (blockType === 'route' && curCidr) {
      if (vendor === 'azure-cloud' && curAzureNhType === 'None' && curName.toLowerCase().startsWith('blackhole')) {
        blackholeCidrs.push(curCidr);
      } else if (vendor === 'azure-cloud' && curAzureNhType) {
        staticRoutes.push({
          id: nextImportId('sr'),
          prefix: curCidr,
          nextHop:
            curAzureNhType === 'None'
              ? 'blackhole'
              : curAzureNhType === 'Internet'
                ? 'internet'
                : curAzureNhType === 'VnetLocal'
                  ? '0.0.0.0'
                  : curNextHop || '0.0.0.0',
          vrf: curVrf,
          azureNextHopType: curAzureNhType,
        });
      } else if ((vendor === 'aws-cloud' || vendor === 'aws-cloudwan') && curAwsTargetType) {
        staticRoutes.push({
          id: nextImportId('sr'),
          prefix: curCidr,
          nextHop:
            curAwsTargetType === 'igw'
              ? 'igw'
              : curAwsTargetType === 'nat'
                ? 'nat-gw'
                : curAwsTargetType === 'blackhole'
                  ? 'blackhole'
                  : curNextHop || '0.0.0.0',
          vrf: curVrf,
          awsTargetType: curAwsTargetType,
        });
      } else if (vendor === 'gcp-cloud' && (curGcpNhType || curNextHop)) {
        staticRoutes.push({
          id: nextImportId('sr'),
          prefix: curCidr,
          nextHop:
            curGcpNhType === 'default-internet-gateway'
              ? 'gcp-igw'
              : curGcpNhType === 'cloud-nat'
                ? 'gcp-nat'
                : curNextHop || '0.0.0.0',
          vrf: curVrf,
          gcpNextHopType: curGcpNhType ?? 'next-hop-address',
          ...(curGcpPriority !== undefined ? { gcpPriority: curGcpPriority } : {}),
          ...(curNetworkTag ? { networkTag: curNetworkTag } : {}),
          ...(curInterfaceName ? { interfaceName: curInterfaceName } : {}),
        });
      } else if (curBlackhole || curNextHop.toLowerCase() === 'none' || curNextHop.toLowerCase() === 'blackhole') {
        blackholeCidrs.push(curCidr);
      } else if (curNextHop) {
        staticRoutes.push({
          id: nextImportId('sr'),
          prefix: curCidr,
          nextHop: curNextHop,
          vrf: curVrf,
        });
      }
    }
    blockType = '';
    curCidr = '';
    curNextHop = '';
    curAzureNhType = undefined;
    curAwsTargetType = undefined;
    curGcpNhType = undefined;
    curGcpPriority = undefined;
    curNetworkTag = undefined;
    curInterfaceName = undefined;
    curBlackhole = false;
    curVrf = 'default';
    curName = '';
    braceDepth = 0;
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    // Single-line CLI: AWS `aws ec2 create-route`
    if (/^aws\s+ec2\s+create-route\b/i.test(line)) {
      const pfx = line.match(/--destination-cidr-block\s+"?([^"\s]+)"?/i)?.[1];
      const igw = line.match(/--gateway-id\s+"?([^"\s]+)"?/i)?.[1];
      const nat = line.match(/--nat-gateway-id\s+"?([^"\s]+)"?/i)?.[1];
      const pcx = line.match(/--vpc-peering-connection-id\s+"?([^"\s]+)"?/i)?.[1];
      const tgw = line.match(/--transit-gateway-id\s+"?([^"\s]+)"?/i)?.[1];
      if (pfx) {
        const targetType: StaticRouteConfig['awsTargetType'] = nat
          ? 'nat'
          : igw?.startsWith('vgw-')
            ? 'vgw'
            : igw
              ? 'igw'
              : pcx
                ? 'pcx'
                : tgw
                  ? 'tgw'
                  : 'igw';
        staticRoutes.push({
          id: nextImportId('sr'),
          prefix: pfx,
          nextHop: targetType === 'nat' ? 'nat-gw' : targetType === 'igw' ? 'igw' : '0.0.0.0',
          vrf: 'default',
          awsTargetType: targetType,
        });
      }
      continue;
    }

    // Single-line CLI: Azure route-table create / update
    if (/^az\s+network\s+route-table\s+(?:create|update)\b/i.test(line)) {
      if (/--disable-bgp-route-propagation\s+(?:true|1|yes)/i.test(line)) {
        disableBgpPropagation = true;
      }
      continue;
    }

    // Single-line CLI: Azure route create
    if (/^az\s+network\s+route-table\s+route\s+create\b/i.test(line)) {
      const pfx = line.match(/--address-prefix\s+"?([^"\s]+)"?/i)?.[1];
      const nhType = normalizeAzureNhType(line.match(/--next-hop-type\s+"?([^"\s]+)"?/i)?.[1]);
      const nhIp = line.match(/--next-hop-ip-address\s+"?([^"\s]+)"?/i)?.[1];
      if (pfx) {
        staticRoutes.push({
          id: nextImportId('sr'),
          prefix: pfx,
          nextHop:
            nhType === 'None'
              ? 'blackhole'
              : nhType === 'Internet'
                ? 'internet'
                : nhType === 'VnetLocal'
                  ? '0.0.0.0'
                  : nhIp || '0.0.0.0',
          vrf: 'default',
          azureNextHopType: nhType ?? (nhIp ? 'VirtualAppliance' : 'None'),
        });
      }
      continue;
    }

    // Single-line CLI: GCP route create
    if (/^gcloud\s+compute\s+routes\s+create\b/i.test(line)) {
      const pfx = line.match(/--destination-range[=\s]+"?([^"\s]+)"?/i)?.[1];
      const nhIp = line.match(/--next-hop-address[=\s]+"?([^"\s]+)"?/i)?.[1];
      const nhGw = line.match(/--next-hop-gateway[=\s]+"?([^"\s]+)"?/i)?.[1];
      const nhIlb = line.match(/--next-hop-ilb[=\s]+"?([^"\s]+)"?/i)?.[1];
      const nhVpn = line.match(/--next-hop-vpn-tunnel[=\s]+"?([^"\s]+)"?/i)?.[1];
      const tagM = line.match(/--tags[=\s]+"?([^"\s,]+)"?/i)?.[1];
      const prio = line.match(/--priority[=\s]+(\d+)/i)?.[1];
      const prioNum = prio ? Number(prio) : undefined;
      if (pfx) {
        const gcpType: StaticRouteConfig['gcpNextHopType'] = nhGw
          ? 'default-internet-gateway'
          : nhIlb
            ? 'ilb'
            : nhVpn
              ? 'vpn-tunnel'
              : 'next-hop-address';
        staticRoutes.push({
          id: nextImportId('sr'),
          prefix: pfx,
          nextHop: nhGw ? 'gcp-igw' : nhIlb || nhIp || '0.0.0.0',
          vrf: 'default',
          gcpNextHopType: gcpType,
          ...(prioNum !== undefined ? { gcpPriority: prioNum } : {}),
          ...(tagM ? { networkTag: tagM } : {}),
          ...(nhVpn ? { interfaceName: nhVpn } : {}),
        });
      }
      continue;
    }

    const resM = line.match(/^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/);
    if (resM) {
      flushBlock();
      const rType = resM[1].toLowerCase();
      curName = resM[2];
      braceDepth = 1;
      if (
        rType === 'aws_ec2_transit_gateway' ||
        rType === 'aws_networkmanager_core_network' ||
        rType === 'azurerm_virtual_hub' ||
        rType === 'google_compute_router' ||
        rType === 'oci_core_drg' ||
        rType === 'cloudflare_magic_transit_site'
      ) {
        blockType = 'hub';
      } else if (
        rType === 'azurerm_route_table' ||
        rType === 'google_network_connectivity_hub' ||
        rType === 'google_compute_global_forwarding_rule'
      ) {
        if (rType === 'google_network_connectivity_hub') nccHubEnabled = true;
        blockType = rType === 'google_compute_global_forwarding_rule' ? 'psc' : 'subhub';
      } else if (rType.includes('attachment')) {
        blockType = 'att';
      } else if (
        rType === 'aws_ec2_transit_gateway_route' ||
        rType === 'aws_route' ||
        rType === 'azurerm_route' ||
        rType === 'google_compute_route' ||
        rType === 'oci_core_drg_route_rule' ||
        rType === 'cloudflare_magic_wan_static_route'
      ) {
        blockType = 'route';
      } else {
        blockType = 'other';
      }
      continue;
    }

    if (!blockType) continue;
    if (line.includes('{')) braceDepth += (line.match(/\{/g) || []).length;

    if (blockType === 'hub' || blockType === 'subhub') {
      if (blockType === 'hub' && braceDepth === 1) {
        const nM = line.match(/^(?:name|description|display_name)\s*=\s*"([^"]+)"/i);
        if (nM) hostname = nM[1];
      }
      const regM = line.match(/^(?:region|location)\s*=\s*"([^"]+)"/i);
      if (regM) region = regM[1];
      const asnM = line.match(/^(?:amazon_side_asn|virtual_router_asn|asn)\s*=\s*(\d+)/i);
      if (asnM) asn = Number(asnM[1]);
      const appM = line.match(/^appliance_mode_support\s*=\s*"(enable|disable)"/i);
      if (appM) applianceMode = appM[1].toLowerCase() === 'enable';
      if (/^disable_bgp_route_propagation\s*=\s*true/i.test(line)) disableBgpPropagation = true;
      const modeM = line.match(/^advertise_mode\s*=\s*"(REGIONAL|GLOBAL)"/i);
      if (modeM) dynamicRoutingMode = modeM[1].toLowerCase() as 'regional' | 'global';
      if (/199\.36\.153\.(?:8|4)\/30/.test(line)) {
        privateGoogleAccess = true;
        pgaOnPremAdvertise = true;
      }
    } else if (blockType === 'psc') {
      const ipM = line.match(/^ip_address\s*=\s*"([^"]+)"/i);
      if (ipM) pscEndpoints.push(ipM[1].includes('/') ? ipM[1] : `${ipM[1]}/32`);
    } else if (blockType === 'att') {
      const cM = line.match(/^subnet_cidr\s*=\s*"([^"]+)"/i);
      if (cM) curCidr = cM[1];
      const rtM = line.match(/^route_table\s*=\s*"([^"]+)"/i);
      if (rtM) curVrf = rtM[1];
    } else if (blockType === 'route') {
      const cM = line.match(/^(?:destination_cidr_block|address_prefix|dest_range|destination|prefix)\s*=\s*"([^"]+)"/i);
      if (cM) curCidr = cM[1];
      const nhM = line.match(/^(?:next_hop|next_hop_in_ip_address|next_hop_ip|nexthop)\s*=\s*"([^"]+)"/i);
      if (nhM) curNextHop = nhM[1];
      const nhTypeM = line.match(/^next_hop_type\s*=\s*"([^"]+)"/i);
      if (nhTypeM) {
        curAzureNhType = normalizeAzureNhType(nhTypeM[1]);
        if (nhTypeM[1].toLowerCase() === 'none') curBlackhole = true;
      }
      if (/^nat_gateway_id\s*=/i.test(line)) curAwsTargetType = 'nat';
      else if (/^gateway_id\s*=\s*"vgw-/i.test(line)) curAwsTargetType = 'vgw';
      else if (/^gateway_id\s*=/i.test(line)) curAwsTargetType = 'igw';
      else if (/^vpc_peering_connection_id\s*=/i.test(line)) curAwsTargetType = 'pcx';
      else if (/^transit_gateway_id\s*=/i.test(line)) curAwsTargetType = 'tgw';
      else if (/^vpc_endpoint_id\s*=/i.test(line)) curAwsTargetType = 'vpce';
      if (/^blackhole\s*=\s*true/i.test(line)) curBlackhole = true;
      if (/^next_hop_gateway\s*=/i.test(line)) {
        curGcpNhType = /cloud\s*nat/i.test(line) ? 'cloud-nat' : 'default-internet-gateway';
      } else if (/^next_hop_ilb\s*=\s*"([^"]+)"/i.test(line)) {
        curGcpNhType = 'ilb';
        curNextHop = line.match(/^next_hop_ilb\s*=\s*"([^"]+)"/i)![1];
      } else if (/^next_hop_vpn_tunnel\s*=/i.test(line)) {
        curGcpNhType = 'vpn-tunnel';
        const vpnM = line.match(/^next_hop_vpn_tunnel\s*=\s*"([^"]+)"/i);
        if (vpnM) curInterfaceName = vpnM[1];
      }
      const prioM = line.match(/^priority\s*=\s*(\d+)/i);
      if (prioM) {
        curGcpPriority = Number(prioM[1]);
      }
      const tagsM = line.match(/^tags\s*=\s*\[\s*"([^"]+)"/i);
      if (tagsM) curNetworkTag = tagsM[1];
    }

    if (line.includes('}')) {
      braceDepth -= (line.match(/\}/g) || []).length;
      if (braceDepth <= 0) flushBlock();
    }
  }
  flushBlock();

  return {
    id: nextImportId('node'),
    hostname,
    vendor,
    routerId: '169.254.0.1',
    position: { x: 180, y: 140 },
    maxPaths: 4,
    vrfs: [...vrfs],
    adOverrides: {},
    interfaces,
    staticRoutes,
    ospf: { enabled: false, networks: [] },
    bgp: { enabled: true, asn, peers: bgpPeers, networks: [] },
    redistributions: [],
    prefixLists: [],
    routeMaps: [],
    vrfLeaks: [],
    cloudConfig: {
      ...(region ? { region } : {}),
      ...(vendor === 'gcp-cloud'
        ? {
            dynamicRoutingMode,
            defaultRoutePriority,
            privateGoogleAccess,
            pgaOnPremAdvertise,
            nccHubEnabled,
            ...(pscEndpoints.length > 0 ? { pscEndpoints } : {}),
          }
        : {}),
      ...(vendor === 'aws-cloud' || vendor === 'aws-cloudwan' ? { applianceMode } : {}),
      ...(vendor === 'azure-cloud' ? { udrOverridesBgp: true, disableBgpPropagation } : {}),
      preferPrivateCircuit: true,
      ...(blackholeCidrs.length > 0 ? { blackholeCidrs } : {}),
    },
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

  const lines = trimmed.split(/\r?\n/).map((l) => normalizeConfigLine(l));
  const isCloud = lines.some((l) =>
    /^(?:resource\s+"(?:aws_|azurerm_|google_compute_|google_network_connectivity_|oci_core_|cloudflare_magic_(?:wan|transit)_)|(?:aws\s+(?:ec2|networkmanager)|az\s+network|gcloud\s+compute|oci\s+network|cf-magic-wan)\b)/i.test(
      l.trim()
    )
  );
  const isForti = !isCloud && lines.some((l) => /^config\s+(?:system|router|firewall)\b/i.test(l.trim()));
  const isMikrotik =
    !isCloud &&
    !isForti &&
    lines.some((l) =>
      /^\/(?:ip\s+(?:address|route|vrf|firewall)|ipv6\s+address|system\s+identity|routing\s+(?:ospf|bgp))\b/i.test(
        l.trim()
      )
    );
  const isVyos =
    !isCloud &&
    !isForti &&
    !isMikrotik &&
    lines.some((l) =>
      /^set\s+(?:interfaces\s+(?:ethernet|loopback|dummy|bonding|vlan|tunnel|vti|wireguard)\s+\S+\s+address|firewall\s+(?:ipv4\s+)?(?:name|forward|input|output|zone)\b|protocols\s+(?:static\s+route|bgp\s+system-as|ospf\s+(?:parameters|interface)|isis\s+(?:net|interface)|rip\s+passive-interface))\b/i.test(
        l.trim()
      )
    );
  const isGaia =
    !isCloud &&
    !isForti &&
    !isMikrotik &&
    !isVyos &&
    lines.some((l) =>
      /^(?:set\s+(?:interface\s+\S+\s+ipv4-address|static-route\s+\S+\s+nexthop|ospf\s+instance|bgp\s+external\s+remote-as)|(?:mgmt_cli\s+)?add\s+(?:access-rule|host|network))\b/i.test(
        l.trim()
      )
    );
  const isJunosSet =
    !isCloud &&
    !isForti &&
    !isMikrotik &&
    !isVyos &&
    !isGaia &&
    lines.some((l) =>
      /^set\s+(?:system\s+host-name|interfaces\s+\S+(?:\.\d+|\s+unit)|routing-options|routing-instances|protocols\s+(?:ospf|bgp)|security\s+(?:policies|address-book))\b/i.test(
        l.trim()
      )
    );
  const isCiscoStyle = !isCloud && lines.some((l) =>
    /^(?:interface\s+\S+|router\s+(?:ospf|bgp|eigrp|isis|rip)|route-map\s+\S+|ip\s+access-list\s+|access-list\s+\d+)/i.test(l.trim())
  );
  const isPanSet =
    !isCloud &&
    !isForti &&
    !isMikrotik &&
    !isVyos &&
    !isGaia &&
    !isJunosSet &&
    !isCiscoStyle &&
    lines.some((l) => /^set\s+/i.test(l.trim()));
  const node = isCloud
    ? parseCloudConfig(lines)
    : isForti
      ? parseFortigateConfig(lines)
      : isMikrotik
        ? parseMikrotikConfig(lines)
        : isVyos
          ? parseVyosConfig(lines)
          : isGaia
            ? parseCheckpointGaiaConfig(lines)
            : isJunosSet
              ? parseJunosSetConfig(lines)
              : isPanSet
                ? parsePanOsSetConfig(lines)
                : parseCiscoStyleConfig(lines);
  const parsedAclRules = isCloud
    ? parseCloudAclRules(lines)
    : isForti
      ? parseFortigateAclRules(lines)
      : isMikrotik
        ? parseMikrotikAclRules(lines)
        : isVyos
          ? parseVyosAclRules(lines)
          : isGaia
            ? parseCheckpointGaiaAclRules(lines)
            : isJunosSet
              ? parseJunosAclRules(lines)
              : isPanSet
                ? parsePanOsAclRules(lines)
                : parseCiscoStyleAclRules(lines);
  if (parsedAclRules.length > 0) {
    node.aclRules = parsedAclRules;
  }
  return { nodes: [node], links: [] };
}

export interface ConfigValidationIssue {
  line: number;
  severity: 'error' | 'warning';
  message: string;
}

function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isValidIpv4Mask(mask: string): boolean {
  if (!isValidIpv4(mask)) return false;
  const num = mask
    .split('.')
    .reduce((acc, oct) => ((acc << 8) | Number(oct)) >>> 0, 0);
  if (num === 0) return true;
  const inv = (~num) >>> 0;
  return (inv & (inv + 1)) === 0;
}

function isValidIpv4Cidr(cidr: string): boolean {
  const [ip, lenStr] = cidr.split('/');
  if (!ip || lenStr === undefined || !/^\d+$/.test(lenStr)) return false;
  const len = Number(lenStr);
  return isValidIpv4(ip) && len >= 0 && len <= 32;
}

const KNOWN_CISCO_GLOBAL_RE =
  /^(?:version|hostname|service|no\s+|enable|boot|logging|ip\s+(?:vrf|route|prefix-list|access-list|nat|sla|dhcp|pim|multicast|routing|cef|domain|name-server|ssh|flow-export)|ipv6\s+(?:unicast-routing|route)|vrf\s+(?:definition|context)|vrf-leak\s+|rd\s+|route-target\s+|address-family\s+|exit-address-family|interface\s+|router\s+(?:ospf|bgp|eigrp|isis|rip|lisp)|route-map\s+|match\s+|set\s+|vpc\s+domain|mlag\s+configuration|spanning-tree\s+|lldp\s+run|mpls\s+|segment-routing|ptp\s+|ntp\s+|bmp\s+|flow\s+|access-list\s+|track\s+|crypto\s+|feature\s+|evpn|vni\s+|member\s+|source-interface|host-reachability|exit\b|end\b)/i;

const KNOWN_CISCO_SUB_RE =
  /^(?:\d+\s+(?:permit|deny|remark)\b|description|vrf\s+(?:forwarding|member)|zone-member\s+|global-block\s+|remote-as\s+|update-source\s+|ebgp-multihop|next-hop-self|route-reflector-client|send-community|maximum-prefix|fall-over|graceful-restart|hsrp\s+|priority\s+|ip\s+(?:address|unnumbered|verify|ospf|router\s+ospf|router\s+isis|summary-address|hello-interval|hold-time|bandwidth-percent|pim|helper-address|dhcp|arp|access-group|nat|policy|\d+\.\d+\.\d+\.\d+)|ipv6\s+(?:address|ospf|nd)|encapsulation\s+dot1[qQ]|switchport|no\s+|shutdown|passive-interface|mtu\s+|speed\s+|bandwidth\s+|delay\s+|standby\s+|vrrp\s+|glbp\s+|channel-group\s+|channel-protocol\s+|vpc\s+|mlag\s+|macsec|dot1x|evpn\s+|isis\s+|bfd\s+|router-id|eigrp\s+|bgp\s+|neighbor\s+|network\s+|redistribute\s+|default-information|default-metric|auto-cost|max-metric|variance\s+|area\s+|maximum-paths|timers\s+|net\s+|is-type|metric-style|metric\s+|set-overload-bit|multi-topology|summary-address|aggregate-address|distance\s+|auto-summary|version\s+|address-family|exit-address-family|locator-table|instance-id|rloc-probing|service\s+ipv4|eid-prefix|database-mapping|map-server|map-resolver|itr\b|etr\b|proxy-itr|proxy-etr|role\s+priority|system-priority|peer-keepalive|peer-gateway|peer-switch|layer3\s+peer-router|auto-recovery|ip\s+arp\s+synchronize|delay\s+restore|domain-id|local-interface|peer-address|peer-link|reload-delay|rd\s+|route-target\s+|seq\s+|permit\b|deny\b|remark\b|match\s+|set\s+|exit\b)/i;

export function validateRunningConfig(text: string): ConfigValidationIssue[] {
  const issues: ConfigValidationIssue[] = [];
  const rawLines = text.split(/\r?\n/).map((l) => normalizeConfigLine(l));
  const trimmedNonEmpty = rawLines.map((l) => l.trim()).filter((l) => l && !l.startsWith('!') && !l.startsWith('#'));

  if (trimmedNonEmpty.length === 0) {
    issues.push({ line: 1, severity: 'error', message: 'Configuration is empty.' });
    return issues;
  }

  // JSON / YAML topology skip line-by-line CLI syntax checks (JSON validated via JSON.parse)
  const firstLine = trimmedNonEmpty[0];
  if (firstLine.startsWith('{') || firstLine.startsWith('[')) {
    try {
      JSON.parse(text);
    } catch (err) {
      issues.push({
        line: 1,
        severity: 'error',
        message: `Invalid JSON: ${err instanceof Error ? err.message : 'syntax error'}`,
      });
    }
    return issues;
  }
  if (/^(?:nodes|links|name|topology):/i.test(firstLine)) {
    return issues;
  }

  const isCloudConfig = rawLines.some((l) =>
    /^(?:resource\s+"[^"]+"\s+"[^"]+"\s*\{|(?:aws\s+(?:ec2|networkmanager)|az\s+network|gcloud\s+compute|oci\s+network|cf-magic-wan)\b)/i.test(
      l.trim()
    )
  );
  if (isCloudConfig) {
    let braceDepth = 0;
    rawLines.forEach((raw, idx) => {
      const t = raw.trim();
      if (!t || t.startsWith('#') || t.startsWith('//')) return;
      const codeOnly = t.replace(/#.*$/, '');
      const opens = (codeOnly.match(/\{/g) || []).length;
      const closes = (codeOnly.match(/\}/g) || []).length;
      braceDepth += opens - closes;
      if (braceDepth < 0) {
        issues.push({
          line: idx + 1,
          severity: 'error',
          message: 'Unexpected "}" without matching "{".',
        });
        braceDepth = 0;
      }
    });
    if (braceDepth > 0) {
      issues.push({
        line: rawLines.length,
        severity: 'error',
        message: `Unclosed Terraform HCL block (${braceDepth} missing "}").`,
      });
    }
    return issues;
  }

  const isForti = rawLines.some((l) => /^config\s+(?:system|router|firewall|vpn)/i.test(l.trim()));
  const isMikrotik = !isForti && rawLines.some((l) => /^\/(?:ip|ipv6|system|routing|interface)\b/i.test(l.trim()));
  const isSetStyle =
    !isForti &&
    !isMikrotik &&
    rawLines.some((l) => /^(?:set\s+|(?:mgmt_cli\s+)?add\s+(?:access-rule|host|network)\b)/i.test(l.trim())) &&
    !rawLines.some((l) => /^(?:interface\s+\S+|router\s+(?:ospf|bgp|eigrp|isis|rip))/i.test(l.trim()));
  const isViptela =
    !isForti &&
    !isMikrotik &&
    rawLines.some((l) => /^system-ip\s+/i.test(l.trim())) &&
    rawLines.some((l) => /^(?:omp|vpn\s+0)\b/i.test(l.trim()));

  if (isForti) {
    let depth = 0;
    rawLines.forEach((raw, idx) => {
      const t = raw.trim();
      if (!t || t.startsWith('#') || t.startsWith('!')) return;
      if (/^config\s+/i.test(t)) depth++;
      else if (/^end$/i.test(t)) {
        if (depth === 0) {
          issues.push({ line: idx + 1, severity: 'error', message: 'Unexpected "end" without matching "config".' });
        } else {
          depth--;
        }
      }
    });
    if (depth > 0) {
      issues.push({ line: rawLines.length, severity: 'error', message: `Unclosed FortiGate "config" block (${depth} missing "end").` });
    }
    return issues;
  }

  if (isMikrotik || isSetStyle || isViptela) {
    return issues;
  }

  let section: 'none' | 'interface' | 'bgp' | 'router' | 'vrf' | 'routemap' | 'acl' | 'other' = 'none';

  rawLines.forEach((raw, idx) => {
    const lineNum = idx + 1;
    const t = raw.trim();
    if (!t || t.startsWith('!') || t.startsWith('#')) {
      if (t === '!') section = 'none';
      return;
    }

    if (/^interface(?:\s|$)/i.test(t)) {
      if (!/^interface\s+\S+/i.test(t)) {
        issues.push({ line: lineNum, severity: 'error', message: `Missing interface name in "${t}".` });
      }
      section = 'interface';
      return;
    }

    const bgpStart = t.match(/^router\s+bgp\s+(\S+)/i);
    if (bgpStart) {
      const asn = Number(bgpStart[1]);
      if (!Number.isInteger(asn) || asn < 1 || asn > 4294967295) {
        issues.push({ line: lineNum, severity: 'error', message: `Invalid BGP ASN "${bgpStart[1]}" (must be 1-4294967295).` });
      }
      section = 'bgp';
      return;
    }

    if (/^router\s+(?:ospf|eigrp|isis|rip|lisp)\b/i.test(t)) {
      section = 'router';
      return;
    }
    if (/^(?:ip\s+)?vrf\s+(?:definition|context)\s+\S+/i.test(t) || /^ip\s+vrf\s+\S+$/i.test(t)) {
      section = 'vrf';
      return;
    }
    if (/^route-map\s+\S+/i.test(t)) {
      section = 'routemap';
      return;
    }
    if (/^ip\s+access-list\s+/i.test(t)) {
      section = 'acl';
      return;
    }
    if (/^(?:vpc\s+domain|mlag\s+configuration|segment-routing\s+mpls)/i.test(t)) {
      section = 'other';
      return;
    }

    // Interface-only subcommands used outside an interface block (shutdown is also valid in router bgp)
    if (
      section !== 'interface' &&
      !(section === 'bgp' && /^shutdown\b/i.test(t)) &&
      /^(?:ip\s+address|encapsulation\s+dot1[qQ]|channel-group|switchport|shutdown)\b/i.test(t)
    ) {
      issues.push({
        line: lineNum,
        severity: 'error',
        message: `"${t}" must be inside an "interface <name>" block.`,
      });
    }

    // BGP-only subcommands used outside router bgp
    if (section !== 'bgp' && /^(?:neighbor\s+\S+\s+remote-as|bgp\s+router-id)\b/i.test(t)) {
      issues.push({
        line: lineNum,
        severity: 'error',
        message: `"${t}" must be inside a "router bgp <asn>" block.`,
      });
    }

    // Validate ip address syntax
    if (/^ip\s+address\b/i.test(t) && !/^ip\s+address\s+dhcp\b/i.test(t)) {
      const mMask = t.match(/^ip\s+address\s+(\S+)\s+(\S+)(?:\s+secondary)?$/i);
      const mCidr = t.match(/^ip\s+address\s+(\S+\/\S+)(?:\s+secondary)?$/i);
      if (mCidr) {
        if (!isValidIpv4Cidr(mCidr[1])) {
          issues.push({ line: lineNum, severity: 'error', message: `Invalid IPv4 CIDR "${mCidr[1]}".` });
        }
      } else if (mMask) {
        if (!isValidIpv4(mMask[1]) || !isValidIpv4Mask(mMask[2])) {
          issues.push({ line: lineNum, severity: 'error', message: `Invalid IPv4 address or subnet mask in "${t}".` });
        }
      } else {
        issues.push({ line: lineNum, severity: 'error', message: `Malformed "ip address" statement: "${t}".` });
      }
      return;
    }

    // Validate encapsulation dot1Q <1-4094>
    const encap = t.match(/^encapsulation\s+dot1[qQ]\s+(\S+)/i);
    if (encap) {
      const vlan = Number(encap[1]);
      if (!Number.isInteger(vlan) || vlan < 1 || vlan > 4094) {
        issues.push({ line: lineNum, severity: 'error', message: `Invalid 802.1Q VLAN ID "${encap[1]}" (must be 1-4094).` });
      }
      return;
    }

    // Validate mtu <68-9216>
    const mtuMatch = t.match(/^mtu\s+(\S+)/i);
    if (mtuMatch) {
      const mtu = Number(mtuMatch[1]);
      if (!Number.isInteger(mtu) || mtu < 68 || mtu > 9216) {
        issues.push({ line: lineNum, severity: 'error', message: `Invalid MTU "${mtuMatch[1]}" (must be 68-9216).` });
      }
      return;
    }

    // Validate channel-group <n> mode <mode>
    const cgMatch = t.match(/^channel-group\s+(\S+)(?:\s+mode\s+(\S+))?/i);
    if (cgMatch) {
      const grp = Number(cgMatch[1]);
      if (!Number.isInteger(grp) || grp < 1 || grp > 4096) {
        issues.push({ line: lineNum, severity: 'error', message: `Invalid channel-group number "${cgMatch[1]}".` });
      }
      if (cgMatch[2] && !/^(?:active|passive|desirable|auto|on)$/i.test(cgMatch[2])) {
        issues.push({
          line: lineNum,
          severity: 'error',
          message: `Invalid channel-group mode "${cgMatch[2]}" (expected active, passive, desirable, auto, or on).`,
        });
      }
      return;
    }

    // Validate neighbor <ip> remote-as <asn>
    const nbrAs = t.match(/^neighbor\s+(\S+)\s+remote-as\s+(\S+)/i);
    if (nbrAs) {
      const asn = Number(nbrAs[2]);
      if (!isValidIpv4(nbrAs[1]) && !nbrAs[1].includes(':')) {
        issues.push({ line: lineNum, severity: 'error', message: `Invalid BGP neighbor IP "${nbrAs[1]}".` });
      }
      if (!Number.isInteger(asn) || asn < 1 || asn > 4294967295) {
        issues.push({ line: lineNum, severity: 'error', message: `Invalid neighbor remote-as "${nbrAs[2]}".` });
      }
      return;
    }

    // Validate static ip route (including octet & subnet mask validity)
    if (/^ip\s+route\b/i.test(t)) {
      const mMask = t.match(/^ip\s+route\s+(?:vrf\s+\S+\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      const mCidr = t.match(/^ip\s+route\s+(?:vrf\s+\S+\s+)?(\d+\.\d+\.\d+\.\d+\/\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (mMask) {
        if (!isValidIpv4(mMask[1]) || !isValidIpv4Mask(mMask[2]) || !isValidIpv4(mMask[3])) {
          issues.push({
            line: lineNum,
            severity: 'error',
            message: `Invalid IPv4 prefix, subnet mask, or next-hop in static route "${t}".`,
          });
        }
      } else if (mCidr) {
        if (!isValidIpv4Cidr(mCidr[1]) || !isValidIpv4(mCidr[2])) {
          issues.push({
            line: lineNum,
            severity: 'error',
            message: `Invalid CIDR or next-hop in static route "${t}".`,
          });
        }
      } else {
        issues.push({
          line: lineNum,
          severity: 'error',
          message: `Malformed static route "${t}" (expected "ip route <prefix> <mask|/> <next-hop>").`,
        });
      }
      return;
    }

    // Check unknown / misspelled commands
    const recognized =
      section === 'none'
        ? KNOWN_CISCO_GLOBAL_RE.test(t)
        : KNOWN_CISCO_SUB_RE.test(t) || KNOWN_CISCO_GLOBAL_RE.test(t);
    if (!recognized) {
      issues.push({
        line: lineNum,
        severity: 'warning',
        message: `Unrecognized or possibly misspelled command: "${t}".`,
      });
    }
  });

  return issues;
}
