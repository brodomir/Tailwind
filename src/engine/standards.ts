import {
  InterfaceConfig,
  LfibEntry,
  MrouteEntry,
  NodeConfig,
  RibEntry,
  StpNodeState,
  TopologyState,
} from '../types/network';
import {
  detectAddressFamily,
  ip6ToBigInt,
  isIp6InCidr,
  isIpInCidr,
  parseCidr,
  parseCidr6,
  uint32ToIp,
} from './ipMath';

export interface StpLldpResult {
  stpByNode: Map<string, StpNodeState>;
  lldpByNode: Map<string, { localInterface: string; remoteChassisId: string; remotePort: string }[]>;
  blockedL2Ports: Set<string>;
}

export function parsePortChannelNumber(name: string): number | null {
  const base = name.split('.')[0].trim();
  const m = base.match(/^(?:port-?channel|po|ae|bond)\s*(\d+)$/i);
  return m ? Number(m[1]) : null;
}

export function getLagProtocol(iface: InterfaceConfig): 'lacp' | 'pagp' | 'static' {
  if (iface.lagProtocol) return iface.lagProtocol;
  if (iface.lacpMode === 'desirable' || iface.lacpMode === 'auto') return 'pagp';
  if (iface.lacpMode === 'on') return 'static';
  return 'lacp';
}

export function negotiateLagPair(
  srcIface: InterfaceConfig,
  dstIface: InterfaceConfig
): { ok: boolean; protocol: 'lacp' | 'pagp' | 'static'; reason?: string } {
  const srcProto = getLagProtocol(srcIface);
  const dstProto = getLagProtocol(dstIface);
  if (srcIface.lacpGroup === undefined || dstIface.lacpGroup === undefined) {
    return {
      ok: false,
      protocol: srcIface.lacpGroup !== undefined ? srcProto : dstProto,
      reason: 'Port-Channel / LAG membership mismatch (only one end configured in channel-group)',
    };
  }
  if (srcProto !== dstProto) {
    return {
      ok: false,
      protocol: srcProto,
      reason: `LAG protocol mismatch (${srcProto.toUpperCase()} vs ${dstProto.toUpperCase()})`,
    };
  }
  const sMode = srcIface.lacpMode ?? (srcProto === 'pagp' ? 'auto' : srcProto === 'static' ? 'on' : 'active');
  const dMode = dstIface.lacpMode ?? (dstProto === 'pagp' ? 'auto' : dstProto === 'static' ? 'on' : 'active');
  if (srcProto === 'lacp' && sMode === 'passive' && dMode === 'passive') {
    return { ok: false, protocol: 'lacp', reason: 'LACP negotiation failed (both ends passive)' };
  }
  if (srcProto === 'pagp' && sMode === 'auto' && dMode === 'auto') {
    return { ok: false, protocol: 'pagp', reason: 'PAgP negotiation failed (both ends auto)' };
  }
  return { ok: true, protocol: srcProto };
}

function getStpPortCost(node: NodeConfig, ifaceId: string): number {
  const iface = node.interfaces.find((i) => i.id === ifaceId);
  if (!iface) return 4;
  if (iface.stpCost !== undefined) return iface.stpCost;
  if ((iface.speedMbps ?? 1000) >= 10000) return 2;
  if ((iface.speedMbps ?? 1000) >= 1000) return 4;
  return 19;
}

/**
 * Computes IEEE 802.1w RSTP root election & loop blocking on L2 links,
 * plus IEEE 802.1AB LLDP neighbor discovery across active links.
 */
export function computeStpAndLldp(
  topology: TopologyState,
  warnings: string[]
): StpLldpResult {
  const stpByNode = new Map<string, StpNodeState>();
  const lldpByNode = new Map<
    string,
    { localInterface: string; remoteChassisId: string; remotePort: string }[]
  >();
  const blockedL2Ports = new Set<string>();
  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));

  // LLDP neighbor discovery
  for (const node of topology.nodes) {
    if (!node.switching?.lldpEnabled || node.adminDown) continue;
    const neighbors: { localInterface: string; remoteChassisId: string; remotePort: string }[] = [];
    for (const link of topology.links) {
      if (link.adminDown) continue;
      const isSrc = link.sourceNodeId === node.id;
      const isDst = link.targetNodeId === node.id;
      if (!isSrc && !isDst) continue;
      const localIf = node.interfaces.find(
        (i) => i.id === (isSrc ? link.sourceInterfaceId : link.targetInterfaceId)
      );
      const remoteNode = nodeMap.get(isSrc ? link.targetNodeId : link.sourceNodeId);
      const remoteIf = remoteNode?.interfaces.find(
        (i) => i.id === (isSrc ? link.targetInterfaceId : link.sourceInterfaceId)
      );
      if (
        !localIf ||
        localIf.shutdown ||
        !remoteNode ||
        remoteNode.adminDown ||
        !remoteIf ||
        remoteIf.shutdown ||
        !remoteNode.switching?.lldpEnabled
      ) {
        continue;
      }
      neighbors.push({
        localInterface: localIf.name,
        remoteChassisId: remoteNode.hostname,
        remotePort: remoteIf.name,
      });
    }
    if (neighbors.length > 0) lldpByNode.set(node.id, neighbors);
  }

  // RSTP / STP across layer2 links
  const stpNodes = topology.nodes.filter((n) => n.switching?.stpEnabled && !n.adminDown);
  if (stpNodes.length === 0) {
    return { stpByNode, lldpByNode, blockedL2Ports };
  }

  const bridgeId = (n: NodeConfig) =>
    `${n.switching?.stpPriority ?? 32768}.${n.routerId}`;
  const sortedRoots = [...stpNodes].sort((a, b) => {
    const pa = a.switching?.stpPriority ?? 32768;
    const pb = b.switching?.stpPriority ?? 32768;
    if (pa !== pb) return pa - pb;
    return a.routerId.localeCompare(b.routerId);
  });
  const rootNode = sortedRoots[0];
  const rootBid = bridgeId(rootNode);

  // Dijkstra from rootNode over active L2 links
  const dist = new Map<string, number>([[rootNode.id, 0]]);
  const rootLinkByNode = new Map<string, { linkId: string; localIfId: string }>();
  const l2Links = topology.links.filter(
    (l) =>
      !l.adminDown &&
      l.linkType === 'layer2' &&
      nodeMap.get(l.sourceNodeId)?.switching?.stpEnabled &&
      nodeMap.get(l.targetNodeId)?.switching?.stpEnabled
  );

  const visited = new Set<string>();
  while (visited.size < stpNodes.length) {
    let bestNode: NodeConfig | undefined;
    let bestCost = Infinity;
    for (const n of stpNodes) {
      if (visited.has(n.id)) continue;
      const d = dist.get(n.id) ?? Infinity;
      if (d < bestCost) {
        bestCost = d;
        bestNode = n;
      }
    }
    if (!bestNode || bestCost === Infinity) break;
    visited.add(bestNode.id);

    for (const link of l2Links) {
      const isSrc = link.sourceNodeId === bestNode.id;
      const isDst = link.targetNodeId === bestNode.id;
      if (!isSrc && !isDst) continue;
      const nbrId = isSrc ? link.targetNodeId : link.sourceNodeId;
      const nbr = nodeMap.get(nbrId);
      if (!nbr || visited.has(nbrId)) continue;
      const nbrIfId = isSrc ? link.targetInterfaceId : link.sourceInterfaceId;
      const newCost = bestCost + getStpPortCost(nbr, nbrIfId);
      if (newCost < (dist.get(nbrId) ?? Infinity)) {
        dist.set(nbrId, newCost);
        rootLinkByNode.set(nbrId, { linkId: link.id, localIfId: nbrIfId });
      }
    }
  }

  // Assign port roles: Root, Designated (lower root path cost / bridgeId), Alternate (Blocking)
  for (const n of stpNodes) {
    const isRoot = n.id === rootNode.id;
    const ports: StpNodeState['ports'] = [];
    const myCost = dist.get(n.id) ?? Infinity;
    const myRootLink = rootLinkByNode.get(n.id);

    for (const link of l2Links) {
      const isSrc = link.sourceNodeId === n.id;
      const isDst = link.targetNodeId === n.id;
      if (!isSrc && !isDst) continue;
      const localIfId = isSrc ? link.sourceInterfaceId : link.targetInterfaceId;
      const localIf = n.interfaces.find((i) => i.id === localIfId);
      const remoteNode = nodeMap.get(isSrc ? link.targetNodeId : link.sourceNodeId);
      if (!localIf || !remoteNode) continue;

      const remoteIfId = isSrc ? link.targetInterfaceId : link.sourceInterfaceId;
      const remoteIf = remoteNode.interfaces.find((i) => i.id === remoteIfId);
      const sameLagAs = (otherLinkId: string | undefined): boolean => {
        if (!otherLinkId || !remoteIf) return false;
        if (localIf.lacpGroup === undefined || remoteIf.lacpGroup === undefined) return false;
        if (!negotiateLagPair(localIf, remoteIf).ok) return false;
        const other = l2Links.find((l) => l.id === otherLinkId);
        if (!other) return false;
        const oSrc = other.sourceNodeId === n.id;
        const oDst = other.targetNodeId === n.id;
        if (!oSrc && !oDst) return false;
        const oRemoteId = oSrc ? other.targetNodeId : other.sourceNodeId;
        if (oRemoteId !== remoteNode.id) return false;
        const oLocalIf = n.interfaces.find(
          (i) => i.id === (oSrc ? other.sourceInterfaceId : other.targetInterfaceId)
        );
        const oRemoteIf = remoteNode.interfaces.find(
          (i) => i.id === (oSrc ? other.targetInterfaceId : other.sourceInterfaceId)
        );
        return (
          oLocalIf?.lacpGroup === localIf.lacpGroup &&
          oRemoteIf?.lacpGroup === remoteIf.lacpGroup &&
          negotiateLagPair(oLocalIf, oRemoteIf).ok
        );
      };

      if (
        !isRoot &&
        ((myRootLink?.linkId === link.id && myRootLink.localIfId === localIfId) ||
          sameLagAs(myRootLink?.linkId))
      ) {
        ports.push({ interfaceName: localIf.name, role: 'Root', state: 'Forwarding' });
        continue;
      }

      const remoteRootLink = rootLinkByNode.get(remoteNode.id);
      if (remoteRootLink?.linkId === link.id || sameLagAs(remoteRootLink?.linkId)) {
        ports.push({ interfaceName: localIf.name, role: 'Designated', state: 'Forwarding' });
        continue;
      }

      const remoteCost = dist.get(remoteNode.id) ?? Infinity;
      const iWinDesignated =
        myCost < remoteCost ||
        (myCost === remoteCost && bridgeId(n).localeCompare(bridgeId(remoteNode)) < 0);
      if (iWinDesignated) {
        ports.push({ interfaceName: localIf.name, role: 'Designated', state: 'Forwarding' });
      } else {
        ports.push({ interfaceName: localIf.name, role: 'Alternate', state: 'Blocking' });
        blockedL2Ports.add(`${n.id}|${localIf.id}`);
        warnings.push(
          `STP Alternate/Blocking on ${n.hostname}:${localIf.name} (Root: ${rootNode.hostname})`
        );
      }
    }

    stpByNode.set(n.id, {
      rootBridgeId: rootBid,
      isRoot,
      ports,
    });
  }

  return { stpByNode, lldpByNode, blockedL2Ports };
}

/**
 * Generates MPLS LDP, SR-MPLS, SRv6, and RSVP-TE LFIB entries from converged IGP/RIB state.
 */
export function computeMplsLfib(
  topology: TopologyState,
  finalRibByNode: Map<string, RibEntry[]>
): Map<string, LfibEntry[]> {
  const result = new Map<string, LfibEntry[]>();
  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));

  for (const node of topology.nodes) {
    const mpls = node.mpls;
    if (!mpls?.ldpEnabled && !mpls?.segmentRouting?.enabled && !(mpls?.rsvpTeTunnels?.length)) {
      continue;
    }
    const entries: LfibEntry[] = [];
    const rib = finalRibByNode.get(node.id) ?? [];
    let nextLabel = 1600;

    for (const r of rib) {
      if (!r.active || r.protocol === 'local' || r.protocol === 'connected') continue;
      if (r.af === 6 && !mpls.segmentRouting?.srv6Locator) continue;
      if (r.protocol !== 'ospf' && r.protocol !== 'isis' && r.protocol !== 'eigrp') continue;

      const remoteNode = topology.nodes.find((rn) =>
        rn.interfaces.some(
          (i) =>
            !i.shutdown &&
            (parseCidr(i.cidr)?.network === r.prefix ||
              parseCidr(i.cidr)?.ip === r.prefix)
        )
      );
      const isDirectPhp =
        remoteNode &&
        remoteNode.interfaces.some(
          (i) => !i.shutdown && parseCidr(i.cidr)?.ip === r.nextHop
        );

      if (mpls.segmentRouting?.enabled && r.af !== 6) {
        const srgbBase = mpls.segmentRouting.srgbStart ?? 16000;
        const remoteSid = remoteNode?.mpls?.segmentRouting?.prefixSid;
        const sidIndex = remoteSid ?? (nextLabel - 1599);
        const label = srgbBase + sidIndex;
        entries.push({
          inLabel: label,
          outLabel: isDirectPhp ? 'POP' : label,
          prefix: `${r.prefix}/${r.prefixLen}`,
          nextHop: r.nextHop,
          egressInterface: r.egressInterface,
          protocol: 'sr-mpls',
        });
        nextLabel++;
      } else if (mpls.segmentRouting?.srv6Locator && r.af === 6) {
        entries.push({
          inLabel: `${mpls.segmentRouting.srv6Locator}::${r.prefix}`,
          outLabel: isDirectPhp ? 'POP' : `${mpls.segmentRouting.srv6Locator}::${r.prefix}`,
          prefix: `${r.prefix}/${r.prefixLen}`,
          nextHop: r.nextHop,
          egressInterface: r.egressInterface,
          protocol: 'srv6',
        });
      } else if (mpls.ldpEnabled && r.af !== 6) {
        const inLbl = nextLabel++;
        entries.push({
          inLabel: inLbl,
          outLabel: isDirectPhp ? 'POP' : inLbl + 100,
          prefix: `${r.prefix}/${r.prefixLen}`,
          nextHop: r.nextHop,
          egressInterface: r.egressInterface,
          protocol: 'ldp',
        });
      }
    }

    for (const tun of mpls.rsvpTeTunnels ?? []) {
      const dstNode = Array.from(nodeMap.values()).find(
        (n) => n.routerId === tun.destination || n.hostname === tun.destination
      );
      const match = rib.find(
        (r) => r.active && r.af !== 6 && isIpInCidr(tun.destination, `${r.prefix}/${r.prefixLen}`)
      );
      entries.push({
        inLabel: nextLabel++,
        outLabel: dstNode ? nextLabel + 50 : 'POP',
        prefix: `${tun.destination}/32`,
        nextHop: tun.ero?.[0] ?? match?.nextHop ?? tun.destination,
        egressInterface: match?.egressInterface ?? 'Tunnel0',
        protocol: 'rsvp-te',
      });
    }

    if (entries.length > 0) result.set(node.id, entries);
  }

  return result;
}

/**
 * Computes PIM-SM / IGMP multicast mroute table entries using unicast RPF lookups.
 */
export function computeMulticastMroute(
  topology: TopologyState,
  finalRibByNode: Map<string, RibEntry[]>
): Map<string, MrouteEntry[]> {
  const result = new Map<string, MrouteEntry[]>();
  for (const node of topology.nodes) {
    if (!node.multicast?.pimEnabled) continue;
    const rib = finalRibByNode.get(node.id) ?? [];
    const entries: MrouteEntry[] = [];
    const rp = node.multicast.rpAddress;

    for (const grp of node.multicast.igmpGroups ?? []) {
      const targetIp = grp.source || rp;
      let rpfInterface = 'Null0';
      if (targetIp) {
        const matching = rib
          .filter(
            (r) =>
              r.active &&
              r.af !== 6 &&
              isIpInCidr(targetIp, `${r.prefix}/${r.prefixLen}`)
          )
          .sort((a, b) => b.prefixLen - a.prefixLen);
        if (matching[0]) rpfInterface = matching[0].egressInterface;
      }
      const igmpIface = node.interfaces.find((i) => i.id === grp.interfaceId);
      const oifs = new Set<string>();
      if (igmpIface && !igmpIface.shutdown && igmpIface.name !== rpfInterface) {
        oifs.add(igmpIface.name);
      }
      for (const iface of node.interfaces) {
        if (!iface.shutdown && iface.pimSparse && iface.name !== rpfInterface) {
          oifs.add(iface.name);
        }
      }
      entries.push({
        source: grp.source ?? '*',
        group: grp.group,
        rpfInterface,
        oifList: Array.from(oifs),
        rp,
      });
    }
    if (entries.length > 0) result.set(node.id, entries);
  }
  return result;
}

/**
 * Evaluates BGP FlowSpec rules (RFC 8955 / 8956) on a node during packet trace.
 */
export function evaluateFlowspec(
  node: NodeConfig,
  srcIp: string,
  dstIp: string,
  protocol: string,
  dstPort?: number
): { action: 'drop' | 'rate-limit' | 'redirect'; note: string; redirectNextHop?: string } | null {
  for (const rule of node.bgp.flowspecRules ?? []) {
    if (rule.srcCidr && detectAddressFamily(srcIp) === 4 && !isIpInCidr(srcIp, rule.srcCidr)) {
      continue;
    }
    if (rule.dstCidr && detectAddressFamily(dstIp) === 4 && !isIpInCidr(dstIp, rule.dstCidr)) {
      continue;
    }
    if (rule.protocol && rule.protocol !== 'any' && rule.protocol !== protocol) {
      continue;
    }
    if (rule.dstPort !== undefined && rule.dstPort !== dstPort) {
      continue;
    }
    const desc =
      rule.action === 'drop'
        ? `FlowSpec drop (${rule.dstCidr ?? 'any'}${rule.dstPort ? `:${rule.dstPort}` : ''})`
        : rule.action === 'redirect'
          ? `FlowSpec redirect -> ${rule.redirectNextHop}`
          : `FlowSpec rate-limit ${rule.rateMbps ?? 10}Mbps`;
    return { action: rule.action, note: desc, redirectNextHop: rule.redirectNextHop };
  }
  return null;
}

/**
 * Evaluates NAT64 (RFC 6146) prefix translation from IPv6 to embedded IPv4.
 */
export function evaluateNat64(
  node: NodeConfig,
  dstIp: string
): { dstIp: string; note: string } | null {
  if (detectAddressFamily(dstIp) !== 6) return null;
  for (const rule of node.nat64Rules ?? []) {
    const p6 = parseCidr6(rule.prefix6);
    if (!p6 || !isIp6InCidr(dstIp, rule.prefix6)) continue;
    const addr6 = ip6ToBigInt(dstIp);
    const embeddedV4 = Number(addr6 & 0xffffffffn) >>> 0;
    const v4Str = uint32ToIp(embeddedV4);
    return { dstIp: v4Str, note: `NAT64 (${dstIp} -> ${v4Str})` };
  }
  return null;
}

/**
 * Computes EVPN ESI Designated Forwarder (DF) election (RFC 7432) and BMP Adj-RIB-In summaries (RFC 7854).
 */
export function computeEvpnDfAndBmp(
  topology: TopologyState,
  finalRibByNode: Map<string, RibEntry[]>
): {
  evpnDfByNode: Map<string, { esi: string; interfaceName: string; role: 'DF' | 'Backup' }[]>;
  bmpByNode: Map<string, { serverIp: string; peerCount: number; adjRibInCount: number }>;
} {
  const evpnDfByNode = new Map<
    string,
    { esi: string; interfaceName: string; role: 'DF' | 'Backup' }[]
  >();
  const bmpByNode = new Map<
    string,
    { serverIp: string; peerCount: number; adjRibInCount: number }
  >();

  const esiParticipants = new Map<
    string,
    { nodeId: string; routerId: string; ifaceName: string }[]
  >();
  for (const node of topology.nodes) {
    if (node.adminDown) continue;
    for (const iface of node.interfaces) {
      if (iface.shutdown || !iface.evpnEsi) continue;
      const list = esiParticipants.get(iface.evpnEsi) ?? [];
      list.push({ nodeId: node.id, routerId: node.routerId, ifaceName: iface.name });
      esiParticipants.set(iface.evpnEsi, list);
    }

    if (node.telemetry?.bmpServerIp && node.bgp.enabled) {
      const rib = finalRibByNode.get(node.id) ?? [];
      const bgpRoutes = rib.filter((r) => r.protocol === 'ebgp' || r.protocol === 'ibgp').length;
      bmpByNode.set(node.id, {
        serverIp: node.telemetry.bmpServerIp,
        peerCount: node.bgp.peers.filter((p) => !p.shutdown).length,
        adjRibInCount: bgpRoutes,
      });
    }
  }

  for (const [esi, members] of esiParticipants) {
    const sorted = [...members].sort((a, b) => a.routerId.localeCompare(b.routerId));
    sorted.forEach((m, idx) => {
      const list = evpnDfByNode.get(m.nodeId) ?? [];
      list.push({ esi, interfaceName: m.ifaceName, role: idx === 0 ? 'DF' : 'Backup' });
      evpnDfByNode.set(m.nodeId, list);
    });
  }

  return { evpnDfByNode, bmpByNode };
}
