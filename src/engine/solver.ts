import {
  BgpAttributes,
  BgpOriginType,
  FailoverMatrixEntry,
  FibEntry,
  InterfaceConfig,
  L4Protocol,
  LinkConfig,
  NeighborStatus,
  NodeConfig,
  NodeRoutingResult,
  OspfRouteType,
  PacketTraceHop,
  PacketTraceResult,
  PathTestCase,
  ProtocolType,
  RibEntry,
  SimulationResult,
  TopologyState,
} from '../types/network';
import {
  detectAddressFamily,
  ip6ToBigInt,
  ipToUint32,
  isIp6InCidr,
  isIpInCidr,
  parseCidr,
  parseCidr6,
  uint32ToIp,
} from './ipMath';
import { evaluateRouteMap, matchPrefixList, validateRpkiOrigin } from './policy';
import {
  computeEvpnDfAndBmp,
  computeMplsLfib,
  computeMulticastMroute,
  computeStpAndLldp,
  evaluateFlowspec,
  evaluateNat64,
  negotiateLagPair,
  parsePortChannelNumber,
} from './standards';
import { BinaryRadixTrie, BinaryRadixTrie6 } from './radixTrie';
import {
  evaluateAcl,
  evaluatePostRoutingSnat,
  evaluatePreRoutingDnat,
} from './security';
import { getEffectiveAd } from './vendorProfiles';

interface Adjacency {
  localNodeId: string;
  localIface: InterfaceConfig;
  localIp: string;
  localIp6?: string;
  remoteNodeId: string;
  remoteIface: InterfaceConfig;
  remoteIp: string;
  remoteIp6?: string;
  subnet: string;
}

interface CandidateRoute {
  af?: 4 | 6;
  prefix: string;
  prefixLen: number;
  vrf: string;
  protocol: ProtocolType;
  ospfType?: OspfRouteType;
  isisLevel?: 'L1' | 'L2';
  isisUpDownBit?: boolean;
  feasibleSuccessor?: boolean;
  tag?: number;
  ad: number;
  metric: number;
  nextHop: string;
  egressInterface: string;
  leakedFromVrf?: string;
  bgpAttrs?: BgpAttributes;
  originatingNodeId?: string;
  tloc?: RibEntry['tloc'];
  lisp?: RibEntry['lisp'];
  evpnVni?: number;
}

const OSPF_TYPE_RANK: Record<OspfRouteType, number> = {
  intra: 0,
  inter: 1,
  ext1: 2,
  ext2: 3,
};

const BGP_ORIGIN_RANK: Record<BgpOriginType, number> = {
  igp: 0,
  egp: 1,
  incomplete: 2,
};

function formatBfdTag(
  lTx?: number,
  lRx?: number,
  lMult?: number,
  rTx?: number,
  rRx?: number,
  rMult?: number
): string {
  const hasCustom =
    lTx !== undefined ||
    lRx !== undefined ||
    lMult !== undefined ||
    rTx !== undefined ||
    rRx !== undefined ||
    rMult !== undefined;
  if (!hasCustom) return 'BFD';
  const effTx = Math.max(lTx ?? 50, rRx ?? 50);
  const mult = Math.max(lMult ?? 3, rMult ?? 3);
  return `BFD ${effTx}ms x${mult}=${effTx * mult}ms`;
}

function compareIpStrings(a: string, b: string): number {
  return ipToUint32(a) - ipToUint32(b);
}

function getNodeRouterId(node: NodeConfig, vrf = 'default'): string {
  return node.vrfRouterIds?.[vrf]?.trim() || node.routerId;
}

function computeStandbyNodes(topology: TopologyState): Set<string> {
  const standby = new Set<string>();

  const hasUpLinkBetween = (aId: string, aIfId: string | undefined, bId: string): boolean => {
    if (!aIfId) return false;
    return topology.links.some(
      (l) =>
        !l.adminDown &&
        ((l.sourceNodeId === aId && l.sourceInterfaceId === aIfId && l.targetNodeId === bId) ||
          (l.targetNodeId === aId && l.targetInterfaceId === aIfId && l.sourceNodeId === bId))
    );
  };

  for (const node of topology.nodes) {
    if (node.adminDown) continue;

    if (node.vendor === 'pan-os' && node.panHa?.enabled && node.panHa.mode === 'active-passive') {
      const peers = topology.nodes.filter(
        (p) =>
          p.id !== node.id &&
          !p.adminDown &&
          p.vendor === 'pan-os' &&
          p.panHa?.enabled &&
          p.panHa.mode === 'active-passive' &&
          p.panHa.groupId === node.panHa!.groupId &&
          hasUpLinkBetween(node.id, node.panHa!.ha1InterfaceId, p.id)
      );
      const myPrio = node.panHa.devicePriority ?? 100;
      const beaten = peers.some((p) => {
        const peerPrio = p.panHa!.devicePriority ?? 100;
        return peerPrio < myPrio || (peerPrio === myPrio && compareIpStrings(p.routerId, node.routerId) < 0);
      });
      if (beaten) standby.add(node.id);
    }

    if (node.vendor === 'fortigate' && node.fortiHa?.enabled && node.fortiHa.mode === 'a-p') {
      const peers = topology.nodes.filter(
        (p) =>
          p.id !== node.id &&
          !p.adminDown &&
          p.vendor === 'fortigate' &&
          p.fortiHa?.enabled &&
          p.fortiHa.mode === 'a-p' &&
          p.fortiHa.groupId === node.fortiHa!.groupId &&
          hasUpLinkBetween(node.id, node.fortiHa!.hbInterfaceId, p.id)
      );
      const myPrio = node.fortiHa.priority ?? 128;
      const beaten = peers.some((p) => {
        const peerPrio = p.fortiHa!.priority ?? 128;
        return peerPrio > myPrio || (peerPrio === myPrio && compareIpStrings(p.routerId, node.routerId) > 0);
      });
      if (beaten) standby.add(node.id);
    }
  }

  return standby;
}

function isHaControlInterface(node: NodeConfig, ifaceId: string): boolean {
  if (node.panHa?.enabled) {
    if (
      ifaceId === node.panHa.ha1InterfaceId ||
      ifaceId === node.panHa.ha2InterfaceId ||
      ifaceId === node.panHa.ha3HsciInterfaceId
    ) {
      return true;
    }
  }
  if (node.fortiHa?.enabled && ifaceId === node.fortiHa.hbInterfaceId) return true;
  if (node.forcepointCluster?.enabled && ifaceId === node.forcepointCluster.heartbeatInterfaceId) {
    return true;
  }
  return false;
}

function parseAllowedVlanSet(spec?: string): Set<number> | null {
  if (!spec?.trim()) return null;
  const set = new Set<number>();
  for (const part of spec.split(',')) {
    const token = part.trim();
    if (!token) continue;
    const range = token.match(/^(\d+)\s*-\s*(\d+)$/);
    if (range) {
      const a = Number(range[1]);
      const b = Number(range[2]);
      for (let v = Math.min(a, b); v <= Math.max(a, b) && v <= 4094; v++) set.add(v);
    } else if (/^\d+$/.test(token)) {
      set.add(Number(token));
    }
  }
  return set.size > 0 ? set : null;
}

function isVlanAllowedOnLink(vlanId: number | undefined, link: LinkConfig): boolean {
  if (link.linkType !== 'layer2' || vlanId === undefined) return true;
  if (link.l2Mode === 'access') {
    return link.vlanId === undefined || link.vlanId === vlanId;
  }
  const allowed = parseAllowedVlanSet(link.allowedVlans);
  return !allowed || allowed.has(vlanId);
}

function getSubInterfaceInfo(
  iface: InterfaceConfig
): { parentName: string; vlanId?: number } | null {
  const dotIdx = iface.name.lastIndexOf('.');
  const suffix = dotIdx > 0 ? iface.name.slice(dotIdx + 1) : '';
  const suffixVlan = /^\d+$/.test(suffix) ? Number(suffix) : undefined;
  if (iface.parentInterface) {
    return {
      parentName: iface.parentInterface,
      vlanId: iface.vlanId ?? suffixVlan,
    };
  }
  if (dotIdx > 0 && suffixVlan !== undefined) {
    return {
      parentName: iface.name.slice(0, dotIdx),
      vlanId: iface.vlanId ?? suffixVlan,
    };
  }
  return null;
}

function buildAdjacencies(
  topology: TopologyState,
  warnings: string[],
  standbyNodes?: Set<string>,
  blockedL2Ports?: Set<string>
): Map<string, Adjacency[]> {
  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));
  const adjMap = new Map<string, Adjacency[]>();
  for (const n of topology.nodes) adjMap.set(n.id, []);

  const lagBundles = new Map<
    string,
    {
      srcNode: NodeConfig;
      dstNode: NodeConfig;
      srcGroup: number;
      dstGroup: number;
      activeLinks: { link: LinkConfig; srcIf: InterfaceConfig; dstIf: InterfaceConfig }[];
    }
  >();

  const pushEndpointAdjacencies = (
    srcNode: NodeConfig,
    dstNode: NodeConfig,
    srcIface: InterfaceConfig,
    dstIface: InterfaceConfig,
    link: LinkConfig,
    suppressParentUnnumbered: boolean
  ) => {
    const pushL3Pair = (
      sIface: InterfaceConfig,
      dIface: InterfaceConfig,
      suppressUnnumberedWarning: boolean
    ) => {
      const sMtu = sIface.mtu ?? srcIface.mtu ?? (link.linkType === 'ipsec' ? 1400 : 1500);
      const dMtu = dIface.mtu ?? dstIface.mtu ?? (link.linkType === 'ipsec' ? 1400 : 1500);
      if (sMtu !== dMtu) {
        warnings.push(
          `MTU mismatch on link ${srcNode.hostname}:${sIface.name} (${sMtu}B) <-> ${dstNode.hostname}:${dIface.name} (${dMtu}B)`
        );
      }

      const sParsed = parseCidr(sIface.cidr);
      const dParsed = parseCidr(dIface.cidr);
      const sParsed6 = sIface.cidr6 ? parseCidr6(sIface.cidr6) : null;
      const dParsed6 = dIface.cidr6 ? parseCidr6(dIface.cidr6) : null;

      if (!sParsed || !dParsed) {
        if (
          sParsed6 &&
          dParsed6 &&
          sParsed6.network === dParsed6.network &&
          sParsed6.prefixLen === dParsed6.prefixLen
        ) {
          const subnet6 = `${sParsed6.network}/${sParsed6.prefixLen}`;
          adjMap.get(srcNode.id)!.push({
            localNodeId: srcNode.id,
            localIface: sIface,
            localIp: sParsed6.ip,
            localIp6: sParsed6.ip,
            remoteNodeId: dstNode.id,
            remoteIface: dIface,
            remoteIp: dParsed6.ip,
            remoteIp6: dParsed6.ip,
            subnet: subnet6,
          });
          adjMap.get(dstNode.id)!.push({
            localNodeId: dstNode.id,
            localIface: dIface,
            localIp: dParsed6.ip,
            localIp6: dParsed6.ip,
            remoteNodeId: srcNode.id,
            remoteIface: sIface,
            remoteIp: sParsed6.ip,
            remoteIp6: sParsed6.ip,
            subnet: subnet6,
          });
          return;
        }
        if (suppressUnnumberedWarning || link.linkType === 'layer2') {
          return;
        }
        warnings.push(
          `Invalid CIDR on link ${srcNode.hostname}:${sIface.name} <-> ${dstNode.hostname}:${dIface.name}`
        );
        return;
      }

      if (sParsed.network !== dParsed.network || sParsed.prefixLen !== dParsed.prefixLen) {
        warnings.push(
          `Subnet mismatch on link ${srcNode.hostname}:${sIface.name} (${sIface.cidr}) <-> ${dstNode.hostname}:${dIface.name} (${dIface.cidr})`
        );
        return;
      }

      const subnet = `${sParsed.network}/${sParsed.prefixLen}`;
      adjMap.get(srcNode.id)!.push({
        localNodeId: srcNode.id,
        localIface: sIface,
        localIp: sParsed.ip,
        localIp6: sParsed6?.ip,
        remoteNodeId: dstNode.id,
        remoteIface: dIface,
        remoteIp: dParsed.ip,
        remoteIp6: dParsed6?.ip,
        subnet,
      });
      adjMap.get(dstNode.id)!.push({
        localNodeId: dstNode.id,
        localIface: dIface,
        localIp: dParsed.ip,
        localIp6: dParsed6?.ip,
        remoteNodeId: srcNode.id,
        remoteIface: sIface,
        remoteIp: sParsed.ip,
        remoteIp6: sParsed6?.ip,
        subnet,
      });
    };

    const srcSubs = srcNode.interfaces.filter((sub) => {
      if (sub.id === srcIface.id || sub.shutdown) return false;
      const info = getSubInterfaceInfo(sub);
      return info !== null && info.parentName.toLowerCase() === srcIface.name.toLowerCase();
    });
    const dstSubs = dstNode.interfaces.filter((sub) => {
      if (sub.id === dstIface.id || sub.shutdown) return false;
      const info = getSubInterfaceInfo(sub);
      return info !== null && info.parentName.toLowerCase() === dstIface.name.toLowerCase();
    });
    const linkAllowedSet = parseAllowedVlanSet(link.allowedVlans);
    let hasSubInterfaces = false;
    for (const sSub of srcSubs) {
      const sVlan = getSubInterfaceInfo(sSub)?.vlanId;
      if (sVlan === undefined) continue;
      const dSub = dstSubs.find((d) => getSubInterfaceInfo(d)?.vlanId === sVlan);
      if (!dSub) continue;
      hasSubInterfaces = true;
      if (sSub.dot1xState === 'unauthorized' || dSub.dot1xState === 'unauthorized') {
        warnings.push(
          `802.1X port unauthorized on ${sSub.dot1xState === 'unauthorized' ? `${srcNode.hostname}:${sSub.name}` : `${dstNode.hostname}:${dSub.name}`}`
        );
        continue;
      }
      if (Boolean(sSub.macsecEnabled) !== Boolean(dSub.macsecEnabled)) {
        warnings.push(
          `MACsec (802.1AE) mismatch on link ${srcNode.hostname}:${sSub.name} <-> ${dstNode.hostname}:${dSub.name}`
        );
        continue;
      }
      if (
        (link.linkType === 'layer2' && !isVlanAllowedOnLink(sVlan, link)) ||
        (linkAllowedSet && !linkAllowedSet.has(sVlan))
      ) {
        warnings.push(
          `VLAN ${sVlan} not allowed on link ${srcNode.hostname}:${sSub.name} <-> ${dstNode.hostname}:${dSub.name}`
        );
        continue;
      }
      pushL3Pair(sSub, dSub, false);
    }

    pushL3Pair(
      srcIface,
      dstIface,
      suppressParentUnnumbered ||
        ((hasSubInterfaces || srcSubs.length > 0 || dstSubs.length > 0) &&
          !srcIface.cidr?.trim() &&
          !dstIface.cidr?.trim() &&
          !srcIface.cidr6?.trim() &&
          !dstIface.cidr6?.trim())
    );
  };

  for (const link of topology.links) {
    if (link.adminDown) continue;
    const srcNode = nodeMap.get(link.sourceNodeId);
    const dstNode = nodeMap.get(link.targetNodeId);
    if (!srcNode || !dstNode) continue;
    if (srcNode.adminDown || dstNode.adminDown) continue;

    const srcIface = srcNode.interfaces.find((i) => i.id === link.sourceInterfaceId);
    const dstIface = dstNode.interfaces.find((i) => i.id === link.targetInterfaceId);
    if (!srcIface || !dstIface) continue;
    if (srcIface.shutdown || dstIface.shutdown) continue;
    if (srcIface.dot1xState === 'unauthorized' || dstIface.dot1xState === 'unauthorized') {
      warnings.push(
        `802.1X port unauthorized on ${srcIface.dot1xState === 'unauthorized' ? `${srcNode.hostname}:${srcIface.name}` : `${dstNode.hostname}:${dstIface.name}`}`
      );
      continue;
    }
    if (Boolean(srcIface.macsecEnabled) !== Boolean(dstIface.macsecEnabled)) {
      warnings.push(
        `MACsec (802.1AE) mismatch on link ${srcNode.hostname}:${srcIface.name} <-> ${dstNode.hostname}:${dstIface.name}`
      );
      continue;
    }
    if (link.linkType === 'ipsec' && link.ipsecConfig) {
      const { ikeVersion, remoteIkeVersion, cryptoProfile, remoteCryptoProfile } = link.ipsecConfig;
      if (remoteIkeVersion && ikeVersion && remoteIkeVersion !== ikeVersion) {
        warnings.push(
          `IPsec IKE version mismatch (${ikeVersion} vs ${remoteIkeVersion}) on ${srcNode.hostname}:${srcIface.name} <-> ${dstNode.hostname}:${dstIface.name}`
        );
        continue;
      }
      if (remoteCryptoProfile && cryptoProfile && remoteCryptoProfile !== cryptoProfile) {
        warnings.push(
          `IPsec crypto-profile mismatch (${cryptoProfile} vs ${remoteCryptoProfile}) on ${srcNode.hostname}:${srcIface.name} <-> ${dstNode.hostname}:${dstIface.name}`
        );
        continue;
      }
    }

    if (
      blockedL2Ports &&
      (blockedL2Ports.has(`${srcNode.id}|${srcIface.id}`) ||
        blockedL2Ports.has(`${dstNode.id}|${dstIface.id}`))
    ) {
      continue;
    }

    if (
      standbyNodes &&
      (standbyNodes.has(srcNode.id) || standbyNodes.has(dstNode.id)) &&
      !(isHaControlInterface(srcNode, srcIface.id) && isHaControlInterface(dstNode, dstIface.id))
    ) {
      continue;
    }

    let isLagMember = false;
    if (srcIface.lacpGroup !== undefined || dstIface.lacpGroup !== undefined) {
      const lagNeg = negotiateLagPair(srcIface, dstIface);
      if (!lagNeg.ok) {
        warnings.push(
          `${lagNeg.reason} on ${srcNode.hostname}:${srcIface.name} <-> ${dstNode.hostname}:${dstIface.name}`
        );
        continue;
      }
      isLagMember = true;
      const bKey = `${srcNode.id}:${srcIface.lacpGroup}|${dstNode.id}:${dstIface.lacpGroup}`;
      const existing = lagBundles.get(bKey);
      if (existing) {
        existing.activeLinks.push({ link, srcIf: srcIface, dstIf: dstIface });
      } else {
        lagBundles.set(bKey, {
          srcNode,
          dstNode,
          srcGroup: srcIface.lacpGroup!,
          dstGroup: dstIface.lacpGroup!,
          activeLinks: [{ link, srcIf: srcIface, dstIf: dstIface }],
        });
      }
    }

    const effectiveSrcVlan = srcIface.vlanId ?? (link.linkType === 'layer2' ? link.vlanId : undefined);
    const effectiveDstVlan = dstIface.vlanId ?? (link.linkType === 'layer2' ? link.vlanId : undefined);
    if (
      effectiveSrcVlan !== undefined &&
      effectiveDstVlan !== undefined &&
      effectiveSrcVlan !== effectiveDstVlan
    ) {
      warnings.push(
        `VLAN mismatch on link ${srcNode.hostname}:${srcIface.name} (VLAN ${effectiveSrcVlan}) <-> ${dstNode.hostname}:${dstIface.name} (VLAN ${effectiveDstVlan})`
      );
      continue;
    }
    if (
      !isVlanAllowedOnLink(effectiveSrcVlan, link) ||
      !isVlanAllowedOnLink(effectiveDstVlan, link)
    ) {
      warnings.push(
        `VLAN ${effectiveSrcVlan ?? effectiveDstVlan} not allowed on L2 link ${srcNode.hostname}:${srcIface.name} <-> ${dstNode.hostname}:${dstIface.name}`
      );
      continue;
    }

    pushEndpointAdjacencies(
      srcNode,
      dstNode,
      srcIface,
      dstIface,
      link,
      isLagMember &&
        !srcIface.cidr?.trim() &&
        !dstIface.cidr?.trim() &&
        !srcIface.cidr6?.trim() &&
        !dstIface.cidr6?.trim()
    );
  }

  // Aggregate active LAG / EtherChannel member links into logical Port-Channel adjacencies
  for (const bundle of lagBundles.values()) {
    const srcSpeeds = new Set(
      bundle.activeLinks.map((a) => a.srcIf.speedMbps).filter((s): s is number => s !== undefined)
    );
    if (srcSpeeds.size > 1) {
      warnings.push(
        `Port-Channel${bundle.srcGroup} member speed mismatch on ${bundle.srcNode.hostname}`
      );
    }
    const dstSpeeds = new Set(
      bundle.activeLinks.map((a) => a.dstIf.speedMbps).filter((s): s is number => s !== undefined)
    );
    if (dstSpeeds.size > 1) {
      warnings.push(
        `Port-Channel${bundle.dstGroup} member speed mismatch on ${bundle.dstNode.hostname}`
      );
    }

    const srcPo = bundle.srcNode.interfaces.find(
      (i) => !i.shutdown && parsePortChannelNumber(i.name) === bundle.srcGroup && getSubInterfaceInfo(i) === null
    );
    const dstPo = bundle.dstNode.interfaces.find(
      (i) => !i.shutdown && parsePortChannelNumber(i.name) === bundle.dstGroup && getSubInterfaceInfo(i) === null
    );
    if (!srcPo || !dstPo) continue;
    if (srcPo.dot1xState === 'unauthorized' || dstPo.dot1xState === 'unauthorized') continue;
    if (Boolean(srcPo.macsecEnabled) !== Boolean(dstPo.macsecEnabled)) {
      warnings.push(
        `MACsec (802.1AE) mismatch on ${bundle.srcNode.hostname}:${srcPo.name} <-> ${bundle.dstNode.hostname}:${dstPo.name}`
      );
      continue;
    }

    // Use the lowest-latency active member link as representative physical transport (preserving allowedVlans / linkType)
    const repLink = [...bundle.activeLinks].sort(
      (a, b) => (a.link.latencyMs ?? 0) - (b.link.latencyMs ?? 0)
    )[0].link;
    pushEndpointAdjacencies(
      bundle.srcNode,
      bundle.dstNode,
      srcPo,
      dstPo,
      repLink,
      !srcPo.cidr?.trim() && !dstPo.cidr?.trim() && !srcPo.cidr6?.trim() && !dstPo.cidr6?.trim()
    );
  }

  // Bridge L3 endpoints across unnumbered Layer 2 links/switches sharing the same VLAN
  const l2Graph = new Map<string, { nodeId: string; vlan?: number; link: LinkConfig }[]>();
  for (const link of topology.links) {
    if (link.adminDown || link.linkType !== 'layer2') continue;
    const sNode = nodeMap.get(link.sourceNodeId);
    const dNode = nodeMap.get(link.targetNodeId);
    const sIf = sNode?.interfaces.find((i) => i.id === link.sourceInterfaceId);
    const dIf = dNode?.interfaces.find((i) => i.id === link.targetInterfaceId);
    if (!sNode || !dNode || !sIf || !dIf || sIf.shutdown || dIf.shutdown || sNode.adminDown || dNode.adminDown) {
      continue;
    }
    const sv = sIf.vlanId ?? link.vlanId;
    const dv = dIf.vlanId ?? link.vlanId;
    if (sv !== undefined && dv !== undefined && sv !== dv) continue;
    const vlan = sv ?? dv;
    if (!isVlanAllowedOnLink(vlan, link)) continue;
    if (!l2Graph.has(sNode.id)) l2Graph.set(sNode.id, []);
    if (!l2Graph.has(dNode.id)) l2Graph.set(dNode.id, []);
    l2Graph.get(sNode.id)!.push({ nodeId: dNode.id, vlan, link });
    l2Graph.get(dNode.id)!.push({ nodeId: sNode.id, vlan, link });
  }

  if (l2Graph.size > 0) {
    const isUnnumberedSwitch = (n: NodeConfig) =>
      n.interfaces.every((i) => !parseCidr(i.cidr) && !(i.cidr6 && parseCidr6(i.cidr6)));

    for (const [startId, edges] of l2Graph.entries()) {
      const startNode = nodeMap.get(startId);
      if (!startNode || isUnnumberedSwitch(startNode)) continue;
      for (const firstEdge of edges) {
        const firstPeer = nodeMap.get(firstEdge.nodeId);
        if (!firstPeer || !isUnnumberedSwitch(firstPeer)) continue;
        const targetVlan = firstEdge.vlan;
        const visited = new Set<string>([startId, firstEdge.nodeId]);
        const queue: string[] = [firstEdge.nodeId];
        while (queue.length > 0) {
          const cur = queue.shift()!;
          for (const nxt of l2Graph.get(cur) ?? []) {
            if (visited.has(nxt.nodeId)) continue;
            if (targetVlan !== undefined && nxt.vlan !== undefined && nxt.vlan !== targetVlan) continue;
            if (!isVlanAllowedOnLink(targetVlan ?? nxt.vlan, nxt.link)) continue;
            visited.add(nxt.nodeId);
            const peerNode = nodeMap.get(nxt.nodeId);
            if (!peerNode) continue;
            if (isUnnumberedSwitch(peerNode)) {
              queue.push(nxt.nodeId);
              continue;
            }
            for (const sIf of startNode.interfaces) {
              if (sIf.shutdown) continue;
              const sp = parseCidr(sIf.cidr);
              if (!sp) continue;
              if (targetVlan !== undefined && sIf.vlanId !== undefined && sIf.vlanId !== targetVlan) continue;
              for (const pIf of peerNode.interfaces) {
                if (pIf.shutdown) continue;
                const pp = parseCidr(pIf.cidr);
                if (!pp || sp.network !== pp.network || sp.prefixLen !== pp.prefixLen) continue;
                if (targetVlan !== undefined && pIf.vlanId !== undefined && pIf.vlanId !== targetVlan) continue;
                if ((sIf.vlanId ?? targetVlan) !== (pIf.vlanId ?? targetVlan)) continue;
                const already = (adjMap.get(startId) ?? []).some(
                  (a) => a.remoteNodeId === peerNode.id && a.localIface.id === sIf.id && a.remoteIface.id === pIf.id
                );
                if (!already) {
                  const subnet = `${sp.network}/${sp.prefixLen}`;
                  adjMap.get(startId)!.push({
                    localNodeId: startId,
                    localIface: sIf,
                    localIp: sp.ip,
                    remoteNodeId: peerNode.id,
                    remoteIface: pIf,
                    remoteIp: pp.ip,
                    subnet,
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  return adjMap;
}

function buildActiveTrie(entries: RibEntry[], vrf: string): BinaryRadixTrie<RibEntry[]> {
  const trie = new BinaryRadixTrie<RibEntry[]>();
  const grouped = new Map<string, RibEntry[]>();

  for (const e of entries) {
    if (!e.active || e.vrf !== vrf || (e.af ?? 4) !== 4) continue;
    const key = `${e.prefix}/${e.prefixLen}`;
    const list = grouped.get(key);
    if (list) list.push(e);
    else grouped.set(key, [e]);
  }

  for (const [cidr, list] of grouped) {
    const parsed = parseCidr(cidr);
    if (parsed) {
      trie.insert(parsed.networkUint32, parsed.prefixLen, list);
    }
  }
  return trie;
}

function buildActiveTrie6(entries: RibEntry[], vrf: string): BinaryRadixTrie6<RibEntry[]> {
  const trie = new BinaryRadixTrie6<RibEntry[]>();
  const grouped = new Map<string, RibEntry[]>();

  for (const e of entries) {
    if (!e.active || e.vrf !== vrf || e.af !== 6) continue;
    const key = `${e.prefix}/${e.prefixLen}`;
    const list = grouped.get(key);
    if (list) list.push(e);
    else grouped.set(key, [e]);
  }

  for (const [cidr, list] of grouped) {
    const parsed = parseCidr6(cidr);
    if (parsed) {
      trie.insert(parsed.networkBigInt, parsed.prefixLen, list);
    }
  }
  return trie;
}

function resolveNextHop(
  nextHop: string,
  explicitInterface: string | undefined,
  vrf: string,
  currentRib: RibEntry[],
  node: NodeConfig,
  leakedFromVrf?: string
): { resolvable: boolean; egressInterface: string; igpMetric: number } {
  const lookupVrf = leakedFromVrf ?? vrf;

  if (explicitInterface) {
    const iface = node.interfaces.find(
      (i) => i.name === explicitInterface && !i.shutdown && (i.vrf || 'default') === lookupVrf
    );
    if (iface) {
      return { resolvable: true, egressInterface: iface.name, igpMetric: 0 };
    }
  }

  if (nextHop === '0.0.0.0' || nextHop === '::') {
    return { resolvable: true, egressInterface: explicitInterface ?? '', igpMetric: 0 };
  }

  const af = detectAddressFamily(nextHop);
  if (!af) {
    return { resolvable: false, egressInterface: '', igpMetric: Infinity };
  }

  for (const iface of node.interfaces) {
    if (iface.shutdown || (iface.vrf || 'default') !== lookupVrf) continue;
    if (af === 4 && isIpInCidr(nextHop, iface.cidr)) {
      return { resolvable: true, egressInterface: iface.name, igpMetric: 0 };
    }
    if (af === 6 && iface.cidr6 && isIp6InCidr(nextHop, iface.cidr6)) {
      return { resolvable: true, egressInterface: iface.name, igpMetric: 0 };
    }
  }

  const trie4 = af === 4 ? buildActiveTrie(currentRib, lookupVrf) : null;
  const trie6 = af === 6 ? buildActiveTrie6(currentRib, lookupVrf) : null;
  let targetIp = nextHop;
  let totalMetric = 0;
  const visited = new Set<string>();

  for (let depth = 0; depth < 8; depth++) {
    if (visited.has(targetIp)) {
      return { resolvable: false, egressInterface: '', igpMetric: Infinity };
    }
    visited.add(targetIp);

    const match =
      af === 4
        ? trie4!.longestPrefixMatch(ipToUint32(targetIp))
        : trie6!.longestPrefixMatch(ip6ToBigInt(targetIp));
    if (!match || match.length === 0) {
      return { resolvable: false, egressInterface: '', igpMetric: Infinity };
    }
    const best = match[0];
    if (best.protocol === 'connected') {
      return { resolvable: true, egressInterface: best.egressInterface, igpMetric: totalMetric };
    }
    if (best.protocol === 'local') {
      return { resolvable: false, egressInterface: '', igpMetric: Infinity };
    }
    totalMetric += best.metric;
    if (best.egressInterface) {
      return { resolvable: true, egressInterface: best.egressInterface, igpMetric: totalMetric };
    }
    targetIp = best.nextHop;
  }

  return { resolvable: false, egressInterface: '', igpMetric: Infinity };
}

function compareBgpCandidates(
  a: CandidateRoute,
  b: CandidateRoute,
  opts?: {
    alwaysCompareMed?: boolean;
    bestpathAsPathIgnore?: boolean;
    medMissingAsWorst?: boolean;
    ignoreTieBreakers?: boolean;
  }
): number {
  const ba = a.bgpAttrs!;
  const bb = b.bgpAttrs!;
  if (ba.weight !== bb.weight) return bb.weight - ba.weight;
  // RFC 8326: graceful-shutdown (65535:0) lowers effective LOCAL_PREF to 0
  const lpA =
    ba.communities?.includes('graceful-shutdown') || ba.communities?.includes('65535:0')
      ? 0
      : ba.localPref;
  const lpB =
    bb.communities?.includes('graceful-shutdown') || bb.communities?.includes('65535:0')
      ? 0
      : bb.localPref;
  if (lpA !== lpB) return lpB - lpA;
  if (ba.locallyOriginated !== bb.locallyOriginated) {
    return ba.locallyOriginated ? -1 : 1;
  }
  if (!opts?.bestpathAsPathIgnore && ba.asPath.length !== bb.asPath.length) {
    return ba.asPath.length - bb.asPath.length;
  }
  const origDiff = BGP_ORIGIN_RANK[ba.origin] - BGP_ORIGIN_RANK[bb.origin];
  if (origDiff !== 0) return origDiff;
  if (opts?.alwaysCompareMed || ba.asPath[0] === bb.asPath[0]) {
    const medA =
      opts?.medMissingAsWorst && ba.med === undefined ? Number.MAX_SAFE_INTEGER : (ba.med ?? 0);
    const medB =
      opts?.medMissingAsWorst && bb.med === undefined ? Number.MAX_SAFE_INTEGER : (bb.med ?? 0);
    if (medA !== medB) return medA - medB;
  }
  if (ba.isEbgp !== bb.isEbgp) return ba.isEbgp ? -1 : 1;
  if (ba.aigpMetric !== undefined && bb.aigpMetric !== undefined && ba.aigpMetric !== bb.aigpMetric) {
    return ba.aigpMetric - bb.aigpMetric;
  }
  if (ba.igpMetric !== bb.igpMetric) return ba.igpMetric - bb.igpMetric;
  if (opts?.ignoreTieBreakers) return 0;
  const ridDiff = compareIpStrings(ba.peerRouterId, bb.peerRouterId);
  if (ridDiff !== 0) return ridDiff;
  return compareIpStrings(ba.peerIp, bb.peerIp);
}

function applyRouteMapCommunities(
  set: {
    setCommunity?: string;
    setCommunityAdditive?: boolean;
    deleteCommunity?: string;
    setLargeCommunity?: string;
    setLargeCommunityAdditive?: boolean;
    deleteLargeCommunity?: string;
  },
  communities: string[],
  largeCommunities: string[]
): { communities: string[]; largeCommunities: string[] } {
  let nextComms = [...communities];
  let nextLarge = [...largeCommunities];
  if (set.setCommunity) {
    nextComms =
      set.setCommunityAdditive === false
        ? [set.setCommunity]
        : nextComms.includes(set.setCommunity)
          ? nextComms
          : [...nextComms, set.setCommunity];
  }
  if (set.deleteCommunity) {
    nextComms = nextComms.filter((c) => c !== set.deleteCommunity);
  }
  if (set.setLargeCommunity) {
    nextLarge =
      set.setLargeCommunityAdditive === false
        ? [set.setLargeCommunity]
        : nextLarge.includes(set.setLargeCommunity)
          ? nextLarge
          : [...nextLarge, set.setLargeCommunity];
  }
  if (set.deleteLargeCommunity) {
    nextLarge = nextLarge.filter((c) => c !== set.deleteLargeCommunity);
  }
  return { communities: nextComms, largeCommunities: nextLarge };
}

function matchesRedistSource(
  from: NodeConfig['redistributions'][number]['from'],
  protocol: ProtocolType
): boolean {
  if (from === 'bgp') return protocol === 'ebgp' || protocol === 'ibgp';
  return from === protocol;
}

function getOspfInterfaceCost(iface: NodeConfig['interfaces'][number], node: NodeConfig): number {
  if (node.ospf.maxMetricRouterLsa) return 65535;
  if (iface.ospfCost !== undefined) return iface.ospfCost;
  if (iface.speedMbps !== undefined || node.ospf.referenceBandwidth !== undefined) {
    const refBw = node.ospf.referenceBandwidth ?? 100;
    const speed = iface.speedMbps ?? 1000;
    return Math.max(1, Math.floor(refBw / Math.max(speed, 1)));
  }
  return 10;
}

function solveOspf(
  topology: TopologyState,
  adjMap: Map<string, Adjacency[]>,
  activeRibByNode: Map<string, RibEntry[]>,
  warnings?: string[]
): Map<string, CandidateRoute[]> {
  const ospfCandidates = new Map<string, CandidateRoute[]>();
  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));

  interface OspfLsa {
    af?: 4 | 6;
    prefix: string;
    prefixLen: number;
    vrf: string;
    area: number;
    ospfType: OspfRouteType;
    metric: number;
    internalMetric?: number;
    nextHop: string;
    egressInterface: string;
    viaNodeId: string;
    tag?: number;
  }

  const normalizeOspfAreaOption = (t?: 'normal' | 'stub' | 'totally-stubby' | 'nssa') => {
    if (!t || t === 'normal') return 'normal';
    if (t === 'nssa') return 'nssa';
    return 'stub';
  };

  const nodeLsas = new Map<string, Map<string, OspfLsa>>();
  for (const node of topology.nodes) {
    ospfCandidates.set(node.id, []);
    nodeLsas.set(node.id, new Map());
    if (!node.ospf.enabled) continue;

    const lsaMap = nodeLsas.get(node.id)!;

    for (const iface of node.interfaces) {
      if (iface.shutdown || iface.ospfArea === undefined) continue;
      const vrf = iface.vrf || 'default';
      const cost = getOspfInterfaceCost(iface, node);
      const parsed = parseCidr(iface.cidr);
      if (parsed) {
        const prefix = `${parsed.network}/${parsed.prefixLen}`;
        const key = `4|${vrf}|${prefix}|${iface.ospfArea}|intra`;
        lsaMap.set(key, {
          af: 4,
          prefix: parsed.network,
          prefixLen: parsed.prefixLen,
          vrf,
          area: iface.ospfArea,
          ospfType: 'intra',
          metric: cost,
          nextHop: '0.0.0.0',
          egressInterface: iface.name,
          viaNodeId: node.id,
        });
      }
      if (iface.cidr6) {
        const parsed6 = parseCidr6(iface.cidr6);
        if (parsed6) {
          const prefix6 = `${parsed6.network}/${parsed6.prefixLen}`;
          const key6 = `6|${vrf}|${prefix6}|${iface.ospfArea}|intra`;
          lsaMap.set(key6, {
            af: 6,
            prefix: parsed6.network,
            prefixLen: parsed6.prefixLen,
            vrf,
            area: iface.ospfArea,
            ospfType: 'intra',
            metric: cost,
            nextHop: '::',
            egressInterface: iface.name,
            viaNodeId: node.id,
          });
        }
      }
    }

    for (const net of node.ospf.networks) {
      const parsed = parseCidr(net.prefix);
      if (!parsed) continue;
      const vrf = net.vrf || 'default';
      const rType = net.routeType ?? 'intra';
      const cost = net.cost ?? 10;
      const key = `4|${vrf}|${parsed.network}/${parsed.prefixLen}|${net.area}|${rType}`;
      lsaMap.set(key, {
        af: 4,
        prefix: parsed.network,
        prefixLen: parsed.prefixLen,
        vrf,
        area: net.area,
        ospfType: rType,
        metric: cost,
        nextHop: '0.0.0.0',
        egressInterface: '',
        viaNodeId: node.id,
        tag: net.tag,
      });
    }

    if (node.ospf.defaultOriginate) {
      lsaMap.set('4|default|0.0.0.0/0|0|ext2', {
        af: 4,
        prefix: '0.0.0.0',
        prefixLen: 0,
        vrf: 'default',
        area: 0,
        ospfType: 'ext2',
        metric: 1,
        nextHop: '0.0.0.0',
        egressInterface: '',
        viaNodeId: node.id,
      });
    }

    const currentRib = activeRibByNode.get(node.id) ?? [];
    for (const rule of node.redistributions) {
      if (rule.to !== 'ospf') continue;
      const ruleVrf = rule.vrf || 'default';
      const rm = rule.routeMapId
        ? node.routeMaps.find((m) => m.id === rule.routeMapId)
        : undefined;

      for (const r of currentRib) {
        if (!r.active || r.vrf !== ruleVrf || r.af === 6) continue;
        if (!matchesRedistSource(rule.from, r.protocol)) continue;

        let rType: OspfRouteType = rule.metricType === 'E1' ? 'ext1' : 'ext2';
        let cost = rule.metric ?? 20;
        let tag = r.tag;

        if (rm) {
          const evalRes = evaluateRouteMap(
            r.prefix,
            r.prefixLen,
            rm,
            node.prefixLists ?? [],
            { tag: r.tag }
          );
          if (!evalRes.permitted) continue;
          if (evalRes.set.setOspfMetricType) {
            rType = evalRes.set.setOspfMetricType === 'E1' ? 'ext1' : 'ext2';
          }
          if (evalRes.set.setMed !== undefined) {
            cost = evalRes.set.setMed;
          }
          if (evalRes.set.setTag !== undefined) {
            tag = evalRes.set.setTag;
          }
        }

        const key = `4|${r.vrf}|${r.prefix}/${r.prefixLen}|0|${rType}`;
        if (!lsaMap.has(key)) {
          lsaMap.set(key, {
            af: 4,
            prefix: r.prefix,
            prefixLen: r.prefixLen,
            vrf: r.vrf,
            area: 0,
            ospfType: rType,
            metric: cost,
            nextHop: r.nextHop,
            egressInterface: r.egressInterface,
            viaNodeId: node.id,
            tag,
          });
        }
      }
    }
  }

  const maxHops = Math.max(topology.nodes.length, 4);
  for (let step = 0; step < maxHops; step++) {
    let changed = false;
    for (const node of topology.nodes) {
      if (!node.ospf.enabled) continue;
      const adjs = adjMap.get(node.id) ?? [];
      const myMap = nodeLsas.get(node.id)!;

      for (const adj of adjs) {
        const remoteNode = nodeMap.get(adj.remoteNodeId);
        if (!remoteNode || !remoteNode.ospf.enabled) continue;
        if (adj.localIface.passive || adj.remoteIface.passive) continue;
        const localVrf = adj.localIface.vrf || 'default';
        const remoteVrf = adj.remoteIface.vrf || 'default';
        if (
          adj.localIface.ospfArea === undefined ||
          adj.remoteIface.ospfArea === undefined ||
          adj.localIface.ospfArea !== adj.remoteIface.ospfArea
        ) {
          continue;
        }
        const localAuth = adj.localIface.ospfAuthKey ?? node.ospf.authKey ?? '';
        const remoteAuth = adj.remoteIface.ospfAuthKey ?? remoteNode.ospf.authKey ?? '';
        if (localAuth !== remoteAuth) {
          const msg = `OSPF auth key mismatch on ${node.hostname}:${adj.localIface.name} <-> ${remoteNode.hostname}:${adj.remoteIface.name}`;
          if (warnings && !warnings.includes(msg)) warnings.push(msg);
          continue;
        }
        const localHello = adj.localIface.ospfHelloInterval ?? 10;
        const remoteHello = adj.remoteIface.ospfHelloInterval ?? 10;
        const localDead = adj.localIface.ospfDeadInterval ?? 40;
        const remoteDead = adj.remoteIface.ospfDeadInterval ?? 40;
        if (localHello !== remoteHello || localDead !== remoteDead) {
          const msg = `OSPF timer mismatch on ${node.hostname}:${adj.localIface.name} (H:${localHello}/D:${localDead}) <-> ${remoteNode.hostname}:${adj.remoteIface.name} (H:${remoteHello}/D:${remoteDead})`;
          if (warnings && !warnings.includes(msg)) warnings.push(msg);
          continue;
        }
        const linkArea = adj.localIface.ospfArea;
        const localAreaRaw = node.ospf.areaTypes?.[linkArea] ?? 'normal';
        const remoteAreaRaw = remoteNode.ospf.areaTypes?.[linkArea] ?? 'normal';
        if (normalizeOspfAreaOption(localAreaRaw) !== normalizeOspfAreaOption(remoteAreaRaw)) {
          const msg = `OSPF area ${linkArea} type mismatch on ${node.hostname}:${adj.localIface.name} (${localAreaRaw}) <-> ${remoteNode.hostname}:${adj.remoteIface.name} (${remoteAreaRaw})`;
          if (warnings && !warnings.includes(msg)) warnings.push(msg);
          continue;
        }
        const localMtu = adj.localIface.mtu ?? 1500;
        const remoteMtu = adj.remoteIface.mtu ?? 1500;
        if (localMtu !== remoteMtu) {
          const msg = `OSPF MTU mismatch on ${node.hostname}:${adj.localIface.name} (${localMtu}) <-> ${remoteNode.hostname}:${adj.remoteIface.name} (${remoteMtu})`;
          if (warnings && !warnings.includes(msg)) warnings.push(msg);
          continue;
        }
        const isOspfP2p =
          adj.localIface.ospfNetworkType === 'point-to-point' ||
          adj.localIface.ospfNetworkType === 'point-to-multipoint';
        if (!isOspfP2p && (adj.localIface.ospfPriority ?? 1) === 0 && (adj.remoteIface.ospfPriority ?? 1) === 0) {
          continue;
        }

        const nodeAreas = new Set<number>();
        for (const iface of node.interfaces) {
          if (
            !iface.shutdown &&
            (iface.vrf || 'default') === localVrf &&
            iface.ospfArea !== undefined
          ) {
            nodeAreas.add(iface.ospfArea);
          }
        }
        const isAbr = nodeAreas.size > 1 && nodeAreas.has(0);

        const linkAreaType =
          node.ospf.areaTypes?.[linkArea] ??
          remoteNode.ospf.areaTypes?.[linkArea] ??
          'normal';
        const linkCost = getOspfInterfaceCost(adj.localIface, node);
        const remoteMap = nodeLsas.get(remoteNode.id)!;

        const isNssaNoSummary =
          linkAreaType === 'nssa' &&
          Boolean(
            node.ospf.nssaNoSummary?.[linkArea] ?? remoteNode.ospf.nssaNoSummary?.[linkArea]
          );
        if (
          (linkAreaType === 'stub' || linkAreaType === 'totally-stubby' || isNssaNoSummary) &&
          linkArea !== 0 &&
          remoteNode.interfaces.some(
            (i) => (i.vrf || 'default') === remoteVrf && i.ospfArea === 0
          )
        ) {
          const defKey = `4|${localVrf}|0.0.0.0/0|${linkArea}|inter`;
          if (!myMap.has(defKey)) {
            myMap.set(defKey, {
              af: 4,
              prefix: '0.0.0.0',
              prefixLen: 0,
              vrf: localVrf,
              area: linkArea,
              ospfType: 'inter',
              metric: linkCost + 1,
              nextHop: adj.remoteIp,
              egressInterface: adj.localIface.name,
              viaNodeId: remoteNode.id,
            });
            changed = true;
          }
        }

        for (const rLsa of remoteMap.values()) {
          if (rLsa.viaNodeId === node.id || rLsa.vrf !== remoteVrf) continue;
          if (
            (linkAreaType === 'stub' || linkAreaType === 'totally-stubby') &&
            (rLsa.ospfType === 'ext1' || rLsa.ospfType === 'ext2')
          ) {
            continue;
          }
          if (
            (linkAreaType === 'totally-stubby' || isNssaNoSummary) &&
            rLsa.ospfType === 'inter' &&
            rLsa.prefix !== '0.0.0.0'
          ) {
            continue;
          }
          if (
            linkAreaType === 'nssa' &&
            (rLsa.ospfType === 'ext1' || rLsa.ospfType === 'ext2') &&
            rLsa.area !== linkArea
          ) {
            continue;
          }

          let propagatedType: OspfRouteType | null = null;
          let propagatedArea = linkArea;
          let propagatedMetric = rLsa.metric;
          let propagatedInternalMetric = rLsa.internalMetric ?? 0;

          if (rLsa.ospfType === 'intra') {
            if (rLsa.area === linkArea) {
              propagatedType = 'intra';
              propagatedMetric = rLsa.metric + linkCost;
            } else if (
              isAbr ||
              remoteNode.interfaces.some(
                (i) => (i.vrf || 'default') === remoteVrf && i.ospfArea === 0
              )
            ) {
              propagatedType = 'inter';
              propagatedArea = linkArea;
              propagatedMetric = rLsa.metric + linkCost;
            }
          } else if (rLsa.ospfType === 'inter') {
            propagatedType = 'inter';
            propagatedArea = linkArea;
            propagatedMetric = rLsa.metric + linkCost;
          } else if (rLsa.ospfType === 'ext1') {
            propagatedType = 'ext1';
            propagatedMetric = rLsa.metric + linkCost;
          } else if (rLsa.ospfType === 'ext2') {
            propagatedType = 'ext2';
            propagatedMetric = rLsa.metric;
            propagatedInternalMetric = (rLsa.internalMetric ?? 0) + linkCost;
          }

          if (!propagatedType) continue;

          if ((remoteNode.ospf.areaRanges?.length ?? 0) > 0 && rLsa.area !== propagatedArea) {
            const matchedRange = (remoteNode.ospf.areaRanges ?? []).find((ar) => {
              if (ar.area !== rLsa.area) return false;
              const ap = parseCidr(ar.prefix);
              return ap && rLsa.prefixLen > ap.prefixLen && isIpInCidr(rLsa.prefix, ar.prefix);
            });
            if (matchedRange) {
              const ap = parseCidr(matchedRange.prefix);
              if (ap) {
                const sumKey = `${rLsa.af ?? 4}|${localVrf}|${ap.network}/${ap.prefixLen}|${propagatedArea}|inter`;
                const exSum = myMap.get(sumKey);
                if (!exSum || propagatedMetric < exSum.metric) {
                  myMap.set(sumKey, {
                    af: rLsa.af,
                    prefix: ap.network,
                    prefixLen: ap.prefixLen,
                    vrf: localVrf,
                    area: propagatedArea,
                    ospfType: 'inter',
                    metric: propagatedMetric,
                    nextHop: adj.remoteIp,
                    egressInterface: adj.localIface.name,
                    viaNodeId: remoteNode.id,
                  });
                  changed = true;
                }
              }
              continue;
            }
          }

          const originKey = `${rLsa.af ?? 4}|${localVrf}|${rLsa.prefix}/${rLsa.prefixLen}|${propagatedArea}|${propagatedType}`;
          const localOrigin = myMap.get(originKey);
          if (localOrigin && (localOrigin.nextHop === '0.0.0.0' || localOrigin.nextHop === '::')) {
            continue;
          }
          const key = `${originKey}|${adj.localIface.name}|${adj.remoteIp}`;
          const existing = myMap.get(key);
          if (
            !existing ||
            propagatedMetric < existing.metric ||
            (propagatedMetric === existing.metric &&
              propagatedInternalMetric < (existing.internalMetric ?? 0))
          ) {
            myMap.set(key, {
              af: rLsa.af,
              prefix: rLsa.prefix,
              prefixLen: rLsa.prefixLen,
              vrf: localVrf,
              area: propagatedArea,
              ospfType: propagatedType,
              metric: propagatedMetric,
              internalMetric: propagatedInternalMetric,
              nextHop: adj.remoteIp,
              egressInterface: adj.localIface.name,
              viaNodeId: remoteNode.id,
              tag: rLsa.tag,
            });
            changed = true;
          }
        }
      }

      // RFC 2328 §15 Virtual Links: carry Area 0 LSAs across a non-backbone transit area
      for (const vl of node.ospf.virtualLinks ?? []) {
        if (vl.transitArea === 0) continue;
        const peerNode = topology.nodes.find(
          (rn) => rn.id !== node.id && rn.ospf.enabled && getNodeRouterId(rn, 'default') === vl.peerRouterId
        );
        if (!peerNode) continue;
        const peerIfInTransit = peerNode.interfaces.find(
          (i) => !i.shutdown && (i.vrf || 'default') === 'default' && i.ospfArea === vl.transitArea
        );
        const myIfInTransit = node.interfaces.find(
          (i) => !i.shutdown && (i.vrf || 'default') === 'default' && i.ospfArea === vl.transitArea
        );
        if (!peerIfInTransit || !myIfInTransit) continue;
        const peerTransitIp = parseCidr(peerIfInTransit.cidr)?.ip;
        if (!peerTransitIp) continue;
        let transitReach: { nextHop: string; egressInterface: string; cost: number } | null = null;
        for (const lsa of myMap.values()) {
          if (
            lsa.vrf === 'default' &&
            lsa.area === vl.transitArea &&
            lsa.ospfType === 'intra' &&
            isIpInCidr(peerTransitIp, `${lsa.prefix}/${lsa.prefixLen}`)
          ) {
            if (!transitReach || lsa.metric < transitReach.cost) {
              transitReach = { nextHop: lsa.nextHop, egressInterface: lsa.egressInterface, cost: lsa.metric };
            }
          }
        }
        if (!transitReach) continue;
        const remoteMap = nodeLsas.get(peerNode.id)!;
        for (const rLsa of remoteMap.values()) {
          if (rLsa.vrf !== 'default' || rLsa.area !== 0 || rLsa.viaNodeId === node.id) continue;
          if (rLsa.ospfType !== 'intra' && rLsa.ospfType !== 'inter') continue;
          const originKey = `${rLsa.af ?? 4}|default|${rLsa.prefix}/${rLsa.prefixLen}|0|${rLsa.ospfType}`;
          const localOrigin = myMap.get(originKey);
          if (localOrigin && (localOrigin.nextHop === '0.0.0.0' || localOrigin.nextHop === '::')) continue;
          const key = `${originKey}|vlink|${vl.peerRouterId}`;
          const propagatedMetric = rLsa.metric + Math.max(1, transitReach.cost);
          const existing = myMap.get(key);
          if (!existing || propagatedMetric < existing.metric) {
            myMap.set(key, {
              af: rLsa.af,
              prefix: rLsa.prefix,
              prefixLen: rLsa.prefixLen,
              vrf: 'default',
              area: 0,
              ospfType: rLsa.ospfType,
              metric: propagatedMetric,
              nextHop: transitReach.nextHop === '0.0.0.0' ? peerTransitIp : transitReach.nextHop,
              egressInterface: transitReach.egressInterface || myIfInTransit.name,
              viaNodeId: peerNode.id,
              tag: rLsa.tag,
            });
            changed = true;
          }
        }
      }

      // RFC 4577 OSPF Sham-Links: carry intra-area LSAs across MPLS VPN PE peers
      for (const sham of node.ospf.shamLinks ?? []) {
        const remotePe = topology.nodes.find(
          (rn) =>
            rn.id !== node.id &&
            rn.ospf.enabled &&
            rn.interfaces.some((i) => !i.shutdown && parseCidr(i.cidr)?.ip === sham.dstIp)
        );
        if (!remotePe) continue;
        const myRib = activeRibByNode.get(node.id) ?? [];
        const reach = resolveNextHop(sham.dstIp, undefined, 'default', myRib, node);
        if (!reach.resolvable) continue;
        const shamCost = sham.cost ?? 1;
        const remoteMap = nodeLsas.get(remotePe.id)!;
        for (const rLsa of remoteMap.values()) {
          if (
            rLsa.vrf !== sham.vrf ||
            rLsa.area !== sham.area ||
            rLsa.ospfType !== 'intra' ||
            rLsa.viaNodeId === node.id
          ) {
            continue;
          }
          const originKey = `${rLsa.af ?? 4}|${sham.vrf}|${rLsa.prefix}/${rLsa.prefixLen}|${sham.area}|intra`;
          const localOrigin = myMap.get(originKey);
          if (localOrigin && (localOrigin.nextHop === '0.0.0.0' || localOrigin.nextHop === '::')) {
            continue;
          }
          const key = `${originKey}|sham|${sham.dstIp}`;
          const propagatedMetric = rLsa.metric + shamCost;
          const existing = myMap.get(key);
          if (!existing || propagatedMetric < existing.metric) {
            myMap.set(key, {
              af: rLsa.af,
              prefix: rLsa.prefix,
              prefixLen: rLsa.prefixLen,
              vrf: sham.vrf,
              area: sham.area,
              ospfType: 'intra',
              metric: propagatedMetric,
              nextHop: sham.dstIp,
              egressInterface: reach.egressInterface,
              viaNodeId: remotePe.id,
            });
            changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }

  for (const node of topology.nodes) {
    if (!node.ospf.enabled) continue;
    const myMap = nodeLsas.get(node.id)!;
    const byPrefix = new Map<string, OspfLsa[]>();

    for (const lsa of myMap.values()) {
      if (lsa.nextHop === '0.0.0.0' || lsa.nextHop === '::') continue;
      const pKey = `${lsa.af ?? 4}|${lsa.vrf}|${lsa.prefix}/${lsa.prefixLen}`;
      const list = byPrefix.get(pKey);
      if (list) list.push(lsa);
      else byPrefix.set(pKey, [lsa]);
    }

    const results: CandidateRoute[] = [];
    for (const list of byPrefix.values()) {
      list.sort((a, b) => {
        const rankDiff = OSPF_TYPE_RANK[a.ospfType] - OSPF_TYPE_RANK[b.ospfType];
        if (rankDiff !== 0) return rankDiff;
        if (a.metric !== b.metric) return a.metric - b.metric;
        return (a.internalMetric ?? 0) - (b.internalMetric ?? 0);
      });
      const best = list[0];
      const tied = list.filter(
        (x) =>
          x.ospfType === best.ospfType &&
          x.metric === best.metric &&
          (x.internalMetric ?? 0) === (best.internalMetric ?? 0)
      );
      for (const t of tied) {
        results.push({
          af: t.af,
          prefix: t.prefix,
          prefixLen: t.prefixLen,
          vrf: t.vrf,
          protocol: 'ospf',
          ospfType: t.ospfType,
          ad: getEffectiveAd(node.vendor, 'ospf', node.adOverrides, t.ospfType),
          metric: t.metric,
          nextHop: t.nextHop,
          egressInterface: t.egressInterface,
          tag: t.tag,
        });
      }
    }
    ospfCandidates.set(node.id, results);
  }

  return ospfCandidates;
}

function solveBgp(
  topology: TopologyState,
  activeRibByNode: Map<string, RibEntry[]>,
  warnings?: string[]
): Map<string, CandidateRoute[]> {
  const bgpCandidates = new Map<string, CandidateRoute[]>();
  const ipToNode = new Map<
    string,
    { node: NodeConfig; iface: InterfaceConfig; vrf: string }
  >();

  for (const node of topology.nodes) {
    bgpCandidates.set(node.id, []);
    for (const iface of node.interfaces) {
      if (iface.shutdown) continue;
      const parsed = parseCidr(iface.cidr);
      if (parsed) {
        ipToNode.set(parsed.ip, {
          node,
          iface,
          vrf: iface.vrf || 'default',
        });
      }
      if (iface.cidr6) {
        const parsed6 = parseCidr6(iface.cidr6);
        if (parsed6) {
          ipToNode.set(parsed6.ip, {
            node,
            iface,
            vrf: iface.vrf || 'default',
          });
        }
      }
    }
  }

  const nodeBestBgp = new Map<string, Map<string, CandidateRoute>>();
  const nodeMultipathBgp = new Map<string, Map<string, CandidateRoute[]>>();

  for (const node of topology.nodes) {
    const map = new Map<string, CandidateRoute>();
    nodeBestBgp.set(node.id, map);
    nodeMultipathBgp.set(node.id, new Map<string, CandidateRoute[]>());
    if (!node.bgp.enabled) continue;

    for (const net of node.bgp.networks) {
      const af = detectAddressFamily(net.prefix);
      if (!af) continue;
      const parsed = af === 4 ? parseCidr(net.prefix) : parseCidr6(net.prefix);
      if (!parsed) continue;
      const vrf = net.vrf || 'default';
      const key = `${vrf}|${parsed.network}/${parsed.prefixLen}`;
      map.set(key, {
        af,
        prefix: parsed.network,
        prefixLen: parsed.prefixLen,
        vrf,
        protocol: 'ibgp',
        ad: getEffectiveAd(node.vendor, 'ibgp', node.adOverrides),
        metric: net.med ?? 0,
        nextHop: af === 6 ? '::' : '0.0.0.0',
        egressInterface: '',
        originatingNodeId: node.id,
        bgpAttrs: {
          weight: 32768,
          localPref: net.localPref ?? 100,
          locallyOriginated: true,
          asPath: net.asPath ?? [],
          origin: net.origin ?? 'igp',
          med: net.med ?? 0,
          isEbgp: false,
          igpMetric: 0,
          peerRouterId: node.routerId,
          peerIp: '0.0.0.0',
          communities: net.communities?.length ? [...net.communities] : undefined,
          rpkiState: validateRpkiOrigin(
            parsed.network,
            parsed.prefixLen,
            net.asPath?.length ? net.asPath[net.asPath.length - 1] : node.bgp.asn,
            topology.roaTable
          ),
        },
      });
    }

    const currentRib = activeRibByNode.get(node.id) ?? [];
    for (const rule of node.redistributions) {
      if (rule.to !== 'bgp') continue;
      const ruleVrf = rule.vrf || 'default';
      const rm = rule.routeMapId
        ? node.routeMaps.find((m) => m.id === rule.routeMapId)
        : undefined;

      for (const r of currentRib) {
        if (!r.active || r.vrf !== ruleVrf || r.af === 6) continue;
        if (!matchesRedistSource(rule.from, r.protocol)) continue;

        let med = rule.metric ?? 0;
        let localPref = 100;
        let asPath: number[] = [];

        if (rm) {
          const evalRes = evaluateRouteMap(
            r.prefix,
            r.prefixLen,
            rm,
            node.prefixLists ?? []
          );
          if (!evalRes.permitted) continue;
          if (evalRes.set.setMed !== undefined) med = evalRes.set.setMed;
          if (evalRes.set.setLocalPref !== undefined) localPref = evalRes.set.setLocalPref;
          if (evalRes.set.prependAsPath?.length) asPath = [...evalRes.set.prependAsPath];
        }

        const key = `${r.vrf}|${r.prefix}/${r.prefixLen}`;
        if (!map.has(key)) {
          map.set(key, {
            prefix: r.prefix,
            prefixLen: r.prefixLen,
            vrf: r.vrf,
            protocol: 'ibgp',
            ad: getEffectiveAd(node.vendor, 'ibgp', node.adOverrides),
            metric: med,
            nextHop: r.nextHop,
            egressInterface: r.egressInterface,
            originatingNodeId: node.id,
            bgpAttrs: {
              weight: 32768,
              localPref,
              locallyOriginated: true,
              asPath,
              origin: 'incomplete',
              med,
              isEbgp: false,
              igpMetric: 0,
              peerRouterId: node.routerId,
              peerIp: '0.0.0.0',
            },
          });
        }
      }
    }

    for (const agg of node.bgp.aggregates ?? []) {
      const aggVrf = agg.vrf || 'default';
      const parsedAgg = parseCidr(agg.prefix);
      if (!parsedAgg) continue;
      const contributors = Array.from(map.values()).filter((r) => {
        if (r.vrf !== aggVrf) return false;
        const rp = parseCidr(`${r.prefix}/${r.prefixLen}`);
        return (
          rp &&
          rp.prefixLen > parsedAgg.prefixLen &&
          isIpInCidr(rp.network, `${parsedAgg.network}/${parsedAgg.prefixLen}`)
        );
      });
      if (contributors.length > 0) {
        const asSetNums = agg.asSet
          ? Array.from(new Set(contributors.flatMap((c) => c.bgpAttrs?.asPath ?? [])))
          : undefined;
        const key = `${aggVrf}|${parsedAgg.network}/${parsedAgg.prefixLen}`;
        map.set(key, {
          prefix: parsedAgg.network,
          prefixLen: parsedAgg.prefixLen,
          vrf: aggVrf,
          protocol: 'ibgp',
          ad: getEffectiveAd(node.vendor, 'ibgp', node.adOverrides),
          metric: 0,
          nextHop: '0.0.0.0',
          egressInterface: 'Null0',
          originatingNodeId: node.id,
          bgpAttrs: {
            weight: 32768,
            localPref: 100,
            locallyOriginated: true,
            asPath: [],
            asSet: asSetNums?.length ? asSetNums : undefined,
            atomicAggregate: !agg.asSet,
            aggregator: `${node.bgp.asn}:${getNodeRouterId(node, aggVrf)}`,
            origin: 'igp',
            med: 0,
            isEbgp: false,
            igpMetric: 0,
            peerRouterId: getNodeRouterId(node, aggVrf),
            peerIp: '0.0.0.0',
          },
        });
      }
    }
  }

  const maxRounds = Math.max(topology.nodes.length, 4);
  for (let round = 0; round < maxRounds; round++) {
    let changed = false;

    for (const node of topology.nodes) {
      if (!node.bgp.enabled) continue;
      const myRib = activeRibByNode.get(node.id) ?? [];
      const myBestMap = nodeBestBgp.get(node.id)!;
      const allReceived = new Map<string, CandidateRoute[]>();

      for (const existing of myBestMap.values()) {
        if (existing.bgpAttrs?.locallyOriginated) {
          const k = `${existing.vrf}|${existing.prefix}/${existing.prefixLen}`;
          allReceived.set(k, [existing]);
        }
      }

      for (const peer of node.bgp.peers) {
        if (peer.shutdown) continue;
        const peerVrf = peer.vrf || 'default';
        if (peer.updateSource) {
          const updIf = node.interfaces.find((i) => i.name === peer.updateSource);
          if (!updIf || updIf.shutdown) continue;
        }
        const remote = ipToNode.get(peer.peerIp);
        if (!remote || !remote.node.bgp.enabled) continue;
        if (remote.node.bgp.asn !== peer.remoteAs) continue;

        const localRid = getNodeRouterId(node, peerVrf);
        const remoteRid = getNodeRouterId(remote.node, remote.vrf);
        if (localRid === '0.0.0.0' || remoteRid === '0.0.0.0' || localRid === remoteRid) {
          continue;
        }
        const lHold = peer.holdTime ?? 180;
        const rHold = remote.node.bgp.peers.find((rp) => (rp.vrf || 'default') === remote.vrf && rp.remoteAs === node.bgp.asn)?.holdTime ?? 180;
        if (lHold === 1 || lHold === 2 || rHold === 1 || rHold === 2) {
          continue;
        }

        const reach = resolveNextHop(peer.peerIp, undefined, peerVrf, myRib, node);
        if (!reach.resolvable) continue;

        const remoteBestMap = nodeBestBgp.get(remote.node.id)!;
        const isEbgp = peer.remoteAs !== node.bgp.asn;

        const isDirectPeer = node.interfaces.some(
          (i) =>
            !i.shutdown &&
            (i.vrf || 'default') === peerVrf &&
            (isIpInCidr(peer.peerIp, i.cidr) ||
              (Boolean(i.cidr6) && isIp6InCidr(peer.peerIp, i.cidr6!)))
        );
        if (isEbgp && !isDirectPeer && !peer.ebgpMultihop && !peer.disableConnectedCheck) {
          continue;
        }

        const remotePeerBack = remote.node.bgp.peers.find(
          (rp) =>
            (rp.vrf || 'default') === remote.vrf &&
            rp.remoteAs === node.bgp.asn &&
            node.interfaces.some(
              (i) =>
                !i.shutdown &&
                (i.cidr.startsWith(`${rp.peerIp}/`) ||
                  Boolean(i.cidr6?.startsWith(`${rp.peerIp}/`)))
            )
        );
        if (remotePeerBack?.shutdown) continue;
        const outRm =
          remotePeerBack?.routeMapOutId
            ? remote.node.routeMaps.find((m) => m.id === remotePeerBack.routeMapOutId)
            : undefined;
        const inRm =
          peer.routeMapInId
            ? node.routeMaps.find((m) => m.id === peer.routeMapInId)
            : undefined;
        let peerAcceptedCount = 0;
        const peerCandidates: CandidateRoute[] = [];

        for (const rRoute of remoteBestMap.values()) {
          if (!rRoute.bgpAttrs || rRoute.vrf !== remote.vrf) continue;
          const canReflectIbgp = Boolean(
            remotePeerBack?.routeReflectorClient || peer.routeReflectorClient
          );
          if (
            !isEbgp &&
            !rRoute.bgpAttrs.locallyOriginated &&
            !rRoute.bgpAttrs.isEbgp &&
            !canReflectIbgp
          ) {
            continue;
          }
          if (rRoute.originatingNodeId === node.id) continue;
          if (!peer.allowAsIn && rRoute.bgpAttrs.asPath.includes(node.bgp.asn)) continue;
          const reflectedByRemote = Boolean(
            !isEbgp && !rRoute.bgpAttrs.locallyOriginated && canReflectIbgp
          );
          const remoteClusterId =
            remote.node.bgp.clusterId?.trim() || getNodeRouterId(remote.node, remote.vrf);
          const nextClusterList = reflectedByRemote
            ? [...(rRoute.bgpAttrs.clusterList ?? []), remoteClusterId]
            : rRoute.bgpAttrs.clusterList;
          const myClusterId = node.bgp.clusterId?.trim();
          if (!isEbgp && myClusterId && nextClusterList?.includes(myClusterId)) {
            continue;
          }

          const srcComms = rRoute.bgpAttrs.communities ?? [];
          if (srcComms.includes('no-advertise')) continue;
          const isConfedPeer = Boolean(
            peer.confederationPeer ||
              (node.bgp.confederationId &&
                remote.node.bgp.confederationId === node.bgp.confederationId &&
                (node.bgp.confederationPeers?.includes(remote.node.bgp.asn) ||
                  remote.node.bgp.confederationPeers?.includes(node.bgp.asn)))
          );
          if (
            isEbgp &&
            !isConfedPeer &&
            (srcComms.includes('no-export') ||
              srcComms.includes('local-as') ||
              srcComms.includes('no-peer'))
          ) {
            continue;
          }
          const suppressedByAggregate = (remote.node.bgp.aggregates ?? []).some((agg) => {
            if (!agg.summaryOnly || (agg.vrf || 'default') !== remote.vrf) return false;
            const ap = parseCidr(agg.prefix);
            return (
              ap &&
              rRoute.prefixLen > ap.prefixLen &&
              isIpInCidr(rRoute.prefix, `${ap.network}/${ap.prefixLen}`)
            );
          });
          if (suppressedByAggregate) continue;

          const filteredSrcAsPath =
            isEbgp && remotePeerBack?.removePrivateAs
              ? rRoute.bgpAttrs.asPath.filter(
                  (a) => !((a >= 64512 && a <= 65534) || (a >= 4200000000 && a <= 4294967294))
                )
              : rRoute.bgpAttrs.asPath;
          const advertisedAsn =
            isEbgp && !isConfedPeer && remotePeerBack?.localAs
              ? remotePeerBack.localAs
              : isEbgp && !isConfedPeer && remote.node.bgp.confederationId
                ? remote.node.bgp.confederationId
                : remote.node.bgp.asn;
          let newAsPath =
            isEbgp && !isConfedPeer
              ? [
                  ...(remotePeerBack?.localAs &&
                  !remotePeerBack.localAsNoPrepend &&
                  !remotePeerBack.localAsReplaceAs
                    ? [advertisedAsn, remote.node.bgp.asn]
                    : [advertisedAsn]),
                  ...filteredSrcAsPath.map((a) =>
                    remotePeerBack?.asOverride && a === node.bgp.asn ? remote.node.bgp.asn : a
                  ),
                ]
              : [...rRoute.bgpAttrs.asPath];
          const nextConfedPath = isConfedPeer
            ? [...(rRoute.bgpAttrs.confedAsPath ?? []), remote.node.bgp.asn]
            : !isEbgp
              ? rRoute.bgpAttrs.confedAsPath
              : undefined;
          let localPref =
            isEbgp && !isConfedPeer ? (peer.localPref ?? 100) : rRoute.bgpAttrs.localPref;
          // RFC 4271 §5.1.4: MED is optional non-transitive across eBGP AS boundaries
          let med =
            isEbgp && !isConfedPeer
              ? (peer.med ?? (rRoute.bgpAttrs.locallyOriginated ? rRoute.bgpAttrs.med : 0))
              : (peer.med ?? rRoute.bgpAttrs.med);
          let communities =
            remotePeerBack?.sendCommunity === 'none'
              ? []
              : [...(rRoute.bgpAttrs.communities ?? [])];
          let largeCommunities =
            remotePeerBack?.sendCommunity === 'none'
              ? []
              : [...(rRoute.bgpAttrs.largeCommunities ?? [])];

          const originAsn =
            newAsPath.length > 0
              ? newAsPath[newAsPath.length - 1]
              : remote.node.bgp.asn;
          const rpkiState = validateRpkiOrigin(
            rRoute.prefix,
            rRoute.prefixLen,
            originAsn,
            topology.roaTable
          );
          if (node.bgp.rpkiRejectInvalid && rpkiState === 'invalid') {
            continue;
          }

          if (outRm) {
            const outEval = evaluateRouteMap(
              rRoute.prefix,
              rRoute.prefixLen,
              outRm,
              remote.node.prefixLists ?? [],
              { communities, largeCommunities, asPath: newAsPath, rpkiState }
            );
            if (!outEval.permitted) continue;
            if (outEval.set.setMed !== undefined) med = outEval.set.setMed;
            if (outEval.set.setLocalPref !== undefined) localPref = outEval.set.setLocalPref;
            if (outEval.set.prependAsPath?.length) {
              newAsPath = [...outEval.set.prependAsPath, ...newAsPath];
            }
            const updatedComms = applyRouteMapCommunities(
              outEval.set,
              communities,
              largeCommunities
            );
            communities = updatedComms.communities;
            largeCommunities = updatedComms.largeCommunities;
          }

          const proto: ProtocolType = isEbgp && !isConfedPeer ? 'ebgp' : 'ibgp';
          let ad = getEffectiveAd(node.vendor, proto, node.adOverrides);

          const effectiveNextHop =
            (!isEbgp || isConfedPeer) &&
            !remotePeerBack?.nextHopSelf &&
            rRoute.bgpAttrs.isEbgp &&
            rRoute.nextHop !== '0.0.0.0'
              ? rRoute.nextHop
              : peer.peerIp;
          const nhReach =
            effectiveNextHop === peer.peerIp
              ? reach
              : resolveNextHop(effectiveNextHop, undefined, peerVrf, myRib, node);
          if (!nhReach.resolvable) continue;

          if (inRm) {
            const inEval = evaluateRouteMap(
              rRoute.prefix,
              rRoute.prefixLen,
              inRm,
              node.prefixLists ?? [],
              { communities, largeCommunities, asPath: newAsPath, rpkiState }
            );
            if (!inEval.permitted) continue;
            if (inEval.set.setLocalPref !== undefined) localPref = inEval.set.setLocalPref;
            if (inEval.set.setMed !== undefined) med = inEval.set.setMed;
            if (inEval.set.prependAsPath?.length) {
              newAsPath = [...inEval.set.prependAsPath, ...newAsPath];
            }
            if (inEval.set.setAd !== undefined) ad = inEval.set.setAd;
            const updatedComms = applyRouteMapCommunities(
              inEval.set,
              communities,
              largeCommunities
            );
            communities = updatedComms.communities;
            largeCommunities = updatedComms.largeCommunities;
          }

          const cand: CandidateRoute = {
            af: rRoute.af,
            prefix: rRoute.prefix,
            prefixLen: rRoute.prefixLen,
            vrf: peerVrf,
            protocol: proto,
            ad,
            metric: med,
            nextHop: effectiveNextHop,
            egressInterface: nhReach.egressInterface,
            originatingNodeId: rRoute.originatingNodeId,
            bgpAttrs: {
              weight: peer.weight ?? 0,
              localPref,
              locallyOriginated: false,
              asPath: newAsPath,
              confedAsPath: nextConfedPath,
              asSet: rRoute.bgpAttrs.asSet,
              origin: rRoute.bgpAttrs.origin,
              med,
              isEbgp: isEbgp && !isConfedPeer,
              igpMetric: nhReach.igpMetric,
              peerRouterId: getNodeRouterId(remote.node, remote.vrf),
              peerIp: peer.peerIp,
              communities: communities.length > 0 ? communities : undefined,
              largeCommunities: largeCommunities.length > 0 ? largeCommunities : undefined,
              clusterList: nextClusterList?.length ? nextClusterList : undefined,
              rpkiState,
              atomicAggregate: rRoute.bgpAttrs.atomicAggregate,
              aggregator: rRoute.bgpAttrs.aggregator,
              linkBandwidthMbps: peer.linkBandwidthMbps ?? rRoute.bgpAttrs.linkBandwidthMbps,
              aigpMetric:
                peer.aigp || rRoute.bgpAttrs.aigpMetric !== undefined
                  ? (rRoute.bgpAttrs.aigpMetric ?? 0) + nhReach.igpMetric
                  : undefined,
            },
          };

          peerAcceptedCount++;
          peerCandidates.push(cand);
        }

        if (peer.maxPrefixes !== undefined && peerAcceptedCount > peer.maxPrefixes) {
          const warnMsg = `BGP peer ${peer.peerIp} on ${node.hostname} exceeded maximum-prefix ${peer.maxPrefixes} (${peerAcceptedCount} received)`;
          if (warnings && !warnings.includes(warnMsg)) warnings.push(warnMsg);
        } else {
          for (const cand of peerCandidates) {
            const k = `${cand.vrf}|${cand.prefix}/${cand.prefixLen}`;
            const list = allReceived.get(k);
            if (list) list.push(cand);
            else allReceived.set(k, [cand]);
          }
        }

        if (remotePeerBack?.defaultOriginate) {
          const proto: ProtocolType = isEbgp ? 'ebgp' : 'ibgp';
          const ad = getEffectiveAd(node.vendor, proto, node.adOverrides);
          const defCand: CandidateRoute = {
            prefix: '0.0.0.0',
            prefixLen: 0,
            vrf: peerVrf,
            protocol: proto,
            ad,
            metric: peer.med ?? 0,
            nextHop: peer.peerIp,
            egressInterface: reach.egressInterface,
            originatingNodeId: remote.node.id,
            bgpAttrs: {
              weight: peer.weight ?? 0,
              localPref: peer.localPref ?? 100,
              locallyOriginated: false,
              asPath: isEbgp ? [remote.node.bgp.asn] : [],
              origin: 'igp',
              med: peer.med ?? 0,
              isEbgp,
              igpMetric: reach.igpMetric,
              peerRouterId: remote.node.routerId,
              peerIp: peer.peerIp,
            },
          };
          const defKey = `${defCand.vrf}|0.0.0.0/0`;
          const defList = allReceived.get(defKey);
          if (defList) defList.push(defCand);
          else allReceived.set(defKey, [defCand]);
        }
      }

      for (const [k, list] of allReceived) {
        const cmpOpts = {
          alwaysCompareMed: node.bgp.alwaysCompareMed,
          bestpathAsPathIgnore: node.bgp.bestpathAsPathIgnore,
          medMissingAsWorst: node.bgp.medMissingAsWorst,
        };
        list.sort((a, b) => compareBgpCandidates(a, b, cmpOpts));
        const winner = list[0];
        const maxPaths = Math.max(1, node.maxPaths);
        const multipathList: CandidateRoute[] = [];
        const seenNh = new Set<string>();
        for (const cand of list) {
          if (compareBgpCandidates(winner, cand, { ...cmpOpts, ignoreTieBreakers: true }) !== 0) {
            break;
          }
          const nhKey = `${cand.nextHop}|${cand.egressInterface ?? ''}`;
          if (!seenNh.has(nhKey)) {
            seenNh.add(nhKey);
            multipathList.push(cand);
            if (multipathList.length >= maxPaths) break;
          }
        }
        nodeMultipathBgp.get(node.id)!.set(k, multipathList);
        const prev = myBestMap.get(k);
        if (
          !prev ||
          prev.nextHop !== winner.nextHop ||
          prev.protocol !== winner.protocol ||
          prev.ad !== winner.ad ||
          prev.bgpAttrs?.asPath.join(',') !== winner.bgpAttrs?.asPath.join(',') ||
          prev.bgpAttrs?.localPref !== winner.bgpAttrs?.localPref ||
          prev.bgpAttrs?.med !== winner.bgpAttrs?.med
        ) {
          myBestMap.set(k, winner);
          changed = true;
        }
      }
    }

    if (!changed) break;
  }

  for (const node of topology.nodes) {
    const myBestMap = nodeBestBgp.get(node.id)!;
    const myMultipathMap = nodeMultipathBgp.get(node.id)!;
    const learned: CandidateRoute[] = [];
    for (const [k, r] of myBestMap.entries()) {
      const mList = myMultipathMap.get(k);
      if (mList && mList.length > 0 && !r.bgpAttrs?.locallyOriginated) {
        learned.push(...mList);
      } else if (!r.bgpAttrs?.locallyOriginated || r.egressInterface === 'Null0') {
        learned.push(r);
      }
    }
    bgpCandidates.set(node.id, learned);
  }

  return bgpCandidates;
}

function computeEigrpMetric(
  minBwKbps: number,
  sumDelayUsec: number,
  kValues: [number, number, number, number, number] = [1, 0, 1, 0, 0]
): number {
  const [k1, k2, k3, k4, k5] = kValues;
  const bwTerm = Math.floor(10000000 / Math.max(1, minBwKbps));
  const delayTerm = Math.floor(sumDelayUsec / 10);
  const load = 1;
  const reliability = 255;
  let base = k1 * bwTerm + Math.floor((k2 * bwTerm) / (256 - load)) + k3 * delayTerm;
  if (k5 > 0) {
    base = Math.floor((base * k5) / Math.max(1, k4 + reliability));
  }
  return Math.max(256, base * 256);
}

function eigrpKValuesMatch(
  a?: [number, number, number, number, number],
  b?: [number, number, number, number, number]
): boolean {
  const ka = a ?? [1, 0, 1, 0, 0];
  const kb = b ?? [1, 0, 1, 0, 0];
  return ka[0] === kb[0] && ka[1] === kb[1] && ka[2] === kb[2] && ka[3] === kb[3] && ka[4] === kb[4];
}

function solveEigrp(
  topology: TopologyState,
  adjMap: Map<string, Adjacency[]>,
  activeRibByNode: Map<string, RibEntry[]>,
  warnings?: string[]
): Map<string, CandidateRoute[]> {
  const results = new Map<string, CandidateRoute[]>();
  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));

  interface EigrpPath {
    prefix: string;
    prefixLen: number;
    vrf: string;
    minBw: number;
    sumDelay: number;
    fd: number;
    reportedAd: number;
    nextHop: string;
    egressInterface: string;
    viaNodeId: string;
    tag?: number;
    external?: boolean;
  }

  const nodePaths = new Map<string, EigrpPath[]>();
  for (const node of topology.nodes) {
    results.set(node.id, []);
    const list: EigrpPath[] = [];
    nodePaths.set(node.id, list);
    if (!node.eigrp?.enabled) continue;

    const kVals = node.eigrp.kValues ?? [1, 0, 1, 0, 0];
    for (const iface of node.interfaces) {
      if (iface.shutdown) continue;
      const parsed = parseCidr(iface.cidr);
      if (!parsed) continue;
      const bw = iface.eigrpBw ?? 1000000;
      const delay = iface.eigrpDelay ?? 10;
      list.push({
        prefix: parsed.network,
        prefixLen: parsed.prefixLen,
        vrf: iface.vrf || 'default',
        minBw: bw,
        sumDelay: delay,
        fd: computeEigrpMetric(bw, delay, kVals),
        reportedAd: 0,
        nextHop: '0.0.0.0',
        egressInterface: iface.name,
        viaNodeId: node.id,
      });
    }
    for (const net of node.eigrp.networks) {
      const parsed = parseCidr(net.prefix);
      if (!parsed) continue;
      const bw = net.bandwidth ?? 1000000;
      const delay = net.delay ?? 10;
      list.push({
        prefix: parsed.network,
        prefixLen: parsed.prefixLen,
        vrf: net.vrf || 'default',
        minBw: bw,
        sumDelay: delay,
        fd: computeEigrpMetric(bw, delay, kVals),
        reportedAd: 0,
        nextHop: '0.0.0.0',
        egressInterface: '',
        viaNodeId: node.id,
        tag: net.tag,
      });
    }

    const currentRib = activeRibByNode.get(node.id) ?? [];
    for (const rule of node.redistributions) {
      if (rule.to !== 'eigrp') continue;
      const ruleVrf = rule.vrf || 'default';
      const rm = rule.routeMapId
        ? node.routeMaps.find((m) => m.id === rule.routeMapId)
        : undefined;
      for (const r of currentRib) {
        if (!r.active || r.vrf !== ruleVrf || !matchesRedistSource(rule.from, r.protocol)) continue;
        let tag = r.tag;
        if (rm) {
          const evalRes = evaluateRouteMap(
            r.prefix,
            r.prefixLen,
            rm,
            node.prefixLists ?? [],
            { tag: r.tag }
          );
          if (!evalRes.permitted) continue;
          if (evalRes.set.setTag !== undefined) tag = evalRes.set.setTag;
        }
        const bw = 100000;
        const delay = rule.metric ?? 100;
        list.push({
          prefix: r.prefix,
          prefixLen: r.prefixLen,
          vrf: ruleVrf,
          minBw: bw,
          sumDelay: delay,
          fd: computeEigrpMetric(bw, delay, kVals),
          reportedAd: 0,
          nextHop: '0.0.0.0',
          egressInterface: '',
          viaNodeId: node.id,
          tag,
          external: true,
        });
      }
    }
  }

  const maxRounds = Math.max(topology.nodes.length, 4);
  for (let round = 0; round < maxRounds; round++) {
    let changed = false;
    for (const node of topology.nodes) {
      if (!node.eigrp?.enabled) continue;
      const kVals = node.eigrp.kValues ?? [1, 0, 1, 0, 0];
      const adjs = adjMap.get(node.id) ?? [];
      const myPaths = nodePaths.get(node.id)!;

      for (const adj of adjs) {
        const remote = nodeMap.get(adj.remoteNodeId);
        if (!remote?.eigrp?.enabled || remote.eigrp.asn !== node.eigrp.asn) continue;
        if (adj.localIface.passive || adj.remoteIface.passive) continue;
        if (!eigrpKValuesMatch(node.eigrp.kValues, remote.eigrp.kValues)) {
          const msg = `EIGRP K-value mismatch on ${node.hostname}:${adj.localIface.name} <-> ${remote.hostname}:${adj.remoteIface.name}`;
          if (warnings && !warnings.includes(msg)) warnings.push(msg);
          continue;
        }
        const localVrf = adj.localIface.vrf || 'default';
        const remoteVrf = adj.remoteIface.vrf || 'default';
        const linkBw =
          adj.localIface.eigrpBw ??
          (adj.localIface.speedMbps ? adj.localIface.speedMbps * 1000 : 1000000);
        const linkDelay = adj.localIface.eigrpDelay ?? 10;

        for (const rp of nodePaths.get(remote.id)!) {
          if (rp.vrf !== remoteVrf || rp.viaNodeId === node.id) continue;
          const minBw = Math.min(rp.minBw, linkBw);
          const sumDelay = rp.sumDelay + linkDelay;
          const fd = computeEigrpMetric(minBw, sumDelay, kVals);

          const existingIdx = myPaths.findIndex(
            (p) =>
              p.vrf === localVrf &&
              p.prefix === rp.prefix &&
              p.prefixLen === rp.prefixLen &&
              p.nextHop === adj.remoteIp
          );
          if (existingIdx === -1) {
            myPaths.push({
              prefix: rp.prefix,
              prefixLen: rp.prefixLen,
              vrf: localVrf,
              minBw,
              sumDelay,
              fd,
              reportedAd: rp.fd,
              nextHop: adj.remoteIp,
              egressInterface: adj.localIface.name,
              viaNodeId: remote.id,
              tag: rp.tag,
              external: rp.external,
            });
            changed = true;
          } else if (fd < myPaths[existingIdx].fd) {
            myPaths[existingIdx].minBw = minBw;
            myPaths[existingIdx].sumDelay = sumDelay;
            myPaths[existingIdx].fd = fd;
            myPaths[existingIdx].reportedAd = rp.fd;
            myPaths[existingIdx].tag = rp.tag;
            myPaths[existingIdx].external = rp.external;
            changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }

  for (const node of topology.nodes) {
    if (!node.eigrp?.enabled) continue;
    const byPrefix = new Map<string, EigrpPath[]>();
    for (const p of nodePaths.get(node.id)!) {
      if (p.nextHop === '0.0.0.0') continue;
      const k = `${p.vrf}|${p.prefix}/${p.prefixLen}`;
      const list = byPrefix.get(k);
      if (list) list.push(p);
      else byPrefix.set(k, [p]);
    }

    const cands: CandidateRoute[] = [];
    const variance = Math.max(1, node.eigrp.variance ?? 1);
    for (const list of byPrefix.values()) {
      list.sort((a, b) => a.fd - b.fd);
      const bestFd = list[0].fd;
      for (const p of list) {
        const isBest = p.fd === bestFd;
        const isFs = !isBest && p.reportedAd < bestFd;
        const withinVariance = variance > 1 && isFs && p.fd <= bestFd * variance;
        if (isBest || isFs) {
          cands.push({
            prefix: p.prefix,
            prefixLen: p.prefixLen,
            vrf: p.vrf,
            protocol: 'eigrp',
            feasibleSuccessor: isFs && !withinVariance,
            ad:
              node.adOverrides.eigrp !== undefined
                ? node.adOverrides.eigrp
                : p.external
                  ? 170
                  : getEffectiveAd(node.vendor, 'eigrp', node.adOverrides),
            metric: withinVariance ? bestFd : p.fd,
            nextHop: p.nextHop,
            egressInterface: p.egressInterface,
            tag: p.tag,
          });
        }
      }
    }
    for (const sum of node.eigrp?.summaries ?? []) {
      const sp = parseCidr(sum.prefix);
      if (!sp) continue;
      const hasMoreSpec = cands.some(
        (c) => c.prefixLen > sp.prefixLen && isIpInCidr(c.prefix, sum.prefix)
      );
      if (hasMoreSpec) {
        cands.push({
          prefix: sp.network,
          prefixLen: sp.prefixLen,
          vrf: 'default',
          protocol: 'eigrp',
          ad: getEffectiveAd(node.vendor, 'eigrp', node.adOverrides),
          metric: 2560,
          nextHop: '0.0.0.0',
          egressInterface: 'Null0',
        });
      }
    }
    results.set(node.id, cands);
  }

  return results;
}

function parseIsisNet(net?: string): { areaId: string; systemId: string } | null {
  if (!net) return null;
  const parts = net.trim().split('.');
  if (parts.length < 5) return null;
  return {
    areaId: parts.slice(0, -4).join('.').toLowerCase(),
    systemId: parts.slice(-4, -1).join('.').toLowerCase(),
  };
}

function checkIsisAdjacency(
  node: NodeConfig,
  iface: NodeConfig['interfaces'][number],
  remote: NodeConfig,
  remoteIface: NodeConfig['interfaces'][number]
): { ok: boolean; canL1: boolean; canL2: boolean; reason?: string } {
  const lMtu = iface.mtu ?? 1500;
  const rMtu = remoteIface.mtu ?? 1500;
  if (lMtu !== rMtu) {
    return { ok: false, canL1: false, canL2: false, reason: `MTU mismatch (${lMtu}/${rMtu})` };
  }
  const lNet = parseIsisNet(node.isis?.net);
  const rNet = parseIsisNet(remote.isis?.net);
  if (lNet && rNet && lNet.systemId === rNet.systemId) {
    return { ok: false, canL1: false, canL2: false, reason: `Duplicate System-ID (${lNet.systemId})` };
  }
  const lNodeLvl = node.isis?.level ?? 'L1-L2';
  const rNodeLvl = remote.isis?.level ?? 'L1-L2';
  const l1Compat =
    lNodeLvl !== 'L2' &&
    rNodeLvl !== 'L2' &&
    !(lNodeLvl === 'L1-L2' && iface.isisLevel === 'L2' && rNodeLvl === 'L1-L2' && remoteIface.isisLevel === 'L2');
  const l2Compat =
    lNodeLvl !== 'L1' &&
    rNodeLvl !== 'L1' &&
    !(lNodeLvl === 'L1-L2' && iface.isisLevel === 'L1' && rNodeLvl === 'L1-L2' && remoteIface.isisLevel === 'L1');
  if (!l1Compat && !l2Compat) {
    return { ok: false, canL1: false, canL2: false, reason: `Level mismatch (${lNodeLvl}/${rNodeLvl})` };
  }
  const sameArea = !lNet || !rNet || lNet.areaId === rNet.areaId;
  const canL1 = l1Compat && sameArea;
  const canL2 = l2Compat;
  if (!canL1 && !canL2) {
    return {
      ok: false,
      canL1: false,
      canL2: false,
      reason: `Area ID mismatch (${lNet?.areaId}/${rNet?.areaId})`,
    };
  }
  return { ok: true, canL1, canL2 };
}

function solveIsis(
  topology: TopologyState,
  adjMap: Map<string, Adjacency[]>,
  activeRibByNode: Map<string, RibEntry[]>,
  warnings?: string[]
): Map<string, CandidateRoute[]> {
  const results = new Map<string, CandidateRoute[]>();
  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));

  interface IsisLsp {
    af?: 4 | 6;
    prefix: string;
    prefixLen: number;
    vrf: string;
    level: 'L1' | 'L2';
    upDownBit?: boolean;
    metric: number;
    nextHop: string;
    egressInterface: string;
    viaNodeId: string;
    tag?: number;
  }

  const nodeLsps = new Map<string, Map<string, IsisLsp>>();
  for (const node of topology.nodes) {
    results.set(node.id, []);
    const map = new Map<string, IsisLsp>();
    nodeLsps.set(node.id, map);
    if (!node.isis?.enabled) continue;

    for (const iface of node.interfaces) {
      if (iface.shutdown || !iface.isisLevel) continue;
      const vrf = iface.vrf || 'default';
      const parsed = parseCidr(iface.cidr);
      if (parsed) {
        const key = `4|${vrf}|${parsed.network}/${parsed.prefixLen}|${iface.isisLevel}`;
        map.set(key, {
          af: 4,
          prefix: parsed.network,
          prefixLen: parsed.prefixLen,
          vrf,
          level: iface.isisLevel,
          metric: iface.isisMetric ?? 10,
          nextHop: '0.0.0.0',
          egressInterface: iface.name,
          viaNodeId: node.id,
        });
      }
      if (node.isis.multiTopologyV6 && iface.cidr6) {
        const parsed6 = parseCidr6(iface.cidr6);
        if (parsed6) {
          const key6 = `6|${vrf}|${parsed6.network}/${parsed6.prefixLen}|${iface.isisLevel}`;
          map.set(key6, {
            af: 6,
            prefix: parsed6.network,
            prefixLen: parsed6.prefixLen,
            vrf,
            level: iface.isisLevel,
            metric: iface.isisMetric ?? 10,
            nextHop: '::',
            egressInterface: iface.name,
            viaNodeId: node.id,
          });
        }
      }
    }
    for (const net of node.isis.networks) {
      const af = detectAddressFamily(net.prefix);
      if (!af) continue;
      if (af === 6 && !node.isis.multiTopologyV6) continue;
      const parsed = af === 4 ? parseCidr(net.prefix) : parseCidr6(net.prefix);
      if (!parsed) continue;
      const vrf = net.vrf || 'default';
      const lvl = net.level ?? (node.isis.level === 'L1' ? 'L1' : 'L2');
      const key = `${af}|${vrf}|${parsed.network}/${parsed.prefixLen}|${lvl}`;
      map.set(key, {
        af,
        prefix: parsed.network,
        prefixLen: parsed.prefixLen,
        vrf,
        level: lvl,
        metric: net.metric ?? 10,
        nextHop: af === 6 ? '::' : '0.0.0.0',
        egressInterface: '',
        viaNodeId: node.id,
      });
    }

    const currentRib = activeRibByNode.get(node.id) ?? [];
    for (const rule of node.redistributions) {
      if (rule.to !== 'isis') continue;
      const ruleVrf = rule.vrf || 'default';
      const lvl = node.isis.level === 'L1' ? 'L1' : 'L2';
      const rm = rule.routeMapId
        ? node.routeMaps.find((m) => m.id === rule.routeMapId)
        : undefined;
      for (const r of currentRib) {
        if (!r.active || r.vrf !== ruleVrf || !matchesRedistSource(rule.from, r.protocol)) continue;
        if (r.af === 6 && !node.isis.multiTopologyV6) continue;
        let tag = r.tag;
        if (rm) {
          const evalRes = evaluateRouteMap(r.prefix, r.prefixLen, rm, node.prefixLists ?? [], { tag: r.tag });
          if (!evalRes.permitted) continue;
          if (evalRes.set.setTag !== undefined) tag = evalRes.set.setTag;
        }
        const af = r.af ?? 4;
        map.set(`${af}|${ruleVrf}|${r.prefix}/${r.prefixLen}|${lvl}`, {
          af,
          prefix: r.prefix,
          prefixLen: r.prefixLen,
          vrf: ruleVrf,
          level: lvl,
          metric: rule.metric ?? 20,
          nextHop: af === 6 ? '::' : '0.0.0.0',
          egressInterface: '',
          viaNodeId: node.id,
          tag,
        });
      }
    }
  }

  const maxHops = Math.max(topology.nodes.length, 4);
  for (let step = 0; step < maxHops; step++) {
    let changed = false;
    for (const node of topology.nodes) {
      if (!node.isis?.enabled) continue;
      const myMap = nodeLsps.get(node.id)!;
      for (const adj of adjMap.get(node.id) ?? []) {
        const remote = nodeMap.get(adj.remoteNodeId);
        if (!remote?.isis?.enabled) continue;
        if (adj.localIface.passive || adj.remoteIface.passive) continue;
        if (!adj.localIface.isisLevel || !adj.remoteIface.isisLevel) continue;
        const adjCheck = checkIsisAdjacency(node, adj.localIface, remote, adj.remoteIface);
        if (!adjCheck.ok) {
          const msg = `IS-IS ${adjCheck.reason} on ${node.hostname}:${adj.localIface.name} <-> ${remote.hostname}:${adj.remoteIface.name}`;
          if (warnings && !warnings.includes(msg)) warnings.push(msg);
          continue;
        }
        const localVrf = adj.localIface.vrf || 'default';
        const remoteVrf = adj.remoteIface.vrf || 'default';
        // RFC 1195 / ISO 10589 Overload Bit: transit through an overloaded router adds max cost (0xFFFFFE / 16777214)
        const rawLinkCost =
          node.isis.metricStyle === 'narrow'
            ? Math.min(63, adj.localIface.isisMetric ?? 10)
            : (adj.localIface.isisMetric ?? 10);
        const overloadPenalty = remote.isis.overloadBit ? 16777214 : 0;

        // ISO/IEC 10589 §7.2.8 ATT (Attached) bit: L1-only router installs default route toward L1-L2 ABR
        if (node.isis.level === 'L1' && remote.isis.level === 'L1-L2' && adjCheck.canL1) {
          const attKey = `4|${localVrf}|0.0.0.0/0|L1`;
          const exAtt = myMap.get(attKey);
          if (!exAtt || rawLinkCost < exAtt.metric) {
            myMap.set(attKey, {
              af: 4,
              prefix: '0.0.0.0',
              prefixLen: 0,
              vrf: localVrf,
              level: 'L1',
              metric: rawLinkCost,
              nextHop: adj.remoteIp,
              egressInterface: adj.localIface.name,
              viaNodeId: remote.id,
            });
            changed = true;
          }
        }

        for (const rLsp of nodeLsps.get(remote.id)!.values()) {
          if (rLsp.vrf !== remoteVrf || rLsp.viaNodeId === node.id) continue;
          if (rLsp.af === 6 && !node.isis.multiTopologyV6) continue;
          // RFC 5302/5305 Up/Down bit loop prevention: routes leaked down to L1 cannot be re-advertised into L2
          if (rLsp.upDownBit && node.isis.level !== 'L1' && remote.isis.level === 'L1-L2') {
            continue;
          }
          const canCarry =
            (rLsp.level === 'L1' && adjCheck.canL1) ||
            (rLsp.level === 'L2' && adjCheck.canL2);
          if (!canCarry) continue;

          // Only apply overload penalty if remote is a transit hop (not directly attached to prefix)
          const isDirectOnRemote = rLsp.nextHop === '0.0.0.0' || rLsp.nextHop === '::';
          const newMetric = rLsp.metric + rawLinkCost + (isDirectOnRemote ? 0 : overloadPenalty);
          const nh = rLsp.af === 6 ? (adj.remoteIp6 ?? adj.remoteIp) : adj.remoteIp;
          const key = `${rLsp.af ?? 4}|${localVrf}|${rLsp.prefix}/${rLsp.prefixLen}|${rLsp.level}`;
          const existing = myMap.get(key);
          if (!existing || newMetric < existing.metric) {
            myMap.set(key, {
              af: rLsp.af,
              prefix: rLsp.prefix,
              prefixLen: rLsp.prefixLen,
              vrf: localVrf,
              level: rLsp.level,
              upDownBit: rLsp.upDownBit,
              metric: newMetric,
              nextHop: nh,
              egressInterface: adj.localIface.name,
              viaNodeId: remote.id,
              tag: rLsp.tag,
            });
            changed = true;
          }
        }
      }

      // RFC 5302 / 5305 L2 -> L1 Route Leaking on L1-L2 routers
      if (node.isis.level === 'L1-L2' && (node.isis.leakL2ToL1?.length ?? 0) > 0) {
        for (const rLsp of Array.from(myMap.values())) {
          if (rLsp.level !== 'L2' || rLsp.nextHop === '0.0.0.0' || rLsp.nextHop === '::') continue;
          const matchesLeak = node.isis.leakL2ToL1!.some((lk) => {
            const lp = parseCidr(lk.prefix);
            return lp && isIpInCidr(rLsp.prefix, lk.prefix);
          });
          if (!matchesLeak) continue;
          const l1Key = `${rLsp.af ?? 4}|${rLsp.vrf}|${rLsp.prefix}/${rLsp.prefixLen}|L1`;
          if (!myMap.has(l1Key)) {
            myMap.set(l1Key, {
              ...rLsp,
              level: 'L1',
              upDownBit: true,
            });
            changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }

  for (const node of topology.nodes) {
    if (!node.isis?.enabled) continue;
    // ISO/IEC 10589 §7.2.8: L1 routes are always preferred over L2 routes for the same prefix
    const byPrefix = new Map<string, IsisLsp[]>();
    for (const lsp of nodeLsps.get(node.id)!.values()) {
      if (lsp.nextHop === '0.0.0.0' || lsp.nextHop === '::') continue;
      const pKey = `${lsp.af ?? 4}|${lsp.vrf}|${lsp.prefix}/${lsp.prefixLen}`;
      const list = byPrefix.get(pKey);
      if (list) list.push(lsp);
      else byPrefix.set(pKey, [lsp]);
    }
    const cands: CandidateRoute[] = [];
    for (const list of byPrefix.values()) {
      list.sort((a, b) => {
        if (a.level !== b.level) return a.level === 'L1' ? -1 : 1;
        return a.metric - b.metric;
      });
      const best = list[0];
      for (const lsp of list) {
        if (lsp.level !== best.level || lsp.metric !== best.metric) break;
        cands.push({
          af: lsp.af,
          prefix: lsp.prefix,
          prefixLen: lsp.prefixLen,
          vrf: lsp.vrf,
          protocol: 'isis',
          isisLevel: lsp.level,
          isisUpDownBit: lsp.upDownBit,
          ad: getEffectiveAd(node.vendor, 'isis', node.adOverrides),
          metric: lsp.metric,
          nextHop: lsp.nextHop,
          egressInterface: lsp.egressInterface,
          tag: lsp.tag,
        });
      }
    }
    for (const sum of node.isis?.summaries ?? []) {
      const sp = parseCidr(sum.prefix);
      if (!sp) continue;
      const hasMoreSpec = cands.some(
        (c) => c.prefixLen > sp.prefixLen && isIpInCidr(c.prefix, sum.prefix)
      );
      if (hasMoreSpec) {
        cands.push({
          prefix: sp.network,
          prefixLen: sp.prefixLen,
          vrf: 'default',
          protocol: 'isis',
          ad: getEffectiveAd(node.vendor, 'isis', node.adOverrides),
          metric: 10,
          nextHop: '0.0.0.0',
          egressInterface: 'Null0',
        });
      }
    }
    results.set(node.id, cands);
  }

  return results;
}

function solveRip(
  topology: TopologyState,
  adjMap: Map<string, Adjacency[]>,
  activeRibByNode: Map<string, RibEntry[]>
): Map<string, CandidateRoute[]> {
  const results = new Map<string, CandidateRoute[]>();
  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));

  interface RipEntry {
    prefix: string;
    prefixLen: number;
    vrf: string;
    metric: number;
    nextHop: string;
    egressInterface: string;
    viaNodeId: string;
    tag?: number;
  }

  const nodeRoutes = new Map<string, Map<string, RipEntry>>();
  for (const node of topology.nodes) {
    results.set(node.id, []);
    const map = new Map<string, RipEntry>();
    nodeRoutes.set(node.id, map);
    if (!node.rip?.enabled) continue;

    for (const net of node.rip.networks) {
      const parsed = parseCidr(net.prefix);
      if (!parsed) continue;
      const vrf = net.vrf || 'default';
      map.set(`${vrf}|${parsed.network}/${parsed.prefixLen}`, {
        prefix: parsed.network,
        prefixLen: parsed.prefixLen,
        vrf,
        metric: 0,
        nextHop: '0.0.0.0',
        egressInterface: '',
        viaNodeId: node.id,
      });
    }

    if (node.rip.defaultOriginate) {
      map.set('default|0.0.0.0/0', {
        prefix: '0.0.0.0',
        prefixLen: 0,
        vrf: 'default',
        metric: 1,
        nextHop: '0.0.0.0',
        egressInterface: '',
        viaNodeId: node.id,
      });
    }

    const currentRib = activeRibByNode.get(node.id) ?? [];
    for (const rule of node.redistributions) {
      if (rule.to !== 'rip') continue;
      const ruleVrf = rule.vrf || 'default';
      const rm = rule.routeMapId
        ? node.routeMaps.find((m) => m.id === rule.routeMapId)
        : undefined;
      for (const r of currentRib) {
        if (!r.active || r.vrf !== ruleVrf || !matchesRedistSource(rule.from, r.protocol)) continue;
        let tag = r.tag;
        if (rm) {
          const evalRes = evaluateRouteMap(r.prefix, r.prefixLen, rm, node.prefixLists ?? [], { tag: r.tag });
          if (!evalRes.permitted) continue;
          if (evalRes.set.setTag !== undefined) tag = evalRes.set.setTag;
        }
        map.set(`${ruleVrf}|${r.prefix}/${r.prefixLen}`, {
          prefix: r.prefix,
          prefixLen: r.prefixLen,
          vrf: ruleVrf,
          metric: Math.min(rule.metric ?? 1, 15),
          nextHop: '0.0.0.0',
          egressInterface: '',
          viaNodeId: node.id,
          tag,
        });
      }
    }
  }

  const maxRounds = Math.min(Math.max(topology.nodes.length, 4), 15);
  for (let round = 0; round < maxRounds; round++) {
    let changed = false;
    for (const node of topology.nodes) {
      if (!node.rip?.enabled) continue;
      const myMap = nodeRoutes.get(node.id)!;
      for (const adj of adjMap.get(node.id) ?? []) {
        const remote = nodeMap.get(adj.remoteNodeId);
        if (!remote?.rip?.enabled) continue;
        if (adj.localIface.passive || adj.remoteIface.passive) continue;
        const localVrf = adj.localIface.vrf || 'default';
        const remoteVrf = adj.remoteIface.vrf || 'default';

        for (const rEntry of nodeRoutes.get(remote.id)!.values()) {
          if (rEntry.vrf !== remoteVrf || rEntry.viaNodeId === node.id) continue;
          const newMetric = rEntry.metric + 1;
          if (newMetric > 15) continue;
          const key = `${localVrf}|${rEntry.prefix}/${rEntry.prefixLen}`;
          const existing = myMap.get(key);
          if (!existing || newMetric < existing.metric) {
            myMap.set(key, {
              prefix: rEntry.prefix,
              prefixLen: rEntry.prefixLen,
              vrf: localVrf,
              metric: newMetric,
              nextHop: adj.remoteIp,
              egressInterface: adj.localIface.name,
              viaNodeId: remote.id,
              tag: rEntry.tag,
            });
            changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }

  for (const node of topology.nodes) {
    if (!node.rip?.enabled) continue;
    const ad = getEffectiveAd(node.vendor, 'rip', node.adOverrides);
    const out: CandidateRoute[] = [];
    for (const entry of nodeRoutes.get(node.id)!.values()) {
      if (entry.nextHop === '0.0.0.0') continue;
      out.push({
        prefix: entry.prefix,
        prefixLen: entry.prefixLen,
        vrf: entry.vrf,
        protocol: 'rip',
        ad,
        metric: entry.metric,
        nextHop: entry.nextHop,
        egressInterface: entry.egressInterface,
        tag: entry.tag,
      });
    }
    results.set(node.id, out);
  }

  return results;
}

function ribSignature(rib: RibEntry[]): string {
  return rib
    .filter((r) => r.active)
    .map(
      (r) =>
        `${r.af ?? 4}|${r.vrf}|${r.prefix}/${r.prefixLen}|${r.protocol}|${r.ospfType ?? ''}|${r.ad}|${r.metric}|${r.nextHop}|${r.egressInterface}|${r.leakedFromVrf ?? ''}`
    )
    .sort()
    .join(';');
}

export function solveTopology(rawTopology: TopologyState): SimulationResult {
  const startTime = performance.now();
  const warnings: string[] = [];

  const hasAnyLink = new Set<string>();
  const hasUpLink = new Set<string>();
  for (const l of rawTopology.links) {
    hasAnyLink.add(`${l.sourceNodeId}|${l.sourceInterfaceId}`);
    hasAnyLink.add(`${l.targetNodeId}|${l.targetInterfaceId}`);
    if (!l.adminDown) {
      hasUpLink.add(`${l.sourceNodeId}|${l.sourceInterfaceId}`);
      hasUpLink.add(`${l.targetNodeId}|${l.targetInterfaceId}`);
    }
  }
  const topology: TopologyState = {
    ...rawTopology,
    nodes: rawTopology.nodes.map((n) => ({
      ...n,
      interfaces: n.interfaces.map((iface) =>
        hasAnyLink.has(`${n.id}|${iface.id}`) && !hasUpLink.has(`${n.id}|${iface.id}`)
          ? { ...iface, shutdown: true }
          : iface
      ),
    })),
  };

  const standbyNodes = computeStandbyNodes(topology);
  const stpLldp = computeStpAndLldp(topology, warnings);
  const adjMap = buildAdjacencies(topology, warnings, standbyNodes, stpLldp.blockedL2Ports);

  const activeRibByNode = new Map<string, RibEntry[]>();
  const baseCandidatesByNode = new Map<string, CandidateRoute[]>();

  for (const node of topology.nodes) {
    if (node.adminDown) {
      activeRibByNode.set(node.id, []);
      baseCandidatesByNode.set(node.id, []);
      continue;
    }
    if (node.vendor === 'forcepoint-ngfw' && (node.vrfs?.length ?? 1) > 1) {
      warnings.push(
        `Forcepoint NGFW (${node.hostname}) only supports 1 VRF per virtual engine, even though underlying FRR/VRR supports multiple VRFs.`
      );
    }
    const base: CandidateRoute[] = [];
    const initialActive: RibEntry[] = [];

    for (const iface of node.interfaces) {
      if (iface.shutdown) continue;
      const effectiveCidr =
        !iface.cidr?.trim() && iface.unnumberedSource
          ? node.interfaces.find((src) => src.name === iface.unnumberedSource)?.cidr ?? ''
          : iface.cidr;
      const parsed = parseCidr(effectiveCidr);
      if (!parsed) {
        const isL2Port =
          !iface.cidr?.trim() &&
          topology.links.some(
            (l) =>
              l.linkType === 'layer2' &&
              ((l.sourceNodeId === node.id && l.sourceInterfaceId === iface.id) ||
                (l.targetNodeId === node.id && l.targetInterfaceId === iface.id))
          );
        const isSubIfaceParent =
          !iface.cidr?.trim() &&
          node.interfaces.some((other) => {
            if (other.id === iface.id) return false;
            const info = getSubInterfaceInfo(other);
            return info !== null && info.parentName.toLowerCase() === iface.name.toLowerCase();
          });
        const isUnnumberedLagOrPo =
          !iface.cidr?.trim() &&
          (iface.lacpGroup !== undefined || parsePortChannelNumber(iface.name) !== null);
        if (!isL2Port && !isSubIfaceParent && !isUnnumberedLagOrPo) {
          warnings.push(`Invalid CIDR "${iface.cidr}" on ${node.hostname}:${iface.name}`);
        }
        continue;
      }

      const vrf = iface.vrf || 'default';
      const allV4Cidrs = [effectiveCidr, ...(iface.secondaryCidrs ?? [])];
      for (const cStr of allV4Cidrs) {
        const cp = parseCidr(cStr);
        if (!cp) continue;
        const conn: CandidateRoute = {
          prefix: cp.network,
          prefixLen: cp.prefixLen,
          vrf,
          protocol: 'connected',
          ad: getEffectiveAd(node.vendor, 'connected', node.adOverrides),
          metric: 0,
          nextHop: '0.0.0.0',
          egressInterface: iface.name,
        };
        const local: CandidateRoute = {
          prefix: cp.ip,
          prefixLen: 32,
          vrf,
          protocol: 'local',
          ad: getEffectiveAd(node.vendor, 'local', node.adOverrides),
          metric: 0,
          nextHop: '0.0.0.0',
          egressInterface: iface.name,
        };
        base.push(conn, local);
        initialActive.push(
          { ...conn, active: true, ecmp: false },
          { ...local, active: true, ecmp: false }
        );
      }

      if (iface.cidr6) {
        const parsed6 = parseCidr6(iface.cidr6);
        if (parsed6) {
          const conn6: CandidateRoute = {
            af: 6,
            prefix: parsed6.network,
            prefixLen: parsed6.prefixLen,
            vrf,
            protocol: 'connected',
            ad: getEffectiveAd(node.vendor, 'connected', node.adOverrides),
            metric: 0,
            nextHop: '::',
            egressInterface: iface.name,
          };
          const local6: CandidateRoute = {
            af: 6,
            prefix: parsed6.ip,
            prefixLen: 128,
            vrf,
            protocol: 'local',
            ad: getEffectiveAd(node.vendor, 'local', node.adOverrides),
            metric: 0,
            nextHop: '::',
            egressInterface: iface.name,
          };
          base.push(conn6, local6);
          initialActive.push(
            { ...conn6, active: true, ecmp: false },
            { ...local6, active: true, ecmp: false }
          );
        }
      }
    }

    baseCandidatesByNode.set(node.id, base);
    activeRibByNode.set(node.id, initialActive);
  }

  const fhrpWinners = new Map<
    string,
    { nodeId: string; priority: number; routerId: string; ifaceName: string; vrf: string; vip: string }
  >();
  for (const node of topology.nodes) {
    for (const grp of node.fhrpGroups ?? []) {
      const iface = node.interfaces.find((i) => i.id === grp.interfaceId && !i.shutdown);
      if (!iface || !grp.virtualIp) continue;
      const vrf = iface.vrf || 'default';
      const fKey = `${grp.protocol}|${grp.groupId}|${grp.virtualIp}`;
      const cur = fhrpWinners.get(fKey);
      if (
        !cur ||
        grp.priority > cur.priority ||
        (grp.priority === cur.priority && compareIpStrings(node.routerId, cur.routerId) > 0)
      ) {
        fhrpWinners.set(fKey, {
          nodeId: node.id,
          priority: grp.priority,
          routerId: node.routerId,
          ifaceName: iface.name,
          vrf,
          vip: grp.virtualIp,
        });
      }
    }
  }
  for (const w of fhrpWinners.values()) {
    const winnerNode = topology.nodes.find((n) => n.id === w.nodeId);
    if (!winnerNode) continue;
    const vipCand: CandidateRoute = {
      prefix: w.vip,
      prefixLen: 32,
      vrf: w.vrf,
      protocol: 'local',
      ad: getEffectiveAd(winnerNode.vendor, 'local', winnerNode.adOverrides),
      metric: 0,
      nextHop: '0.0.0.0',
      egressInterface: w.ifaceName,
    };
    baseCandidatesByNode.get(w.nodeId)?.push(vipCand);
    activeRibByNode.get(w.nodeId)?.push({ ...vipCand, active: true, ecmp: false });
  }

  let convergedIterations = 0;
  const finalRibByNode = new Map<string, RibEntry[]>();

  for (let iter = 0; iter < 16; iter++) {
    convergedIterations = iter + 1;
    let anyChanged = false;

    const ospfCands = solveOspf(topology, adjMap, activeRibByNode, warnings);
    const bgpCands = solveBgp(topology, activeRibByNode, warnings);
    const eigrpCands = solveEigrp(topology, adjMap, activeRibByNode, warnings);
    const isisCands = solveIsis(topology, adjMap, activeRibByNode, warnings);
    const ripCands = solveRip(topology, adjMap, activeRibByNode);

    for (const node of topology.nodes) {
      const prevRib = activeRibByNode.get(node.id) ?? [];
      const candidates: CandidateRoute[] = [...(baseCandidatesByNode.get(node.id) ?? [])];

      for (const sr of node.staticRoutes) {
        if (sr.trackId) {
          const track = (node.tracks ?? []).find((t) => t.id === sr.trackId);
          if (track) {
            const trackRes = resolveNextHop(
              track.targetIp,
              undefined,
              track.vrf || sr.vrf || 'default',
              prevRib,
              node
            );
            if (!trackRes.resolvable) continue;
          }
        }
        const af = detectAddressFamily(sr.prefix);
        if (!af) continue;
        const parsed = af === 4 ? parseCidr(sr.prefix) : parseCidr6(sr.prefix);
        if (!parsed) continue;
        const ad =
          sr.ad !== undefined
            ? sr.ad
            : getEffectiveAd(node.vendor, 'static', node.adOverrides);
        let staticEgress = sr.interfaceName ?? '';
        if (sr.globalNextHop) {
          const gRes = resolveNextHop(sr.nextHop, sr.interfaceName, 'default', prevRib, node);
          if (!gRes.resolvable) continue;
          staticEgress = gRes.egressInterface;
        }
        candidates.push({
          af,
          prefix: parsed.network,
          prefixLen: parsed.prefixLen,
          vrf: sr.vrf || 'default',
          protocol: 'static',
          ad,
          metric: 0,
          nextHop: sr.nextHop,
          egressInterface: staticEgress,
          tag: sr.tag,
        });
      }

      candidates.push(...(ospfCands.get(node.id) ?? []));
      candidates.push(...(bgpCands.get(node.id) ?? []));
      candidates.push(...(eigrpCands.get(node.id) ?? []));
      candidates.push(...(isisCands.get(node.id) ?? []));
      candidates.push(...(ripCands.get(node.id) ?? []));

      for (const leak of node.vrfLeaks ?? []) {
        if (leak.fromVrf === leak.toVrf) continue;
        const pl = leak.matchPrefixListId
          ? (node.prefixLists ?? []).find((p) => p.id === leak.matchPrefixListId)
          : undefined;
        for (const r of prevRib) {
          if (!r.active || r.vrf !== leak.fromVrf || r.protocol === 'local') continue;
          if (pl && !matchPrefixList(r.prefix, r.prefixLen, pl)) continue;
          candidates.push({
            af: r.af,
            prefix: r.prefix,
            prefixLen: r.prefixLen,
            vrf: leak.toVrf,
            protocol: r.protocol,
            ospfType: r.ospfType,
            ad: r.ad,
            metric: r.metric,
            nextHop: r.nextHop,
            egressInterface: r.egressInterface,
            leakedFromVrf: leak.fromVrf,
            bgpAttrs: r.bgpAttrs,
          });
        }
      }

      if (node.sdwan?.enabled) {
        interface LocalTloc {
          color: string;
          encap: 'ipsec' | 'gre';
          ip: string;
          ifaceName: string;
          nextHop?: string;
          viaTlocExtension?: string;
        }
        const getDirectTlocs = (n: NodeConfig): LocalTloc[] => {
          const out: LocalTloc[] = [];
          for (const iface of n.interfaces) {
            if (iface.shutdown || !iface.tlocColor) continue;
            const parsed = parseCidr(iface.cidr);
            if (!parsed) continue;
            out.push({
              color: iface.tlocColor,
              encap: iface.tlocEncap ?? 'ipsec',
              ip: parsed.ip,
              ifaceName: iface.name,
            });
          }
          return out;
        };
        const getEffectiveTlocs = (n: NodeConfig): LocalTloc[] => {
          const tlocs = getDirectTlocs(n);
          for (const adj of adjMap.get(n.id) ?? []) {
            const peer = topology.nodes.find((x) => x.id === adj.remoteNodeId);
            if (!peer?.sdwan?.enabled) continue;
            // Peer extends one of its WAN TLOCs over this link to us
            if (adj.remoteIface.tlocExtension) {
              const peerDirect = getDirectTlocs(peer);
              const matched =
                peerDirect.find(
                  (t) =>
                    t.ifaceName.toLowerCase() === adj.remoteIface.tlocExtension?.toLowerCase() ||
                    t.color.toLowerCase() === adj.remoteIface.tlocExtension?.toLowerCase()
                ) ?? peerDirect[0];
              if (matched) {
                tlocs.push({
                  color: matched.color,
                  encap: matched.encap,
                  ip: matched.ip,
                  ifaceName: adj.localIface.name,
                  nextHop: adj.remoteIp,
                  viaTlocExtension: `${peer.hostname}:${matched.ifaceName}`,
                });
              }
            }
          }
          return tlocs;
        };

        const localTlocs = getEffectiveTlocs(node);
        const ompAd =
          node.sdwan.ompAdminDistance ??
          getEffectiveAd(node.vendor, 'omp', node.adOverrides);

        for (const remoteNode of topology.nodes) {
          if (remoteNode.id === node.id || !remoteNode.sdwan?.enabled) continue;
          const remoteTlocs = getDirectTlocs(remoteNode);
          if (remoteTlocs.length === 0 || localTlocs.length === 0) continue;

          // Match transport color when possible, otherwise allow overlay if both have active TLOCs
          const matchedPair = (() => {
            for (const lt of localTlocs) {
              const rt = remoteTlocs.find((r) => r.color === lt.color);
              if (rt) return { lt, rt };
            }
            return { lt: localTlocs[0], rt: remoteTlocs[0] };
          })();

          const remotePrevRib = activeRibByNode.get(remoteNode.id) ?? [];
          for (const r of remotePrevRib) {
            if (!r.active || r.protocol === 'local' || r.protocol === 'omp') continue;
            if (r.protocol === 'connected') {
              if (remoteNode.sdwan.advertiseConnected === false) continue;
              const isTransport = remoteNode.interfaces.some(
                (i) =>
                  i.name === r.egressInterface &&
                  (Boolean(i.tlocColor) || Boolean(i.tlocExtension))
              );
              if (isTransport) continue;
            }
            if (r.protocol === 'static' && remoteNode.sdwan.advertiseStatic === false) continue;
            if (r.protocol === 'ospf' && !remoteNode.sdwan.advertiseOspf) continue;
            if ((r.protocol === 'ebgp' || r.protocol === 'ibgp') && !remoteNode.sdwan.advertiseBgp) continue;

            // Resolve underlay next-hop to the remote TLOC (or via our TLOC-extension peer)
            let ompNextHop = matchedPair.rt.ip;
            let ompEgress = matchedPair.lt.ifaceName;
            if (matchedPair.lt.nextHop) {
              ompNextHop = matchedPair.lt.nextHop;
            } else {
              const underlay = resolveNextHop(
                matchedPair.rt.ip,
                matchedPair.lt.ifaceName,
                'default',
                prevRib,
                node
              );
              if (underlay.resolvable) {
                ompEgress = underlay.egressInterface;
              } else {
                // Direct adjacency check over same transport link
                const adj = (adjMap.get(node.id) ?? []).find(
                  (a) => a.localIface.name === matchedPair.lt.ifaceName
                );
                if (adj) {
                  ompNextHop = adj.remoteIp;
                }
              }
            }

            candidates.push({
              af: r.af ?? 4,
              prefix: r.prefix,
              prefixLen: r.prefixLen,
              vrf: r.vrf,
              protocol: 'omp',
              ad: ompAd,
              metric: matchedPair.lt.viaTlocExtension ? 10 : 0,
              nextHop: ompNextHop,
              egressInterface: ompEgress,
                tloc: {
                  systemIp: remoteNode.sdwan.systemIp,
                  color: matchedPair.rt.color,
                  encap: matchedPair.rt.encap,
                  viaTlocExtension: matchedPair.lt.viaTlocExtension,
                },
              });
            }
          }
        }

      if (
        node.lisp?.enabled &&
        node.lisp.role !== 'ms-mr' &&
        node.lisp.role !== 'petr'
      ) {
        const lispAd = getEffectiveAd(node.vendor, 'lisp', node.adOverrides);
        const myIid = node.lisp.instanceId ?? 0;
        const hasMsMrInTopo =
          Boolean(node.lisp.mapServerIp) &&
          topology.nodes.some(
            (n) =>
              n.lisp?.enabled &&
              n.lisp.role === 'ms-mr' &&
              (n.lisp.rlocIp === node.lisp!.mapServerIp ||
                n.interfaces.some((i) => parseCidr(i.cidr)?.ip === node.lisp!.mapServerIp))
          );
        const msReachable =
          !hasMsMrInTopo ||
          resolveNextHop(node.lisp.mapServerIp!, undefined, 'default', prevRib, node).resolvable;
        if (!msReachable) {
          const msg = `LISP Map-Server/Resolver ${node.lisp.mapServerIp} unreachable from ${node.hostname}`;
          if (!warnings.includes(msg)) warnings.push(msg);
        } else {
          for (const remoteNode of topology.nodes) {
            if (remoteNode.id === node.id || remoteNode.adminDown || !remoteNode.lisp?.enabled) continue;
            if (remoteNode.lisp.role === 'ms-mr' || remoteNode.lisp.role === 'pitr') continue;
            if (!remoteNode.lisp.rlocIp) continue;
            const rlocReach = resolveNextHop(
              remoteNode.lisp.rlocIp,
              undefined,
              'default',
              prevRib,
              node
            );
            if (!rlocReach.resolvable) continue;

            for (const eid of remoteNode.lisp.eidPrefixes ?? []) {
              const prio = eid.priority ?? 1;
              // RFC 9300 §6.3: Priority 255 means the RLOC MUST NOT be used for unicast forwarding
              if (prio >= 255) continue;
              const iid = eid.instanceId ?? remoteNode.lisp.instanceId ?? 0;
              // RFC 9300 §5.5 / RFC 9301: Instance ID isolation
              if (iid !== myIid) continue;
              const af = detectAddressFamily(eid.prefix);
              if (!af) continue;
              const parsed = af === 4 ? parseCidr(eid.prefix) : parseCidr6(eid.prefix);
              if (!parsed) continue;
              const wt = eid.weight ?? 100;
              candidates.push({
                af,
                prefix: parsed.network,
                prefixLen: parsed.prefixLen,
                vrf: eid.vrf || 'default',
                protocol: 'lisp',
                ad: lispAd,
                metric: prio * 100 + Math.max(0, 100 - wt),
                nextHop: remoteNode.lisp.rlocIp,
                egressInterface: rlocReach.egressInterface,
                lisp: {
                  rlocIp: remoteNode.lisp.rlocIp,
                  instanceId: iid,
                  priority: prio,
                  weight: wt,
                },
              });
            }
          }
        }
      }

      if (node.evpn?.enabled) {
        const localVrf = node.evpn.vrf || 'default';
        const ibgpAd = getEffectiveAd(node.vendor, 'ibgp', node.adOverrides);
        for (const remoteNode of topology.nodes) {
          if (remoteNode.id === node.id || !remoteNode.evpn?.enabled || !remoteNode.evpn.vtepIp) {
            continue;
          }
          const vtepReach = resolveNextHop(
            remoteNode.evpn.vtepIp,
            undefined,
            'default',
            prevRib,
            node
          );
          if (!vtepReach.resolvable) continue;
          const remoteRib = activeRibByNode.get(remoteNode.id) ?? [];
          const remoteVrf = remoteNode.evpn.vrf || 'default';
          const vni = remoteNode.evpn.l3Vni ?? remoteNode.evpn.l2Vni;
          for (const r of remoteRib) {
            if (!r.active || r.vrf !== remoteVrf || r.protocol === 'local') continue;
            if (remoteNode.evpn.advertiseConnected === false && r.protocol === 'connected') continue;
            candidates.push({
              af: r.af,
              prefix: r.prefix,
              prefixLen: r.prefixLen,
              vrf: localVrf,
              protocol: 'ibgp',
              ad: ibgpAd,
              metric: 0,
              nextHop: remoteNode.evpn.vtepIp,
              egressInterface: vtepReach.egressInterface,
              evpnVni: vni,
            });
          }
        }
      }

      if (node.mplsVpn?.enabled) {
        const ibgpAd = getEffectiveAd(node.vendor, 'ibgp', node.adOverrides);
        for (const localTarget of node.mplsVpn.vrfTargets) {
          if (!localTarget.importRt) continue;
          for (const remoteNode of topology.nodes) {
            if (remoteNode.id === node.id || !remoteNode.mplsVpn?.enabled) continue;
            const matchingRemoteVrfs = remoteNode.mplsVpn.vrfTargets.filter(
              (rt) => rt.exportRt && rt.exportRt === localTarget.importRt
            );
            if (matchingRemoteVrfs.length === 0) continue;
            const peReach = resolveNextHop(
              remoteNode.routerId,
              undefined,
              'default',
              prevRib,
              node
            );
            if (!peReach.resolvable) continue;
            const remoteRib = activeRibByNode.get(remoteNode.id) ?? [];
            for (const mVrf of matchingRemoteVrfs) {
              for (const r of remoteRib) {
                if (!r.active || r.vrf !== mVrf.vrf || r.protocol === 'local') continue;
                candidates.push({
                  af: r.af,
                  prefix: r.prefix,
                  prefixLen: r.prefixLen,
                  vrf: localTarget.vrf,
                  protocol: 'ibgp',
                  ad: ibgpAd,
                  metric: r.metric,
                  nextHop: remoteNode.routerId,
                  egressInterface: peReach.egressInterface,
                  leakedFromVrf: 'default',
                });
              }
            }
          }
        }
      }

      const byPrefix = new Map<string, RibEntry[]>();

      for (const c of candidates) {
        const res = resolveNextHop(
          c.nextHop,
          c.egressInterface || undefined,
          c.vrf,
          prevRib,
          node,
          c.leakedFromVrf
        );
        const entry: RibEntry = {
          af: c.af ?? 4,
          prefix: c.prefix,
          prefixLen: c.prefixLen,
          vrf: c.vrf,
          protocol: c.protocol,
          ospfType: c.ospfType,
          isisLevel: c.isisLevel,
          isisUpDownBit: c.isisUpDownBit,
          tag: c.tag,
          feasibleSuccessor: c.feasibleSuccessor,
          ad: c.ad,
          metric: c.metric,
          nextHop: c.nextHop,
          egressInterface: res.egressInterface || c.egressInterface,
          active: false,
          ecmp: false,
          reason: c.feasibleSuccessor
            ? 'EIGRP Feasible Successor (Backup)'
            : res.resolvable
              ? undefined
              : 'Unresolvable next-hop',
          leakedFromVrf: c.leakedFromVrf,
          bgpAttrs: c.bgpAttrs,
          tloc: c.tloc,
          lisp: c.lisp,
          evpnVni: c.evpnVni,
        };
        const key = `${c.af ?? 4}|${c.vrf}|${c.prefix}/${c.prefixLen}`;
        const list = byPrefix.get(key);
        if (list) list.push(entry);
        else byPrefix.set(key, [entry]);
      }

      const newRib: RibEntry[] = [];
      for (const list of byPrefix.values()) {
        const resolvable = list.filter((e) => !e.reason);
        const unresolvable = list.filter((e) => Boolean(e.reason));

        if (resolvable.length > 0) {
          resolvable.sort((a, b) => {
            if (a.ad !== b.ad) return a.ad - b.ad;
            return a.metric - b.metric;
          });
          const best = resolvable[0];
          const winners = resolvable
            .filter((e) => e.ad === best.ad && e.metric === best.metric)
            .slice(0, Math.max(1, node.maxPaths));

          const isEcmp = winners.length > 1;
          for (const w of winners) {
            w.active = true;
            w.ecmp = isEcmp;
          }
          for (const loser of resolvable) {
            if (!loser.active) {
              loser.reason = `Higher AD/metric than ${best.protocol.toUpperCase()} [${best.ad}/${best.metric}]`;
            }
          }
        }
        newRib.push(...resolvable, ...unresolvable);
      }

      newRib.sort((a, b) => {
        if ((a.af ?? 4) !== (b.af ?? 4)) return (a.af ?? 4) - (b.af ?? 4);
        if (a.vrf !== b.vrf) return a.vrf.localeCompare(b.vrf);
        if ((a.af ?? 4) === 4) {
          const ipDiff = ipToUint32(a.prefix) - ipToUint32(b.prefix);
          if (ipDiff !== 0) return ipDiff;
        } else {
          const diff6 = ip6ToBigInt(a.prefix) - ip6ToBigInt(b.prefix);
          if (diff6 !== 0n) return diff6 < 0n ? -1 : 1;
        }
        if (a.prefixLen !== b.prefixLen) return a.prefixLen - b.prefixLen;
        return Number(b.active) - Number(a.active);
      });

      if (ribSignature(newRib) !== ribSignature(prevRib)) {
        anyChanged = true;
      }
      activeRibByNode.set(node.id, newRib);
      finalRibByNode.set(node.id, newRib);
    }

    if (!anyChanged) break;
  }

  const routerIdCounts = new Map<string, string[]>();
  for (const n of topology.nodes) {
    if (!n.routerId) continue;
    const list = routerIdCounts.get(n.routerId) ?? [];
    list.push(n.hostname);
    routerIdCounts.set(n.routerId, list);
  }
  for (const [rid, hosts] of routerIdCounts) {
    if (hosts.length > 1) {
      warnings.push(`Duplicate Router-ID ${rid} on ${hosts.join(', ')}`);
    }
  }

  const hasArea0 = topology.nodes.some(
    (n) => n.ospf.enabled && n.interfaces.some((i) => !i.shutdown && i.ospfArea === 0)
  );
  if (hasArea0) {
    for (const n of topology.nodes) {
      if (!n.ospf.enabled) continue;
      const areas = new Set(
        n.interfaces.filter((i) => !i.shutdown && i.ospfArea !== undefined).map((i) => i.ospfArea!)
      );
      if (areas.size > 0 && !areas.has(0)) {
        const hasVlink = (n.ospf.virtualLinks?.length ?? 0) > 0;
        const neighborHasArea0 = (adjMap.get(n.id) ?? []).some((a) => {
          const rn = topology.nodes.find((x) => x.id === a.remoteNodeId);
          return rn?.ospf.enabled && rn.interfaces.some((i) => !i.shutdown && i.ospfArea === 0);
        });
        if (!hasVlink && !neighborHasArea0) {
          warnings.push(
            `OSPF ${n.hostname} has non-backbone area(s) [${Array.from(areas).join(', ')}] with no path to Area 0 (consider an OSPF virtual-link)`
          );
        }
      }
    }
  }

  for (const link of topology.links) {
    if (link.adminDown || link.linkType !== 'ipsec') continue;
    const dstUnderlay = link.ipsecConfig?.underlayDstIp;
    if (dstUnderlay) {
      const srcRib = finalRibByNode.get(link.sourceNodeId) ?? [];
      const srcNode = topology.nodes.find((n) => n.id === link.sourceNodeId);
      if (srcNode && !resolveNextHop(dstUnderlay, undefined, 'default', srcRib, srcNode).resolvable) {
        warnings.push(
          `IPsec underlay destination ${dstUnderlay} unreachable from ${srcNode.hostname}`
        );
      }
    }
  }

  const nodeResults: Record<string, NodeRoutingResult> = {};
  for (const node of topology.nodes) {
    const rib = finalRibByNode.get(node.id) ?? [];
    const neighbors: NeighborStatus[] = [];

    for (const adj of adjMap.get(node.id) ?? []) {
      const remoteNode = topology.nodes.find((n) => n.id === adj.remoteNodeId);
      if (!remoteNode) continue;
      if (
        node.ospf.enabled &&
        remoteNode.ospf.enabled &&
        adj.localIface.ospfArea !== undefined &&
        adj.remoteIface.ospfArea === adj.localIface.ospfArea &&
        !adj.localIface.passive &&
        !adj.remoteIface.passive
      ) {
        const lAuth = adj.localIface.ospfAuthKey ?? node.ospf.authKey ?? '';
        const rAuth = adj.remoteIface.ospfAuthKey ?? remoteNode.ospf.authKey ?? '';
        const lHello = adj.localIface.ospfHelloInterval ?? 10;
        const rHello = adj.remoteIface.ospfHelloInterval ?? 10;
        const lDead = adj.localIface.ospfDeadInterval ?? 40;
        const rDead = adj.remoteIface.ospfDeadInterval ?? 40;
        const timerMismatch = lHello !== rHello || lDead !== rDead;
        const lAreaType = node.ospf.areaTypes?.[adj.localIface.ospfArea] ?? 'normal';
        const rAreaType = remoteNode.ospf.areaTypes?.[adj.localIface.ospfArea] ?? 'normal';
        const normArea = (t: string) => (t === 'normal' ? 'normal' : t === 'nssa' ? 'nssa' : 'stub');
        const areaTypeMismatch = normArea(lAreaType) !== normArea(rAreaType);
        const lMtu = adj.localIface.mtu ?? 1500;
        const rMtu = adj.remoteIface.mtu ?? 1500;
        const mtuMismatch = lMtu !== rMtu;
        const customTimerTag = lHello !== 10 || lDead !== 40 ? ` (H:${lHello}s/D:${lDead}s)` : '';
        const ospfBfdTag =
          node.ospf.bfd && remoteNode.ospf.bfd
            ? ` (${formatBfdTag(
                adj.localIface.bfdIntervalMs,
                adj.localIface.bfdMinRxMs,
                adj.localIface.bfdMultiplier,
                adj.remoteIface.bfdIntervalMs,
                adj.remoteIface.bfdMinRxMs,
                adj.remoteIface.bfdMultiplier
              )})`
            : '';
        const localOspfPrio = adj.localIface.ospfPriority ?? 1;
        const remoteOspfPrio = adj.remoteIface.ospfPriority ?? 1;
        const localRid = getNodeRouterId(node, adj.localIface.vrf || 'default');
        const remoteRid = getNodeRouterId(remoteNode, adj.remoteIface.vrf || 'default');
        const isOspfP2p =
          adj.localIface.ospfNetworkType === 'point-to-point' ||
          adj.localIface.ospfNetworkType === 'point-to-multipoint';
        let ospfRole: NeighborStatus['ospfRole'] = isOspfP2p ? 'P2P' : 'DROther';
        const bothPrioZero = !isOspfP2p && localOspfPrio === 0 && remoteOspfPrio === 0;
        if (!isOspfP2p && remoteOspfPrio > 0) {
          const remoteHigher =
            remoteOspfPrio > localOspfPrio ||
            (remoteOspfPrio === localOspfPrio && compareIpStrings(remoteRid, localRid) > 0);
          ospfRole = remoteHigher ? 'DR' : localOspfPrio > 0 ? 'BDR' : 'DR';
        }
        neighbors.push({
          protocol: 'ospf',
          neighborId: remoteRid,
          peerIp: adj.remoteIp,
          interfaceName: adj.localIface.name,
          state:
            lAuth !== rAuth || timerMismatch || areaTypeMismatch
              ? 'Down'
              : mtuMismatch
                ? 'ExStart'
                : bothPrioZero
                  ? '2-Way'
                  : 'FULL',
          ospfRole,
          detail:
            lAuth !== rAuth
              ? 'Auth key mismatch'
              : timerMismatch
                ? `Timer mismatch (H:${lHello}/${rHello} D:${lDead}/${rDead})`
                : areaTypeMismatch
                  ? `Area type mismatch (${lAreaType}/${rAreaType})`
                  : mtuMismatch
                    ? `MTU mismatch (${lMtu}/${rMtu})`
                    : bothPrioZero
                      ? `Area ${adj.localIface.ospfArea} (2-Way, Priority 0)`
                      : `Area ${adj.localIface.ospfArea}${isOspfP2p ? ' (P2P)' : ` (${ospfRole})`}${customTimerTag}${ospfBfdTag}`,
        });
      }
      if (node.eigrp?.enabled && remoteNode.eigrp?.enabled && node.eigrp.asn === remoteNode.eigrp.asn && !adj.localIface.passive && !adj.remoteIface.passive) {
        const kMatch = eigrpKValuesMatch(node.eigrp.kValues, remoteNode.eigrp.kValues);
        const eHello = adj.localIface.eigrpHelloInterval;
        const eHold = adj.localIface.eigrpHoldTime;
        const eTimerTag =
          eHello !== undefined || eHold !== undefined
            ? ` (H:${eHello ?? 5}s/Hold:${eHold ?? 15}s)`
            : '';
        const eBfdTag =
          node.eigrp.bfd && remoteNode.eigrp.bfd
            ? ` (${formatBfdTag(
                adj.localIface.bfdIntervalMs,
                adj.localIface.bfdMinRxMs,
                adj.localIface.bfdMultiplier,
                adj.remoteIface.bfdIntervalMs,
                adj.remoteIface.bfdMinRxMs,
                adj.remoteIface.bfdMultiplier
              )})`
            : '';
        neighbors.push({
          protocol: 'eigrp',
          neighborId: remoteNode.hostname,
          peerIp: adj.remoteIp,
          interfaceName: adj.localIface.name,
          state: kMatch ? 'Up' : 'Down',
          detail: kMatch ? `AS ${node.eigrp.asn}${eTimerTag}${eBfdTag}` : `K-value mismatch (AS ${node.eigrp.asn})`,
        });
      }
      if (node.isis?.enabled && remoteNode.isis?.enabled && adj.localIface.isisLevel && adj.remoteIface.isisLevel && !adj.localIface.passive && !adj.remoteIface.passive) {
        const adjCheck = checkIsisAdjacency(node, adj.localIface, remoteNode, adj.remoteIface);
        const iHello = adj.localIface.isisHelloInterval;
        const iMult = adj.localIface.isisHelloMultiplier;
        const iP2p = adj.localIface.isisNetworkType === 'point-to-point' ? ' (P2P)' : '';
        const iTimerTag =
          iHello !== undefined || iMult !== undefined
            ? ` (H:${iHello ?? 10}s x${iMult ?? 3})`
            : '';
        const iBfdTag =
          node.isis.bfd && remoteNode.isis.bfd
            ? ` (${formatBfdTag(
                adj.localIface.bfdIntervalMs,
                adj.localIface.bfdMinRxMs,
                adj.localIface.bfdMultiplier,
                adj.remoteIface.bfdIntervalMs,
                adj.remoteIface.bfdMinRxMs,
                adj.remoteIface.bfdMultiplier
              )})`
            : '';
        const localIsisPrio = adj.localIface.isisPriority ?? 64;
        const remoteIsisPrio = adj.remoteIface.isisPriority ?? 64;
        const isIsisP2p = adj.localIface.isisNetworkType === 'point-to-point';
        const isisDis =
          adjCheck.ok &&
          !isIsisP2p &&
          (remoteIsisPrio > localIsisPrio ||
            (remoteIsisPrio === localIsisPrio &&
              compareIpStrings(remoteNode.routerId, node.routerId) > 0));
        neighbors.push({
          protocol: 'isis',
          neighborId: remoteNode.hostname,
          peerIp: adj.remoteIp,
          interfaceName: adj.localIface.name,
          state: adjCheck.ok ? 'Up' : 'Down',
          isisDis,
          detail: adjCheck.ok
            ? `${adj.localIface.isisLevel}${iP2p}${isisDis ? ' (DIS)' : ''}${iTimerTag}${iBfdTag}`
            : (adjCheck.reason ?? 'IS-IS adjacency down'),
        });
      }
      if (node.rip?.enabled && remoteNode.rip?.enabled && !adj.localIface.passive && !adj.remoteIface.passive) {
        neighbors.push({
          protocol: 'rip',
          neighborId: remoteNode.hostname,
          peerIp: adj.remoteIp,
          interfaceName: adj.localIface.name,
          state: 'Up',
          detail: `RIPv${node.rip.version ?? 2}`,
        });
      }
    }

    if (node.bgp.enabled) {
      for (const peer of node.bgp.peers) {
        const peerVrf = peer.vrf || 'default';
        const hasMatchingIp = (n: NodeConfig, vrfFilter?: string) =>
          !n.adminDown &&
          n.interfaces.some(
            (i) =>
              !i.shutdown &&
              (!vrfFilter || (i.vrf || 'default') === vrfFilter) &&
              (parseCidr(i.cidr)?.ip === peer.peerIp ||
                (Boolean(i.cidr6) && parseCidr6(i.cidr6!)?.ip === peer.peerIp))
          );
        const remote =
          topology.nodes.find((n) => n.id !== node.id && hasMatchingIp(n, peerVrf)) ??
          topology.nodes.find((n) => n.id !== node.id && hasMatchingIp(n));
        const reach = resolveNextHop(peer.peerIp, undefined, peerVrf, rib, node);
        const isEbgp = peer.remoteAs !== node.bgp.asn;
        const isDirect = node.interfaces.some(
          (i) =>
            !i.shutdown &&
            (i.vrf || 'default') === peerVrf &&
            (isIpInCidr(peer.peerIp, i.cidr) ||
              (Boolean(i.cidr6) && isIp6InCidr(peer.peerIp, i.cidr6!)))
        );
        const remotePeer = remote
          ? remote.bgp.peers.find((rp) =>
              node.interfaces.some(
                (i) =>
                  !i.shutdown &&
                  (parseCidr(i.cidr)?.ip === rp.peerIp ||
                    (Boolean(i.cidr6) && parseCidr6(i.cidr6!)?.ip === rp.peerIp))
              )
            )
          : undefined;
        let state: NeighborStatus['state'] = 'Established';
        let detail = `AS ${peer.remoteAs}`;
        const localAsnValid = Number.isInteger(node.bgp.asn) && node.bgp.asn >= 1 && node.bgp.asn <= 4294967295;
        const remoteAsnValid = Number.isInteger(peer.remoteAs) && peer.remoteAs >= 1 && peer.remoteAs <= 4294967295;
        if (peer.shutdown) {
          state = 'Down';
          detail = 'Admin Shutdown';
        } else if (!localAsnValid || !remoteAsnValid) {
          state = 'Down';
          detail = 'Invalid ASN (must be 1–4294967295)';
          warnings.push(`Invalid BGP ASN on ${node.hostname} (local ${node.bgp.asn}, peer ${peer.remoteAs})`);
        } else if (!remote || !remote.bgp.enabled || remote.bgp.asn !== peer.remoteAs) {
          state = 'Down';
          detail = 'Peer/AS mismatch or disabled';
        } else if (!remotePeer || remotePeer.remoteAs !== node.bgp.asn) {
          state = 'Down';
          detail = !remotePeer ? 'Peer not configured on remote' : 'Remote AS mismatch';
        } else if (remotePeer.shutdown) {
          state = 'Down';
          detail = 'Peer Admin Shutdown';
        } else if (
          peer.updateSource &&
          !node.interfaces.some((i) => i.name === peer.updateSource && !i.shutdown)
        ) {
          state = 'Down';
          detail = `Update-source ${peer.updateSource} down`;
        } else if (!reach.resolvable) {
          state = 'Down';
          detail = 'Unreachable';
        } else if (
          peer.maxPrefixes !== undefined &&
          warnings.some((w) => w.includes(`BGP peer ${peer.peerIp} on ${node.hostname} exceeded maximum-prefix`))
        ) {
          state = 'Down';
          detail = `Max-Prefix (${peer.maxPrefixes}) Exceeded`;
        } else if (isEbgp && !isDirect && !peer.ebgpMultihop && !peer.disableConnectedCheck) {
          state = 'Down';
          detail = 'eBGP-multihop required';
        } else {
          const localRid = getNodeRouterId(node, peerVrf);
          const remoteRid = getNodeRouterId(remote, remotePeer?.vrf || 'default');
          const lKa = peer.keepaliveTime ?? 60;
          const lHold = peer.holdTime ?? 180;
          const rKa = remotePeer?.keepaliveTime ?? 60;
          const rHold = remotePeer?.holdTime ?? 180;
          if (localRid === '0.0.0.0' || remoteRid === '0.0.0.0' || localRid === remoteRid) {
            state = 'Down';
            detail = localRid === remoteRid ? `Duplicate BGP Router-ID (${localRid})` : 'Invalid BGP Router-ID (0.0.0.0)';
            warnings.push(`RFC 4271 BGP ID error on ${node.hostname} <-> ${remote.hostname}: ${detail}`);
          } else if (lHold === 1 || lHold === 2 || rHold === 1 || rHold === 2) {
            state = 'Down';
            detail = `Unacceptable Hold Time (${lHold}s/${rHold}s; must be 0 or >=3s)`;
          } else {
            const negHold = Math.min(lHold, rHold);
            const customTimers = lKa !== 60 || lHold !== 180 || rKa !== 60 || rHold !== 180 ? ` (KA:${Math.min(lKa, rKa)}s/H:${negHold}s)` : '';
            detail = `AS ${peer.remoteAs}${customTimers}`;
          }
          if (lHold > 0 && lKa * 3 > lHold) {
            warnings.push(`BGP peer ${peer.peerIp} on ${node.hostname} has keepalive (${lKa}s) > 1/3 hold-time (${lHold}s)`);
          }
          const negHold = Math.min(lHold, rHold);
          const negKa = negHold === 0 ? 0 : Math.min(lKa, rKa, Math.floor(negHold / 3));
          const hasCustomTimers =
            peer.keepaliveTime !== undefined ||
            peer.holdTime !== undefined ||
            remotePeer?.keepaliveTime !== undefined ||
            remotePeer?.holdTime !== undefined;
          const flags = [
            peer.bfd
              ? formatBfdTag(
                  peer.bfdIntervalMs,
                  peer.bfdMinRxMs,
                  peer.bfdMultiplier,
                  remotePeer?.bfdIntervalMs,
                  remotePeer?.bfdMinRxMs,
                  remotePeer?.bfdMultiplier
                )
              : '',
            hasCustomTimers ? `K:${negKa}s/H:${negHold}s` : '',
            peer.routeReflectorClient && node.bgp.clusterId?.trim()
              ? `Cluster ${node.bgp.clusterId.trim()}`
              : '',
            peer.updateSource ? `Src ${peer.updateSource}` : '',
            peer.softReconfigurationInbound ? 'Soft-Reconfig' : '',
            peer.gracefulRestart || node.bgp.gracefulRestart ? 'GR' : '',
          ].filter(Boolean);
          if (flags.length) detail += ` (${flags.join(', ')})`;
        }
        neighbors.push({
          protocol: 'bgp',
          neighborId: remote ? getNodeRouterId(remote, peerVrf) : peer.peerIp,
          peerIp: peer.peerIp,
          interfaceName: reach.egressInterface || '-',
          state,
          detail,
        });
      }
    }

    if (node.lisp?.enabled && node.lisp.role !== 'ms-mr' && !node.adminDown) {
      const myIid = node.lisp.instanceId ?? 0;
      for (const remote of topology.nodes) {
        if (remote.id === node.id || remote.adminDown || !remote.lisp?.enabled) continue;
        if ((remote.lisp.instanceId ?? 0) !== myIid && remote.lisp.role !== 'ms-mr') continue;
        const rlocReach = resolveNextHop(remote.lisp.rlocIp, undefined, 'default', rib, node);
        const bothBfd = Boolean((node.lisp.bfd || node.lisp.rlocProbing) && (remote.lisp.bfd || remote.lisp.rlocProbing || true));
        const bfdLabel =
          node.lisp.bfd && (remote.lisp.bfd ?? true)
            ? ` (${formatBfdTag(
                node.lisp.bfdIntervalMs,
                node.lisp.bfdMinRxMs,
                node.lisp.bfdMultiplier,
                remote.lisp.bfdIntervalMs,
                remote.lisp.bfdMinRxMs,
                remote.lisp.bfdMultiplier
              )} RLOC-Probe)`
            : node.lisp.rlocProbing && bothBfd
              ? ' (RLOC-Probe)'
              : '';
        neighbors.push({
          protocol: 'lisp',
          neighborId: remote.hostname,
          peerIp: remote.lisp.rlocIp,
          interfaceName: rlocReach.egressInterface || '-',
          state: rlocReach.resolvable ? 'Up' : 'Down',
          detail: `IID ${myIid} (${remote.lisp.role.toUpperCase()})${bfdLabel}`,
        });
      }
    }

    for (const grp of node.fhrpGroups ?? []) {
      const winner = fhrpWinners.get(`${grp.protocol}|${grp.groupId}|${grp.virtualIp}`);
      const ifaceName = node.interfaces.find((i) => i.id === grp.interfaceId)?.name ?? grp.interfaceId;
      neighbors.push({
        protocol: grp.protocol,
        neighborId: `Grp ${grp.groupId}`,
        peerIp: grp.virtualIp,
        interfaceName: ifaceName,
        state: winner?.nodeId === node.id ? 'Active' : 'Standby',
        detail: `Prio ${grp.priority}`,
      });
    }

    if (node.vendor === 'cisco-nx-os' && node.vpc?.enabled) {
      const peerAdj = (adjMap.get(node.id) ?? []).find(
        (a) => a.localIface.id === node.vpc?.peerLinkInterfaceId
      );
      const peerNode = peerAdj ? topology.nodes.find((n) => n.id === peerAdj.remoteNodeId) : undefined;
      const keepaliveOk = node.vpc.peerKeepaliveDst
        ? resolveNextHop(
            node.vpc.peerKeepaliveDst,
            undefined,
            node.vpc.peerKeepaliveVrf || 'default',
            rib,
            node
          ).resolvable
        : false;
      let vpcState: NeighborStatus['state'] = 'Up';
      let vpcDetail = `Domain ${node.vpc.domainId}`;

      if (!peerAdj || !peerNode?.vpc?.enabled) {
        vpcState = 'Down';
        vpcDetail = 'Peer-link down or peer vPC disabled';
        warnings.push(`vPC peer-link down or unlinked on ${node.hostname}`);
      } else if (peerNode.vpc.domainId !== node.vpc.domainId) {
        vpcState = 'Down';
        vpcDetail = `Domain mismatch (${node.vpc.domainId} vs ${peerNode.vpc.domainId})`;
        warnings.push(
          `vPC domain mismatch: ${node.hostname} (domain ${node.vpc.domainId}) vs ${peerNode.hostname} (domain ${peerNode.vpc.domainId})`
        );
      } else {
        if (Boolean(peerNode.vpc.peerGateway) !== Boolean(node.vpc.peerGateway)) {
          warnings.push(`vPC peer-gateway mismatch between ${node.hostname} and ${peerNode.hostname}`);
        }
        if (Boolean(peerNode.vpc.peerSwitch) !== Boolean(node.vpc.peerSwitch)) {
          warnings.push(`vPC peer-switch mismatch between ${node.hostname} and ${peerNode.hostname}`);
        }
        if (node.vpc.peerKeepaliveDst && !keepaliveOk) {
          warnings.push(
            `vPC peer-keepalive destination ${node.vpc.peerKeepaliveDst} unreachable from ${node.hostname}`
          );
          vpcDetail = `Domain ${node.vpc.domainId} (Keepalive unreachable)`;
        } else {
          const myPrio = node.vpc.rolePriority ?? 32667;
          const peerPrio = peerNode.vpc.rolePriority ?? 32667;
          const role =
            myPrio < peerPrio || (myPrio === peerPrio && compareIpStrings(node.routerId, peerNode.routerId) < 0)
              ? 'Primary'
              : 'Secondary';
          vpcDetail = `Domain ${node.vpc.domainId} (${role})`;
        }
      }

      neighbors.push({
        protocol: 'vpc',
        neighborId: peerNode?.hostname ?? 'vPC Peer',
        peerIp: node.vpc.peerKeepaliveDst ?? peerAdj?.remoteIp ?? '-',
        interfaceName: peerAdj?.localIface.name ?? '-',
        state: vpcState,
        detail: vpcDetail,
      });
    }

    if (node.vendor === 'pan-os' && node.panHa?.enabled) {
      const ha = node.panHa;
      const adjs = adjMap.get(node.id) ?? [];
      const ha1Adj = adjs.find((a) => a.localIface.id === ha.ha1InterfaceId);
      const ha2Adj = adjs.find((a) => a.localIface.id === ha.ha2InterfaceId);
      const hsciAdj = adjs.find((a) => a.localIface.id === ha.ha3HsciInterfaceId);
      const peerAdj = ha1Adj ?? ha2Adj ?? hsciAdj;
      const peerNode = peerAdj ? topology.nodes.find((n) => n.id === peerAdj.remoteNodeId) : undefined;
      const downPeer = topology.nodes.find(
        (n) =>
          n.id !== node.id &&
          n.adminDown &&
          n.vendor === 'pan-os' &&
          n.panHa?.enabled &&
          n.panHa.groupId === ha.groupId
      );
      let haState: NeighborStatus['state'] = 'Active';
      let haDetail = `${ha.mode}, Grp ${ha.groupId}`;

      if (node.adminDown) {
        haState = 'Down';
        haDetail = 'Node Admin Down';
      } else if (!ha1Adj || !peerNode?.panHa?.enabled) {
        if (downPeer) {
          haState = 'Active';
          haDetail = 'Active (Failover — Peer Down)';
        } else {
          haState = 'Down';
          haDetail = 'HA1 control link down or peer HA disabled';
          warnings.push(`PAN-OS HA1 control link down or peer unlinked on ${node.hostname}`);
        }
      } else if (peerNode.panHa.groupId !== ha.groupId || peerNode.panHa.mode !== ha.mode) {
        haState = 'Down';
        haDetail = `Group/mode mismatch`;
        warnings.push(`PAN-OS HA group/mode mismatch between ${node.hostname} and ${peerNode.hostname}`);
      } else {
        if (ha.sessionSync && !ha2Adj && !hsciAdj) {
          warnings.push(`PAN-OS session-sync enabled on ${node.hostname} but HA2/HSCI link is down`);
        }
        if (ha.mode === 'active-active' && !hsciAdj) {
          warnings.push(`PAN-OS active-active enabled on ${node.hostname} without an UP HSCI (HA3) link`);
        }
        const myPrio = ha.devicePriority ?? 100;
        const peerPrio = peerNode.panHa.devicePriority ?? 100;
        const isPrimary =
          myPrio < peerPrio || (myPrio === peerPrio && compareIpStrings(node.routerId, peerNode.routerId) < 0);
        haState = ha.mode === 'active-active' ? 'Active' : isPrimary ? 'Active' : 'Standby';
        haDetail = `${ha.mode}${hsciAdj ? ' + HSCI' : ''}${ha2Adj ? ' + HA2 Sync' : ''}`;
      }
      neighbors.push({
        protocol: 'ha',
        neighborId: peerNode?.hostname ?? downPeer?.hostname ?? 'PAN-HA Peer',
        peerIp: peerAdj?.remoteIp ?? '-',
        interfaceName: peerAdj?.localIface.name ?? '-',
        state: haState,
        detail: haDetail,
      });
    }

    if (node.vendor === 'fortigate' && node.fortiHa?.enabled) {
      const fha = node.fortiHa;
      const hbAdj = (adjMap.get(node.id) ?? []).find((a) => a.localIface.id === fha.hbInterfaceId);
      const peerNode = hbAdj ? topology.nodes.find((n) => n.id === hbAdj.remoteNodeId) : undefined;
      const downPeer = topology.nodes.find(
        (n) =>
          n.id !== node.id &&
          n.adminDown &&
          n.vendor === 'fortigate' &&
          n.fortiHa?.enabled &&
          n.fortiHa.groupId === fha.groupId
      );
      let fState: NeighborStatus['state'] = 'Active';
      let fDetail = `FGCP ${fha.mode}, Grp ${fha.groupId}`;
      if (node.adminDown) {
        fState = 'Down';
        fDetail = 'Node Admin Down';
      } else if (!hbAdj || !peerNode?.fortiHa?.enabled) {
        if (downPeer) {
          fState = 'Active';
          fDetail = 'FGCP Active (Failover — Peer Down)';
        } else {
          fState = 'Down';
          fDetail = 'HB dev down or peer disabled';
          warnings.push(`FortiGate FGCP heartbeat down on ${node.hostname}`);
        }
      } else if (peerNode.fortiHa.groupId !== fha.groupId || peerNode.fortiHa.mode !== fha.mode) {
        fState = 'Down';
        fDetail = 'FGCP group/mode mismatch';
        warnings.push(`FortiGate FGCP group/mode mismatch between ${node.hostname} and ${peerNode.hostname}`);
      } else {
        const myPrio = fha.priority ?? 128;
        const peerPrio = peerNode.fortiHa.priority ?? 128;
        const isPrimary =
          myPrio > peerPrio || (myPrio === peerPrio && compareIpStrings(node.routerId, peerNode.routerId) > 0);
        fState = fha.mode === 'a-a' ? 'Active' : isPrimary ? 'Active' : 'Standby';
        if (fha.sessionPickup) fDetail += ' + Session-Pickup';
      }
      neighbors.push({
        protocol: 'ha',
        neighborId: peerNode?.hostname ?? downPeer?.hostname ?? 'FGCP Peer',
        peerIp: hbAdj?.remoteIp ?? '-',
        interfaceName: hbAdj?.localIface.name ?? '-',
        state: fState,
        detail: fDetail,
      });
    }

    if (node.vendor === 'forcepoint-ngfw' && node.forcepointCluster?.enabled) {
      const fc = node.forcepointCluster;
      const hbAdj = (adjMap.get(node.id) ?? []).find((a) => a.localIface.id === fc.heartbeatInterfaceId);
      const peerNode = hbAdj ? topology.nodes.find((n) => n.id === hbAdj.remoteNodeId) : undefined;
      const downPeer = topology.nodes.find(
        (n) =>
          n.id !== node.id &&
          n.adminDown &&
          n.vendor === 'forcepoint-ngfw' &&
          n.forcepointCluster?.enabled &&
          n.forcepointCluster.clusterId === fc.clusterId
      );
      let cState: NeighborStatus['state'] = 'Active';
      let cDetail = `Cluster ${fc.clusterId} (${fc.mode})`;
      if (node.adminDown) {
        cState = 'Down';
        cDetail = 'Node Admin Down';
      } else if (!hbAdj || !peerNode?.forcepointCluster?.enabled) {
        if (downPeer) {
          cState = 'Active';
          cDetail = 'Cluster Active (Failover — Peer Down)';
        } else {
          cState = 'Down';
          cDetail = 'Heartbeat link down or peer disabled';
          warnings.push(`Forcepoint cluster heartbeat down on ${node.hostname}`);
        }
      } else if (peerNode.forcepointCluster.clusterId !== fc.clusterId) {
        cState = 'Down';
        cDetail = 'Cluster ID mismatch';
        warnings.push(`Forcepoint cluster ID mismatch between ${node.hostname} and ${peerNode.hostname}`);
      } else {
        if (fc.stateSync) cDetail += ' + State-Sync';
      }
      neighbors.push({
        protocol: 'ha',
        neighborId: peerNode?.hostname ?? downPeer?.hostname ?? 'FP Cluster Peer',
        peerIp: fc.cviIp ?? hbAdj?.remoteIp ?? '-',
        interfaceName: hbAdj?.localIface.name ?? '-',
        state: cState,
        detail: cDetail,
      });
    }

    if (node.vendor === 'arista-eos' && node.mlag?.enabled) {
      const mlag = node.mlag;
      const plAdj = (adjMap.get(node.id) ?? []).find((a) => a.localIface.id === mlag.peerLinkInterfaceId);
      const peerNode = plAdj ? topology.nodes.find((n) => n.id === plAdj.remoteNodeId) : undefined;
      const peerReach = mlag.peerAddress
        ? resolveNextHop(mlag.peerAddress, undefined, 'default', rib, node).resolvable
        : Boolean(plAdj);
      let mState: NeighborStatus['state'] = 'Up';
      let mDetail = `Domain ${mlag.domainId}`;
      if (!plAdj || !peerNode?.mlag?.enabled) {
        mState = 'Down';
        mDetail = 'Peer-link down or peer MLAG disabled';
        warnings.push(`Arista MLAG peer-link down on ${node.hostname}`);
      } else if (peerNode.mlag.domainId !== mlag.domainId) {
        mState = 'Down';
        mDetail = 'Domain ID mismatch';
        warnings.push(`Arista MLAG domain mismatch between ${node.hostname} and ${peerNode.hostname}`);
      } else if (mlag.peerAddress && !peerReach) {
        mState = 'Down';
        mDetail = 'Peer address unreachable';
        warnings.push(`Arista MLAG peer-address ${mlag.peerAddress} unreachable from ${node.hostname}`);
      }
      neighbors.push({
        protocol: 'mlag',
        neighborId: peerNode?.hostname ?? 'MLAG Peer',
        peerIp: mlag.peerAddress ?? plAdj?.remoteIp ?? '-',
        interfaceName: plAdj?.localIface.name ?? '-',
        state: mState,
        detail: mDetail,
      });
    }

    if (node.sdwan?.enabled) {
      const directTlocs = node.interfaces.filter((i) => !i.shutdown && Boolean(i.tlocColor));
      const extTlocs = (adjMap.get(node.id) ?? []).filter((a) => {
        const peer = topology.nodes.find((x) => x.id === a.remoteNodeId);
        return Boolean(peer?.sdwan?.enabled && a.remoteIface.tlocExtension);
      });
      const totalTlocs = directTlocs.length + extTlocs.length;
      const peers = node.sdwan.vSmartPeers?.length ? node.sdwan.vSmartPeers : ['10.255.0.100'];
      for (const peerIp of peers) {
        neighbors.push({
          protocol: 'omp',
          neighborId: `vSmart (${peerIp})`,
          peerIp,
          interfaceName: directTlocs[0]?.name ?? extTlocs[0]?.localIface.name ?? 'system',
          state: totalTlocs > 0 ? 'Up' : 'Down',
          detail: `Site ${node.sdwan.siteId} • ${directTlocs.length} TLOC(s)${extTlocs.length > 0 ? ` + ${extTlocs.length} TLOC-Ext` : ''}`,
        });
      }
    }

    if (node.sdwanSla?.enabled) {
      for (const rule of node.sdwanSla.rules) {
        const compliant = rule.preferredMembers.some((ifName) => {
          const adj = (adjMap.get(node.id) ?? []).find((a) => a.localIface.name === ifName);
          if (!adj) return false;
          const link = topology.links.find(
            (l) =>
              !l.adminDown &&
              ((l.sourceNodeId === node.id && l.sourceInterfaceId === adj.localIface.id) ||
                (l.targetNodeId === node.id && l.targetInterfaceId === adj.localIface.id))
          );
          if (!link) return false;
          if (rule.maxLatencyMs !== undefined && (link.latencyMs ?? 0) > rule.maxLatencyMs) return false;
          if (rule.maxJitterMs !== undefined && (link.jitterMs ?? 0) > rule.maxJitterMs) return false;
          if (rule.maxLossPct !== undefined && (link.lossPct ?? 0) > rule.maxLossPct) return false;
          return true;
        });
        if (!compliant && rule.preferredMembers.length > 0) {
          warnings.push(
            `SD-WAN SLA "${rule.name}" on ${node.hostname} has no compliant member links`
          );
        }
      }
    }

    const fib: FibEntry[] = rib
      .filter((r) => r.active)
      .map((r) => ({
        af: r.af ?? 4,
        prefix: r.prefix,
        prefixLen: r.prefixLen,
        vrf: r.vrf,
        nextHop: r.nextHop,
        egressInterface: r.egressInterface,
        protocol: r.protocol,
        flags: r.protocol === 'connected' || r.protocol === 'local' ? 'u' : 'ug',
      }));

    nodeResults[node.id] = {
      nodeId: node.id,
      hostname: node.hostname,
      vendor: node.vendor,
      rib,
      fib,
      neighbors,
      stpState: stpLldp.stpByNode.get(node.id),
      lldpNeighbors: stpLldp.lldpByNode.get(node.id),
      warnings: [],
    };
  }

  const lfibMap = computeMplsLfib(topology, finalRibByNode);
  const mrouteMap = computeMulticastMroute(topology, finalRibByNode);
  const { evpnDfByNode, bmpByNode } = computeEvpnDfAndBmp(topology, finalRibByNode);
  for (const node of topology.nodes) {
    if (nodeResults[node.id]) {
      const lfib = lfibMap.get(node.id);
      if (lfib) nodeResults[node.id].lfib = lfib;
      const mroute = mrouteMap.get(node.id);
      if (mroute) nodeResults[node.id].mroute = mroute;
      const evpnDf = evpnDfByNode.get(node.id);
      if (evpnDf) nodeResults[node.id].evpnDfState = evpnDf;
      const bmp = bmpByNode.get(node.id);
      if (bmp) nodeResults[node.id].bmpSummary = bmp;
    }
  }

  return {
    nodes: nodeResults,
    computeTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
    convergedIterations,
    warnings,
  };
}

function inferHostIpFromInterface(iface: InterfaceConfig | undefined): string {
  if (!iface) return '0.0.0.0';
  const parsed = parseCidr(iface.cidr);
  if (!parsed) return iface.cidr.split('/')[0] ?? '0.0.0.0';
  if (parsed.prefixLen >= 31) return parsed.ip;
  const candidate = parsed.networkUint32 + 10;
  return candidate === parsed.ipUint32
    ? uint32ToIp(parsed.networkUint32 + 11)
    : uint32ToIp(candidate);
}

export function tracePacket(
  topology: TopologyState,
  simResult: SimulationResult,
  srcNodeId: string,
  dstIp: string,
  vrf = 'default',
  opts?: {
    srcInterfaceId?: string;
    srcIp?: string;
    protocol?: L4Protocol;
    dstPort?: number;
    packetSize?: number;
    skipReturn?: boolean;
  }
): PacketTraceResult {
  const initialAf = detectAddressFamily(dstIp);
  if (!initialAf) {
    return {
      dstIp,
      srcIp: opts?.srcIp,
      srcNodeId,
      srcInterfaceId: opts?.srcInterfaceId,
      vrf,
      hops: [],
      outcome: 'dropped',
      failureReason: 'Invalid destination IP address',
    };
  }

  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));
  const standbyNodes = computeStandbyNodes(topology);
  const adjMap = buildAdjacencies(topology, [], standbyNodes);
  const hops: PacketTraceHop[] = [];
  const visited = new Set<string>();
  let currentId: string | null = srcNodeId;
  const startNode = nodeMap.get(srcNodeId);
  if (startNode?.adminDown) {
    return {
      dstIp,
      srcIp: opts?.srcIp?.trim() || '0.0.0.0',
      srcNodeId,
      srcInterfaceId: opts?.srcInterfaceId,
      vrf,
      hops,
      outcome: 'dropped',
      blockedNodeId: startNode.id,
      failureReason: `Source node ${startNode.hostname} is down (admin-down)`,
    };
  }
  const startIface = opts?.srcInterfaceId
    ? startNode?.interfaces.find((i) => i.id === opts.srcInterfaceId)
    : startNode?.interfaces[0];
  let currentVrf = opts?.srcInterfaceId ? (startIface?.vrf || vrf) : vrf;
  let currentIngressIf = startIface?.name;
  let currentSrcIp = opts?.srcIp?.trim() || inferHostIpFromInterface(startIface);
  let currentDstIp = dstIp.trim();
  let overlayInnerDstIp: string | null = null;
  const l4Proto = opts?.protocol ?? 'any';
  const dstPort = opts?.dstPort;
  const packetSize = opts?.packetSize ?? 1500;
  let totalLatencyMs = 0;
  let totalJitterMs = 0;
  let survivingProb = 1;
  let minPathMtu = Infinity;

  for (let ttl = 0; ttl < 32 && currentId; ttl++) {
    const node = nodeMap.get(currentId);
    const res: NodeRoutingResult | undefined = simResult.nodes[currentId];
    if (!node || !res) break;

    const visitKey = `${currentId}|${currentVrf}`;
    if (visited.has(visitKey)) {
      hops.push({
        nodeId: node.id,
        hostname: node.hostname,
        vrf: currentVrf,
        ingressInterface: currentIngressIf,
        egressInterface: '-',
        nextHop: '-',
        matchedPrefix: '-',
        protocol: 'static',
        ad: 0,
        metric: 0,
        status: 'loop',
        routeStatus: 'loop',
      });
      return {
        dstIp,
        srcIp: currentSrcIp,
        srcNodeId,
        srcInterfaceId: opts?.srcInterfaceId,
        vrf,
        hops,
        outcome: 'loop',
        blockedNodeId: node.id,
        failureReason: `Routing loop detected at ${node.hostname} [${currentVrf}]`,
      };
    }
    visited.add(visitKey);

    const dnat = evaluatePreRoutingDnat(node.natRules, currentSrcIp, currentDstIp);
    currentDstIp = dnat.dstIp;
    const nat64 = evaluateNat64(node, currentDstIp);
    if (nat64) {
      currentDstIp = nat64.dstIp;
    }
    const af = detectAddressFamily(currentDstIp) ?? initialAf;

    const isMplsOrDiaCloud = node.vendor === 'mpls-cloud' || node.vendor === 'internet-cloud';

    // RFC 3704 uRPF check on ingress interface
    const ingressIfaceObj = currentIngressIf
      ? node.interfaces.find((i) => i.name === currentIngressIf)
      : undefined;
    let urpfStatus: PacketTraceHop['urpfStatus'];
    if (
      !isMplsOrDiaCloud &&
      ingressIfaceObj?.urpfMode &&
      currentSrcIp &&
      currentSrcIp !== '0.0.0.0' &&
      currentSrcIp !== '::'
    ) {
      const srcAf = detectAddressFamily(currentSrcIp) ?? af;
      const revMatches =
        srcAf === 4
          ? buildActiveTrie(res.rib, currentVrf).longestPrefixMatch(ipToUint32(currentSrcIp))
          : buildActiveTrie6(res.rib, currentVrf).longestPrefixMatch(ip6ToBigInt(currentSrcIp));
      const hasRevRoute = Boolean(revMatches && revMatches.length > 0);
      const strictOk =
        hasRevRoute &&
        revMatches!.some((m) => m.egressInterface === ingressIfaceObj.name);
      if (ingressIfaceObj.urpfMode === 'loose' && !hasRevRoute) {
        urpfStatus = 'drop-loose';
      } else if (ingressIfaceObj.urpfMode === 'strict' && !strictOk) {
        urpfStatus = 'drop-strict';
      } else {
        urpfStatus = 'pass';
      }
      if (urpfStatus !== 'pass') {
        hops.push({
          nodeId: node.id,
          hostname: node.hostname,
          vrf: currentVrf,
          ingressInterface: currentIngressIf,
          egressInterface: '-',
          nextHop: '-',
          matchedPrefix: 'uRPF',
          protocol: 'static',
          ad: 0,
          metric: 0,
          status: 'dropped',
          urpfStatus,
        });
        return {
          dstIp,
          srcIp: currentSrcIp,
          srcNodeId,
          srcInterfaceId: opts?.srcInterfaceId,
          vrf,
          hops,
          outcome: 'dropped',
          blockedNodeId: node.id,
          failureReason: `uRPF (${ingressIfaceObj.urpfMode}) drop for source ${currentSrcIp} on ${node.hostname}:${ingressIfaceObj.name}`,
        };
      }
    }

    const matches: RibEntry[] | null =
      af === 4
        ? buildActiveTrie(res.rib, currentVrf).longestPrefixMatch(ipToUint32(currentDstIp))
        : buildActiveTrie6(res.rib, currentVrf).longestPrefixMatch(ip6ToBigInt(currentDstIp));
    if (!matches || matches.length === 0) {
      if (isMplsOrDiaCloud) {
        const snatCloud = evaluatePostRoutingSnat(node.natRules, currentSrcIp, currentDstIp);
        currentSrcIp = snatCloud.srcIp;
        const natNoteCloud = [dnat.note, snatCloud.note].filter(Boolean).join(' | ') || undefined;
        hops.push({
          nodeId: node.id,
          hostname: node.hostname,
          vrf: currentVrf,
          ingressInterface: currentIngressIf,
          egressInterface: 'any',
          nextHop: node.vendor === 'mpls-cloud' ? 'mpls-accept' : 'dia-accept',
          matchedPrefix: af === 6 ? '::/0' : '0.0.0.0/0',
          protocol: 'connected',
          ad: 0,
          metric: 0,
          status: 'delivered',
          routeStatus: 'ok',
          aclStatus: 'allowed',
          natApplied: natNoteCloud,
        });
        const returnTrace =
          !opts?.skipReturn && node.id !== srcNodeId && currentSrcIp && currentSrcIp !== '0.0.0.0'
            ? tracePacket(topology, simResult, node.id, currentSrcIp, currentVrf, {
                srcIp: currentDstIp,
                protocol: l4Proto,
                dstPort,
                skipReturn: true,
              })
            : undefined;
        const forwardNodeSeq = hops.map((h) => h.nodeId).join('>');
        const returnNodeSeq =
          returnTrace?.outcome === 'delivered'
            ? [...returnTrace.hops].reverse().map((h) => h.nodeId).join('>')
            : undefined;
        const asymmetricPath = Boolean(returnNodeSeq && returnNodeSeq !== forwardNodeSeq);
        const resolvedMtu = minPathMtu === Infinity ? undefined : minPathMtu;
        const srcNodeObj = nodeMap.get(srcNodeId);
        const ipfixCollector = srcNodeObj?.telemetry?.ipfixCollectorIp ?? node.telemetry?.ipfixCollectorIp;
        return {
          dstIp,
          srcIp: currentSrcIp,
          srcNodeId,
          srcInterfaceId: opts?.srcInterfaceId,
          vrf,
          hops,
          outcome: 'delivered',
          totalLatencyMs: totalLatencyMs > 0 ? Math.round(totalLatencyMs * 100) / 100 : undefined,
          totalJitterMs: totalJitterMs > 0 ? Math.round(totalJitterMs * 100) / 100 : undefined,
          combinedLossPct:
            survivingProb < 1 ? Math.round((1 - survivingProb) * 10000) / 100 : undefined,
          pathMtu: resolvedMtu,
          mtuWarning:
            resolvedMtu !== undefined && packetSize > resolvedMtu
              ? `Packet size ${packetSize}B exceeds path MTU ${resolvedMtu}B (fragmentation / PMTUD drop risk)`
              : undefined,
          asymmetricPath: asymmetricPath || undefined,
          ipfixRecord: ipfixCollector
            ? {
                srcIp: currentSrcIp,
                dstIp: currentDstIp,
                protocol: l4Proto,
                dstPort,
                bytes: packetSize,
                dscp: hops.find((h) => h.dscp !== undefined)?.dscp,
                exporterIp: ipfixCollector,
              }
            : undefined,
          returnTrace: returnTrace
            ? {
                outcome: returnTrace.outcome,
                hops: returnTrace.hops,
                failureReason: returnTrace.failureReason,
              }
            : undefined,
        };
      }
      hops.push({
        nodeId: node.id,
        hostname: node.hostname,
        vrf: currentVrf,
        ingressInterface: currentIngressIf,
        egressInterface: '-',
        nextHop: '-',
        matchedPrefix: 'none',
        protocol: 'static',
        ad: 0,
        metric: 0,
        status: 'dropped',
        routeStatus: 'no-route',
        natApplied: dnat.note,
      });
      return {
        dstIp,
        srcIp: currentSrcIp,
        srcNodeId,
        srcInterfaceId: opts?.srcInterfaceId,
        vrf,
        hops,
        outcome: 'dropped',
        blockedNodeId: node.id,
        failureReason: `No route to ${currentDstIp} on ${node.hostname} [${currentVrf}]`,
      };
    }

    const best: RibEntry = matches[0];
    const ecmpMatches = matches.filter(
      (m) => m.prefix === best.prefix && m.prefixLen === best.prefixLen
    );
    const ecmpPaths =
      ecmpMatches.length > 1
        ? ecmpMatches.map((m) => `${m.nextHop} (${m.egressInterface || 'local'})`)
        : undefined;
    const matchedPrefix = `${best.prefix}/${best.prefixLen}`;
    const adjs: Adjacency[] = adjMap.get(node.id) ?? [];
    let selectedEgressIf = best.egressInterface;
    let selectedNextHop = best.nextHop;
    let sdwanSteeredNote: string | undefined;
    let pbrAppliedNote: string | undefined;
    let encapNote: string | undefined;

    if (
      best.protocol !== 'local' &&
      best.protocol !== 'connected' &&
      node.pbrRules &&
      node.pbrRules.length > 0
    ) {
      const matchedPbr = node.pbrRules.find((rule) => {
        if (rule.interfaceName && currentIngressIf && rule.interfaceName !== currentIngressIf) {
          return false;
        }
        return af === 4 ? isIpInCidr(currentDstIp, rule.matchPrefix) : isIp6InCidr(currentDstIp, rule.matchPrefix);
      });
      if (matchedPbr) {
        selectedNextHop = matchedPbr.nextHop;
        if (matchedPbr.interfaceName) {
          selectedEgressIf = matchedPbr.interfaceName;
        } else {
          const pbrAdj = adjs.find(
            (a) => a.remoteIp === matchedPbr.nextHop || a.remoteIp6 === matchedPbr.nextHop
          );
          if (pbrAdj) selectedEgressIf = pbrAdj.localIface.name;
        }
        pbrAppliedNote = `PBR "${matchedPbr.name}" -> ${selectedNextHop}`;
      }
    }

    const flowspecRes = isMplsOrDiaCloud
      ? null
      : evaluateFlowspec(node, currentSrcIp, currentDstIp, l4Proto, dstPort);
    if (flowspecRes?.action === 'drop') {
      hops.push({
        nodeId: node.id,
        hostname: node.hostname,
        vrf: currentVrf,
        ingressInterface: currentIngressIf,
        egressInterface: selectedEgressIf,
        nextHop: selectedNextHop,
        matchedPrefix,
        protocol: best.protocol,
        ad: best.ad,
        metric: best.metric,
        status: 'blocked',
        routeStatus: 'ok',
        flowspecMatched: flowspecRes.note,
      });
      return {
        dstIp,
        srcIp: currentSrcIp,
        srcNodeId,
        srcInterfaceId: opts?.srcInterfaceId,
        vrf,
        hops,
        outcome: 'blocked',
        blockedNodeId: node.id,
        failureReason: `Blocked by ${flowspecRes.note} on ${node.hostname}`,
      };
    }
    if (flowspecRes?.action === 'redirect' && flowspecRes.redirectNextHop) {
      selectedNextHop = flowspecRes.redirectNextHop;
      const fsAdj = adjs.find(
        (a) => a.remoteIp === selectedNextHop || a.remoteIp6 === selectedNextHop
      );
      if (fsAdj) selectedEgressIf = fsAdj.localIface.name;
    }

    if (
      best.protocol !== 'local' &&
      best.protocol !== 'connected' &&
      node.sdwanSla?.enabled &&
      node.sdwanSla.rules.length > 0
    ) {
      const matchedRule = node.sdwanSla.rules.find((rule) => {
        if (rule.dstCidr && rule.dstCidr !== '0.0.0.0/0') {
          if (af !== 4 || !isIpInCidr(currentDstIp, rule.dstCidr)) return false;
        }
        if (rule.protocol && rule.protocol !== 'any' && rule.protocol !== l4Proto) return false;
        if (rule.dstPort !== undefined && rule.dstPort !== dstPort) return false;
        return true;
      });
      if (matchedRule && matchedRule.preferredMembers.length > 0) {
        const candidates = matchedRule.preferredMembers
          .map((ifName) => {
            const adj = adjs.find((a) => a.localIface.name === ifName);
            if (!adj) return null;
            const link = topology.links.find(
              (l) =>
                !l.adminDown &&
                ((l.sourceNodeId === node.id && l.sourceInterfaceId === adj.localIface.id) ||
                  (l.targetNodeId === node.id && l.targetInterfaceId === adj.localIface.id))
            );
            if (!link) return null;
            const lat = link.latencyMs ?? 0;
            const jit = link.jitterMs ?? 0;
            const loss = link.lossPct ?? 0;
            const ok =
              (matchedRule.maxLatencyMs === undefined || lat <= matchedRule.maxLatencyMs) &&
              (matchedRule.maxJitterMs === undefined || jit <= matchedRule.maxJitterMs) &&
              (matchedRule.maxLossPct === undefined || loss <= matchedRule.maxLossPct);
            const score = lat + jit * 2 + loss * 20;
            return { ifName, adj, lat, jit, loss, ok, score };
          })
          .filter((x): x is NonNullable<typeof x> => Boolean(x));

        if (candidates.length > 0) {
          let chosen = candidates.find((c) => c.ok) ?? candidates[0];
          if (matchedRule.mode === 'best-quality') {
            const pool = candidates.some((c) => c.ok)
              ? candidates.filter((c) => c.ok)
              : candidates;
            chosen = [...pool].sort((a, b) => a.score - b.score)[0];
          }
          selectedEgressIf = chosen.ifName;
          selectedNextHop = chosen.adj.remoteIp;
          sdwanSteeredNote = `${matchedRule.name}: ${chosen.ifName} (${chosen.lat}ms, ${chosen.loss}% loss)`;
        }
      }
    }

    const ingressZone = currentIngressIf
      ? node.interfaces.find((i) => i.name === currentIngressIf)?.zone
      : undefined;
    const egressZone = selectedEgressIf
      ? node.interfaces.find((i) => i.name === selectedEgressIf)?.zone
      : undefined;

    const acl = isMplsOrDiaCloud
      ? { allowed: true }
      : evaluateAcl(
          node.aclRules,
          currentSrcIp,
          currentDstIp,
          l4Proto,
          dstPort,
          ingressZone,
          egressZone
        );
    if (!acl.allowed) {
      hops.push({
        nodeId: node.id,
        hostname: node.hostname,
        vrf: currentVrf,
        ingressInterface: currentIngressIf,
        egressInterface: selectedEgressIf,
        nextHop: selectedNextHop,
        matchedPrefix,
        protocol: best.protocol,
        ad: best.ad,
        metric: best.metric,
        status: 'blocked',
        routeStatus: 'ok',
        aclStatus: 'blocked',
        aclMatched: acl.matchedRule,
        natApplied: dnat.note,
      });
      return {
        dstIp,
        srcIp: currentSrcIp,
        srcNodeId,
        srcInterfaceId: opts?.srcInterfaceId,
        vrf,
        hops,
        outcome: 'blocked',
        blockedNodeId: node.id,
        failureReason: `Blocked at ${node.hostname} by ${acl.matchedRule}`,
      };
    }

    const snat = evaluatePostRoutingSnat(node.natRules, currentSrcIp, currentDstIp);
    currentSrcIp = snat.srcIp;
    const natNote = [dnat.note, snat.note].filter(Boolean).join(' | ') || undefined;

    if (
      !overlayInnerDstIp &&
      ((best.protocol === 'omp' && !best.tloc?.viaTlocExtension) ||
        best.protocol === 'lisp' ||
        best.evpnVni !== undefined)
    ) {
      overlayInnerDstIp = currentDstIp;
      currentDstIp = best.nextHop;
      if (best.protocol === 'lisp' && best.lisp) {
        encapNote = `LISP encap -> RLOC ${best.lisp.rlocIp} (IID ${best.lisp.instanceId})`;
      } else if (best.evpnVni !== undefined) {
        encapNote = `VXLAN EVPN encap -> VTEP ${best.nextHop} (VNI ${best.evpnVni})`;
      }
    }

    if (best.protocol === 'local' || best.protocol === 'connected') {
      if (overlayInnerDstIp) {
        const isTunnelEndpoint =
          (Boolean(node.sdwan?.enabled) ||
            Boolean(node.lisp?.enabled) ||
            Boolean(node.evpn?.enabled)) &&
          node.interfaces.some(
            (i) =>
              parseCidr(i.cidr)?.ip === currentDstIp ||
              (i.cidr6 ? parseCidr6(i.cidr6)?.ip === currentDstIp : false)
          );
        if (isTunnelEndpoint) {
          currentDstIp = overlayInnerDstIp;
          overlayInnerDstIp = null;
          visited.delete(visitKey);
          continue;
        }
        // Transit router (e.g. MPLS core) with connected subnet to the remote TLOC: forward across the link instead of terminating
      } else {
        hops.push({
        nodeId: node.id,
        hostname: node.hostname,
        vrf: currentVrf,
        ingressInterface: currentIngressIf,
        egressInterface: best.egressInterface,
        nextHop: 'direct',
        matchedPrefix,
        protocol: best.protocol,
        ad: best.ad,
        metric: best.metric,
        status: 'delivered',
        routeStatus: 'ok',
        aclStatus: 'allowed',
        aclMatched: acl.matchedRule,
        natApplied: natNote,
      });
      const returnTrace =
        !opts?.skipReturn && node.id !== srcNodeId && currentSrcIp && currentSrcIp !== '0.0.0.0'
          ? tracePacket(topology, simResult, node.id, currentSrcIp, currentVrf, {
              srcIp: currentDstIp,
              protocol: l4Proto,
              dstPort,
              skipReturn: true,
            })
          : undefined;
      const forwardNodeSeq = hops.map((h) => h.nodeId).join('>');
      const returnNodeSeq =
        returnTrace?.outcome === 'delivered'
          ? [...returnTrace.hops].reverse().map((h) => h.nodeId).join('>')
          : undefined;
      const asymmetricPath = Boolean(
        returnNodeSeq && returnNodeSeq !== forwardNodeSeq
      );
      const resolvedMtu = minPathMtu === Infinity ? undefined : minPathMtu;
      const srcNodeObj = nodeMap.get(srcNodeId);
      const ipfixCollector = srcNodeObj?.telemetry?.ipfixCollectorIp ?? node.telemetry?.ipfixCollectorIp;
      return {
        dstIp,
        srcIp: currentSrcIp,
        srcNodeId,
        srcInterfaceId: opts?.srcInterfaceId,
        vrf,
        hops,
        outcome: 'delivered',
        totalLatencyMs: totalLatencyMs > 0 ? Math.round(totalLatencyMs * 100) / 100 : undefined,
        totalJitterMs: totalJitterMs > 0 ? Math.round(totalJitterMs * 100) / 100 : undefined,
        combinedLossPct:
          survivingProb < 1 ? Math.round((1 - survivingProb) * 10000) / 100 : undefined,
        pathMtu: resolvedMtu,
        mtuWarning:
          resolvedMtu !== undefined && packetSize > resolvedMtu
            ? `Packet size ${packetSize}B exceeds path MTU ${resolvedMtu}B (fragmentation / PMTUD drop risk)`
            : undefined,
        asymmetricPath: asymmetricPath || undefined,
        ipfixRecord: ipfixCollector
          ? {
              srcIp: currentSrcIp,
              dstIp: currentDstIp,
              protocol: l4Proto,
              dstPort,
              bytes: packetSize,
              dscp: hops.find((h) => h.dscp !== undefined)?.dscp,
              exporterIp: ipfixCollector,
            }
          : undefined,
        returnTrace: returnTrace
          ? {
              outcome: returnTrace.outcome,
              hops: returnTrace.hops,
              failureReason: returnTrace.failureReason,
            }
          : undefined,
        };
      }
    }

    const nextAdj: Adjacency | undefined =
      adjs.find(
        (a: Adjacency) =>
          a.localIface.name === selectedEgressIf &&
          (a.remoteIp === selectedNextHop || a.remoteIp6 === selectedNextHop)
      ) ?? adjs.find((a: Adjacency) => a.localIface.name === selectedEgressIf);

    if (!nextAdj) {
      hops.push({
        nodeId: node.id,
        hostname: node.hostname,
        vrf: currentVrf,
        ingressInterface: currentIngressIf,
        egressInterface: selectedEgressIf,
        nextHop: selectedNextHop,
        matchedPrefix,
        protocol: best.protocol,
        ad: best.ad,
        metric: best.metric,
        status: 'dropped',
        routeStatus: 'no-route',
        aclStatus: 'allowed',
        aclMatched: acl.matchedRule,
        natApplied: natNote,
      });
      return {
        dstIp,
        srcIp: currentSrcIp,
        srcNodeId,
        srcInterfaceId: opts?.srcInterfaceId,
        vrf,
        hops,
        outcome: 'dropped',
        blockedNodeId: node.id,
        failureReason: `Next-hop ${selectedNextHop} unreachable via ${selectedEgressIf} on ${node.hostname}`,
      };
    }

    const localSubInfo = getSubInterfaceInfo(nextAdj.localIface);
    const localParentIface = localSubInfo
      ? node.interfaces.find((i) => i.name.toLowerCase() === localSubInfo.parentName.toLowerCase())
      : undefined;
    const localPoNum = parsePortChannelNumber((localParentIface ?? nextAdj.localIface).name);
    const remotePoNum = parsePortChannelNumber(nextAdj.remoteIface.name);
    const traversedLink =
      topology.links.find(
        (l) =>
          !l.adminDown &&
          ((l.sourceNodeId === node.id &&
            (l.sourceInterfaceId === nextAdj.localIface.id ||
              (localParentIface && l.sourceInterfaceId === localParentIface.id)) &&
            l.targetNodeId === nextAdj.remoteNodeId) ||
            (l.targetNodeId === node.id &&
              (l.targetInterfaceId === nextAdj.localIface.id ||
                (localParentIface && l.targetInterfaceId === localParentIface.id)) &&
              l.sourceNodeId === nextAdj.remoteNodeId))
      ) ??
      (localPoNum !== null && remotePoNum !== null
        ? topology.links
            .filter((l) => {
              if (l.adminDown) return false;
              const isSrc = l.sourceNodeId === node.id && l.targetNodeId === nextAdj.remoteNodeId;
              const isDst = l.targetNodeId === node.id && l.sourceNodeId === nextAdj.remoteNodeId;
              if (!isSrc && !isDst) return false;
              const lIf = node.interfaces.find(
                (i) => i.id === (isSrc ? l.sourceInterfaceId : l.targetInterfaceId)
              );
              const rNode = nodeMap.get(nextAdj.remoteNodeId);
              const rIf = rNode?.interfaces.find(
                (i) => i.id === (isSrc ? l.targetInterfaceId : l.sourceInterfaceId)
              );
              return (
                lIf &&
                rIf &&
                !lIf.shutdown &&
                !rIf.shutdown &&
                lIf.lacpGroup === localPoNum &&
                rIf.lacpGroup === remotePoNum &&
                negotiateLagPair(lIf, rIf).ok
              );
            })
            .sort((a, b) => (a.latencyMs ?? 0) - (b.latencyMs ?? 0))[0]
        : undefined);
    let macsecSecured = false;
    let ecnMarked = false;
    if (traversedLink) {
      macsecSecured = Boolean(nextAdj.localIface.macsecEnabled && nextAdj.remoteIface.macsecEnabled);
      const macsecOverhead = macsecSecured ? 32 : 0;
      const encapOverhead =
        (best.protocol === 'lisp'
          ? 36
          : best.evpnVni !== undefined
            ? 50
            : best.tloc?.encap === 'gre'
              ? 24
              : best.tloc?.encap === 'ipsec' && traversedLink.linkType !== 'ipsec'
                ? 60
                : 0) + macsecOverhead;
      if (
        nextAdj.localIface.qosPolicy?.ecnEnabled &&
        ((traversedLink.latencyMs ?? 0) > 20 || (traversedLink.lossPct ?? 0) > 0)
      ) {
        ecnMarked = true;
      }
      const rawLinkMtu = Math.min(
        nextAdj.localIface.mtu ?? (traversedLink.linkType === 'ipsec' ? 1400 : 1500),
        nextAdj.remoteIface.mtu ?? (traversedLink.linkType === 'ipsec' ? 1400 : 1500)
      );
      const linkMtu = Math.max(576, rawLinkMtu - encapOverhead);
      minPathMtu = Math.min(minPathMtu, linkMtu);
      totalLatencyMs += traversedLink.latencyMs ?? 0;
      totalJitterMs += traversedLink.jitterMs ?? 0;
      const loss = Math.min(100, Math.max(0, traversedLink.lossPct ?? 0));
      if (loss >= 100) {
        hops.push({
          nodeId: node.id,
          hostname: node.hostname,
          vrf: currentVrf,
          ingressInterface: currentIngressIf,
          egressInterface: selectedEgressIf,
          nextHop: selectedNextHop,
          matchedPrefix,
          protocol: best.protocol,
          ad: best.ad,
          metric: best.metric,
          status: 'dropped',
          routeStatus: 'ok',
          aclStatus: 'allowed',
          aclMatched: acl.matchedRule,
          natApplied: natNote,
        });
        return {
          dstIp,
          srcIp: currentSrcIp,
          srcNodeId,
          srcInterfaceId: opts?.srcInterfaceId,
          vrf,
          hops,
          outcome: 'dropped',
          blockedNodeId: node.id,
          failureReason: `Packet dropped by 100% link loss on ${node.hostname}:${selectedEgressIf}`,
          totalLatencyMs: totalLatencyMs > 0 ? Math.round(totalLatencyMs * 100) / 100 : undefined,
          totalJitterMs: totalJitterMs > 0 ? Math.round(totalJitterMs * 100) / 100 : undefined,
          combinedLossPct: 100,
        };
      }
      survivingProb *= 1 - loss / 100;
    }

    const matchingLfib = res.lfib?.find((l) => l.prefix === matchedPrefix);
    const mplsLabels = matchingLfib
      ? [matchingLfib.inLabel, ...(matchingLfib.outLabel === 'POP' ? [] : [matchingLfib.outLabel])]
      : undefined;
    const dscp = ingressIfaceObj?.qosPolicy?.dscpMark;
    hops.push({
      nodeId: node.id,
      hostname: node.hostname,
      vrf: currentVrf,
      ingressInterface: currentIngressIf,
      egressInterface: selectedEgressIf,
      nextHop: selectedNextHop,
      matchedPrefix,
      protocol: best.protocol,
      ad: best.ad,
      metric: best.metric,
      status: 'forwarded',
      routeStatus: 'ok',
      aclStatus: 'allowed',
      aclMatched: acl.matchedRule,
      natApplied: nat64?.note ?? natNote,
      sdwanSteered: sdwanSteeredNote,
      pbrApplied: pbrAppliedNote,
      ecmpPaths,
      encapNote,
      urpfStatus,
      mplsLabels,
      flowspecMatched: flowspecRes?.note,
      dscp,
      ecnMarked: ecnMarked || undefined,
      macsecSecured: macsecSecured || undefined,
    });
    currentId = nextAdj.remoteNodeId;
    currentVrf = nextAdj.remoteIface.vrf || 'default';
    currentIngressIf = nextAdj.remoteIface.name;
  }

  return {
    dstIp,
    srcIp: currentSrcIp,
    srcNodeId,
    srcInterfaceId: opts?.srcInterfaceId,
    vrf,
    hops,
    outcome: 'dropped',
    failureReason: 'TTL exceeded',
  };
}

export interface PathTestRunResult {
  test: PathTestCase;
  trace: PacketTraceResult;
  passed: boolean;
  message: string;
}

export function runPathTestSuite(
  topology: TopologyState,
  simResult: SimulationResult,
  tests: PathTestCase[]
): { passed: number; failed: number; results: PathTestRunResult[] } {
  const results: PathTestRunResult[] = tests.map((test) => {
    const trace = tracePacket(
      topology,
      simResult,
      test.srcNodeId,
      test.dstIp,
      test.vrf,
      {
        srcInterfaceId: test.srcInterfaceId,
        srcIp: test.srcIp,
        protocol: test.protocol,
        dstPort: test.dstPort,
      }
    );

    const outcomeOk = trace.outcome === test.expectedOutcome;
    const nodeOk =
      !test.expectedBlockedNodeId ||
      trace.blockedNodeId === test.expectedBlockedNodeId;
    const passed = outcomeOk && nodeOk;

    const message = passed
      ? `PASS: ${trace.outcome.toUpperCase()} (${trace.hops.length} hops)`
      : `FAIL: expected ${test.expectedOutcome.toUpperCase()}${test.expectedBlockedNodeId ? ` at ${test.expectedBlockedNodeId}` : ''}, got ${trace.outcome.toUpperCase()}${trace.failureReason ? ` — ${trace.failureReason}` : ''}`;

    return { test, trace, passed, message };
  });

  return {
    passed: results.filter((r) => r.passed).length,
    failed: results.filter((r) => !r.passed).length,
    results,
  };
}

export function runFailoverMatrix(
  topology: TopologyState,
  tests: PathTestCase[]
): FailoverMatrixEntry[] {
  if (tests.length === 0) return [];
  const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));
  const activeLinks = topology.links.filter((l) => !l.adminDown);

  return activeLinks.map((link) => {
    const failedTopo: TopologyState = {
      ...topology,
      links: topology.links.map((l) =>
        l.id === link.id ? { ...l, adminDown: true } : l
      ),
    };
    const sim = solveTopology(failedTopo);
    const suite = runPathTestSuite(failedTopo, sim, tests);
    const srcName = nodeMap.get(link.sourceNodeId)?.hostname ?? link.sourceNodeId;
    const dstName = nodeMap.get(link.targetNodeId)?.hostname ?? link.targetNodeId;
    return {
      linkId: link.id,
      linkLabel: `${srcName} <-> ${dstName}`,
      passed: suite.passed,
      failed: suite.failed,
      brokenTests: suite.results.filter((r) => !r.passed).map((r) => r.test.name),
    };
  });
}