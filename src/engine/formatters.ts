import { NodeConfig, NodeRoutingResult, RibEntry } from '../types/network';
import { parseCidr, uint32ToIp } from './ipMath';

function ciscoCode(entry: RibEntry): string {
  switch (entry.protocol) {
    case 'connected':
      return 'C';
    case 'local':
      return 'L';
    case 'static':
      return entry.prefix === '0.0.0.0' && entry.prefixLen === 0 ? 'S*' : 'S';
    case 'ospf':
      if (entry.ospfType === 'inter') return 'O IA';
      if (entry.ospfType === 'ext1') return 'O E1';
      if (entry.ospfType === 'ext2') return 'O E2';
      return 'O';
    case 'ebgp':
    case 'ibgp':
      return 'B';
    case 'eigrp':
      return 'D';
    case 'isis':
      return entry.isisLevel === 'L1' ? 'i L1' : entry.isisLevel === 'L2' ? 'i L2' : 'i';
    case 'rip':
      return 'R';
    case 'omp':
      return 'm';
    case 'lisp':
      return 'L*';
  }
}

function getUniqueVrfs(node: NodeConfig, result: NodeRoutingResult): string[] {
  const set = new Set<string>(node.vrfs?.length ? node.vrfs : ['default']);
  for (const r of result.rib) set.add(r.vrf || 'default');
  return Array.from(set);
}

export function formatCiscoCli(node: NodeConfig, result: NodeRoutingResult): string {
  const vrfs = getUniqueVrfs(node, result);
  const sections: string[] = [];

  for (const vrf of vrfs) {
    const active = result.rib.filter((r) => r.active && (r.vrf || 'default') === vrf);
    const cmd = vrf === 'default' ? 'show ip route' : `show ip route vrf ${vrf}`;
    const lines: string[] = [`${node.hostname}# ${cmd}`];

    if (vrf !== 'default') {
      lines.push(`Routing Table: ${vrf}`);
    }

    lines.push(
      `Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP`,
      `       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area`,
      `       E1 - OSPF external type 1, E2 - OSPF external type 2, i - IS-IS`,
      ``
    );

    const defRoute = active.find((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0);
    if (defRoute) {
      lines.push(`Gateway of last resort is ${defRoute.nextHop} to network 0.0.0.0`);
    } else {
      lines.push(`Gateway of last resort is not set`);
    }
    lines.push(``);

    for (const r of active) {
      const code = ciscoCode(r).padEnd(5, ' ');
      const cidr = `${r.prefix}/${r.prefixLen}`;
      const leakNote = r.leakedFromVrf ? ` (leaked from ${r.leakedFromVrf})` : '';
      if (r.protocol === 'connected' || r.protocol === 'local') {
        lines.push(`${code} ${cidr} is directly connected, ${r.egressInterface}${leakNote}`);
      } else {
        const via = r.nextHop !== '0.0.0.0' ? `via ${r.nextHop}` : 'directly';
        const iface = r.egressInterface ? `, ${r.egressInterface}` : '';
        const commNote = r.bgpAttrs?.communities?.length
          ? ` [comm: ${r.bgpAttrs.communities.join(' ')}]`
          : '';
        const clusterNote = r.bgpAttrs?.clusterList?.length
          ? ` [cluster: ${r.bgpAttrs.clusterList.join(' ')}]`
          : '';
        const lcommNote = r.bgpAttrs?.largeCommunities?.length
          ? ` [lcomm: ${r.bgpAttrs.largeCommunities.join(' ')}]`
          : '';
        const rpkiNote = r.bgpAttrs?.rpkiState && r.bgpAttrs.rpkiState !== 'not-found'
          ? ` [rpki: ${r.bgpAttrs.rpkiState}]`
          : '';
        const tagNote = r.tag !== undefined ? ` [tag ${r.tag}]` : '';
        lines.push(
          `${code} ${cidr} [${r.ad}/${r.metric}] ${via}, 00:04:12${iface}${leakNote}${commNote}${lcommNote}${rpkiNote}${tagNote}${clusterNote}`
        );
      }
    }
    sections.push(lines.join('\n'));
  }

  if (result.lfib && result.lfib.length > 0) {
    const lfibLines = [
      `${node.hostname}# show mpls forwarding-table`,
      `Local   Outgoing      Prefix             Bytes    Outgoing   Next Hop`,
      ...result.lfib.map(
        (e) =>
          `${String(e.inLabel).padEnd(8)}${String(e.outLabel).padEnd(14)}${e.prefix.padEnd(19)}0        ${e.egressInterface.padEnd(11)}${e.nextHop} [${e.protocol.toUpperCase()}]`
      ),
    ];
    sections.push(lfibLines.join('\n'));
  }

  if (result.stpState) {
    const stpLines = [
      `${node.hostname}# show spanning-tree`,
      `Root ID: ${result.stpState.rootBridgeId}${result.stpState.isRoot ? ' (This bridge is the root)' : ''}`,
      `Interface        Role       State`,
      ...result.stpState.ports.map(
        (p) => `${p.interfaceName.padEnd(17)}${p.role.padEnd(11)}${p.state}`
      ),
    ];
    sections.push(stpLines.join('\n'));
  }

  if (result.lldpNeighbors && result.lldpNeighbors.length > 0) {
    const lldpLines = [
      `${node.hostname}# show lldp neighbors`,
      `Device ID           Local Intf     Port ID`,
      ...result.lldpNeighbors.map(
        (n) => `${n.remoteChassisId.padEnd(20)}${n.localInterface.padEnd(15)}${n.remotePort}`
      ),
    ];
    sections.push(lldpLines.join('\n'));
  }

  if (result.mroute && result.mroute.length > 0) {
    const mLines = [
      `${node.hostname}# show ip mroute`,
      ...result.mroute.map(
        (m) => `(${m.source}, ${m.group}), RPF nbr/intf: ${m.rpfInterface}, OIFs: ${m.oifList.join(', ') || 'Null'}`
      ),
    ];
    sections.push(mLines.join('\n'));
  }

  return sections.join('\n\n');
}

function panOsFlags(entry: RibEntry): string {
  const activeFlag = entry.active ? 'A' : '?';
  let protoFlag = 'S';
  switch (entry.protocol) {
    case 'connected':
    case 'local':
      protoFlag = 'C';
      break;
    case 'static':
      protoFlag = 'S';
      break;
    case 'ospf':
      protoFlag = entry.ospfType === 'ext1' || entry.ospfType === 'ext2' ? 'O E' : 'O';
      break;
    case 'eigrp':
      protoFlag = 'D';
      break;
    case 'isis':
      protoFlag = 'i';
      break;
    case 'rip':
      protoFlag = 'R';
      break;
    case 'omp':
      protoFlag = 'M';
      break;
    case 'ebgp':
    case 'ibgp':
      protoFlag = 'B';
      break;
  }
  return `${activeFlag} ${protoFlag}`.trim();
}

export function formatPanOsRouteCli(node: NodeConfig, result: NodeRoutingResult): string {
  const vrfs = getUniqueVrfs(node, result);
  const lines: string[] = [
    `admin@${node.hostname}> show routing route`,
    ``,
    `flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp,`,
    `       Oi:ospf intra-area, Oo:ospf inter-area, O1:ospf ext-type-1, O2:ospf ext-type-2`,
    ``,
  ];

  vrfs.forEach((vrf, idx) => {
    const vrfRib = result.rib.filter((r) => (r.vrf || 'default') === vrf);
    lines.push(
      `VIRTUAL ROUTER: ${vrf} (id ${idx + 1})`,
      `  ==========`,
      `destination          nexthop          metric  flags    age   interface          next-AS`
    );

    for (const r of vrfRib) {
      const dest = `${r.prefix}/${r.prefixLen}`.padEnd(20, ' ');
      const nh = (r.nextHop === '0.0.0.0' ? '0.0.0.0' : r.nextHop).padEnd(16, ' ');
      const metric = String(r.metric).padEnd(7, ' ');
      const flags = panOsFlags(r).padEnd(8, ' ');
      const age = (r.protocol === 'connected' || r.protocol === 'local' ? '-' : '120').padEnd(6, ' ');
      const iface = (r.egressInterface || '-').padEnd(18, ' ');
      const nextAs =
        r.bgpAttrs && r.bgpAttrs.asPath.length > 0 ? String(r.bgpAttrs.asPath[0]) : '';
      const leakNote = r.leakedFromVrf ? ` [vr:${r.leakedFromVrf}]` : '';
      lines.push(`${dest} ${nh} ${metric} ${flags} ${age} ${iface} ${nextAs}${leakNote}`.trimEnd());
    }
    lines.push(``);
  });

  return lines.join('\n').trimEnd();
}

function formatPanOsFibCli(node: NodeConfig, result: NodeRoutingResult): string {
  const vrfs = getUniqueVrfs(node, result);
  const lines: string[] = [
    `admin@${node.hostname}> show routing fib`,
    ``,
    `total virtual-router shown : ${vrfs.length}`,
  ];

  vrfs.forEach((vrf, vIdx) => {
    const vrfFib = result.fib.filter((f) => (f.vrf || 'default') === vrf);
    lines.push(
      `--------------------------------------------------------------------------------`,
      `vr-name: ${vrf} (id ${vIdx + 1})`,
      `id    destination          nexthop          flags   interface          mtu`
    );
    vrfFib.forEach((f, idx) => {
      const idStr = String(idx + 1).padEnd(5, ' ');
      const dest = `${f.prefix}/${f.prefixLen}`.padEnd(20, ' ');
      const nh = f.nextHop.padEnd(16, ' ');
      const flags = f.flags.padEnd(7, ' ');
      const iface = (f.egressInterface || '-').padEnd(18, ' ');
      lines.push(`${idStr} ${dest} ${nh} ${flags} ${iface} 1500`);
    });
  });

  return lines.join('\n');
}

export function formatForcepointFrrCli(node: NodeConfig, result: NodeRoutingResult): string {
  const vrfs = getUniqueVrfs(node, result);
  const sections: string[] = [];

  for (const vrf of vrfs) {
    const active = result.rib.filter((r) => r.active && (r.vrf || 'default') === vrf);
    const vrfFlag = vrf === 'default' ? '' : ` vrf ${vrf}`;
    const lines: string[] = [
      `${node.hostname}# vtysh -c "show ip route${vrfFlag}"`,
      `Codes: K - kernel route, C - connected, L - local, S - static, O - OSPF, B - BGP`,
      `       > - selected route, * - FIB route`,
      ``,
    ];

    for (const r of active) {
      const code =
        r.protocol === 'connected'
          ? 'C>*'
          : r.protocol === 'local'
            ? 'L>*'
          : r.protocol === 'static'
            ? 'S>*'
            : r.protocol === 'ospf'
              ? 'O>*'
              : r.protocol === 'eigrp'
                ? 'D>*'
                : r.protocol === 'isis'
                  ? 'i>*'
                  : r.protocol === 'rip'
                    ? 'R>*'
                    : r.protocol === 'omp'
                      ? 'M>*'
                      : 'B>*';
      const cidr = `${r.prefix}/${r.prefixLen}`;
      const leakNote = r.leakedFromVrf ? ` (leaked from ${r.leakedFromVrf})` : '';
      if (r.protocol === 'connected' || r.protocol === 'local') {
        lines.push(`${code} ${cidr} is directly connected, ${r.egressInterface}, 00:12:40${leakNote}`);
      } else {
        lines.push(
          `${code} ${cidr} [${r.ad}/${r.metric}] via ${r.nextHop}, ${r.egressInterface}, 00:05:18${leakNote}`
        );
      }
    }
    sections.push(lines.join('\n'));
  }

  if (result.lfib && result.lfib.length > 0) {
    const lfibLines = [
      `${node.hostname}# show mpls forwarding-table`,
      `Local   Outgoing      Prefix             Bytes    Outgoing   Next Hop`,
      ...result.lfib.map(
        (e) =>
          `${String(e.inLabel).padEnd(8)}${String(e.outLabel).padEnd(14)}${e.prefix.padEnd(19)}0        ${e.egressInterface.padEnd(11)}${e.nextHop} [${e.protocol.toUpperCase()}]`
      ),
    ];
    sections.push(lfibLines.join('\n'));
  }

  if (result.stpState) {
    const stpLines = [
      `${node.hostname}# show spanning-tree`,
      `Root ID: ${result.stpState.rootBridgeId}${result.stpState.isRoot ? ' (This bridge is the root)' : ''}`,
      `Interface        Role       State`,
      ...result.stpState.ports.map(
        (p) => `${p.interfaceName.padEnd(17)}${p.role.padEnd(11)}${p.state}`
      ),
    ];
    sections.push(stpLines.join('\n'));
  }

  if (result.lldpNeighbors && result.lldpNeighbors.length > 0) {
    const lldpLines = [
      `${node.hostname}# show lldp neighbors`,
      `Device ID           Local Intf     Port ID`,
      ...result.lldpNeighbors.map(
        (n) => `${n.remoteChassisId.padEnd(20)}${n.localInterface.padEnd(15)}${n.remotePort}`
      ),
    ];
    sections.push(lldpLines.join('\n'));
  }

  if (result.mroute && result.mroute.length > 0) {
    const mLines = [
      `${node.hostname}# show ip mroute`,
      ...result.mroute.map(
        (m) => `(${m.source}, ${m.group}), RPF nbr/intf: ${m.rpfInterface}, OIFs: ${m.oifList.join(', ') || 'Null'}`
      ),
    ];
    sections.push(mLines.join('\n'));
  }

  return sections.join('\n\n');
}

export function formatForcepointSgCli(node: NodeConfig, result: NodeRoutingResult): string {
  const active = result.rib.filter((r) => r.active);
  const lines: string[] = [
    `root@${node.hostname}:~# sg-dynamic-routing route-table`,
    `VRF          Destination          Gateway          Prefix  Metric  Proto    Interface`,
    `----------------------------------------------------------------------------------------`,
  ];

  for (const r of active) {
    const vrf = (r.vrf || 'default').padEnd(12, ' ');
    const dest = r.prefix.padEnd(20, ' ');
    const gw = (r.nextHop === '0.0.0.0' || r.nextHop === '::' ? '*' : r.nextHop).padEnd(16, ' ');
    const pfx = `/${r.prefixLen}`.padEnd(7, ' ');
    const metric = String(r.metric).padEnd(7, ' ');
    const proto = r.protocol.toUpperCase().padEnd(8, ' ');
    const pbrMatch = (node.pbrRules ?? []).find((p) => p.matchPrefix === `${r.prefix}/${r.prefixLen}`);
    const pbrNote = pbrMatch
      ? `  [PBR:${pbrMatch.name}${pbrMatch.multiLinkPool ? ` pool=${pbrMatch.multiLinkPool}` : ''}]`
      : '';
    lines.push(`${vrf} ${dest} ${gw} ${pfx} ${metric} ${proto} ${r.egressInterface}${pbrNote}`);
  }

  if (node.pbrRules && node.pbrRules.length > 0) {
    lines.push(``, `Policy-Based Routing (PBR) & Multi-Link Overrides:`);
    for (const p of node.pbrRules) {
      lines.push(
        `  rule "${p.name}": match ${p.matchPrefix} -> next-hop ${p.nextHop}${p.multiLinkPool ? ` (Multi-Link Pool: ${p.multiLinkPool})` : ''}${p.interfaceName ? ` dev ${p.interfaceName}` : ''}`
      );
    }
  }

  return lines.join('\n');
}

function formatFortigateCli(node: NodeConfig, result: NodeRoutingResult): string {
  const vrfs = getUniqueVrfs(node, result);
  const sections: string[] = [];

  for (const vrf of vrfs) {
    const active = result.rib.filter((r) => r.active && (r.vrf || 'default') === vrf);
    const lines: string[] = [
      `${node.hostname} # get router info routing-table all${vrf === 'default' ? '' : ` vrf ${vrf}`}`,
      `Codes: K - kernel, C - connected, S - static, B - BGP, O - OSPF`,
      ``,
    ];

    for (const r of active) {
      const code = ciscoCode(r).padEnd(5, ' ');
      const cidr = `${r.prefix}/${r.prefixLen}`;
      if (r.protocol === 'connected' || r.protocol === 'local') {
        lines.push(`${code} ${cidr} is directly connected, ${r.egressInterface}`);
      } else {
        lines.push(`${code} ${cidr} [${r.ad}/${r.metric}] via ${r.nextHop}, ${r.egressInterface}`);
      }
    }
    sections.push(lines.join('\n'));
  }

  if (result.lfib && result.lfib.length > 0) {
    const lfibLines = [
      `${node.hostname}# show mpls forwarding-table`,
      `Local   Outgoing      Prefix             Bytes    Outgoing   Next Hop`,
      ...result.lfib.map(
        (e) =>
          `${String(e.inLabel).padEnd(8)}${String(e.outLabel).padEnd(14)}${e.prefix.padEnd(19)}0        ${e.egressInterface.padEnd(11)}${e.nextHop} [${e.protocol.toUpperCase()}]`
      ),
    ];
    sections.push(lfibLines.join('\n'));
  }

  if (result.stpState) {
    const stpLines = [
      `${node.hostname}# show spanning-tree`,
      `Root ID: ${result.stpState.rootBridgeId}${result.stpState.isRoot ? ' (This bridge is the root)' : ''}`,
      `Interface        Role       State`,
      ...result.stpState.ports.map(
        (p) => `${p.interfaceName.padEnd(17)}${p.role.padEnd(11)}${p.state}`
      ),
    ];
    sections.push(stpLines.join('\n'));
  }

  if (result.lldpNeighbors && result.lldpNeighbors.length > 0) {
    const lldpLines = [
      `${node.hostname}# show lldp neighbors`,
      `Device ID           Local Intf     Port ID`,
      ...result.lldpNeighbors.map(
        (n) => `${n.remoteChassisId.padEnd(20)}${n.localInterface.padEnd(15)}${n.remotePort}`
      ),
    ];
    sections.push(lldpLines.join('\n'));
  }

  if (result.mroute && result.mroute.length > 0) {
    const mLines = [
      `${node.hostname}# show ip mroute`,
      ...result.mroute.map(
        (m) => `(${m.source}, ${m.group}), RPF nbr/intf: ${m.rpfInterface}, OIFs: ${m.oifList.join(', ') || 'Null'}`
      ),
    ];
    sections.push(mLines.join('\n'));
  }

  return sections.join('\n\n');
}

function formatSdwanOmpRoutesCli(node: NodeConfig, result: NodeRoutingResult): string {
  const ompRoutes = result.rib.filter((r) => r.protocol === 'omp');
  const lines: string[] = [
    `${node.hostname}# show omp routes`,
    `Code: C - chosen, I - installed, R - redistributed, S - stale`,
    ``,
    `PREFIX              VPN    ORIGINATOR       COLOR            ENCAP   STATUS    NEXT-HOP / TLOC-EXT`,
    `----------------------------------------------------------------------------------------------------`,
  ];
  if (ompRoutes.length === 0) {
    lines.push('(no OMP routes installed)');
  } else {
    for (const r of ompRoutes) {
      const pfx = `${r.prefix}/${r.prefixLen}`.padEnd(19);
      const vpn = (r.vrf === 'default' ? '0' : r.vrf).padEnd(6);
      const orig = (r.tloc?.systemIp ?? node.sdwan?.systemIp ?? '-').padEnd(16);
      const color = (r.tloc?.color ?? 'default').padEnd(16);
      const encap = (r.tloc?.encap ?? 'ipsec').padEnd(7);
      const status = (r.active ? 'C,I,R' : 'R').padEnd(9);
      const ext = r.tloc?.viaTlocExtension ? ` (tloc-ext ${r.tloc.viaTlocExtension})` : '';
      lines.push(`${pfx} ${vpn} ${orig} ${color} ${encap} ${status} ${r.nextHop}${ext}`);
    }
  }
  lines.push('', formatCiscoCli(node, result));
  return lines.join('\n');
}

function formatSdwanTlocsCli(node: NodeConfig, result: NodeRoutingResult): string {
  const lines: string[] = [
    `${node.hostname}# show omp tlocs`,
    `SYSTEM-IP        COLOR            ENCAP   INTERFACE    ADDRESS            TLOC-EXTENSION`,
    `----------------------------------------------------------------------------------------`,
  ];
  const sysIp = (node.sdwan?.systemIp ?? node.routerId).padEnd(16);
  for (const iface of node.interfaces) {
    if (!iface.tlocColor && !iface.tlocExtension) continue;
    const color = (iface.tlocColor ?? 'extension').padEnd(16);
    const encap = (iface.tlocEncap ?? 'ipsec').padEnd(7);
    const ifName = iface.name.padEnd(12);
    const addr = iface.cidr.padEnd(18);
    const ext = iface.tlocExtension ?? '-';
    lines.push(`${sysIp} ${color} ${encap} ${ifName} ${addr} ${ext}`);
  }
  const ompPeers = (result.neighbors ?? []).filter((n) => n.protocol === 'omp');
  lines.push('', `${node.hostname}# show omp peers`);
  for (const p of ompPeers) {
    lines.push(`PEER ${p.peerIp.padEnd(16)} STATE ${p.state.padEnd(6)} ${p.detail ?? ''}`);
  }
  return lines.join('\n');
}

function formatPrismaIonCli(node: NodeConfig, result: NodeRoutingResult): string {
  const lines: string[] = [
    `${node.hostname}# dump interface status`,
    `INTERFACE      CIDR                STATUS`,
    `--------------------------------------------`,
    ...node.interfaces.map(
      (i) => `${i.name.padEnd(14)} ${i.cidr.padEnd(19)} ${i.shutdown ? 'DOWN' : 'UP'}`
    ),
  ];
  if (node.sdwanSla?.enabled) {
    lines.push('', `${node.hostname}# dump path-policy status`);
    for (const r of node.sdwanSla.rules) {
      lines.push(
        `RULE "${r.name}" mode=${r.mode} members=[${r.preferredMembers.join(', ')}] maxLat=${r.maxLatencyMs ?? '-'}ms maxLoss=${r.maxLossPct ?? '-'}%`
      );
    }
  }
  lines.push('', formatCiscoCli(node, result));
  return lines.join('\n');
}

function junosProtoLabel(entry: RibEntry): string {
  switch (entry.protocol) {
    case 'connected':
      return 'Direct';
    case 'local':
      return 'Local';
    case 'static':
      return 'Static';
    case 'ospf':
      return 'OSPF';
    case 'isis':
      return 'IS-IS';
    case 'rip':
      return 'RIP';
    case 'ebgp':
    case 'ibgp':
      return 'BGP';
    case 'omp':
      return 'OMP';
    default:
      return entry.protocol.toUpperCase();
  }
}

function formatJunosRouteCli(node: NodeConfig, result: NodeRoutingResult): string {
  const vrfs = getUniqueVrfs(node, result);
  const sections: string[] = [];

  for (const vrf of vrfs) {
    const tableName = vrf === 'default' ? 'inet.0' : `${vrf}.inet.0`;
    const active = result.rib.filter((r) => r.active && (r.vrf || 'default') === vrf);
    const lines: string[] = [
      `admin@${node.hostname}> show route table ${tableName}`,
      ``,
      `${tableName}: ${active.length} destinations, ${active.length} routes (${active.length} active, 0 holddown, 0 hidden)`,
      `+ = Active Route, - = Last Active, * = Both`,
      ``,
    ];

    for (const r of active) {
      const pfx = `${r.prefix}/${r.prefixLen}`;
      const proto = junosProtoLabel(r);
      lines.push(`${pfx.padEnd(19, ' ')} *[${proto}/${r.ad}] 00:12:40${r.metric > 0 ? `, metric ${r.metric}` : ''}`);
      if (r.protocol === 'connected' || r.protocol === 'local') {
        lines.push(`                    >  via ${r.egressInterface || 'lo0.0'}`);
      } else {
        lines.push(`                    >  to ${r.nextHop} via ${r.egressInterface || 'ge-0/0/0'}`);
      }
    }
    sections.push(lines.join('\n'));
  }

  if (result.lfib && result.lfib.length > 0) {
    const lfibLines = [
      `${node.hostname}# show mpls forwarding-table`,
      `Local   Outgoing      Prefix             Bytes    Outgoing   Next Hop`,
      ...result.lfib.map(
        (e) =>
          `${String(e.inLabel).padEnd(8)}${String(e.outLabel).padEnd(14)}${e.prefix.padEnd(19)}0        ${e.egressInterface.padEnd(11)}${e.nextHop} [${e.protocol.toUpperCase()}]`
      ),
    ];
    sections.push(lfibLines.join('\n'));
  }

  if (result.stpState) {
    const stpLines = [
      `${node.hostname}# show spanning-tree`,
      `Root ID: ${result.stpState.rootBridgeId}${result.stpState.isRoot ? ' (This bridge is the root)' : ''}`,
      `Interface        Role       State`,
      ...result.stpState.ports.map(
        (p) => `${p.interfaceName.padEnd(17)}${p.role.padEnd(11)}${p.state}`
      ),
    ];
    sections.push(stpLines.join('\n'));
  }

  if (result.lldpNeighbors && result.lldpNeighbors.length > 0) {
    const lldpLines = [
      `${node.hostname}# show lldp neighbors`,
      `Device ID           Local Intf     Port ID`,
      ...result.lldpNeighbors.map(
        (n) => `${n.remoteChassisId.padEnd(20)}${n.localInterface.padEnd(15)}${n.remotePort}`
      ),
    ];
    sections.push(lldpLines.join('\n'));
  }

  if (result.mroute && result.mroute.length > 0) {
    const mLines = [
      `${node.hostname}# show ip mroute`,
      ...result.mroute.map(
        (m) => `(${m.source}, ${m.group}), RPF nbr/intf: ${m.rpfInterface}, OIFs: ${m.oifList.join(', ') || 'Null'}`
      ),
    ];
    sections.push(mLines.join('\n'));
  }

  return sections.join('\n\n');
}

function formatJunosFibCli(node: NodeConfig, result: NodeRoutingResult): string {
  const vrfs = getUniqueVrfs(node, result);
  const lines: string[] = [`admin@${node.hostname}> show route forwarding-table`, ``];
  for (const vrf of vrfs) {
    const vrfFib = result.fib.filter((f) => (f.vrf || 'default') === vrf);
    lines.push(
      `Routing table: ${vrf === 'default' ? 'default.inet' : `${vrf}.inet`}`,
      `Internet:`,
      `Destination        Type RtRef Next hop           Type Index    NhRef Netif`
    );
    for (const f of vrfFib) {
      const dest = `${f.prefix}/${f.prefixLen}`.padEnd(18, ' ');
      const rtype = (f.protocol === 'connected' || f.protocol === 'local' ? 'intf' : 'user').padEnd(4, ' ');
      const nh = (f.nextHop === '0.0.0.0' || f.nextHop === '::' ? '' : f.nextHop).padEnd(18, ' ');
      const nhType = (f.protocol === 'connected' || f.protocol === 'local' ? 'rslv' : 'ucst').padEnd(4, ' ');
      lines.push(`${dest} ${rtype}     0 ${nh} ${nhType} 512      1     ${f.egressInterface || 'lo0.0'}`);
    }
    lines.push('');
  }
  return lines.join('\n').trimEnd();
}

function mikrotikFlags(entry: RibEntry): string {
  const act = entry.active ? 'A' : ' ';
  if (entry.protocol === 'connected' || entry.protocol === 'local') return `${act}DC`;
  if (entry.protocol === 'static') return `${act} S`;
  if (entry.protocol === 'ospf') return `${act}Do`;
  if (entry.protocol === 'ebgp' || entry.protocol === 'ibgp') return `${act}Db`;
  if (entry.protocol === 'rip') return `${act}Dr`;
  return `${act}D `;
}

function formatMikrotikCli(node: NodeConfig, result: NodeRoutingResult): string {
  const lines: string[] = [
    `[admin@${node.hostname}] > /ip route print`,
    `Flags: D - dynamic; X - disabled, I - inactive, A - active;`,
    `c - connect, s - static, r - rip, b - bgp, o - ospf`,
    ` #      DST-ADDRESS        GATEWAY            ROUTING-TABLE     DISTANCE`,
  ];

  const active = result.rib.filter((r) => r.active);
  active.forEach((r, idx) => {
    const flags = mikrotikFlags(r).padEnd(6, ' ');
    const dst = `${r.prefix}/${r.prefixLen}`.padEnd(18, ' ');
    const gw =
      r.protocol === 'connected' || r.protocol === 'local'
        ? (r.egressInterface || 'bridge1')
        : `${r.nextHop}${r.egressInterface ? `%${r.egressInterface}` : ''}`;
    const vrf = (r.vrf === 'default' ? 'main' : r.vrf || 'main').padEnd(17, ' ');
    lines.push(`${String(idx).padStart(2, ' ')} ${flags} ${dst} ${gw.padEnd(18, ' ')} ${vrf} ${r.ad}`);
  });

  return lines.join('\n');
}

function formatAlignedTable(headers: string[], rows: string[][]): string[] {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length))
  );
  const fmtRow = (cols: string[]) =>
    cols
      .map((c, i) => (i === cols.length - 1 ? c : c.padEnd(widths[i])))
      .join('  ');
  const headerLine = fmtRow(headers);
  const divider = '-'.repeat(headerLine.length);
  return [headerLine, divider, ...rows.map(fmtRow)];
}

function formatAwsTgwCli(node: NodeConfig, result: NodeRoutingResult, isSecondary = false): string {
  const region = node.cloudConfig?.region || 'us-east-1';
  const isCloudWan = node.vendor === 'aws-cloudwan';
  const header = isSecondary
    ? `# AWS VPC Effective Route Tables (${node.hostname} | ${region})`
    : isCloudWan
      ? `# aws networkmanager get-network-routes --core-network-id ${node.hostname} (${region})`
      : `# aws ec2 search-transit-gateway-routes --transit-gateway-route-table-id tgw-rtb-${node.hostname.toLowerCase()} (${region})`;
  const rows = result.rib
    .filter((e) => e.active)
    .map((r) => [
      `${r.prefix}/${r.prefixLen}`,
      r.protocol === 'ebgp' || r.protocol === 'ibgp'
        ? 'propagated'
        : r.protocol === 'connected' || r.protocol === 'local'
          ? 'local'
          : 'static',
      r.nextHop === 'blackhole' || r.egressInterface === 'blackhole' ? 'blackhole' : 'active',
      r.awsTargetType
        ? `${r.awsTargetType}:${r.nextHop}`
        : `${r.egressInterface || 'local'} (${r.nextHop})`,
      r.vrf,
    ]);
  return [
    header,
    `# ASN: ${node.bgp.enabled ? node.bgp.asn : 64512} | ApplianceMode: ${node.cloudConfig?.applianceMode ? 'enable' : 'disable'} | PreferDX: ${node.cloudConfig?.preferPrivateCircuit !== false ? 'true' : 'false'}`,
    '',
    ...formatAlignedTable(['DESTINATION', 'TYPE', 'STATE', 'NEXT-HOP / ATTACHMENT', 'ROUTE-TABLE'], rows),
  ].join('\n');
}

function formatAzureVhubCli(node: NodeConfig, result: NodeRoutingResult, isSecondary = false): string {
  const region = node.cloudConfig?.region || 'eastus';
  const header = isSecondary
    ? `# az network nic show-effective-route-table (${node.hostname} | ${region})`
    : `# az network vhub route-table show --vhub-name ${node.hostname} (${region})`;
  const rows = result.rib
    .filter((e) => e.active)
    .map((r) => [
      `${r.prefix}/${r.prefixLen}`,
      r.protocol === 'static' ? 'User(UDR)' : r.protocol === 'ebgp' || r.protocol === 'ibgp' ? 'BGP' : 'System',
      r.azureNextHopType
        ? r.azureNextHopType
        : r.nextHop === 'blackhole' || r.egressInterface === 'blackhole'
          ? 'None'
          : r.protocol === 'static'
            ? 'VirtualAppliance'
            : r.protocol === 'ebgp'
              ? r.ad <= 20
                ? 'ExpressRoute'
                : 'VPN_S2S'
              : 'VnetLocal',
      `${r.nextHop} (${r.egressInterface || 'local'})`,
      r.vrf,
    ]);
  return [
    header,
    `# ASN: ${node.bgp.enabled ? node.bgp.asn : 65515} | UDR-Overrides-BGP: ${node.cloudConfig?.udrOverridesBgp !== false ? 'true' : 'false'} | DisableBgpProp: ${node.cloudConfig?.disableBgpPropagation ? 'true' : 'false'} | PreferExpressRoute: ${node.cloudConfig?.preferPrivateCircuit !== false ? 'true' : 'false'}`,
    '',
    ...formatAlignedTable(['ADDRESS_PREFIX', 'ORIGIN', 'NEXT_HOP_TYPE', 'NEXT_HOP', 'ROUTE_TABLE'], rows),
  ].join('\n');
}

function formatGcpRouterCli(node: NodeConfig, result: NodeRoutingResult, isSecondary = false): string {
  const region = node.cloudConfig?.region || 'us-central1';
  const mode = (node.cloudConfig?.dynamicRoutingMode ?? 'global').toUpperCase();
  const header = isSecondary
    ? `# gcloud compute routes list --filter="network:${node.hostname}" (${region})`
    : `# gcloud compute routers get-status ${node.hostname} --region=${region} (MODE=${mode})`;
  const rows = result.rib
    .filter((e) => e.active)
    .map((r) => [
      `${r.prefix}/${r.prefixLen}`,
      r.protocol === 'ebgp' || r.protocol === 'ibgp' ? 'BGP' : r.protocol === 'static' ? 'STATIC' : 'SUBNET',
      String(
        r.protocol === 'connected' || r.protocol === 'local'
          ? 0
          : r.gcpPriority ?? (node.cloudConfig?.defaultRoutePriority ?? 1000) + r.ad
      ),
      r.gcpNextHopType
        ? `${r.gcpNextHopType} (${r.nextHop})`
        : `${r.nextHop} (${r.egressInterface || 'local'})`,
      r.vrf,
    ]);
  return [
    header,
    `# ASN: ${node.bgp.enabled ? node.bgp.asn : 64514} | DynamicRoutingMode: ${mode} | NCC-Hub: ${node.cloudConfig?.nccHubEnabled ? 'enabled' : 'disabled'} | PGA: ${node.cloudConfig?.privateGoogleAccess ? 'on' : 'off'} | PGA-OnPrem: ${node.cloudConfig?.pgaOnPremAdvertise ? 'advertised' : 'off'}`,
    '',
    ...formatAlignedTable(['DEST_RANGE', 'SOURCE', 'PRIORITY', 'NEXT_HOP', 'NETWORK'], rows),
  ].join('\n');
}

function formatOciDrgCli(node: NodeConfig, result: NodeRoutingResult): string {
  const region = node.cloudConfig?.region || 'us-ashburn-1';
  const rows = result.rib
    .filter((e) => e.active)
    .map((r) => [
      `${r.prefix}/${r.prefixLen}`,
      r.protocol === 'static' ? 'STATIC' : 'DYNAMIC',
      r.protocol === 'ebgp' ? 'FASTCONNECT/IPSEC' : r.protocol === 'connected' ? 'VCN' : 'STATIC',
      `${r.egressInterface || 'local'} (${r.nextHop})`,
      r.vrf,
    ]);
  return [
    `# oci network drg-route-table list-drg-route-rules (${node.hostname} | ${region})`,
    `# ASN: ${node.bgp.enabled ? node.bgp.asn : 31898}`,
    '',
    ...formatAlignedTable(['DESTINATION', 'ROUTE_TYPE', 'PROVENANCE', 'NEXT_HOP_ATTACHMENT', 'TABLE'], rows),
  ].join('\n');
}

function formatCloudflareMwanCli(node: NodeConfig, result: NodeRoutingResult): string {
  const rows = result.rib
    .filter((e) => e.active)
    .map((r) => [
      `${r.prefix}/${r.prefixLen}`,
      r.protocol.toUpperCase(),
      String(100 + r.ad),
      `${r.nextHop} (${r.egressInterface || 'anycast'})`,
      r.vrf,
    ]);
  return [
    `# cf-magic-wan routes list --account ${node.hostname}`,
    `# ASN: ${node.bgp.enabled ? node.bgp.asn : 13335} | Anycast Edge`,
    '',
    ...formatAlignedTable(['PREFIX', 'ORIGIN', 'PRIORITY', 'NEXTHOP / TUNNEL', 'TABLE'], rows),
  ].join('\n');
}

export function formatPrimaryCli(node: NodeConfig, result: NodeRoutingResult): string {
  switch (node.vendor) {
    case 'cisco-ios-xe':
    case 'cisco-nx-os':
    case 'cisco-ios-xr':
    case 'arista-eos':
    case 'aruba-aos-cx':
    case 'vyos':
    case 'checkpoint-gaia':
    case 'mpls-cloud':
    case 'internet-cloud':
      return formatCiscoCli(node, result);
    case 'aws-cloud':
    case 'aws-cloudwan':
      return formatAwsTgwCli(node, result, false);
    case 'azure-cloud':
      return formatAzureVhubCli(node, result, false);
    case 'gcp-cloud':
      return formatGcpRouterCli(node, result, false);
    case 'oci-cloud':
      return formatOciDrgCli(node, result);
    case 'cloudflare-mwan':
      return formatCloudflareMwanCli(node, result);
    case 'cisco-sdwan':
      return formatSdwanOmpRoutesCli(node, result);
    case 'prisma-sdwan':
      return formatPrismaIonCli(node, result);
    case 'pan-os':
      return formatPanOsRouteCli(node, result);
    case 'forcepoint-ngfw':
      return formatForcepointFrrCli(node, result);
    case 'fortigate':
      return formatFortigateCli(node, result);
    case 'juniper-junos':
      return formatJunosRouteCli(node, result);
    case 'mikrotik-routeros':
      return formatMikrotikCli(node, result);
  }
}

export function formatSecondaryCli(node: NodeConfig, result: NodeRoutingResult): string | null {
  if (node.vendor === 'cisco-sdwan') {
    return formatSdwanTlocsCli(node, result);
  }
  if (node.vendor === 'pan-os') {
    return formatPanOsFibCli(node, result);
  }
  if (node.vendor === 'forcepoint-ngfw') {
    return formatForcepointSgCli(node, result);
  }
  if (node.vendor === 'juniper-junos') {
    return formatJunosFibCli(node, result);
  }
  if (node.vendor === 'aws-cloud' || node.vendor === 'aws-cloudwan') {
    return formatAwsTgwCli(node, result, true);
  }
  if (node.vendor === 'azure-cloud') {
    return formatAzureVhubCli(node, result, true);
  }
  if (node.vendor === 'gcp-cloud') {
    return formatGcpRouterCli(node, result, true);
  }
  return null;
}

export function formatRunningConfig(node: NodeConfig): string {
  if (node.vendor === 'aws-cloud' || node.vendor === 'aws-cloudwan') {
    const region = node.cloudConfig?.region || 'us-east-1';
    const isCwan = node.vendor === 'aws-cloudwan';
    const lines: string[] = [
      `# Terraform HCL — ${isCwan ? 'AWS Cloud WAN' : 'AWS Transit Gateway'} (${node.hostname})`,
      `# Region: ${region}`,
      `resource "${isCwan ? 'aws_networkmanager_core_network' : 'aws_ec2_transit_gateway'}" "${node.hostname.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
      `  description                     = "${node.hostname}"`,
      `  amazon_side_asn                 = ${node.bgp.enabled ? node.bgp.asn : 64512}`,
      `  appliance_mode_support          = "${node.cloudConfig?.applianceMode ? 'enable' : 'disable'}"`,
      `}`,
    ];
    for (const iface of node.interfaces) {
      lines.push(
        ``,
        `# Attachment ${iface.name} (${iface.vrf || 'default'}) — ${iface.cidr}`,
        `resource "aws_ec2_transit_gateway_vpc_attachment" "${iface.name.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
        `  subnet_cidr = "${iface.cidr}"`,
        `  route_table = "${iface.vrf || 'default'}"`,
        `}`
      );
    }
    for (const sr of node.staticRoutes) {
      const targetAttr =
        sr.awsTargetType === 'igw'
          ? `  gateway_id                = "igw-main"`
          : sr.awsTargetType === 'nat'
            ? `  nat_gateway_id            = "nat-private"`
            : sr.awsTargetType === 'pcx'
              ? `  vpc_peering_connection_id = "pcx-${sr.id}"\n  next_hop                  = "${sr.nextHop}"`
              : sr.awsTargetType === 'vpce'
                ? `  vpc_endpoint_id           = "vpce-${sr.id}"\n  next_hop                  = "${sr.nextHop}"`
                : sr.awsTargetType === 'vgw'
                  ? `  gateway_id                = "vgw-${sr.id}"\n  next_hop                  = "${sr.nextHop}"`
                  : sr.awsTargetType === 'blackhole' || sr.nextHop === 'blackhole'
                    ? `  blackhole                 = true`
                    : `  next_hop                  = "${sr.nextHop}"`;
      const resType =
        sr.awsTargetType === 'igw' || sr.awsTargetType === 'nat' || sr.awsTargetType === 'pcx' || sr.awsTargetType === 'vpce'
          ? 'aws_route'
          : 'aws_ec2_transit_gateway_route';
      lines.push(
        ``,
        `resource "${resType}" "route_${sr.id.replace(/[^a-z0-9_]/gi, '_')}" {`,
        `  destination_cidr_block    = "${sr.prefix}"`,
        targetAttr,
        `}`
      );
    }
    for (const bh of node.cloudConfig?.blackholeCidrs ?? []) {
      lines.push(
        ``,
        `resource "aws_ec2_transit_gateway_route" "blackhole_${bh.replace(/[^a-z0-9]/gi, '_')}" {`,
        `  destination_cidr_block = "${bh}"`,
        `  blackhole              = true`,
        `}`
      );
    }
    for (const r of node.aclRules ?? []) {
      lines.push(
        ``,
        `resource "aws_network_acl_rule" "${r.name.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
        `  rule_number = ${r.seq}`,
        `  rule_action = "${r.action}"`,
        `  protocol    = "${r.protocol === 'any' ? '-1' : r.protocol}"`,
        `  cidr_block  = "${r.srcCidr === 'any' ? '0.0.0.0/0' : r.srcCidr}"`,
        ...(r.dstPort !== undefined ? [`  from_port   = ${r.dstPort}`, `  to_port     = ${r.dstPort}`] : []),
        `}`
      );
    }
    return lines.join('\n');
  }

  if (node.vendor === 'azure-cloud') {
    const region = node.cloudConfig?.region || 'eastus';
    const lines: string[] = [
      `# Terraform HCL — Azure Virtual WAN / vHub & Route Table (${node.hostname})`,
      `resource "azurerm_virtual_hub" "${node.hostname.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
      `  name               = "${node.hostname}"`,
      `  location           = "${region}"`,
      `  virtual_router_asn = ${node.bgp.enabled ? node.bgp.asn : 65515}`,
      `}`,
      ``,
      `resource "azurerm_route_table" "${node.hostname.toLowerCase().replace(/[^a-z0-9_]/g, '_')}_udr" {`,
      `  name                          = "${node.hostname}-udr"`,
      `  location                      = "${region}"`,
      `  disable_bgp_route_propagation = ${node.cloudConfig?.disableBgpPropagation ? 'true' : 'false'}`,
      `}`,
    ];
    for (const iface of node.interfaces) {
      lines.push(
        ``,
        `# vHub Connection ${iface.name} (${iface.vrf || 'default'}) — ${iface.cidr}`
      );
    }
    for (const sr of node.staticRoutes) {
      const nhType = sr.azureNextHopType ?? (sr.nextHop === 'blackhole' ? 'None' : 'VirtualAppliance');
      lines.push(
        ``,
        `resource "azurerm_route" "udr_${sr.id.replace(/[^a-z0-9_]/gi, '_')}" {`,
        `  name                   = "udr-${sr.id}"`,
        `  address_prefix         = "${sr.prefix}"`,
        `  next_hop_type          = "${nhType}"`,
        ...(nhType === 'VirtualAppliance' && sr.nextHop ? [`  next_hop_in_ip_address = "${sr.nextHop}"`] : []),
        `}`
      );
    }
    for (const bh of node.cloudConfig?.blackholeCidrs ?? []) {
      lines.push(
        ``,
        `resource "azurerm_route" "blackhole_${bh.replace(/[^a-z0-9]/gi, '_')}" {`,
        `  name           = "blackhole-${bh.replace(/[^a-z0-9]/gi, '-')}"`,
        `  address_prefix = "${bh}"`,
        `  next_hop_type  = "None"`,
        `}`
      );
    }
    for (const r of node.aclRules ?? []) {
      lines.push(
        ``,
        `resource "azurerm_network_security_rule" "${r.name.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
        `  name                       = "${r.name}"`,
        `  priority                   = ${Math.max(100, r.seq)}`,
        `  access                     = "${r.action === 'allow' ? 'Allow' : 'Deny'}"`,
        `  protocol                   = "${r.protocol === 'any' ? '*' : r.protocol.toUpperCase()}"`,
        `  source_address_prefix      = "${r.srcCidr === 'any' ? '*' : r.srcCidr}"`,
        `  destination_address_prefix = "${r.dstCidr === 'any' ? '*' : r.dstCidr}"`,
        `  destination_port_range     = "${r.dstPort !== undefined ? r.dstPort : '*'}"`,
        `}`
      );
    }
    return lines.join('\n');
  }

  if (node.vendor === 'gcp-cloud') {
    const region = node.cloudConfig?.region || 'us-central1';
    const mode = (node.cloudConfig?.dynamicRoutingMode ?? 'global').toUpperCase();
    const lines: string[] = [
      `# Terraform HCL — Google Cloud Router & VPC (${node.hostname})`,
      `resource "google_compute_router" "${node.hostname.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
      `  name   = "${node.hostname}"`,
      `  region = "${region}"`,
      `  bgp {`,
      `    asn            = ${node.bgp.enabled ? node.bgp.asn : 64514}`,
      `    advertise_mode = "${mode}"`,
      ...(node.cloudConfig?.pgaOnPremAdvertise
        ? [
            `    advertised_ip_ranges {`,
            `      range       = "199.36.153.8/30"`,
            `      description = "restricted.googleapis.com (Private Google Access)"`,
            `    }`,
            `    advertised_ip_ranges {`,
            `      range       = "199.36.153.4/30"`,
            `      description = "private.googleapis.com (Private Google Access)"`,
            `    }`,
          ]
        : []),
      `  }`,
      `}`,
      ...(node.cloudConfig?.nccHubEnabled
        ? [
            ``,
            `resource "google_network_connectivity_hub" "${node.hostname.toLowerCase().replace(/[^a-z0-9_]/g, '_')}_ncc" {`,
            `  name = "${node.hostname}-ncc-hub"`,
            `}`,
          ]
        : []),
      ...(node.cloudConfig?.pscEndpoints ?? []).flatMap((ep, idx) => [
        ``,
        `resource "google_compute_global_forwarding_rule" "psc_${idx + 1}" {`,
        `  name       = "psc-endpoint-${idx + 1}"`,
        `  ip_address = "${ep}"`,
        `}`,
      ]),
    ];
    for (const sr of node.staticRoutes) {
      const nhAttr =
        sr.gcpNextHopType === 'default-internet-gateway'
          ? `  next_hop_gateway = "default-internet-gateway"`
          : sr.gcpNextHopType === 'cloud-nat'
            ? `  next_hop_gateway = "default-internet-gateway" # Cloud NAT`
            : sr.gcpNextHopType === 'ilb'
              ? `  next_hop_ilb     = "${sr.nextHop}"`
              : sr.gcpNextHopType === 'vpn-tunnel'
                ? `  next_hop_vpn_tunnel = "${sr.interfaceName || 'vpn-tunnel-1'}"`
                : `  next_hop_ip      = "${sr.nextHop}"`;
      lines.push(
        ``,
        `resource "google_compute_route" "route_${sr.id.replace(/[^a-z0-9_]/gi, '_')}" {`,
        `  name       = "route-${sr.id}"`,
        `  dest_range = "${sr.prefix}"`,
        nhAttr,
        `  priority   = ${sr.gcpPriority ?? node.cloudConfig?.defaultRoutePriority ?? 1000}`,
        ...(sr.networkTag ? [`  tags       = ["${sr.networkTag}"]`] : []),
        `}`
      );
    }
    for (const r of node.aclRules ?? []) {
      lines.push(
        ``,
        `resource "google_compute_firewall" "${r.name.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
        `  name          = "${r.name}"`,
        `  priority      = ${r.seq}`,
        `  source_ranges = ["${r.srcCidr === 'any' ? '0.0.0.0/0' : r.srcCidr}"]`,
        ...(r.networkTag ? [`  target_tags   = ["${r.networkTag}"]`] : []),
        `  ${r.action} {`,
        `    protocol = "${r.protocol === 'any' ? 'all' : r.protocol}"`,
        ...(r.dstPort !== undefined ? [`    ports    = ["${r.dstPort}"]`] : []),
        `  }`,
        `}`
      );
    }
    return lines.join('\n');
  }

  if (node.vendor === 'oci-cloud') {
    const region = node.cloudConfig?.region || 'us-ashburn-1';
    const lines: string[] = [
      `# Terraform HCL — Oracle Cloud DRG (${node.hostname} | ${region})`,
      `resource "oci_core_drg" "${node.hostname.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
      `  display_name = "${node.hostname}"`,
      `}`,
    ];
    for (const sr of node.staticRoutes) {
      lines.push(
        ``,
        `resource "oci_core_drg_route_rule" "rule_${sr.id.replace(/[^a-z0-9_]/gi, '_')}" {`,
        `  destination      = "${sr.prefix}"`,
        `  destination_type = "CIDR_BLOCK"`,
        `  next_hop         = "${sr.nextHop}"`,
        `}`
      );
    }
    return lines.join('\n');
  }

  if (node.vendor === 'cloudflare-mwan') {
    const lines: string[] = [
      `# Terraform HCL — Cloudflare Magic WAN (${node.hostname})`,
      `resource "cloudflare_magic_transit_site" "${node.hostname.toLowerCase().replace(/[^a-z0-9_]/g, '_')}" {`,
      `  name = "${node.hostname}"`,
      `  asn  = ${node.bgp.enabled ? node.bgp.asn : 13335}`,
      `}`,
    ];
    for (const iface of node.interfaces) {
      lines.push(
        ``,
        `# Tunnel ${iface.name} (${iface.vrf || 'default'}) — ${iface.cidr}`
      );
    }
    for (const sr of node.staticRoutes) {
      lines.push(
        ``,
        `resource "cloudflare_magic_wan_static_route" "route_${sr.id.replace(/[^a-z0-9_]/gi, '_')}" {`,
        `  prefix   = "${sr.prefix}"`,
        `  nexthop  = "${sr.nextHop}"`,
        `  priority = 100`,
        `}`
      );
    }
    return lines.join('\n');
  }

  if (node.vendor === 'cisco-sdwan') {
    const sw = node.sdwan;
    const lines: string[] = [
      `! Cisco SD-WAN (Viptela) Configuration (${node.hostname})`,
      `system`,
      ` host-name             ${node.hostname}`,
      ` system-ip             ${sw?.systemIp ?? node.routerId}`,
      ` site-id               ${sw?.siteId ?? 100}`,
      ` organization-name     "${sw?.organizationName ?? 'Tailwind-SDWAN'}"`,
      `!`,
      `omp`,
      ` no shutdown`,
      ...(sw?.ompGracefulRestart ? [` graceful-restart`] : []),
      ...(sw?.ompAdminDistance ? [` distance ${sw.ompAdminDistance}`] : []),
      ...(sw?.advertiseConnected !== false ? [` advertise connected`] : []),
      ...(sw?.advertiseStatic !== false ? [` advertise static`] : []),
      ...(sw?.advertiseOspf ? [` advertise ospf external`] : []),
      ...(sw?.advertiseBgp ? [` advertise bgp`] : []),
      `!`,
      `vpn 0`,
    ];
    for (const iface of node.interfaces) {
      lines.push(` interface ${iface.name}`);
      lines.push(`  ip address ${iface.cidr}`);
      if (iface.tlocColor) {
        lines.push(`  tunnel-interface`);
        lines.push(`   encapsulation ${iface.tlocEncap ?? 'ipsec'}`);
        lines.push(`   color ${iface.tlocColor}`);
        lines.push(`  !`);
      }
      if (iface.tlocExtension) {
        lines.push(`  tloc-extension ${iface.tlocExtension}`);
      }
      lines.push(`  ${iface.shutdown ? 'shutdown' : 'no shutdown'}`);
      lines.push(` !`);
    }
    lines.push(`!`);
    return lines.join('\n');
  }

  const vrfs = (node.vrfs?.length ? node.vrfs : ['default']).filter((v) => v !== 'default');

  if (node.vendor === 'pan-os') {
    const lines: string[] = [
      `# PAN-OS Set Commands (${node.hostname})`,
      `set deviceconfig system hostname ${node.hostname}`,
    ];
    for (const iface of node.interfaces) {
      if (iface.cidr) {
        lines.push(`set network interface ethernet ${iface.name} layer3 ip ${iface.cidr}`);
      }
      const vr = iface.vrf || 'default';
      lines.push(`set network virtual-router ${vr} interface ${iface.name}`);
    }
    for (const sr of node.staticRoutes) {
      const vr = sr.vrf || 'default';
      lines.push(
        `set network virtual-router ${vr} routing-table ip static-route ${sr.id} destination ${sr.prefix} nexthop ip-address ${sr.nextHop}`
      );
    }
    if (node.ospf.enabled) {
      lines.push(`set network virtual-router default protocol ospf enable yes`);
      lines.push(`set network virtual-router default protocol ospf router-id ${node.routerId}`);
      for (const iface of node.interfaces.filter((i) => i.ospfArea !== undefined)) {
        const vr = iface.vrf || 'default';
        lines.push(
          `set network virtual-router ${vr} protocol ospf area 0.0.0.${iface.ospfArea} interface ${iface.name}${iface.passive ? ' passive enable yes' : ''}`
        );
      }
    }
    if (node.bgp.enabled) {
      lines.push(`set network virtual-router default protocol bgp enable yes`);
      lines.push(`set network virtual-router default protocol bgp router-id ${node.routerId}`);
      lines.push(`set network virtual-router default protocol bgp local-as ${node.bgp.asn}`);
      for (const p of node.bgp.peers) {
        lines.push(
          `set network virtual-router default protocol bgp peer-group PG-${p.remoteAs} peer ${p.id} peer-address ip ${p.peerIp}`
        );
        lines.push(
          `set network virtual-router default protocol bgp peer-group PG-${p.remoteAs} peer ${p.id} peer-as ${p.remoteAs}`
        );
      }
    }
    for (const acl of node.aclRules ?? []) {
      const svc =
        acl.protocol === 'any'
          ? 'any'
          : acl.dstPort !== undefined
            ? `${acl.protocol}-${acl.dstPort}`
            : acl.protocol;
      const ruleName = /\s/.test(acl.name) ? `"${acl.name}"` : acl.name;
      lines.push(
        `set rulebase security rules ${ruleName} from ${acl.srcZone || 'any'} to ${acl.dstZone || 'any'} source ${acl.srcCidr} destination ${acl.dstCidr} service ${svc} action ${acl.action}`
      );
    }
    if (node.panHa?.enabled) {
      const ha = node.panHa;
      lines.push(`set deviceconfig high-availability enabled yes`);
      lines.push(`set deviceconfig high-availability group group-id ${ha.groupId}`);
      lines.push(`set deviceconfig high-availability group mode ${ha.mode}`);
      if (ha.devicePriority !== undefined) {
        lines.push(`set deviceconfig high-availability group election-option device-priority ${ha.devicePriority}`);
      }
      if (ha.preempt !== undefined) {
        lines.push(`set deviceconfig high-availability group election-option preemptive ${ha.preempt ? 'yes' : 'no'}`);
      }
      if (ha.sessionSync !== undefined) {
        lines.push(`set deviceconfig high-availability group state-synchronization enabled ${ha.sessionSync ? 'yes' : 'no'}`);
      }
      const ha1Name = node.interfaces.find((i) => i.id === ha.ha1InterfaceId)?.name;
      const ha2Name = node.interfaces.find((i) => i.id === ha.ha2InterfaceId)?.name;
      const ha3Name = node.interfaces.find((i) => i.id === ha.ha3HsciInterfaceId)?.name;
      if (ha1Name) lines.push(`set deviceconfig high-availability interface ha1 port ${ha1Name}`);
      if (ha2Name) lines.push(`set deviceconfig high-availability interface ha2 port ${ha2Name}`);
      if (ha3Name) lines.push(`set deviceconfig high-availability interface ha3 port ${ha3Name} # HSCI`);
    }
    if (node.sdwanSla?.enabled) {
      for (const rule of node.sdwanSla.rules) {
        lines.push(`set rulebase sdwan rules "${rule.name}" path-quality-profile "${rule.mode}"`);
      }
    }
    return lines.join('\n');
  }

  if (node.vendor === 'vyos') {
    const lines: string[] = [
      `# VyOS Configuration (${node.hostname})`,
      `set system host-name '${node.hostname}'`,
    ];
    for (const iface of node.interfaces) {
      if (iface.cidr) lines.push(`set interfaces ethernet ${iface.name} address '${iface.cidr}'`);
      if (iface.cidr6) lines.push(`set interfaces ethernet ${iface.name} address '${iface.cidr6}'`);
      if (iface.vrf && iface.vrf !== 'default') {
        lines.push(`set interfaces ethernet ${iface.name} vrf '${iface.vrf}'`);
      }
      if (iface.shutdown) lines.push(`set interfaces ethernet ${iface.name} disable`);
    }
    for (const sr of node.staticRoutes) {
      const vrfPfx = sr.vrf && sr.vrf !== 'default' ? `vrf name ${sr.vrf} ` : '';
      lines.push(`set ${vrfPfx}protocols static route ${sr.prefix} next-hop ${sr.nextHop}`);
    }
    if (node.ospf.enabled) {
      lines.push(`set protocols ospf parameters router-id '${node.routerId}'`);
      for (const iface of node.interfaces.filter((i) => i.ospfArea !== undefined)) {
        lines.push(`set protocols ospf interface ${iface.name} area '${iface.ospfArea}'`);
        if (iface.passive) lines.push(`set protocols ospf interface ${iface.name} passive`);
      }
    }
    if (node.isis?.enabled) {
      if (node.isis.net) lines.push(`set protocols isis net '${node.isis.net}'`);
      for (const iface of node.interfaces.filter((i) => i.isisLevel)) {
        lines.push(`set protocols isis interface ${iface.name}`);
        if (iface.passive) lines.push(`set protocols isis interface ${iface.name} passive`);
      }
    }
    if (node.rip?.enabled) {
      for (const iface of node.interfaces.filter((i) => i.passive)) {
        lines.push(`set protocols rip passive-interface '${iface.name}'`);
      }
    }
    if (node.bgp.enabled) {
      lines.push(`set protocols bgp system-as '${node.bgp.asn}'`);
      lines.push(`set protocols bgp parameters router-id '${node.routerId}'`);
      for (const p of node.bgp.peers) {
        lines.push(`set protocols bgp neighbor ${p.peerIp} remote-as '${p.remoteAs}'`);
        if (p.nextHopSelf) lines.push(`set protocols bgp neighbor ${p.peerIp} address-family ipv4-unicast nexthop-self`);
      }
    }
    return lines.join('\n');
  }

  if (node.vendor === 'checkpoint-gaia') {
    const lines: string[] = [
      `# Check Point Gaia Clish Configuration (${node.hostname})`,
      `set hostname ${node.hostname}`,
      `set router-id ${node.routerId}`,
    ];
    for (const iface of node.interfaces) {
      const parsed = parseCidr(iface.cidr);
      if (parsed) {
        lines.push(`set interface ${iface.name} ipv4-address ${parsed.ip} mask-length ${parsed.prefixLen}`);
      }
      lines.push(`set interface ${iface.name} state ${iface.shutdown ? 'off' : 'on'}`);
    }
    for (const sr of node.staticRoutes) {
      lines.push(`set static-route ${sr.prefix} nexthop gateway address ${sr.nextHop} on`);
    }
    if (node.ospf.enabled) {
      for (const iface of node.interfaces.filter((i) => i.ospfArea !== undefined)) {
        lines.push(`set ospf instance default interface ${iface.name} area 0.0.0.${iface.ospfArea} on`);
        if (iface.passive) lines.push(`set ospf instance default interface ${iface.name} passive on`);
      }
    }
    if (node.bgp.enabled) {
      lines.push(`set as ${node.bgp.asn}`);
      for (const p of node.bgp.peers) {
        lines.push(`set bgp external remote-as ${p.remoteAs} on`);
        lines.push(`set bgp external remote-as ${p.remoteAs} peer ${p.peerIp} on`);
      }
    }
    return lines.join('\n');
  }

  if (node.vendor === 'juniper-junos') {
    const lines: string[] = [
      `# Juniper Junos Set Configuration (${node.hostname})`,
      `set system host-name ${node.hostname}`,
      `set routing-options router-id ${node.routerId}`,
    ];
    for (const iface of node.interfaces) {
      const unitM = iface.name.match(/^(.+)\.(\d+)$/);
      const baseIf = unitM ? unitM[1] : iface.name;
      const unitNum = unitM ? unitM[2] : '0';
      const fullIf = `${baseIf}.${unitNum}`;
      if (iface.cidr) lines.push(`set interfaces ${baseIf} unit ${unitNum} family inet address ${iface.cidr}`);
      if (iface.cidr6) lines.push(`set interfaces ${baseIf} unit ${unitNum} family inet6 address ${iface.cidr6}`);
      if (iface.vrf && iface.vrf !== 'default') {
        lines.push(`set routing-instances ${iface.vrf} instance-type virtual-router`);
        lines.push(`set routing-instances ${iface.vrf} interface ${fullIf}`);
      }
      if (node.ospf.enabled && iface.ospfArea !== undefined) {
        lines.push(`set protocols ospf area 0.0.0.${iface.ospfArea} interface ${fullIf}${iface.passive ? ' passive' : ''}`);
      }
      if (node.isis?.enabled && iface.isisLevel) {
        lines.push(`set protocols isis interface ${fullIf}${iface.passive ? ' passive' : ''}`);
      }
    }
    for (const sr of node.staticRoutes) {
      const pfx = sr.vrf && sr.vrf !== 'default' ? `routing-instances ${sr.vrf} ` : '';
      lines.push(`set ${pfx}routing-options static route ${sr.prefix} next-hop ${sr.nextHop}`);
    }
    if (node.bgp.enabled) {
      lines.push(`set routing-options autonomous-system ${node.bgp.asn}`);
      for (const p of node.bgp.peers) {
        lines.push(`set protocols bgp group EBGP neighbor ${p.peerIp} peer-as ${p.remoteAs}`);
      }
    }
    return lines.join('\n');
  }

  if (node.vendor === 'mikrotik-routeros') {
    const lines: string[] = [
      `# MikroTik RouterOS Export (${node.hostname})`,
      `/system identity set name=${node.hostname}`,
    ];
    for (const vrf of (node.vrfs ?? []).filter((v) => v !== 'default' && v !== 'main')) {
      const vrfIfs = node.interfaces.filter((i) => i.vrf === vrf).map((i) => i.name).join(',');
      lines.push(`/ip vrf add name=${vrf}${vrfIfs ? ` interfaces=${vrfIfs}` : ''}`);
    }
    for (const iface of node.interfaces) {
      if (iface.cidr) lines.push(`/ip address add address=${iface.cidr} interface=${iface.name}`);
      if (iface.cidr6) lines.push(`/ipv6 address add address=${iface.cidr6} interface=${iface.name}`);
    }
    for (const sr of node.staticRoutes) {
      const rt = sr.vrf && sr.vrf !== 'default' && sr.vrf !== 'main' ? ` routing-table=${sr.vrf}` : '';
      const dist = sr.ad !== undefined ? ` distance=${sr.ad}` : '';
      lines.push(`/ip route add dst-address=${sr.prefix} gateway=${sr.nextHop}${rt}${dist}`);
    }
    if (node.ospf.enabled) {
      lines.push(`/routing ospf instance add name=default-v2 router-id=${node.routerId}`);
      const areas = new Set(node.interfaces.filter((i) => i.ospfArea !== undefined).map((i) => i.ospfArea!));
      for (const a of areas) {
        lines.push(`/routing ospf area add name=area-${a} area-id=0.0.0.${a} instance=default-v2`);
      }
      for (const iface of node.interfaces.filter((i) => i.ospfArea !== undefined)) {
        lines.push(`/routing ospf interface-template add area=area-${iface.ospfArea} interfaces=${iface.name}${iface.passive ? ' passive=yes' : ''}`);
      }
    }
    if (node.bgp.enabled) {
      lines.push(`/routing bgp template set default as=${node.bgp.asn} router-id=${node.routerId}`);
      for (const p of node.bgp.peers) {
        lines.push(`/routing bgp connection add name=peer-${p.peerIp} remote.address=${p.peerIp} remote.as=${p.remoteAs} templates=default`);
      }
    }
    return lines.join('\n');
  }

  if (node.vendor === 'fortigate') {
    const lines: string[] = [
      `# FortiOS Configuration (${node.hostname})`,
      `config system global`,
      `    set hostname "${node.hostname}"`,
      `end`,
      `config system interface`,
    ];
    for (const iface of node.interfaces) {
      const parsed = parseCidr(iface.cidr);
      lines.push(`    edit "${iface.name}"`);
      if (iface.vrf && iface.vrf !== 'default') lines.push(`        set vrf ${iface.vrf}`);
      if (parsed) lines.push(`        set ip ${parsed.ip} ${uint32ToIp(parsed.maskUint32)}`);
      lines.push(`    next`);
    }
    lines.push(`end`);
    if (node.staticRoutes.length > 0) {
      lines.push(`config router static`);
      node.staticRoutes.forEach((sr, idx) => {
        lines.push(`    edit ${idx + 1}`);
        lines.push(`        set dst ${sr.prefix}`);
        lines.push(`        set gateway ${sr.nextHop}`);
        if (sr.ad !== undefined) lines.push(`        set distance ${sr.ad}`);
        lines.push(`    next`);
      });
      lines.push(`end`);
    }
    if ((node.pbrRules?.length ?? 0) > 0) {
      lines.push(`config router policy`);
      node.pbrRules!.forEach((p, idx) => {
        lines.push(`    edit ${idx + 1}`);
        if (p.ingressInterface) lines.push(`        set input-device "${p.ingressInterface}"`);
        if (p.srcCidr) lines.push(`        set src "${p.srcCidr}"`);
        if (p.matchPrefix) lines.push(`        set dst "${p.matchPrefix}"`);
        if (p.protocol === 'tcp') lines.push(`        set protocol 6`);
        else if (p.protocol === 'udp') lines.push(`        set protocol 17`);
        else if (p.protocol === 'icmp') lines.push(`        set protocol 1`);
        if (p.dstPort !== undefined) {
          lines.push(`        set start-port ${p.dstPort}`);
          lines.push(`        set end-port ${p.dstPort}`);
        }
        if (p.interfaceName) lines.push(`        set output-device "${p.interfaceName}"`);
        if (p.nextHop) lines.push(`        set gateway ${p.nextHop}`);
        lines.push(`    next`);
      });
      lines.push(`end`);
    }
    if (node.ospf.enabled) {
      lines.push(`config router ospf`, `    set router-id ${node.routerId}`);
      const passiveIfs = node.interfaces.filter((i) => i.passive);
      if (passiveIfs.length > 0) {
        lines.push(`    set passive-interface ${passiveIfs.map((i) => `"${i.name}"`).join(' ')}`);
      }
      lines.push(`end`);
    }
    if (node.rip?.enabled) {
      lines.push(`config router rip`);
      const passiveIfs = node.interfaces.filter((i) => i.passive);
      if (passiveIfs.length > 0) {
        lines.push(`    set passive-interface ${passiveIfs.map((i) => `"${i.name}"`).join(' ')}`);
      }
      lines.push(`end`);
    }
    if (node.bgp.enabled) {
      lines.push(`config router bgp`, `    set as ${node.bgp.asn}`, `    set router-id ${node.routerId}`);
      if (node.bgp.peers.length > 0) {
        lines.push(`    config neighbor`);
        for (const p of node.bgp.peers) {
        lines.push(`        edit "${p.peerIp}"`, `            set remote-as ${p.remoteAs}`);
        if (p.nextHopSelf) lines.push(`            set next-hop-self enable`);
        if (p.defaultOriginate) lines.push(`            set capability-default-originate enable`);
        lines.push(`        next`);
      }
        lines.push(`    end`);
      }
      lines.push(`end`);
    }
    if (node.fortiHa?.enabled) {
      const fha = node.fortiHa;
      const hbName = node.interfaces.find((i) => i.id === fha.hbInterfaceId)?.name;
      lines.push(`config system ha`);
      lines.push(`    set group-id ${fha.groupId}`);
      lines.push(`    set mode ${fha.mode}`);
      if (fha.priority !== undefined) lines.push(`    set priority ${fha.priority}`);
      if (fha.sessionPickup) lines.push(`    set session-pickup enable`);
      if (fha.override) lines.push(`    set override enable`);
      if (hbName) lines.push(`    set hbdev "${hbName}" 50`);
      lines.push(`end`);
    }
    if (node.sdwanSla?.enabled) {
      lines.push(`config system sdwan`, `    set status enable`);
      if (node.sdwanSla.rules.length > 0) {
        lines.push(`    config service`);
        node.sdwanSla.rules.forEach((rule, idx) => {
          lines.push(`        edit ${idx + 1}`, `            set name "${rule.name}"`);
          lines.push(`            set mode ${rule.mode === 'best-quality' ? 'sla' : 'priority'}`);
          if (rule.preferredMembers.length > 0) {
            lines.push(`            set priority-members ${rule.preferredMembers.map((m) => `"${m}"`).join(' ')}`);
          }
          lines.push(`        next`);
        });
        lines.push(`    end`);
      }
      lines.push(`end`);
    }
    return lines.join('\n');
  }

  const isForcepoint = node.vendor === 'forcepoint-ngfw';
  const lines: string[] = [
    isForcepoint
      ? `! Forcepoint NGFW FRR / vtysh Configuration (Single Engine VRF)`
      : `! Running Configuration (${node.hostname})`,
    `hostname ${node.hostname}`,
    `!`,
  ];

  if (!isForcepoint) {
    for (const vrf of vrfs) {
      lines.push(`vrf definition ${vrf}`, ` address-family ipv4`, ` exit-address-family`, `!`);
    }
  }

  if (node.vendor === 'cisco-nx-os' && node.vpc?.enabled) {
    lines.push(`feature vpc`, `vpc domain ${node.vpc.domainId}`);
    if (node.vpc.rolePriority !== undefined) lines.push(` role priority ${node.vpc.rolePriority}`);
    if (node.vpc.systemPriority !== undefined) lines.push(` system-priority ${node.vpc.systemPriority}`);
    if (node.vpc.peerKeepaliveDst) {
      const srcPart = node.vpc.peerKeepaliveSrc ? ` source ${node.vpc.peerKeepaliveSrc}` : '';
      const vrfPart = node.vpc.peerKeepaliveVrf ? ` vrf ${node.vpc.peerKeepaliveVrf}` : '';
      lines.push(` peer-keepalive destination ${node.vpc.peerKeepaliveDst}${srcPart}${vrfPart}`);
    }
    if (node.vpc.peerGateway) lines.push(` peer-gateway`);
    if (node.vpc.peerSwitch) lines.push(` peer-switch`);
    if (node.vpc.layer3PeerRouter) lines.push(` layer3 peer-router`);
    if (node.vpc.autoRecovery) lines.push(` auto-recovery`);
    if (node.vpc.ipArpSynchronize) lines.push(` ip arp synchronize`);
    if (node.vpc.delayRestore !== undefined) lines.push(` delay restore ${node.vpc.delayRestore}`);
    lines.push(`!`);
  }

  if (node.vendor === 'arista-eos' && node.mlag?.enabled) {
    const plName = node.interfaces.find((i) => i.id === node.mlag?.peerLinkInterfaceId)?.name;
    lines.push(`mlag configuration`, ` domain-id ${node.mlag.domainId || 'MLAG'}`);
    if (node.mlag.localInterface) lines.push(` local-interface ${node.mlag.localInterface}`);
    if (node.mlag.peerAddress) lines.push(` peer-address ${node.mlag.peerAddress}`);
    if (plName) lines.push(` peer-link ${plName}`);
    if (node.mlag.reloadDelay !== undefined) lines.push(` reload-delay ${node.mlag.reloadDelay}`);
    lines.push(`!`);
  }

  if (node.vendor === 'forcepoint-ngfw' && node.forcepointCluster?.enabled) {
    const fc = node.forcepointCluster;
    const hbName = node.interfaces.find((i) => i.id === fc.heartbeatInterfaceId)?.name;
    lines.push(`! Forcepoint NGFW Cluster ID ${fc.clusterId} (${fc.mode})`);
    if (fc.cviIp) lines.push(`! CVI: ${fc.cviIp}`);
    if (hbName) lines.push(`! Heartbeat / State-Sync Interface: ${hbName} (${fc.stateSync ? 'enabled' : 'disabled'})`);
    lines.push(`!`);
  }

  for (const iface of node.interfaces) {
    lines.push(`interface ${iface.name}`);
    const subDotIdx = iface.name.lastIndexOf('.');
    const subSuffix = subDotIdx > 0 ? iface.name.slice(subDotIdx + 1) : '';
    const subVlan = iface.vlanId ?? (/^\d+$/.test(subSuffix) ? Number(subSuffix) : undefined);
    if ((iface.parentInterface || (subDotIdx > 0 && /^\d+$/.test(subSuffix))) && subVlan !== undefined) {
      lines.push(` encapsulation dot1Q ${subVlan}`);
    }
    if (iface.vrf && iface.vrf !== 'default' && !isForcepoint) {
      lines.push(` vrf forwarding ${iface.vrf}`);
    }
    const parsed = parseCidr(iface.cidr);
    if (iface.unnumberedSource) {
      lines.push(` ip unnumbered ${iface.unnumberedSource}`);
    } else if (parsed) {
      lines.push(
        isForcepoint
          ? ` ip address ${iface.cidr}`
          : ` ip address ${parsed.ip} ${uint32ToIp(parsed.maskUint32)}`
      );
    } else if (iface.cidr.includes(':')) {
      lines.push(` ipv6 address ${iface.cidr}`);
    }
    if (iface.cidr6) {
      lines.push(` ipv6 address ${iface.cidr6}`);
    }
    for (const sec of iface.secondaryCidrs ?? []) {
      const sp = parseCidr(sec);
      if (sp) lines.push(` ip address ${sp.ip} ${uint32ToIp(sp.maskUint32)} secondary`);
    }
    if (iface.urpfMode) {
      lines.push(` ip verify unicast source reachable-via ${iface.urpfMode === 'strict' ? 'rx' : 'any'}`);
    }
    if (iface.speedMbps !== undefined) {
      lines.push(` speed ${iface.speedMbps}`);
      lines.push(` bandwidth ${iface.speedMbps * 1000}`);
    }
    if (iface.mtu !== undefined) {
      lines.push(` mtu ${iface.mtu}`);
    }
    if (
      iface.bfdIntervalMs !== undefined ||
      iface.bfdMinRxMs !== undefined ||
      iface.bfdMultiplier !== undefined
    ) {
      lines.push(
        ` bfd interval ${iface.bfdIntervalMs ?? 50} min_rx ${iface.bfdMinRxMs ?? 50} multiplier ${iface.bfdMultiplier ?? 3}`
      );
    }
    if (iface.ospfArea !== undefined) {
      lines.push(` ip ospf 1 area ${iface.ospfArea}`);
      if (iface.ospfCost !== undefined) lines.push(` ip ospf cost ${iface.ospfCost}`);
      if (iface.ospfPriority !== undefined) lines.push(` ip ospf priority ${iface.ospfPriority}`);
      if (iface.ospfNetworkType && iface.ospfNetworkType !== 'broadcast') {
        lines.push(` ip ospf network ${iface.ospfNetworkType}`);
      }
      if (iface.ospfHelloInterval !== undefined) {
        lines.push(` ip ospf hello-interval ${iface.ospfHelloInterval}`);
      }
      if (iface.ospfDeadInterval !== undefined) {
        lines.push(` ip ospf dead-interval ${iface.ospfDeadInterval}`);
      }
      if (iface.ospfAuthKey) {
        lines.push(` ip ospf authentication-key ${iface.ospfAuthKey}`);
      }
    }
    if (node.eigrp?.enabled) {
      if (iface.eigrpBw !== undefined) {
        lines.push(` bandwidth ${iface.eigrpBw}`);
      }
      if (iface.eigrpDelay !== undefined) {
        lines.push(` delay ${Math.max(1, Math.round(iface.eigrpDelay / 10))}`);
      }
      if (iface.eigrpHelloInterval !== undefined) {
        lines.push(` ip hello-interval eigrp ${node.eigrp.asn} ${iface.eigrpHelloInterval}`);
      }
      if (iface.eigrpHoldTime !== undefined) {
        lines.push(` ip hold-time eigrp ${node.eigrp.asn} ${iface.eigrpHoldTime}`);
      }
    }
    if (iface.isisLevel) {
      lines.push(` ip router isis`);
      lines.push(` isis circuit-type ${iface.isisLevel === 'L1' ? 'level-1' : 'level-2-only'}`);
      if (iface.isisMetric !== undefined) {
        lines.push(` isis metric ${iface.isisMetric}`);
      }
      if (iface.isisPriority !== undefined) {
        lines.push(` isis priority ${iface.isisPriority}`);
      }
      if (iface.isisNetworkType === 'point-to-point') {
        lines.push(` isis network point-to-point`);
      }
      if (iface.isisHelloInterval !== undefined) {
        lines.push(` isis hello-interval ${iface.isisHelloInterval}`);
      }
      if (iface.isisHelloMultiplier !== undefined) {
        lines.push(` isis hello-multiplier ${iface.isisHelloMultiplier}`);
      }
    }
    for (const grp of (node.fhrpGroups ?? []).filter((g) => g.interfaceId === iface.id)) {
      if (grp.protocol === 'hsrp') {
        lines.push(` standby ${grp.groupId} ip ${grp.virtualIp}`, ` standby ${grp.groupId} priority ${grp.priority}`);
      } else {
        lines.push(` vrrp ${grp.groupId} ip ${grp.virtualIp}`, ` vrrp ${grp.groupId} priority ${grp.priority}`);
      }
    }
    if (node.vendor === 'cisco-nx-os' && node.vpc?.enabled) {
      if (iface.id === node.vpc.peerLinkInterfaceId) lines.push(` vpc peer-link`);
      else if (iface.vpcId !== undefined) lines.push(` vpc ${iface.vpcId}`);
    }
    if (node.vendor === 'arista-eos' && node.mlag?.enabled && iface.mlagId !== undefined) {
      lines.push(` mlag ${iface.mlagId}`);
    }
    if (iface.lacpGroup !== undefined) {
      const mode = iface.lacpMode ?? 'active';
      const proto = iface.lagProtocol ?? (mode === 'desirable' || mode === 'auto' ? 'pagp' : mode === 'on' ? 'static' : 'lacp');
      if (proto === 'lacp' || proto === 'pagp') {
        lines.push(` channel-protocol ${proto}`);
      }
      lines.push(` channel-group ${iface.lacpGroup} mode ${mode}`);
    }
    if (iface.pimSparse) {
      lines.push(` ip pim sparse-mode`);
    }
    for (const h of iface.dhcpHelperIps ?? []) {
      lines.push(` ip helper-address ${h}`);
    }
    if (iface.qosPolicy?.dscpMark !== undefined) {
      lines.push(` ! qos-dscp ${iface.qosPolicy.dscpMark}`);
    }
    if (iface.macsecEnabled) lines.push(` macsec`);
    if (iface.dot1xState) lines.push(` dot1x port-control ${iface.dot1xState === 'force-authorized' ? 'force-authorized' : 'auto'}`);
    if (iface.dhcpSnoopingTrust) lines.push(` ip dhcp snooping trust`);
    if (iface.daiEnabled) lines.push(` ip arp inspection trust`);
    if (iface.ipSourceGuard) lines.push(` ip verify source`);
    if (iface.raGuard) lines.push(` ipv6 nd raguard attach-policy`);
    if (iface.evpnEsi) lines.push(` evpn ethernet-segment esi ${iface.evpnEsi}`);
    if (iface.shutdown) lines.push(` shutdown`);
    lines.push(`!`);
  }

  if (node.switching?.stpEnabled) {
    lines.push(`spanning-tree mode ${node.switching.stpMode ?? 'rstp'}`);
    if (node.switching.stpPriority !== undefined) {
      lines.push(`spanning-tree vlan 1 priority ${node.switching.stpPriority}`);
    }
  }
  if (node.switching?.lldpEnabled) {
    lines.push(`lldp run`);
  }
  if (node.timing?.ptpMode) {
    lines.push(`ptp mode ${node.timing.ptpMode}${node.timing.ptpDomain !== undefined ? ` domain ${node.timing.ptpDomain}` : ''}`);
  }
  if (node.timing?.ntpServer) {
    lines.push(`ntp server ${node.timing.ntpServer}`);
  }
  if (node.telemetry?.bmpServerIp) {
    lines.push(`bmp server 1 ${node.telemetry.bmpServerIp}`);
  }
  if (node.telemetry?.ipfixCollectorIp) {
    lines.push(`ip flow-export destination ${node.telemetry.ipfixCollectorIp} 4739`);
  }
  if (node.mpls?.ldpEnabled) {
    lines.push(`mpls ip`, `mpls ldp router-id ${node.mpls.ldpRouterId ?? node.routerId}`);
  }
  if (node.mpls?.segmentRouting?.enabled) {
    lines.push(
      `segment-routing mpls`,
      ` global-block ${node.mpls.segmentRouting.srgbStart ?? 16000} ${node.mpls.segmentRouting.srgbEnd ?? 23999}`,
      `!`
    );
  }
  if (node.multicast?.pimEnabled && node.multicast.rpAddress) {
    lines.push(`ip multicast-routing`, `ip pim rp-address ${node.multicast.rpAddress}`);
  }

  for (const sr of node.staticRoutes) {
    const parsed = parseCidr(sr.prefix);
    const vrfPart = sr.vrf && sr.vrf !== 'default' && !isForcepoint ? `vrf ${sr.vrf} ` : '';
    const adPart = sr.ad ? ` ${sr.ad}` : '';
    if (parsed) {
      const trackPart = sr.trackId ? ` track ${sr.trackId}` : '';
      const tagPart = sr.tag !== undefined ? ` tag ${sr.tag}` : '';
      lines.push(
        isForcepoint
          ? `ip route ${sr.prefix} ${sr.nextHop}${adPart}${trackPart}${tagPart}`
          : `ip route ${vrfPart}${parsed.network} ${uint32ToIp(parsed.maskUint32)} ${sr.nextHop}${sr.globalNextHop ? ' global' : ''}${adPart}${trackPart}${tagPart}`
      );
    }
  }
  for (const t of node.tracks ?? []) {
    lines.push(`track ${t.id} ip route ${t.targetIp} 255.255.255.255 reachability`);
  }
  for (const vl of node.vrfLeaks ?? []) {
    lines.push(`vrf-leak ${vl.fromVrf} to ${vl.toVrf}`);
  }
  if (node.staticRoutes.length > 0 || (node.tracks?.length ?? 0) > 0 || (node.vrfLeaks?.length ?? 0) > 0) lines.push(`!`);

  if (node.ospf.enabled) {
    lines.push(`router ospf 1`, ` router-id ${node.routerId}`);
    if (node.ospf.referenceBandwidth) {
      lines.push(` auto-cost reference-bandwidth ${node.ospf.referenceBandwidth}`);
    }
    if (node.ospf.maxMetricRouterLsa) {
      lines.push(` max-metric router-lsa`);
    }
    if (node.ospf.bfd) {
      lines.push(` bfd all-interfaces`);
    }
    for (const iface of node.interfaces.filter(
      (i) => (i.vrf || 'default') === 'default' && i.passive && i.ospfArea !== undefined
    )) {
      lines.push(` passive-interface ${iface.name}`);
    }
    for (const net of node.ospf.networks.filter((n) => (n.vrf || 'default') === 'default')) {
      const parsed = parseCidr(net.prefix);
      if (parsed) {
        const wildcard = uint32ToIp((~parsed.maskUint32) >>> 0);
        lines.push(` network ${parsed.network} ${wildcard} area ${net.area}`);
      }
    }
    for (const [areaId, aType] of Object.entries(node.ospf.areaTypes ?? {})) {
      if (aType === 'stub') lines.push(` area ${areaId} stub`);
      else if (aType === 'totally-stubby') lines.push(` area ${areaId} stub no-summary`);
      else if (aType === 'nssa') {
        lines.push(
          ` area ${areaId} nssa${node.ospf.nssaNoSummary?.[Number(areaId)] ? ' no-summary' : ''}`
        );
      }
    }
    for (const ar of node.ospf.areaRanges ?? []) {
      const p = parseCidr(ar.prefix);
      if (p) lines.push(` area ${ar.area} range ${p.network} ${uint32ToIp(p.maskUint32)}`);
    }
    for (const vl of node.ospf.virtualLinks ?? []) {
      lines.push(` area ${vl.transitArea} virtual-link ${vl.peerRouterId}`);
    }
    if (node.ospf.defaultOriginate) {
      lines.push(` default-information originate`);
    }
    for (const r of node.redistributions.filter((x) => x.to === 'ospf')) {
      const mType = r.metricType === 'E1' ? ' metric-type 1' : '';
      lines.push(` redistribute ${r.from}${r.metric ? ` metric ${r.metric}` : ''}${mType} subnets`);
    }
    lines.push(`!`);
    const ospfNonDefaultVrfs = Array.from(
      new Set([
        ...node.interfaces
          .filter((i) => i.ospfArea !== undefined && (i.vrf || 'default') !== 'default')
          .map((i) => i.vrf),
        ...node.ospf.networks
          .filter((n) => (n.vrf || 'default') !== 'default')
          .map((n) => n.vrf!),
      ])
    );
    for (const ovrf of ospfNonDefaultVrfs) {
      const vRid = node.vrfRouterIds?.[ovrf]?.trim() || node.routerId;
      lines.push(`router ospf 1 vrf ${ovrf}`, ` router-id ${vRid}`);
      if (node.ospf.bfd) lines.push(` bfd all-interfaces`);
      for (const iface of node.interfaces.filter((i) => i.passive && i.ospfArea !== undefined && (i.vrf || 'default') === ovrf)) {
        lines.push(` passive-interface ${iface.name}`);
      }
      for (const net of node.ospf.networks.filter((n) => (n.vrf || 'default') === ovrf)) {
        const parsed = parseCidr(net.prefix);
        if (parsed) {
          const wildcard = uint32ToIp((~parsed.maskUint32) >>> 0);
          lines.push(` network ${parsed.network} ${wildcard} area ${net.area}`);
        }
      }
      lines.push(`!`);
    }
  }

  if (node.eigrp?.enabled) {
    lines.push(`router eigrp ${node.eigrp.asn}`, ` eigrp router-id ${node.routerId}`);
    if (node.eigrp.variance && node.eigrp.variance > 1) {
      lines.push(` variance ${node.eigrp.variance}`);
    }
    if (node.eigrp.kValues) {
      lines.push(` metric weights 0 ${node.eigrp.kValues.join(' ')}`);
    }
    if (node.eigrp.bfd) lines.push(` bfd all-interfaces`);
    for (const iface of node.interfaces.filter((i) => i.passive)) {
      lines.push(` passive-interface ${iface.name}`);
    }
    for (const net of node.eigrp.networks) {
      const parsed = parseCidr(net.prefix);
      if (parsed) {
        const wildcard = uint32ToIp((~parsed.maskUint32) >>> 0);
        lines.push(` network ${parsed.network} ${wildcard}`);
      }
    }
    for (const r of node.redistributions.filter((x) => x.to === 'eigrp')) {
      lines.push(` redistribute ${r.from}${r.metric ? ` metric ${r.metric}` : ''}`);
    }
    lines.push(`!`);
  }

  if (node.isis?.enabled) {
    const isisType =
      node.isis.level === 'L1'
        ? 'level-1'
        : node.isis.level === 'L2'
          ? 'level-2-only'
          : 'level-1-2';
    lines.push(`router isis`);
    if (node.isis.net) lines.push(` net ${node.isis.net}`);
    lines.push(` is-type ${isisType}`);
    if (node.isis.overloadBit) lines.push(` set-overload-bit`);
    if (node.isis.metricStyle) lines.push(` metric-style ${node.isis.metricStyle}`);
    if (node.isis.multiTopologyV6) lines.push(` address-family ipv6 unicast`, `  multi-topology`, ` exit-address-family`);
    if (node.isis.bfd) lines.push(` bfd all-interfaces`);
    for (const iface of node.interfaces.filter((i) => i.passive && i.isisLevel)) {
      lines.push(` passive-interface ${iface.name}`);
    }
    for (const sum of node.isis.summaries ?? []) {
      const parsed = parseCidr(sum.prefix);
      if (parsed) lines.push(` summary-address ${parsed.network} ${uint32ToIp(parsed.maskUint32)}`);
    }
    for (const lk of node.isis.leakL2ToL1 ?? []) {
      lines.push(` redistribute isis ip level-2 into level-1 prefix ${lk.prefix}`);
    }
    for (const net of node.isis.networks) {
      lines.push(` ! advertise ${net.prefix}${net.level ? ` (${net.level})` : ''}`);
    }
    for (const r of node.redistributions.filter((x) => x.to === 'isis')) {
      lines.push(` redistribute ${r.from}${r.metric ? ` metric ${r.metric}` : ''}`);
    }
    lines.push(`!`);
  }

  if (node.rip?.enabled) {
    lines.push(`router rip`, ` version ${node.rip.version ?? 2}`, ` no auto-summary`);
    for (const iface of node.interfaces.filter((i) => i.passive)) {
      lines.push(` passive-interface ${iface.name}`);
    }
    for (const net of node.rip.networks) {
      const parsed = parseCidr(net.prefix);
      if (parsed) lines.push(` network ${parsed.network}/${parsed.prefixLen}`);
    }
    if (node.rip.defaultOriginate) lines.push(` default-information originate`);
    for (const r of node.redistributions.filter((x) => x.to === 'rip')) {
      lines.push(` redistribute ${r.from}${r.metric ? ` metric ${r.metric}` : ''}`);
    }
    lines.push(`!`);
  }

  if (node.lisp?.enabled) {
    lines.push(`router lisp`);
    lines.push(` locator-table default`);
    lines.push(` instance-id ${node.lisp.instanceId ?? 0}`);
    lines.push(`  service ipv4`);
    if (node.lisp.role !== 'ms-mr') {
      lines.push(`   itr`);
      lines.push(`   etr`);
      if (node.lisp.bfd) {
        lines.push(`   rloc-probing bfd`);
      }
      if (node.lisp.mapServerIp) {
        lines.push(`   map-resolver ${node.lisp.mapServerIp}`);
        lines.push(`   map-server ${node.lisp.mapServerIp}`);
      }
      for (const eid of node.lisp.eidPrefixes) {
        lines.push(
          `   database-mapping ${eid.prefix} ${node.lisp.rlocIp || node.routerId} priority ${eid.priority ?? 1} weight ${eid.weight ?? 100}`
        );
      }
    } else {
      lines.push(`   map-server`);
      lines.push(`   map-resolver`);
    }
    lines.push(`!`);
  }

  if (node.evpn?.enabled) {
    lines.push(`! VXLAN / BGP EVPN`);
    lines.push(`interface nve1`);
    lines.push(` source-interface ${node.evpn.vtepIp || node.routerId}`);
    if (node.evpn.l3Vni) lines.push(` member vni ${node.evpn.l3Vni} associate-vrf`);
    if (node.evpn.l2Vni) lines.push(` member vni ${node.evpn.l2Vni}`);
    lines.push(`!`);
  }

  if (node.mplsVpn?.enabled) {
    for (const vt of node.mplsVpn.vrfTargets) {
      lines.push(`vrf definition ${vt.vrf}`);
      lines.push(` rd ${vt.rd}`);
      if (vt.exportRt) lines.push(` route-target export ${vt.exportRt}`);
      if (vt.importRt) lines.push(` route-target import ${vt.importRt}`);
      lines.push(`!`);
    }
  }

  if (node.bgp.enabled) {
    lines.push(
      `router bgp ${node.bgp.asn}`,
      ` bgp router-id ${node.routerId}`,
      ` maximum-paths ${node.maxPaths ?? 4}`
    );
    if (node.bgp.clusterId?.trim()) {
      lines.push(` bgp cluster-id ${node.bgp.clusterId.trim()}`);
    }
    if (node.bgp.confederationId) {
      lines.push(` bgp confederation identifier ${node.bgp.confederationId}`);
      if (node.bgp.confederationPeers?.length) {
        lines.push(` bgp confederation peers ${node.bgp.confederationPeers.join(' ')}`);
      }
    }
    if (node.bgp.alwaysCompareMed) lines.push(` bgp always-compare-med`);
    if (node.bgp.deterministicMed) lines.push(` bgp deterministic-med`);
    if (node.bgp.bestpathAsPathIgnore) lines.push(` bgp bestpath as-path ignore`);
    if (node.bgp.medMissingAsWorst) lines.push(` bgp bestpath med missing-as-worst`);
    if (node.bgp.rpkiRejectInvalid) lines.push(` bgp rpki reject-invalid`);
    if (node.bgp.gracefulRestart) lines.push(` bgp graceful-restart`);
    const formatBgpPeerLines = (p: (typeof node.bgp.peers)[number], indent = ' ') => {
      lines.push(`${indent}neighbor ${p.peerIp} remote-as ${p.remoteAs}`);
      if (p.localAs) {
        lines.push(
          `${indent}neighbor ${p.peerIp} local-as ${p.localAs}${p.localAsNoPrepend ? ' no-prepend' : ''}${p.localAsReplaceAs ? ' replace-as' : ''}`
        );
      }
      if (p.disableConnectedCheck) lines.push(`${indent}neighbor ${p.peerIp} disable-connected-check`);
      if (p.addPath) lines.push(`${indent}neighbor ${p.peerIp} add-path ${p.addPath}`);
      if (p.shutdown) lines.push(`${indent}neighbor ${p.peerIp} shutdown`);
      if (p.updateSource) lines.push(`${indent}neighbor ${p.peerIp} update-source ${p.updateSource}`);
      if (p.allowAsIn) lines.push(`${indent}neighbor ${p.peerIp} allowas-in`);
      if (p.asOverride) lines.push(`${indent}neighbor ${p.peerIp} as-override`);
      if (p.sendCommunity && p.sendCommunity !== 'none') {
        lines.push(
          `${indent}neighbor ${p.peerIp} send-community${p.sendCommunity === 'standard' ? '' : ` ${p.sendCommunity}`}`
        );
      }
      if (p.removePrivateAs) lines.push(`${indent}neighbor ${p.peerIp} remove-private-as`);
      if (p.maxPrefixes !== undefined) lines.push(`${indent}neighbor ${p.peerIp} maximum-prefix ${p.maxPrefixes}`);
      if (p.nextHopSelf) lines.push(`${indent}neighbor ${p.peerIp} next-hop-self`);
      if (p.defaultOriginate) lines.push(`${indent}neighbor ${p.peerIp} default-originate`);
      if (p.routeReflectorClient) lines.push(`${indent}neighbor ${p.peerIp} route-reflector-client`);
      if (p.ebgpMultihop) lines.push(`${indent}neighbor ${p.peerIp} ebgp-multihop`);
      if (p.bfd) lines.push(`${indent}neighbor ${p.peerIp} fall-over bfd`);
      if (p.keepaliveTime !== undefined || p.holdTime !== undefined) {
        lines.push(`${indent}neighbor ${p.peerIp} timers ${p.keepaliveTime ?? 60} ${p.holdTime ?? 180}`);
      }
      if (p.softReconfigurationInbound) lines.push(`${indent}neighbor ${p.peerIp} soft-reconfiguration inbound`);
      if (p.gracefulRestart) lines.push(`${indent}neighbor ${p.peerIp} graceful-restart`);
      if (p.weight !== undefined) lines.push(`${indent}neighbor ${p.peerIp} weight ${p.weight}`);
      if (p.routeMapInId) {
        const rmIn = node.routeMaps.find((m) => m.id === p.routeMapInId);
        if (rmIn) lines.push(`${indent}neighbor ${p.peerIp} route-map ${rmIn.name} in`);
      }
      if (p.routeMapOutId) {
        const rmOut = node.routeMaps.find((m) => m.id === p.routeMapOutId);
        if (rmOut) lines.push(`${indent}neighbor ${p.peerIp} route-map ${rmOut.name} out`);
      }
      if (p.localPref !== undefined) lines.push(`${indent}! local-preference ${p.localPref}`);
    };

    for (const p of node.bgp.peers.filter((x) => (x.vrf || 'default') === 'default')) {
      formatBgpPeerLines(p, ' ');
    }
    for (const n of node.bgp.networks.filter((x) => (x.vrf || 'default') === 'default')) {
      const parsed = parseCidr(n.prefix);
      if (parsed) {
        lines.push(` network ${parsed.network} mask ${uint32ToIp(parsed.maskUint32)}`);
      }
    }
    const bgpVrfs = Array.from(
      new Set([
        ...Object.keys(node.vrfRouterIds ?? {}).filter((v) => v !== 'default' && node.vrfRouterIds?.[v]?.trim()),
        ...node.bgp.peers.map((p) => p.vrf || 'default').filter((v) => v !== 'default'),
        ...node.bgp.networks.map((n) => n.vrf || 'default').filter((v) => v !== 'default'),
      ])
    );
    for (const vrfName of bgpVrfs) {
      lines.push(` address-family ipv4 vrf ${vrfName}`);
      const rid = node.vrfRouterIds?.[vrfName]?.trim();
      if (rid) lines.push(`  bgp router-id ${rid}`);
      for (const p of node.bgp.peers.filter((x) => (x.vrf || 'default') === vrfName)) {
        formatBgpPeerLines(p, '  ');
      }
      for (const n of node.bgp.networks.filter((x) => (x.vrf || 'default') === vrfName)) {
        const parsed = parseCidr(n.prefix);
        if (parsed) {
          lines.push(`  network ${parsed.network} mask ${uint32ToIp(parsed.maskUint32)}`);
        }
      }
      lines.push(` exit-address-family`);
    }
    for (const agg of node.bgp.aggregates ?? []) {
      const parsed = parseCidr(agg.prefix);
      if (parsed) {
        lines.push(
          ` aggregate-address ${parsed.network} ${uint32ToIp(parsed.maskUint32)}${agg.summaryOnly ? ' summary-only' : ''}${agg.asSet ? ' as-set' : ''}`
        );
      }
    }
    for (const r of node.redistributions.filter((x) => x.to === 'bgp')) {
      lines.push(` redistribute ${r.from}${r.metric ? ` metric ${r.metric}` : ''}`);
    }
    lines.push(`!`);
  }

  for (const pl of node.prefixLists ?? []) {
    for (const e of pl.entries) {
      const gePart = e.ge !== undefined ? ` ge ${e.ge}` : '';
      const lePart = e.le !== undefined ? ` le ${e.le}` : '';
      lines.push(`ip prefix-list ${pl.name} seq ${e.seq} ${e.action} ${e.prefix}${gePart}${lePart}`);
    }
  }
  if ((node.prefixLists ?? []).length > 0) lines.push(`!`);

  for (const rm of node.routeMaps ?? []) {
    for (const e of rm.entries) {
      lines.push(`route-map ${rm.name} ${e.action} ${e.seq}`);
      if (e.matchPrefixListId) {
        const pl = node.prefixLists.find((p) => p.id === e.matchPrefixListId);
        if (pl) lines.push(` match ip address prefix-list ${pl.name}`);
      }
      if (e.matchCommunity) lines.push(` match community ${e.matchCommunity}`);
      if (e.matchAsPathRegex) lines.push(` match as-path ${e.matchAsPathRegex}`);
      if (e.matchTag !== undefined) lines.push(` match tag ${e.matchTag}`);
      if (e.set.setLocalPref !== undefined) {
        lines.push(` set local-preference ${e.set.setLocalPref}`);
      }
      if (e.set.setMed !== undefined) {
        lines.push(` set metric ${e.set.setMed}`);
      }
      if (e.set.prependAsPath?.length) {
        lines.push(` set as-path prepend ${e.set.prependAsPath.join(' ')}`);
      }
      if (e.set.setCommunity) {
        lines.push(` set community ${e.set.setCommunity}`);
      }
      if (e.set.setTag !== undefined) {
        lines.push(` set tag ${e.set.setTag}`);
      }
      if (e.set.setAd !== undefined) {
        lines.push(` set distance ${e.set.setAd}`);
      }
      lines.push(`!`);
    }
  }

  if (node.aclRules && node.aclRules.length > 0) {
    lines.push(`ip access-list extended SIM-POLICY`);
    for (const a of node.aclRules) {
      lines.push(
        ` ${a.seq} ${a.action === 'allow' ? 'permit' : 'deny'} ${a.protocol} ${a.srcCidr} ${a.dstCidr}${a.dstPort ? ` eq ${a.dstPort}` : ''} ! ${a.name}`
      );
    }
    lines.push(`!`);
  }

  lines.push(`end`);
  return lines.join('\n');
}
