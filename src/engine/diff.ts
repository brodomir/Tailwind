import { RibEntry, SimulationResult } from '../types/network';

export interface RibDiffItem {
  nodeId: string;
  hostname: string;
  vrf: string;
  cidr: string;
  status: 'added' | 'removed' | 'modified';
  before?: RibEntry;
  after?: RibEntry;
}

export interface RibDiffSummary {
  items: RibDiffItem[];
  added: number;
  removed: number;
  modified: number;
}

function entryKey(r: RibEntry): string {
  return `${r.vrf}|${r.prefix}/${r.prefixLen}`;
}

function entryFingerprint(r: RibEntry): string {
  const b = r.bgpAttrs;
  const bgpPart = b
    ? `${b.weight}|${b.localPref}|${b.asPath.join(',')}|${b.origin}|${b.med}|${(b.communities ?? []).join(',')}|${b.rpkiState ?? ''}`
    : '';
  const tlocPart = r.tloc ? `${r.tloc.systemIp}|${r.tloc.color}|${r.tloc.encap}` : '';
  return `${r.protocol}|${r.ospfType ?? ''}|${r.isisLevel ?? ''}|${r.ad}|${r.metric}|${r.nextHop}|${r.egressInterface}|${r.leakedFromVrf ?? ''}|${r.tag ?? ''}|${r.evpnVni ?? ''}|${r.azureNextHopType ?? ''}|${r.awsTargetType ?? ''}|${r.gcpNextHopType ?? ''}|${r.gcpPriority ?? ''}|${bgpPart}|${tlocPart}`;
}

export function computeRibDiff(
  baseline: SimulationResult,
  current: SimulationResult
): RibDiffSummary {
  const items: RibDiffItem[] = [];
  const allNodeIds = new Set([
    ...Object.keys(baseline.nodes),
    ...Object.keys(current.nodes),
  ]);

  for (const nodeId of allNodeIds) {
    const bNode = baseline.nodes[nodeId];
    const cNode = current.nodes[nodeId];
    const hostname = cNode?.hostname ?? bNode?.hostname ?? nodeId;

    const bMap = new Map<string, RibEntry[]>();
    for (const r of bNode?.rib ?? []) {
      if (!r.active) continue;
      const k = entryKey(r);
      const list = bMap.get(k);
      if (list) list.push(r);
      else bMap.set(k, [r]);
    }

    const cMap = new Map<string, RibEntry[]>();
    for (const r of cNode?.rib ?? []) {
      if (!r.active) continue;
      const k = entryKey(r);
      const list = cMap.get(k);
      if (list) list.push(r);
      else cMap.set(k, [r]);
    }

    const keys = new Set([...bMap.keys(), ...cMap.keys()]);
    for (const key of keys) {
      const beforeList = bMap.get(key);
      const afterList = cMap.get(key);
      const before = beforeList?.[0];
      const after = afterList?.[0];
      const sep = key.indexOf('|');
      const vrf = sep === -1 ? 'default' : key.slice(0, sep);
      const cidr = sep === -1 ? key : key.slice(sep + 1);

      if (!beforeList && afterList) {
        items.push({ nodeId, hostname, vrf, cidr, status: 'added', after });
      } else if (beforeList && !afterList) {
        items.push({ nodeId, hostname, vrf, cidr, status: 'removed', before });
      } else if (beforeList && afterList) {
        const beforeFp = beforeList.map(entryFingerprint).sort().join('||');
        const afterFp = afterList.map(entryFingerprint).sort().join('||');
        if (beforeFp !== afterFp) {
          items.push({ nodeId, hostname, vrf, cidr, status: 'modified', before, after });
        }
      }
    }
  }

  return {
    items,
    added: items.filter((i) => i.status === 'added').length,
    removed: items.filter((i) => i.status === 'removed').length,
    modified: items.filter((i) => i.status === 'modified').length,
  };
}

