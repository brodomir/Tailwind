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
  return `${r.protocol}|${r.ospfType ?? ''}|${r.ad}|${r.metric}|${r.nextHop}|${r.egressInterface}|${r.leakedFromVrf ?? ''}`;
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

    const bMap = new Map<string, RibEntry>();
    for (const r of bNode?.rib ?? []) {
      if (r.active) bMap.set(entryKey(r), r);
    }

    const cMap = new Map<string, RibEntry>();
    for (const r of cNode?.rib ?? []) {
      if (r.active) cMap.set(entryKey(r), r);
    }

    const keys = new Set([...bMap.keys(), ...cMap.keys()]);
    for (const key of keys) {
      const before = bMap.get(key);
      const after = cMap.get(key);
      const sep = key.indexOf('|');
      const vrf = sep === -1 ? 'default' : key.slice(0, sep);
      const cidr = sep === -1 ? key : key.slice(sep + 1);

      if (!before && after) {
        items.push({ nodeId, hostname, vrf, cidr, status: 'added', after });
      } else if (before && !after) {
        items.push({ nodeId, hostname, vrf, cidr, status: 'removed', before });
      } else if (before && after && entryFingerprint(before) !== entryFingerprint(after)) {
        items.push({ nodeId, hostname, vrf, cidr, status: 'modified', before, after });
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

