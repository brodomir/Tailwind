import {
  PrefixListConfig,
  RoaEntry,
  RouteMapAction,
  RouteMapConfig,
} from '../types/network';
import {
  detectAddressFamily,
  isIp6InCidr,
  isIpInCidr,
  parseCidr,
  parseCidr6,
  prefixMask,
  prefixMask6,
} from './ipMath';

export function validateRpkiOrigin(
  prefix: string,
  prefixLen: number,
  originAsn: number | undefined,
  roaTable?: RoaEntry[]
): 'valid' | 'invalid' | 'not-found' {
  if (!roaTable || roaTable.length === 0) return 'not-found';
  const af = detectAddressFamily(prefix);
  if (!af) return 'not-found';
  let covered = false;
  for (const roa of roaTable) {
    const rAf = detectAddressFamily(roa.prefix);
    if (rAf !== af) continue;
    const roaParsed = af === 4 ? parseCidr(roa.prefix) : parseCidr6(roa.prefix);
    if (!roaParsed || prefixLen < roaParsed.prefixLen) continue;
    const inSupernet =
      af === 4 ? isIpInCidr(prefix, roa.prefix) : isIp6InCidr(prefix, roa.prefix);
    if (!inSupernet) continue;
    covered = true;
    if (
      originAsn !== undefined &&
      roa.originAsn === originAsn &&
      prefixLen <= roa.maxLength
    ) {
      return 'valid';
    }
  }
  return covered ? 'invalid' : 'not-found';
}

export interface RouteMapEvaluation {
  permitted: boolean;
  set: RouteMapAction;
}

export function matchPrefixList(
  prefix: string,
  prefixLen: number,
  prefixList: PrefixListConfig
): boolean {
  const af = detectAddressFamily(prefix);
  const sorted = [...prefixList.entries].sort((a, b) => a.seq - b.seq);

  if (af === 6) {
    const target = parseCidr6(`${prefix}/${prefixLen}`);
    if (!target) return false;
    for (const entry of sorted) {
      const rule = parseCidr6(entry.prefix);
      if (!rule) continue;
      const ruleMask = prefixMask6(rule.prefixLen);
      const sameSupernet = (target.networkBigInt & ruleMask) === rule.networkBigInt;
      if (!sameSupernet) continue;

      const minLen = Math.max(entry.ge ?? rule.prefixLen, rule.prefixLen);
      const maxLen = entry.le ?? (entry.ge !== undefined ? 128 : rule.prefixLen);
      if (prefixLen >= minLen && prefixLen <= maxLen) {
        return entry.action === 'permit';
      }
    }
    return false;
  }

  const target = parseCidr(`${prefix}/${prefixLen}`);
  if (!target) return false;

  for (const entry of sorted) {
    const rule = parseCidr(entry.prefix);
    if (!rule) continue;

    const ruleMask = prefixMask(rule.prefixLen);
    const sameSupernet =
      ((target.networkUint32 & ruleMask) >>> 0) === rule.networkUint32;
    if (!sameSupernet) continue;

    const minLen = Math.max(entry.ge ?? rule.prefixLen, rule.prefixLen);
    const maxLen = entry.le ?? (entry.ge !== undefined ? 32 : rule.prefixLen);

    if (prefixLen >= minLen && prefixLen <= maxLen) {
      return entry.action === 'permit';
    }
  }

  return false;
}

function safeCompileRegex(pattern: string): RegExp | null {
  if (!pattern || pattern.length > 128) return null;
  if (/(\+|\*|\{[^}]+\})\s*(\+|\*|\?|\{)/.test(pattern)) return null;
  if (/\([^)]*[+*][^)]*\)\s*[+*?]/.test(pattern)) return null;
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}

export function evaluateRouteMap(
  prefix: string,
  prefixLen: number,
  routeMap: RouteMapConfig,
  prefixLists: PrefixListConfig[],
  ctx?: {
    communities?: string[];
    largeCommunities?: string[];
    asPath?: number[];
    rpkiState?: 'valid' | 'invalid' | 'not-found';
    tag?: number;
  }
): RouteMapEvaluation {
  const sorted = [...routeMap.entries].sort((a, b) => a.seq - b.seq);
  for (const entry of sorted) {
    let matched = true;
    if (entry.matchPrefixListId) {
      const pl = prefixLists.find((p) => p.id === entry.matchPrefixListId);
      matched = pl ? matchPrefixList(prefix, prefixLen, pl) : false;
    }
    if (matched && entry.matchCommunity) {
      const targetComm = entry.matchCommunity.trim();
      matched = Boolean(ctx?.communities?.includes(targetComm));
    }
    if (matched && entry.matchLargeCommunity) {
      const targetLarge = entry.matchLargeCommunity.trim();
      matched = Boolean(ctx?.largeCommunities?.includes(targetLarge));
    }
    if (matched && entry.matchAsPathRegex) {
      const rx = safeCompileRegex(entry.matchAsPathRegex);
      matched = rx ? rx.test((ctx?.asPath ?? []).join(' ')) : false;
    }
    if (matched && entry.matchRpki) {
      matched = (ctx?.rpkiState ?? 'not-found') === entry.matchRpki;
    }
    if (matched && entry.matchTag !== undefined) {
      matched = ctx?.tag === entry.matchTag;
    }

    if (matched) {
      if (entry.action === 'deny') {
        return { permitted: false, set: {} };
      }
      return { permitted: true, set: entry.set };
    }
  }

  return { permitted: false, set: {} };
}

