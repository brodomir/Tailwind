import { AclRuleConfig, L4Protocol, NatRuleConfig } from '../types/network';
import { detectAddressFamily, isIp6InCidr, isIpInCidr } from './ipMath';

function matchesCidrOrAny(ip: string, cidrOrAny: string): boolean {
  const c = cidrOrAny.trim().toLowerCase();
  if (!c || c === 'any') return true;
  const af = detectAddressFamily(ip);
  if (c === '0.0.0.0/0') return af === 4;
  if (c === '::/0') return af === 6;
  const normalized = c.includes('/') ? c : af === 6 ? `${c}/128` : `${c}/32`;
  if (af === 4) return isIpInCidr(ip, normalized);
  if (af === 6) return isIp6InCidr(ip, normalized);
  return false;
}

export function evaluateAcl(
  rules: AclRuleConfig[] | undefined,
  srcIp: string,
  dstIp: string,
  protocol: L4Protocol = 'any',
  dstPort?: number,
  srcZone?: string,
  dstZone?: string
): { allowed: boolean; matchedRule?: string } {
  if (!rules || rules.length === 0) {
    return { allowed: true };
  }

  const sorted = [...rules].sort((a, b) => a.seq - b.seq);
  for (const r of sorted) {
    if (r.srcZone && r.srcZone.toLowerCase() !== 'any' && srcZone?.toLowerCase() !== r.srcZone.toLowerCase()) continue;
    if (r.dstZone && r.dstZone.toLowerCase() !== 'any' && dstZone?.toLowerCase() !== r.dstZone.toLowerCase()) continue;
    if (!matchesCidrOrAny(srcIp, r.srcCidr)) continue;
    if (!matchesCidrOrAny(dstIp, r.dstCidr)) continue;
    if (r.protocol !== 'any' && protocol !== 'any' && r.protocol !== protocol) continue;
    if (r.dstPort !== undefined && dstPort !== undefined && r.dstPort !== dstPort) continue;

    return {
      allowed: r.action === 'allow',
      matchedRule: `${r.action.toUpperCase()} (${r.name})`,
    };
  }

  return {
    allowed: false,
    matchedRule: 'DENY (implicit-deny)',
  };
}

export function evaluatePreRoutingDnat(
  rules: NatRuleConfig[] | undefined,
  srcIp: string,
  dstIp: string
): { dstIp: string; note?: string } {
  if (!rules || rules.length === 0) return { dstIp };

  const dstAf = detectAddressFamily(dstIp);
  const sorted = [...rules].filter((r) => r.type === 'dnat').sort((a, b) => a.seq - b.seq);
  for (const r of sorted) {
    if (!matchesCidrOrAny(srcIp, r.srcCidr)) continue;
    if (!matchesCidrOrAny(dstIp, r.dstCidr)) continue;
    if (r.translatedIp && (!dstAf || detectAddressFamily(r.translatedIp) === dstAf)) {
      return {
        dstIp: r.translatedIp,
        note: `DNAT ${dstIp} → ${r.translatedIp} (${r.name})`,
      };
    }
  }
  return { dstIp };
}

export function evaluatePostRoutingSnat(
  rules: NatRuleConfig[] | undefined,
  srcIp: string,
  dstIp: string
): { srcIp: string; note?: string } {
  if (!rules || rules.length === 0) return { srcIp };

  const srcAf = detectAddressFamily(srcIp);
  const sorted = [...rules].filter((r) => r.type === 'snat').sort((a, b) => a.seq - b.seq);
  for (const r of sorted) {
    if (!matchesCidrOrAny(srcIp, r.srcCidr)) continue;
    if (!matchesCidrOrAny(dstIp, r.dstCidr)) continue;
    if (r.translatedIp && (!srcAf || detectAddressFamily(r.translatedIp) === srcAf)) {
      return {
        srcIp: r.translatedIp,
        note: `SNAT ${srcIp} → ${r.translatedIp} (${r.name})`,
      };
    }
  }
  return { srcIp };
}

