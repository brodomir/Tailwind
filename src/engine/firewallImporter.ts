import { AclRuleConfig, L4Protocol } from '../types/network';

const WELL_KNOWN_SERVICES: Record<string, { protocol: L4Protocol; dstPort?: number }> = {
  any: { protocol: 'any' },
  all: { protocol: 'any' },
  'application-default': { protocol: 'any' },
  ip: { protocol: 'any' },
  icmp: { protocol: 'icmp' },
  ping: { protocol: 'icmp' },
  all_icmp: { protocol: 'icmp' },
  'junos-icmp-all': { protocol: 'icmp' },
  'junos-ping': { protocol: 'icmp' },
  tcp: { protocol: 'tcp' },
  udp: { protocol: 'udp' },
  http: { protocol: 'tcp', dstPort: 80 },
  www: { protocol: 'tcp', dstPort: 80 },
  'junos-http': { protocol: 'tcp', dstPort: 80 },
  https: { protocol: 'tcp', dstPort: 443 },
  'junos-https': { protocol: 'tcp', dstPort: 443 },
  ssh: { protocol: 'tcp', dstPort: 22 },
  'junos-ssh': { protocol: 'tcp', dstPort: 22 },
  telnet: { protocol: 'tcp', dstPort: 23 },
  smtp: { protocol: 'tcp', dstPort: 25 },
  dns: { protocol: 'udp', dstPort: 53 },
  domain: { protocol: 'udp', dstPort: 53 },
  'junos-dns-udp': { protocol: 'udp', dstPort: 53 },
  ntp: { protocol: 'udp', dstPort: 123 },
  snmp: { protocol: 'udp', dstPort: 161 },
  bgp: { protocol: 'tcp', dstPort: 179 },
  syslog: { protocol: 'udp', dstPort: 514 },
  rdp: { protocol: 'tcp', dstPort: 3389 },
  'ms-rdp': { protocol: 'tcp', dstPort: 3389 },
};

function stripQuotes(s: string): string {
  return s.trim().replace(/^["']|["']$/g, '').trim();
}

function maskToPrefixLenLocal(mask: string): number {
  const parts = mask.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return 32;
  let bits = 0;
  for (const octet of parts) {
    let v = octet;
    while (v > 0) {
      bits += v & 1;
      v >>= 1;
    }
  }
  return bits;
}

function wildcardToPrefixLenLocal(wildcard: string): number {
  const parts = wildcard.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return 32;
  let hostBits = 0;
  for (const octet of parts) {
    let v = octet;
    while (v > 0) {
      hostBits += v & 1;
      v >>= 1;
    }
  }
  return Math.max(0, 32 - hostBits);
}

function resolveAddressToken(token: string, addrBook: Map<string, string>): string {
  const clean = stripQuotes(token).replace(/^\[|\]$/g, '').trim();
  const lower = clean.toLowerCase();
  if (!clean || lower === 'any' || lower === 'all' || lower === '0.0.0.0/0') return '0.0.0.0/0';
  const mapped = addrBook.get(lower);
  if (mapped) return mapped;
  if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(clean)) return clean;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(clean)) return `${clean}/32`;
  return '0.0.0.0/0';
}

function resolveServiceToken(
  token: string,
  svcBook: Map<string, { protocol: L4Protocol; dstPort?: number }>
): { protocol: L4Protocol; dstPort?: number } {
  const clean = stripQuotes(token).replace(/^\[|\]$/g, '').trim();
  const lower = clean.toLowerCase();
  const custom = svcBook.get(lower);
  if (custom) return custom;
  const known = WELL_KNOWN_SERVICES[lower];
  if (known) return known;
  const protoPort = lower.match(/^(tcp|udp)[/_-](\d+)$/);
  if (protoPort) {
    return { protocol: protoPort[1] as L4Protocol, dstPort: Number(protoPort[2]) };
  }
  if (/^\d+$/.test(lower)) {
    return { protocol: 'tcp', dstPort: Number(lower) };
  }
  return { protocol: 'any' };
}

export function parsePanOsAclRules(lines: string[]): AclRuleConfig[] {
  const addrBook = new Map<string, string>();
  const svcBook = new Map<string, { protocol: L4Protocol; dstPort?: number }>();
  const ruleOrder: string[] = [];
  const ruleMap = new Map<
    string,
    {
      name: string;
      action: 'allow' | 'deny';
      srcZone?: string;
      dstZone?: string;
      srcCidr: string;
      dstCidr: string;
      protocol: L4Protocol;
      dstPort?: number;
    }
  >();

  const getOrCreateRule = (name: string) => {
    let r = ruleMap.get(name);
    if (!r) {
      r = { name, action: 'allow', srcCidr: '0.0.0.0/0', dstCidr: '0.0.0.0/0', protocol: 'any' };
      ruleMap.set(name, r);
      ruleOrder.push(name);
    }
    return r;
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (!/^set\s+/i.test(line)) continue;

    const addrM = line.match(/^set\s+address\s+(?:"([^"]+)"|([^"\s]+))\s+ip-netmask\s+(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)/i);
    if (addrM) {
      const addrName = (addrM[1] ?? addrM[2]).trim();
      const cidr = addrM[3].includes('/') ? addrM[3] : `${addrM[3]}/32`;
      addrBook.set(addrName.toLowerCase(), cidr);
      continue;
    }

    const svcM = line.match(/^set\s+service\s+(?:"([^"]+)"|([^"\s]+))\s+protocol\s+(tcp|udp)\s+port\s+(\d+)/i);
    if (svcM) {
      const svcName = (svcM[1] ?? svcM[2]).trim();
      svcBook.set(svcName.toLowerCase(), {
        protocol: svcM[3].toLowerCase() as L4Protocol,
        dstPort: Number(svcM[4]),
      });
      continue;
    }

    const ruleM = line.match(/^set\s+rulebase\s+security\s+rules\s+(?:"([^"]+)"|([^"\s]+))\s+(.+)$/i);
    if (!ruleM) continue;
    const rule = getOrCreateRule((ruleM[1] ?? ruleM[2]).trim());
    const rest = ruleM[3];

    const fromM = rest.match(/\bfrom\s+(?:\[\s*)?(?:"([^"]+)"|([^\s\]]+))/i);
    const fromVal = fromM ? (fromM[1] ?? fromM[2]) : undefined;
    if (fromVal && fromVal.toLowerCase() !== 'any') rule.srcZone = stripQuotes(fromVal);
    const toM = rest.match(/\bto\s+(?:\[\s*)?(?:"([^"]+)"|([^\s\]]+))/i);
    const toVal = toM ? (toM[1] ?? toM[2]) : undefined;
    if (toVal && toVal.toLowerCase() !== 'any') rule.dstZone = stripQuotes(toVal);
    const srcM = rest.match(/\bsource\s+(?:\[\s*)?(?:"([^"]+)"|([^\s\]]+))/i);
    const srcVal = srcM ? (srcM[1] ?? srcM[2]) : undefined;
    if (srcVal) rule.srcCidr = resolveAddressToken(srcVal, addrBook);
    const dstM = rest.match(/\bdestination\s+(?:\[\s*)?(?:"([^"]+)"|([^\s\]]+))/i);
    const dstVal = dstM ? (dstM[1] ?? dstM[2]) : undefined;
    if (dstVal) rule.dstCidr = resolveAddressToken(dstVal, addrBook);
    const svcRefM = rest.match(/\bservice\s+(?:\[\s*)?(?:"([^"]+)"|([^\s\]]+))/i);
    const svcRefVal = svcRefM ? (svcRefM[1] ?? svcRefM[2]) : undefined;
    if (svcRefVal) {
      const resolved = resolveServiceToken(svcRefVal, svcBook);
      rule.protocol = resolved.protocol;
      if (resolved.dstPort !== undefined) rule.dstPort = resolved.dstPort;
    }
    const actM = rest.match(/\baction\s+(allow|deny|drop|reset-client|reset-server|reset-both)/i);
    if (actM) {
      rule.action = actM[1].toLowerCase() === 'allow' ? 'allow' : 'deny';
    }
  }

  return ruleOrder.map((name, idx) => ({
    id: `acl-pan-${Date.now()}-${idx}`,
    seq: (idx + 1) * 10,
    ...ruleMap.get(name)!,
  }));
}

export function parseFortigateAclRules(lines: string[]): AclRuleConfig[] {
  const addrBook = new Map<string, string>();
  const svcBook = new Map<string, { protocol: L4Protocol; dstPort?: number }>();
  const rules: AclRuleConfig[] = [];

  let block: '' | 'address' | 'service' | 'policy' = '';
  let curName = '';
  let curRule: Partial<AclRuleConfig> | null = null;

  const flushPolicy = () => {
    if (block === 'policy' && curRule) {
      rules.push({
        id: `acl-fgt-${Date.now()}-${rules.length}`,
        seq: (rules.length + 1) * 10,
        name: curRule.name || `policy-${curName || rules.length + 1}`,
        action: curRule.action ?? 'deny',
        srcZone: curRule.srcZone,
        dstZone: curRule.dstZone,
        srcCidr: curRule.srcCidr ?? '0.0.0.0/0',
        dstCidr: curRule.dstCidr ?? '0.0.0.0/0',
        protocol: curRule.protocol ?? 'any',
        dstPort: curRule.dstPort,
      });
      curRule = null;
    }
  };

  for (const raw of lines) {
    const t = raw.trim();
    if (!t || t.startsWith('#')) continue;
    if (/^config\s+firewall\s+address$/i.test(t)) { block = 'address'; curName = ''; continue; }
    if (/^config\s+firewall\s+service\s+custom$/i.test(t)) { block = 'service'; curName = ''; continue; }
    if (/^config\s+firewall\s+policy$/i.test(t)) { block = 'policy'; curName = ''; curRule = null; continue; }
    if (/^config\s+/i.test(t)) { flushPolicy(); block = ''; continue; }
    if (/^end$/i.test(t)) { flushPolicy(); block = ''; curName = ''; continue; }
    if (/^next$/i.test(t)) { flushPolicy(); curName = ''; continue; }

    const editM = t.match(/^edit\s+"?([^"]+)"?$/i);
    if (editM) {
      flushPolicy();
      curName = editM[1].trim();
      if (block === 'policy') {
        curRule = { name: `policy-${curName}`, action: 'deny', srcCidr: '0.0.0.0/0', dstCidr: '0.0.0.0/0', protocol: 'any' };
      }
      continue;
    }

    if (block === 'address' && curName) {
      const subMask = t.match(/^set\s+subnet\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (subMask) addrBook.set(curName.toLowerCase(), `${subMask[1]}/${maskToPrefixLenLocal(subMask[2])}`);
      const subCidr = t.match(/^set\s+subnet\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i);
      if (subCidr) addrBook.set(curName.toLowerCase(), subCidr[1]);
    } else if (block === 'service' && curName) {
      const tcpM = t.match(/^set\s+tcp-portrange\s+(\d+)/i);
      if (tcpM) svcBook.set(curName.toLowerCase(), { protocol: 'tcp', dstPort: Number(tcpM[1]) });
      const udpM = t.match(/^set\s+udp-portrange\s+(\d+)/i);
      if (udpM) svcBook.set(curName.toLowerCase(), { protocol: 'udp', dstPort: Number(udpM[1]) });
    } else if (block === 'policy' && curRule) {
      const nmM = t.match(/^set\s+name\s+"?([^"]+)"?/i);
      if (nmM) curRule.name = nmM[1].trim();
      const siM = t.match(/^set\s+srcintf\s+(?:"([^"]+)"|([^"\s]+))/i);
      const siVal = siM ? (siM[1] ?? siM[2]) : undefined;
      if (siVal && siVal.toLowerCase() !== 'any') curRule.srcZone = siVal;
      const diM = t.match(/^set\s+dstintf\s+(?:"([^"]+)"|([^"\s]+))/i);
      const diVal = diM ? (diM[1] ?? diM[2]) : undefined;
      if (diVal && diVal.toLowerCase() !== 'any') curRule.dstZone = diVal;
      const saM = t.match(/^set\s+srcaddr\s+(?:"([^"]+)"|([^"\s]+))/i);
      const saVal = saM ? (saM[1] ?? saM[2]) : undefined;
      if (saVal) curRule.srcCidr = resolveAddressToken(saVal, addrBook);
      const daM = t.match(/^set\s+dstaddr\s+(?:"([^"]+)"|([^"\s]+))/i);
      const daVal = daM ? (daM[1] ?? daM[2]) : undefined;
      if (daVal) curRule.dstCidr = resolveAddressToken(daVal, addrBook);
      const svM = t.match(/^set\s+service\s+(?:"([^"]+)"|([^"\s]+))/i);
      const svVal = svM ? (svM[1] ?? svM[2]) : undefined;
      if (svVal) {
        const res = resolveServiceToken(svVal, svcBook);
        curRule.protocol = res.protocol;
        curRule.dstPort = res.dstPort;
      }
      const acM = t.match(/^set\s+action\s+(accept|deny)/i);
      if (acM) curRule.action = acM[1].toLowerCase() === 'accept' ? 'allow' : 'deny';
    }
  }
  flushPolicy();
  return rules;
}

export function parseCiscoStyleAclRules(lines: string[]): AclRuleConfig[] {
  const rules: AclRuleConfig[] = [];
  let currentAclName: string | null = null;
  let currentAclIsStandard = false;

  const parseEndpoint = (tokens: string[], idx: number): { cidr: string; nextIdx: number } => {
    const t = (tokens[idx] ?? '').toLowerCase();
    if (t === 'any' || t === 'any4') return { cidr: '0.0.0.0/0', nextIdx: idx + 1 };
    if (t === 'host' && tokens[idx + 1]) return { cidr: `${tokens[idx + 1]}/32`, nextIdx: idx + 2 };
    if (/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(t)) return { cidr: t, nextIdx: idx + 1 };
    if (/^\d+\.\d+\.\d+\.\d+$/.test(t) && tokens[idx + 1] && /^\d+\.\d+\.\d+\.\d+$/.test(tokens[idx + 1])) {
      return { cidr: `${t}/${wildcardToPrefixLenLocal(tokens[idx + 1])}`, nextIdx: idx + 2 };
    }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(t)) return { cidr: `${t}/32`, nextIdx: idx + 1 };
    return { cidr: '0.0.0.0/0', nextIdx: idx + 1 };
  };

  const skipPortClause = (tokens: string[], idx: number): number => {
    const op = (tokens[idx] ?? '').toLowerCase();
    if (op === 'eq' || op === 'neq' || op === 'gt' || op === 'lt') return idx + 2;
    if (op === 'range') return idx + 3;
    return idx;
  };

  const parseAce = (aceText: string, aclName: string, isStandard: boolean) => {
    const tokens = aceText.trim().split(/\s+/);
    let i = 0;
    let explicitSeq: number | undefined;
    if (/^\d+$/.test(tokens[0] ?? '')) {
      explicitSeq = Number(tokens[0]);
      i = 1;
    }
    const actRaw = (tokens[i] ?? '').toLowerCase();
    if (actRaw !== 'permit' && actRaw !== 'deny') return;
    let protocol: L4Protocol = 'any';
    let src: { cidr: string; nextIdx: number };
    let dst: { cidr: string; nextIdx: number };
    let dstPort: number | undefined;
    if (isStandard) {
      src = parseEndpoint(tokens, i + 1);
      dst = { cidr: '0.0.0.0/0', nextIdx: src.nextIdx };
    } else {
      const protoRaw = (tokens[i + 1] ?? '').toLowerCase();
      protocol = protoRaw === 'tcp' || protoRaw === 'udp' || protoRaw === 'icmp' ? protoRaw : 'any';
      src = parseEndpoint(tokens, i + 2);
      const dstStart = skipPortClause(tokens, src.nextIdx);
      dst = parseEndpoint(tokens, dstStart);
      const eqIdx = tokens.findIndex((tok, k) => k >= dst.nextIdx && tok.toLowerCase() === 'eq');
      if (eqIdx >= 0 && tokens[eqIdx + 1]) {
        const resolved = resolveServiceToken(tokens[eqIdx + 1], new Map());
        dstPort = resolved.dstPort ?? (Number.isFinite(Number(tokens[eqIdx + 1])) ? Number(tokens[eqIdx + 1]) : undefined);
      }
    }
    rules.push({
      id: `acl-cisco-${Date.now()}-${rules.length}`,
      seq: explicitSeq ?? (rules.length + 1) * 10,
      name: `${aclName}-${rules.length + 1}`,
      action: actRaw === 'permit' ? 'allow' : 'deny',
      srcCidr: src.cidr,
      dstCidr: dst.cidr,
      protocol,
      dstPort,
    });
  };

  for (const raw of lines) {
    const t = raw.trim();
    if (!t || t === '!') {
      if (t === '!') {
        currentAclName = null;
        currentAclIsStandard = false;
      }
      continue;
    }
    const extAcl = t.match(/^(?:ipv4\s+access-list|ip\s+access-list(?:\s+(extended|standard))?|access-list\s+ip)\s+(\S+)/i);
    if (extAcl) {
      currentAclIsStandard = (extAcl[1] ?? '').toLowerCase() === 'standard';
      currentAclName = extAcl[2];
      continue;
    }
    const numAcl = t.match(/^access-list\s+(1\d\d|2\d\d\d)\s+((?:permit|deny)\s+.+)$/i);
    if (numAcl) {
      parseAce(numAcl[2], `ACL-${numAcl[1]}`, false);
      continue;
    }
    if (currentAclName && /^(?:\d+\s+)?(?:permit|deny)\s+/i.test(t)) {
      parseAce(t, currentAclName, currentAclIsStandard);
    } else if (/^(?:interface|router|vrf|route-map|hostname)\s+/i.test(t)) {
      currentAclName = null;
      currentAclIsStandard = false;
    }
  }
  return rules;
}

export function parseJunosAclRules(lines: string[]): AclRuleConfig[] {
  const addrBook = new Map<string, string>();
  const ruleOrder: string[] = [];
  const ruleMap = new Map<string, Omit<AclRuleConfig, 'id' | 'seq'>>();

  // Pass 1: collect address-book entries (which often appear after security policies in JunOS set output)
  for (const raw of lines) {
    const line = raw.trim();
    if (!/^set\s+security\s+/i.test(line)) continue;
    const abM = line.match(
      /^set\s+security\s+(?:address-book\s+\S+|zones\s+security-zone\s+\S+\s+address-book)\s+address\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+\/\d+)/i
    );
    if (abM) {
      addrBook.set(abM[1].toLowerCase(), abM[2]);
    }
  }

  for (const raw of lines) {
    const line = raw.trim();
    if (!/^set\s+security\s+/i.test(line)) continue;

    const polM = line.match(
      /^set\s+security\s+policies\s+from-zone\s+(\S+)\s+to-zone\s+(\S+)\s+policy\s+(\S+)\s+(match|then)\s+(.+)$/i
    );
    if (!polM) continue;
    const key = `${polM[1]}|${polM[2]}|${polM[3]}`;
    let rule = ruleMap.get(key);
    if (!rule) {
      rule = {
        name: polM[3],
        action: 'allow',
        srcZone: polM[1],
        dstZone: polM[2],
        srcCidr: '0.0.0.0/0',
        dstCidr: '0.0.0.0/0',
        protocol: 'any',
      };
      ruleMap.set(key, rule);
      ruleOrder.push(key);
    }
    const kind = polM[4].toLowerCase();
    const rest = polM[5];
    if (kind === 'match') {
      const sa = rest.match(/^source-address\s+(\S+)/i);
      if (sa) rule.srcCidr = resolveAddressToken(sa[1], addrBook);
      const da = rest.match(/^destination-address\s+(\S+)/i);
      if (da) rule.dstCidr = resolveAddressToken(da[1], addrBook);
      const app = rest.match(/^application\s+(\S+)/i);
      if (app) {
        const res = resolveServiceToken(app[1], new Map());
        rule.protocol = res.protocol;
        if (res.dstPort !== undefined) rule.dstPort = res.dstPort;
      }
    } else if (kind === 'then') {
      if (/^permit\b/i.test(rest)) rule.action = 'allow';
      else if (/^(?:deny|reject)\b/i.test(rest)) rule.action = 'deny';
    }
  }

  return ruleOrder.map((key, idx) => ({
    id: `acl-junos-${Date.now()}-${idx}`,
    seq: (idx + 1) * 10,
    ...ruleMap.get(key)!,
  }));
}

export function parseVyosAclRules(lines: string[]): AclRuleConfig[] {
  const ruleOrder: string[] = [];
  const ruleMap = new Map<string, Omit<AclRuleConfig, 'id'>>();

  for (const raw of lines) {
    const line = raw.trim().replace(/'/g, '');
    const m = line.match(
      /^set\s+firewall\s+(?:ipv4\s+)?(?:name\s+(\S+)|forward\s+filter)\s+rule\s+(\d+)\s+(.+)$/i
    );
    if (!m) continue;
    const setName = m[1] || 'FWD';
    const ruleNum = Number(m[2]);
    const key = `${setName}-${ruleNum}`;
    let rule = ruleMap.get(key);
    if (!rule) {
      rule = { seq: ruleNum, name: key, action: 'allow', srcCidr: '0.0.0.0/0', dstCidr: '0.0.0.0/0', protocol: 'any' };
      ruleMap.set(key, rule);
      ruleOrder.push(key);
    }
    const rest = m[3];
    const actM = rest.match(/^action\s+(accept|drop|reject)/i);
    if (actM) rule.action = actM[1].toLowerCase() === 'accept' ? 'allow' : 'deny';
    const srcM = rest.match(/^source\s+address\s+(\S+)/i);
    if (srcM) rule.srcCidr = resolveAddressToken(srcM[1], new Map());
    const dstM = rest.match(/^destination\s+address\s+(\S+)/i);
    if (dstM) rule.dstCidr = resolveAddressToken(dstM[1], new Map());
    const portM = rest.match(/^destination\s+port\s+(\d+)/i);
    if (portM) rule.dstPort = Number(portM[1]);
    const protoM = rest.match(/^protocol\s+(tcp_udp|tcp|udp|icmp|all)\b/i);
    if (protoM) {
      const p = protoM[1].toLowerCase();
      rule.protocol = p === 'all' || p === 'tcp_udp' ? 'any' : (p as L4Protocol);
    }
  }

  return ruleOrder.map((key, idx) => ({
    id: `acl-vyos-${Date.now()}-${idx}`,
    ...ruleMap.get(key)!,
  }));
}

export function parseMikrotikAclRules(lines: string[]): AclRuleConfig[] {
  const rules: AclRuleConfig[] = [];
  let inFilterSection = false;
  for (const raw of lines) {
    const line = raw.trim().replace(/\s*=\s*/g, '=');
    if (/^\/ip\s+firewall\s+filter$/i.test(line)) {
      inFilterSection = true;
      continue;
    }
    if (line.startsWith('/') && !/^\/ip\s+firewall\s+filter\s+add\b/i.test(line)) {
      inFilterSection = false;
      continue;
    }
    const isAdd =
      /^\/ip\s+firewall\s+filter\s+add\b/i.test(line) ||
      (inFilterSection && /^add\b/i.test(line));
    if (!isAdd) continue;
    const actM = line.match(/\baction=(\S+)/i);
    const act = (actM?.[1] ?? 'accept').toLowerCase();
    if (act !== 'accept' && act !== 'drop' && act !== 'reject') continue;
    const srcM = line.match(/\bsrc-address=(\S+)/i);
    const dstM = line.match(/\bdst-address=(\S+)/i);
    const protoM = line.match(/\bprotocol=(tcp|udp|icmp)/i);
    const portM = line.match(/\bdst-port=(\d+)/i);
    const cmtM = line.match(/\bcomment=(?:"([^"]+)"|(\S+))/i);
    rules.push({
      id: `acl-mt-${Date.now()}-${rules.length}`,
      seq: (rules.length + 1) * 10,
      name: (cmtM?.[1] ?? cmtM?.[2])?.trim() || `mt-filter-${rules.length + 1}`,
      action: act === 'accept' ? 'allow' : 'deny',
      srcCidr: srcM ? resolveAddressToken(srcM[1], new Map()) : '0.0.0.0/0',
      dstCidr: dstM ? resolveAddressToken(dstM[1], new Map()) : '0.0.0.0/0',
      protocol: (protoM?.[1]?.toLowerCase() as L4Protocol) ?? 'any',
      dstPort: portM ? Number(portM[1]) : undefined,
    });
  }
  return rules;
}

export function parseCheckpointGaiaAclRules(lines: string[]): AclRuleConfig[] {
  const addrBook = new Map<string, string>();
  const rules: AclRuleConfig[] = [];

  for (const raw of lines) {
    const line = raw.trim();
    const hostM = line.match(/\badd\s+host\s+name\s+(?:"([^"]+)"|([^"\s]+))\s+ip-address\s+(\d+\.\d+\.\d+\.\d+)/i);
    if (hostM) {
      addrBook.set((hostM[1] ?? hostM[2]).toLowerCase(), `${hostM[3]}/32`);
      continue;
    }
    const netM = line.match(/\badd\s+network\s+name\s+(?:"([^"]+)"|([^"\s]+))\s+subnet\s+(\d+\.\d+\.\d+\.\d+)\s+mask-length\s+(\d+)/i);
    if (netM) {
      addrBook.set((netM[1] ?? netM[2]).toLowerCase(), `${netM[3]}/${netM[4]}`);
      continue;
    }
    if (!/\badd\s+access-rule\b/i.test(line)) continue;
    const nameM = line.match(/\bname\s+(?:"([^"]+)"|([^"\s]+))/i);
    const srcM = line.match(/\bsource\s+(?:"([^"]+)"|([^"\s]+))/i);
    const dstM = line.match(/\bdestination\s+(?:"([^"]+)"|([^"\s]+))/i);
    const svcM = line.match(/\bservice\s+(?:"([^"]+)"|([^"\s]+))/i);
    const actM = line.match(/\baction\s+"?(accept|drop|reject)"?/i);
    const svcVal = svcM ? (svcM[1] ?? svcM[2]) : undefined;
    const svc = svcVal ? resolveServiceToken(svcVal, new Map()) : { protocol: 'any' as L4Protocol };
    rules.push({
      id: `acl-cp-${Date.now()}-${rules.length}`,
      seq: (rules.length + 1) * 10,
      name: (nameM ? (nameM[1] ?? nameM[2]) : undefined) || `cp-rule-${rules.length + 1}`,
      action: (actM?.[1] ?? 'accept').toLowerCase() === 'accept' ? 'allow' : 'deny',
      srcCidr: srcM ? resolveAddressToken(srcM[1] ?? srcM[2], addrBook) : '0.0.0.0/0',
      dstCidr: dstM ? resolveAddressToken(dstM[1] ?? dstM[2], addrBook) : '0.0.0.0/0',
      protocol: svc.protocol,
      dstPort: svc.dstPort,
    });
  }
  return rules;
}

/**
 * Cloud firewall / security rule importer supporting:
 * - AWS Terraform (`aws_network_acl_rule`, `aws_security_group_rule`)
 * - Azure Terraform & CLI (`azurerm_network_security_rule`, `az network nsg rule create`)
 * - GCP Terraform & CLI (`google_compute_firewall`, `gcloud compute firewall-rules create`)
 */
export function parseCloudAclRules(lines: string[]): AclRuleConfig[] {
  const rules: AclRuleConfig[] = [];
  let blockKind: 'aws-nacl' | 'aws-sg' | 'azure-nsg' | 'gcp-fw' | null = null;
  let blockName = '';
  let seq = 10;
  let action: 'allow' | 'deny' = 'allow';
  let protocol: L4Protocol = 'any';
  let srcCidr = '0.0.0.0/0';
  let dstCidr = '0.0.0.0/0';
  let awsCidrRaw: string | undefined;
  let isAwsEgress = false;
  let dstPort: number | undefined;
  let toPort: number | undefined;
  let braceDepth = 0;

  const flushBlock = () => {
    if (!blockKind) return;
    let finalSrc = srcCidr;
    let finalDst = dstCidr;
    if ((blockKind === 'aws-nacl' || blockKind === 'aws-sg') && awsCidrRaw) {
      if (isAwsEgress) finalDst = awsCidrRaw;
      else finalSrc = awsCidrRaw;
    }
    const finalDstPort =
      dstPort === 0 && (protocol === 'any' || toPort === 0 || toPort === 65535)
        ? undefined
        : dstPort;
    rules.push({
      id: `acl-cloud-${Date.now()}-${rules.length}`,
      seq,
      name: blockName || `cloud-rule-${rules.length + 1}`,
      action,
      srcCidr: finalSrc,
      dstCidr: finalDst,
      protocol,
      ...(finalDstPort !== undefined ? { dstPort: finalDstPort } : {}),
    });
    blockKind = null;
    blockName = '';
    action = 'allow';
    protocol = 'any';
    srcCidr = '0.0.0.0/0';
    dstCidr = '0.0.0.0/0';
    awsCidrRaw = undefined;
    isAwsEgress = false;
    dstPort = undefined;
    toPort = undefined;
    braceDepth = 0;
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    // CLI single-line forms: Azure `az network nsg rule create`
    if (/^az\s+network\s+nsg\s+rule\s+create\b/i.test(line)) {
      const nameM = line.match(/--name\s+"?([^"\s]+)"?/i);
      const prioM = line.match(/--priority\s+(\d+)/i);
      const accM = line.match(/--access\s+"?(Allow|Deny)"?/i);
      const protoM = line.match(/--protocol\s+"?([^"\s]+)"?/i);
      const srcM = line.match(/--source-address-prefix(?:es)?\s+"?([^"\s]+)"?/i);
      const dstM = line.match(/--destination-address-prefix(?:es)?\s+"?([^"\s]+)"?/i);
      const portM = line.match(/--destination-port-ranges?\s+"?(\d+)/i);
      const p = (protoM?.[1] ?? '*').toLowerCase();
      rules.push({
        id: `acl-az-${Date.now()}-${rules.length}`,
        seq: prioM ? Number(prioM[1]) : (rules.length + 1) * 10,
        name: nameM?.[1] || `az-nsg-${rules.length + 1}`,
        action: (accM?.[1] ?? 'Allow').toLowerCase() === 'deny' ? 'deny' : 'allow',
        srcCidr: !srcM || srcM[1] === '*' ? '0.0.0.0/0' : srcM[1],
        dstCidr: !dstM || dstM[1] === '*' ? '0.0.0.0/0' : dstM[1],
        protocol: p === 'tcp' || p === 'udp' || p === 'icmp' ? (p as L4Protocol) : 'any',
        ...(portM ? { dstPort: Number(portM[1]) } : {}),
      });
      continue;
    }

    // CLI single-line forms: GCP `gcloud compute firewall-rules create`
    if (/^gcloud\s+compute\s+firewall-rules\s+create\b/i.test(line)) {
      const nameM = line.match(/firewall-rules\s+create\s+"?([^"\s]+)"?/i);
      const prioM = line.match(/--priority[=\s]+(\d+)/i);
      const allowM = line.match(/--allow[=\s]+"?([^"\s]+)"?/i);
      const denyM = line.match(/--rules[=\s]+"?([^"\s]+)"?/i);
      const actM = line.match(/--action[=\s]+"?(ALLOW|DENY)"?/i);
      const srcM = line.match(/--source-ranges[=\s]+"?([^"\s,]+)"?/i);
      const tagM = line.match(/--target-tags[=\s]+"?([^"\s,]+)"?/i);
      const ruleToken = (allowM?.[1] ?? denyM?.[1] ?? 'all').toLowerCase();
      const [protoPart, portPart] = ruleToken.split(':');
      const parsedProto: L4Protocol =
        protoPart === 'tcp' || protoPart === 'udp' || protoPart === 'icmp' ? (protoPart as L4Protocol) : 'any';
      const parsedPort = portPart && /^\d+/.test(portPart) ? Number(portPart.match(/^\d+/)![0]) : undefined;
      rules.push({
        id: `acl-gcp-${Date.now()}-${rules.length}`,
        seq: prioM ? Number(prioM[1]) : (rules.length + 1) * 10,
        name: nameM?.[1] || `gcp-fw-${rules.length + 1}`,
        action: (actM?.[1] ?? 'ALLOW').toLowerCase() === 'deny' ? 'deny' : 'allow',
        srcCidr: srcM?.[1] || '0.0.0.0/0',
        dstCidr: '0.0.0.0/0',
        protocol: parsedProto,
        ...(parsedPort !== undefined ? { dstPort: parsedPort } : {}),
        ...(tagM ? { networkTag: tagM[1] } : {}),
      });
      continue;
    }

    // Terraform HCL resource blocks
    const resM = line.match(/^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/);
    if (resM) {
      flushBlock();
      const rType = resM[1].toLowerCase();
      if (rType === 'aws_network_acl_rule') blockKind = 'aws-nacl';
      else if (rType === 'aws_security_group_rule') blockKind = 'aws-sg';
      else if (rType === 'azurerm_network_security_rule') blockKind = 'azure-nsg';
      else if (rType === 'google_compute_firewall') blockKind = 'gcp-fw';
      if (blockKind) {
        blockName = resM[2];
        seq = (rules.length + 1) * 10;
        braceDepth = 1;
      }
      continue;
    }

    if (!blockKind) continue;

    if (/^deny\s*\{/i.test(line)) {
      action = 'deny';
    } else if (/^allow\s*\{/i.test(line)) {
      action = 'allow';
    }
    if (line.includes('{')) braceDepth += (line.match(/\{/g) || []).length;

    const nameEq = line.match(/\bname\s*=\s*"([^"]+)"/);
    if (nameEq) blockName = nameEq[1];
    const seqEq = line.match(/\b(?:rule_number|priority)\s*=\s*(\d+)/);
    if (seqEq) seq = Number(seqEq[1]);
    const actEq = line.match(/\b(?:rule_action|access)\s*=\s*"([^"]+)"/i);
    if (actEq) action = actEq[1].toLowerCase() === 'deny' ? 'deny' : 'allow';
    if (/\begress\s*=\s*true\b/i.test(line) || /\btype\s*=\s*"egress"/i.test(line)) {
      isAwsEgress = true;
    }
    const protoEq = line.match(/\bprotocol\s*=\s*"([^"]+)"/i);
    if (protoEq) {
      const p = protoEq[1].toLowerCase();
      if (p === 'tcp' || p === '6') protocol = 'tcp';
      else if (p === 'udp' || p === '17') protocol = 'udp';
      else if (p === 'icmp' || p === '1') protocol = 'icmp';
      else protocol = 'any';
    }
    const awsCidrEq = line.match(/\bcidr_block\s*=\s*"([^"]+)"/i);
    if (awsCidrEq) awsCidrRaw = awsCidrEq[1];
    const awsCidrArrEq = line.match(/\bcidr_blocks\s*=\s*\[\s*"([^"]+)"/i);
    if (awsCidrArrEq) awsCidrRaw = awsCidrArrEq[1];
    const srcEq = line.match(/\bsource_address_prefix\s*=\s*"([^"]+)"/i);
    if (srcEq) srcCidr = srcEq[1] === '*' ? '0.0.0.0/0' : srcEq[1];
    const srcArrEq = line.match(/\bsource_ranges\s*=\s*\[\s*"([^"]+)"/i);
    if (srcArrEq) srcCidr = srcArrEq[1];
    const dstEq = line.match(/\bdestination_address_prefix\s*=\s*"([^"]+)"/i);
    if (dstEq) dstCidr = dstEq[1] === '*' ? '0.0.0.0/0' : dstEq[1];
    const portEq = line.match(/\b(?:from_port|destination_port_range)\s*=\s*"?(\d+)"?/i);
    if (portEq) dstPort = Number(portEq[1]);
    const toPortEq = line.match(/\bto_port\s*=\s*"?(\d+)"?/i);
    if (toPortEq) toPort = Number(toPortEq[1]);
    const portsArrEq = line.match(/\bports\s*=\s*\[\s*"(\d+)/i);
    if (portsArrEq) dstPort = Number(portsArrEq[1]);

    if (line.includes('}')) {
      braceDepth -= (line.match(/\}/g) || []).length;
      if (braceDepth <= 0) flushBlock();
    }
  }
  flushBlock();
  return rules;
}
