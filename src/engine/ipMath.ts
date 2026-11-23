export interface ParsedCidr {
  ip: string;
  ipUint32: number;
  network: string;
  networkUint32: number;
  prefixLen: number;
  maskUint32: number;
}

export function isValidIpv4(ip: string): boolean {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    if (num < 0 || num > 255) return false;
  }
  return true;
}

export function ipToUint32(ip: string): number {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return 0;
  return (
    ((Number(parts[0]) << 24) |
      (Number(parts[1]) << 16) |
      (Number(parts[2]) << 8) |
      Number(parts[3])) >>>
    0
  );
}

export function uint32ToIp(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join('.');
}

export function prefixMask(prefixLen: number): number {
  if (prefixLen <= 0) return 0;
  if (prefixLen >= 32) return 0xffffffff >>> 0;
  return (0xffffffff << (32 - prefixLen)) >>> 0;
}

export function parseCidr(cidr: string): ParsedCidr | null {
  const trimmed = cidr.trim();
  const slashIdx = trimmed.indexOf('/');
  if (slashIdx === -1) return null;
  const ipStr = trimmed.slice(0, slashIdx);
  const lenStr = trimmed.slice(slashIdx + 1);
  if (!isValidIpv4(ipStr) || !/^\d{1,2}$/.test(lenStr)) return null;
  const prefixLen = Number(lenStr);
  if (prefixLen < 0 || prefixLen > 32) return null;

  const ipUint32 = ipToUint32(ipStr);
  const maskUint32 = prefixMask(prefixLen);
  const networkUint32 = (ipUint32 & maskUint32) >>> 0;

  return {
    ip: ipStr,
    ipUint32,
    network: uint32ToIp(networkUint32),
    networkUint32,
    prefixLen,
    maskUint32,
  };
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  if (!isValidIpv4(ip)) return false;
  const parsed = parseCidr(cidr);
  if (!parsed) return false;
  const ipVal = ipToUint32(ip);
  return ((ipVal & parsed.maskUint32) >>> 0) === parsed.networkUint32;
}

export interface ParsedCidr6 {
  ip: string;
  ipBigInt: bigint;
  network: string;
  networkBigInt: bigint;
  prefixLen: number;
  maskBigInt: bigint;
}

const MASK_128 = (1n << 128n) - 1n;

export function expandIpv6(ip: string): string[] | null {
  const trimmed = ip.trim().toLowerCase();
  if (!trimmed || trimmed.includes('.')) return null;
  const parts = trimmed.split('::');
  if (parts.length > 2) return null;

  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (parts.length === 1 && missing !== 0) return null;
  if (parts.length === 2 && missing < 1) return null;

  const full = [...left, ...Array(missing).fill('0'), ...right];
  if (full.length !== 8) return null;
  for (const h of full) {
    if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
  }
  return full;
}

export function isValidIpv6(ip: string): boolean {
  return expandIpv6(ip) !== null;
}

export function ip6ToBigInt(ip: string): bigint {
  const hextets = expandIpv6(ip);
  if (!hextets) return 0n;
  let val = 0n;
  for (const h of hextets) {
    val = (val << 16n) | BigInt(parseInt(h, 16));
  }
  return val;
}

export function bigIntToIp6(val: bigint): string {
  const groups: string[] = [];
  for (let i = 7; i >= 0; i--) {
    const seg = Number((val >> BigInt(i * 16)) & 0xffffn);
    groups.push(seg.toString(16));
  }
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === '0') {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return groups.join(':');
  const head = groups.slice(0, bestStart).join(':');
  const tail = groups.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

export function prefixMask6(prefixLen: number): bigint {
  if (prefixLen <= 0) return 0n;
  if (prefixLen >= 128) return MASK_128;
  return (MASK_128 << BigInt(128 - prefixLen)) & MASK_128;
}

export function parseCidr6(cidr: string): ParsedCidr6 | null {
  const trimmed = cidr.trim();
  const slashIdx = trimmed.indexOf('/');
  if (slashIdx === -1) return null;
  const ipStr = trimmed.slice(0, slashIdx);
  const lenStr = trimmed.slice(slashIdx + 1);
  if (!isValidIpv6(ipStr) || !/^\d{1,3}$/.test(lenStr)) return null;
  const prefixLen = Number(lenStr);
  if (prefixLen < 0 || prefixLen > 128) return null;

  const ipBigInt = ip6ToBigInt(ipStr);
  const maskBigInt = prefixMask6(prefixLen);
  const networkBigInt = ipBigInt & maskBigInt;

  return {
    ip: bigIntToIp6(ipBigInt),
    ipBigInt,
    network: bigIntToIp6(networkBigInt),
    networkBigInt,
    prefixLen,
    maskBigInt,
  };
}

export function isIp6InCidr(ip: string, cidr: string): boolean {
  if (!isValidIpv6(ip)) return false;
  const parsed = parseCidr6(cidr);
  if (!parsed) return false;
  return (ip6ToBigInt(ip) & parsed.maskBigInt) === parsed.networkBigInt;
}

export function detectAddressFamily(ipOrCidr: string): 4 | 6 | null {
  const base = ipOrCidr.split('/')[0];
  if (isValidIpv4(base)) return 4;
  if (isValidIpv6(base)) return 6;
  return null;
}

