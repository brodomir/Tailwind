import { SimulationResult, TopologyState } from '../types/network';
import { formatPrimaryCli, formatSecondaryCli } from './formatters';

function yamlScalar(val: unknown): string {
  if (val === null || val === undefined) return 'null';
  if (typeof val === 'number') return Number.isFinite(val) ? String(val) : 'null';
  if (typeof val === 'boolean') return String(val);
  const str = String(val);
  if (
    str === '' ||
    /^\s|\s$/.test(str) ||
    /^[-?~]/.test(str) ||
    /[:#{}[\],&*!|>'"%@`\n]/.test(str) ||
    /^(true|false|null|yes|no|on|off|~)$/i.test(str) ||
    /^[+-]?\d+(\.\d+)?$/.test(str)
  ) {
    return JSON.stringify(str);
  }
  return str;
}

function toYaml(value: unknown, indent = 0): string {
  const pad = ' '.repeat(indent);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return value
      .map((item) => {
        if (item !== null && typeof item === 'object') {
          const inner = toYaml(item, indent + 2).trimStart();
          return `${pad}- ${inner}`;
        }
        return `${pad}- ${yamlScalar(item)}`;
      })
      .join('\n');
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(
      ([, v]) => v !== undefined
    );
    if (entries.length === 0) return '{}';
    return entries
      .map(([k, v]) => {
        if (Array.isArray(v)) {
          if (v.length === 0) return `${pad}${k}: []`;
          return `${pad}${k}:\n${toYaml(v, indent + 2)}`;
        }
        if (v !== null && typeof v === 'object') {
          const objEntries = Object.entries(v as Record<string, unknown>).filter(
            ([, ov]) => ov !== undefined
          );
          if (objEntries.length === 0) return `${pad}${k}: {}`;
          return `${pad}${k}:\n${toYaml(v, indent + 2)}`;
        }
        return `${pad}${k}: ${yamlScalar(v)}`;
      })
      .join('\n');
  }
  return `${pad}${yamlScalar(value)}`;
}

export function topologyToYaml(topology: TopologyState): string {
  return `# Multi-Vendor Control-Plane & RIB Simulator Topology\n${toYaml(topology)}\n`;
}

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function createZipBlob(files: { name: string; content: string }[]): Blob {
  const encoder = new TextEncoder();
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let offset = 0;

  for (const file of files) {
    const nameBytes = encoder.encode(file.name);
    const dataBytes = encoder.encode(file.content);
    const crc = crc32(dataBytes);

    const local = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(8, 0, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, dataBytes.length, true);
    lv.setUint32(22, dataBytes.length, true);
    lv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);

    localParts.push(local, dataBytes);

    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, dataBytes.length, true);
    cv.setUint32(24, dataBytes.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, offset, true);
    central.set(nameBytes, 46);
    centralParts.push(central);

    offset += local.length + dataBytes.length;
  }

  const centralSize = centralParts.reduce((sum, c) => sum + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, files.length, true);
  ev.setUint16(10, files.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, offset, true);

  return new Blob([...localParts, ...centralParts, eocd] as BlobPart[], {
    type: 'application/zip',
  });
}

export function buildAutomationBundleZip(
  topology: TopologyState,
  simResult: SimulationResult
): Blob {
  const files: { name: string; content: string }[] = [
    { name: 'topology.yaml', content: topologyToYaml(topology) },
    { name: 'simulation-result.json', content: JSON.stringify(simResult, null, 2) },
  ];

  const usedNames = new Set<string>();
  for (const node of topology.nodes) {
    const res = simResult.nodes[node.id];
    if (!res) continue;
    const baseName = node.hostname.replace(/[^a-zA-Z0-9._-]/g, '_') || node.id;
    let safeName = baseName;
    let suffix = 1;
    while (usedNames.has(safeName)) {
      safeName = `${baseName}-${suffix++}`;
    }
    usedNames.add(safeName);
    files.push({
      name: `cli/${safeName}-route.txt`,
      content: formatPrimaryCli(node, res),
    });
    const sec = formatSecondaryCli(node, res);
    if (sec) {
      files.push({
        name: `cli/${safeName}-fib.txt`,
        content: sec,
      });
    }
    files.push({
      name: `fixtures/${safeName}-rib.json`,
      content: JSON.stringify(res, null, 2),
    });
  }

  return createZipBlob(files);
}
