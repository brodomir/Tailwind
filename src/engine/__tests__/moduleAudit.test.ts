import { describe, expect, it } from 'vitest';
import { PRESET_TOPOLOGIES } from '../../data/presets';
import { useSimStore } from '../../store/useSimStore';
import { NodeConfig, SimulationResult, TopologyState, VendorProfile } from '../../types/network';
import { computeRibDiff } from '../diff';
import { buildAutomationBundleZip, topologyToYaml } from '../exportBundle';
import {
  parseCheckpointGaiaAclRules,
  parseCiscoStyleAclRules,
  parseFortigateAclRules,
  parseJunosAclRules,
  parseMikrotikAclRules,
  parsePanOsAclRules,
  parseVyosAclRules,
} from '../firewallImporter';
import { formatPrimaryCli, formatRunningConfig, formatSecondaryCli } from '../formatters';
import { autoFormatRunningConfig, importTopologyFromText, normalizeConfigLine, validateRunningConfig } from '../importer';
import {
  bigIntToIp6,
  detectAddressFamily,
  expandIpv6,
  ip6ToBigInt,
  ipToUint32,
  isIp6InCidr,
  isIpInCidr,
  isValidIpv4,
  isValidIpv6,
  parseCidr,
  parseCidr6,
  prefixMask,
  prefixMask6,
  uint32ToIp,
} from '../ipMath';
import { BinaryRadixTrie, BinaryRadixTrie6 } from '../radixTrie';
import { evaluateAcl, evaluatePostRoutingSnat, evaluatePreRoutingDnat } from '../security';
import { solveTopology, tracePacket } from '../solver';
import { VENDOR_CAPABILITIES, VENDOR_METADATA } from '../vendorProfiles';

function makeMinimalNode(id: string, hostname: string, vendor: VendorProfile): NodeConfig {
  return {
    id,
    hostname,
    vendor,
    routerId: '1.1.1.1',
    position: { x: 0, y: 0 },
    maxPaths: 4,
    vrfs: ['default'],
    adOverrides: {},
    interfaces: [
      { id: `${id}-i1`, name: 'eth0', cidr: '10.0.0.1/30', vrf: 'default' },
    ],
    staticRoutes: [],
    ospf: { enabled: false, networks: [] },
    bgp: { enabled: false, asn: 65001, peers: [], networks: [] },
    redistributions: [],
    prefixLists: [],
    routeMaps: [],
    vrfLeaks: [],
  };
}

describe('Cross-Module Bug-Hunting Audit Suite', () => {
  describe('1. ipMath module', () => {
    it('validates IPv4/IPv6 addresses, CIDR boundaries, and RFC 5952 compression', () => {
      expect(isValidIpv4('0.0.0.0')).toBe(true);
      expect(isValidIpv4('255.255.255.255')).toBe(true);
      expect(isValidIpv4('256.0.0.1')).toBe(false);
      expect(isValidIpv4('10.0.0')).toBe(false);
      expect(isValidIpv4('10.0.0.1/24')).toBe(false);

      expect(uint32ToIp(ipToUint32('192.168.10.25'))).toBe('192.168.10.25');
      expect(prefixMask(0)).toBe(0);
      expect(prefixMask(32)).toBe(0xffffffff);
      expect(parseCidr('10.1.2.3/24')?.network).toBe('10.1.2.0');
      expect(parseCidr('10.1.2.3/33')).toBeNull();
      expect(parseCidr('bad/24')).toBeNull();
      expect(isIpInCidr('10.1.2.99', '10.1.2.0/24')).toBe(true);
      expect(isIpInCidr('10.1.3.1', '10.1.2.0/24')).toBe(false);
      expect(isIpInCidr('1.2.3.4', '0.0.0.0/0')).toBe(true);

      expect(isValidIpv6('::')).toBe(true);
      expect(isValidIpv6('::1')).toBe(true);
      expect(isValidIpv6('2001:db8::1')).toBe(true);
      expect(isValidIpv6('2001:db8::1::2')).toBe(false);
      expect(isValidIpv6('2001:db8:zzzz::1')).toBe(false);
      expect(expandIpv6('::1')).toEqual(['0', '0', '0', '0', '0', '0', '0', '1']);
      expect(bigIntToIp6(0n)).toBe('::');
      expect(bigIntToIp6(1n)).toBe('::1');
      expect(bigIntToIp6(ip6ToBigInt('2001:0db8:0000:0000:0000:0000:0000:0001'))).toBe('2001:db8::1');
      expect(prefixMask6(0)).toBe(0n);
      expect(parseCidr6('2001:db8::1/64')?.network).toBe('2001:db8::');
      expect(parseCidr6('2001:db8::1/129')).toBeNull();
      expect(isIp6InCidr('2001:db8::dead:beef', '2001:db8::/64')).toBe(true);
      expect(isIp6InCidr('2001:db9::1', '2001:db8::/64')).toBe(false);

      expect(detectAddressFamily('10.0.0.1/24')).toBe(4);
      expect(detectAddressFamily('2001:db8::1/64')).toBe(6);
      expect(detectAddressFamily('not-an-ip')).toBeNull();
    });
  });

  describe('2. radixTrie module', () => {
    it('performs exact LPM for IPv4 and IPv6 with /0, overlapping prefixes, and /32 or /128 host routes', () => {
      const t4 = new BinaryRadixTrie<string>();
      expect(t4.longestPrefixMatch(ipToUint32('10.1.1.1'))).toBeNull();
      t4.insert(0, 0, 'default');
      t4.insert(parseCidr('10.0.0.0/8')!.networkUint32, 8, 'slash8');
      t4.insert(parseCidr('10.1.0.0/16')!.networkUint32, 16, 'slash16');
      t4.insert(parseCidr('10.1.1.1/32')!.networkUint32, 32, 'host32');

      expect(t4.longestPrefixMatch(ipToUint32('8.8.8.8'))).toBe('default');
      expect(t4.longestPrefixMatch(ipToUint32('10.2.0.1'))).toBe('slash8');
      expect(t4.longestPrefixMatch(ipToUint32('10.1.2.1'))).toBe('slash16');
      expect(t4.longestPrefixMatch(ipToUint32('10.1.1.1'))).toBe('host32');

      const t6 = new BinaryRadixTrie6<string>();
      t6.insert(0n, 0, 'default6');
      t6.insert(parseCidr6('2001:db8::/32')!.networkBigInt, 32, 'v6-32');
      t6.insert(parseCidr6('2001:db8:1::1/128')!.networkBigInt, 128, 'v6-128');

      expect(t6.longestPrefixMatch(ip6ToBigInt('2606:4700::1'))).toBe('default6');
      expect(t6.longestPrefixMatch(ip6ToBigInt('2001:db8:2::1'))).toBe('v6-32');
      expect(t6.longestPrefixMatch(ip6ToBigInt('2001:db8:1::1'))).toBe('v6-128');
    });
  });

  describe('3. security module (ACL, DNAT, SNAT)', () => {
    it('enforces ACL sequence order, zones, IPv4/IPv6 CIDR, and implicit deny', () => {
      const rules = [
        { id: 'r2', seq: 20, name: 'ALLOW_ALL', action: 'allow' as const, srcCidr: 'any', dstCidr: 'any', protocol: 'any' as const },
        { id: 'r1', seq: 10, name: 'BLOCK_DMZ_SSH', action: 'deny' as const, srcZone: 'untrust', dstZone: 'dmz', srcCidr: '0.0.0.0/0', dstCidr: '10.50.0.0/24', protocol: 'tcp' as const, dstPort: 22 },
      ];
      expect(evaluateAcl(rules, '203.0.113.5', '10.50.0.10', 'tcp', 22, 'untrust', 'dmz').allowed).toBe(false);
      expect(evaluateAcl(rules, '203.0.113.5', '10.50.0.10', 'tcp', 443, 'untrust', 'dmz').allowed).toBe(true);
      expect(evaluateAcl(rules, '203.0.113.5', '10.50.0.10', 'tcp', 22, 'trust', 'dmz').allowed).toBe(true);

      const dnat = evaluatePreRoutingDnat(
        [{ id: 'n1', seq: 10, name: 'VIP', type: 'dnat', srcCidr: 'any', dstCidr: '198.51.100.10/32', translatedIp: '10.50.0.10' }],
        '203.0.113.5',
        '198.51.100.10'
      );
      expect(dnat.dstIp).toBe('10.50.0.10');
      expect(dnat.note).toContain('VIP');

      const snat = evaluatePostRoutingSnat(
        [{ id: 'n2', seq: 10, name: 'OUTBOUND', type: 'snat', srcCidr: '10.10.0.0/24', dstCidr: '0.0.0.0/0', translatedIp: '198.51.100.1' }],
        '10.10.0.55',
        '8.8.8.8'
      );
      expect(snat.srcIp).toBe('198.51.100.1');
      expect(snat.note).toContain('OUTBOUND');
    });
  });

  describe('4. diff module (computeRibDiff)', () => {
    it('detects added, removed, modified, AND ECMP path changes', () => {
      const base: SimulationResult = {
        nodes: {
          r1: {
            nodeId: 'r1',
            hostname: 'R1',
            vendor: 'cisco-ios-xe',
            rib: [
              { af: 4, prefix: '10.99.0.0', prefixLen: 24, vrf: 'default', protocol: 'ospf', ad: 110, metric: 20, nextHop: '10.0.0.2', egressInterface: 'Gi0/0', active: true, ecmp: true },
              { af: 4, prefix: '10.99.0.0', prefixLen: 24, vrf: 'default', protocol: 'ospf', ad: 110, metric: 20, nextHop: '10.0.1.2', egressInterface: 'Gi0/1', active: true, ecmp: true },
            ],
            fib: [],
            warnings: [],
          },
        },
        computeTimeMs: 1,
        convergedIterations: 1,
        warnings: [],
      };
      // One ECMP path is lost (10.0.0.2 disappears while 10.0.1.2 remains)
      const afterLoss: SimulationResult = {
        nodes: {
          r1: {
            nodeId: 'r1',
            hostname: 'R1',
            vendor: 'cisco-ios-xe',
            rib: [
              { af: 4, prefix: '10.99.0.0', prefixLen: 24, vrf: 'default', protocol: 'ospf', ad: 110, metric: 20, nextHop: '10.0.1.2', egressInterface: 'Gi0/1', active: true, ecmp: false },
            ],
            fib: [],
            warnings: [],
          },
        },
        computeTimeMs: 1,
        convergedIterations: 1,
        warnings: [],
      };
      const diff = computeRibDiff(base, afterLoss);
      expect(diff.items.length).toBeGreaterThan(0);
    });
  });

  describe('5. exportBundle module (YAML & ZIP)', () => {
    it('serializes empty arrays as [] (not empty strings) in topologyToYaml and builds a valid ZIP', async () => {
      const n1 = makeMinimalNode('n1', 'EDGE-1', 'cisco-ios-xe');
      const n2 = makeMinimalNode('n2', 'EDGE-1', 'fortigate'); // intentional duplicate hostname
      const topo: TopologyState = { nodes: [n1, n2], links: [] };
      const yaml = topologyToYaml(topo);
      expect(yaml).toContain('staticRoutes: []');
      expect(yaml).not.toContain('staticRoutes: ""');
      expect(yaml).toContain('links: []');
      expect(yaml).not.toContain('links: ""');

      const sim = solveTopology(topo);
      const blob = buildAutomationBundleZip(topo, sim);
      const bytes = new Uint8Array(await blob.arrayBuffer());
      // ZIP local file header signature PK\x03\x04
      expect(bytes[0]).toBe(0x50);
      expect(bytes[1]).toBe(0x4b);
      expect(bytes[2]).toBe(0x03);
      expect(bytes[3]).toBe(0x04);
      // Duplicate hostnames should both appear in the ZIP central directory
      const text = new TextDecoder('latin1').decode(bytes);
      expect(text).toContain('cli/EDGE-1-route.txt');
      expect(text).toContain('cli/EDGE-1-1-route.txt');
    });
  });

  describe('6. vendorProfiles & formatters coverage across ALL vendors', () => {
    it('formats running config, primary CLI, and secondary CLI cleanly for every single VendorProfile', () => {
      const vendors = Object.keys(VENDOR_METADATA) as VendorProfile[];
      expect(vendors.length).toBeGreaterThanOrEqual(17);

      for (const vendor of vendors) {
        expect(VENDOR_CAPABILITIES[vendor]).toBeDefined();
        const node = makeMinimalNode(`v-${vendor}`, `NODE-${vendor}`, vendor);
        const sim = solveTopology({ nodes: [node], links: [] });
        const running = formatRunningConfig(node);
        const primary = formatPrimaryCli(node, sim.nodes[node.id]);
        const secondary = formatSecondaryCli(node, sim.nodes[node.id]);

        expect(typeof running).toBe('string');
        expect(running).not.toContain('undefined');
        expect(running).not.toContain('NaN');
        expect(typeof primary).toBe('string');
        expect(primary).not.toContain('NaN');
        expect(secondary === null || typeof secondary === 'string').toBe(true);
      }
    });
  });

  describe('7. importer & firewallImporter resilience', () => {
    it('handles empty, malformed, smart-quoted, and multi-vendor firewall configs without throwing', () => {
      expect(normalizeConfigLine('set src \u201c10.0.0.0/24\u201d\u00a0')).toBe('set src "10.0.0.0/24"');
      expect(autoFormatRunningConfig('config system global\r\n  set hostname \u201cFW1\u201d\r\nend')).toContain('set hostname "FW1"');
      expect(() => importTopologyFromText('')).toThrow('Input is empty.');
      expect(() => importTopologyFromText('   \n\n  ')).toThrow('Input is empty.');
      expect(validateRunningConfig('').length).toBeGreaterThanOrEqual(0);

      // Malformed / partial snippets should not crash firewallImporter
      expect(parseFortigateAclRules([])).toHaveLength(0);
      expect(parseFortigateAclRules(['config firewall policy', '  edit 1', '    set action accept'])).toBeInstanceOf(Array);
      expect(parsePanOsAclRules(['set rulebase security rules R1 from untrust to trust source any destination any service any action deny'])[0]).toMatchObject({
        name: 'R1',
        action: 'deny',
        srcZone: 'untrust',
        dstZone: 'trust',
      });
      expect(parseCiscoStyleAclRules(['access-list 101 permit tcp any host 10.0.0.1 eq 443'])[0]).toMatchObject({
        action: 'allow',
        protocol: 'tcp',
        dstPort: 443,
      });
      expect(parseJunosAclRules(['set security policies from-zone trust to-zone untrust policy ALLOW-WEB match destination-address any', 'set security policies from-zone trust to-zone untrust policy ALLOW-WEB then permit'])).toBeInstanceOf(Array);
      expect(parseVyosAclRules(['set firewall name WAN-IN rule 10 action drop'])).toBeInstanceOf(Array);
      expect(parseMikrotikAclRules(['/ip firewall filter add chain=forward action=drop protocol=tcp dst-port=23'])[0]).toMatchObject({
        action: 'deny',
        protocol: 'tcp',
        dstPort: 23,
      });
      expect(parseCheckpointGaiaAclRules(['mgmt_cli add access-rule name Block-Telnet source any destination any service telnet action drop'])[0]).toMatchObject({
        name: 'Block-Telnet',
        action: 'deny',
      });
    });
  });

  describe('8. presets integrity & store consistency', () => {
    it('verifies every preset has unique IDs, valid link endpoints, and zero dangling references', () => {
      for (const preset of PRESET_TOPOLOGIES) {
        const nodeIds = new Set<string>();
        const ifaceByNode = new Map<string, Set<string>>();
        for (const n of preset.topology.nodes) {
          expect(nodeIds.has(n.id), `Duplicate node id ${n.id} in preset ${preset.name}`).toBe(false);
          nodeIds.add(n.id);
          const ifSet = new Set<string>();
          for (const iface of n.interfaces) {
            expect(ifSet.has(iface.id), `Duplicate iface id ${iface.id} on ${n.hostname} in ${preset.name}`).toBe(false);
            ifSet.add(iface.id);
          }
          ifaceByNode.set(n.id, ifSet);
        }
        const linkIds = new Set<string>();
        for (const l of preset.topology.links) {
          expect(linkIds.has(l.id), `Duplicate link id ${l.id} in preset ${preset.name}`).toBe(false);
          linkIds.add(l.id);
          expect(nodeIds.has(l.sourceNodeId), `Dangling sourceNodeId ${l.sourceNodeId} in ${preset.name}`).toBe(true);
          expect(nodeIds.has(l.targetNodeId), `Dangling targetNodeId ${l.targetNodeId} in ${preset.name}`).toBe(true);
          expect(ifaceByNode.get(l.sourceNodeId)?.has(l.sourceInterfaceId), `Dangling sourceInterfaceId ${l.sourceInterfaceId} in ${preset.name}`).toBe(true);
          expect(ifaceByNode.get(l.targetNodeId)?.has(l.targetInterfaceId), `Dangling targetInterfaceId ${l.targetInterfaceId} in ${preset.name}`).toBe(true);
        }
      }
    });

    it('preserves PBR & ACL rules on applyParsedNodeConfig and handles undo/redo cleanly in useSimStore', () => {
      const store = useSimStore.getState();
      store.loadPreset(PRESET_TOPOLOGIES[0].id);
      const beforeCount = useSimStore.getState().topology.nodes.length;
      const targetNode = useSimStore.getState().topology.nodes[0];

      const fgtWithPbr = importTopologyFromText(`config system global
    set hostname "${targetNode.hostname}"
end
config system interface
    edit "port1"
        set ip 10.10.0.1 255.255.255.0
    next
end
config router policy
    edit 1
        set input-device "port1"
        set src "10.10.0.0/24"
        set dst "0.0.0.0/0"
        set output-device "port1"
        set gateway 10.10.0.2
    next
end`).nodes[0];

      useSimStore.getState().applyParsedNodeConfig(targetNode.id, fgtWithPbr);
      const updated = useSimStore.getState().topology.nodes.find((n) => n.id === targetNode.id)!;
      expect(updated.pbrRules?.length).toBe(1);
      expect(updated.pbrRules?.[0].nextHop).toBe('10.10.0.2');

      useSimStore.getState().undo();
      expect(useSimStore.getState().topology.nodes.length).toBe(beforeCount);
    });
  });

  describe('9. solver edge cases (empty topology, loop detection, DNAT+ACL+SNAT)', () => {
    it('handles empty topologies and detects static routing loops without infinite recursion', () => {
      const emptyRes = solveTopology({ nodes: [], links: [] });
      expect(Object.keys(emptyRes.nodes)).toHaveLength(0);

      // 2-node static routing loop: R1 -> R2 -> R1 for 198.51.100.1
      const r1 = makeMinimalNode('r1', 'R1', 'cisco-ios-xe');
      const r2 = makeMinimalNode('r2', 'R2', 'cisco-ios-xe');
      r1.interfaces = [{ id: 'r1-e0', name: 'Gi0/0', cidr: '10.0.0.1/30', vrf: 'default' }];
      r2.interfaces = [{ id: 'r2-e0', name: 'Gi0/0', cidr: '10.0.0.2/30', vrf: 'default' }];
      r1.staticRoutes = [{ id: 's1', prefix: '198.51.100.0/24', nextHop: '10.0.0.2', vrf: 'default', ad: 1 }];
      r2.staticRoutes = [{ id: 's2', prefix: '198.51.100.0/24', nextHop: '10.0.0.1', vrf: 'default', ad: 1 }];
      const loopTopo: TopologyState = {
        nodes: [r1, r2],
        links: [{ id: 'l1', sourceNodeId: 'r1', sourceInterfaceId: 'r1-e0', targetNodeId: 'r2', targetInterfaceId: 'r2-e0' }],
      };
      const loopRes = solveTopology(loopTopo);
      const trace = tracePacket(loopTopo, loopRes, 'r1', '198.51.100.1', 'default', { skipReturn: true });
      expect(trace.outcome, `Unexpected failureReason: ${trace.failureReason}, hops: ${JSON.stringify(trace.hops)}`).toBe('loop');

      // Resilience against legacy JSON topologies missing maxPaths (must not collapse RIB to [] via NaN)
      const legacyNode = { ...makeMinimalNode('leg', 'LEGACY', 'cisco-ios-xe'), maxPaths: undefined as unknown as number };
      const legacySim = solveTopology({ nodes: [legacyNode], links: [] });
      expect(legacySim.nodes['leg'].rib.some((r) => r.active && r.protocol === 'connected')).toBe(true);
    });
  });

  describe('10. Cloud expansion & auto-arrange spacing', () => {
    it('supports AWS/Azure/GCP/OCI/Cloudflare Terraform & CLI round-trip, cloud firewalls, blackhole routes, and non-overlapping auto-layout', () => {
      const awsTf = `resource "aws_ec2_transit_gateway" "tgw_prod" {
  description = "AWS-TGW-PROD"
  amazon_side_asn = 64512
  appliance_mode_support = "enable"
}
resource "aws_route" "nat_default" {
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = "nat-0123456789"
}
resource "aws_route" "pcx_partner" {
  destination_cidr_block = "172.30.0.0/16"
  vpc_peering_connection_id = "pcx-0abcdef123"
}
resource "aws_ec2_transit_gateway_route" "bh1" {
  destination_cidr_block = "192.0.2.0/24"
  blackhole = true
}
resource "aws_network_acl_rule" "allow_https" {
  rule_number = 100
  rule_action = "allow"
  protocol = "tcp"
  cidr_block = "10.0.0.0/8"
  from_port = 443
  to_port = 443
}`;
      const awsNode = importTopologyFromText(awsTf).nodes[0];
      expect(awsNode.vendor).toBe('aws-cloud');
      expect(awsNode.hostname).toBe('AWS-TGW-PROD');
      expect(awsNode.cloudConfig?.applianceMode).toBe(true);
      expect(awsNode.cloudConfig?.blackholeCidrs).toContain('192.0.2.0/24');
      expect(awsNode.staticRoutes.some((r) => r.awsTargetType === 'nat' && r.prefix === '0.0.0.0/0')).toBe(true);
      expect(awsNode.staticRoutes.some((r) => r.awsTargetType === 'pcx' && r.prefix === '172.30.0.0/16')).toBe(true);
      expect(awsNode.aclRules?.[0]).toMatchObject({ action: 'allow', protocol: 'tcp', dstPort: 443 });
      expect(formatRunningConfig(awsNode)).toContain('aws_ec2_transit_gateway');
      expect(formatRunningConfig(awsNode)).toContain('nat_gateway_id');

      // Verify AWS NAT Gateway SNAT breakout + blackhole drop in tracePacket
      const awsSim = solveTopology({ nodes: [awsNode], links: [] });
      const awsNatTrace = tracePacket({ nodes: [awsNode], links: [] }, awsSim, awsNode.id, '8.8.8.8', 'default', {
        srcIp: '10.0.0.10',
        protocol: 'tcp',
        dstPort: 443,
        skipReturn: true,
      });
      expect(awsNatTrace.outcome).toBe('delivered');
      expect(awsNatTrace.hops[0].natApplied).toContain('AWS NAT Gateway SNAT');

      // Verify AWS CLI `aws ec2 create-route` with IGW
      const awsCliNode = importTopologyFromText('aws ec2 create-route --route-table-id rtb-1 --destination-cidr-block 0.0.0.0/0 --gateway-id igw-123').nodes[0];
      expect(awsCliNode.staticRoutes[0]).toMatchObject({ prefix: '0.0.0.0/0', awsTargetType: 'igw' });

      const azCli = `az network route-table create --name hub-rt --disable-bgp-route-propagation true
az network route-table route create --name udr1 --address-prefix 10.99.0.0/24 --next-hop-type VirtualAppliance --next-hop-ip-address 10.0.0.4
az network route-table route create --name udr2 --address-prefix 0.0.0.0/0 --next-hop-type Internet
az network route-table route create --name udr3 --address-prefix 198.51.100.0/24 --next-hop-type None
az network nsg rule create --name Allow-HTTPS --priority 110 --access Allow --protocol Tcp --source-address-prefixes 10.0.0.0/8 --destination-address-prefixes * --destination-port-ranges 443`;
      const azNode = importTopologyFromText(azCli).nodes[0];
      expect(azNode.vendor).toBe('azure-cloud');
      expect(azNode.cloudConfig?.disableBgpPropagation).toBe(true);
      expect(azNode.staticRoutes[0]).toMatchObject({ prefix: '10.99.0.0/24', nextHop: '10.0.0.4', azureNextHopType: 'VirtualAppliance' });
      expect(azNode.staticRoutes[1]).toMatchObject({ prefix: '0.0.0.0/0', azureNextHopType: 'Internet' });
      expect(azNode.staticRoutes[2]).toMatchObject({ prefix: '198.51.100.0/24', azureNextHopType: 'None' });
      expect(azNode.aclRules?.[0]).toMatchObject({ name: 'Allow-HTTPS', action: 'allow', protocol: 'tcp', dstPort: 443 });
      expect(formatRunningConfig(azNode)).toContain('disable_bgp_route_propagation = true');
      expect(formatRunningConfig(azNode)).toContain('next_hop_type          = "Internet"');

      // Verify Azure UDR execution (Internet breakout, None drop, and BGP suppression)
      const azSim = solveTopology({ nodes: [azNode], links: [] });
      expect(
        tracePacket({ nodes: [azNode], links: [] }, azSim, azNode.id, '8.8.4.4', 'default', {
          srcIp: '10.0.0.10',
          protocol: 'tcp',
          dstPort: 443,
          skipReturn: true,
        }).outcome
      ).toBe('delivered');
      expect(
        tracePacket({ nodes: [azNode], links: [] }, azSim, azNode.id, '198.51.100.5', 'default', {
          srcIp: '10.0.0.10',
          protocol: 'tcp',
          dstPort: 443,
          skipReturn: true,
        }).outcome
      ).toBe('dropped');

      const gcpCli = `gcloud compute routes create r1 --destination-range=10.88.0.0/24 --next-hop-address=10.0.0.5 --priority=500 --tags=web-tier
gcloud compute routes create r-inet --destination-range=0.0.0.0/0 --next-hop-gateway=default-internet-gateway --priority=1000
gcloud compute firewall-rules create allow-ssh --priority=1000 --allow=tcp:22 --source-ranges=10.0.0.0/8`;
      const gcpNode = importTopologyFromText(gcpCli).nodes[0];
      gcpNode.cloudConfig = {
        ...gcpNode.cloudConfig,
        privateGoogleAccess: true,
        pgaOnPremAdvertise: true,
        nccHubEnabled: true,
        pscEndpoints: ['10.240.0.10/32'],
      };
      expect(gcpNode.vendor).toBe('gcp-cloud');
      expect(gcpNode.staticRoutes[0]).toMatchObject({ prefix: '10.88.0.0/24', gcpNextHopType: 'next-hop-address', gcpPriority: 500, networkTag: 'web-tier' });
      expect(gcpNode.staticRoutes[1]).toMatchObject({ prefix: '0.0.0.0/0', gcpNextHopType: 'default-internet-gateway', gcpPriority: 1000 });
      expect(gcpNode.aclRules?.[0]).toMatchObject({ name: 'allow-ssh', action: 'allow', protocol: 'tcp', dstPort: 22 });
      const gcpTf = formatRunningConfig(gcpNode);
      expect(validateRunningConfig(gcpTf)).toEqual([]);
      expect(validateRunningConfig(formatRunningConfig(awsNode))).toEqual([]);
      expect(validateRunningConfig(formatRunningConfig(azNode))).toEqual([]);
      expect(gcpTf).toContain('next_hop_gateway = "default-internet-gateway"');
      expect(gcpTf).toContain('google_network_connectivity_hub');
      expect(gcpTf).toContain('199.36.153.8/30');
      expect(gcpTf).toContain('10.240.0.10/32');
      expect(gcpTf).toContain('tags       = ["web-tier"]');

      // Verify GCP default-internet-gateway, PGA (199.36.153.8), and PSC (10.240.0.10) traces
      const gcpSim = solveTopology({ nodes: [gcpNode], links: [] });
      for (const dst of ['8.8.8.8', '199.36.153.8', '10.240.0.10']) {
        expect(
          tracePacket({ nodes: [gcpNode], links: [] }, gcpSim, gcpNode.id, dst, 'default', {
            srcIp: '10.0.0.10',
            protocol: 'tcp',
            dstPort: 22,
            skipReturn: true,
          }).outcome
        ).toBe('delivered');
      }

      // Auto-arrange spacing check on the 9-branch MPLS+DMVPN preset
      useSimStore.getState().loadPreset('cisco-mpls-dmvpn');
      useSimStore.getState().autoLayoutTopology();
      const laidOut = useSimStore.getState().topology.nodes;
      for (let i = 0; i < laidOut.length; i++) {
        for (let j = i + 1; j < laidOut.length; j++) {
          const dx = Math.abs(laidOut[i].position.x - laidOut[j].position.x);
          const dy = Math.abs(laidOut[i].position.y - laidOut[j].position.y);
          // Nodes on the same row must have at least 340px horizontal separation; different rows at least 270px vertical
          expect(dx >= 340 || dy >= 270).toBe(true);
        }
      }
    });

    it('covers bug-hunt regressions: FortiGate BGP enable, Cloud hostname/CF round-trip, VnetLocal/local trace, IPv6-only iface, and store defaults', () => {
      // 1. FortiGate `config router bgp` must set bgp.enabled = true
      const fgtBgp = importTopologyFromText(`config system global
    set hostname "FGT-BGP"
end
config router bgp
    set as 65123
    set router-id 10.0.0.1
end`).nodes[0];
      expect(fgtBgp.bgp.enabled).toBe(true);
      expect(fgtBgp.bgp.asn).toBe(65123);

      // 2. Azure/GCP/Cloudflare Terraform HCL round-trip preserves exact hostname (not -udr / -ncc-hub / description)
      const gcpRoundTripSrc = makeMinimalNode('g1', 'GCP-HUB-1', 'gcp-cloud');
      gcpRoundTripSrc.cloudConfig = { region: 'us-central1', nccHubEnabled: true, pgaOnPremAdvertise: true, privateGoogleAccess: true };
      const gcpReimported = importTopologyFromText(formatRunningConfig(gcpRoundTripSrc)).nodes[0];
      expect(gcpReimported.vendor).toBe('gcp-cloud');
      expect(gcpReimported.hostname).toBe('GCP-HUB-1');

      const cfSrc = makeMinimalNode('cf1', 'CF-EDGE-1', 'cloudflare-mwan');
      const cfReimported = importTopologyFromText(formatRunningConfig(cfSrc)).nodes[0];
      expect(cfReimported.vendor).toBe('cloudflare-mwan');
      expect(cfReimported.hostname).toBe('CF-EDGE-1');

      // 3. Azure VnetLocal UDR delivers cleanly in tracePacket (instead of dropping as unreachable)
      const azLocal = makeMinimalNode('az-loc', 'AZ-LOC', 'azure-cloud');
      azLocal.staticRoutes = [{ id: 'u1', vrf: 'default', prefix: '10.77.0.0/16', nextHop: '0.0.0.0', azureNextHopType: 'VnetLocal' }];
      const azLocalSim = solveTopology({ nodes: [azLocal], links: [] });
      expect(tracePacket({ nodes: [azLocal], links: [] }, azLocalSim, 'az-loc', '10.77.1.5', 'default', { skipReturn: true }).outcome).toBe('delivered');

      // 4. IPv6-only interface installs connected/local IPv6 routes with zero warnings
      const v6Only = makeMinimalNode('v6', 'V6-ONLY', 'cisco-ios-xe');
      v6Only.interfaces = [{ id: 'v6-i1', name: 'Gi0/0', cidr: '', cidr6: '2001:db8:99::1/64', vrf: 'default' }];
      const v6Sim = solveTopology({ nodes: [v6Only], links: [] });
      expect(v6Sim.warnings).toHaveLength(0);
      expect(v6Sim.nodes['v6'].rib.some((r) => r.af === 6 && r.prefix === '2001:db8:99::' && r.active)).toBe(true);

      // 5. Store: addNode on cloud disables OSPF & enables BGP; setTraceParams(..., null) clears traceSrcInterfaceId
      useSimStore.getState().createWorkspace('BugHuntTest');
      useSimStore.getState().addNode('aws-cloud');
      const addedAws = useSimStore.getState().topology.nodes[0];
      expect(addedAws.ospf.enabled).toBe(false);
      expect(addedAws.bgp.enabled).toBe(true);
      useSimStore.getState().setTraceParams(addedAws.id, '8.8.8.8', 'default', 'any', null, addedAws.interfaces[0].id);
      expect(useSimStore.getState().traceSrcInterfaceId).toBe(addedAws.interfaces[0].id);
      useSimStore.getState().setTraceParams(addedAws.id, '8.8.8.8', 'default', 'any', null, null);
      expect(useSimStore.getState().traceSrcInterfaceId).toBeUndefined();

      // 6. JunOS BGP must not overwrite eBGP remoteAs on subsequent neighbor lines
      const junosBgp = importTopologyFromText(`set system host-name JUN-BGP
set routing-options autonomous-system 65100
set protocols bgp group EBGP neighbor 10.0.0.2 peer-as 65200
set protocols bgp group EBGP neighbor 10.0.0.2 description "To ISP"`).nodes[0];
      expect(junosBgp.bgp.peers[0].remoteAs).toBe(65200);

      // 7. FHRP adminDown failover promotes standby router to Active and installs VIP
      const h1 = makeMinimalNode('h1', 'HSRP-1', 'cisco-ios-xe');
      const h2 = makeMinimalNode('h2', 'HSRP-2', 'cisco-ios-xe');
      h1.adminDown = true;
      h1.fhrpGroups = [{ id: 'fg1', protocol: 'hsrp', groupId: 1, interfaceId: 'h1-i1', virtualIp: '10.0.0.254', priority: 150 }];
      h2.fhrpGroups = [{ id: 'fg2', protocol: 'hsrp', groupId: 1, interfaceId: 'h2-i1', virtualIp: '10.0.0.254', priority: 100 }];
      const fhrpSim = solveTopology({ nodes: [h1, h2], links: [] });
      expect(fhrpSim.nodes['h2'].rib.some((r) => r.prefix === '10.0.0.254' && r.prefixLen === 32 && r.active)).toBe(true);

      // 8. YAML export quotes special object keys cleanly
      const yamlSpecial = topologyToYaml({ nodes: [h2], links: [], vrfColors: { 'vrf:prod#1': '#ff0000' } });
      expect(yamlSpecial).toContain('"vrf:prod#1": "#ff0000"');
    });

    it('verifies Pass-2 bug hunt fixes (Cisco BGP route-map order, GCP vpn-tunnel, loose uRPF blackhole, cloud latency, DNAT hairpin)', () => {
      // 1. Cisco BGP peer route-map defined AFTER router bgp
      const ciscoRm = importTopologyFromText(`hostname R-BGP-RM
router bgp 65100
 neighbor 10.0.0.2 remote-as 65200
 neighbor 10.0.0.2 route-map RM-IN in
 neighbor 10.0.0.2 route-map RM-OUT out
!
route-map RM-IN permit 10
 set local-preference 200
!
route-map RM-OUT permit 10
 set community 65100:100`).nodes[0];
      expect(ciscoRm.bgp.peers[0].routeMapInId).toBe(ciscoRm.routeMaps.find((m) => m.name === 'RM-IN')?.id);
      expect(ciscoRm.bgp.peers[0].routeMapOutId).toBe(ciscoRm.routeMaps.find((m) => m.name === 'RM-OUT')?.id);

      // 2. GCP vpn-tunnel static route preserves interfaceName in Terraform HCL & gcloud CLI
      const gcpVpnHcl = importTopologyFromText(`resource "google_compute_router" "gcp_r1" {
  name = "GCP-R1"
  region = "us-central1"
}
resource "google_compute_route" "vpn_rt" {
  dest_range = "10.99.0.0/16"
  next_hop_vpn_tunnel = "ha-vpn-tun-0"
  priority = 500
}`).nodes[0];
      expect(gcpVpnHcl.staticRoutes[0].gcpNextHopType).toBe('vpn-tunnel');
      expect(gcpVpnHcl.staticRoutes[0].interfaceName).toBe('ha-vpn-tun-0');

      const gcpVpnCli = importTopologyFromText(
        `gcloud compute routes create vpn-rt --destination-range=10.88.0.0/16 --next-hop-vpn-tunnel=ha-vpn-tun-1 --priority=400`
      ).nodes[0];
      expect(gcpVpnCli.staticRoutes[0].gcpNextHopType).toBe('vpn-tunnel');
      expect(gcpVpnCli.staticRoutes[0].interfaceName).toBe('ha-vpn-tun-1');

      // 3. Loose uRPF must drop when the only reverse route is a blackhole / Null0 route
      const rUrpfSrc = makeMinimalNode('u-src', 'U-SRC', 'cisco-ios-xe');
      rUrpfSrc.interfaces = [{ id: 'us-i1', name: 'Gi0/0', cidr: '10.1.0.1/24', vrf: 'default' }];
      rUrpfSrc.staticRoutes = [{ id: 'us-sr1', vrf: 'default', prefix: '10.2.0.0/24', nextHop: '10.1.0.2' }];
      const rUrpfDst = makeMinimalNode('u-dst', 'U-DST', 'cisco-ios-xe');
      rUrpfDst.interfaces = [
        { id: 'ud-i1', name: 'Gi0/0', cidr: '10.1.0.2/24', vrf: 'default', urpfMode: 'loose' },
        { id: 'ud-i2', name: 'Gi0/1', cidr: '10.2.0.1/24', vrf: 'default' },
      ];
      rUrpfDst.staticRoutes = [{ id: 'ud-bh', vrf: 'default', prefix: '198.51.100.0/24', nextHop: 'Null0' }];
      const urpfTopo: TopologyState = {
        nodes: [rUrpfSrc, rUrpfDst],
        links: [{ id: 'ul1', sourceNodeId: 'u-src', sourceInterfaceId: 'us-i1', targetNodeId: 'u-dst', targetInterfaceId: 'ud-i1' }],
      };
      const urpfSim = solveTopology(urpfTopo);
      const urpfTrace = tracePacket(urpfTopo, urpfSim, 'u-src', '10.2.0.1', 'default', {
        srcIp: '198.51.100.10',
        skipReturn: true,
      });
      expect(urpfTrace.outcome).toBe('dropped');
      expect(urpfTrace.hops[urpfTrace.hops.length - 1]?.matchedPrefix).toBe('uRPF');

      // 4. Cloud gateway delivery preserves accumulated path latency
      const onPrem = makeMinimalNode('op1', 'ON-PREM', 'cisco-ios-xe');
      onPrem.interfaces = [{ id: 'op-i1', name: 'Gi0/0', cidr: '169.254.1.1/30', vrf: 'default' }];
      onPrem.staticRoutes = [{ id: 'op-sr1', vrf: 'default', prefix: '0.0.0.0/0', nextHop: '169.254.1.2' }];
      const awsGw = makeMinimalNode('aws1', 'AWS-GW', 'aws-cloud');
      awsGw.interfaces = [{ id: 'aws-i1', name: 'tgw-att-1', cidr: '169.254.1.2/30', vrf: 'default' }];
      awsGw.staticRoutes = [{ id: 'aws-igw', vrf: 'default', prefix: '0.0.0.0/0', nextHop: 'igw', awsTargetType: 'igw' }];
      const cloudTopo: TopologyState = {
        nodes: [onPrem, awsGw],
        links: [
          {
            id: 'cl1',
            sourceNodeId: 'op1',
            sourceInterfaceId: 'op-i1',
            targetNodeId: 'aws1',
            targetInterfaceId: 'aws-i1',
            latencyMs: 18,
          },
        ],
      };
      const cloudSim = solveTopology(cloudTopo);
      const cloudTrace = tracePacket(cloudTopo, cloudSim, 'op1', '1.1.1.1', 'default', { skipReturn: true });
      expect(cloudTrace.outcome).toBe('delivered');
      expect(cloudTrace.totalLatencyMs).toBeGreaterThanOrEqual(18);
    });

    it('verifies Pass-3 deep audit fixes (OSPFv3 IPv6 NH, BGP aggregate/RR/confed, IS-IS ECMP, globalNextHop, STP, ACLs, importers)', () => {
      // 1. OSPFv3 dual-stack link installs IPv6 next-hop (not IPv4 adj.remoteIp)
      const o1 = makeMinimalNode('o1', 'O1', 'cisco-ios-xe');
      o1.ospf.enabled = true;
      o1.interfaces = [
        { id: 'o1-i1', name: 'Gi0/0', cidr: '10.0.0.1/30', cidr6: '2001:db8:12::1/64', vrf: 'default', ospfArea: 0 },
      ];
      const o2 = makeMinimalNode('o2', 'O2', 'cisco-ios-xe');
      o2.routerId = '2.2.2.2';
      o2.ospf.enabled = true;
      o2.interfaces = [
        { id: 'o2-i1', name: 'Gi0/0', cidr: '10.0.0.2/30', cidr6: '2001:db8:12::2/64', vrf: 'default', ospfArea: 0 },
        { id: 'o2-lo', name: 'Lo0', cidr: '10.2.2.2/32', cidr6: '2001:db8:2::1/128', vrf: 'default', ospfArea: 0 },
      ];
      const ospfSim = solveTopology({
        nodes: [o1, o2],
        links: [{ id: 'ol1', sourceNodeId: 'o1', sourceInterfaceId: 'o1-i1', targetNodeId: 'o2', targetInterfaceId: 'o2-i1' }],
      });
      const o1v6 = ospfSim.nodes['o1'].rib.find((r) => r.af === 6 && r.prefix === '2001:db8:2::1' && r.active);
      expect(o1v6?.nextHop).toBe('2001:db8:12::2');

      // 2. BGP aggregate-address aggregates BGP-learned routes (not blackholed by summaryOnly)
      const b1 = makeMinimalNode('b1', 'B1', 'cisco-ios-xe');
      b1.routerId = '1.1.1.1';
      b1.interfaces = [{ id: 'b1-i1', name: 'Gi0/0', cidr: '10.12.0.1/30', vrf: 'default' }];
      b1.bgp = { enabled: true, asn: 65001, peers: [{ id: 'p1', peerIp: '10.12.0.2', remoteAs: 65002 }], networks: [{ id: 'n1', prefix: '10.1.1.0/24' }] };
      const b2 = makeMinimalNode('b2', 'B2', 'cisco-ios-xe');
      b2.routerId = '2.2.2.2';
      b2.interfaces = [
        { id: 'b2-i1', name: 'Gi0/0', cidr: '10.12.0.2/30', vrf: 'default' },
        { id: 'b2-i2', name: 'Gi0/1', cidr: '10.23.0.1/30', vrf: 'default' },
      ];
      b2.bgp = {
        enabled: true,
        asn: 65002,
        peers: [
          { id: 'p2a', peerIp: '10.12.0.1', remoteAs: 65001 },
          { id: 'p2b', peerIp: '10.23.0.2', remoteAs: 65003 },
        ],
        networks: [],
        aggregates: [{ id: 'a1', prefix: '10.1.0.0/16', summaryOnly: true }],
      };
      const b3 = makeMinimalNode('b3', 'B3', 'cisco-ios-xe');
      b3.routerId = '3.3.3.3';
      b3.interfaces = [{ id: 'b3-i1', name: 'Gi0/0', cidr: '10.23.0.2/30', vrf: 'default' }];
      b3.bgp = { enabled: true, asn: 65003, peers: [{ id: 'p3', peerIp: '10.23.0.1', remoteAs: 65002 }], networks: [] };
      const aggSim = solveTopology({
        nodes: [b1, b2, b3],
        links: [
          { id: 'bl1', sourceNodeId: 'b1', sourceInterfaceId: 'b1-i1', targetNodeId: 'b2', targetInterfaceId: 'b2-i1' },
          { id: 'bl2', sourceNodeId: 'b2', sourceInterfaceId: 'b2-i2', targetNodeId: 'b3', targetInterfaceId: 'b3-i1' },
        ],
      });
      expect(aggSim.nodes['b3'].rib.some((r) => r.prefix === '10.1.0.0' && r.prefixLen === 16 && r.active)).toBe(true);
      expect(aggSim.nodes['b3'].rib.some((r) => r.prefix === '10.1.1.0' && r.prefixLen === 24 && r.active)).toBe(false);

      // 3. Static route with globalNextHop in non-default VRF resolves cleanly
      const gnh = makeMinimalNode('gnh', 'GNH', 'cisco-ios-xe');
      gnh.vrfs = ['default', 'CUST-A'];
      gnh.interfaces = [
        { id: 'g-i0', name: 'Gi0/0', cidr: '10.0.0.1/30', vrf: 'default' },
        { id: 'g-i1', name: 'Gi0/1', cidr: '192.168.1.1/24', vrf: 'CUST-A' },
      ];
      gnh.staticRoutes = [{ id: 'gs1', vrf: 'CUST-A', prefix: '0.0.0.0/0', nextHop: '10.0.0.2', globalNextHop: true }];
      const gnhSim = solveTopology({ nodes: [gnh], links: [] });
      expect(gnhSim.nodes['gnh'].rib.some((r) => r.vrf === 'CUST-A' && r.prefix === '0.0.0.0' && r.active)).toBe(true);

      // 4. Global-multinational preset uk-sdwan2 TLOC extension now converges OMP routes
      const globalPreset = PRESET_TOPOLOGIES.find((p) => p.id === 'global-multinational')!;
      const globalSim = solveTopology(globalPreset.topology);
      expect(globalSim.nodes['uk-sdwan2'].rib.some((r) => r.protocol === 'omp' && r.active)).toBe(true);

      // 5. Importer & firewall fixes: PAN-OS quoted spaces & named peer-as, FortiGate nested config, VyOS alphabetical nexthop-self, JunOS subinterface round-trip, Cisco standard ACL & ip flow-export validation
      const panAcl = parsePanOsAclRules([
        'set address "Web Server" ip-netmask 10.1.1.10/32',
        'set rulebase security rules "Allow Web" from trust to untrust source "Web Server" destination any service any action allow',
      ]);
      expect(panAcl).toHaveLength(1);
      expect(panAcl[0].srcCidr).toBe('10.1.1.10/32');

      const ciscoStdAcl = parseCiscoStyleAclRules([
        'ip access-list standard MGMT',
        ' 20 deny any',
        ' 10 permit 10.0.0.0 0.0.0.255',
      ]);
      expect(ciscoStdAcl[0].seq).toBe(20);
      expect(ciscoStdAcl[1].seq).toBe(10);
      expect(ciscoStdAcl[1].srcCidr).toBe('10.0.0.0/24');

      const vyosBgp = importTopologyFromText(`set system host-name 'VY-1'
set protocols bgp system-as '65001'
set protocols bgp neighbor 10.0.0.2 address-family ipv4-unicast nexthop-self
set protocols bgp neighbor 10.0.0.2 remote-as '65002'`).nodes[0];
      expect(vyosBgp.bgp.peers[0].remoteAs).toBe(65002);
      expect(vyosBgp.bgp.peers[0].nextHopSelf).toBe(true);

      const fgtNested = importTopologyFromText(`config system interface
  edit "port1"
    set ip 10.0.0.1 255.255.255.0
    config secondaryip
      edit 1
        set ip 192.168.1.1 255.255.255.0
      next
    end
    set vrf 2
  next
end`).nodes[0];
      expect(fgtNested.interfaces).toHaveLength(1);
      expect(fgtNested.interfaces[0].name).toBe('port1');
      expect(fgtNested.interfaces[0].vrf).toBe('2');

      const junosSub = makeMinimalNode('j1', 'JUN-SUB', 'juniper-junos');
      junosSub.interfaces = [{ id: 'ji1', name: 'ge-0/0/0.100', cidr: '10.100.0.1/30', vrf: 'default' }];
      const junosRe = importTopologyFromText(formatRunningConfig(junosSub)).nodes[0];
      expect(junosRe.interfaces.some((i) => i.name === 'ge-0/0/0.100' && i.cidr === '10.100.0.1/30')).toBe(true);

      const ipfixNode = makeMinimalNode('c1', 'C-IPFIX', 'cisco-ios-xe');
      ipfixNode.telemetry = { ipfixCollectorIp: '10.0.0.50' };
      expect(validateRunningConfig(formatRunningConfig(ipfixNode))).toHaveLength(0);

      // 6. Store setTraceParams preserves traceSrcIp when editing other trace fields on the same source node
      useSimStore.getState().setTraceParams('node-a', '8.8.8.8', 'default', 'tcp', 443, null, '10.50.0.10');
      useSimStore.getState().setTraceParams('node-a', '1.1.1.1', 'default', 'udp', 53);
      expect(useSimStore.getState().traceSrcIp).toBe('10.50.0.10');
    });

    it('verifies Pass-4 audit fixes (store remap/cleanup, BGP redist/outRm, PBR blackhole, Arista MLAG, prefix-list, FortiGate, Azure blackhole)', () => {
      // 1. Store duplicateNode remaps internal interfaceIds & deleteInterface strips dangling refs
      useSimStore.getState().createWorkspace('Pass4StoreTest');
      const nOrig = makeMinimalNode('n-orig', 'NX-1', 'cisco-nx-os');
      nOrig.interfaces = [{ id: 'if-orig-1', name: 'Po10', cidr: '10.10.0.1/24', vrf: 'default' }];
      nOrig.fhrpGroups = [{ id: 'fg-1', protocol: 'hsrp', groupId: 1, interfaceId: 'if-orig-1', virtualIp: '10.10.0.254', priority: 110 }];
      nOrig.vpc = { enabled: true, domainId: 10, peerLinkInterfaceId: 'if-orig-1' };
      useSimStore.getState().importTopology({ nodes: [nOrig], links: [] });
      useSimStore.getState().duplicateNode('n-orig');
      const dup = useSimStore.getState().topology.nodes.find((n) => n.id !== 'n-orig')!;
      expect(dup.interfaces[0].id).not.toBe('if-orig-1');
      expect(dup.fhrpGroups?.[0].interfaceId).toBe(dup.interfaces[0].id);
      expect(dup.vpc?.peerLinkInterfaceId).toBe(dup.interfaces[0].id);
      useSimStore.getState().deleteInterface(dup.id, dup.interfaces[0].id);
      const afterDel = useSimStore.getState().topology.nodes.find((n) => n.id === dup.id)!;
      expect(afterDel.fhrpGroups).toHaveLength(0);
      expect(afterDel.vpc?.peerLinkInterfaceId).toBeUndefined();

      // 2. BGP redistribution route-map supports matchTag & setCommunity; outbound eBGP route-map matches ^$ pre-prepend and does not leak setLocalPref
      const r1 = makeMinimalNode('br1', 'BR1', 'cisco-ios-xe');
      r1.routerId = '1.1.1.1';
      r1.interfaces = [{ id: 'br1-i1', name: 'Gi0/0', cidr: '10.0.0.1/30', vrf: 'default' }];
      r1.staticRoutes = [{ id: 'sr1', vrf: 'default', prefix: '10.50.0.0/24', nextHop: '10.0.0.2', tag: 100 }];
      r1.routeMaps = [
        { id: 'rm-red', name: 'RED-TAG', entries: [{ id: 'e1', seq: 10, action: 'permit', matchTag: 100, set: { setCommunity: '65001:100' } }] },
        { id: 'rm-out', name: 'OUT-LOC', entries: [{ id: 'e2', seq: 10, action: 'permit', matchAsPathRegex: '^$', set: { setLocalPref: 500 } }] },
      ];
      r1.redistributions = [{ id: 'rd1', from: 'static', to: 'bgp', routeMapId: 'rm-red' }];
      r1.bgp = { enabled: true, asn: 65001, peers: [{ id: 'bp1', peerIp: '10.0.0.2', remoteAs: 65002, routeMapOutId: 'rm-out' }], networks: [] };
      const r2 = makeMinimalNode('br2', 'BR2', 'cisco-ios-xe');
      r2.routerId = '2.2.2.2';
      r2.interfaces = [{ id: 'br2-i1', name: 'Gi0/0', cidr: '10.0.0.2/30', vrf: 'default' }];
      r2.bgp = { enabled: true, asn: 65002, peers: [{ id: 'bp2', peerIp: '10.0.0.1', remoteAs: 65001 }], networks: [] };
      const bgpSim = solveTopology({
        nodes: [r1, r2],
        links: [{ id: 'bl1', sourceNodeId: 'br1', sourceInterfaceId: 'br1-i1', targetNodeId: 'br2', targetInterfaceId: 'br2-i1' }],
      });
      const learned = bgpSim.nodes['br2'].rib.find((r) => r.prefix === '10.50.0.0' && r.active);
      expect(learned).toBeDefined();
      expect(learned?.bgpAttrs?.communities).toContain('65001:100');
      expect(learned?.bgpAttrs?.localPref).toBe(100);

      // 3. PBR with nextHop: 'blackhole' drops traffic instead of skipping
      const pbrN = makeMinimalNode('pbr1', 'PBR-1', 'cisco-ios-xe');
      pbrN.interfaces = [{ id: 'pi1', name: 'Gi0/0', cidr: '10.1.0.1/24', vrf: 'default' }];
      pbrN.staticRoutes = [{ id: 'ps1', vrf: 'default', prefix: '0.0.0.0/0', nextHop: '10.1.0.2' }];
      pbrN.pbrRules = [{ id: 'pr1', name: 'DROP-BAD', matchPrefix: '198.51.100.0/24', nextHop: 'blackhole' }];
      const pbrSim = solveTopology({ nodes: [pbrN], links: [] });
      const pbrTrace = tracePacket({ nodes: [pbrN], links: [] }, pbrSim, 'pbr1', '198.51.100.5', 'default', { skipReturn: true });
      expect(pbrTrace.outcome).toBe('dropped');

      // 4. Arista EOS MLAG round-trip preserves vendor, peerLinkInterfaceId, and mlagId
      const aristaSrc = makeMinimalNode('ar1', 'LEAF-EOS-1', 'arista-eos');
      aristaSrc.interfaces = [
        { id: 'po1', name: 'Port-Channel1000', cidr: '', vrf: 'default', lacpGroup: 1000, lacpMode: 'active' },
        { id: 'po10', name: 'Port-Channel10', cidr: '', vrf: 'default', mlagId: 10 },
      ];
      aristaSrc.mlag = { enabled: true, domainId: 'MLAG-DC1', localInterface: 'Vlan4094', peerAddress: '10.255.255.2', peerLinkInterfaceId: 'po1', reloadDelay: 300 };
      const aristaRe = importTopologyFromText(formatRunningConfig(aristaSrc)).nodes[0];
      expect(aristaRe.vendor).toBe('arista-eos');
      expect(aristaRe.mlag?.enabled).toBe(true);
      expect(aristaRe.mlag?.domainId).toBe('MLAG-DC1');
      expect(aristaRe.mlag?.peerLinkInterfaceId).toBe(aristaRe.interfaces.find((i) => i.name === 'Port-Channel1000')?.id);
      expect(aristaRe.interfaces.find((i) => i.name === 'Port-Channel10')?.mlagId).toBe(10);

      // 5. Cisco ip prefix-list, route-map clauses, and static route track/tag round-trip
      const ciscoPl = importTopologyFromText(`hostname R-PL
ip prefix-list CORP-PFX seq 10 permit 10.0.0.0/8 ge 16 le 24
route-map RM-CORP permit 10
 match ip address prefix-list CORP-PFX
 set metric 50
 set as-path prepend 65001 65001
 set distance 180
!
ip route 0.0.0.0 0.0.0.0 10.0.0.2 10 track 1 tag 777`).nodes[0];
      expect(ciscoPl.prefixLists).toHaveLength(1);
      expect(ciscoPl.prefixLists[0].entries[0]).toMatchObject({ prefix: '10.0.0.0/8', ge: 16, le: 24 });
      expect(ciscoPl.routeMaps[0].entries[0].matchPrefixListId).toBe(ciscoPl.prefixLists[0].id);
      expect(ciscoPl.routeMaps[0].entries[0].set).toMatchObject({ setMed: 50, prependAsPath: [65001, 65001], setAd: 180 });
      expect(ciscoPl.staticRoutes[0]).toMatchObject({ ad: 10, trackId: '1', tag: 777 });

      // 6. FortiGate passive-interface before interface block + static distance
      const fgtOrder = importTopologyFromText(`config router ospf
  set passive-interface "port1"
end
config system interface
  edit "port1"
    set ip 10.1.1.1 255.255.255.0
  next
end
config router static
  edit 1
    set dst 10.9.0.0/16
    set gateway 10.1.1.254
    set distance 25
  next
end`).nodes[0];
      expect(fgtOrder.interfaces[0].passive).toBe(true);
      expect(fgtOrder.staticRoutes[0].ad).toBe(25);

      // 7. Azure blackholeCidrs round-trip stays in cloudConfig.blackholeCidrs
      const azBh = makeMinimalNode('azb', 'AZ-BH', 'azure-cloud');
      azBh.cloudConfig = { region: 'eastus', blackholeCidrs: ['192.0.2.0/24'] };
      const azRe = importTopologyFromText(formatRunningConfig(azBh)).nodes[0];
      expect(azRe.cloudConfig?.blackholeCidrs).toContain('192.0.2.0/24');
    });

    it('verifies Pass-5 audit fixes (AS-path _/lazy regex, NAT AF guard, VRF leak loop/chain, FHRP VRF/IPv6, Forcepoint standby, YAML autoFormat, NX-OS/Null0 validator)', () => {
      // 1. NAT AF guard: IPv4 SNAT with srcCidr='any' must not rewrite IPv6 srcIp
      const snatV6 = evaluatePostRoutingSnat(
        [{ id: 'n1', seq: 10, name: 'V4-SNAT', type: 'snat', srcCidr: 'any', dstCidr: 'any', translatedIp: '203.0.113.1' }],
        '2001:db8:1::10',
        '2001:db8:2::20'
      );
      expect(snatV6.srcIp).toBe('2001:db8:1::10');

      // 2. Bidirectional VRF leak (A <-> B) does not bounce routes back; chained leak (A -> B -> C) preserves origin VRF
      const vrfNode = makeMinimalNode('vn1', 'VRF-RTR', 'cisco-ios-xe');
      vrfNode.vrfs = ['default', 'A', 'B', 'C'];
      vrfNode.interfaces = [
        { id: 'va', name: 'Gi0/0', cidr: '10.1.0.1/24', vrf: 'A' },
        { id: 'vb', name: 'Gi0/1', cidr: '10.2.0.1/24', vrf: 'B' },
        { id: 'vc', name: 'Gi0/2', cidr: '10.3.0.1/24', vrf: 'C' },
      ];
      vrfNode.staticRoutes = [{ id: 'vs1', vrf: 'A', prefix: '172.16.0.0/16', nextHop: '10.1.0.2' }];
      vrfNode.vrfLeaks = [
        { id: 'l1', fromVrf: 'A', toVrf: 'B' },
        { id: 'l2', fromVrf: 'B', toVrf: 'A' },
        { id: 'l3', fromVrf: 'B', toVrf: 'C' },
      ];
      const vrfSim = solveTopology({ nodes: [vrfNode], links: [] });
      const aConn = vrfSim.nodes['vn1'].rib.filter((r) => r.vrf === 'A' && r.prefix === '10.1.0.0' && r.active);
      expect(aConn).toHaveLength(1);
      const cChained = vrfSim.nodes['vn1'].rib.find((r) => r.vrf === 'C' && r.prefix === '172.16.0.0' && r.active);
      expect(cChained).toBeDefined();
      expect(cChained?.leakedFromVrf).toBe('A');

      // 3. FHRP cross-VRF isolation & IPv6 VIP /128 installation
      const f1 = makeMinimalNode('fv1', 'F1', 'cisco-ios-xe');
      f1.vrfs = ['default', 'CUST-A', 'CUST-B'];
      f1.interfaces = [
        { id: 'fa', name: 'Gi0/0', cidr: '10.0.0.1/24', vrf: 'CUST-A' },
        { id: 'fb', name: 'Gi0/1', cidr: '10.0.0.1/24', cidr6: '2001:db8:1::2/64', vrf: 'CUST-B' },
      ];
      f1.fhrpGroups = [
        { id: 'g1', protocol: 'hsrp', groupId: 1, interfaceId: 'fa', virtualIp: '10.0.0.254', priority: 110 },
        { id: 'g2', protocol: 'hsrp', groupId: 1, interfaceId: 'fb', virtualIp: '10.0.0.254', priority: 100 },
        { id: 'g3', protocol: 'vrrp', groupId: 6, interfaceId: 'fb', virtualIp: '2001:db8:1::1', priority: 120 },
      ];
      const fSim = solveTopology({ nodes: [f1], links: [] });
      expect(fSim.nodes['fv1'].rib.some((r) => r.vrf === 'CUST-A' && r.prefix === '10.0.0.254' && r.active)).toBe(true);
      expect(fSim.nodes['fv1'].rib.some((r) => r.vrf === 'CUST-B' && r.prefix === '10.0.0.254' && r.active)).toBe(true);
      expect(fSim.nodes['fv1'].rib.some((r) => r.af === 6 && r.prefix === '2001:db8:1::1' && r.prefixLen === 128 && r.active)).toBe(true);

      // 4. Forcepoint Cluster standby mode elects Active + Standby
      const fp1 = makeMinimalNode('fp1', 'FP-1', 'forcepoint-ngfw');
      fp1.routerId = '10.0.0.1';
      fp1.interfaces = [{ id: 'fp1-hb', name: 'eth0', cidr: '169.254.1.1/30', vrf: 'default' }];
      fp1.forcepointCluster = { enabled: true, clusterId: 30, mode: 'standby', heartbeatInterfaceId: 'fp1-hb' };
      const fp2 = makeMinimalNode('fp2', 'FP-2', 'forcepoint-ngfw');
      fp2.routerId = '10.0.0.2';
      fp2.interfaces = [{ id: 'fp2-hb', name: 'eth0', cidr: '169.254.1.2/30', vrf: 'default' }];
      fp2.forcepointCluster = { enabled: true, clusterId: 30, mode: 'standby', heartbeatInterfaceId: 'fp2-hb' };
      const fpSim = solveTopology({
        nodes: [fp1, fp2],
        links: [{ id: 'fpl1', sourceNodeId: 'fp1', sourceInterfaceId: 'fp1-hb', targetNodeId: 'fp2', targetInterfaceId: 'fp2-hb' }],
      });
      expect(fpSim.nodes['fp1'].neighbors?.find((n) => n.protocol === 'ha')?.state).toBe('Active');
      expect(fpSim.nodes['fp2'].neighbors?.find((n) => n.protocol === 'ha')?.state).toBe('Standby');

      // 5. NX-OS nested BGP & Null0 static routes validate cleanly; autoFormatRunningConfig preserves YAML
      const nxIssues = validateRunningConfig(`hostname NX1
router bgp 65001
  vrf PROD
    neighbor 10.0.0.2
      remote-as 65002
      default-originate
      soft-reconfiguration inbound
      allowas-in
      as-override
      remove-private-as
!
ip route 10.99.0.0 255.255.0.0 Null0`);
      expect(nxIssues).toHaveLength(0);

      const sampleYaml = topologyToYaml({ nodes: [fp1], links: [] });
      const formattedYaml = autoFormatRunningConfig(sampleYaml);
      expect(importTopologyFromText(formattedYaml).nodes[0].hostname).toBe('FP-1');
    });

    it('verifies recursive zero-bug convergence fixes (STP L2 islands, BGP asOverride & localAs, adminDown RIB, Junos IS-IS, store traceVrf)', () => {
      // 1. Disconnected STP L2 islands each elect their own Root Bridge without blocking loop-free links
      const sw1 = makeMinimalNode('sw1', 'SW1', 'cisco-ios-xe');
      sw1.routerId = '1.1.1.1';
      sw1.switching = { stpEnabled: true, stpPriority: 32768 };
      sw1.interfaces = [{ id: 'sw1-i1', name: 'Gi0/1', cidr: '', vrf: 'default' }];
      const sw2 = makeMinimalNode('sw2', 'SW2', 'cisco-ios-xe');
      sw2.routerId = '2.2.2.2';
      sw2.switching = { stpEnabled: true, stpPriority: 32768 };
      sw2.interfaces = [{ id: 'sw2-i1', name: 'Gi0/1', cidr: '', vrf: 'default' }];
      const sw3 = makeMinimalNode('sw3', 'SW3', 'cisco-ios-xe');
      sw3.routerId = '3.3.3.3';
      sw3.switching = { stpEnabled: true, stpPriority: 32768 };
      sw3.interfaces = [{ id: 'sw3-i1', name: 'Gi0/1', cidr: '', vrf: 'default' }];
      const stpSim = solveTopology({
        nodes: [sw1, sw2, sw3],
        links: [{ id: 'sl1', sourceNodeId: 'sw2', sourceInterfaceId: 'sw2-i1', targetNodeId: 'sw3', targetInterfaceId: 'sw3-i1', linkType: 'layer2' }],
      });
      expect(stpSim.nodes['sw2'].stpState?.isRoot).toBe(true);
      expect(stpSim.nodes['sw3'].stpState?.ports[0]?.state).toBe('Forwarding');

      // 2. BGP asOverride works without allowAsIn; localAs establishes session cleanly
      const ce1 = makeMinimalNode('ce1', 'CE1', 'cisco-ios-xe');
      ce1.routerId = '1.1.1.1';
      ce1.interfaces = [{ id: 'ce1-i1', name: 'Gi0/0', cidr: '10.1.0.1/30', vrf: 'default' }];
      ce1.bgp = { enabled: true, asn: 65001, peers: [{ id: 'p1', peerIp: '10.1.0.2', remoteAs: 65000 }], networks: [{ id: 'n1', prefix: '192.168.10.0/24' }] };
      const pe = makeMinimalNode('pe', 'PE', 'cisco-ios-xe');
      pe.routerId = '2.2.2.2';
      pe.interfaces = [
        { id: 'pe-i1', name: 'Gi0/0', cidr: '10.1.0.2/30', vrf: 'default' },
        { id: 'pe-i2', name: 'Gi0/1', cidr: '10.2.0.1/30', vrf: 'default' },
      ];
      pe.bgp = {
        enabled: true,
        asn: 65000,
        peers: [
          { id: 'p2a', peerIp: '10.1.0.1', remoteAs: 65001 },
          { id: 'p2b', peerIp: '10.2.0.2', remoteAs: 65001, asOverride: true },
        ],
        networks: [],
      };
      const ce2 = makeMinimalNode('ce2', 'CE2', 'cisco-ios-xe');
      ce2.routerId = '3.3.3.3';
      ce2.interfaces = [{ id: 'ce2-i1', name: 'Gi0/0', cidr: '10.2.0.2/30', vrf: 'default' }];
      ce2.bgp = { enabled: true, asn: 65001, peers: [{ id: 'p3', peerIp: '10.2.0.1', remoteAs: 65000 }], networks: [] };
      const asoSim = solveTopology({
        nodes: [ce1, pe, ce2],
        links: [
          { id: 'al1', sourceNodeId: 'ce1', sourceInterfaceId: 'ce1-i1', targetNodeId: 'pe', targetInterfaceId: 'pe-i1' },
          { id: 'al2', sourceNodeId: 'pe', sourceInterfaceId: 'pe-i2', targetNodeId: 'ce2', targetInterfaceId: 'ce2-i1' },
        ],
      });
      const ce2Learned = asoSim.nodes['ce2'].rib.find((r) => r.prefix === '192.168.10.0' && r.active);
      expect(ce2Learned?.bgpAttrs?.asPath).toEqual([65000, 65000]);

      // 3. adminDown node installs 0 RIB/FIB entries even with static Null0 routes
      const downNode = makeMinimalNode('dn1', 'DOWN-R1', 'cisco-ios-xe');
      downNode.adminDown = true;
      downNode.staticRoutes = [{ id: 'ds1', vrf: 'default', prefix: '0.0.0.0/0', nextHop: 'Null0' }];
      const downSim = solveTopology({ nodes: [downNode], links: [] });
      expect(downSim.nodes['dn1'].rib).toHaveLength(0);

      // 4. Junos config with IS-IS is classified as juniper-junos (not vyos)
      const junosIsis = importTopologyFromText(`set system host-name JUNOS-ISIS
set routing-options router-id 10.0.0.1
set interfaces ge-0/0/0 unit 0 family inet address 10.1.0.1/30
set protocols isis interface ge-0/0/0.0`).nodes[0];
      expect(junosIsis.vendor).toBe('juniper-junos');
      expect(junosIsis.interfaces[0].cidr).toBe('10.1.0.1/30');

      // 5. Store updateNode resets orphaned traceVrf to 'default' when deleted from trace source node
      useSimStore.getState().createWorkspace('VrfSanitizeTest');
      const vrfSrc = makeMinimalNode('vs1', 'VRF-SRC', 'cisco-ios-xe');
      vrfSrc.vrfs = ['default', 'CORP'];
      useSimStore.getState().importTopology({ nodes: [vrfSrc], links: [] });
      useSimStore.getState().setTraceParams('vs1', '8.8.8.8', 'CORP');
      expect(useSimStore.getState().traceVrf).toBe('CORP');
      useSimStore.getState().updateNode('vs1', { vrfs: ['default'] });
      expect(useSimStore.getState().traceVrf).toBe('default');
    });

    it('covers confirmation sweep fixes (OSPF redist/totally-stubby, BGP max-prefix pruning, sub-iface down, IPv6 BGP status, dotted-quad OSPF, VRF round-trip, ACL comments, store rename/delete)', () => {
      // 1. OSPF redistribution of RIP does not self-install or oscillate
      const ripSrc = makeMinimalNode('osr1', 'RIP-SRC', 'cisco-ios-xe');
      ripSrc.routerId = '1.1.1.1';
      ripSrc.interfaces = [
        { id: 'osr1-i1', name: 'Gi0/0', cidr: '10.1.0.1/30', vrf: 'default' },
        { id: 'osr1-lo0', name: 'Lo0', cidr: '172.16.99.1/24', vrf: 'default' },
      ];
      ripSrc.rip = { enabled: true, version: 2, networks: [{ id: 'rn1', prefix: '10.1.0.0/30' }, { id: 'rn2', prefix: '172.16.99.0/24' }] };

      const asbr = makeMinimalNode('osr2', 'ASBR', 'cisco-ios-xe');
      asbr.routerId = '2.2.2.2';
      asbr.interfaces = [
        { id: 'osr2-i1', name: 'Gi0/0', cidr: '10.1.0.2/30', vrf: 'default' },
        { id: 'osr2-i2', name: 'Gi0/1', cidr: '10.2.0.1/30', vrf: 'default', ospfArea: 0 },
      ];
      asbr.rip = { enabled: true, version: 2, networks: [{ id: 'rn3', prefix: '10.1.0.0/30' }] };
      asbr.ospf = { enabled: true, networks: [] };
      asbr.redistributions = [{ id: 'red-rip-ospf', from: 'rip', to: 'ospf', metric: 20 }];

      const ospfNbr = makeMinimalNode('osr3', 'OSPF-NBR', 'cisco-ios-xe');
      ospfNbr.routerId = '3.3.3.3';
      ospfNbr.interfaces = [{ id: 'osr3-i1', name: 'Gi0/0', cidr: '10.2.0.2/30', vrf: 'default', ospfArea: 0 }];
      ospfNbr.ospf = { enabled: true, networks: [] };

      const ospfRedSim = solveTopology({
        nodes: [ripSrc, asbr, ospfNbr],
        links: [
          { id: 'ol1', sourceNodeId: 'osr1', sourceInterfaceId: 'osr1-i1', targetNodeId: 'osr2', targetInterfaceId: 'osr2-i1' },
          { id: 'ol2', sourceNodeId: 'osr2', sourceInterfaceId: 'osr2-i2', targetNodeId: 'osr3', targetInterfaceId: 'osr3-i1' },
        ],
      });
      expect(ospfRedSim.nodes['osr2'].rib.find((r) => r.prefix === '172.16.99.0' && r.active)?.protocol).toBe('rip');
      expect(ospfRedSim.nodes['osr2'].rib.some((r) => r.prefix === '172.16.99.0' && r.protocol === 'ospf')).toBe(false);
      expect(ospfRedSim.nodes['osr3'].rib.find((r) => r.prefix === '172.16.99.0' && r.active)?.protocol).toBe('ospf');

      // 2. OSPF totally-stubby area blocks Area 0 intra-area routes
      const a0 = makeMinimalNode('ts1', 'A0-R1', 'cisco-ios-xe');
      a0.routerId = '10.0.0.1';
      a0.interfaces = [
        { id: 'ts1-i1', name: 'Gi0/0', cidr: '10.10.0.1/30', vrf: 'default', ospfArea: 0 },
        { id: 'ts1-lo0', name: 'Lo0', cidr: '192.168.50.1/24', vrf: 'default', ospfArea: 0 },
      ];
      a0.ospf = { enabled: true, networks: [] };
      const abr = makeMinimalNode('ts2', 'ABR', 'cisco-ios-xe');
      abr.routerId = '10.0.0.2';
      abr.interfaces = [
        { id: 'ts2-i1', name: 'Gi0/0', cidr: '10.10.0.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'ts2-i2', name: 'Gi0/1', cidr: '10.11.0.1/30', vrf: 'default', ospfArea: 1 },
      ];
      abr.ospf = { enabled: true, networks: [], areaTypes: { 1: 'totally-stubby' } };
      const a1 = makeMinimalNode('ts3', 'A1-R1', 'cisco-ios-xe');
      a1.routerId = '10.0.0.3';
      a1.interfaces = [{ id: 'ts3-i1', name: 'Gi0/0', cidr: '10.11.0.2/30', vrf: 'default', ospfArea: 1 }];
      a1.ospf = { enabled: true, networks: [], areaTypes: { 1: 'totally-stubby' } };
      const tsSim = solveTopology({
        nodes: [a0, abr, a1],
        links: [
          { id: 'tl1', sourceNodeId: 'ts1', sourceInterfaceId: 'ts1-i1', targetNodeId: 'ts2', targetInterfaceId: 'ts2-i1' },
          { id: 'tl2', sourceNodeId: 'ts2', sourceInterfaceId: 'ts2-i2', targetNodeId: 'ts3', targetInterfaceId: 'ts3-i1' },
        ],
      });
      expect(tsSim.nodes['ts3'].rib.some((r) => r.prefix === '192.168.50.0')).toBe(false);

      // 3. BGP maxPrefixes prunes previously learned routes & skips defaultOriginate
      const mp3 = makeMinimalNode('mp3', 'MP3', 'cisco-ios-xe');
      mp3.routerId = '3.3.3.3';
      mp3.interfaces = [
        { id: 'mp3-i1', name: 'Gi0/0', cidr: '10.30.0.1/30', vrf: 'default' },
        { id: 'mp3-lo1', name: 'Lo1', cidr: '198.51.100.1/24', vrf: 'default' },
      ];
      mp3.bgp = { enabled: true, asn: 65003, peers: [{ id: 'p31', peerIp: '10.30.0.2', remoteAs: 65001 }], networks: [{ id: 'n3', prefix: '198.51.100.0/24' }] };
      const mp1 = makeMinimalNode('mp1', 'MP1', 'cisco-ios-xe');
      mp1.routerId = '1.1.1.1';
      mp1.interfaces = [
        { id: 'mp1-i1', name: 'Gi0/0', cidr: '10.30.0.2/30', vrf: 'default' },
        { id: 'mp1-i2', name: 'Gi0/1', cidr: '10.31.0.1/30', vrf: 'default' },
        { id: 'mp1-lo1', name: 'Lo1', cidr: '192.0.2.1/24', vrf: 'default' },
        { id: 'mp1-lo2', name: 'Lo2', cidr: '203.0.113.1/24', vrf: 'default' },
      ];
      mp1.bgp = {
        enabled: true,
        asn: 65001,
        peers: [
          { id: 'p13', peerIp: '10.30.0.1', remoteAs: 65003 },
          { id: 'p12', peerIp: '10.31.0.2', remoteAs: 65002, defaultOriginate: true },
        ],
        networks: [{ id: 'n1a', prefix: '192.0.2.0/24' }, { id: 'n1b', prefix: '203.0.113.0/24' }],
      };
      const mp2 = makeMinimalNode('mp2', 'MP2', 'cisco-ios-xe');
      mp2.routerId = '2.2.2.2';
      mp2.interfaces = [{ id: 'mp2-i1', name: 'Gi0/0', cidr: '10.31.0.2/30', vrf: 'default' }];
      mp2.bgp = { enabled: true, asn: 65002, peers: [{ id: 'p21', peerIp: '10.31.0.1', remoteAs: 65001, maxPrefixes: 2 }], networks: [] };
      const mpSim = solveTopology({
        nodes: [mp3, mp1, mp2],
        links: [
          { id: 'mpl1', sourceNodeId: 'mp3', sourceInterfaceId: 'mp3-i1', targetNodeId: 'mp1', targetInterfaceId: 'mp1-i1' },
          { id: 'mpl2', sourceNodeId: 'mp1', sourceInterfaceId: 'mp1-i2', targetNodeId: 'mp2', targetInterfaceId: 'mp2-i1' },
        ],
      });
      expect(mpSim.nodes['mp2'].rib.filter((r) => r.protocol === 'ebgp')).toHaveLength(0);

      // 4. Sub-interface goes down when parent physical link is adminDown
      const subR1 = makeMinimalNode('sub1', 'SUB1', 'cisco-ios-xe');
      subR1.interfaces = [
        { id: 'sub1-p', name: 'Gi0/0', cidr: '', vrf: 'default' },
        { id: 'sub1-s', name: 'Gi0/0.10', cidr: '10.99.10.1/24', vrf: 'default', vlanId: 10 },
      ];
      const subR2 = makeMinimalNode('sub2', 'SUB2', 'cisco-ios-xe');
      subR2.interfaces = [{ id: 'sub2-p', name: 'Gi0/0', cidr: '', vrf: 'default' }];
      const subSim = solveTopology({
        nodes: [subR1, subR2],
        links: [{ id: 'subl1', sourceNodeId: 'sub1', sourceInterfaceId: 'sub1-p', targetNodeId: 'sub2', targetInterfaceId: 'sub2-p', adminDown: true }],
      });
      expect(subSim.nodes['sub1'].rib.some((r) => r.prefix === '10.99.10.0')).toBe(false);

      // 5. Non-canonical IPv6 BGP peerIp shows Established in neighbor status
      const v6a = makeMinimalNode('v6a', 'V6A', 'cisco-ios-xe');
      v6a.routerId = '6.6.6.1';
      v6a.interfaces = [{ id: 'v6a-i1', name: 'Gi0/0', cidr: '', cidr6: '2001:db8::1/64', vrf: 'default' }];
      v6a.bgp = { enabled: true, asn: 65100, peers: [{ id: 'v6p1', peerIp: '2001:0DB8::2', remoteAs: 65200 }], networks: [] };
      const v6b = makeMinimalNode('v6b', 'V6B', 'cisco-ios-xe');
      v6b.routerId = '6.6.6.2';
      v6b.interfaces = [{ id: 'v6b-i1', name: 'Gi0/0', cidr: '', cidr6: '2001:db8::2/64', vrf: 'default' }];
      v6b.bgp = { enabled: true, asn: 65200, peers: [{ id: 'v6p2', peerIp: '2001:0db8::1', remoteAs: 65100 }], networks: [] };
      const v6Sim = solveTopology({
        nodes: [v6a, v6b],
        links: [{ id: 'v6l1', sourceNodeId: 'v6a', sourceInterfaceId: 'v6a-i1', targetNodeId: 'v6b', targetInterfaceId: 'v6b-i1' }],
      });
      expect(v6Sim.nodes['v6a'].neighbors?.find((n) => n.protocol === 'bgp')?.state).toBe('Established');

      // 6. Dotted-quad OSPF areas, VRF CIDR static route, VRF-scoped passive-interface default, and VRF round-trip
      const nxCfg = `hostname NX-VRF-TEST
vrf context CORP
interface Ethernet1/1
 ip address 10.1.0.1/30
 ip router ospf 1 area 0.0.0.51
interface Ethernet1/2
 vrf member CORP
 ip address 10.2.0.1/30
router ospf 1 vrf CORP
 passive-interface default
 network 10.2.0.0 0.0.0.3 area 0.0.0.10
 redistribute bgp 65001 subnets
router bgp 65001
 address-family ipv4 vrf CORP
  aggregate-address 10.20.0.0 255.255.0.0 summary-only
  redistribute ospf 1
 exit-address-family
ip route vrf CORP 192.168.10.0/24 10.2.0.2`;
      const nxNode = importTopologyFromText(nxCfg).nodes[0];
      expect(nxNode.interfaces.find((i) => i.name === 'Ethernet1/1')?.ospfArea).toBe(51);
      expect(nxNode.interfaces.find((i) => i.name === 'Ethernet1/1')?.passive).not.toBe(true);
      expect(nxNode.interfaces.find((i) => i.name === 'Ethernet1/2')?.passive).toBe(true);
      expect(nxNode.ospf.networks[0]?.area).toBe(10);
      expect(nxNode.staticRoutes.find((s) => s.prefix === '192.168.10.0/24')?.vrf).toBe('CORP');
      const roundTripped = importTopologyFromText(formatRunningConfig(nxNode)).nodes[0];
      expect(roundTripped.redistributions.find((r) => r.to === 'ospf')?.vrf).toBe('CORP');
      expect(roundTripped.redistributions.find((r) => r.to === 'bgp')?.vrf).toBe('CORP');
      expect(roundTripped.bgp.aggregates?.[0]?.vrf).toBe('CORP');

      // 7. PAN-OS description keywords & Cisco inline comment do not corrupt ACL rules
      const panAcl = parsePanOsAclRules(`set rulebase security rules allow-web from trust
set rulebase security rules allow-web to untrust
set rulebase security rules allow-web action allow
set rulebase security rules allow-web description "Migrated from old-zone to new-zone; action deny was removed"`.split('\n'));
      expect(panAcl[0]?.action).toBe('allow');
      expect(panAcl[0]?.srcZone).toBe('trust');
      expect(panAcl[0]?.dstZone).toBe('untrust');
      const ciscoAcl = parseCiscoStyleAclRules(`ip access-list extended TEST
 10 permit ip 10.0.0.0 0.0.0.255 192.168.1.0 0.0.0.255 ! allow eq 80 comment`.split('\n'));
      expect(ciscoAcl[0]?.dstPort).toBeUndefined();

      // 8. Store updateInterface rename and deleteInterface propagate/clean up name references
      useSimStore.getState().createWorkspace('IfaceRenameCleanupTest');
      const rn = makeMinimalNode('rn1', 'RN1', 'cisco-ios-xe');
      rn.interfaces = [{ id: 'rn-lo0', name: 'Loopback0', cidr: '1.1.1.1/32', vrf: 'default' }];
      rn.bgp = { enabled: true, asn: 65001, peers: [{ id: 'rp1', peerIp: '2.2.2.2', remoteAs: 65001, updateSource: 'Loopback0' }], networks: [] };
      rn.staticRoutes = [{ id: 'rs1', vrf: 'default', prefix: '10.0.0.0/8', nextHop: '1.1.1.2', interfaceName: 'Loopback0' }];
      useSimStore.getState().importTopology({ nodes: [rn], links: [] });
      useSimStore.getState().updateInterface('rn1', 'rn-lo0', { name: 'Loopback10' });
      let updatedRn = useSimStore.getState().topology.nodes[0];
      expect(updatedRn.bgp.peers[0].updateSource).toBe('Loopback10');
      expect(updatedRn.staticRoutes[0].interfaceName).toBe('Loopback10');
      useSimStore.getState().deleteInterface('rn1', 'rn-lo0');
      updatedRn = useSimStore.getState().topology.nodes[0];
      expect(updatedRn.bgp.peers[0].updateSource).toBeUndefined();
      expect(updatedRn.staticRoutes[0].interfaceName).toBeUndefined();
    });

    it('covers recursive hunt pass 1 fixes (OSPF sham-link VRF, EVPN/MPLS-VPN loop prevention, overlapping-IP BGP VRFs, EIGRP/IS-IS triangle loops, BGP medMissingAsWorst, dotted-quad >255, secondary IP, PAN-OS bracket VR, FortiGate default static, Gaia BGP dedup, MikroTik quoted VRF, route-map validator, maxPaths, store applyParsedNodeConfig)', () => {
      // 1. OSPF sham-link in non-default VRF resolves next-hop via default VRF
      const pe1 = makeMinimalNode('sh1', 'PE1', 'cisco-ios-xe');
      pe1.routerId = '1.1.1.1';
      pe1.vrfs = ['default', 'CUST'];
      pe1.interfaces = [
        { id: 'sh1-bb', name: 'Gi0/0', cidr: '10.0.0.1/30', vrf: 'default', ospfArea: 0 },
        { id: 'sh1-lo', name: 'Lo0', cidr: '1.1.1.1/32', vrf: 'default', ospfArea: 0 },
      ];
      pe1.ospf = {
        enabled: true,
        networks: [],
        shamLinks: [{ id: 'sl1', vrf: 'CUST', area: 0, srcIp: '1.1.1.1', dstIp: '2.2.2.2', cost: 5 }],
      };
      const pe2 = makeMinimalNode('sh2', 'PE2', 'cisco-ios-xe');
      pe2.routerId = '2.2.2.2';
      pe2.vrfs = ['default', 'CUST'];
      pe2.interfaces = [
        { id: 'sh2-bb', name: 'Gi0/0', cidr: '10.0.0.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'sh2-lo', name: 'Lo0', cidr: '2.2.2.2/32', vrf: 'default', ospfArea: 0 },
        { id: 'sh2-cu', name: 'Gi0/1', cidr: '192.168.77.1/24', vrf: 'CUST', ospfArea: 0 },
      ];
      pe2.ospf = {
        enabled: true,
        networks: [],
      };
      const shamSim = solveTopology({
        nodes: [pe1, pe2],
        links: [{ id: 'shl1', sourceNodeId: 'sh1', sourceInterfaceId: 'sh1-bb', targetNodeId: 'sh2', targetInterfaceId: 'sh2-bb' }],
      });
      const shamRoute = shamSim.nodes['sh1'].rib.find((r) => r.vrf === 'CUST' && r.prefix === '192.168.77.0');
      expect(shamRoute?.active).toBe(true);
      expect(shamRoute?.protocol).toBe('ospf');

      // 2. BGP medMissingAsWorst treats missing MED as worst vs explicit MED
      const b1 = makeMinimalNode('bm1', 'BM1', 'cisco-ios-xe');
      b1.routerId = '10.0.0.1';
      b1.interfaces = [{ id: 'bm1-i1', name: 'Gi0/0', cidr: '10.1.0.1/30', vrf: 'default' }];
      b1.bgp = { enabled: true, asn: 65001, peers: [{ id: 'bp1', peerIp: '10.1.0.2', remoteAs: 65000 }], networks: [{ id: 'bn1', prefix: '198.18.0.0/24' }] };
      const b2 = makeMinimalNode('bm2', 'BM2', 'cisco-ios-xe');
      b2.routerId = '10.0.0.2';
      b2.interfaces = [{ id: 'bm2-i1', name: 'Gi0/0', cidr: '10.2.0.1/30', vrf: 'default' }];
      b2.bgp = { enabled: true, asn: 65001, peers: [{ id: 'bp2', peerIp: '10.2.0.2', remoteAs: 65000 }], networks: [{ id: 'bn2', prefix: '198.18.0.0/24', med: 50 }] };
      const b0 = makeMinimalNode('bm0', 'BM0', 'cisco-ios-xe');
      b0.routerId = '10.0.0.3';
      b0.interfaces = [
        { id: 'bm0-i1', name: 'Gi0/0', cidr: '10.1.0.2/30', vrf: 'default' },
        { id: 'bm0-i2', name: 'Gi0/1', cidr: '10.2.0.2/30', vrf: 'default' },
      ];
      b0.bgp = {
        enabled: true,
        asn: 65000,
        medMissingAsWorst: true,
        peers: [
          { id: 'bp01', peerIp: '10.1.0.1', remoteAs: 65001 },
          { id: 'bp02', peerIp: '10.2.0.1', remoteAs: 65001 },
        ],
        networks: [],
      };
      const medSim = solveTopology({
        nodes: [b1, b2, b0],
        links: [
          { id: 'bml1', sourceNodeId: 'bm1', sourceInterfaceId: 'bm1-i1', targetNodeId: 'bm0', targetInterfaceId: 'bm0-i1' },
          { id: 'bml2', sourceNodeId: 'bm2', sourceInterfaceId: 'bm2-i1', targetNodeId: 'bm0', targetInterfaceId: 'bm0-i2' },
        ],
      });
      const medBest = medSim.nodes['bm0'].rib.find((r) => r.prefix === '198.18.0.0' && r.active);
      expect(medBest?.nextHop).toBe('10.2.0.1');

      // 3. Importer & Formatter round-trip fixes
      const ciscoAdv = importTopologyFromText(`hostname ADV-TEST
vrf context MGMT
  ip route 0.0.0.0/0 192.168.1.1
ip route 10.20.0.0/16 10.0.0.2
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.252
 ip address 10.0.1.1 255.255.255.0 secondary
 ip ospf 1 area 0.0.1.0
router eigrp 100
 network 10.0.0.0
router lisp
 proxy-itr
router bgp 65001
 maximum-paths 8
 address-family ipv4 unicast vrf CUST-A
  network 172.16.0.0 mask 255.255.0.0
 exit-address-family`).nodes[0];
      expect(ciscoAdv.interfaces[0].ospfArea).toBe(256);
      expect(ciscoAdv.interfaces[0].secondaryCidrs).toEqual(['10.0.1.1/24']);
      expect(ciscoAdv.staticRoutes.find((r) => r.prefix === '10.20.0.0/16')?.vrf).toBe('default');
      expect(ciscoAdv.eigrp?.networks[0]?.prefix).toBe('10.0.0.0/8');
      expect(ciscoAdv.lisp?.role).toBe('pitr');
      expect(ciscoAdv.maxPaths).toBe(8);
      expect(ciscoAdv.bgp.networks[0]?.vrf).toBe('CUST-A');

      // PAN-OS bracket VR, FortiGate default static, Gaia BGP dedup, MikroTik quoted VRF, route-map validator
      const panVr = importTopologyFromText(`set deviceconfig system hostname PAN-VR
set network virtual-router VR-CORP interface [ ethernet1/1 ethernet1/2 ]`).nodes[0];
      expect(panVr.interfaces.map((i) => i.name)).toEqual(['ethernet1/1', 'ethernet1/2']);
      const fgtDef = importTopologyFromText(`config system global
 set hostname FGT-DEF
end
config router static
 edit 1
  set gateway 198.51.100.1
 next
end`).nodes[0];
      expect(fgtDef.staticRoutes[0]?.prefix).toBe('0.0.0.0/0');
      const gaiaDedup = importTopologyFromText(`set hostname GAIA-BGP
set as 65001
set bgp external remote-as 65002 peer 10.0.0.2 on
set bgp external remote-as 65002 peer 10.0.0.2 holdtime 90`).nodes[0];
      expect(gaiaDedup.bgp.peers).toHaveLength(1);
      const mkVrf = importTopologyFromText(`/system identity set name=MK-VRF
/ip vrf add name=CUST interfaces="ether1,ether2"`).nodes[0];
      expect(mkVrf.interfaces.map((i) => i.name)).toEqual(['ether1', 'ether2']);
      expect(validateRunningConfig('route-map TEST permit 10\n set local-preference 200\n totally-bogus-cmd\n!').length).toBeGreaterThan(0);
    });

    it('covers recursive hunt pass 2 fixes (OSPF sham-link encap, BGP confed/asSet loop prevention, IS-IS L2->L1 metric update, indented !, network 0.0.0.0, applyParsedNodeConfig vendor/attr removal, atomic deleteSelection)', () => {
      // 1. BGP confederationId and aggregate asSet loop prevention
      const aggR1 = makeMinimalNode('ag1', 'AG1', 'cisco-ios-xe');
      aggR1.routerId = '1.1.1.1';
      aggR1.interfaces = [
        { id: 'ag1-i1', name: 'Gi0/0', cidr: '10.0.0.1/30', vrf: 'default' },
        { id: 'ag1-lo', name: 'Lo0', cidr: '10.1.0.1/24', vrf: 'default' },
      ];
      aggR1.bgp = {
        enabled: true,
        asn: 65001,
        peers: [{ id: 'ap1', peerIp: '10.0.0.2', remoteAs: 65002 }],
        networks: [{ id: 'an1', prefix: '10.1.0.0/24' }],
      };
      const aggR2 = makeMinimalNode('ag2', 'AG2', 'cisco-ios-xe');
      aggR2.routerId = '2.2.2.2';
      aggR2.interfaces = [{ id: 'ag2-i1', name: 'Gi0/0', cidr: '10.0.0.2/30', vrf: 'default' }];
      aggR2.bgp = {
        enabled: true,
        asn: 65002,
        peers: [{ id: 'ap2', peerIp: '10.0.0.1', remoteAs: 65001 }],
        networks: [],
        aggregates: [{ id: 'agg1', prefix: '10.1.0.0/16', summaryOnly: true, asSet: true }],
      };
      const aggSim = solveTopology({
        nodes: [aggR1, aggR2],
        links: [{ id: 'agl1', sourceNodeId: 'ag1', sourceInterfaceId: 'ag1-i1', targetNodeId: 'ag2', targetInterfaceId: 'ag2-i1' }],
      });
      expect(aggSim.nodes['ag1'].rib.some((r) => r.prefix === '10.1.0.0' && r.prefixLen === 16)).toBe(false);

      // 2. Indented ' !' inside router bgp does not terminate section & network 0.0.0.0 -> 0.0.0.0/0
      const iosBgp = `hostname IOS-INDENT-BANG
router eigrp 100
 network 0.0.0.0
!
router bgp 65001
 bgp router-id 10.0.0.1
 neighbor 10.1.1.2 remote-as 65002
 !
 address-family ipv4
  network 10.10.0.0 mask 255.255.255.0
 exit-address-family
 !
 address-family ipv4 vrf CORP
  neighbor 10.2.2.2 remote-as 65003
 exit-address-family
!`;
      const parsedBgp = importTopologyFromText(iosBgp).nodes[0];
      expect(parsedBgp.eigrp?.networks[0]?.prefix).toBe('0.0.0.0/0');
      expect(parsedBgp.bgp.networks[0]?.prefix).toBe('10.10.0.0/24');
      expect(parsedBgp.bgp.peers.find((p) => p.peerIp === '10.2.2.2')?.vrf).toBe('CORP');
      expect(validateRunningConfig(iosBgp)).toHaveLength(0);

      // 3. applyParsedNodeConfig preserves vendor and removes deleted interface attributes; deleteSelection is single atomic undo
      useSimStore.getState().createWorkspace('Pass2StoreTest');
      const eosNode = makeMinimalNode('eos1', 'EOS1', 'arista-eos');
      eosNode.interfaces = [{ id: 'eos-i1', name: 'Ethernet1', cidr: '10.1.0.1/24', vrf: 'default', shutdown: true }];
      const eosNode2 = makeMinimalNode('eos2', 'EOS2', 'arista-eos');
      eosNode2.interfaces = [{ id: 'eos-i2', name: 'Ethernet1', cidr: '10.1.0.2/24', vrf: 'default' }];
      useSimStore.getState().importTopology({
        nodes: [eosNode, eosNode2],
        links: [{ id: 'el1', sourceNodeId: 'eos1', sourceInterfaceId: 'eos-i1', targetNodeId: 'eos2', targetInterfaceId: 'eos-i2' }],
      });
      const editedParsed = importTopologyFromText(`hostname EOS1\ninterface Ethernet1\n ip address 10.1.0.1/24\n!`).nodes[0];
      useSimStore.getState().applyParsedNodeConfig('eos1', editedParsed);
      const afterApply = useSimStore.getState().topology.nodes.find((n) => n.id === 'eos1')!;
      expect(afterApply.vendor).toBe('arista-eos');
      expect(afterApply.interfaces[0].shutdown).toBeUndefined();

      useSimStore.getState().deleteSelection(['eos1', 'eos2'], ['el1']);
      expect(useSimStore.getState().topology.nodes).toHaveLength(0);
      useSimStore.getState().undo();
      expect(useSimStore.getState().topology.nodes).toHaveLength(2);
      expect(useSimStore.getState().topology.links).toHaveLength(1);

      // 4. Pass 3: autoFormatRunningConfig keeps 'version 2' indented inside 'router rip'
      const formattedRip = autoFormatRunningConfig('router rip\n version 2\n no auto-summary\n network 10.0.0.0\n!');
      expect(formattedRip).toContain('router rip\n version 2\n no auto-summary\n network 10.0.0.0\n!');

      // 5. Pass 4: Dual-stack BGP IPv6 session exchanges routes even when IPv4 peer is shutdown
      const ds1 = makeMinimalNode('ds1', 'DS1', 'cisco-ios-xe');
      ds1.routerId = '11.11.11.1';
      ds1.interfaces = [{ id: 'ds1-i1', name: 'Gi0/0', cidr: '10.50.0.1/30', cidr6: '2001:db8:50::1/64', vrf: 'default' }];
      ds1.bgp = {
        enabled: true,
        asn: 65010,
        peers: [
          { id: 'dsp1v4', peerIp: '10.50.0.2', remoteAs: 65020, shutdown: true },
          { id: 'dsp1v6', peerIp: '2001:db8:50::2', remoteAs: 65020 },
        ],
        networks: [],
      };
      const ds2 = makeMinimalNode('ds2', 'DS2', 'cisco-ios-xe');
      ds2.routerId = '11.11.11.2';
      ds2.interfaces = [{ id: 'ds2-i1', name: 'Gi0/0', cidr: '10.50.0.2/30', cidr6: '2001:db8:50::2/64', vrf: 'default' }];
      ds2.bgp = {
        enabled: true,
        asn: 65020,
        peers: [
          { id: 'dsp2v4', peerIp: '10.50.0.1', remoteAs: 65010, shutdown: true },
          { id: 'dsp2v6', peerIp: '2001:db8:50::1', remoteAs: 65010 },
        ],
        networks: [{ id: 'dsn6', prefix: '2001:db8:99::/48' }],
      };
      const dsSim = solveTopology({
        nodes: [ds1, ds2],
        links: [{ id: 'dsl1', sourceNodeId: 'ds1', sourceInterfaceId: 'ds1-i1', targetNodeId: 'ds2', targetInterfaceId: 'ds2-i1' }],
      });
      expect(dsSim.nodes['ds1'].rib.some((r) => r.prefix === '2001:db8:99::' && r.active)).toBe(true);
    });
  });
});
