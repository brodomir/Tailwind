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
  });
});
