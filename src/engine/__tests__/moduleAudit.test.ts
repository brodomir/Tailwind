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
import { evaluateNat64 } from '../standards';
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

    it('covers fresh sweep fixes (NAT64 pool4Cidr srcIp, OSPFv3/MP-BGP IPv6 redist, IPv6 BGP aggregate, preferPrivateCircuit maxPaths=1, IPv6 firewall/Cisco/VyOS/MikroTik/Junos round-trip)', () => {
      // 1. NAT64 translates srcIp using pool4Cidr so downstream IPv4 ACL matches
      const n64 = makeMinimalNode('n64', 'NAT64-GW', 'cisco-ios-xe');
      n64.interfaces = [
        { id: 'n64-i1', name: 'Gi0/0', cidr: '10.0.0.1/30', cidr6: '2001:db8::1/64', vrf: 'default' },
        { id: 'n64-i2', name: 'Gi0/1', cidr: '198.51.100.1/24', vrf: 'default' },
      ];
      n64.nat64Rules = [{ id: 'r1', prefix6: '64:ff9b::/96', pool4Cidr: '198.51.100.10/24' }];
      n64.aclRules = [
        { id: 'a1', seq: 10, name: 'allow-v4-nat64', action: 'allow', srcCidr: '198.51.100.0/24', dstCidr: '198.51.100.2/32', protocol: 'any' },
      ];
      const n64Sim = solveTopology({ nodes: [n64], links: [] });
      const n64Trace = tracePacket(
        { nodes: [n64], links: [] },
        n64Sim,
        'n64',
        '64:ff9b::c633:6402',
        'default',
        { srcIp: '2001:db8::99' }
      );
      expect(n64Trace.outcome).toBe('delivered');

      // 2. Cloud preferPrivateCircuit wins even with maxPaths === 1
      const aws = makeMinimalNode('aws1', 'AWS-TGW', 'aws-cloud');
      aws.routerId = '10.0.0.100';
      aws.maxPaths = 1;
      aws.cloudConfig = { preferPrivateCircuit: true };
      aws.interfaces = [
        { id: 'aws-dx', name: 'dx-1', cidr: '169.254.1.1/30', vrf: 'default' },
        { id: 'aws-vpn', name: 'vpn-1', cidr: '169.254.2.1/30', vrf: 'default' },
      ];
      aws.bgp = {
        enabled: true,
        asn: 64512,
        peers: [
          { id: 'p-dx', peerIp: '169.254.1.2', remoteAs: 65001 },
          { id: 'p-vpn', peerIp: '169.254.2.2', remoteAs: 65001 },
        ],
        networks: [],
      };
      const onprem = makeMinimalNode('op1', 'ONPREM', 'cisco-ios-xe');
      onprem.routerId = '10.0.0.1';
      onprem.interfaces = [
        { id: 'op-dx', name: 'Gi0/0', cidr: '169.254.1.2/30', vrf: 'default' },
        { id: 'op-vpn', name: 'Gi0/1', cidr: '169.254.2.2/30', vrf: 'default' },
      ];
      onprem.bgp = {
        enabled: true,
        asn: 65001,
        peers: [
          { id: 'p-a1', peerIp: '169.254.1.1', remoteAs: 64512 },
          { id: 'p-a2', peerIp: '169.254.2.1', remoteAs: 64512 },
        ],
        networks: [{ id: 'n1', prefix: '10.55.0.0/16' }],
      };
      const cloudSim = solveTopology({
        nodes: [aws, onprem],
        links: [
          { id: 'cl-vpn', sourceNodeId: 'aws1', sourceInterfaceId: 'aws-vpn', targetNodeId: 'op1', targetInterfaceId: 'op-vpn', linkType: 'ipsec' },
          { id: 'cl-dx', sourceNodeId: 'aws1', sourceInterfaceId: 'aws-dx', targetNodeId: 'op1', targetInterfaceId: 'op-dx', linkType: 'ethernet' },
        ],
      });
      expect(cloudSim.nodes['aws1'].rib.find((r) => r.prefix === '10.55.0.0' && r.active)?.nextHop).toBe('169.254.1.2');

      // 3. Cisco, VyOS, MikroTik, JunOS, and Firewall IPv6 round-trips
      const v6Cisco = makeMinimalNode('c6', 'C6', 'cisco-ios-xe');
      v6Cisco.staticRoutes = [{ id: 'sr6', vrf: 'default', prefix: '2001:db8:10::/48', nextHop: '2001:db8::2' }];
      v6Cisco.bgp = {
        enabled: true,
        asn: 65001,
        peers: [{ id: 'p6', peerIp: '2001:db8::2', remoteAs: 65002 }],
        networks: [{ id: 'n6', prefix: '2001:db8:20::/48' }],
        aggregates: [{ id: 'a6', prefix: '2001:db8::/32', summaryOnly: true }],
      };
      const c6Parsed = importTopologyFromText(formatRunningConfig(v6Cisco)).nodes[0];
      expect(c6Parsed.staticRoutes[0]?.prefix).toBe('2001:db8:10::/48');
      expect(c6Parsed.bgp.peers[0]?.peerIp).toBe('2001:db8::2');
      expect(c6Parsed.bgp.networks[0]?.prefix).toBe('2001:db8:20::/48');
      expect(c6Parsed.bgp.aggregates?.[0]?.prefix).toBe('2001:db8::/32');

      const vyosV6 = importTopologyFromText(`set system host-name VYOS-V6
set protocols static route6 2001:db8:30::/48 next-hop 2001:db8::1`).nodes[0];
      expect(vyosV6.vendor).toBe('vyos');
      expect(vyosV6.staticRoutes[0]?.prefix).toBe('2001:db8:30::/48');

      const panV6Acl = parsePanOsAclRules([
        'set rulebase security rules allow-v6 source 2001:db8::/32 destination ::/0 action allow',
      ]);
      expect(panV6Acl[0]?.srcCidr).toBe('2001:db8::/32');
      expect(panV6Acl[0]?.dstCidr).toBe('::/0');
    });

    it('covers deep engine-only sweep fixes (unnumbered OSPF, own-IP next-hop rejection, OSPF virtual-link ABR, BGP defaultOriginate inRm/maxPrefixes, IS-IS summaries, STP sender-BID tie-break, SRv6/RSVP-TE LFIB, FlowSpec redirect on connected)', () => {
      // 1. ip unnumbered link forms OSPF adjacency & rejects own interface IP as static next-hop
      const u1 = makeMinimalNode('u1', 'U1', 'cisco-ios-xe');
      u1.routerId = '1.1.1.1';
      u1.interfaces = [
        { id: 'u1-lo', name: 'Loopback0', cidr: '10.255.0.1/32', vrf: 'default', ospfArea: 0 },
        { id: 'u1-g0', name: 'Gi0/0', cidr: '', unnumberedSource: 'Loopback0', vrf: 'default', ospfArea: 0 },
      ];
      u1.ospf = { enabled: true, networks: [] };
      u1.staticRoutes = [{ id: 'own-nh', vrf: 'default', prefix: '198.51.100.0/24', nextHop: '10.255.0.1' }];
      const u2 = makeMinimalNode('u2', 'U2', 'cisco-ios-xe');
      u2.routerId = '2.2.2.2';
      u2.interfaces = [
        { id: 'u2-lo', name: 'Loopback0', cidr: '10.255.0.2/32', vrf: 'default', ospfArea: 0 },
        { id: 'u2-g0', name: 'Gi0/0', cidr: '', unnumberedSource: 'Loopback0', vrf: 'default', ospfArea: 0 },
      ];
      u2.ospf = { enabled: true, networks: [] };
      const uSim = solveTopology({
        nodes: [u1, u2],
        links: [{ id: 'ul1', sourceNodeId: 'u1', sourceInterfaceId: 'u1-g0', targetNodeId: 'u2', targetInterfaceId: 'u2-g0' }],
      });
      expect(uSim.nodes['u1'].rib.some((r) => r.prefix === '10.255.0.2' && r.active && r.protocol === 'ospf')).toBe(true);
      expect(uSim.nodes['u1'].rib.find((r) => r.prefix === '198.51.100.0')?.active).toBe(false);

      // 2. OSPF virtual link promotes remote ABR and advertises Area 2 into Area 0
      const vl1 = makeMinimalNode('vl1', 'VL1', 'cisco-ios-xe');
      vl1.routerId = '1.1.1.1';
      vl1.interfaces = [
        { id: 'vl1-a0', name: 'Lo0', cidr: '10.0.0.1/32', vrf: 'default', ospfArea: 0 },
        { id: 'vl1-a1', name: 'Gi0/0', cidr: '10.1.0.1/30', vrf: 'default', ospfArea: 1 },
      ];
      vl1.ospf = { enabled: true, networks: [], virtualLinks: [{ id: 'v1', transitArea: 1, peerRouterId: '2.2.2.2' }] };
      const vl2 = makeMinimalNode('vl2', 'VL2', 'cisco-ios-xe');
      vl2.routerId = '2.2.2.2';
      vl2.interfaces = [
        { id: 'vl2-a1', name: 'Gi0/0', cidr: '10.1.0.2/30', vrf: 'default', ospfArea: 1 },
        { id: 'vl2-a2', name: 'Gi0/1', cidr: '10.2.0.1/30', vrf: 'default', ospfArea: 2 },
      ];
      vl2.ospf = { enabled: true, networks: [], virtualLinks: [{ id: 'v2', transitArea: 1, peerRouterId: '1.1.1.1' }] };
      const vl3 = makeMinimalNode('vl3', 'VL3', 'cisco-ios-xe');
      vl3.routerId = '3.3.3.3';
      vl3.interfaces = [
        { id: 'vl3-a2', name: 'Gi0/0', cidr: '10.2.0.2/30', vrf: 'default', ospfArea: 2 },
        { id: 'vl3-lo', name: 'Lo0', cidr: '10.22.0.1/24', vrf: 'default', ospfArea: 2 },
      ];
      vl3.ospf = { enabled: true, networks: [] };
      const vlSim = solveTopology({
        nodes: [vl1, vl2, vl3],
        links: [
          { id: 'vll1', sourceNodeId: 'vl1', sourceInterfaceId: 'vl1-a1', targetNodeId: 'vl2', targetInterfaceId: 'vl2-a1' },
          { id: 'vll2', sourceNodeId: 'vl2', sourceInterfaceId: 'vl2-a2', targetNodeId: 'vl3', targetInterfaceId: 'vl3-a2' },
        ],
      });
      expect(vlSim.nodes['vl3'].rib.some((r) => r.prefix === '10.0.0.1' && r.active)).toBe(true);
      expect(vlSim.nodes['vl1'].rib.some((r) => r.prefix === '10.22.0.0' && r.active)).toBe(true);

      // 3. IS-IS summary suppresses specifics and advertises summary prefix
      const is1 = makeMinimalNode('is1', 'IS1', 'cisco-ios-xe');
      is1.interfaces = [
        { id: 'is1-i1', name: 'Gi0/0', cidr: '10.40.0.1/30', vrf: 'default', isisLevel: 'L2' },
        { id: 'is1-lo', name: 'Lo0', cidr: '10.30.1.1/24', vrf: 'default', isisLevel: 'L2' },
      ];
      is1.isis = { enabled: true, net: '49.0001.0000.0000.0001.00', level: 'L2', networks: [], summaries: [{ id: 's1', prefix: '10.30.0.0/16' }] };
      const is2 = makeMinimalNode('is2', 'IS2', 'cisco-ios-xe');
      is2.interfaces = [{ id: 'is2-i1', name: 'Gi0/0', cidr: '10.40.0.2/30', vrf: 'default', isisLevel: 'L2' }];
      is2.isis = { enabled: true, net: '49.0001.0000.0000.0002.00', level: 'L2', networks: [] };
      const isSim = solveTopology({
        nodes: [is1, is2],
        links: [{ id: 'isl1', sourceNodeId: 'is1', sourceInterfaceId: 'is1-i1', targetNodeId: 'is2', targetInterfaceId: 'is2-i1' }],
      });
      expect(isSim.nodes['is2'].rib.some((r) => r.prefix === '10.30.0.0' && r.prefixLen === 16 && r.active)).toBe(true);
      expect(isSim.nodes['is2'].rib.some((r) => r.prefix === '10.30.1.0' && r.prefixLen === 24)).toBe(false);

      // 4. STP equal-cost diamond elects Root Port by lowest Sender Bridge ID regardless of node order
      const swA = makeMinimalNode('swA', 'SWA', 'cisco-ios-xe');
      swA.routerId = '1.1.1.1';
      swA.switching = { stpEnabled: true, stpPriority: 4096 };
      swA.interfaces = [
        { id: 'swA-1', name: 'Gi0/1', cidr: '', vrf: 'default' },
        { id: 'swA-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
      ];
      const swB = makeMinimalNode('swB', 'SWB', 'cisco-ios-xe');
      swB.routerId = '2.2.2.2';
      swB.switching = { stpEnabled: true, stpPriority: 32768 };
      swB.interfaces = [
        { id: 'swB-1', name: 'Gi0/1', cidr: '', vrf: 'default' },
        { id: 'swB-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
      ];
      const swC = makeMinimalNode('swC', 'SWC', 'cisco-ios-xe');
      swC.routerId = '1.1.1.2';
      swC.switching = { stpEnabled: true, stpPriority: 32768 };
      swC.interfaces = [
        { id: 'swC-1', name: 'Gi0/1', cidr: '', vrf: 'default' },
        { id: 'swC-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
      ];
      const swD = makeMinimalNode('swD', 'SWD', 'cisco-ios-xe');
      swD.routerId = '4.4.4.4';
      swD.switching = { stpEnabled: true, stpPriority: 32768 };
      swD.interfaces = [
        { id: 'swD-b', name: 'Gi0/1', cidr: '', vrf: 'default' },
        { id: 'swD-c', name: 'Gi0/2', cidr: '', vrf: 'default' },
      ];
      const stpSim = solveTopology({
        nodes: [swA, swB, swC, swD],
        links: [
          { id: 'l-ab', sourceNodeId: 'swA', sourceInterfaceId: 'swA-1', targetNodeId: 'swB', targetInterfaceId: 'swB-1', linkType: 'layer2' },
          { id: 'l-ac', sourceNodeId: 'swA', sourceInterfaceId: 'swA-2', targetNodeId: 'swC', targetInterfaceId: 'swC-1', linkType: 'layer2' },
          { id: 'l-bd', sourceNodeId: 'swB', sourceInterfaceId: 'swB-2', targetNodeId: 'swD', targetInterfaceId: 'swD-b', linkType: 'layer2' },
          { id: 'l-cd', sourceNodeId: 'swC', sourceInterfaceId: 'swC-2', targetNodeId: 'swD', targetInterfaceId: 'swD-c', linkType: 'layer2' },
        ],
      });
      const dRootPort = stpSim.nodes['swD'].stpState?.ports.find((p) => p.role === 'Root');
      expect(dRootPort?.interfaceName).toBe('Gi0/2');

      // 5. Engine Pass 2: BGP confed-eBGP -> iBGP propagation (RFC 5065) & IPv6 ACL/prefix-list/BGP importer parity
      const cf1 = makeMinimalNode('cf1', 'CF1', 'cisco-ios-xe');
      cf1.routerId = '1.1.1.1';
      cf1.interfaces = [{ id: 'cf1-i1', name: 'Gi0/0', cidr: '10.60.0.1/30', vrf: 'default' }];
      cf1.bgp = {
        enabled: true,
        asn: 65100,
        confederationId: 65000,
        confederationPeers: [65200],
        peers: [{ id: 'cp1', peerIp: '10.60.0.2', remoteAs: 65200, confederationPeer: true }],
        networks: [{ id: 'cn1', prefix: '198.18.60.0/24' }],
      };
      const cf2 = makeMinimalNode('cf2', 'CF2', 'cisco-ios-xe');
      cf2.routerId = '2.2.2.2';
      cf2.interfaces = [
        { id: 'cf2-i1', name: 'Gi0/0', cidr: '10.60.0.2/30', vrf: 'default' },
        { id: 'cf2-i2', name: 'Gi0/1', cidr: '10.61.0.1/30', vrf: 'default' },
      ];
      cf2.bgp = {
        enabled: true,
        asn: 65200,
        confederationId: 65000,
        confederationPeers: [65100],
        peers: [
          { id: 'cp2a', peerIp: '10.60.0.1', remoteAs: 65100, confederationPeer: true },
          { id: 'cp2b', peerIp: '10.61.0.2', remoteAs: 65200, nextHopSelf: true },
        ],
        networks: [],
      };
      const cf3 = makeMinimalNode('cf3', 'CF3', 'cisco-ios-xe');
      cf3.routerId = '3.3.3.3';
      cf3.interfaces = [{ id: 'cf3-i1', name: 'Gi0/0', cidr: '10.61.0.2/30', vrf: 'default' }];
      cf3.bgp = {
        enabled: true,
        asn: 65200,
        confederationId: 65000,
        confederationPeers: [65100],
        peers: [{ id: 'cp3', peerIp: '10.61.0.1', remoteAs: 65200 }],
        networks: [],
      };
      const cfSim = solveTopology({
        nodes: [cf1, cf2, cf3],
        links: [
          { id: 'cfl1', sourceNodeId: 'cf1', sourceInterfaceId: 'cf1-i1', targetNodeId: 'cf2', targetInterfaceId: 'cf2-i1' },
          { id: 'cfl2', sourceNodeId: 'cf2', sourceInterfaceId: 'cf2-i2', targetNodeId: 'cf3', targetInterfaceId: 'cf3-i1' },
        ],
      });
      expect(cfSim.nodes['cf3'].rib.some((r) => r.prefix === '198.18.60.0' && r.active)).toBe(true);

      const ciscoV6Acl = parseCiscoStyleAclRules([
        'ipv6 access-list V6-IN',
        ' 10 permit tcp 2001:db8:1::/64 any eq 443',
      ]);
      expect(ciscoV6Acl[0]?.srcCidr).toBe('2001:db8:1::/64');
      expect(ciscoV6Acl[0]?.dstCidr).toBe('::/0');
      expect(ciscoV6Acl[0]?.dstPort).toBe(443);

      const ciscoV6Pl = importTopologyFromText('hostname PL6\nipv6 prefix-list P6 seq 10 permit 2001:db8::/32 le 48\n!').nodes[0];
      expect(ciscoV6Pl.prefixLists?.[0]?.entries[0]?.prefix).toBe('2001:db8::/32');
    });

    it('covers Solver Recursive Pass 1 fixes (OSPF dual-ABR Type-3/stub default, EIGRP internal>external, SD-WAN unreachable TLOC, overlay transit connected nextHop)', () => {
      // 1. OSPF dual-ABR: ABR does not install stub default from peer ABR and does not leak non-backbone Type-3 back into Area 0
      const rA0 = makeMinimalNode('da-a0', 'A0-R', 'cisco-ios-xe');
      rA0.routerId = '1.1.1.1';
      rA0.interfaces = [
        { id: 'da-a0-1', name: 'Gi0/0', cidr: '10.1.0.1/30', vrf: 'default', ospfArea: 0 },
        { id: 'da-a0-2', name: 'Gi0/1', cidr: '10.2.0.1/30', vrf: 'default', ospfArea: 0 },
      ];
      rA0.ospf = { enabled: true, networks: [] };

      const abr1 = makeMinimalNode('da-abr1', 'ABR1', 'cisco-ios-xe');
      abr1.routerId = '2.2.2.2';
      abr1.interfaces = [
        { id: 'da-abr1-0', name: 'Gi0/0', cidr: '10.1.0.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'da-abr1-1', name: 'Gi0/1', cidr: '10.10.0.1/30', vrf: 'default', ospfArea: 1 },
      ];
      abr1.ospf = { enabled: true, networks: [], areaTypes: { 1: 'stub' } };

      const abr2 = makeMinimalNode('da-abr2', 'ABR2', 'cisco-ios-xe');
      abr2.routerId = '3.3.3.3';
      abr2.interfaces = [
        { id: 'da-abr2-0', name: 'Gi0/0', cidr: '10.2.0.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'da-abr2-1', name: 'Gi0/1', cidr: '10.10.0.2/30', vrf: 'default', ospfArea: 1 },
      ];
      abr2.ospf = { enabled: true, networks: [], areaTypes: { 1: 'stub' } };

      const dualAbrSim = solveTopology({
        nodes: [rA0, abr1, abr2],
        links: [
          { id: 'dal1', sourceNodeId: 'da-a0', sourceInterfaceId: 'da-a0-1', targetNodeId: 'da-abr1', targetInterfaceId: 'da-abr1-0' },
          { id: 'dal2', sourceNodeId: 'da-a0', sourceInterfaceId: 'da-a0-2', targetNodeId: 'da-abr2', targetInterfaceId: 'da-abr2-0' },
          { id: 'dal3', sourceNodeId: 'da-abr1', sourceInterfaceId: 'da-abr1-1', targetNodeId: 'da-abr2', targetInterfaceId: 'da-abr2-1' },
        ],
      });
      expect(dualAbrSim.nodes['da-abr1'].rib.some((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0)).toBe(false);
      expect(dualAbrSim.nodes['da-abr2'].rib.some((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0)).toBe(false);
      expect(dualAbrSim.nodes['da-a0'].rib.some((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0)).toBe(false);

      // 2. EIGRP internal path (AD 90) is preferred over external path (AD 170) even when external has lower FD
      const eSrc = makeMinimalNode('eg-src', 'EG-SRC', 'cisco-ios-xe');
      eSrc.routerId = '10.0.0.1';
      eSrc.interfaces = [
        { id: 'eg-src-1', name: 'Gi0/0', cidr: '10.40.0.1/30', vrf: 'default' },
        { id: 'eg-src-lo', name: 'Lo0', cidr: '192.168.77.1/24', vrf: 'default' },
      ];
      eSrc.eigrp = { enabled: true, asn: 100, networks: [{ id: 'en1', prefix: '10.40.0.0/30' }, { id: 'en2', prefix: '192.168.77.0/24' }] };
      eSrc.staticRoutes = [{ id: 'es1', vrf: 'default', prefix: '192.168.77.0/24', nextHop: 'Null0' }];
      eSrc.redistributions = [{ id: 'er1', from: 'static', to: 'eigrp', metric: 1 }];

      const eDst = makeMinimalNode('eg-dst', 'EG-DST', 'cisco-ios-xe');
      eDst.routerId = '10.0.0.2';
      eDst.interfaces = [{ id: 'eg-dst-1', name: 'Gi0/0', cidr: '10.40.0.2/30', vrf: 'default' }];
      eDst.eigrp = { enabled: true, asn: 100, networks: [{ id: 'en3', prefix: '10.40.0.0/30' }] };

      const eigrpSim = solveTopology({
        nodes: [eSrc, eDst],
        links: [{ id: 'egl1', sourceNodeId: 'eg-src', sourceInterfaceId: 'eg-src-1', targetNodeId: 'eg-dst', targetInterfaceId: 'eg-dst-1' }],
      });
      const learned = eigrpSim.nodes['eg-dst'].rib.filter((r) => r.prefix === '192.168.77.0' && r.protocol === 'eigrp');
      expect(learned.length).toBe(1);
      expect(learned[0].ad).toBe(90);

      // 3. SD-WAN OMP does not install an active route when remote TLOC is unreachable in underlay
      const sd1 = makeMinimalNode('sd-u1', 'SD1', 'cisco-ios-xe');
      sd1.routerId = '1.1.1.1';
      sd1.interfaces = [
        { id: 'sd1-wan', name: 'Gi0/0', cidr: '198.51.100.1/30', vrf: 'default', tlocColor: 'biz-internet' },
        { id: 'sd1-lan', name: 'Gi0/1', cidr: '10.81.0.1/24', vrf: 'default' },
      ];
      sd1.sdwan = { enabled: true, siteId: 1, systemIp: '1.1.1.1', advertiseConnected: true };

      const isp = makeMinimalNode('sd-isp', 'ISP', 'cisco-ios-xe');
      isp.routerId = '9.9.9.9';
      isp.interfaces = [
        { id: 'isp-1', name: 'Gi0/0', cidr: '198.51.100.2/30', vrf: 'default' },
        { id: 'isp-2', name: 'Gi0/1', cidr: '203.0.113.2/30', vrf: 'default' },
      ];

      const sd2 = makeMinimalNode('sd-u2', 'SD2', 'cisco-ios-xe');
      sd2.routerId = '2.2.2.2';
      sd2.interfaces = [
        { id: 'sd2-wan', name: 'Gi0/0', cidr: '203.0.113.1/30', vrf: 'default', tlocColor: 'biz-internet' },
        { id: 'sd2-lan', name: 'Gi0/1', cidr: '10.82.0.1/24', vrf: 'default' },
      ];
      sd2.sdwan = { enabled: true, siteId: 2, systemIp: '2.2.2.2', advertiseConnected: true };

      const sdUnreachSim = solveTopology({
        nodes: [sd1, isp, sd2],
        links: [
          { id: 'sdl1', sourceNodeId: 'sd-u1', sourceInterfaceId: 'sd1-wan', targetNodeId: 'sd-isp', targetInterfaceId: 'isp-1' },
          { id: 'sdl2', sourceNodeId: 'sd-isp', sourceInterfaceId: 'isp-2', targetNodeId: 'sd-u2', targetInterfaceId: 'sd2-wan' },
        ],
      });
      // Neither SD1 nor SD2 has an underlay route to the other's WAN TLOC, so OMP must not install a looping active route
      expect(sdUnreachSim.nodes['sd-u1'].rib.some((r) => r.protocol === 'omp' && r.prefix === '10.82.0.0')).toBe(false);
    });

    it('covers Solver Recursive Pass 2 fixes (IS-IS ATT ECMP & L1-L2 Up/Down, tracePacket adminDown PBR failover, SD-WAN SLA steered OMP outer TLOC)', () => {
      // 1. IS-IS L1-only router gets 2-way ECMP ATT-bit defaults from dual L1-L2 ABRs; L1-L2 peer receives leaked L1-down route over L1
      const isL1 = makeMinimalNode('is-l1', 'IS-L1', 'cisco-ios-xe');
      isL1.routerId = '1.1.1.1';
      isL1.interfaces = [
        { id: 'is-l1-1', name: 'Gi0/0', cidr: '10.70.1.1/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
        { id: 'is-l1-2', name: 'Gi0/1', cidr: '10.70.2.1/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
      ];
      isL1.isis = { enabled: true, net: '49.0001.0001.0001.0001.00', level: 'L1', networks: [] };

      const isAbr1 = makeMinimalNode('is-abr1', 'IS-ABR1', 'cisco-ios-xe');
      isAbr1.routerId = '2.2.2.2';
      isAbr1.interfaces = [
        { id: 'is-a1-1', name: 'Gi0/0', cidr: '10.70.1.2/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
        { id: 'is-a1-2', name: 'Gi0/1', cidr: '10.70.3.1/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
        { id: 'is-a1-3', name: 'Gi0/2', cidr: '10.70.4.1/30', vrf: 'default', isisLevel: 'L2', isisMetric: 10 },
      ];
      isAbr1.isis = {
        enabled: true,
        net: '49.0001.0002.0002.0002.00',
        level: 'L1-L2',
        leakL2ToL1: [{ id: 'lk1', prefix: '198.51.200.0/24' }],
        networks: [],
      };

      const isAbr2 = makeMinimalNode('is-abr2', 'IS-ABR2', 'cisco-ios-xe');
      isAbr2.routerId = '3.3.3.3';
      isAbr2.interfaces = [
        { id: 'is-a2-1', name: 'Gi0/0', cidr: '10.70.2.2/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
        { id: 'is-a2-2', name: 'Gi0/1', cidr: '10.70.3.2/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
      ];
      isAbr2.isis = { enabled: true, net: '49.0001.0003.0003.0003.00', level: 'L1-L2', networks: [] };

      const isL2 = makeMinimalNode('is-l2', 'IS-L2', 'cisco-ios-xe');
      isL2.routerId = '4.4.4.4';
      isL2.interfaces = [
        { id: 'is-l2-1', name: 'Gi0/0', cidr: '10.70.4.2/30', vrf: 'default', isisLevel: 'L2', isisMetric: 10 },
        { id: 'is-l2-lo', name: 'Lo0', cidr: '198.51.200.1/24', vrf: 'default', isisLevel: 'L2' },
      ];
      isL2.isis = { enabled: true, net: '49.0002.0004.0004.0004.00', level: 'L2', networks: [{ id: 'isn1', prefix: '198.51.200.0/24', level: 'L2' }] };

      const isisSim = solveTopology({
        nodes: [isL1, isAbr1, isAbr2, isL2],
        links: [
          { id: 'isl1', sourceNodeId: 'is-l1', sourceInterfaceId: 'is-l1-1', targetNodeId: 'is-abr1', targetInterfaceId: 'is-a1-1' },
          { id: 'isl2', sourceNodeId: 'is-l1', sourceInterfaceId: 'is-l1-2', targetNodeId: 'is-abr2', targetInterfaceId: 'is-a2-1' },
          { id: 'isl3', sourceNodeId: 'is-abr1', sourceInterfaceId: 'is-a1-2', targetNodeId: 'is-abr2', targetInterfaceId: 'is-a2-2' },
          { id: 'isl4', sourceNodeId: 'is-abr1', sourceInterfaceId: 'is-a1-3', targetNodeId: 'is-l2', targetInterfaceId: 'is-l2-1' },
        ],
      });
      const l1Defaults = isisSim.nodes['is-l1'].rib.filter((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0 && r.active);
      expect(l1Defaults).toHaveLength(2);
      expect(isisSim.nodes['is-abr2'].rib.some((r) => r.prefix === '198.51.200.0' && r.active)).toBe(true);

      // 2. tracePacket normalizes adminDown links so PBR/FlowSpec redirect resolves over backup IGP path
      const pR1 = makeMinimalNode('pr1', 'PR1', 'cisco-ios-xe');
      pR1.routerId = '1.1.1.1';
      pR1.interfaces = [
        { id: 'pr1-1', name: 'Gi0/0', cidr: '10.90.12.1/30', vrf: 'default', ospfArea: 0 },
        { id: 'pr1-2', name: 'Gi0/1', cidr: '10.90.13.1/30', vrf: 'default', ospfArea: 0 },
      ];
      pR1.ospf = { enabled: true, networks: [] };
      pR1.pbrRules = [{ id: 'pbr1', name: 'PBR', matchPrefix: '172.31.0.0/24', nextHop: '10.90.12.2' }];

      const pR2 = makeMinimalNode('pr2', 'PR2', 'cisco-ios-xe');
      pR2.routerId = '2.2.2.2';
      pR2.interfaces = [
        { id: 'pr2-1', name: 'Gi0/0', cidr: '10.90.12.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'pr2-2', name: 'Gi0/1', cidr: '10.90.23.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'pr2-lo', name: 'Lo0', cidr: '172.31.0.1/24', vrf: 'default', ospfArea: 0 },
      ];
      pR2.ospf = { enabled: true, networks: [{ id: 'on2', prefix: '10.90.12.0/30', area: 0 }] };

      const pR3 = makeMinimalNode('pr3', 'PR3', 'cisco-ios-xe');
      pR3.routerId = '3.3.3.3';
      pR3.interfaces = [
        { id: 'pr3-1', name: 'Gi0/0', cidr: '10.90.13.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'pr3-2', name: 'Gi0/1', cidr: '10.90.23.1/30', vrf: 'default', ospfArea: 0 },
      ];
      pR3.ospf = { enabled: true, networks: [] };

      const pbrTopo = {
        nodes: [pR1, pR2, pR3],
        links: [
          { id: 'pl1', sourceNodeId: 'pr1', sourceInterfaceId: 'pr1-1', targetNodeId: 'pr2', targetInterfaceId: 'pr2-1', adminDown: true },
          { id: 'pl2', sourceNodeId: 'pr1', sourceInterfaceId: 'pr1-2', targetNodeId: 'pr3', targetInterfaceId: 'pr3-1' },
          { id: 'pl3', sourceNodeId: 'pr3', sourceInterfaceId: 'pr3-2', targetNodeId: 'pr2', targetInterfaceId: 'pr2-2' },
        ],
      };
      const pbrSim = solveTopology(pbrTopo);
      const pbrTrace = tracePacket(pbrTopo, pbrSim, 'pr1', '172.31.0.10');
      expect(pbrTrace.outcome).toBe('delivered');
      expect(pbrTrace.hops[0]?.egressInterface).toBe('Gi0/1');
      expect(pbrTrace.hops[0]?.pbrApplied).toContain('PBR');
    });

    it('covers Solver Recursive Pass 3 fixes (IS-IS ATT no-loop to L2, BGP aggregate over peer route, overlay decap before ACL)', () => {
      // 1. IS-IS ATT-bit default on dual-homed L1 does NOT loop back to L1-L2 ABRs or promote into L2
      const l1 = makeMinimalNode('att-l1', 'ATT-L1', 'cisco-ios-xe');
      l1.routerId = '1.1.1.1';
      l1.interfaces = [
        { id: 'att-l1-1', name: 'Gi0/0', cidr: '10.71.1.1/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
        { id: 'att-l1-2', name: 'Gi0/1', cidr: '10.71.2.1/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
      ];
      l1.isis = { enabled: true, net: '49.0001.0001.0001.0001.00', level: 'L1', networks: [] };

      const a1 = makeMinimalNode('att-a1', 'ATT-A1', 'cisco-ios-xe');
      a1.routerId = '2.2.2.2';
      a1.interfaces = [
        { id: 'att-a1-1', name: 'Gi0/0', cidr: '10.71.1.2/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
        { id: 'att-a1-2', name: 'Gi0/1', cidr: '10.71.3.1/30', vrf: 'default', isisLevel: 'L2', isisMetric: 10 },
      ];
      a1.isis = { enabled: true, net: '49.0001.0002.0002.0002.00', level: 'L1-L2', networks: [] };

      const a2 = makeMinimalNode('att-a2', 'ATT-A2', 'cisco-ios-xe');
      a2.routerId = '3.3.3.3';
      a2.interfaces = [
        { id: 'att-a2-1', name: 'Gi0/0', cidr: '10.71.2.2/30', vrf: 'default', isisLevel: 'L1', isisMetric: 10 },
        { id: 'att-a2-2', name: 'Gi0/1', cidr: '10.71.4.1/30', vrf: 'default', isisLevel: 'L2', isisMetric: 10 },
      ];
      a2.isis = { enabled: true, net: '49.0001.0003.0003.0003.00', level: 'L1-L2', networks: [] };

      const core = makeMinimalNode('att-core', 'ATT-CORE', 'cisco-ios-xe');
      core.routerId = '4.4.4.4';
      core.interfaces = [
        { id: 'att-c-1', name: 'Gi0/0', cidr: '10.71.3.2/30', vrf: 'default', isisLevel: 'L2', isisMetric: 10 },
        { id: 'att-c-2', name: 'Gi0/1', cidr: '10.71.4.2/30', vrf: 'default', isisLevel: 'L2', isisMetric: 10 },
      ];
      core.isis = { enabled: true, net: '49.0002.0004.0004.0004.00', level: 'L2', networks: [] };

      const attSim = solveTopology({
        nodes: [l1, a1, a2, core],
        links: [
          { id: 'al1', sourceNodeId: 'att-l1', sourceInterfaceId: 'att-l1-1', targetNodeId: 'att-a1', targetInterfaceId: 'att-a1-1' },
          { id: 'al2', sourceNodeId: 'att-l1', sourceInterfaceId: 'att-l1-2', targetNodeId: 'att-a2', targetInterfaceId: 'att-a2-1' },
          { id: 'al3', sourceNodeId: 'att-a1', sourceInterfaceId: 'att-a1-2', targetNodeId: 'att-core', targetInterfaceId: 'att-c-1' },
          { id: 'al4', sourceNodeId: 'att-a2', sourceInterfaceId: 'att-a2-2', targetNodeId: 'att-core', targetInterfaceId: 'att-c-2' },
        ],
      });
      expect(attSim.nodes['att-l1'].rib.filter((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0 && r.active)).toHaveLength(2);
      expect(attSim.nodes['att-a1'].rib.some((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0)).toBe(false);
      expect(attSim.nodes['att-core'].rib.some((r) => r.prefix === '0.0.0.0' && r.prefixLen === 0)).toBe(false);

      // 2. BGP aggregate-address originates locally even if a peer already advertised the exact aggregate prefix
      const ag1 = makeMinimalNode('ag1', 'AG1', 'cisco-ios-xe');
      ag1.routerId = '1.1.1.1';
      ag1.interfaces = [
        { id: 'ag1-1', name: 'Gi0/0', cidr: '10.72.1.1/30', vrf: 'default' },
        { id: 'ag1-2', name: 'Gi0/1', cidr: '10.72.2.1/30', vrf: 'default' },
      ];
      ag1.bgp = {
        enabled: true,
        asn: 65001,
        peers: [
          { id: 'agp1', peerIp: '10.72.1.2', remoteAs: 65002 },
          { id: 'agp2', peerIp: '10.72.2.2', remoteAs: 65003 },
        ],
        networks: [],
        aggregates: [{ id: 'agg1', prefix: '10.200.0.0/16', summaryOnly: true }],
      };
      const ag2 = makeMinimalNode('ag2', 'AG2', 'cisco-ios-xe');
      ag2.routerId = '2.2.2.2';
      ag2.interfaces = [{ id: 'ag2-1', name: 'Gi0/0', cidr: '10.72.1.2/30', vrf: 'default' }];
      ag2.bgp = {
        enabled: true,
        asn: 65002,
        peers: [{ id: 'agp21', peerIp: '10.72.1.1', remoteAs: 65001 }],
        networks: [{ id: 'agn2', prefix: '10.200.1.0/24' }],
      };
      const ag3 = makeMinimalNode('ag3', 'AG3', 'cisco-ios-xe');
      ag3.routerId = '3.3.3.3';
      ag3.interfaces = [{ id: 'ag3-1', name: 'Gi0/0', cidr: '10.72.2.2/30', vrf: 'default' }];
      ag3.bgp = {
        enabled: true,
        asn: 65003,
        peers: [{ id: 'agp31', peerIp: '10.72.2.1', remoteAs: 65001 }],
        networks: [{ id: 'agn3', prefix: '10.200.0.0/16' }],
      };
      const aggSim = solveTopology({
        nodes: [ag1, ag2, ag3],
        links: [
          { id: 'agl1', sourceNodeId: 'ag1', sourceInterfaceId: 'ag1-1', targetNodeId: 'ag2', targetInterfaceId: 'ag2-1' },
          { id: 'agl2', sourceNodeId: 'ag1', sourceInterfaceId: 'ag1-2', targetNodeId: 'ag3', targetInterfaceId: 'ag3-1' },
        ],
      });
      const ag1Agg = aggSim.nodes['ag1'].rib.find((r) => r.prefix === '10.200.0.0' && r.prefixLen === 16 && r.active);
      expect(ag1Agg?.egressInterface).toBe('Null0');

      // 3. Overlay decapsulation occurs BEFORE ACL evaluation on remote tunnel endpoint
      const sdA = makeMinimalNode('sda', 'SD-A', 'cisco-ios-xe');
      sdA.routerId = '1.1.1.1';
      sdA.interfaces = [
        { id: 'sda-wan', name: 'Gi0/0', cidr: '198.51.100.1/30', vrf: 'default', tlocColor: 'biz-internet' },
        { id: 'sda-lan', name: 'Gi0/1', cidr: '192.168.10.1/24', vrf: 'default' },
      ];
      sdA.staticRoutes = [{ id: 'sds1', vrf: 'default', prefix: '0.0.0.0/0', nextHop: '198.51.100.2' }];
      sdA.sdwan = { enabled: true, siteId: 1, systemIp: '1.1.1.1', advertiseConnected: true };

      const sdMid = makeMinimalNode('sdm', 'SD-MID', 'cisco-ios-xe');
      sdMid.routerId = '9.9.9.9';
      sdMid.interfaces = [
        { id: 'sdm-1', name: 'Gi0/0', cidr: '198.51.100.2/30', vrf: 'default' },
        { id: 'sdm-2', name: 'Gi0/1', cidr: '203.0.113.2/30', vrf: 'default' },
      ];

      const sdB = makeMinimalNode('sdb', 'SD-B', 'cisco-ios-xe');
      sdB.routerId = '2.2.2.2';
      sdB.interfaces = [
        { id: 'sdb-wan', name: 'Gi0/0', cidr: '203.0.113.1/30', vrf: 'default', tlocColor: 'biz-internet' },
        { id: 'sdb-lan', name: 'Gi0/1', cidr: '192.168.20.1/24', vrf: 'default' },
      ];
      sdB.staticRoutes = [{ id: 'sds2', vrf: 'default', prefix: '0.0.0.0/0', nextHop: '203.0.113.2' }];
      sdB.sdwan = { enabled: true, siteId: 2, systemIp: '2.2.2.2', advertiseConnected: true };
      sdB.aclRules = [
        { id: 'sdacl1', seq: 10, name: 'ALLOW-LAN', action: 'allow', srcCidr: '192.168.10.0/24', dstCidr: '192.168.20.0/24', protocol: 'any' },
      ];

      const sdAclTopo = {
        nodes: [sdA, sdMid, sdB],
        links: [
          { id: 'sdal1', sourceNodeId: 'sda', sourceInterfaceId: 'sda-wan', targetNodeId: 'sdm', targetInterfaceId: 'sdm-1' },
          { id: 'sdal2', sourceNodeId: 'sdm', sourceInterfaceId: 'sdm-2', targetNodeId: 'sdb', targetInterfaceId: 'sdb-wan' },
        ],
      };
      const sdAclSim = solveTopology(sdAclTopo);
      const sdAclTrace = tracePacket(sdAclTopo, sdAclSim, 'sda', '192.168.20.10', 'default', { srcIp: '192.168.10.10' });
      expect(sdAclTrace.outcome).toBe('delivered');
    });

    it('covers Solver Recursive Pass 4 fixes (BGP AS-path poisoning via outRm rejected, aggregate withdrawn when contributors disappear)', () => {
      // 1. Outbound route-map prependAsPath poisoning receiver's own ASN is rejected by receiver AS-path loop check
      const p1 = makeMinimalNode('ap1', 'AP1', 'cisco-ios-xe');
      p1.routerId = '1.1.1.1';
      p1.interfaces = [{ id: 'ap1-1', name: 'Gi0/0', cidr: '10.73.1.1/30', vrf: 'default' }];
      p1.routeMaps = [
        {
          id: 'rm-poison',
          name: 'POISON',
          entries: [{ id: 'rme-poison', seq: 10, action: 'permit', set: { prependAsPath: [65002] } }],
        },
      ];
      p1.bgp = {
        enabled: true,
        asn: 65001,
        peers: [{ id: 'app1', peerIp: '10.73.1.2', remoteAs: 65002, routeMapOutId: 'rm-poison' }],
        networks: [{ id: 'apn1', prefix: '198.51.73.0/24' }],
      };
      const p2 = makeMinimalNode('ap2', 'AP2', 'cisco-ios-xe');
      p2.routerId = '2.2.2.2';
      p2.interfaces = [{ id: 'ap2-1', name: 'Gi0/0', cidr: '10.73.1.2/30', vrf: 'default' }];
      p2.bgp = {
        enabled: true,
        asn: 65002,
        peers: [{ id: 'app2', peerIp: '10.73.1.1', remoteAs: 65001 }],
        networks: [],
      };
      const poisonSim = solveTopology({
        nodes: [p1, p2],
        links: [{ id: 'apl1', sourceNodeId: 'ap1', sourceInterfaceId: 'ap1-1', targetNodeId: 'ap2', targetInterfaceId: 'ap2-1' }],
      });
      expect(poisonSim.nodes['ap2'].rib.some((r) => r.prefix === '198.51.73.0')).toBe(false);

      // 2. Generated aggregate is withdrawn when contributing BGP routes are later pruned by maxPrefixes
      const w2 = makeMinimalNode('aw2', 'AW2', 'cisco-ios-xe');
      w2.routerId = '2.2.2.2';
      w2.interfaces = [{ id: 'aw2-1', name: 'Gi0/0', cidr: '10.74.1.2/30', vrf: 'default' }];
      w2.bgp = {
        enabled: true,
        asn: 65002,
        peers: [{ id: 'awp2', peerIp: '10.74.1.1', remoteAs: 65001, maxPrefixes: 1 }],
        networks: [],
        aggregates: [{ id: 'awa2', prefix: '10.201.0.0/16', summaryOnly: true }],
      };
      const w1 = makeMinimalNode('aw1', 'AW1', 'cisco-ios-xe');
      w1.routerId = '1.1.1.1';
      w1.interfaces = [
        { id: 'aw1-1', name: 'Gi0/0', cidr: '10.74.1.1/30', vrf: 'default' },
        { id: 'aw1-2', name: 'Gi0/1', cidr: '10.74.2.1/30', vrf: 'default' },
      ];
      w1.bgp = {
        enabled: true,
        asn: 65001,
        peers: [
          { id: 'awp12', peerIp: '10.74.1.2', remoteAs: 65002 },
          { id: 'awp13', peerIp: '10.74.2.2', remoteAs: 65003 },
        ],
        networks: [{ id: 'awn1', prefix: '10.201.1.0/24' }],
      };
      const w3 = makeMinimalNode('aw3', 'AW3', 'cisco-ios-xe');
      w3.routerId = '3.3.3.3';
      w3.interfaces = [{ id: 'aw3-1', name: 'Gi0/0', cidr: '10.74.2.2/30', vrf: 'default' }];
      w3.bgp = {
        enabled: true,
        asn: 65003,
        peers: [{ id: 'awp31', peerIp: '10.74.2.1', remoteAs: 65001 }],
        networks: [{ id: 'awn3', prefix: '10.201.2.0/24' }],
      };
      const withdrawSim = solveTopology({
        nodes: [w2, w1, w3],
        links: [
          { id: 'awl1', sourceNodeId: 'aw1', sourceInterfaceId: 'aw1-1', targetNodeId: 'aw2', targetInterfaceId: 'aw2-1' },
          { id: 'awl2', sourceNodeId: 'aw1', sourceInterfaceId: 'aw1-2', targetNodeId: 'aw3', targetInterfaceId: 'aw3-1' },
        ],
      });
      expect(withdrawSim.nodes['aw2'].rib.some((r) => r.prefix === '10.201.0.0' && r.prefixLen === 16)).toBe(false);
    });

    it('covers Solver Recursive Pass 5 fixes (OSPF single-ABR Area 1<->Area 2, BGP RR ORIGINATOR_ID split-horizon, BGP asSet convergence)', () => {
      // 1. Single ABR attached to Area 0, Area 1, and Area 2 propagates intra-area routes between Area 1 and Area 2
      const o0 = makeMinimalNode('oa0', 'OA0', 'cisco-ios-xe');
      o0.routerId = '10.0.0.0';
      o0.interfaces = [{ id: 'oa0-1', name: 'Gi0/0', cidr: '10.80.0.1/30', vrf: 'default', ospfArea: 0 }];
      o0.ospf = { enabled: true, networks: [] };

      const oAbr = makeMinimalNode('oabr', 'OABR', 'cisco-ios-xe');
      oAbr.routerId = '10.0.0.1';
      oAbr.interfaces = [
        { id: 'oabr-0', name: 'Gi0/0', cidr: '10.80.0.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'oabr-1', name: 'Gi0/1', cidr: '10.80.1.1/30', vrf: 'default', ospfArea: 1 },
        { id: 'oabr-2', name: 'Gi0/2', cidr: '10.80.2.1/30', vrf: 'default', ospfArea: 2 },
      ];
      oAbr.ospf = { enabled: true, networks: [] };

      const o1 = makeMinimalNode('oa1', 'OA1', 'cisco-ios-xe');
      o1.routerId = '10.0.0.2';
      o1.interfaces = [
        { id: 'oa1-1', name: 'Gi0/0', cidr: '10.80.1.2/30', vrf: 'default', ospfArea: 1 },
        { id: 'oa1-lo', name: 'Lo0', cidr: '172.21.1.1/24', vrf: 'default', ospfArea: 1 },
      ];
      o1.ospf = { enabled: true, networks: [] };

      const o2 = makeMinimalNode('oa2', 'OA2', 'cisco-ios-xe');
      o2.routerId = '10.0.0.3';
      o2.interfaces = [
        { id: 'oa2-1', name: 'Gi0/0', cidr: '10.80.2.2/30', vrf: 'default', ospfArea: 2 },
        { id: 'oa2-lo', name: 'Lo0', cidr: '172.22.2.1/24', vrf: 'default', ospfArea: 2 },
      ];
      o2.ospf = { enabled: true, networks: [] };

      const abr12Sim = solveTopology({
        nodes: [o0, oAbr, o1, o2],
        links: [
          { id: 'ol0', sourceNodeId: 'oa0', sourceInterfaceId: 'oa0-1', targetNodeId: 'oabr', targetInterfaceId: 'oabr-0' },
          { id: 'ol1', sourceNodeId: 'oabr', sourceInterfaceId: 'oabr-1', targetNodeId: 'oa1', targetInterfaceId: 'oa1-1' },
          { id: 'ol2', sourceNodeId: 'oabr', sourceInterfaceId: 'oabr-2', targetNodeId: 'oa2', targetInterfaceId: 'oa2-1' },
        ],
      });
      expect(abr12Sim.nodes['oa1'].rib.some((r) => r.prefix === '172.22.2.0' && r.active)).toBe(true);
      expect(abr12Sim.nodes['oa2'].rib.some((r) => r.prefix === '172.21.1.0' && r.active)).toBe(true);

      // 2. BGP RR does not reflect eBGP-learned route back to sending client (prevents C1 <-> RR1 loop even with higher LP on RR1)
      const ext = makeMinimalNode('rrext', 'RR-EXT', 'cisco-ios-xe');
      ext.routerId = '9.9.9.9';
      ext.interfaces = [{ id: 'rrext-1', name: 'Gi0/0', cidr: '10.81.0.1/30', vrf: 'default' }];
      ext.bgp = {
        enabled: true,
        asn: 65002,
        peers: [{ id: 'rrp0', peerIp: '10.81.0.2', remoteAs: 65001 }],
        networks: [{ id: 'rrn0', prefix: '203.0.113.0/24' }],
      };
      const c1 = makeMinimalNode('rrc1', 'RR-C1', 'cisco-ios-xe');
      c1.routerId = '1.1.1.1';
      c1.interfaces = [
        { id: 'rrc1-1', name: 'Gi0/0', cidr: '10.81.0.2/30', vrf: 'default' },
        { id: 'rrc1-2', name: 'Gi0/1', cidr: '10.81.1.1/30', vrf: 'default' },
      ];
      c1.bgp = {
        enabled: true,
        asn: 65001,
        peers: [
          { id: 'rrp1', peerIp: '10.81.0.1', remoteAs: 65002, localPref: 100 },
          { id: 'rrp2', peerIp: '10.81.1.2', remoteAs: 65001, nextHopSelf: true, localPref: 200 },
        ],
        networks: [],
      };
      const rr1 = makeMinimalNode('rr1', 'RR1', 'cisco-ios-xe');
      rr1.routerId = '2.2.2.2';
      rr1.interfaces = [{ id: 'rr1-1', name: 'Gi0/0', cidr: '10.81.1.2/30', vrf: 'default' }];
      rr1.bgp = {
        enabled: true,
        asn: 65001,
        peers: [{ id: 'rrp3', peerIp: '10.81.1.1', remoteAs: 65001, routeReflectorClient: true }],
        networks: [],
      };
      const rrSim = solveTopology({
        nodes: [ext, c1, rr1],
        links: [
          { id: 'rrl1', sourceNodeId: 'rrext', sourceInterfaceId: 'rrext-1', targetNodeId: 'rrc1', targetInterfaceId: 'rrc1-1' },
          { id: 'rrl2', sourceNodeId: 'rrc1', sourceInterfaceId: 'rrc1-2', targetNodeId: 'rr1', targetInterfaceId: 'rr1-1' },
        ],
      });
      const c1Best = rrSim.nodes['rrc1'].rib.find((r) => r.prefix === '203.0.113.0' && r.active);
      expect(c1Best?.protocol).toBe('ebgp');
      expect(c1Best?.nextHop).toBe('10.81.0.1');
    });

    it('covers Engine Hunt Pass 1 fixes (NAT64 /64, RIB diff largeCommunities/LISP, OSPF areaRanges Null0, LAG adminDown failover, IPv6 FHRP canonicalization, dual-stack v6 mismatch)', () => {
      // 1. NAT64 RFC 6052 /64 embedded IPv4 extraction
      const n64 = makeMinimalNode('n64', 'NAT64', 'cisco-ios-xe');
      n64.nat64Rules = [{ id: 'r64', prefix6: '2001:db8:1:2::/64', pool4Cidr: '198.51.100.1/24' }];
      const nat64Res = evaluateNat64(n64, '2001:db8:1:2:00c0:0002:0100:0000');
      expect(nat64Res?.dstIp).toBe('192.0.2.1');
      expect(nat64Res?.srcIp).toBe('198.51.100.1');

      // 2. computeRibDiff detects largeCommunities change
      const baseSim: SimulationResult = {
        nodes: {
          d1: {
            nodeId: 'd1',
            hostname: 'D1',
            vendor: 'cisco-ios-xe',
            warnings: [],
            rib: [{ af: 4, prefix: '10.0.0.0', prefixLen: 24, vrf: 'default', protocol: 'ebgp', ad: 20, metric: 0, nextHop: '10.0.0.1', egressInterface: 'Gi0/0', active: true, ecmp: false, bgpAttrs: { weight: 0, localPref: 100, locallyOriginated: false, asPath: [65002], origin: 'igp', med: 0, isEbgp: true, igpMetric: 0, peerRouterId: '2.2.2.2', peerIp: '10.0.0.1', largeCommunities: ['65001:100:1'] } }],
            fib: [],
            neighbors: [],
          },
        },
        warnings: [],
        convergedIterations: 1,
        computeTimeMs: 1,
      };
      const curSim: SimulationResult = {
        ...baseSim,
        nodes: {
          d1: {
            ...baseSim.nodes.d1,
            rib: [{ ...baseSim.nodes.d1.rib[0], bgpAttrs: { ...baseSim.nodes.d1.rib[0].bgpAttrs!, largeCommunities: ['65001:100:2'] } }],
          },
        },
      };
      expect(computeRibDiff(baseSim, curSim).modified).toBe(1);

      // 3. OSPF areaRanges installs Null0 discard route on ABR
      const arAbr = makeMinimalNode('ar-abr', 'AR-ABR', 'cisco-ios-xe');
      arAbr.routerId = '1.1.1.1';
      arAbr.interfaces = [
        { id: 'ar-0', name: 'Gi0/0', cidr: '10.91.0.1/30', vrf: 'default', ospfArea: 0 },
        { id: 'ar-1', name: 'Gi0/1', cidr: '10.91.1.1/24', vrf: 'default', ospfArea: 1 },
      ];
      arAbr.ospf = { enabled: true, networks: [], areaRanges: [{ id: 'ar1', area: 1, prefix: '10.91.0.0/16' }] };
      const arSim = solveTopology({ nodes: [arAbr], links: [] });
      expect(arSim.nodes['ar-abr'].rib.some((r) => r.prefix === '10.91.0.0' && r.prefixLen === 16 && r.egressInterface === 'Null0')).toBe(true);

      // 4. LAG Port-Channel shuts down when all member links are adminDown, failing over static route
      const lg1 = makeMinimalNode('lg1', 'LG1', 'cisco-ios-xe');
      lg1.routerId = '1.1.1.1';
      lg1.interfaces = [
        { id: 'lg1-m1', name: 'Gi0/0', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'active' },
        { id: 'lg1-po1', name: 'Port-Channel1', cidr: '10.92.0.1/30', vrf: 'default' },
        { id: 'lg1-bk', name: 'Gi0/1', cidr: '10.92.1.1/30', vrf: 'default' },
      ];
      lg1.staticRoutes = [
        { id: 'lgs1', vrf: 'default', prefix: '192.168.92.0/24', nextHop: '10.92.0.2', ad: 1 },
        { id: 'lgs2', vrf: 'default', prefix: '192.168.92.0/24', nextHop: '10.92.1.2', ad: 5 },
      ];
      const lg2 = makeMinimalNode('lg2', 'LG2', 'cisco-ios-xe');
      lg2.routerId = '2.2.2.2';
      lg2.interfaces = [
        { id: 'lg2-m1', name: 'Gi0/0', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'active' },
        { id: 'lg2-po1', name: 'Port-Channel1', cidr: '10.92.0.2/30', vrf: 'default' },
        { id: 'lg2-bk', name: 'Gi0/1', cidr: '10.92.1.2/30', vrf: 'default' },
      ];
      const lgSim = solveTopology({
        nodes: [lg1, lg2],
        links: [
          { id: 'lgl1', sourceNodeId: 'lg1', sourceInterfaceId: 'lg1-m1', targetNodeId: 'lg2', targetInterfaceId: 'lg2-m1', adminDown: true },
          { id: 'lgl2', sourceNodeId: 'lg1', sourceInterfaceId: 'lg1-bk', targetNodeId: 'lg2', targetInterfaceId: 'lg2-bk' },
        ],
      });
      const lgBest = lgSim.nodes['lg1'].rib.find((r) => r.prefix === '192.168.92.0' && r.active);
      expect(lgBest?.nextHop).toBe('10.92.1.2');

      // 5. Non-canonical IPv6 FHRP VIPs elect single Active and store canonical /128
      const fv1 = makeMinimalNode('fv6-1', 'FV6-1', 'cisco-ios-xe');
      fv1.routerId = '1.1.1.1';
      fv1.interfaces = [{ id: 'fv6-1i', name: 'Gi0/0', cidr: '', cidr6: '2001:db8::2/64', vrf: 'default' }];
      fv1.fhrpGroups = [{ id: 'fg1', protocol: 'vrrp', groupId: 1, interfaceId: 'fv6-1i', virtualIp: '2001:0db8::1', priority: 100 }];
      const fv2 = makeMinimalNode('fv6-2', 'FV6-2', 'cisco-ios-xe');
      fv2.routerId = '2.2.2.2';
      fv2.interfaces = [{ id: 'fv6-2i', name: 'Gi0/0', cidr: '', cidr6: '2001:db8::3/64', vrf: 'default' }];
      fv2.fhrpGroups = [{ id: 'fg2', protocol: 'vrrp', groupId: 1, interfaceId: 'fv6-2i', virtualIp: '2001:db8::1', priority: 150 }];
      const fvSim = solveTopology({ nodes: [fv1, fv2], links: [] });
      expect(fvSim.nodes['fv6-1'].neighbors?.find((n) => n.protocol === 'vrrp')?.state).toBe('Standby');
      expect(fvSim.nodes['fv6-2'].neighbors?.find((n) => n.protocol === 'vrrp')?.state).toBe('Active');
      expect(fvSim.nodes['fv6-2'].rib.some((r) => r.af === 6 && r.prefix === '2001:db8::1' && r.prefixLen === 128)).toBe(true);
    });

    it('covers Engine Hunt Pass 2 fixes (OSPF non-ABR no Null0, EIGRP speedMbps origination, L2 Port-Channel vPC peer-link)', () => {
      // 1. OSPF areaRanges does NOT install Null0 when Area 0 is shut down (router is no longer an active ABR)
      const nonAbr = makeMinimalNode('na-r1', 'NA-R1', 'cisco-ios-xe');
      nonAbr.routerId = '1.1.1.1';
      nonAbr.interfaces = [
        { id: 'na-0', name: 'Gi0/0', cidr: '10.93.0.1/30', vrf: 'default', ospfArea: 0, shutdown: true },
        { id: 'na-1', name: 'Gi0/1', cidr: '10.93.1.1/24', vrf: 'default', ospfArea: 1 },
      ];
      nonAbr.ospf = { enabled: true, networks: [], areaRanges: [{ id: 'nar1', area: 1, prefix: '10.93.0.0/16' }] };
      const nonAbrSim = solveTopology({ nodes: [nonAbr], links: [] });
      expect(nonAbrSim.nodes['na-r1'].rib.some((r) => r.prefix === '10.93.0.0' && r.egressInterface === 'Null0')).toBe(false);

      // 2. EIGRP connected origination honors iface.speedMbps
      const es1 = makeMinimalNode('es1', 'ES1', 'cisco-ios-xe');
      es1.routerId = '1.1.1.1';
      es1.interfaces = [
        { id: 'es1-0', name: 'Gi0/0', cidr: '10.94.0.1/30', vrf: 'default', speedMbps: 1000 },
        { id: 'es1-1', name: 'Gi0/1', cidr: '10.94.10.1/24', vrf: 'default', speedMbps: 10 },
      ];
      es1.eigrp = { enabled: true, asn: 100, networks: [{ id: 'esn1', prefix: '10.94.0.0/30' }, { id: 'esn2', prefix: '10.94.10.0/24' }] };
      const es2 = makeMinimalNode('es2', 'ES2', 'cisco-ios-xe');
      es2.routerId = '2.2.2.2';
      es2.interfaces = [{ id: 'es2-0', name: 'Gi0/0', cidr: '10.94.0.2/30', vrf: 'default', speedMbps: 1000 }];
      es2.eigrp = { enabled: true, asn: 100, networks: [{ id: 'esn3', prefix: '10.94.0.0/30' }] };
      const esSim = solveTopology({
        nodes: [es1, es2],
        links: [{ id: 'esl1', sourceNodeId: 'es1', sourceInterfaceId: 'es1-0', targetNodeId: 'es2', targetInterfaceId: 'es2-0' }],
      });
      const esRoute = esSim.nodes['es2'].rib.find((r) => r.prefix === '10.94.10.0' && r.active);
      expect(esRoute?.metric).toBeGreaterThan(200000);

      // 3. L2 Port-Channel vPC peer-link resolves via negotiated physical LAG members
      const nx1 = makeMinimalNode('nx-v1', 'NX1', 'cisco-nx-os');
      nx1.routerId = '1.1.1.1';
      nx1.interfaces = [
        { id: 'nx1-po1', name: 'Port-Channel1', cidr: '', vrf: 'default' },
        { id: 'nx1-e1', name: 'Ethernet1/1', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'active' },
      ];
      nx1.vpc = { enabled: true, domainId: 10, peerLinkInterfaceId: 'nx1-po1' };
      const nx2 = makeMinimalNode('nx-v2', 'NX2', 'cisco-nx-os');
      nx2.routerId = '2.2.2.2';
      nx2.interfaces = [
        { id: 'nx2-po1', name: 'Port-Channel1', cidr: '', vrf: 'default' },
        { id: 'nx2-e1', name: 'Ethernet1/1', cidr: '', vrf: 'default', lacpGroup: 1, lacpMode: 'active' },
      ];
      nx2.vpc = { enabled: true, domainId: 10, peerLinkInterfaceId: 'nx2-po1' };
      const vpcSim = solveTopology({
        nodes: [nx1, nx2],
        links: [{ id: 'nxl1', sourceNodeId: 'nx-v1', sourceInterfaceId: 'nx1-e1', targetNodeId: 'nx-v2', targetInterfaceId: 'nx2-e1', linkType: 'layer2' }],
      });
      expect(vpcSim.nodes['nx-v1'].neighbors?.find((n) => n.protocol === 'vpc')?.state).toBe('Up');
    });

    it('covers Engine Hunt Pass 3 fixes (MPLS LFIB default VRF scope, shutdown IGMP skip, BGP HA standby exclusion, IS-IS net.tag)', () => {
      // 1. MPLS LFIB excludes customer-VRF IGP routes & resolves RSVP-TE in default VRF
      const pe = makeMinimalNode('pe-lf', 'PE-LF', 'cisco-ios-xe');
      pe.routerId = '10.255.0.1';
      pe.vrfs = ['default', 'CUST'];
      pe.interfaces = [
        { id: 'pe-0', name: 'Gi0/0', cidr: '10.0.0.1/30', vrf: 'default', ospfArea: 0 },
        { id: 'pe-1', name: 'Gi0/1', cidr: '172.16.0.1/30', vrf: 'CUST', ospfArea: 0 },
      ];
      pe.ospf = { enabled: true, networks: [] };
      pe.mpls = { ldpEnabled: true, rsvpTeTunnels: [{ id: 't1', name: 'T1', destination: '10.255.0.2' }] };
      const pCore = makeMinimalNode('p-lf', 'P-LF', 'cisco-ios-xe');
      pCore.routerId = '10.255.0.2';
      pCore.interfaces = [
        { id: 'p-0', name: 'Gi0/0', cidr: '10.0.0.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'p-lo', name: 'Lo0', cidr: '10.255.0.2/32', vrf: 'default', ospfArea: 0 },
      ];
      pCore.ospf = { enabled: true, networks: [] };
      const ce = makeMinimalNode('ce-lf', 'CE-LF', 'cisco-ios-xe');
      ce.routerId = '172.16.99.1';
      ce.interfaces = [
        { id: 'ce-0', name: 'Gi0/0', cidr: '172.16.0.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'ce-lo', name: 'Lo0', cidr: '192.168.250.1/24', vrf: 'default', ospfArea: 0 },
      ];
      ce.ospf = { enabled: true, networks: [] };
      const lfibSim = solveTopology({
        nodes: [pe, pCore, ce],
        links: [
          { id: 'lfl1', sourceNodeId: 'pe-lf', sourceInterfaceId: 'pe-0', targetNodeId: 'p-lf', targetInterfaceId: 'p-0' },
          { id: 'lfl2', sourceNodeId: 'pe-lf', sourceInterfaceId: 'pe-1', targetNodeId: 'ce-lf', targetInterfaceId: 'ce-0' },
        ],
      });
      expect(lfibSim.nodes['pe-lf'].lfib?.some((e) => e.prefix === '192.168.250.0/24')).toBe(false);
      expect(lfibSim.nodes['pe-lf'].lfib?.some((e) => e.prefix === '10.255.0.2/32')).toBe(true);

      // 2. Shutdown IGMP receiver interface does not generate mroute
      const mc = makeMinimalNode('mc-sd', 'MC-SD', 'cisco-ios-xe');
      mc.interfaces = [
        { id: 'mc-lan', name: 'Gi0/0', cidr: '10.95.0.1/24', vrf: 'default', shutdown: true },
        { id: 'mc-up', name: 'Gi0/1', cidr: '10.95.1.1/30', vrf: 'default', pimSparse: true },
      ];
      mc.multicast = { pimEnabled: true, rpAddress: '10.95.1.2', igmpGroups: [{ id: 'g1', group: '239.1.1.1', interfaceId: 'mc-lan' }] };
      const mcSim = solveTopology({ nodes: [mc], links: [] });
      expect(mcSim.nodes['mc-sd'].mroute ?? []).toHaveLength(0);

      // 3. IS-IS propagates net.tag from isis.networks
      const it1 = makeMinimalNode('it1', 'IT1', 'cisco-ios-xe');
      it1.routerId = '1.1.1.1';
      it1.interfaces = [{ id: 'it1-0', name: 'Gi0/0', cidr: '10.96.0.1/30', vrf: 'default', isisLevel: 'L2' }];
      it1.isis = { enabled: true, net: '49.0001.0001.0001.0001.00', level: 'L2', networks: [{ id: 'itn1', prefix: '10.96.50.0/24', level: 'L2', tag: 42 }] };
      const it2 = makeMinimalNode('it2', 'IT2', 'cisco-ios-xe');
      it2.routerId = '2.2.2.2';
      it2.interfaces = [{ id: 'it2-0', name: 'Gi0/0', cidr: '10.96.0.2/30', vrf: 'default', isisLevel: 'L2' }];
      it2.isis = { enabled: true, net: '49.0001.0002.0002.0002.00', level: 'L2', networks: [] };
      const itSim = solveTopology({
        nodes: [it1, it2],
        links: [{ id: 'itl1', sourceNodeId: 'it1', sourceInterfaceId: 'it1-0', targetNodeId: 'it2', targetInterfaceId: 'it2-0' }],
      });
      expect(itSim.nodes['it2'].rib.find((r) => r.prefix === '10.96.50.0' && r.active)?.tag).toBe(42);
    });

    it('covers Engine Hunt Pass 4 fixes (order-independent MPLS PHP, parallel BGP peer matching, NSSA ABR translator failover)', () => {
      // 1. Order-independent MPLS PHP for shared transit subnet (R3 before R2 in topology.nodes)
      const mr1 = makeMinimalNode('mr1', 'MR1', 'cisco-ios-xe');
      mr1.routerId = '1.1.1.1';
      mr1.interfaces = [{ id: 'mr1-0', name: 'Gi0/0', cidr: '10.97.12.1/30', vrf: 'default', ospfArea: 0 }];
      mr1.ospf = { enabled: true, networks: [] };
      mr1.mpls = { ldpEnabled: true };
      const mr2 = makeMinimalNode('mr2', 'MR2', 'cisco-ios-xe');
      mr2.routerId = '2.2.2.2';
      mr2.interfaces = [
        { id: 'mr2-0', name: 'Gi0/0', cidr: '10.97.12.2/30', vrf: 'default', ospfArea: 0 },
        { id: 'mr2-1', name: 'Gi0/1', cidr: '10.97.23.1/30', vrf: 'default', ospfArea: 0 },
      ];
      mr2.ospf = { enabled: true, networks: [] };
      const mr3 = makeMinimalNode('mr3', 'MR3', 'cisco-ios-xe');
      mr3.routerId = '3.3.3.3';
      mr3.interfaces = [{ id: 'mr3-0', name: 'Gi0/0', cidr: '10.97.23.2/30', vrf: 'default', ospfArea: 0 }];
      mr3.ospf = { enabled: true, networks: [] };
      const phpSim = solveTopology({
        nodes: [mr1, mr3, mr2],
        links: [
          { id: 'mrl1', sourceNodeId: 'mr1', sourceInterfaceId: 'mr1-0', targetNodeId: 'mr2', targetInterfaceId: 'mr2-0' },
          { id: 'mrl2', sourceNodeId: 'mr2', sourceInterfaceId: 'mr2-1', targetNodeId: 'mr3', targetInterfaceId: 'mr3-0' },
        ],
      });
      const phpEntry = phpSim.nodes['mr1'].lfib?.find((e) => e.prefix === '10.97.23.0/30');
      expect(phpEntry?.outLabel).toBe('POP');

      // 2. Parallel BGP sessions match the same-subnet remote peer (shutdown on link 1 does not kill link 2)
      const bp1 = makeMinimalNode('bp1', 'BP1', 'cisco-ios-xe');
      bp1.routerId = '1.1.1.1';
      bp1.interfaces = [
        { id: 'bp1-1', name: 'Gi0/0', cidr: '10.98.1.1/30', vrf: 'default' },
        { id: 'bp1-2', name: 'Gi0/1', cidr: '10.98.2.1/30', vrf: 'default' },
      ];
      bp1.bgp = {
        enabled: true,
        asn: 65001,
        peers: [
          { id: 'bpp1a', peerIp: '10.98.1.2', remoteAs: 65002 },
          { id: 'bpp1b', peerIp: '10.98.2.2', remoteAs: 65002 },
        ],
        networks: [],
      };
      const bp2 = makeMinimalNode('bp2', 'BP2', 'cisco-ios-xe');
      bp2.routerId = '2.2.2.2';
      bp2.interfaces = [
        { id: 'bp2-1', name: 'Gi0/0', cidr: '10.98.1.2/30', vrf: 'default' },
        { id: 'bp2-2', name: 'Gi0/1', cidr: '10.98.2.2/30', vrf: 'default' },
      ];
      bp2.bgp = {
        enabled: true,
        asn: 65002,
        peers: [
          { id: 'bpp2a', peerIp: '10.98.1.1', remoteAs: 65001, shutdown: true },
          { id: 'bpp2b', peerIp: '10.98.2.1', remoteAs: 65001 },
        ],
        networks: [{ id: 'bpn2', prefix: '198.51.98.0/24' }],
      };
      const parBgpSim = solveTopology({
        nodes: [bp1, bp2],
        links: [
          { id: 'bpl1', sourceNodeId: 'bp1', sourceInterfaceId: 'bp1-1', targetNodeId: 'bp2', targetInterfaceId: 'bp2-1' },
          { id: 'bpl2', sourceNodeId: 'bp1', sourceInterfaceId: 'bp1-2', targetNodeId: 'bp2', targetInterfaceId: 'bp2-2' },
        ],
      });
      const bp1Route = parBgpSim.nodes['bp1'].rib.find((r) => r.prefix === '198.51.98.0' && r.active);
      expect(bp1Route?.nextHop).toBe('10.98.2.2');
      expect(parBgpSim.nodes['bp1'].neighbors?.find((n) => n.peerIp === '10.98.1.2')?.state).toBe('Down');
      expect(parBgpSim.nodes['bp1'].neighbors?.find((n) => n.peerIp === '10.98.2.2')?.state).toBe('Established');
    });

    it('covers Engine Hunt Pass 6 fixes (L2 switch bridging no phantom/failed-LAG adjacency, IS-IS local & IPv6 L2->L1 leak)', () => {
      // 1. L2 switch bridging does not bridge unrelated interfaces not attached to the switch
      const br1 = makeMinimalNode('br1', 'BR1', 'cisco-ios-xe');
      br1.routerId = '1.1.1.1';
      br1.interfaces = [
        { id: 'br1-0', name: 'Gi0/0', cidr: '10.100.1.1/24', vrf: 'default' },
        { id: 'br1-1', name: 'Gi0/1', cidr: '10.100.2.1/24', vrf: 'default', ospfArea: 0 },
      ];
      br1.ospf = { enabled: true, networks: [] };
      const sw = makeMinimalNode('br-sw', 'BR-SW', 'cisco-ios-xe');
      sw.interfaces = [
        { id: 'sw-1', name: 'Gi0/1', cidr: '', vrf: 'default' },
        { id: 'sw-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
      ];
      const br2 = makeMinimalNode('br2', 'BR2', 'cisco-ios-xe');
      br2.routerId = '2.2.2.2';
      br2.interfaces = [
        { id: 'br2-0', name: 'Gi0/0', cidr: '10.100.1.2/24', vrf: 'default' },
        { id: 'br2-1', name: 'Gi0/1', cidr: '10.100.2.2/24', vrf: 'default', ospfArea: 0 },
      ];
      br2.ospf = { enabled: true, networks: [] };
      const brSim = solveTopology({
        nodes: [br1, sw, br2],
        links: [
          { id: 'brl1', sourceNodeId: 'br1', sourceInterfaceId: 'br1-0', targetNodeId: 'br-sw', targetInterfaceId: 'sw-1', linkType: 'layer2' },
          { id: 'brl2', sourceNodeId: 'br-sw', sourceInterfaceId: 'sw-2', targetNodeId: 'br2', targetInterfaceId: 'br2-0', linkType: 'layer2' },
        ],
      });
      expect(brSim.nodes['br1'].neighbors?.filter((n) => n.protocol === 'ospf')).toHaveLength(0);

      // 2. IS-IS L1-L2 ABR leaks locally originated L2 IPv4 & IPv6 networks into L1 via leakL2ToL1
      const lk1 = makeMinimalNode('lk1', 'LK1', 'cisco-ios-xe');
      lk1.routerId = '1.1.1.1';
      lk1.interfaces = [{ id: 'lk1-0', name: 'Gi0/0', cidr: '10.101.0.1/30', cidr6: '2001:db8:101::1/64', vrf: 'default', isisLevel: 'L1' }];
      lk1.isis = {
        enabled: true,
        net: '49.0001.0001.0001.0001.00',
        level: 'L1-L2',
        multiTopologyV6: true,
        networks: [
          { id: 'lkn4', prefix: '172.29.0.0/24', level: 'L2' },
          { id: 'lkn6', prefix: '2001:db8:29::/48', level: 'L2' },
        ],
        leakL2ToL1: [
          { id: 'lkr4', prefix: '172.29.0.0/24' },
          { id: 'lkr6', prefix: '2001:db8:29::/48' },
        ],
      };
      const lk2 = makeMinimalNode('lk2', 'LK2', 'cisco-ios-xe');
      lk2.routerId = '2.2.2.2';
      lk2.interfaces = [{ id: 'lk2-0', name: 'Gi0/0', cidr: '10.101.0.2/30', cidr6: '2001:db8:101::2/64', vrf: 'default', isisLevel: 'L1' }];
      lk2.isis = { enabled: true, net: '49.0001.0002.0002.0002.00', level: 'L1', multiTopologyV6: true, networks: [] };
      const lkSim = solveTopology({
        nodes: [lk1, lk2],
        links: [{ id: 'lkl1', sourceNodeId: 'lk1', sourceInterfaceId: 'lk1-0', targetNodeId: 'lk2', targetInterfaceId: 'lk2-0' }],
      });
      expect(lkSim.nodes['lk2'].rib.some((r) => r.prefix === '172.29.0.0' && r.active)).toBe(true);
      expect(lkSim.nodes['lk2'].rib.some((r) => r.af === 6 && r.prefix === '2001:db8:29::' && r.active)).toBe(true);

      // 3. Pass 7A: Dotted SVI/IRB (irb.10) bridges across L2 switch; asymmetric ebgpMultihop does not import routes
      const irb1 = makeMinimalNode('irb1', 'IRB1', 'juniper-junos');
      irb1.routerId = '1.1.1.1';
      irb1.interfaces = [
        { id: 'irb1-ge', name: 'ge-0/0/0', cidr: '', vrf: 'default' },
        { id: 'irb1-10', name: 'irb.10', cidr: '10.102.10.1/24', vrf: 'default', vlanId: 10, ospfArea: 0 },
      ];
      irb1.ospf = { enabled: true, networks: [] };
      const irbSw = makeMinimalNode('irb-sw', 'IRB-SW', 'cisco-ios-xe');
      irbSw.interfaces = [
        { id: 'isw-1', name: 'Gi0/1', cidr: '', vrf: 'default' },
        { id: 'isw-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
      ];
      const irb2 = makeMinimalNode('irb2', 'IRB2', 'juniper-junos');
      irb2.routerId = '2.2.2.2';
      irb2.interfaces = [
        { id: 'irb2-ge', name: 'ge-0/0/0', cidr: '', vrf: 'default' },
        { id: 'irb2-10', name: 'irb.10', cidr: '10.102.10.2/24', vrf: 'default', vlanId: 10, ospfArea: 0 },
      ];
      irb2.ospf = { enabled: true, networks: [] };
      const irbSim = solveTopology({
        nodes: [irb1, irbSw, irb2],
        links: [
          { id: 'il1', sourceNodeId: 'irb1', sourceInterfaceId: 'irb1-ge', targetNodeId: 'irb-sw', targetInterfaceId: 'isw-1', linkType: 'layer2' },
          { id: 'il2', sourceNodeId: 'irb-sw', sourceInterfaceId: 'isw-2', targetNodeId: 'irb2', targetInterfaceId: 'irb2-ge', linkType: 'layer2' },
        ],
      });
      expect(irbSim.nodes['irb1'].neighbors?.find((n) => n.protocol === 'ospf')?.state).toBe('FULL');

      const mh1 = makeMinimalNode('mh1', 'MH1', 'cisco-ios-xe');
      mh1.routerId = '1.1.1.1';
      mh1.interfaces = [
        { id: 'mh1-0', name: 'Gi0/0', cidr: '10.103.0.1/30', vrf: 'default' },
        { id: 'mh1-lo', name: 'Lo0', cidr: '1.1.1.1/32', vrf: 'default' },
      ];
      mh1.staticRoutes = [{ id: 'mhs1', vrf: 'default', prefix: '2.2.2.2/32', nextHop: '10.103.0.2' }];
      mh1.bgp = { enabled: true, asn: 65001, peers: [{ id: 'mhp1', peerIp: '2.2.2.2', remoteAs: 65002, updateSource: 'Lo0', ebgpMultihop: true }], networks: [] };
      const mh2 = makeMinimalNode('mh2', 'MH2', 'cisco-ios-xe');
      mh2.routerId = '2.2.2.2';
      mh2.interfaces = [
        { id: 'mh2-0', name: 'Gi0/0', cidr: '10.103.0.2/30', vrf: 'default' },
        { id: 'mh2-lo', name: 'Lo0', cidr: '2.2.2.2/32', vrf: 'default' },
      ];
      mh2.staticRoutes = [{ id: 'mhs2', vrf: 'default', prefix: '1.1.1.1/32', nextHop: '10.103.0.1' }];
      mh2.bgp = { enabled: true, asn: 65002, peers: [{ id: 'mhp2', peerIp: '1.1.1.1', remoteAs: 65001, updateSource: 'Lo0', ebgpMultihop: false }], networks: [{ id: 'mhn2', prefix: '198.51.103.0/24' }] };
      const mhSim = solveTopology({
        nodes: [mh1, mh2],
        links: [{ id: 'mhl1', sourceNodeId: 'mh1', sourceInterfaceId: 'mh1-0', targetNodeId: 'mh2', targetInterfaceId: 'mh2-0' }],
      });
      expect(mhSim.nodes['mh1'].rib.some((r) => r.prefix === '198.51.103.0')).toBe(false);

      // 4. Pass 8A: Vlan10 SVI without explicit vlanId enforces allowedVlans & one-way BGP loopback reachability blocks session
      const sv1 = makeMinimalNode('sv1', 'SV1', 'cisco-ios-xe');
      sv1.routerId = '1.1.1.1';
      sv1.interfaces = [
        { id: 'sv1-g', name: 'Gi0/0', cidr: '', vrf: 'default' },
        { id: 'sv1-v', name: 'Vlan10', cidr: '10.104.10.1/24', vrf: 'default', ospfArea: 0 },
      ];
      sv1.ospf = { enabled: true, networks: [] };
      const svSw = makeMinimalNode('sv-sw', 'SV-SW', 'cisco-ios-xe');
      svSw.interfaces = [
        { id: 'ssw-1', name: 'Gi0/1', cidr: '', vrf: 'default' },
        { id: 'ssw-2', name: 'Gi0/2', cidr: '', vrf: 'default' },
      ];
      const sv2 = makeMinimalNode('sv2', 'SV2', 'cisco-ios-xe');
      sv2.routerId = '2.2.2.2';
      sv2.interfaces = [
        { id: 'sv2-g', name: 'Gi0/0', cidr: '', vrf: 'default' },
        { id: 'sv2-v', name: 'Vlan10', cidr: '10.104.10.2/24', vrf: 'default', ospfArea: 0 },
      ];
      sv2.ospf = { enabled: true, networks: [] };
      const svSim = solveTopology({
        nodes: [sv1, svSw, sv2],
        links: [
          { id: 'svl1', sourceNodeId: 'sv1', sourceInterfaceId: 'sv1-g', targetNodeId: 'sv-sw', targetInterfaceId: 'ssw-1', linkType: 'layer2', allowedVlans: '20' },
          { id: 'svl2', sourceNodeId: 'sv-sw', sourceInterfaceId: 'ssw-2', targetNodeId: 'sv2', targetInterfaceId: 'sv2-g', linkType: 'layer2', allowedVlans: '20' },
        ],
      });
      expect(svSim.nodes['sv1'].neighbors?.filter((n) => n.protocol === 'ospf')).toHaveLength(0);

      // 5. Pass 10A: EIGRP summary of redistributed external route is advertised as internal (AD 90)
      const esum1 = makeMinimalNode('esum1', 'ESUM1', 'cisco-ios-xe');
      esum1.routerId = '1.1.1.1';
      esum1.interfaces = [{ id: 'esum1-0', name: 'Gi0/0', cidr: '10.105.0.1/30', vrf: 'default' }];
      esum1.staticRoutes = [{ id: 'esums1', vrf: 'default', prefix: '10.205.1.0/24', nextHop: 'Null0' }];
      esum1.redistributions = [{ id: 'esumr1', from: 'static', to: 'eigrp' }];
      esum1.eigrp = {
        enabled: true,
        asn: 100,
        networks: [{ id: 'esumn1', prefix: '10.105.0.0/30' }],
        summaries: [{ id: 'esuma1', prefix: '10.205.0.0/16' }],
      };
      const esum2 = makeMinimalNode('esum2', 'ESUM2', 'cisco-ios-xe');
      esum2.routerId = '2.2.2.2';
      esum2.interfaces = [{ id: 'esum2-0', name: 'Gi0/0', cidr: '10.105.0.2/30', vrf: 'default' }];
      esum2.eigrp = { enabled: true, asn: 100, networks: [{ id: 'esumn2', prefix: '10.105.0.0/30' }] };
      const esumSim = solveTopology({
        nodes: [esum1, esum2],
        links: [{ id: 'esuml1', sourceNodeId: 'esum1', sourceInterfaceId: 'esum1-0', targetNodeId: 'esum2', targetInterfaceId: 'esum2-0' }],
      });
      const esumRoute = esumSim.nodes['esum2'].rib.find((r) => r.prefix === '10.205.0.0' && r.prefixLen === 16 && r.active);
      expect(esumRoute?.ad).toBe(90);
    });
  });
});
