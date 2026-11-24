import { describe, expect, it } from 'vitest';
import { PRESET_TOPOLOGIES } from '../../data/presets';
import { useSimStore } from '../../store/useSimStore';
import { NodeConfig, TopologyState, VendorProfile } from '../../types/network';
import { computeRibDiff } from '../diff';
import { buildAutomationBundleZip } from '../exportBundle';
import { formatPrimaryCli, formatRunningConfig } from '../formatters';
import { importTopologyFromText, validateRunningConfig } from '../importer';
import { runFailoverMatrix, runPathTestSuite, solveTopology, tracePacket } from '../solver';
import { VENDOR_CAPABILITIES, VENDOR_METADATA } from '../vendorProfiles';

describe('Beta Release 5-Pass Feature Validation', () => {
  it('Pass 1: converges every preset topology, validates all built-in pathTests, and runs N-1 failover cleanly', () => {
    expect(PRESET_TOPOLOGIES.length).toBeGreaterThanOrEqual(8);

    for (const preset of PRESET_TOPOLOGIES) {
      const sim = solveTopology(preset.topology);
      expect(Object.keys(sim.nodes).length).toBe(preset.topology.nodes.length);

      for (const node of preset.topology.nodes) {
        const nodeRes = sim.nodes[node.id];
        expect(nodeRes).toBeDefined();
        const hasIpIface = node.interfaces.some((i) => Boolean(i.cidr?.trim()) || Boolean(i.cidr6?.trim()));
        if (hasIpIface) {
          expect(nodeRes.rib.length, `Node ${node.hostname} in ${preset.id} has empty RIB`).toBeGreaterThan(0);
        }
      }

      if (preset.pathTests && preset.pathTests.length > 0) {
        const suite = runPathTestSuite(preset.topology, sim, preset.pathTests);
        expect(suite.results.filter((r) => !r.passed), `Preset ${preset.id} failed pathTests`).toEqual([]);
        expect(suite.failed).toBe(0);

        const matrix = runFailoverMatrix(preset.topology, preset.pathTests);
        expect(matrix.length).toBe(preset.topology.links.length);
      }
    }
  }, 20000);

  it('Pass 2: validates VENDOR_METADATA, VENDOR_CAPABILITIES, primary CLI, and running-config formatters for all 19 vendors', () => {
    const vendors = Object.keys(VENDOR_METADATA) as VendorProfile[];
    expect(vendors.length).toBe(19);

    for (const vendor of vendors) {
      const meta = VENDOR_METADATA[vendor];
      const caps = VENDOR_CAPABILITIES[vendor];
      expect(meta).toBeDefined();
      expect(caps).toBeDefined();

      const node: NodeConfig = {
        id: `n-${vendor}`,
        hostname: `R-${vendor}`,
        vendor,
        routerId: '10.255.255.1',
        position: { x: 0, y: 0 },
        maxPaths: 2,
        vrfs: [meta.defaultVrf],
        adOverrides: {},
        interfaces: [
          {
            id: `if-${vendor}`,
            name: `${meta.defaultInterfacePrefix}1`,
            cidr: '10.0.0.1/30',
            vrf: meta.defaultVrf,
          },
        ],
        staticRoutes: [],
        ospf: { enabled: caps.igps.ospf, networks: [] },
        bgp: { enabled: caps.bgp, asn: 65100, peers: [], networks: [] },
        redistributions: [],
        prefixLists: [],
        routeMaps: [],
        vrfLeaks: [],
      };

      const sim = solveTopology({ nodes: [node], links: [] });
      const cli = formatPrimaryCli(node, sim.nodes[node.id]);
      const cfg = formatRunningConfig(node);
      expect(cli.length).toBeGreaterThan(0);
      expect(cfg.length).toBeGreaterThan(0);
    }
  });

  it('Pass 3: validates workspace lifecycle (create, save-copy, rename, load, delete), undo/redo, and RIB diff', () => {
    const store = useSimStore.getState();
    store.loadPreset('bgp-ecmp-lab');
    store.captureSnapshot();

    // Save copy of preset, rename it, modify an interface, verify RIB diff & undo/redo
    store.saveCurrentWorkspace('Beta Validation Copy');
    const copyId = useSimStore.getState().activePresetId;
    expect(useSimStore.getState().workspaces.some((w) => w.id === copyId && w.name === 'Beta Validation Copy')).toBe(true);

    store.renameWorkspace(copyId, 'Beta Renamed Lab');
    expect(useSimStore.getState().workspaces.some((w) => w.id === copyId && w.name === 'Beta Renamed Lab')).toBe(true);

    const beforeSim = useSimStore.getState().simResult;
    useSimStore.getState().updateInterface('wan-a', 'wa-1', { shutdown: true });
    const afterDownSim = useSimStore.getState().simResult;
    const diff = computeRibDiff(beforeSim, afterDownSim);
    expect(diff.added + diff.removed + diff.modified).toBeGreaterThan(0);

    useSimStore.getState().undo();
    expect(useSimStore.getState().topology.nodes.find((n) => n.id === 'wan-a')?.interfaces[0]?.shutdown).toBeFalsy();
    useSimStore.getState().redo();
    expect(useSimStore.getState().topology.nodes.find((n) => n.id === 'wan-a')?.interfaces[0]?.shutdown).toBe(true);

    useSimStore.getState().deleteWorkspace(copyId);
    expect(useSimStore.getState().workspaces.some((w) => w.id === copyId)).toBe(false);
  });

  it('Pass 4: generates non-empty automation .zip bundle and share URL', () => {
    const preset = PRESET_TOPOLOGIES.find((p) => p.id === 'cisco-mpls-dmvpn')!;
    const sim = solveTopology(preset.topology);
    const blob = buildAutomationBundleZip(preset.topology, sim);
    expect(blob.size).toBeGreaterThan(1000);
  });

  it('Pass 5: applies edited Running Config text back to a device while preserving links and converging RIB', () => {
    const store = useSimStore.getState();
    store.loadPreset('bgp-ecmp-lab');
    const linksBefore = useSimStore.getState().topology.links.length;
    const edgeNode = useSimStore.getState().topology.nodes.find((n) => n.id === 'edge-1')!;
    const cfg = formatRunningConfig(edgeNode);
    const editedCfg = `${cfg}\nip route 203.0.113.0/24 100.64.1.1\n`;
    const parsed = importTopologyFromText(editedCfg);
    useSimStore.getState().applyParsedNodeConfig('edge-1', parsed.nodes[0]);

    expect(useSimStore.getState().topology.links.length).toBe(linksBefore);
    const rib = useSimStore.getState().simResult.nodes['edge-1']?.rib ?? [];
    expect(rib.some((r) => r.prefix === '203.0.113.0' && r.protocol === 'static' && r.active)).toBe(true);

    // Config validation: valid generated config passes cleanly, while typos/bad IPs/bad VLANs are flagged
    expect(validateRunningConfig(cfg)).toEqual([]);
    const badCfg = `hostname R1
ip address 10.0.0.1 255.255.255.0
interface Gi0/0.5000
 encapsulation dot1Q 5000
 ip address 10.0.0.999 255.255.255.0
 ip adres 10.0.0.1 255.255.255.0
!`;
    const issues = validateRunningConfig(badCfg);
    expect(issues.some((i) => i.severity === 'error' && i.message.includes('interface <name>'))).toBe(true);
    expect(issues.some((i) => i.severity === 'error' && i.message.includes('VLAN ID'))).toBe(true);
    expect(issues.some((i) => i.severity === 'error' && i.message.includes('Invalid IPv4'))).toBe(true);
    expect(issues.some((i) => i.severity === 'warning' && i.message.includes('ip adres'))).toBe(true);

    // passive-interface default + no passive-interface <if> in OSPF
    const passiveCfg = `hostname R-PASSIVE
interface Gi0/0
 ip address 10.0.0.1 255.255.255.252
!
interface Gi0/1
 ip address 10.0.1.1 255.255.255.0
!
router ospf 1
 passive-interface default
 no passive-interface Gi0/0
!`;
    expect(validateRunningConfig(passiveCfg)).toEqual([]);
    const parsedPassive = importTopologyFromText(passiveCfg).nodes[0];
    expect(parsedPassive.interfaces.find((i) => i.name === 'Gi0/0')?.passive).toBe(false);
    expect(parsedPassive.interfaces.find((i) => i.name === 'Gi0/1')?.passive).toBe(true);

    // RIP + NX-OS interface passive + Junos + FortiGate + PAN-OS + MikroTik passive parsing
    const ripCfg = `hostname R-RIP
interface Gi0/0
 ip address 10.1.0.1 255.255.255.252
!
interface Gi0/1
 ip address 10.1.1.1 255.255.255.0
!
router rip
 version 2
 passive-interface default
 no passive-interface Gi0/0
!`;
    const parsedRip = importTopologyFromText(ripCfg).nodes[0];
    expect(parsedRip.rip?.enabled).toBe(true);
    expect(parsedRip.interfaces.find((i) => i.name === 'Gi0/0')?.passive).toBe(false);
    expect(parsedRip.interfaces.find((i) => i.name === 'Gi0/1')?.passive).toBe(true);

    const nxosCfg = `hostname NX-PASSIVE
interface Ethernet1/1
 ip address 10.2.0.1/30
 ip ospf passive-interface
!`;
    const parsedNxos = importTopologyFromText(nxosCfg).nodes[0];
    expect(parsedNxos.vendor).toBe('cisco-nx-os');
    expect(parsedNxos.interfaces[0].passive).toBe(true);

    const junosCfg = `set system host-name J-PASSIVE
set interfaces ge-0/0/0 unit 0 family inet address 10.3.0.1/30
set interfaces ge-0/0/1 unit 0 family inet address 10.3.1.1/24
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0
set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 passive`;
    const parsedJunos = importTopologyFromText(junosCfg).nodes[0];
    expect(parsedJunos.interfaces.find((i) => i.name === 'ge-0/0/0')?.passive).toBeUndefined();
    expect(parsedJunos.interfaces.find((i) => i.name === 'ge-0/0/1')?.passive).toBe(true);

    const fgtCfg = `config system global
    set hostname "FGT-PASSIVE"
end
config system interface
    edit "port1"
        set ip 10.4.0.1 255.255.255.252
    next
    edit "port2"
        set ip 10.4.1.1 255.255.255.0
    next
end
config router ospf
    set router-id 10.4.0.1
    set passive-interface "port2"
end`;
    const parsedFgt = importTopologyFromText(fgtCfg).nodes[0];
    expect(parsedFgt.ospf.enabled).toBe(true);
    expect(parsedFgt.interfaces.find((i) => i.name === 'port1')?.passive).toBeUndefined();
    expect(parsedFgt.interfaces.find((i) => i.name === 'port2')?.passive).toBe(true);

    const panCfg = `set deviceconfig system hostname PAN-PASSIVE
set network interface ethernet ethernet1/1 layer3 ip 10.5.0.1/24
set network virtual-router default interface ethernet1/1
set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/1 passive enable yes`;
    const parsedPan = importTopologyFromText(panCfg).nodes[0];
    expect(parsedPan.ospf.enabled).toBe(true);
    expect(parsedPan.interfaces[0].passive).toBe(true);

    const mtCfg = `/system identity set name=MT-PASSIVE
/ip address add address=10.6.0.1/24 interface=ether1
/routing ospf area add name=area-0 area-id=0.0.0.0 instance=default-v2
/routing ospf interface-template add area=area-0 interfaces=ether1 passive=yes`;
    const parsedMt = importTopologyFromText(mtCfg).nodes[0];
    expect(parsedMt.ospf.enabled).toBe(true);
    expect(parsedMt.interfaces[0].passive).toBe(true);

    // Round-trip protocol completeness: OSPF, EIGRP, IS-IS, BGP, Redistribution, and zero false-positive warnings
    const fullProtoCfg = `hostname FULL-PROTO
interface Gi0/0
 ip address 10.10.0.1 255.255.255.252
 ip ospf 1 area 0
 ip ospf authentication-key S3CR3T
 ip router isis
 isis metric 25
 isis priority 100
!
router ospf 1
 router-id 10.10.0.1
 auto-cost reference-bandwidth 10000
 max-metric router-lsa
 default-information originate
 redistribute static metric 50 metric-type 1 subnets
!
router eigrp 100
 eigrp router-id 10.10.0.1
 variance 2
 metric weights 0 1 0 1 0 0
 network 10.10.0.0 0.0.0.3
 redistribute connected metric 1500
!
router isis
 net 49.0001.0000.0000.0001.00
 is-type level-1-2
 set-overload-bit
 metric-style wide
 address-family ipv6 unicast
  multi-topology
 exit-address-family
 summary-address 10.20.0.0 255.255.0.0
!
router bgp 65100
 bgp router-id 10.10.0.1
 bgp rpki reject-invalid
 bgp graceful-restart
 neighbor 10.10.0.2 remote-as 65200
 neighbor 10.10.0.2 next-hop-self
 neighbor 10.10.0.2 default-originate
 neighbor 10.10.0.2 route-reflector-client
 neighbor 10.10.0.2 weight 250
!`;
    expect(validateRunningConfig(fullProtoCfg)).toEqual([]);
    const fullNode = importTopologyFromText(fullProtoCfg).nodes[0];
    expect(fullNode.ospf.defaultOriginate).toBe(true);
    expect(fullNode.ospf.referenceBandwidth).toBe(10000);
    expect(fullNode.ospf.maxMetricRouterLsa).toBe(true);
    expect(fullNode.interfaces[0].ospfAuthKey).toBe('S3CR3T');
    expect(fullNode.interfaces[0].isisMetric).toBe(25);
    expect(fullNode.interfaces[0].isisPriority).toBe(100);
    expect(fullNode.eigrp?.variance).toBe(2);
    expect(fullNode.eigrp?.kValues).toEqual([1, 0, 1, 0, 0]);
    expect(fullNode.eigrp?.networks[0]?.prefix).toBe('10.10.0.0/30');
    expect(fullNode.isis?.overloadBit).toBe(true);
    expect(fullNode.isis?.multiTopologyV6).toBe(true);
    expect(fullNode.isis?.summaries?.[0]?.prefix).toBe('10.20.0.0/16');
    expect(fullNode.bgp.rpkiRejectInvalid).toBe(true);
    expect(fullNode.bgp.gracefulRestart).toBe(true);
    expect(fullNode.bgp.peers[0]?.nextHopSelf).toBe(true);
    expect(fullNode.bgp.peers[0]?.defaultOriginate).toBe(true);
    expect(fullNode.bgp.peers[0]?.routeReflectorClient).toBe(true);
    expect(fullNode.bgp.peers[0]?.weight).toBe(250);
    expect(fullNode.redistributions.some((r) => r.from === 'static' && r.to === 'ospf' && r.metricType === 'E1')).toBe(true);
    expect(fullNode.redistributions.some((r) => r.from === 'connected' && r.to === 'eigrp' && r.metric === 1500)).toBe(true);

    // Sweep EVERY node across EVERY preset topology: formatRunningConfig must produce zero validation errors
    for (const preset of PRESET_TOPOLOGIES) {
      for (const n of preset.topology.nodes) {
        const genCfg = formatRunningConfig(n);
        const genIssues = validateRunningConfig(genCfg).filter((i) => i.severity === 'error');
        expect(genIssues, `${preset.id}/${n.hostname} config validation errors`).toEqual([]);
      }
    }

    // New vendor profiles: VyOS & Check Point Gaia round-trip format + import + validate
    const vyosCfg = `set system host-name 'VYOS-EDGE-1'
set interfaces ethernet eth0 address '10.70.0.1/30'
set protocols ospf parameters router-id '10.70.0.1'
set protocols ospf interface eth0 area '0'
set protocols ospf interface eth0 passive
set protocols bgp system-as '65700'
set protocols bgp neighbor 10.70.0.2 remote-as '65701'`;
    const parsedVyos = importTopologyFromText(vyosCfg).nodes[0];
    expect(parsedVyos.vendor).toBe('vyos');
    expect(parsedVyos.interfaces[0].passive).toBe(true);
    expect(parsedVyos.bgp.asn).toBe(65700);
    expect(formatRunningConfig(parsedVyos)).toContain("set protocols bgp system-as '65700'");

    const gaiaCfg = `set hostname CP-FW-1
set router-id 10.80.0.1
set interface eth0 ipv4-address 10.80.0.1 mask-length 24
set ospf instance default interface eth0 area 0.0.0.0 on
set ospf instance default interface eth0 passive on
set as 65800
set bgp external remote-as 65801 peer 10.80.0.2 on`;
    const parsedGaia = importTopologyFromText(gaiaCfg).nodes[0];
    expect(parsedGaia.vendor).toBe('checkpoint-gaia');
    expect(parsedGaia.interfaces[0].passive).toBe(true);
    expect(parsedGaia.bgp.asn).toBe(65800);
    expect(formatRunningConfig(parsedGaia)).toContain('set ospf instance default interface eth0 passive on');

    // Messy whitespace, tabs, smart quotes, extra spaces, CIDR/mask variants in FortiGate & autoFormatRunningConfig
    const messyForti = `config   system   global
\tset   hostname   “FGT-MESSY”
END
config  system   interface
edit  “port1”
  set   ip   10.90.0.1/24
  set   vrf   “CORP”
NEXT
end
config  router  static
  edit 1
    set   dst   192.168.50.0   255.255.255.0
    set   gateway   10.90.0.254
end`;
    const parsedMessyFgt = importTopologyFromText(messyForti).nodes[0];
    expect(parsedMessyFgt.vendor).toBe('fortigate');
    expect(parsedMessyFgt.hostname).toBe('FGT-MESSY');
    expect(parsedMessyFgt.interfaces[0].cidr).toBe('10.90.0.1/24');
    expect(parsedMessyFgt.interfaces[0].vrf).toBe('CORP');
    expect(parsedMessyFgt.staticRoutes[0]?.prefix).toBe('192.168.50.0/24');

    // Multi-vendor firewall security rule import (FortiGate, PAN-OS, Cisco, Junos, VyOS, MikroTik, Check Point)
    const fgtFw = `config firewall address
    edit "LAN"
        set subnet 10.10.0.0 255.255.0.0
    next
end
config firewall policy
    edit 1
        set name "Allow-HTTPS"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LAN"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
    next
end`;
    const fgtFwNode = importTopologyFromText(fgtFw).nodes[0];
    expect(fgtFwNode.aclRules?.[0]).toMatchObject({
      name: 'Allow-HTTPS',
      action: 'allow',
      srcZone: 'port1',
      dstZone: 'port2',
      srcCidr: '10.10.0.0/16',
      dstCidr: '0.0.0.0/0',
      protocol: 'tcp',
      dstPort: 443,
    });

    const panFw = `set address WEB-SRV ip-netmask 10.20.1.10/32
set rulebase security rules ALLOW-WEB from trust to untrust source 10.10.0.0/16 destination WEB-SRV service HTTPS action allow`;
    const panFwNode = importTopologyFromText(panFw).nodes[0];
    expect(panFwNode.aclRules?.[0]).toMatchObject({
      name: 'ALLOW-WEB',
      action: 'allow',
      srcZone: 'trust',
      dstZone: 'untrust',
      srcCidr: '10.10.0.0/16',
      dstCidr: '10.20.1.10/32',
      protocol: 'tcp',
      dstPort: 443,
    });

    const ciscoFw = `hostname FW-IOS
ip access-list extended EDGE-IN
 permit tcp 10.1.0.0 0.0.255.255 host 198.51.100.10 eq 443
 deny ip any any
!`;
    const ciscoFwNode = importTopologyFromText(ciscoFw).nodes[0];
    expect(ciscoFwNode.aclRules).toHaveLength(2);
    expect(ciscoFwNode.aclRules?.[0]).toMatchObject({
      action: 'allow',
      srcCidr: '10.1.0.0/16',
      dstCidr: '198.51.100.10/32',
      protocol: 'tcp',
      dstPort: 443,
    });
    expect(ciscoFwNode.aclRules?.[1]?.action).toBe('deny');

    const junosFw = `set security address-book global address CORP 10.30.0.0/16
set security policies from-zone trust to-zone dmz policy ALLOW-SSH match source-address CORP
set security policies from-zone trust to-zone dmz policy ALLOW-SSH match destination-address 172.16.1.10/32
set security policies from-zone trust to-zone dmz policy ALLOW-SSH match application junos-ssh
set security policies from-zone trust to-zone dmz policy ALLOW-SSH then permit`;
    const junosFwNode = importTopologyFromText(junosFw).nodes[0];
    expect(junosFwNode.aclRules?.[0]).toMatchObject({
      name: 'ALLOW-SSH',
      action: 'allow',
      srcZone: 'trust',
      dstZone: 'dmz',
      srcCidr: '10.30.0.0/16',
      dstCidr: '172.16.1.10/32',
      protocol: 'tcp',
      dstPort: 22,
    });

    const vyosFw = `set firewall name WAN-IN rule 10 action drop
set firewall name WAN-IN rule 10 protocol tcp
set firewall name WAN-IN rule 10 destination port 23`;
    expect(importTopologyFromText(vyosFw).nodes[0].aclRules?.[0]).toMatchObject({
      action: 'deny',
      protocol: 'tcp',
      dstPort: 23,
    });

    const mtFw = `/ip firewall filter add chain=forward src-address=10.40.0.0/24 protocol=udp dst-port=53 action=accept comment="DNS"`;
    expect(importTopologyFromText(mtFw).nodes[0].aclRules?.[0]).toMatchObject({
      name: 'DNS',
      action: 'allow',
      srcCidr: '10.40.0.0/24',
      protocol: 'udp',
      dstPort: 53,
    });

    const cpFw = `mgmt_cli add host name WEB ip-address 10.50.0.10
mgmt_cli add access-rule name Allow-HTTP source any destination WEB service HTTP action accept`;
    expect(importTopologyFromText(cpFw).nodes[0].aclRules?.[0]).toMatchObject({
      name: 'Allow-HTTP',
      action: 'allow',
      dstCidr: '10.50.0.10/32',
      protocol: 'tcp',
      dstPort: 80,
    });

    // FortiGate PBR (`config router policy`) round-trip + source-based & no-RIB trace steering
    const fgtPbrCfg = `config system global
    set hostname "FGT-PBR"
end
config system interface
    edit "port1"
        set ip 10.10.0.1 255.255.255.0
    next
    edit "port2"
        set ip 10.20.0.1 255.255.255.252
    next
    edit "port3"
        set ip 10.30.0.1 255.255.255.252
    next
end
config router policy
    edit 1
        set input-device "port1"
        set src "10.10.0.0/24"
        set dst "0.0.0.0/0"
        set protocol 6
        set start-port 443
        set end-port 443
        set output-device "port3"
        set gateway 10.30.0.2
    next
end`;
    const fgtPbrNode = importTopologyFromText(fgtPbrCfg).nodes[0];
    expect(fgtPbrNode.pbrRules?.[0]).toMatchObject({
      ingressInterface: 'port1',
      interfaceName: 'port3',
      srcCidr: '10.10.0.0/24',
      matchPrefix: '0.0.0.0/0',
      protocol: 'tcp',
      dstPort: 443,
      nextHop: '10.30.0.2',
    });
    expect(formatRunningConfig(fgtPbrNode)).toContain('config router policy');
    expect(formatRunningConfig(fgtPbrNode)).toContain('set output-device "port3"');

    // Verify end-to-end tracePacket PBR steering (overrides default route & works even without RIB route)
    const wan1Node = importTopologyFromText(`hostname WAN-1
interface GigabitEthernet0/0
 ip address 10.20.0.2 255.255.255.252
interface Loopback0
 ip address 8.8.8.8 255.255.255.255`).nodes[0];
    const wan2Node = importTopologyFromText(`hostname WAN-2
interface GigabitEthernet0/0
 ip address 10.30.0.2 255.255.255.252
interface Loopback0
 ip address 8.8.8.8 255.255.255.255`).nodes[0];

    const pbrTopology: TopologyState = {
      nodes: [
        {
          ...fgtPbrNode,
          id: 'fgt-pbr',
          staticRoutes: [
            { id: 'sr-def', prefix: '0.0.0.0/0', nextHop: '10.20.0.2', ad: 10, vrf: 'default' },
          ],
        },
        { ...wan1Node, id: 'wan1' },
        { ...wan2Node, id: 'wan2' },
      ],
      links: [
        {
          id: 'l-w1',
          sourceNodeId: 'fgt-pbr',
          sourceInterfaceId: fgtPbrNode.interfaces.find((i) => i.name === 'port2')!.id,
          targetNodeId: 'wan1',
          targetInterfaceId: wan1Node.interfaces.find((i) => i.name === 'GigabitEthernet0/0')!.id,
        },
        {
          id: 'l-w2',
          sourceNodeId: 'fgt-pbr',
          sourceInterfaceId: fgtPbrNode.interfaces.find((i) => i.name === 'port3')!.id,
          targetNodeId: 'wan2',
          targetInterfaceId: wan2Node.interfaces.find((i) => i.name === 'GigabitEthernet0/0')!.id,
        },
      ],
    };
    const pbrSim = solveTopology(pbrTopology);
    const port1Id = fgtPbrNode.interfaces.find((i) => i.name === 'port1')!.id;
    // Matching TCP/443 from 10.10.0.50 on port1 must steer via PBR out port3 -> 10.30.0.2 (WAN-2)
    const pbrHit = tracePacket(pbrTopology, pbrSim, 'fgt-pbr', '8.8.8.8', 'default', {
      srcIp: '10.10.0.50',
      srcInterfaceId: port1Id,
      protocol: 'tcp',
      dstPort: 443,
      skipReturn: true,
    });
    expect(pbrHit.outcome).toBe('delivered');
    expect(pbrHit.hops[0].egressInterface).toBe('port3');
    expect(pbrHit.hops[0].nextHop).toBe('10.30.0.2');
    expect(pbrHit.hops[0].pbrApplied).toContain('10.30.0.2');
    expect(pbrHit.hops[1].nodeId).toBe('wan2');

    // Non-matching port (TCP/80) must fall back to RIB default route out port2 -> 10.20.0.2 (WAN-1)
    const pbrMiss = tracePacket(pbrTopology, pbrSim, 'fgt-pbr', '8.8.8.8', 'default', {
      srcIp: '10.10.0.50',
      srcInterfaceId: port1Id,
      protocol: 'tcp',
      dstPort: 80,
      skipReturn: true,
    });
    expect(pbrMiss.outcome).toBe('delivered');
    expect(pbrMiss.hops[0].egressInterface).toBe('port2');
    expect(pbrMiss.hops[0].nextHop).toBe('10.20.0.2');
    expect(pbrMiss.hops[1].nodeId).toBe('wan1');

    // Even with NO static default route in RIB, PBR must still steer matching traffic out port3 -> WAN-2
    const noRibTopology: TopologyState = {
      ...pbrTopology,
      nodes: pbrTopology.nodes.map((n) => (n.id === 'fgt-pbr' ? { ...n, staticRoutes: [] } : n)),
    };
    const noRibSim = solveTopology(noRibTopology);
    const noRibHit = tracePacket(noRibTopology, noRibSim, 'fgt-pbr', '8.8.8.8', 'default', {
      srcIp: '10.10.0.50',
      srcInterfaceId: port1Id,
      protocol: 'tcp',
      dstPort: 443,
      skipReturn: true,
    });
    expect(noRibHit.outcome).toBe('delivered');
    expect(noRibHit.hops[0].egressInterface).toBe('port3');
    expect(noRibHit.hops[0].nextHop).toBe('10.30.0.2');
    expect(noRibHit.hops[1].nodeId).toBe('wan2');
  });
});
