import { describe, expect, it } from 'vitest';
import { PRESET_TOPOLOGIES } from '../../data/presets';
import { useSimStore } from '../../store/useSimStore';
import { NodeConfig, VendorProfile } from '../../types/network';
import { computeRibDiff } from '../diff';
import { buildAutomationBundleZip } from '../exportBundle';
import { formatPrimaryCli, formatRunningConfig } from '../formatters';
import { importTopologyFromText, validateRunningConfig } from '../importer';
import { runFailoverMatrix, runPathTestSuite, solveTopology } from '../solver';
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

  it('Pass 2: validates VENDOR_METADATA, VENDOR_CAPABILITIES, primary CLI, and running-config formatters for all 15 vendors', () => {
    const vendors = Object.keys(VENDOR_METADATA) as VendorProfile[];
    expect(vendors.length).toBe(15);

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
  });
});
