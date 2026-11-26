import { describe, expect, it } from 'vitest';
import { PRESET_TOPOLOGIES } from '../../data/presets';
import { solveTopology, tracePacket } from '../solver';
import type { TopologyState } from '../../types/network';

function getMultinationalTopology(): TopologyState {
  const preset = PRESET_TOPOLOGIES.find((p) => p.id === 'global-multinational');
  if (!preset) {
    throw new Error('global-multinational preset not found');
  }
  return structuredClone(preset.topology);
}

describe('Multinational Network (Spine-Leaf + Global WAN + Multi-Vendor)', () => {
  it('converges cleanly with zero warnings across all 24 nodes and 26 links', () => {
    const topo = getMultinationalTopology();
    expect(topo.nodes).toHaveLength(24);
    expect(topo.links).toHaveLength(26);

    const res = solveTopology(topo);
    expect(res.warnings).toHaveLength(0);
    for (const node of topo.nodes) {
      expect(res.nodes[node.id]).toBeDefined();
    }
  });

  describe('US-East HQ Spine-Leaf Fabric & Perimeter HA', () => {
    it('brings up NX-OS vPC Domain 100, Arista MLAG, IS-IS L2, and PAN-OS Active-Active HSCI', () => {
      const topo = getMultinationalTopology();
      const res = solveTopology(topo);

      expect(
        res.nodes['us-nx1'].neighbors?.some((n) => n.protocol === 'vpc' && n.state === 'Up')
      ).toBe(true);
      expect(
        res.nodes['us-nx2'].neighbors?.some((n) => n.protocol === 'vpc' && n.state === 'Up')
      ).toBe(true);

      expect(
        res.nodes['us-ar1'].neighbors?.some((n) => n.protocol === 'mlag' && n.state === 'Up')
      ).toBe(true);
      expect(
        res.nodes['us-ar1'].neighbors?.some((n) => n.protocol === 'isis' && n.state === 'Up')
      ).toBe(true);

      expect(
        res.nodes['us-pa1'].neighbors?.some(
          (n) => n.protocol === 'ha' && n.detail?.includes('HSCI')
        )
      ).toBe(true);
      expect(
        res.nodes['us-pa2'].neighbors?.some((n) => n.protocol === 'ha')
      ).toBe(true);
    });

    it('aggregates 10.10.0.0/16 (summary-only) on NX-OS and applies PREF_US_HQ Local-Pref 150 on PAN-OS', () => {
      const topo = getMultinationalTopology();
      const res = solveTopology(topo);

      const pa1Agg = res.nodes['us-pa1'].rib.find(
        (r) => r.prefix === '10.10.0.0' && r.prefixLen === 16
      );
      expect(pa1Agg).toBeDefined();
      expect(pa1Agg?.bgpAttrs?.localPref).toBe(150);

      // summary-only suppresses more-specific 10.10.100.0/24 via eBGP to us-pa1
      const pa1Specific = res.nodes['us-pa1'].rib.find(
        (r) => r.prefix === '10.10.100.0' && r.prefixLen === 24 && r.protocol === 'ebgp'
      );
      expect(pa1Specific).toBeUndefined();
    });
  });

  describe('EU-Frankfurt Remote DC (FortiGate FGCP + IOS-XE)', () => {
    it('forms FortiGate FGCP Active-Passive HA, OSPF Area 10 stub + summary, OSPFv3, and HSRP', () => {
      const topo = getMultinationalTopology();
      const res = solveTopology(topo);

      expect(
        res.nodes['eu-fgt1'].neighbors?.some((n) => n.protocol === 'ha' && n.state === 'Active')
      ).toBe(true);
      expect(
        res.nodes['eu-fgt2'].neighbors?.some((n) => n.protocol === 'ha' && n.state === 'Standby')
      ).toBe(true);
      expect(
        res.nodes['eu-ios1'].neighbors?.some((n) => n.protocol === 'hsrp' && n.state === 'Active')
      ).toBe(true);

      // OSPFv3 IPv6 connected/OSPF route on eu-ios1
      expect(
        res.nodes['eu-ios1'].rib.some((r) => r.af === 6 && r.prefix === '2001:db8:20::')
      ).toBe(true);

      // EU learns US aggregate and AWS VPC via MPLS BGP -> OSPF redistribution
      expect(
        res.nodes['eu-ios1'].rib.some((r) => r.prefix === '10.10.0.0' && r.prefixLen === 16)
      ).toBe(true);
      expect(
        res.nodes['eu-ios1'].rib.some((r) => r.prefix === '172.31.10.0' && r.prefixLen === 24)
      ).toBe(true);
    });
  });

  describe('APAC-Tokyo Remote Site (Forcepoint Cluster + IOS-XE)', () => {
    it('forms Forcepoint Cluster HA, EIGRP, HSRP, VRF guest->default leak, and IP SLA Track 1', () => {
      const topo = getMultinationalTopology();
      const res = solveTopology(topo);

      expect(
        res.nodes['ap-fp1'].neighbors?.some((n) => n.protocol === 'ha' && n.state === 'Active')
      ).toBe(true);
      expect(
        res.nodes['ap-fp2'].neighbors?.some((n) => n.protocol === 'ha' && n.state === 'Standby')
      ).toBe(true);
      expect(
        res.nodes['ap-ios1'].neighbors?.some((n) => n.protocol === 'hsrp' && n.state === 'Active')
      ).toBe(true);

      expect(
        res.nodes['ap-ios1'].rib.some(
          (r) =>
            r.prefix === '10.30.99.0' &&
            r.prefixLen === 24 &&
            r.vrf === 'default' &&
            r.leakedFromVrf === 'guest'
        )
      ).toBe(true);

      expect(
        res.nodes['ap-ios1'].rib.some(
          (r) => r.prefix === '198.51.100.0' && r.prefixLen === 24 && r.protocol === 'static'
        )
      ).toBe(true);
    });
  });

  describe('End-to-End Packet Traces, PMTUD, and Security Policies', () => {
    it('delivers APAC -> AWS traffic over IPsec with accurate latency and 1400B path MTU', () => {
      const topo = getMultinationalTopology();
      const res = solveTopology(topo);

      const trace = tracePacket(topo, res, 'ap-ios1', '172.31.10.10', 'default', {
        srcIp: '10.30.10.10',
        protocol: 'tcp',
        dstPort: 443,
      });
      expect(trace.outcome).toBe('delivered');
      expect(trace.totalLatencyMs).toBe(124);
      expect(trace.pathMtu).toBe(1400);

      const jumboTrace = tracePacket(topo, res, 'ap-ios1', '172.31.10.10', 'default', {
        srcIp: '10.30.10.10',
        protocol: 'tcp',
        dstPort: 443,
        packetSize: 1600,
      });
      expect(jumboTrace.outcome).toBe('delivered');
      expect(jumboTrace.mtuWarning).toContain('exceeds path MTU 1400B');
    });

    it('delivers EU -> US-East HQ HTTPS traffic and blocks WAN Telnet via PAN-OS ACL', () => {
      const topo = getMultinationalTopology();
      const res = solveTopology(topo);

      const euToUs = tracePacket(topo, res, 'eu-ios1', '10.10.100.1', 'default', {
        srcIp: '10.20.1.10',
        protocol: 'tcp',
        dstPort: 443,
      });
      expect(euToUs.outcome).toBe('delivered');

      const wanTelnet = tracePacket(topo, res, 'gl-mpls', '10.10.100.1', 'default', {
        srcIp: '198.51.100.5',
        protocol: 'tcp',
        dstPort: 23,
      });
      expect(wanTelnet.outcome).toBe('blocked');
      expect(wanTelnet.failureReason).toContain('BLOCK_TELNET_WAN');
    });
  });

  describe('Fault-Injection & Failure Scenarios', () => {
    it('withdraws AWS route when the US-PA1 <-> AWS IPsec link is admin-down', () => {
      const topo = getMultinationalTopology();
      topo.links = topo.links.map((l) => (l.id === 'gl-11' ? { ...l, adminDown: true } : l));

      const res = solveTopology(topo);
      expect(
        res.nodes['ap-ios1'].rib.some((r) => r.prefix === '172.31.10.0' && r.prefixLen === 24)
      ).toBe(false);

      const trace = tracePacket(topo, res, 'ap-ios1', '172.31.10.10', 'default', {
        srcIp: '10.30.10.10',
      });
      expect(trace.outcome).not.toBe('delivered');
    });

    it('trips IP SLA Track 1 on ap-ios1 when US-HQ uplink (gl-7) goes admin-down', () => {
      const topo = getMultinationalTopology();
      topo.links = topo.links.map((l) => (l.id === 'gl-7' ? { ...l, adminDown: true } : l));

      const res = solveTopology(topo);
      expect(
        res.nodes['ap-ios1'].rib.some(
          (r) => r.prefix === '198.51.100.0' && r.prefixLen === 24 && r.protocol === 'static'
        )
      ).toBe(false);
    });

    it('emits an MTU mismatch warning when Spine-Leaf link MTU is mismatched', () => {
      const topo = getMultinationalTopology();
      topo.nodes = topo.nodes.map((n) =>
        n.id === 'us-ar1'
          ? {
              ...n,
              interfaces: n.interfaces.map((i) =>
                i.id === 'us-ar1-e1' ? { ...i, mtu: 1500 } : i
              ),
            }
          : n
      );

      const res = solveTopology(topo);
      expect(res.warnings.some((w) => w.includes('MTU mismatch'))).toBe(true);
    });
  });
});
