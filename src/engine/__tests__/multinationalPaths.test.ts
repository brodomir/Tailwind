import { describe, expect, it } from 'vitest';
import { PRESET_TOPOLOGIES } from '../../data/presets';
import { runPathTestSuite, solveTopology, tracePacket } from '../solver';
import type { TopologyState } from '../../types/network';

function getMultinationalTopology(): TopologyState {
  const preset = PRESET_TOPOLOGIES.find((p) => p.id === 'global-multinational');
  if (!preset) {
    throw new Error('global-multinational preset not found');
  }
  return structuredClone(preset.topology);
}

describe('Multinational Network Full Path Test Matrix', () => {
  const topo = getMultinationalTopology();
  const sim = solveTopology(topo);

  describe('Intra-HQ Spine-Leaf Fabric & Cloud (US-East)', () => {
    it('delivers Leaf-1 <-> Leaf-2 jumbo traffic across NX-OS Spine with 9000B path MTU', () => {
      const trace = tracePacket(topo, sim, 'us-ar1', '10.10.201.1', 'default', {
        srcIp: '10.10.200.10',
        protocol: 'tcp',
        dstPort: 443,
        packetSize: 8500,
      });

      expect(trace.outcome).toBe('delivered');
      expect(trace.pathMtu).toBe(9000);
      expect(trace.mtuWarning).toBeUndefined();
      expect(trace.totalLatencyMs).toBe(2);
      expect(trace.hops.map((h) => h.nodeId)).toEqual(['us-ar1', 'us-nx1', 'us-ar2']);
    });

    it('delivers US-East Leaf-1 -> AWS US-East TGW over IPsec with 1400B path MTU', () => {
      const trace = tracePacket(topo, sim, 'us-ar1', '172.31.10.10', 'default', {
        srcIp: '10.10.200.10',
        protocol: 'tcp',
        dstPort: 443,
      });

      expect(trace.outcome).toBe('delivered');
      expect(trace.pathMtu).toBe(1400);
      expect(trace.totalLatencyMs).toBe(17);
      expect(trace.hops.map((h) => h.nodeId)).toEqual(['us-ar1', 'us-nx1', 'us-pa1', 'aws-us']);
    });
  });

  describe('Inter-Region Full Mesh (US-East <-> EU-Frankfurt <-> APAC-Tokyo <-> AWS)', () => {
    const interRegionCases = [
      {
        name: 'US-East Leaf-1 -> EU-Frankfurt LAN',
        srcNodeId: 'us-ar1',
        srcIp: '10.10.200.10',
        dstIp: '10.20.1.10',
        expectedHops: ['us-ar1', 'us-nx1', 'us-pa1', 'gl-mpls', 'eu-fgt1', 'eu-ios1'],
        expectedLatencyMs: 61,
        expectedMtu: 1500,
      },
      {
        name: 'US-East Leaf-2 -> APAC-Tokyo LAN',
        srcNodeId: 'us-ar2',
        srcIp: '10.10.201.10',
        dstIp: '10.30.1.10',
        expectedHops: ['us-ar2', 'us-nx1', 'us-pa1', 'gl-mpls', 'ap-fp1', 'ap-ios1'],
        expectedLatencyMs: 111,
        expectedMtu: 1500,
      },
      {
        name: 'EU-Frankfurt LAN -> US-East Leaf-1',
        srcNodeId: 'eu-ios1',
        srcIp: '10.20.1.10',
        dstIp: '10.10.200.1',
        expectedHops: ['eu-ios1', 'eu-fgt1', 'gl-mpls', 'us-pa1', 'us-nx1', 'us-ar1'],
        expectedLatencyMs: 61,
        expectedMtu: 1500,
      },
      {
        name: 'EU-Frankfurt LAN -> APAC-Tokyo LAN',
        srcNodeId: 'eu-ios1',
        srcIp: '10.20.1.10',
        dstIp: '10.30.1.10',
        expectedHops: ['eu-ios1', 'eu-fgt1', 'gl-mpls', 'ap-fp1', 'ap-ios1'],
        expectedLatencyMs: 144,
        expectedMtu: 1500,
      },
      {
        name: 'EU-Frankfurt LAN -> AWS US-East VPC',
        srcNodeId: 'eu-ios1',
        srcIp: '10.20.1.10',
        dstIp: '172.31.10.10',
        expectedHops: ['eu-ios1', 'eu-fgt1', 'gl-mpls', 'us-pa1', 'aws-us'],
        expectedLatencyMs: 74,
        expectedMtu: 1400,
      },
      {
        name: 'APAC-Tokyo LAN -> US-East Leaf-1',
        srcNodeId: 'ap-ios1',
        srcIp: '10.30.1.10',
        dstIp: '10.10.200.1',
        expectedHops: ['ap-ios1', 'ap-fp1', 'gl-mpls', 'us-pa1', 'us-nx1', 'us-ar1'],
        expectedLatencyMs: 111,
        expectedMtu: 1500,
      },
      {
        name: 'APAC-Tokyo LAN -> EU-Frankfurt LAN',
        srcNodeId: 'ap-ios1',
        srcIp: '10.30.1.10',
        dstIp: '10.20.1.10',
        expectedHops: ['ap-ios1', 'ap-fp1', 'gl-mpls', 'eu-fgt1', 'eu-ios1'],
        expectedLatencyMs: 144,
        expectedMtu: 1500,
      },
      {
        name: 'APAC-Tokyo LAN -> AWS US-East VPC',
        srcNodeId: 'ap-ios1',
        srcIp: '10.30.1.10',
        dstIp: '172.31.10.10',
        expectedHops: ['ap-ios1', 'ap-fp1', 'gl-mpls', 'us-pa1', 'aws-us'],
        expectedLatencyMs: 124,
        expectedMtu: 1400,
      },
    ];

    it.each(interRegionCases)(
      'delivers $name with expected hop sequence, latency, and path MTU',
      ({ srcNodeId, srcIp, dstIp, expectedHops, expectedLatencyMs, expectedMtu }) => {
        const trace = tracePacket(topo, sim, srcNodeId, dstIp, 'default', {
          srcIp,
          protocol: 'tcp',
          dstPort: 443,
        });

        expect(trace.outcome).toBe('delivered');
        expect(trace.hops.map((h) => h.nodeId)).toEqual(expectedHops);
        expect(trace.totalLatencyMs).toBe(expectedLatencyMs);
        expect(trace.pathMtu).toBe(expectedMtu);
        expect(trace.returnTrace?.outcome).toBe('delivered');
      }
    );
  });

  describe('VRF Route-Leaking & Tracked Static Paths', () => {
    it('delivers US-East -> APAC leaked guest VRF subnet (10.30.99.0/24)', () => {
      const trace = tracePacket(topo, sim, 'us-ar1', '10.30.99.10', 'default', {
        srcIp: '10.10.200.10',
        protocol: 'tcp',
        dstPort: 443,
      });

      expect(trace.outcome).toBe('delivered');
      expect(trace.hops.map((h) => h.nodeId)).toEqual([
        'us-ar1',
        'us-nx1',
        'us-pa1',
        'gl-mpls',
        'ap-fp1',
        'ap-ios1',
      ]);
    });

    it('forwards APAC -> 198.51.100.5 via IP SLA Track 1 static route when US-HQ is up, and drops when gl-7 fails', () => {
      const upTrace = tracePacket(topo, sim, 'ap-ios1', '198.51.100.5', 'default', {
        srcIp: '10.30.1.10',
      });
      expect(upTrace.hops[0].matchedPrefix).toBe('198.51.100.0/24');
      expect(upTrace.hops[0].protocol).toBe('static');

      const failedTopo = getMultinationalTopology();
      failedTopo.links = failedTopo.links.map((l) =>
        l.id === 'gl-7' ? { ...l, adminDown: true } : l
      );
      const failedSim = solveTopology(failedTopo);
      const downTrace = tracePacket(failedTopo, failedSim, 'ap-ios1', '198.51.100.5', 'default', {
        srcIp: '10.30.1.10',
      });
      expect(downTrace.outcome).toBe('dropped');
    });
  });

  describe('Security Policies & ACL Enforcement Paths', () => {
    it('blocks Telnet (TCP/23) from EU-Frankfurt and MPLS WAN into US-East HQ at US-PA-FW-1', () => {
      const euTelnet = tracePacket(topo, sim, 'eu-ios1', '10.10.100.1', 'default', {
        srcIp: '10.20.1.10',
        protocol: 'tcp',
        dstPort: 23,
      });
      expect(euTelnet.outcome).toBe('blocked');
      expect(euTelnet.blockedNodeId).toBe('us-pa1');
      expect(euTelnet.failureReason).toContain('BLOCK_TELNET_WAN');

      const wanTelnet = tracePacket(topo, sim, 'gl-mpls', '10.10.100.1', 'default', {
        srcIp: '198.51.100.5',
        protocol: 'tcp',
        dstPort: 23,
      });
      expect(wanTelnet.outcome).toBe('blocked');
      expect(wanTelnet.blockedNodeId).toBe('us-pa1');
      expect(wanTelnet.failureReason).toContain('BLOCK_TELNET_WAN');
    });

    it('blocks non-corporate WAN -> Cloud traffic via PAN-OS implicit zone deny', () => {
      const rogueCloud = tracePacket(topo, sim, 'gl-mpls', '172.31.10.10', 'default', {
        srcIp: '192.0.2.50',
        protocol: 'tcp',
        dstPort: 443,
      });
      expect(rogueCloud.outcome).toBe('blocked');
      expect(rogueCloud.blockedNodeId).toBe('us-pa1');
    });
  });

  describe('PMTUD & Oversized Packet Warnings Across WAN & IPsec', () => {
    it('flags jumbo 8500B packet crossing 1500B MPLS WAN and 1450B packet crossing 1400B IPsec', () => {
      const wanOversize = tracePacket(topo, sim, 'us-ar1', '10.20.1.10', 'default', {
        srcIp: '10.10.200.10',
        packetSize: 8500,
      });
      expect(wanOversize.outcome).toBe('delivered');
      expect(wanOversize.pathMtu).toBe(1500);
      expect(wanOversize.mtuWarning).toContain('exceeds path MTU 1500B');

      const ipsecOversize = tracePacket(topo, sim, 'ap-ios1', '172.31.10.10', 'default', {
        srcIp: '10.30.1.10',
        packetSize: 1450,
      });
      expect(ipsecOversize.outcome).toBe('delivered');
      expect(ipsecOversize.pathMtu).toBe(1400);
      expect(ipsecOversize.mtuWarning).toContain('exceeds path MTU 1400B');
    });
  });

  describe('In-App Path & Policy Verification Suite Preset Assertions', () => {
    it('passes all 17 built-in UI Path & Policy Verification Suite assertions', () => {
      const preset = PRESET_TOPOLOGIES.find((p) => p.id === 'global-multinational');
      expect(preset?.pathTests).toBeDefined();
      expect(preset?.pathTests).toHaveLength(17);

      const summary = runPathTestSuite(topo, sim, preset?.pathTests ?? []);
      expect(summary.failed).toBe(0);
      expect(summary.passed).toBe(17);
    });
  });
});

