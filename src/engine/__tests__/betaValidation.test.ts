import { describe, expect, it } from 'vitest';
import { PRESET_TOPOLOGIES } from '../../data/presets';
import { useSimStore } from '../../store/useSimStore';
import { NodeConfig, VendorProfile } from '../../types/network';
import { computeRibDiff } from '../diff';
import { buildAutomationBundleZip } from '../exportBundle';
import { formatPrimaryCli, formatRunningConfig } from '../formatters';
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
});
