import { compressToEncodedURIComponent, decompressFromEncodedURIComponent } from 'lz-string';
import { create } from 'zustand';
import { PRESET_TOPOLOGIES } from '../data/presets';
import { solveTopology, tracePacket } from '../engine/solver';
import { VENDOR_METADATA } from '../engine/vendorProfiles';
import {
  InterfaceConfig,
  L4Protocol,
  LinkConfig,
  NodeConfig,
  PacketTraceResult,
  PathTestCase,
  RoaEntry,
  SimulationResult,
  TopologyState,
  VendorProfile,
} from '../types/network';

export type ProtocolOverlayMode = 'none' | 'bgp-asn' | 'ospf-area' | 'stp';

export interface SavedWorkspace {
  id: string;
  name: string;
  topology: TopologyState;
  pathTests?: PathTestCase[];
  updatedAt: number;
}

const WORKSPACE_STORAGE_KEY = 'rib-sim-workspaces-v1';
const THEME_STORAGE_KEY = 'rib-sim-theme-v1';

export type ThemeMode = 'dark' | 'light';

function applyHtmlThemeClass(mode: ThemeMode) {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  root.classList.toggle('dark', mode === 'dark');
  root.classList.toggle('light', mode === 'light');
  root.style.colorScheme = mode;
}

function loadInitialThemeMode(): ThemeMode {
  let mode: ThemeMode = 'dark';
  if (typeof localStorage !== 'undefined') {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') mode = saved;
  }
  applyHtmlThemeClass(mode);
  return mode;
}

function loadSavedWorkspaces(): SavedWorkspace[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(WORKSPACE_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as SavedWorkspace[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persistWorkspaces(workspaces: SavedWorkspace[]) {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(WORKSPACE_STORAGE_KEY, JSON.stringify(workspaces));
  } catch {
    // Ignore storage quota errors
  }
}

function normalizeTopology(t: TopologyState): TopologyState {
  return {
    ...t,
    links: Array.isArray(t.links) ? t.links : [],
    nodes: (Array.isArray(t.nodes) ? t.nodes : []).map((n, idx) => ({
      ...n,
      vendor: n.vendor && VENDOR_METADATA[n.vendor] ? n.vendor : 'cisco-ios-xe',
      vrfs: n.vrfs?.length ? n.vrfs : ['default'],
      adOverrides: n.adOverrides ?? {},
      interfaces: Array.isArray(n.interfaces) ? n.interfaces : [],
      staticRoutes: Array.isArray(n.staticRoutes) ? n.staticRoutes : [],
      ospf: n.ospf
        ? { ...n.ospf, networks: Array.isArray(n.ospf.networks) ? n.ospf.networks : [] }
        : { enabled: false, networks: [] },
      bgp: n.bgp
        ? {
            ...n.bgp,
            peers: Array.isArray(n.bgp.peers) ? n.bgp.peers : [],
            networks: Array.isArray(n.bgp.networks) ? n.bgp.networks : [],
          }
        : { enabled: false, asn: 65000, peers: [], networks: [] },
      redistributions: Array.isArray(n.redistributions) ? n.redistributions : [],
      prefixLists: Array.isArray(n.prefixLists) ? n.prefixLists : [],
      routeMaps: Array.isArray(n.routeMaps) ? n.routeMaps : [],
      vrfLeaks: Array.isArray(n.vrfLeaks) ? n.vrfLeaks : [],
      position:
        n.position && Number.isFinite(n.position.x) && Number.isFinite(n.position.y)
          ? n.position
          : { x: 160 + (idx % 4) * 220, y: 120 + Math.floor(idx / 4) * 160 },
    })),
  };
}

function loadInitialTopology(): { topology: TopologyState; fromHash: boolean } {
  if (typeof window !== 'undefined' && window.location.hash.startsWith('#s=')) {
    try {
      const compressed = window.location.hash.slice(3);
      if (compressed.length > 500_000) {
        return { topology: structuredClone(PRESET_TOPOLOGIES[0].topology), fromHash: false };
      }
      const json = decompressFromEncodedURIComponent(compressed);
      if (json && json.length <= 4_000_000) {
        const parsed = JSON.parse(json) as TopologyState;
        if (parsed && typeof parsed === 'object' && Array.isArray(parsed.nodes) && Array.isArray(parsed.links)) {
          return { topology: normalizeTopology(parsed), fromHash: true };
        }
      }
    } catch {
      // Fallback to default preset when URL hash is malformed
    }
  }
  return { topology: structuredClone(PRESET_TOPOLOGIES[0].topology), fromHash: false };
}

let workerInstance: Worker | null = null;
let workerReqId = 0;

function getWorker(): Worker | null {
  if (typeof Worker === 'undefined') return null;
  if (!workerInstance) {
    workerInstance = new Worker(
      new URL('../workers/simWorker.ts', import.meta.url),
      { type: 'module' }
    );
  }
  return workerInstance;
}

interface SimStore {
  topology: TopologyState;
  simResult: SimulationResult;
  baselineSimResult: SimulationResult | null;
  workspaces: SavedWorkspace[];
  selectedNodeId: string | null;
  viewportCenter: { x: number; y: number } | null;
  setViewportCenter: (center: { x: number; y: number } | null) => void;
  activePresetId: string;
  traceSrcNodeId: string;
  traceSrcInterfaceId?: string;
  traceSrcIp?: string;
  traceDstIp: string;
  traceVrf: string;
  traceProto: L4Protocol;
  tracePort?: number;
  traceResult: PacketTraceResult | null;
  pathTests: PathTestCase[];
  themeMode: ThemeMode;
  protocolOverlay: ProtocolOverlayMode;

  toggleThemeMode: () => void;
  setProtocolOverlay: (mode: ProtocolOverlayMode) => void;
  setRoaTable: (roaTable: RoaEntry[]) => void;
  selectNode: (nodeId: string | null) => void;
  loadPreset: (presetId: string) => void;
  createWorkspace: (name: string) => void;
  saveCurrentWorkspace: (name?: string) => void;
  renameWorkspace: (workspaceId: string, name: string) => void;
  loadWorkspace: (workspaceId: string) => void;
  deleteWorkspace: (workspaceId: string) => void;
  importTopology: (topology: TopologyState) => void;
  mergeImportedNodes: (nodes: NodeConfig[], links?: LinkConfig[]) => void;
  hydrateMatchingNodes: (nodes: NodeConfig[]) => number;
  applyParsedNodeConfig: (nodeId: string, parsedNode: NodeConfig) => void;
  captureSnapshot: () => void;
  clearSnapshot: () => void;
  setTraceParams: (
    srcNodeId: string,
    dstIp: string,
    vrf?: string,
    proto?: L4Protocol,
    port?: number | null,
    srcInterfaceId?: string,
    srcIp?: string | null
  ) => void;
  runTrace: () => void;
  clearTrace: () => void;
  setTraceResult: (res: PacketTraceResult) => void;
  addPathTest: (test: PathTestCase) => void;
  deletePathTest: (id: string) => void;
  getShareUrl: () => string;

  addNode: (vendor: VendorProfile) => void;
  duplicateNode: (nodeId: string) => void;
  updateNode: (nodeId: string, patch: Partial<NodeConfig>) => void;
  updateNodePosition: (nodeId: string, position: { x: number; y: number }) => void;
  deleteNode: (nodeId: string) => void;

  addInterface: (nodeId: string, iface: InterfaceConfig) => void;
  updateInterface: (nodeId: string, ifaceId: string, patch: Partial<InterfaceConfig>) => void;
  deleteInterface: (nodeId: string, ifaceId: string) => void;

  addLink: (link: LinkConfig) => void;
  updateLink: (linkId: string, patch: Partial<LinkConfig>) => void;
  deleteLink: (linkId: string) => void;
  setVrfColor: (vrf: string, color: string) => void;
  autoLayoutTopology: () => void;

  past: TopologyState[];
  future: TopologyState[];
  undo: () => void;
  redo: () => void;
}

const { topology: initialTopology, fromHash: loadedFromHash } = loadInitialTopology();
const initialSim = solveTopology(initialTopology);

export const useSimStore = create<SimStore>((set, get) => {
  const applySolvedResult = (topology: TopologyState, simResult: SimulationResult) => {
    const state = get();
    set({
      simResult,
      traceResult: state.traceResult
        ? tracePacket(
            topology,
            simResult,
            state.traceSrcNodeId,
            state.traceDstIp,
            state.traceVrf,
            {
              srcIp: state.traceSrcIp,
              srcInterfaceId: state.traceSrcInterfaceId,
              protocol: state.traceProto,
              dstPort: state.tracePort,
            }
          )
        : null,
    });
  };

  const triggerSolve = (topology: TopologyState) => {
    const worker = getWorker();
    if (!worker) {
      applySolvedResult(topology, solveTopology(topology));
      return;
    }

    const reqId = ++workerReqId;
    worker.onmessage = (
      event: MessageEvent<{ id: number; result?: SimulationResult; error?: string }>
    ) => {
      if (event.data.id !== workerReqId) return;
      if (event.data.error || !event.data.result) {
        try {
          applySolvedResult(get().topology, solveTopology(get().topology));
        } catch {
          // Keep current state if fallback solve also fails
        }
        return;
      }
      applySolvedResult(get().topology, event.data.result);
    };
    worker.onerror = () => {
      try {
        applySolvedResult(get().topology, solveTopology(get().topology));
      } catch {
        // Keep current state if fallback solve also fails
      }
    };
    worker.postMessage({ id: reqId, topology });
  };

  return {
    topology: initialTopology,
    simResult: initialSim,
    baselineSimResult: null,
    workspaces: loadSavedWorkspaces(),
    selectedNodeId: initialTopology.nodes[1]?.id ?? initialTopology.nodes[0]?.id ?? null,
    viewportCenter: null,
    setViewportCenter: (center) => set({ viewportCenter: center }),
    activePresetId: loadedFromHash ? '' : PRESET_TOPOLOGIES[0].id,
    past: [],
    future: [],
    undo: () => {
      const { past, topology, future } = get();
      if (past.length === 0) return;
      const previous = past[past.length - 1];
      set({
        topology: previous,
        past: past.slice(0, -1),
        future: [structuredClone(topology), ...future].slice(0, 30),
      });
      triggerSolve(previous);
    },
    redo: () => {
      const { past, topology, future } = get();
      if (future.length === 0) return;
      const next = future[0];
      set({
        topology: next,
        past: [...past, structuredClone(topology)].slice(-30),
        future: future.slice(1),
      });
      triggerSolve(next);
    },
    traceSrcNodeId: initialTopology.nodes[2]?.id ?? initialTopology.nodes[0]?.id ?? '',
    traceSrcInterfaceId: undefined,
    traceSrcIp: undefined,
    traceDstIp: '8.8.8.8',
    traceVrf: 'default',
    traceProto: 'any',
    tracePort: undefined,
    traceResult: null,
    pathTests: loadedFromHash ? [] : structuredClone(PRESET_TOPOLOGIES[0].pathTests ?? []),
    themeMode: loadInitialThemeMode(),
    protocolOverlay: 'none',

    setProtocolOverlay: (mode) => set({ protocolOverlay: mode }),
    setRoaTable: (roaTable) => {
      const { topology, past } = get();
      const next: TopologyState = { ...topology, roaTable };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    toggleThemeMode: () =>
      set((state) => {
        const next: ThemeMode = state.themeMode === 'dark' ? 'light' : 'dark';
        applyHtmlThemeClass(next);
        if (typeof localStorage !== 'undefined') {
          try {
            localStorage.setItem(THEME_STORAGE_KEY, next);
          } catch {
            // Ignore storage errors
          }
        }
        return { themeMode: next };
      }),

    selectNode: (nodeId) => set({ selectedNodeId: nodeId }),

    captureSnapshot: () =>
      set((state) => ({
        baselineSimResult: structuredClone(state.simResult),
      })),

    clearSnapshot: () => set({ baselineSimResult: null }),

    loadPreset: (presetId) => {
      const preset = PRESET_TOPOLOGIES.find((p) => p.id === presetId);
      if (!preset) return;
      const topology = structuredClone(preset.topology);
      set({
        topology,
        activePresetId: presetId,
        baselineSimResult: null,
        selectedNodeId: topology.nodes[0]?.id ?? null,
        traceSrcNodeId: topology.nodes[0]?.id ?? '',
        traceVrf: 'default',
        traceResult: null,
        pathTests: structuredClone(preset.pathTests ?? []),
        past: [],
        future: [],
      });
      triggerSolve(topology);
    },

    importTopology: (rawTopology) => {
      const topology = normalizeTopology(rawTopology);
      set({
        topology,
        activePresetId: 'custom-import',
        baselineSimResult: null,
        selectedNodeId: topology.nodes[0]?.id ?? null,
        traceSrcNodeId: topology.nodes[0]?.id ?? '',
        traceVrf: 'default',
        traceResult: null,
        pathTests: [],
        past: [],
        future: [],
      });
      triggerSolve(topology);
    },

    mergeImportedNodes: (nodes, links = []) => {
      const { topology } = get();
      if (!nodes.length) return;
      const existingIds = new Set(topology.nodes.map((n) => n.id));
      const idMap = new Map<string, string>();
      const offset = topology.nodes.length * 40;
      const normalized = normalizeTopology({ nodes, links: [] }).nodes.map((n, i) => {
        let uniqueId = n.id;
        let suffix = 1;
        while (existingIds.has(uniqueId)) {
          uniqueId = `${n.id}-${suffix++}`;
        }
        existingIds.add(uniqueId);
        idMap.set(n.id, uniqueId);
        return {
          ...n,
          id: uniqueId,
          position:
            links.length > 0 && n.position
              ? { x: n.position.x + offset, y: n.position.y }
              : { x: 160 + offset + i * 60, y: 120 + (i % 3) * 60 },
        };
      });
      const existingLinkIds = new Set(topology.links.map((l) => l.id));
      const mergedLinks: LinkConfig[] = links
        .map((l, idx) => {
          const srcId = idMap.get(l.sourceNodeId) ?? l.sourceNodeId;
          const dstId = idMap.get(l.targetNodeId) ?? l.targetNodeId;
          let linkId = l.id || `imp-link-${Date.now()}-${idx}`;
          let suffix = 1;
          while (existingLinkIds.has(linkId)) {
            linkId = `${l.id}-${suffix++}`;
          }
          existingLinkIds.add(linkId);
          return {
            ...l,
            id: linkId,
            sourceNodeId: srcId,
            targetNodeId: dstId,
          };
        })
        .filter(
          (l) =>
            (idMap.has(l.sourceNodeId) || topology.nodes.some((n) => n.id === l.sourceNodeId) || normalized.some((n) => n.id === l.sourceNodeId)) &&
            (idMap.has(l.targetNodeId) || topology.nodes.some((n) => n.id === l.targetNodeId) || normalized.some((n) => n.id === l.targetNodeId))
        );
      const next: TopologyState = {
        ...topology,
        nodes: [...topology.nodes, ...normalized],
        links: [...topology.links, ...mergedLinks],
      };
      set({
        topology: next,
        selectedNodeId: normalized[0]?.id ?? get().selectedNodeId,
        past: [...get().past.slice(-29), topology],
        future: [],
      });
      triggerSolve(next);
    },

    hydrateMatchingNodes: (parsedNodes) => {
      const { topology } = get();
      if (!parsedNodes.length) return 0;

      const normIf = (name: string) =>
        name
          .toLowerCase()
          .replace(/^gigabitethernet/, 'gi')
          .replace(/^tengigabitethernet/, 'te')
          .replace(/^fastethernet/, 'fa')
          .replace(/^ethernet/, 'eth')
          .replace(/^port-channel/, 'po')
          .replace(/[^a-z0-9/.]/g, '');

      let matchedCount = 0;
      const nextNodes = topology.nodes.map((existing) => {
        const match = parsedNodes.find(
          (p) =>
            p.hostname.trim().toLowerCase() === existing.hostname.trim().toLowerCase() ||
            p.id === existing.id
        );
        if (!match) return existing;
        matchedCount++;

        const usedParsedIds = new Set<string>();
        const mergedIfaces = existing.interfaces.map((exIf) => {
          const exNorm = normIf(exIf.name);
          const pIf = match.interfaces.find(
            (mIf) =>
              mIf.name.toLowerCase() === exIf.name.toLowerCase() ||
              normIf(mIf.name) === exNorm
          );
          if (!pIf) return exIf;
          usedParsedIds.add(pIf.id);
          return {
            ...exIf,
            cidr: pIf.cidr,
            cidr6: pIf.cidr6 ?? exIf.cidr6,
            vrf: pIf.vrf || exIf.vrf,
            ospfArea: pIf.ospfArea ?? exIf.ospfArea,
            ospfCost: pIf.ospfCost ?? exIf.ospfCost,
            passive: pIf.passive ?? exIf.passive,
            mtu: pIf.mtu ?? exIf.mtu,
            shutdown: pIf.shutdown ?? exIf.shutdown,
          };
        });

        for (const pIf of match.interfaces) {
          if (!usedParsedIds.has(pIf.id)) {
            mergedIfaces.push(pIf);
          }
        }

        return {
          ...existing,
          vendor: match.vendor,
          routerId: match.routerId || existing.routerId,
          vrfs: match.vrfs?.length ? match.vrfs : existing.vrfs,
          interfaces: mergedIfaces,
          staticRoutes: match.staticRoutes,
          ospf: match.ospf,
          bgp: match.bgp,
          eigrp: match.eigrp ?? existing.eigrp,
          isis: match.isis ?? existing.isis,
          rip: match.rip ?? existing.rip,
          redistributions: match.redistributions,
          prefixLists: match.prefixLists?.length ? match.prefixLists : existing.prefixLists,
          routeMaps: match.routeMaps?.length ? match.routeMaps : existing.routeMaps,
          vrfLeaks: match.vrfLeaks?.length ? match.vrfLeaks : existing.vrfLeaks,
        };
      });

      if (matchedCount === 0) return 0;
      const next: TopologyState = { ...topology, nodes: nextNodes };
      set({
        topology: next,
        past: [...get().past.slice(-29), topology],
        future: [],
      });
      triggerSolve(next);
      return matchedCount;
    },

    applyParsedNodeConfig: (nodeId, parsedNode) => {
      const { topology, past } = get();
      const normIf = (s: string) =>
        s
          .trim()
          .toLowerCase()
          .replace(/^gigabitethernet/, 'gi')
          .replace(/^tengigabitethernet/, 'te')
          .replace(/^fastethernet/, 'fa')
          .replace(/^ethernet/, 'eth')
          .replace(/^port-channel/, 'po')
          .replace(/^loopback/, 'lo');

      const nextNodes = topology.nodes.map((existing) => {
        if (existing.id !== nodeId) return existing;
        const usedParsedIds = new Set<string>();
        const mergedIfaces = existing.interfaces
          .filter((exIf) => {
            const isLinked = topology.links.some(
              (l) =>
                (l.sourceNodeId === nodeId && l.sourceInterfaceId === exIf.id) ||
                (l.targetNodeId === nodeId && l.targetInterfaceId === exIf.id)
            );
            const exNorm = normIf(exIf.name);
            const stillPresent = parsedNode.interfaces.some(
              (mIf) =>
                mIf.name.toLowerCase() === exIf.name.toLowerCase() ||
                normIf(mIf.name) === exNorm
            );
            return isLinked || stillPresent;
          })
          .map((exIf) => {
            const exNorm = normIf(exIf.name);
            const pIf = parsedNode.interfaces.find(
              (mIf) =>
                mIf.name.toLowerCase() === exIf.name.toLowerCase() ||
                normIf(mIf.name) === exNorm
            );
            if (!pIf) return exIf;
            usedParsedIds.add(pIf.id);
            return {
              ...exIf,
              name: pIf.name,
              cidr: pIf.cidr,
              cidr6: pIf.cidr6,
              vrf: pIf.vrf || 'default',
              ospfArea: pIf.ospfArea,
              ospfCost: pIf.ospfCost,
              ospfPriority: pIf.ospfPriority,
              ospfHelloInterval: pIf.ospfHelloInterval,
              ospfDeadInterval: pIf.ospfDeadInterval,
              ospfNetworkType: pIf.ospfNetworkType,
              ospfAuthKey: pIf.ospfAuthKey,
              passive: pIf.passive,
              mtu: pIf.mtu,
              shutdown: pIf.shutdown,
              lacpGroup: pIf.lacpGroup,
              lacpMode: pIf.lacpMode,
              lagProtocol: pIf.lagProtocol,
              vlanId: pIf.vlanId,
              parentInterface: pIf.parentInterface,
              secondaryCidrs: pIf.secondaryCidrs,
              unnumberedSource: pIf.unnumberedSource,
              urpfMode: pIf.urpfMode,
            };
          });

        for (const pIf of parsedNode.interfaces) {
          if (!usedParsedIds.has(pIf.id)) {
            mergedIfaces.push(pIf);
          }
        }

        return {
          ...existing,
          hostname: parsedNode.hostname || existing.hostname,
          vendor: parsedNode.vendor || existing.vendor,
          routerId: parsedNode.routerId || existing.routerId,
          vrfs: parsedNode.vrfs?.length ? parsedNode.vrfs : ['default'],
          interfaces: mergedIfaces,
          staticRoutes: parsedNode.staticRoutes,
          ospf: parsedNode.ospf,
          bgp: parsedNode.bgp,
          eigrp: parsedNode.eigrp,
          isis: parsedNode.isis,
          rip: parsedNode.rip,
          redistributions: parsedNode.redistributions,
          prefixLists: parsedNode.prefixLists,
          routeMaps: parsedNode.routeMaps,
          vrfLeaks: parsedNode.vrfLeaks,
          aclRules: parsedNode.aclRules,
          natRules: parsedNode.natRules,
          fhrpGroups: parsedNode.fhrpGroups,
        };
      });

      const next: TopologyState = { ...topology, nodes: nextNodes };
      set({
        topology: next,
        past: [...past, structuredClone(topology)].slice(-30),
        future: [],
      });
      triggerSolve(next);
    },

    autoLayoutTopology: () => {
      const { topology } = get();
      if (topology.nodes.length === 0) return;

      const degree = new Map<string, number>();
      const adj = new Map<string, string[]>();
      for (const n of topology.nodes) {
        degree.set(n.id, 0);
        adj.set(n.id, []);
      }
      for (const l of topology.links) {
        degree.set(l.sourceNodeId, (degree.get(l.sourceNodeId) ?? 0) + 1);
        degree.set(l.targetNodeId, (degree.get(l.targetNodeId) ?? 0) + 1);
        adj.get(l.sourceNodeId)?.push(l.targetNodeId);
        adj.get(l.targetNodeId)?.push(l.sourceNodeId);
      }

      // BFS layering starting from highest-degree core/cloud nodes
      const sortedRoots = [...topology.nodes].sort(
        (a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0)
      );
      const level = new Map<string, number>();
      const queue: string[] = [];
      for (const root of sortedRoots) {
        if (level.has(root.id)) continue;
        level.set(root.id, 0);
        queue.push(root.id);
        while (queue.length > 0) {
          const cur = queue.shift()!;
          const curLvl = level.get(cur)!;
          for (const nb of adj.get(cur) ?? []) {
            if (!level.has(nb)) {
              level.set(nb, curLvl + 1);
              queue.push(nb);
            }
          }
        }
      }

      const byLevel = new Map<number, NodeConfig[]>();
      for (const n of topology.nodes) {
        const l = level.get(n.id) ?? 0;
        const arr = byLevel.get(l) ?? [];
        arr.push(n);
        byLevel.set(l, arr);
      }

      const posMap = new Map<string, { x: number; y: number }>();
      for (const [lvl, list] of byLevel.entries()) {
        list.forEach((n, idx) => {
          const x = 120 + idx * 280;
          const y = 80 + lvl * 200;
          posMap.set(n.id, { x, y });
        });
      }

      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.map((n) => ({
          ...n,
          position: posMap.get(n.id) ?? n.position,
        })),
      };
      set({
        topology: next,
        past: [...get().past.slice(-29), topology],
        future: [],
      });
    },

    createWorkspace: (name) => {
      const id = `ws-${Date.now()}`;
      const blankTopology: TopologyState = { nodes: [], links: [] };
      const ws: SavedWorkspace = {
        id,
        name: name.trim() || `Workspace ${get().workspaces.length + 1}`,
        topology: blankTopology,
        pathTests: [],
        updatedAt: Date.now(),
      };
      const nextWorkspaces = [...get().workspaces, ws];
      persistWorkspaces(nextWorkspaces);
      set({
        workspaces: nextWorkspaces,
        topology: blankTopology,
        activePresetId: id,
        baselineSimResult: null,
        selectedNodeId: null,
        viewportCenter: null,
        setViewportCenter: (center) => set({ viewportCenter: center }),
        traceSrcNodeId: '',
        traceVrf: 'default',
        traceResult: null,
        pathTests: [],
        past: [],
        future: [],
      });
      triggerSolve(blankTopology);
    },

    saveCurrentWorkspace: (name) => {
      const { activePresetId, topology, workspaces, pathTests } = get();
      const existing = workspaces.find((w) => w.id === activePresetId);
      if (existing && !name) {
        const updated = workspaces.map((w) =>
          w.id === activePresetId
            ? {
                ...w,
                topology: structuredClone(topology),
                pathTests: structuredClone(pathTests),
                updatedAt: Date.now(),
              }
            : w
        );
        persistWorkspaces(updated);
        set({ workspaces: updated });
        return;
      }
      const id = `ws-${Date.now()}`;
      const ws: SavedWorkspace = {
        id,
        name: name?.trim() || `Workspace ${workspaces.length + 1}`,
        topology: structuredClone(topology),
        pathTests: structuredClone(pathTests),
        updatedAt: Date.now(),
      };
      const nextWorkspaces = [...workspaces, ws];
      persistWorkspaces(nextWorkspaces);
      set({ workspaces: nextWorkspaces, activePresetId: id });
    },

    loadWorkspace: (workspaceId) => {
      const ws = get().workspaces.find((w) => w.id === workspaceId);
      if (!ws) return;
      const topology = normalizeTopology(structuredClone(ws.topology));
      set({
        topology,
        activePresetId: ws.id,
        baselineSimResult: null,
        selectedNodeId: topology.nodes[0]?.id ?? null,
        traceSrcNodeId: topology.nodes[0]?.id ?? '',
        traceVrf: 'default',
        traceResult: null,
        pathTests: structuredClone(ws.pathTests ?? []),
        past: [],
        future: [],
      });
      triggerSolve(topology);
    },

    deleteWorkspace: (workspaceId) => {
      const nextWorkspaces = get().workspaces.filter((w) => w.id !== workspaceId);
      persistWorkspaces(nextWorkspaces);
      set({ workspaces: nextWorkspaces });
      if (get().activePresetId === workspaceId) {
        get().loadPreset(PRESET_TOPOLOGIES[0].id);
      }
    },

    renameWorkspace: (workspaceId, name) => {
      const trimmed = name.trim();
      if (!trimmed) return;
      const nextWorkspaces = get().workspaces.map((w) =>
        w.id === workspaceId ? { ...w, name: trimmed, updatedAt: Date.now() } : w
      );
      persistWorkspaces(nextWorkspaces);
      set({ workspaces: nextWorkspaces });
    },

    setTraceParams: (srcNodeId, dstIp, vrf, proto, port, srcInterfaceId, srcIp) =>
      set((state) => ({
        traceSrcNodeId: srcNodeId,
        traceSrcInterfaceId:
          srcNodeId !== state.traceSrcNodeId ? srcInterfaceId : (srcInterfaceId ?? state.traceSrcInterfaceId),
        traceSrcIp: srcIp === null ? undefined : srcIp !== undefined ? srcIp : undefined,
        traceDstIp: dstIp,
        traceVrf: vrf ?? state.traceVrf,
        traceProto: proto ?? state.traceProto,
        tracePort:
          port === null ? undefined : port !== undefined ? port : state.tracePort,
      })),

    runTrace: () => {
      const {
        topology,
        simResult,
        traceSrcNodeId,
        traceSrcInterfaceId,
        traceSrcIp,
        traceDstIp,
        traceVrf,
        traceProto,
        tracePort,
      } = get();
      const traceResult = tracePacket(
        topology,
        simResult,
        traceSrcNodeId,
        traceDstIp,
        traceVrf,
        { srcIp: traceSrcIp, srcInterfaceId: traceSrcInterfaceId, protocol: traceProto, dstPort: tracePort }
      );
      set({ traceResult });
    },

    clearTrace: () => set({ traceResult: null }),
    setTraceResult: (res) =>
      set({
        traceResult: res,
        traceSrcNodeId: res.srcNodeId,
        traceSrcInterfaceId: res.srcInterfaceId,
        traceSrcIp: res.srcIp,
        traceDstIp: res.dstIp,
        traceVrf: res.vrf,
      }),
    addPathTest: (test) => set((state) => ({ pathTests: [...state.pathTests, test] })),
    deletePathTest: (id) =>
      set((state) => ({ pathTests: state.pathTests.filter((t) => t.id !== id) })),

    getShareUrl: () => {
      const { topology } = get();
      const compressed = compressToEncodedURIComponent(JSON.stringify(topology));
      const url = new URL(window.location.href);
      url.hash = `s=${compressed}`;
      window.history.replaceState(null, '', url.toString());
      return url.toString();
    },

    addNode: (vendor) => {
      const { topology, viewportCenter } = get();
      const idx = topology.nodes.length + 1;
      const meta = VENDOR_METADATA[vendor];
      const id = `node-${Date.now()}`;
      const stagger = ((idx % 5) - 2) * 24;
      const position = viewportCenter
        ? {
            x: Math.round(viewportCenter.x - 102 + stagger),
            y: Math.round(viewportCenter.y - 45 + stagger),
          }
        : { x: 260 + (idx % 4) * 60, y: 120 + (idx % 3) * 60 };
      const newNode: NodeConfig = {
        id,
        hostname: `${meta.shortLabel.toUpperCase().replace(/[^A-Z0-9]/g, '')}-${idx}`,
        vendor,
        routerId: `10.254.0.${idx}`,
        position,
        maxPaths: 4,
        vrfs: ['default'],
        adOverrides: {},
        interfaces: [
          {
            id: `if-${Date.now()}-0`,
            name: `${meta.defaultInterfacePrefix}1`,
            cidr: `10.200.${idx}.1/30`,
            vrf: 'default',
            ospfArea: 0,
            ospfCost: 10,
          },
        ],
        staticRoutes: [],
        ospf: { enabled: true, networks: [] },
        bgp: { enabled: false, asn: 65000 + idx, peers: [], networks: [] },
        redistributions: [],
        prefixLists: [],
        routeMaps: [],
        vrfLeaks: [],
      };
      const next: TopologyState = {
        ...topology,
        nodes: [...topology.nodes, newNode],
      };
      set({ topology: next, selectedNodeId: id, past: [...get().past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    duplicateNode: (nodeId) => {
      const { topology, past } = get();
      const src = topology.nodes.find((n) => n.id === nodeId);
      if (!src) return;
      const clone: NodeConfig = structuredClone(src);
      const newId = `node-${Date.now()}`;
      clone.id = newId;
      clone.hostname = `${src.hostname}-copy`;
      clone.position = { x: src.position.x + 60, y: src.position.y + 60 };
      clone.interfaces = clone.interfaces.map((i, idx) => ({
        ...i,
        id: `if-${Date.now()}-${idx}`,
      }));
      const next: TopologyState = { ...topology, nodes: [...topology.nodes, clone] };
      set({
        topology: next,
        selectedNodeId: newId,
        past: [...past, structuredClone(topology)].slice(-30),
        future: [],
      });
      triggerSolve(next);
    },

    updateNode: (nodeId, patch) => {
      const { topology, past } = get();
      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.map((n) => (n.id === nodeId ? { ...n, ...patch } : n)),
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    updateNodePosition: (nodeId, position) => {
      const { topology } = get();
      set({
        topology: {
          ...topology,
          nodes: topology.nodes.map((n) => (n.id === nodeId ? { ...n, position } : n)),
        },
      });
    },

    deleteNode: (nodeId) => {
      const { topology, selectedNodeId, past } = get();
      const next: TopologyState = {
        nodes: topology.nodes.filter((n) => n.id !== nodeId),
        links: topology.links.filter(
          (l) => l.sourceNodeId !== nodeId && l.targetNodeId !== nodeId
        ),
      };
      set({
        topology: next,
        selectedNodeId: selectedNodeId === nodeId ? (next.nodes[0]?.id ?? null) : selectedNodeId,
        past: [...past, structuredClone(topology)].slice(-30),
        future: [],
      });
      triggerSolve(next);
    },

    addInterface: (nodeId, iface) => {
      const { topology, past } = get();
      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.map((n) =>
          n.id === nodeId ? { ...n, interfaces: [...n.interfaces, iface] } : n
        ),
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    updateInterface: (nodeId, ifaceId, patch) => {
      const { topology, past } = get();
      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.map((n) =>
          n.id === nodeId
            ? {
                ...n,
                interfaces: n.interfaces.map((i) =>
                  i.id === ifaceId ? { ...i, ...patch } : i
                ),
              }
            : n
        ),
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    deleteInterface: (nodeId, ifaceId) => {
      const { topology, past } = get();
      const next: TopologyState = {
        nodes: topology.nodes.map((n) =>
          n.id === nodeId
            ? { ...n, interfaces: n.interfaces.filter((i) => i.id !== ifaceId) }
            : n
        ),
        links: topology.links.filter(
          (l) =>
            !(l.sourceNodeId === nodeId && l.sourceInterfaceId === ifaceId) &&
            !(l.targetNodeId === nodeId && l.targetInterfaceId === ifaceId)
        ),
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    addLink: (link) => {
      const { topology, past } = get();
      const next: TopologyState = {
        ...topology,
        links: [...topology.links, link],
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    updateLink: (linkId, patch) => {
      const { topology, past } = get();
      const next: TopologyState = {
        ...topology,
        links: topology.links.map((l) => (l.id === linkId ? { ...l, ...patch } : l)),
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    setVrfColor: (vrf, color) => {
      const { topology } = get();
      const next: TopologyState = {
        ...topology,
        vrfColors: { ...(topology.vrfColors ?? {}), [vrf]: color },
      };
      set({ topology: next });
    },

    deleteLink: (linkId) => {
      const { topology, past } = get();
      const next: TopologyState = {
        ...topology,
        links: topology.links.filter((l) => l.id !== linkId),
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },
  };
});

