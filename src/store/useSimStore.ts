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
  try {
    if (typeof localStorage !== 'undefined') {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved === 'light' || saved === 'dark') mode = saved;
    }
  } catch {
    // Ignore storage access errors in restricted/sandboxed browser contexts
  }
  applyHtmlThemeClass(mode);
  return mode;
}

function loadSavedWorkspaces(): SavedWorkspace[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(WORKSPACE_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (w): w is SavedWorkspace =>
        Boolean(
          w &&
          typeof w === 'object' &&
          typeof w.id === 'string' &&
          typeof w.name === 'string' &&
          w.topology &&
          typeof w.topology === 'object' &&
          Array.isArray(w.topology.nodes) &&
          Array.isArray(w.topology.links)
        )
    );
  } catch {
    return [];
  }
}

function persistWorkspaces(workspaces: SavedWorkspace[]): boolean {
  if (typeof localStorage === 'undefined') return true;
  try {
    localStorage.setItem(WORKSPACE_STORAGE_KEY, JSON.stringify(workspaces));
    return true;
  } catch {
    return false;
  }
}

function normalizeTopology(t: TopologyState): TopologyState {
  return {
    ...t,
    links: Array.isArray(t.links) ? t.links : [],
    nodes: (Array.isArray(t.nodes) ? t.nodes : []).map((n, idx) => ({
      ...n,
      vendor: n.vendor && VENDOR_METADATA[n.vendor] ? n.vendor : 'cisco-ios-xe',
      vrfs: Array.from(new Set(['default', ...(Array.isArray(n.vrfs) ? n.vrfs : [])])),
      adOverrides: n.adOverrides ?? {},
      sdwanSla: n.sdwanSla
        ? { ...n.sdwanSla, rules: Array.isArray(n.sdwanSla.rules) ? n.sdwanSla.rules : [] }
        : undefined,
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
    try {
      workerInstance = new Worker(
        new URL('../workers/simWorker.ts', import.meta.url),
        { type: 'module' }
      );
    } catch {
      workerInstance = null;
      return null;
    }
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
  createWorkspace: (name: string) => boolean;
  saveCurrentWorkspace: (name?: string) => boolean;
  renameWorkspace: (workspaceId: string, name: string) => boolean;
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
    srcInterfaceId?: string | null,
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
  deleteSelection: (nodeIds: string[], linkIds: string[]) => void;

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
      try { worker.terminate(); } catch { /* ignore */ }
      workerInstance = null;
      if (reqId !== workerReqId) return;
      try {
        applySolvedResult(get().topology, solveTopology(get().topology));
      } catch {
        // Keep current state if fallback solve also fails
      }
    };
    worker.onmessageerror = () => {
      try { worker.terminate(); } catch { /* ignore */ }
      workerInstance = null;
      if (reqId !== workerReqId) return;
      try {
        applySolvedResult(get().topology, solveTopology(get().topology));
      } catch {
        // Keep current state if fallback solve also fails
      }
    };
    try {
      worker.postMessage({ id: reqId, topology });
    } catch {
      try { worker.terminate(); } catch { /* ignore */ }
      workerInstance = null;
      applySolvedResult(topology, solveTopology(topology));
    }
  };

  const remapNodeInterfaceIds = (node: NodeConfig, idMap: Map<string, string>): NodeConfig => {
    if (idMap.size === 0) return node;
    const mapId = (id?: string) => (id ? (idMap.get(id) ?? id) : id);
    return {
      ...node,
      fhrpGroups: node.fhrpGroups?.map((g) => ({ ...g, interfaceId: mapId(g.interfaceId) ?? g.interfaceId })),
      multicast: node.multicast
        ? {
          ...node.multicast,
          igmpGroups: node.multicast.igmpGroups?.map((g) => ({
            ...g,
            interfaceId: mapId(g.interfaceId) ?? g.interfaceId,
          })),
        }
        : undefined,
      vpc: node.vpc ? { ...node.vpc, peerLinkInterfaceId: mapId(node.vpc.peerLinkInterfaceId) } : undefined,
      mlag: node.mlag ? { ...node.mlag, peerLinkInterfaceId: mapId(node.mlag.peerLinkInterfaceId) } : undefined,
      panHa: node.panHa
        ? {
          ...node.panHa,
          ha1InterfaceId: mapId(node.panHa.ha1InterfaceId),
          ha2InterfaceId: mapId(node.panHa.ha2InterfaceId),
          ha3HsciInterfaceId: mapId(node.panHa.ha3HsciInterfaceId),
        }
        : undefined,
      fortiHa: node.fortiHa ? { ...node.fortiHa, hbInterfaceId: mapId(node.fortiHa.hbInterfaceId) } : undefined,
      forcepointCluster: node.forcepointCluster
        ? { ...node.forcepointCluster, heartbeatInterfaceId: mapId(node.forcepointCluster.heartbeatInterfaceId) }
        : undefined,
    };
  };

  const stripDeletedInterfaceId = (
    node: NodeConfig,
    ifaceId: string,
    deletedNameOverride?: string
  ): NodeConfig => {
    const clearIf = (id?: string) => (id === ifaceId ? undefined : id);
    const deletedName = deletedNameOverride ?? node.interfaces.find((i) => i.id === ifaceId)?.name;
    return {
      ...node,
      interfaces: node.interfaces
        .filter((i) => i.id !== ifaceId)
        .map((i) =>
          deletedName
            ? {
              ...i,
              unnumberedSource: i.unnumberedSource === deletedName ? undefined : i.unnumberedSource,
              parentInterface: i.parentInterface === deletedName ? undefined : i.parentInterface,
              tlocExtension: i.tlocExtension === deletedName ? undefined : i.tlocExtension,
            }
            : i
        ),
      staticRoutes: deletedName
        ? node.staticRoutes.map((sr) =>
          sr.interfaceName === deletedName ? { ...sr, interfaceName: undefined } : sr
        )
        : node.staticRoutes,
      bgp: deletedName
        ? {
          ...node.bgp,
          peers: node.bgp.peers.map((p) =>
            p.updateSource === deletedName ? { ...p, updateSource: undefined } : p
          ),
        }
        : node.bgp,
      pbrRules: deletedName
        ? node.pbrRules?.map((r) => ({
          ...r,
          ingressInterface: r.ingressInterface === deletedName ? undefined : r.ingressInterface,
          interfaceName: r.interfaceName === deletedName ? undefined : r.interfaceName,
        }))
        : node.pbrRules,
      sdwanSla:
        deletedName && node.sdwanSla
          ? {
            ...node.sdwanSla,
            rules: node.sdwanSla.rules.map((r) => ({
              ...r,
              preferredMembers: r.preferredMembers.filter((m) => m !== deletedName),
            })),
          }
          : node.sdwanSla,
      fhrpGroups: node.fhrpGroups?.filter((g) => g.interfaceId !== ifaceId),
      multicast: node.multicast
        ? {
          ...node.multicast,
          igmpGroups: node.multicast.igmpGroups?.filter((g) => g.interfaceId !== ifaceId),
        }
        : undefined,
      vpc: node.vpc ? { ...node.vpc, peerLinkInterfaceId: clearIf(node.vpc.peerLinkInterfaceId) } : undefined,
      mlag: node.mlag
        ? {
          ...node.mlag,
          peerLinkInterfaceId: clearIf(node.mlag.peerLinkInterfaceId),
          localInterface:
            deletedName && node.mlag.localInterface === deletedName
              ? undefined
              : node.mlag.localInterface,
        }
        : undefined,
      panHa: node.panHa
        ? {
          ...node.panHa,
          ha1InterfaceId: clearIf(node.panHa.ha1InterfaceId),
          ha2InterfaceId: clearIf(node.panHa.ha2InterfaceId),
          ha3HsciInterfaceId: clearIf(node.panHa.ha3HsciInterfaceId),
        }
        : undefined,
      fortiHa: node.fortiHa ? { ...node.fortiHa, hbInterfaceId: clearIf(node.fortiHa.hbInterfaceId) } : undefined,
      forcepointCluster: node.forcepointCluster
        ? { ...node.forcepointCluster, heartbeatInterfaceId: clearIf(node.forcepointCluster.heartbeatInterfaceId) }
        : undefined,
    };
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
      const { past, topology, future, selectedNodeId, traceSrcNodeId, traceSrcInterfaceId, traceSrcIp, traceVrf } = get();
      if (past.length === 0) return;
      const previous = past[past.length - 1];
      const nextSelected = previous.nodes.some((n) => n.id === selectedNodeId)
        ? selectedNodeId
        : (previous.nodes[0]?.id ?? null);
      const nextTraceSrc = previous.nodes.some((n) => n.id === traceSrcNodeId)
        ? traceSrcNodeId
        : (previous.nodes[0]?.id ?? '');
      const srcNode = previous.nodes.find((n) => n.id === nextTraceSrc);
      const nextTraceIf = srcNode?.interfaces.some((i) => i.id === traceSrcInterfaceId)
        ? traceSrcInterfaceId
        : undefined;
      const nextTraceVrf =
        srcNode && (srcNode.vrfs.includes(traceVrf) || srcNode.interfaces.some((i) => (i.vrf || 'default') === traceVrf))
          ? traceVrf
          : 'default';
      set({
        topology: previous,
        selectedNodeId: nextSelected,
        traceSrcNodeId: nextTraceSrc,
        traceSrcInterfaceId: nextTraceIf,
        traceSrcIp: nextTraceSrc !== traceSrcNodeId ? undefined : traceSrcIp,
        traceVrf: nextTraceVrf,
        past: past.slice(0, -1),
        future: [structuredClone(topology), ...future].slice(0, 30),
      });
      triggerSolve(previous);
    },
    redo: () => {
      const { past, topology, future, selectedNodeId, traceSrcNodeId, traceSrcInterfaceId, traceSrcIp, traceVrf } = get();
      if (future.length === 0) return;
      const next = future[0];
      const nextSelected = next.nodes.some((n) => n.id === selectedNodeId)
        ? selectedNodeId
        : (next.nodes[0]?.id ?? null);
      const nextTraceSrc = next.nodes.some((n) => n.id === traceSrcNodeId)
        ? traceSrcNodeId
        : (next.nodes[0]?.id ?? '');
      const srcNode = next.nodes.find((n) => n.id === nextTraceSrc);
      const nextTraceIf = srcNode?.interfaces.some((i) => i.id === traceSrcInterfaceId)
        ? traceSrcInterfaceId
        : undefined;
      const nextTraceVrf =
        srcNode && (srcNode.vrfs.includes(traceVrf) || srcNode.interfaces.some((i) => (i.vrf || 'default') === traceVrf))
          ? traceVrf
          : 'default';
      set({
        topology: next,
        selectedNodeId: nextSelected,
        traceSrcNodeId: nextTraceSrc,
        traceSrcInterfaceId: nextTraceIf,
        traceSrcIp: nextTraceSrc !== traceSrcNodeId ? undefined : traceSrcIp,
        traceVrf: nextTraceVrf,
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
        traceSrcInterfaceId: undefined,
        traceSrcIp: undefined,
        traceVrf: 'default',
        traceResult: null,
        pathTests: structuredClone(preset.pathTests ?? []),
        past: [],
        future: [],
      });
      triggerSolve(topology);
    },

    importTopology: (rawTopology) => {
      const topology = normalizeTopology(structuredClone(rawTopology));
      set({
        topology,
        activePresetId: 'custom-import',
        baselineSimResult: null,
        selectedNodeId: topology.nodes[0]?.id ?? null,
        traceSrcNodeId: topology.nodes[0]?.id ?? '',
        traceSrcInterfaceId: undefined,
        traceSrcIp: undefined,
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
          .replace(/^loopback/, 'lo')
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
        const parsedIdMap = new Map<string, string>();
        const mergedIfaces = existing.interfaces.map((exIf) => {
          const exNorm = normIf(exIf.name);
          const pIf = match.interfaces.find(
            (mIf) =>
              mIf.name.toLowerCase() === exIf.name.toLowerCase() ||
              normIf(mIf.name) === exNorm
          );
          if (!pIf) return exIf;
          usedParsedIds.add(pIf.id);
          if (pIf.id !== exIf.id) parsedIdMap.set(pIf.id, exIf.id);
          return {
            ...exIf,
            ...pIf,
            id: exIf.id,
            vrf: pIf.vrf || exIf.vrf,
          };
        });

        const usedIfIds = new Set(mergedIfaces.map((i) => i.id));
        for (const pIf of match.interfaces) {
          if (!usedParsedIds.has(pIf.id)) {
            let finalId = pIf.id;
            if (usedIfIds.has(finalId)) {
              let suffix = 1;
              while (usedIfIds.has(`${pIf.id}-${suffix}`)) suffix++;
              finalId = `${pIf.id}-${suffix}`;
              parsedIdMap.set(pIf.id, finalId);
            }
            usedIfIds.add(finalId);
            mergedIfaces.push(finalId === pIf.id ? pIf : { ...pIf, id: finalId });
          }
        }

        const remappedMatch = remapNodeInterfaceIds(match, parsedIdMap);
        return {
          ...existing,
          vendor: remappedMatch.vendor,
          routerId: remappedMatch.routerId || existing.routerId,
          vrfRouterIds: remappedMatch.vrfRouterIds ?? existing.vrfRouterIds,
          maxPaths: remappedMatch.maxPaths ?? existing.maxPaths,
          vrfs: remappedMatch.vrfs?.length ? remappedMatch.vrfs : existing.vrfs,
          interfaces: mergedIfaces,
          staticRoutes: remappedMatch.staticRoutes,
          ospf: remappedMatch.ospf,
          bgp: remappedMatch.bgp,
          eigrp: remappedMatch.eigrp ?? existing.eigrp,
          isis: remappedMatch.isis ?? existing.isis,
          rip: remappedMatch.rip ?? existing.rip,
          redistributions: remappedMatch.redistributions,
          prefixLists: remappedMatch.prefixLists?.length ? remappedMatch.prefixLists : existing.prefixLists,
          routeMaps: remappedMatch.routeMaps?.length ? remappedMatch.routeMaps : existing.routeMaps,
          vrfLeaks: remappedMatch.vrfLeaks?.length ? remappedMatch.vrfLeaks : existing.vrfLeaks,
          pbrRules: remappedMatch.pbrRules?.length ? remappedMatch.pbrRules : existing.pbrRules,
          aclRules: remappedMatch.aclRules?.length ? remappedMatch.aclRules : existing.aclRules,
          natRules: remappedMatch.natRules?.length ? remappedMatch.natRules : existing.natRules,
          fhrpGroups: remappedMatch.fhrpGroups?.length ? remappedMatch.fhrpGroups : existing.fhrpGroups,
          tracks: remappedMatch.tracks?.length ? remappedMatch.tracks : existing.tracks,
          cloudConfig: remappedMatch.cloudConfig ?? existing.cloudConfig,
          vpc: remappedMatch.vpc ?? existing.vpc,
          mlag: remappedMatch.mlag ?? existing.mlag,
          evpn: remappedMatch.evpn ?? existing.evpn,
          mplsVpn: remappedMatch.mplsVpn ?? existing.mplsVpn,
          panHa: remappedMatch.panHa ?? existing.panHa,
          fortiHa: remappedMatch.fortiHa ?? existing.fortiHa,
          forcepointCluster: remappedMatch.forcepointCluster ?? existing.forcepointCluster,
          sdwan: remappedMatch.sdwan ?? existing.sdwan,
          sdwanSla: remappedMatch.sdwanSla ?? existing.sdwanSla,
          lisp: remappedMatch.lisp ?? existing.lisp,
          mpls: remappedMatch.mpls ?? existing.mpls,
          switching: remappedMatch.switching ?? existing.switching,
          multicast: remappedMatch.multicast ?? existing.multicast,
          timing: remappedMatch.timing ?? existing.timing,
          telemetry: remappedMatch.telemetry ?? existing.telemetry,
          nat64Rules: remappedMatch.nat64Rules ?? existing.nat64Rules,
          vplsInstances: remappedMatch.vplsInstances ?? existing.vplsInstances,
          oam: remappedMatch.oam ?? existing.oam,
        };
      });

      if (matchedCount === 0) return 0;
      const next: TopologyState = { ...topology, nodes: nextNodes };
      const { traceSrcNodeId, traceVrf } = get();
      const updatedSrc = nextNodes.find((n) => n.id === traceSrcNodeId);
      const validSrcVrfs = new Set([
        'default',
        ...(updatedSrc?.vrfs ?? []),
        ...(updatedSrc?.interfaces.map((i) => i.vrf || 'default') ?? []),
      ]);
      const nextTraceVrf = updatedSrc && !validSrcVrfs.has(traceVrf) ? 'default' : traceVrf;
      set({
        topology: next,
        traceVrf: nextTraceVrf,
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
        const parsedIdMap = new Map<string, string>();
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
            if (pIf.id !== exIf.id) parsedIdMap.set(pIf.id, exIf.id);
            return {
              ...pIf,
              id: exIf.id,
              vrf: pIf.vrf || 'default',
              qosPolicy: pIf.qosPolicy ?? exIf.qosPolicy,
              dot1xState: pIf.dot1xState ?? exIf.dot1xState,
              speedMbps: pIf.speedMbps ?? exIf.speedMbps,
              tlocColor: pIf.tlocColor ?? exIf.tlocColor,
              tlocEncap: pIf.tlocEncap ?? exIf.tlocEncap,
              tlocExtension: pIf.tlocExtension ?? exIf.tlocExtension,
            };
          });

        const usedIfIds = new Set(mergedIfaces.map((i) => i.id));
        for (const pIf of parsedNode.interfaces) {
          if (!usedParsedIds.has(pIf.id)) {
            let finalId = pIf.id;
            if (usedIfIds.has(finalId)) {
              let suffix = 1;
              while (usedIfIds.has(`${pIf.id}-${suffix}`)) suffix++;
              finalId = `${pIf.id}-${suffix}`;
              parsedIdMap.set(pIf.id, finalId);
            }
            usedIfIds.add(finalId);
            mergedIfaces.push(finalId === pIf.id ? pIf : { ...pIf, id: finalId });
          }
        }

        const remappedParsed = remapNodeInterfaceIds(parsedNode, parsedIdMap);
        const keptIfIds = new Set(mergedIfaces.map((i) => i.id));
        const removedIfIds = existing.interfaces.map((i) => i.id).filter((id) => !keptIfIds.has(id));
        let mergedNode: NodeConfig = {
          ...existing,
          hostname: remappedParsed.hostname || existing.hostname,
          vendor: existing.vendor || remappedParsed.vendor,
          routerId: remappedParsed.routerId || existing.routerId,
          vrfRouterIds: remappedParsed.vrfRouterIds,
          maxPaths: remappedParsed.maxPaths ?? existing.maxPaths,
          vrfs: remappedParsed.vrfs?.length ? remappedParsed.vrfs : ['default'],
          interfaces: mergedIfaces,
          staticRoutes: remappedParsed.staticRoutes,
          ospf: remappedParsed.ospf,
          bgp: remappedParsed.bgp,
          eigrp: remappedParsed.eigrp,
          isis: remappedParsed.isis,
          rip: remappedParsed.rip,
          redistributions: remappedParsed.redistributions,
          prefixLists: remappedParsed.prefixLists,
          routeMaps: remappedParsed.routeMaps,
          vrfLeaks: remappedParsed.vrfLeaks,
          pbrRules: remappedParsed.pbrRules?.length ? remappedParsed.pbrRules : existing.pbrRules,
          aclRules: remappedParsed.aclRules?.length ? remappedParsed.aclRules : existing.aclRules,
          natRules: remappedParsed.natRules?.length ? remappedParsed.natRules : existing.natRules,
          fhrpGroups: remappedParsed.fhrpGroups ?? existing.fhrpGroups,
          tracks: remappedParsed.tracks ?? existing.tracks,
          cloudConfig: remappedParsed.cloudConfig ?? existing.cloudConfig,
          vpc: remappedParsed.vpc ?? existing.vpc,
          mlag: remappedParsed.mlag ?? existing.mlag,
          evpn: remappedParsed.evpn ?? existing.evpn,
          mplsVpn: remappedParsed.mplsVpn ?? existing.mplsVpn,
          panHa: remappedParsed.panHa ?? existing.panHa,
          fortiHa: remappedParsed.fortiHa ?? existing.fortiHa,
          forcepointCluster: remappedParsed.forcepointCluster ?? existing.forcepointCluster,
          sdwan: remappedParsed.sdwan ?? existing.sdwan,
          sdwanSla: remappedParsed.sdwanSla ?? existing.sdwanSla,
          lisp: remappedParsed.lisp ?? existing.lisp,
          mpls: remappedParsed.mpls ?? existing.mpls,
          switching: remappedParsed.switching ?? existing.switching,
          multicast: remappedParsed.multicast ?? existing.multicast,
          timing: remappedParsed.timing ?? existing.timing,
          telemetry: remappedParsed.telemetry ?? existing.telemetry,
          nat64Rules: remappedParsed.nat64Rules ?? existing.nat64Rules,
          vplsInstances: remappedParsed.vplsInstances ?? existing.vplsInstances,
          oam: remappedParsed.oam ?? existing.oam,
        };
        for (const rid of removedIfIds) {
          const oldName = existing.interfaces.find((i) => i.id === rid)?.name;
          mergedNode = stripDeletedInterfaceId(mergedNode, rid, oldName);
        }
        return mergedNode;
      });

      const next: TopologyState = { ...topology, nodes: nextNodes };
      const { traceSrcNodeId, traceSrcInterfaceId, traceVrf } = get();
      const updatedTarget = nextNodes.find((n) => n.id === nodeId);
      const nextTraceSrcInterfaceId =
        traceSrcNodeId === nodeId &&
          traceSrcInterfaceId &&
          !updatedTarget?.interfaces.some((i) => i.id === traceSrcInterfaceId)
          ? undefined
          : traceSrcInterfaceId;
      const targetVrfs = new Set(['default', ...(updatedTarget?.vrfs ?? [])]);
      const nextTraceVrf =
        traceSrcNodeId === nodeId && !targetVrfs.has(traceVrf) ? 'default' : traceVrf;
      set({
        topology: next,
        traceSrcInterfaceId: nextTraceSrcInterfaceId,
        traceVrf: nextTraceVrf,
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

      const isCloudNode = (n: NodeConfig) =>
        n.vendor === 'mpls-cloud' ||
        n.vendor === 'internet-cloud' ||
        n.vendor === 'aws-cloud' ||
        n.vendor === 'aws-cloudwan' ||
        n.vendor === 'azure-cloud' ||
        n.vendor === 'gcp-cloud' ||
        n.vendor === 'oci-cloud' ||
        n.vendor === 'cloudflare-mwan';

      const nodeSlotWidth = (n: NodeConfig) => (isCloudNode(n) ? 420 : 340);
      const MAX_PER_ROW = 6;
      const TIER_GAP_Y = 330;
      const SUBROW_GAP_Y = 270;

      // Build ordered visual rows (wrapping wide tiers into balanced sub-rows)
      const sortedLevels = [...byLevel.keys()].sort((a, b) => a - b);
      const rows: { nodes: NodeConfig[]; y: number }[] = [];
      let curY = 60;
      const placedX = new Map<string, number>();

      for (let li = 0; li < sortedLevels.length; li++) {
        const lvl = sortedLevels[li];
        const list = [...(byLevel.get(lvl) ?? [])];

        // Barycenter sort against already-placed neighbors to minimize edge crossings
        list.sort((a, b) => {
          const avgX = (node: NodeConfig): number => {
            const xs = (adj.get(node.id) ?? [])
              .map((nb) => placedX.get(nb))
              .filter((v): v is number => v !== undefined);
            if (xs.length === 0) return Number.MAX_SAFE_INTEGER;
            return xs.reduce((s, v) => s + v, 0) / xs.length;
          };
          const ax = avgX(a);
          const bx = avgX(b);
          if (ax !== bx) return ax - bx;
          return a.hostname.localeCompare(b.hostname);
        });

        const subRowCount = Math.max(1, Math.ceil(list.length / MAX_PER_ROW));
        const perSubRow = Math.ceil(list.length / subRowCount);

        for (let r = 0; r < subRowCount; r++) {
          const slice = list.slice(r * perSubRow, (r + 1) * perSubRow);
          let cursor = 0;
          for (const n of slice) {
            const w = nodeSlotWidth(n);
            placedX.set(n.id, cursor + w / 2);
            cursor += w;
          }
          rows.push({ nodes: slice, y: curY });
          curY += r < subRowCount - 1 ? SUBROW_GAP_Y : TIER_GAP_Y;
        }
      }

      // Compute row widths and center every row around the widest row
      const rowWidths = rows.map((row) =>
        row.nodes.reduce((sum, n) => sum + nodeSlotWidth(n), 0)
      );
      const maxRowWidth = Math.max(800, ...rowWidths);

      const posMap = new Map<string, { x: number; y: number }>();
      rows.forEach((row, idx) => {
        const width = rowWidths[idx];
        let cursor = 80 + Math.round((maxRowWidth - width) / 2);
        for (const n of row.nodes) {
          posMap.set(n.id, { x: cursor, y: row.y });
          cursor += nodeSlotWidth(n);
        }
      });

      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.map((n) => ({
          ...n,
          position: posMap.get(n.id) ?? n.position,
        })),
        links: topology.links.map((l) => ({
          ...l,
          sourceHandle: undefined,
          targetHandle: undefined,
          controlPointOffset: undefined,
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
      const saved = persistWorkspaces(nextWorkspaces);
      set({
        workspaces: nextWorkspaces,
        topology: blankTopology,
        activePresetId: id,
        baselineSimResult: null,
        selectedNodeId: null,
        viewportCenter: null,
        traceSrcNodeId: '',
        traceSrcInterfaceId: undefined,
        traceSrcIp: undefined,
        traceVrf: 'default',
        traceResult: null,
        pathTests: [],
        past: [],
        future: [],
      });
      triggerSolve(blankTopology);
      return saved;
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
        const saved = persistWorkspaces(updated);
        set({ workspaces: updated });
        return saved;
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
      const saved = persistWorkspaces(nextWorkspaces);
      set({ workspaces: nextWorkspaces, activePresetId: id });
      return saved;
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
        traceSrcInterfaceId: undefined,
        traceSrcIp: undefined,
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
      if (!trimmed) return false;
      const nextWorkspaces = get().workspaces.map((w) =>
        w.id === workspaceId ? { ...w, name: trimmed, updatedAt: Date.now() } : w
      );
      const saved = persistWorkspaces(nextWorkspaces);
      set({ workspaces: nextWorkspaces });
      return saved;
    },

    setTraceParams: (srcNodeId, dstIp, vrf, proto, port, srcInterfaceId, srcIp) =>
      set((state) => ({
        traceSrcNodeId: srcNodeId,
        traceSrcInterfaceId:
          srcInterfaceId === null
            ? undefined
            : srcInterfaceId !== undefined
              ? srcInterfaceId
              : srcNodeId !== state.traceSrcNodeId
                ? undefined
                : state.traceSrcInterfaceId,
        traceSrcIp:
          srcIp === null
            ? undefined
            : srcIp !== undefined
              ? srcIp
              : srcNodeId !== state.traceSrcNodeId
                ? undefined
                : state.traceSrcIp,
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

    clearTrace: () => set({ traceResult: null, traceSrcIp: undefined }),
    setTraceResult: (res) =>
      set({
        traceResult: res,
        traceSrcNodeId: res.srcNodeId,
        traceSrcInterfaceId: res.srcInterfaceId,
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
      if (compressed.length <= 500_000) {
        try {
          window.history.replaceState(null, '', url.toString());
        } catch {
          // Ignore history restrictions in sandboxed iframes
        }
      }
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
      const isCloud = meta.category === 'cloud';
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
            ...(isCloud ? {} : { ospfArea: 0, ospfCost: 10 }),
          },
        ],
        staticRoutes: [],
        ospf: { enabled: !isCloud, networks: [] },
        bgp: { enabled: isCloud, asn: 65000 + idx, peers: [], networks: [] },
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
      let clone: NodeConfig = structuredClone(src);
      const now = Date.now();
      const newId = `node-${now}`;
      clone.id = newId;
      clone.hostname = `${src.hostname}-copy`;
      clone.position = { x: src.position.x + 60, y: src.position.y + 60 };
      const idMap = new Map<string, string>();
      clone.interfaces = clone.interfaces.map((i, idx) => {
        const nextIfId = `if-${now}-${idx}`;
        idMap.set(i.id, nextIfId);
        return { ...i, id: nextIfId };
      });
      clone = remapNodeInterfaceIds(clone, idMap);
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
      const { topology, past, traceSrcNodeId, traceVrf } = get();
      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.map((n) => (n.id === nodeId ? { ...n, ...patch } : n)),
      };
      const updatedNode = next.nodes.find((n) => n.id === nodeId);
      const validVrfs = new Set([
        'default',
        ...(updatedNode?.vrfs ?? []),
        ...(updatedNode?.interfaces.map((i) => i.vrf || 'default') ?? []),
      ]);
      const nextTraceVrf =
        traceSrcNodeId === nodeId && !validVrfs.has(traceVrf) ? 'default' : traceVrf;
      set({
        topology: next,
        traceVrf: nextTraceVrf,
        past: [...past, structuredClone(topology)].slice(-30),
        future: [],
      });
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
      const { topology, selectedNodeId, traceSrcNodeId, traceSrcInterfaceId, traceSrcIp, traceVrf, past } = get();
      if (!topology.nodes.some((n) => n.id === nodeId)) return;
      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.filter((n) => n.id !== nodeId),
        links: topology.links.filter(
          (l) => l.sourceNodeId !== nodeId && l.targetNodeId !== nodeId
        ),
      };
      set({
        topology: next,
        selectedNodeId: selectedNodeId === nodeId ? (next.nodes[0]?.id ?? null) : selectedNodeId,
        traceSrcNodeId: traceSrcNodeId === nodeId ? (next.nodes[0]?.id ?? '') : traceSrcNodeId,
        traceSrcInterfaceId: traceSrcNodeId === nodeId ? undefined : traceSrcInterfaceId,
        traceSrcIp: traceSrcNodeId === nodeId ? undefined : traceSrcIp,
        traceVrf: traceSrcNodeId === nodeId ? 'default' : traceVrf,
        past: [...past, structuredClone(topology)].slice(-30),
        future: [],
      });
      triggerSolve(next);
    },

    deleteSelection: (nodeIds, linkIds) => {
      const { topology, selectedNodeId, traceSrcNodeId, traceSrcInterfaceId, traceSrcIp, traceVrf, past } = get();
      const nodeSet = new Set(nodeIds);
      const linkSet = new Set(linkIds);
      const hasAnyTarget =
        topology.nodes.some((n) => nodeSet.has(n.id)) ||
        topology.links.some((l) => linkSet.has(l.id));
      if (!hasAnyTarget) return;
      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.filter((n) => !nodeSet.has(n.id)),
        links: topology.links.filter(
          (l) => !linkSet.has(l.id) && !nodeSet.has(l.sourceNodeId) && !nodeSet.has(l.targetNodeId)
        ),
      };
      const deletedTraceSrc = nodeSet.has(traceSrcNodeId);
      set({
        topology: next,
        selectedNodeId:
          selectedNodeId && nodeSet.has(selectedNodeId)
            ? (next.nodes[0]?.id ?? null)
            : selectedNodeId,
        traceSrcNodeId: deletedTraceSrc ? (next.nodes[0]?.id ?? '') : traceSrcNodeId,
        traceSrcInterfaceId: deletedTraceSrc ? undefined : traceSrcInterfaceId,
        traceSrcIp: deletedTraceSrc ? undefined : traceSrcIp,
        traceVrf: deletedTraceSrc ? 'default' : traceVrf,
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
        nodes: topology.nodes.map((n) => {
          if (n.id !== nodeId) return n;
          const oldIf = n.interfaces.find((i) => i.id === ifaceId);
          const renamed =
            oldIf && patch.name !== undefined && patch.name !== oldIf.name
              ? { oldName: oldIf.name, newName: patch.name }
              : null;
          return {
            ...n,
            interfaces: n.interfaces.map((i) => {
              const base = i.id === ifaceId ? { ...i, ...patch } : i;
              if (!renamed) return base;
              return {
                ...base,
                unnumberedSource:
                  base.unnumberedSource === renamed.oldName
                    ? renamed.newName
                    : base.unnumberedSource,
                parentInterface:
                  base.parentInterface === renamed.oldName
                    ? renamed.newName
                    : base.parentInterface,
                tlocExtension:
                  base.tlocExtension === renamed.oldName ? renamed.newName : base.tlocExtension,
              };
            }),
            mlag:
              renamed && n.mlag && n.mlag.localInterface === renamed.oldName
                ? { ...n.mlag, localInterface: renamed.newName }
                : n.mlag,
            staticRoutes: renamed
              ? n.staticRoutes.map((sr) =>
                sr.interfaceName === renamed.oldName
                  ? { ...sr, interfaceName: renamed.newName }
                  : sr
              )
              : n.staticRoutes,
            bgp: renamed
              ? {
                ...n.bgp,
                peers: n.bgp.peers.map((p) =>
                  p.updateSource === renamed.oldName
                    ? { ...p, updateSource: renamed.newName }
                    : p
                ),
              }
              : n.bgp,
            pbrRules: renamed
              ? n.pbrRules?.map((r) => ({
                ...r,
                ingressInterface:
                  r.ingressInterface === renamed.oldName ? renamed.newName : r.ingressInterface,
                interfaceName:
                  r.interfaceName === renamed.oldName ? renamed.newName : r.interfaceName,
              }))
              : n.pbrRules,
            sdwanSla:
              renamed && n.sdwanSla
                ? {
                  ...n.sdwanSla,
                  rules: n.sdwanSla.rules.map((r) => ({
                    ...r,
                    preferredMembers: r.preferredMembers.map((m) =>
                      m === renamed.oldName ? renamed.newName : m
                    ),
                  })),
                }
                : n.sdwanSla,
          };
        }),
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },

    deleteInterface: (nodeId, ifaceId) => {
      const { topology, traceSrcInterfaceId, past } = get();
      const next: TopologyState = {
        ...topology,
        nodes: topology.nodes.map((n) =>
          n.id === nodeId ? stripDeletedInterfaceId(n, ifaceId) : n
        ),
        links: topology.links.filter(
          (l) =>
            !(l.sourceNodeId === nodeId && l.sourceInterfaceId === ifaceId) &&
            !(l.targetNodeId === nodeId && l.targetInterfaceId === ifaceId)
        ),
      };
      set({
        topology: next,
        traceSrcInterfaceId: traceSrcInterfaceId === ifaceId ? undefined : traceSrcInterfaceId,
        past: [...past, structuredClone(topology)].slice(-30),
        future: [],
      });
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
      if (!topology.links.some((l) => l.id === linkId)) return;
      const next: TopologyState = {
        ...topology,
        links: topology.links.filter((l) => l.id !== linkId),
      };
      set({ topology: next, past: [...past, structuredClone(topology)].slice(-30), future: [] });
      triggerSolve(next);
    },
  };
});

