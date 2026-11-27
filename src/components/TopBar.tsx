import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  CloseOutlined,
  DeleteOutlined,
  EditOutlined,
  MoonOutlined,
  PlusOutlined,
  PushpinFilled,
  PushpinOutlined,
  RedoOutlined,
  SaveOutlined,
  SearchOutlined,
  SunOutlined,
  UndoOutlined,
} from '@ant-design/icons';
import {
  Alert,
  Badge,
  Button,
  Drawer,
  Dropdown,
  Input,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Tag,
  Tooltip,
  message,
} from 'antd';
import { PRESET_TOPOLOGIES } from '../data/presets';
import { computeRibDiff } from '../engine/diff';
import { buildAutomationBundleZip } from '../engine/exportBundle';
import { importTopologyFromText } from '../engine/importer';
import { runFailoverMatrix, runPathTestSuite } from '../engine/solver';
import { VENDOR_METADATA } from '../engine/vendorProfiles';
import { ProtocolOverlayMode, useSimStore } from '../store/useSimStore';
import { L4Protocol, VendorProfile } from '../types/network';

export const TopBar: React.FC = () => {
  const {
    topology,
    simResult,
    baselineSimResult,
    workspaces,
    activePresetId,
    traceSrcNodeId,
    traceSrcInterfaceId,
    traceDstIp,
    traceVrf,
    traceProto,
    tracePort,
    traceResult,
    pathTests,
    loadPreset,
    createWorkspace,
    saveCurrentWorkspace,
    renameWorkspace,
    loadWorkspace,
    deleteWorkspace,
    importTopology,
    mergeImportedNodes,
    hydrateMatchingNodes,
    captureSnapshot,
    clearSnapshot,
    addNode,
    setTraceParams,
    runTrace,
    clearTrace,
    setTraceResult,
    addPathTest,
    deletePathTest,
    getShareUrl,
    past,
    future,
    undo,
    redo,
    autoLayoutTopology,
    themeMode,
    toggleThemeMode,
    selectNode,
    protocolOverlay,
    setProtocolOverlay,
    setRoaTable,
  } = useSimStore();

  const [copied, setCopied] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [roaOpen, setRoaOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [newRoaPrefix, setNewRoaPrefix] = useState('203.0.113.0/24');
  const [newRoaMaxLen, setNewRoaMaxLen] = useState<number>(24);
  const [newRoaAsn, setNewRoaAsn] = useState<number>(65100);
  const [importOpen, setImportOpen] = useState(false);
  const [diagOpen, setDiagOpen] = useState(false);
  const [importMode, setImportMode] = useState<'merge' | 'hydrate' | 'replace'>('merge');
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [importText, setImportText] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [newWsOpen, setNewWsOpen] = useState(false);
  const [newWsName, setNewWsName] = useState('');
  const [wsNameModalMode, setWsNameModalMode] = useState<'save-copy' | 'rename' | null>(null);
  const [wsModalName, setWsModalName] = useState('');
  const [testsOpen, setTestsOpen] = useState(false);
  const [testsPinned, setTestsPinned] = useState(false);
  const [showFailoverMatrix, setShowFailoverMatrix] = useState(false);
  const [newTestExpected, setNewTestExpected] = useState<'delivered' | 'blocked' | 'dropped'>(
    'delivered'
  );
  const [msgApi, contextHolder] = message.useMessage();
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
    };
  }, []);

  const srcNode = topology.nodes.find((n) => n.id === traceSrcNodeId);
  const srcVrfs = useMemo(() => {
    const set = new Set<string>(srcNode?.vrfs?.length ? srcNode.vrfs : ['default']);
    for (const iface of srcNode?.interfaces ?? []) {
      if (iface.vrf) set.add(iface.vrf);
    }
    return Array.from(set);
  }, [srcNode]);
  const suiteSummary = useMemo(
    () => runPathTestSuite(topology, simResult, pathTests),
    [topology, simResult, pathTests]
  );
  const failoverMatrix = useMemo(
    () => (testsOpen && showFailoverMatrix ? runFailoverMatrix(topology, pathTests) : null),
    [testsOpen, showFailoverMatrix, topology, pathTests]
  );
  const isCustomWorkspace = workspaces.some((w) => w.id === activePresetId);

  const diffSummary = baselineSimResult
    ? computeRibDiff(baselineSimResult, simResult)
    : null;
  const totalChanges = diffSummary
    ? diffSummary.added + diffSummary.removed + diffSummary.modified
    : 0;

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSearchOpen((prev) => !prev);
        return;
      }
      if (
        e.key === 'Escape' &&
        !searchOpen &&
        !roaOpen &&
        !shortcutsOpen &&
        !importOpen &&
        !diagOpen &&
        !exportOpen &&
        !newWsOpen &&
        wsNameModalMode === null &&
        !testsOpen &&
        traceResult
      ) {
        clearTrace();
        return;
      }
      const target = e.target as HTMLElement | null;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)) {
        return;
      }
      if (!e.ctrlKey && !e.metaKey && !e.altKey && e.key === '?') {
        e.preventDefault();
        setShortcutsOpen((prev) => !prev);
      } else if (!e.ctrlKey && !e.metaKey && !e.altKey && e.shiftKey && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        autoLayoutTopology();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'z') {
        e.preventDefault();
        if (e.shiftKey) redo();
        else undo();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'y') {
        e.preventDefault();
        redo();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [
    undo,
    redo,
    clearTrace,
    autoLayoutTopology,
    searchOpen,
    roaOpen,
    shortcutsOpen,
    importOpen,
    diagOpen,
    exportOpen,
    newWsOpen,
    wsNameModalMode,
    testsOpen,
    traceResult,
  ]);

  const handleShare = async () => {
    const url = getShareUrl();
    const hashPayload = url.split('#s=')[1] ?? '';
    if (hashPayload.length > 500_000) {
      msgApi.warning('Topology exceeds the 500 KB share URL limit; use Export JSON instead.');
      return;
    }
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      msgApi.success('Compressed topology URL copied to clipboard');
      if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = window.setTimeout(() => setCopied(false), 2000);
    } catch {
      msgApi.info('URL hash updated in browser address bar');
    }
  };

  const handleExportBundle = () => {
    const blob = buildAutomationBundleZip(topology, simResult);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activePresetId || 'topology'}-bundle.zip`;
    a.click();
    URL.revokeObjectURL(url);
    msgApi.success('Automation bundle (.zip) downloaded');
  };

  const handleExportSvg = () => {
    const xs = topology.nodes.map((n) => n.position.x);
    const ys = topology.nodes.map((n) => n.position.y);
    const minX = (xs.length ? Math.min(...xs) : 0) - 60;
    const minY = (ys.length ? Math.min(...ys) : 0) - 60;
    const maxX = (xs.length ? Math.max(...xs) : 400) + 280;
    const maxY = (ys.length ? Math.max(...ys) : 300) + 160;
    const w = Math.max(400, maxX - minX);
    const h = Math.max(300, maxY - minY);
    const nodeMap = new Map(topology.nodes.map((n) => [n.id, n]));
    const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const linksSvg = topology.links
      .map((l) => {
        const s = nodeMap.get(l.sourceNodeId);
        const t = nodeMap.get(l.targetNodeId);
        if (!s || !t) return '';
        const x1 = s.position.x + 105;
        const y1 = s.position.y + 45;
        const x2 = t.position.x + 105;
        const y2 = t.position.y + 45;
        const stroke = l.adminDown ? '#ef4444' : l.linkType === 'ipsec' ? '#a855f7' : '#38bdf8';
        return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" stroke-width="2" ${l.linkType === 'ipsec' ? 'stroke-dasharray="6,4"' : ''}/>`;
      })
      .join('');
    const nodesSvg = topology.nodes
      .map(
        (n) =>
          `<g transform="translate(${n.position.x},${n.position.y})"><rect width="210" height="84" rx="10" fill="#0f172a" stroke="#334155" stroke-width="1.5"/><text x="12" y="26" fill="#f8fafc" font-family="monospace" font-size="13" font-weight="bold">${esc(n.hostname)}</text><text x="12" y="46" fill="#94a3b8" font-family="monospace" font-size="11">${esc(n.vendor)} · RID ${esc(n.routerId)}</text><text x="12" y="66" fill="#38bdf8" font-family="monospace" font-size="10">${n.bgp.enabled ? `BGP AS ${n.bgp.asn}` : n.ospf.enabled ? 'OSPF' : 'L2/Static'}</text></g>`
      )
      .join('');
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${minX} ${minY} ${w} ${h}" width="${w}" height="${h}"><rect x="${minX}" y="${minY}" width="${w}" height="${h}" fill="#020617"/>${linksSvg}${nodesSvg}</svg>`;
    const blob = new Blob([svg], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activePresetId || 'topology'}.svg`;
    a.click();
    URL.revokeObjectURL(url);
    msgApi.success('SVG diagram downloaded');
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(topology, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activePresetId || 'topology'}.json`;
    a.click();
    URL.revokeObjectURL(url);
    msgApi.success('Topology JSON downloaded');
  };

  const handleImportSubmit = () => {
    try {
      setImportError(null);
      const parsed = importTopologyFromText(importText);
      if (importMode === 'merge') {
        mergeImportedNodes(parsed.nodes, parsed.links);
        msgApi.success(`Added ${parsed.nodes.length} appliance(s) to current workspace`);
      } else if (importMode === 'hydrate') {
        const updated = hydrateMatchingNodes(parsed.nodes);
        if (updated === 0) {
          setImportError(
            `No existing appliance matched hostname "${parsed.nodes[0]?.hostname ?? ''}". Rename or select "Add Appliance(s)".`
          );
          return;
        }
        msgApi.success(`Updated ${updated} existing appliance(s) and preserved links`);
      } else {
        importTopology(parsed);
        msgApi.success(`Loaded ${parsed.nodes.length} appliance(s)`);
      }
      setImportOpen(false);
      setImportText('');
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Failed to parse input');
    }
  };

  const handleBulkConfigFiles = async (files: FileList | null) => {
    const fileArr = files ? Array.from(files) : [];
    if (fileArr.length === 0) return;
    setImportError(null);
    if (fileArr.length === 1) {
      const text = await fileArr[0].text();
      setImportText(text);
      return;
    }
    const parsedNodes: ReturnType<typeof importTopologyFromText>['nodes'] = [];
    const parsedLinks: ReturnType<typeof importTopologyFromText>['links'] = [];
    const usedNodeIds = new Set<string>();
    const usedLinkIds = new Set<string>();
    for (const f of fileArr) {
      try {
        const text = await f.text();
        const res = importTopologyFromText(text);
        if (res.nodes[0]) {
          if (res.nodes[0].hostname.endsWith('-IMPORTED')) {
            res.nodes[0].hostname = f.name.replace(/\.[^.]+$/, '');
          }
          const idMap = new Map<string, string>();
          for (const n of res.nodes) {
            let nid = n.id;
            if (usedNodeIds.has(nid)) {
              let suffix = 1;
              while (usedNodeIds.has(`${n.id}-${suffix}`)) suffix++;
              nid = `${n.id}-${suffix}`;
            }
            usedNodeIds.add(nid);
            idMap.set(n.id, nid);
            parsedNodes.push(nid === n.id ? n : { ...n, id: nid });
          }
          for (const l of res.links) {
            let lid = l.id;
            if (usedLinkIds.has(lid)) {
              let suffix = 1;
              while (usedLinkIds.has(`${l.id}-${suffix}`)) suffix++;
              lid = `${l.id}-${suffix}`;
            }
            usedLinkIds.add(lid);
            parsedLinks.push({
              ...l,
              id: lid,
              sourceNodeId: idMap.get(l.sourceNodeId) ?? l.sourceNodeId,
              targetNodeId: idMap.get(l.targetNodeId) ?? l.targetNodeId,
            });
          }
        }
      } catch (err) {
        setImportError(`Failed to parse ${f.name}: ${err instanceof Error ? err.message : 'error'}`);
        return;
      }
    }
    if (importMode === 'hydrate') {
      const updated = hydrateMatchingNodes(parsedNodes);
      if (updated === 0) {
        setImportError(
          'No matching appliance hostnames found in the current workspace. Switch mode to "Merge" or "Replace" to add them.'
        );
        return;
      }
      msgApi.success(`Updated ${updated}/${parsedNodes.length} matching appliance(s) from ${fileArr.length} file(s)`);
    } else if (importMode === 'merge') {
      mergeImportedNodes(parsedNodes, parsedLinks);
      msgApi.success(`Added ${parsedNodes.length} appliance(s) from ${fileArr.length} file(s)`);
    } else {
      importTopology({ nodes: parsedNodes, links: parsedLinks });
      msgApi.success(`Loaded ${parsedNodes.length} appliance(s) from ${fileArr.length} file(s)`);
    }
    setImportOpen(false);
  };

  const handleWorkspaceChange = (val: string) => {
    if (PRESET_TOPOLOGIES.some((p) => p.id === val)) {
      loadPreset(val);
    } else if (workspaces.some((w) => w.id === val)) {
      loadWorkspace(val);
    }
  };

  const handleCreateWorkspace = () => {
    const saved = createWorkspace(newWsName);
    setNewWsOpen(false);
    setNewWsName('');
    if (saved) msgApi.success('New blank workspace created');
    else msgApi.error('Workspace created in memory, but browser storage quota was exceeded');
  };

  const handleSaveWorkspace = () => {
    if (isCustomWorkspace) {
      const saved = saveCurrentWorkspace();
      if (saved) msgApi.success('Workspace saved');
      else msgApi.error('Failed to persist workspace: browser storage quota exceeded');
    } else {
      const preset = PRESET_TOPOLOGIES.find((p) => p.id === activePresetId);
      setWsModalName(preset ? `${preset.name} Copy` : `Lab-${workspaces.length + 1}`);
      setWsNameModalMode('save-copy');
    }
  };

  const handleOpenRenameWorkspace = () => {
    const current = workspaces.find((w) => w.id === activePresetId);
    if (!current) return;
    setWsModalName(current.name);
    setWsNameModalMode('rename');
  };

  const handleSubmitWsNameModal = () => {
    const trimmed = wsModalName.trim();
    if (!trimmed) return;
    if (wsNameModalMode === 'save-copy') {
      const saved = saveCurrentWorkspace(trimmed);
      if (saved) msgApi.success(`Saved as "${trimmed}" in My Workspaces`);
      else msgApi.error('Failed to persist workspace: browser storage quota exceeded');
    } else if (wsNameModalMode === 'rename') {
      const saved = renameWorkspace(activePresetId, trimmed);
      if (saved) msgApi.success(`Renamed workspace to "${trimmed}"`);
      else msgApi.error('Failed to persist rename: browser storage quota exceeded');
    }
    setWsNameModalMode(null);
    setWsModalName('');
  };

  const buildVendorMenuItem = (v: VendorProfile) => ({
    key: v,
    label: (
      <div className="flex items-center justify-between gap-4">
        <span>{VENDOR_METADATA[v].label}</span>
        <Tag className="!m-0 !text-[10px]">{VENDOR_METADATA[v].shortLabel}</Tag>
      </div>
    ),
    onClick: () => addNode(v),
  });

  const vendorKeys = Object.keys(VENDOR_METADATA) as VendorProfile[];
  const addMenuItems = [
    {
      type: 'group' as const,
      label: 'Appliances & Routers',
      children: vendorKeys
        .filter((v) => VENDOR_METADATA[v].category === 'appliance')
        .map(buildVendorMenuItem),
    },
    {
      type: 'group' as const,
      label: 'WAN & Cloud Elements',
      children: vendorKeys
        .filter((v) => VENDOR_METADATA[v].category === 'cloud')
        .map(buildVendorMenuItem),
    },
  ];

  const selectOptions = [
    {
      label: 'Example Networks',
      options: PRESET_TOPOLOGIES.map((p) => ({ value: p.id, label: p.name })),
    },
    ...(workspaces.length > 0
      ? [
        {
          label: 'My Workspaces',
          options: workspaces.map((w) => ({ value: w.id, label: w.name })),
        },
      ]
      : []),
    ...(activePresetId === 'custom-import'
      ? [{ value: 'custom-import', label: 'Imported Topology (Unsaved)' }]
      : []),
  ];

  const isLight = themeMode === 'light';
  const dividerClass = `mx-0.5 h-4 w-px shrink-0 ${isLight ? 'bg-black/[0.1]' : 'bg-white/[0.1]'}`;
  const subtleBtnClass = `!border-transparent !shadow-none ${isLight
      ? '!bg-black/[0.04] hover:!bg-black/[0.08] !text-[#1c1c1e]'
      : '!bg-white/[0.06] hover:!bg-white/[0.12] !text-[#f5f5f7]'
    }`;

  return (
    <>
      {contextHolder}
      <header
        className={`shrink-0 border-b backdrop-blur-xl ${isLight
            ? 'border-black/[0.08] bg-[#f9f9fb]/90'
            : 'border-white/[0.08] bg-[#1c1c1e]/85'
          }`}
      >
        {/* Primary Navigation & Workspace Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2">
          <div className="flex flex-wrap items-center gap-2">
            <div className="mr-1 flex flex-col items-start leading-none">
              <span
                className={`text-[19px] font-bold leading-none tracking-[-0.03em] ${isLight ? 'text-[#1c1c1e]' : 'text-[#f5f5f7]'
                  }`}
                style={{ fontFamily: "'Plus Jakarta Sans', 'SF Pro Display', 'Inter', sans-serif" }}
              >
                Tailwind
              </span>
              <span
                className={`mt-0.5 font-mono text-[9px] leading-none tracking-tight ${isLight ? 'text-black/45' : 'text-white/45'
                  }`}
              >
                {typeof __APP_VERSION__ !== 'undefined' ? __APP_VERSION__ : 'dev'}
              </span>
            </div>

            <span className={dividerClass} />

            <Space.Compact size="small">
              <Select
                value={activePresetId}
                onChange={handleWorkspaceChange}
                style={{ width: 230 }}
                options={selectOptions}
              />
              <Tooltip title="New Blank Workspace">
                <Button className={subtleBtnClass} onClick={() => setNewWsOpen(true)}>
                  New
                </Button>
              </Tooltip>
              <Tooltip title={isCustomWorkspace ? 'Save Workspace' : 'Save Copy to My Workspaces'}>
                <Button className={subtleBtnClass} icon={<SaveOutlined />} onClick={handleSaveWorkspace} />
              </Tooltip>
              {isCustomWorkspace && (
                <>
                  <Tooltip title="Rename Workspace">
                    <Button
                      className={subtleBtnClass}
                      icon={<EditOutlined />}
                      onClick={handleOpenRenameWorkspace}
                    />
                  </Tooltip>
                  <Tooltip title="Delete Workspace">
                    <Button
                      danger
                      className={subtleBtnClass}
                      icon={<DeleteOutlined />}
                      onClick={() => {
                        deleteWorkspace(activePresetId);
                        msgApi.info('Workspace deleted');
                      }}
                    />
                  </Tooltip>
                </>
              )}
            </Space.Compact>

            <span className={dividerClass} />

            <Space.Compact size="small">
              <Tooltip title="Undo (Ctrl+Z)">
                <Button
                  className={subtleBtnClass}
                  icon={<UndoOutlined />}
                  disabled={past.length === 0}
                  onClick={undo}
                />
              </Tooltip>
              <Tooltip title="Redo (Ctrl+Y)">
                <Button
                  className={subtleBtnClass}
                  icon={<RedoOutlined />}
                  disabled={future.length === 0}
                  onClick={redo}
                />
              </Tooltip>
            </Space.Compact>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <Dropdown menu={{ items: addMenuItems }} trigger={['click']}>
              <Button size="small" className={subtleBtnClass}>
                Add Appliance
              </Button>
            </Dropdown>

            <Button size="small" className={subtleBtnClass} onClick={() => setImportOpen(true)}>
              Import Config
            </Button>

            <Button size="small" className={subtleBtnClass} onClick={autoLayoutTopology}>
              Auto-Layout
            </Button>

            <Badge count={simResult.warnings.length} size="small">
              <Button
                size="small"
                className={simResult.warnings.length > 0 ? undefined : subtleBtnClass}
                type={simResult.warnings.length > 0 ? 'primary' : 'default'}
                danger={simResult.warnings.length > 0}
                ghost={simResult.warnings.length > 0}
                onClick={() => setDiagOpen(true)}
              >
                Diagnostics
              </Button>
            </Badge>

            <span className={dividerClass} />

            <Tooltip
              title={
                baselineSimResult
                  ? 'Clear baseline snapshot'
                  : 'Capture baseline snapshot for Diff Mode'
              }
            >
              <Badge count={baselineSimResult ? totalChanges : 0} size="small">
                <Button
                  size="small"
                  className={baselineSimResult ? undefined : subtleBtnClass}
                  type={baselineSimResult ? 'primary' : 'default'}
                  ghost={Boolean(baselineSimResult)}
                  onClick={baselineSimResult ? clearSnapshot : captureSnapshot}
                >
                  {baselineSimResult ? 'Diff Active' : 'Snapshot'}
                </Button>
              </Badge>
            </Tooltip>

            <Tooltip title="Quick Search (Ctrl+K)">
              <Button
                size="small"
                className={subtleBtnClass}
                icon={<SearchOutlined />}
                onClick={() => setSearchOpen(true)}
              >
                Search
              </Button>
            </Tooltip>

            <Select<ProtocolOverlayMode>
              size="small"
              value={protocolOverlay}
              onChange={setProtocolOverlay}
              style={{ width: 112 }}
              options={[
                { value: 'none', label: 'Overlay: Off' },
                { value: 'bgp-asn', label: 'Overlay: BGP' },
                { value: 'ospf-area', label: 'Overlay: OSPF' },
                { value: 'stp', label: 'Overlay: STP' },
              ]}
            />

            <Button size="small" className={subtleBtnClass} onClick={() => setRoaOpen(true)}>
              RPKI ({topology.roaTable?.length ?? 0})
            </Button>

            <Button size="small" className={subtleBtnClass} onClick={() => setExportOpen(true)}>
              Export
            </Button>

            <Tooltip title="Keyboard Shortcuts (?)">
              <Button
                size="small"
                className={subtleBtnClass}
                onClick={() => setShortcutsOpen(true)}
              >
                ?
              </Button>
            </Tooltip>

            <Button
              size="small"
              type="primary"
              className="!shadow-none"
              onClick={handleShare}
            >
              {copied ? 'Copied' : 'Share'}
            </Button>

            <Tooltip title={themeMode === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}>
              <Button
                size="small"
                className={subtleBtnClass}
                icon={themeMode === 'dark' ? <SunOutlined /> : <MoonOutlined />}
                onClick={toggleThemeMode}
              />
            </Tooltip>
          </div>
        </div>

        {/* Secondary Packet Trace & Verification Bar */}
        <div
          className={`flex flex-wrap items-center justify-between gap-2 border-t px-4 py-1.5 ${isLight
              ? 'border-black/[0.06] bg-black/[0.02]'
              : 'border-white/[0.06] bg-black/25'
            }`}
        >
          <div className="flex flex-wrap items-center gap-2">
            <Space.Compact size="small">
              <Select
                value={traceSrcNodeId || undefined}
                onChange={(val) => setTraceParams(val, traceDstIp, 'default', undefined, undefined, undefined)}
                style={{ width: 130 }}
                placeholder="Source"
                options={topology.nodes.map((n) => ({ value: n.id, label: n.hostname }))}
              />
              {srcNode && srcNode.interfaces.length > 0 && (
                <Select
                  allowClear
                  placeholder="South of..."
                  value={traceSrcInterfaceId}
                  onChange={(val) => {
                    const pickedIf = srcNode.interfaces.find((i) => i.id === val);
                    setTraceParams(
                      traceSrcNodeId,
                      traceDstIp,
                      pickedIf?.vrf || traceVrf,
                      traceProto,
                      tracePort,
                      val ?? null,
                      null
                    );
                  }}
                  style={{ width: 115 }}
                  options={srcNode.interfaces.map((i) => ({
                    value: i.id,
                    label: `South: ${i.name}`,
                  }))}
                />
              )}
              <Select
                value={traceVrf}
                onChange={(val) => {
                  const pickedIf = topology.nodes
                    .find((n) => n.id === traceSrcNodeId)
                    ?.interfaces.find((i) => i.id === traceSrcInterfaceId);
                  const keepIf = Boolean(pickedIf && (pickedIf.vrf || 'default') === val);
                  setTraceParams(
                    traceSrcNodeId,
                    traceDstIp,
                    val,
                    traceProto,
                    tracePort,
                    keepIf ? traceSrcInterfaceId : null,
                    keepIf ? undefined : null
                  );
                }}
                style={{ width: 96 }}
                placeholder="VRF"
                options={srcVrfs.map((v) => ({ value: v, label: `vrf:${v}` }))}
              />
              <Input
                value={traceDstIp}
                onChange={(e) =>
                  setTraceParams(traceSrcNodeId, e.target.value, undefined, undefined, undefined, undefined, null)
                }
                onPressEnter={runTrace}
                placeholder="IPv4 or IPv6"
                style={{ width: 135, fontFamily: 'monospace' }}
              />
              <Select
                value={traceProto}
                onChange={(val) =>
                  setTraceParams(
                    traceSrcNodeId,
                    traceDstIp,
                    traceVrf,
                    val as L4Protocol,
                    undefined,
                    undefined,
                    null
                  )
                }
                style={{ width: 72 }}
                options={[
                  { value: 'any', label: 'any' },
                  { value: 'tcp', label: 'tcp' },
                  { value: 'udp', label: 'udp' },
                  { value: 'icmp', label: 'icmp' },
                ]}
              />
              <Input
                value={tracePort ?? ''}
                onChange={(e) => {
                  const raw = e.target.value.replace(/\D/g, '');
                  setTraceParams(
                    traceSrcNodeId,
                    traceDstIp,
                    traceVrf,
                    traceProto,
                    raw ? Number(raw) : null,
                    undefined,
                    null
                  );
                }}
                onPressEnter={runTrace}
                placeholder="Port"
                style={{ width: 58, fontFamily: 'monospace' }}
              />
              <Button type="primary" onClick={runTrace}>
                Trace
              </Button>
              {traceResult && (
                <Button icon={<CloseOutlined />} onClick={clearTrace} />
              )}
            </Space.Compact>
          </div>

          <div className="flex items-center gap-2">
            <Tooltip title="Path & Policy Verification Suite">
              <Badge
                count={pathTests.length > 0 ? suiteSummary.failed : 0}
                size="small"
              >
                <Button
                  size="small"
                  className={subtleBtnClass}
                  onClick={() => setTestsOpen(true)}
                >
                  Path Tests ({pathTests.length})
                </Button>
              </Badge>
            </Tooltip>
          </div>
        </div>
      </header>

      <Modal
        title="Create New Blank Workspace"
        open={newWsOpen}
        onOk={handleCreateWorkspace}
        onCancel={() => setNewWsOpen(false)}
        okText="Create Workspace"
        width={420}
      >
        <Input
          autoFocus
          value={newWsName}
          onChange={(e) => setNewWsName(e.target.value)}
          onPressEnter={handleCreateWorkspace}
          placeholder="Workspace name (e.g. Core Migration Lab)"
        />
      </Modal>

      <Modal
        title={wsNameModalMode === 'rename' ? 'Rename Workspace' : 'Save Copy to My Workspaces'}
        open={wsNameModalMode !== null}
        onOk={handleSubmitWsNameModal}
        onCancel={() => setWsNameModalMode(null)}
        okText={wsNameModalMode === 'rename' ? 'Rename' : 'Save Copy'}
        okButtonProps={{ disabled: !wsModalName.trim() }}
        width={420}
      >
        <Input
          autoFocus
          value={wsModalName}
          onChange={(e) => setWsModalName(e.target.value)}
          onPressEnter={handleSubmitWsNameModal}
          placeholder="Workspace name"
        />
      </Modal>

      <Modal
        title="Import Topology or Device Configs"
        open={importOpen}
        onOk={handleImportSubmit}
        onCancel={() => {
          setImportOpen(false);
          setImportError(null);
        }}
        okText={
          importMode === 'merge'
            ? 'Add to Workspace'
            : importMode === 'hydrate'
              ? 'Update Matching Nodes'
              : 'Replace Workspace'
        }
        width={680}
      >
        <div className="mb-3 flex items-center justify-between">
          <Radio.Group
            size="small"
            value={importMode}
            onChange={(e) => setImportMode(e.target.value)}
            optionType="button"
            options={[
              { value: 'merge', label: 'Add Appliance(s)' },
              { value: 'hydrate', label: 'Update Existing (Keep Links)' },
              { value: 'replace', label: 'Replace Workspace' },
            ]}
          />
        </div>
        {importError && (
          <Alert type="error" message={importError} showIcon className="!mb-3" />
        )}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-[#8e8e93]">
              Tip: Select &quot;Update Existing (Keep Links)&quot; and upload device .cfg/.txt files to populate existing nodes.
            </span>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".cfg,.txt,.conf,.yaml,.yml,.json"
              className="hidden"
              onChange={(e) => {
                void handleBulkConfigFiles(e.target.files);
                e.target.value = '';
              }}
            />
            <Button size="small" onClick={() => fileInputRef.current?.click()}>
              Upload .cfg / .txt File(s)
            </Button>
          </div>
          <Input.TextArea
            rows={10}
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder={`Paste any of:\n• Cisco IOS-XE / NX-OS / FRR running-config\n• Juniper Junos 'set' commands or MikroTik RouterOS /export\n• Palo Alto PAN-OS 'set' commands or FortiGate 'config'\n• Exported topology.yaml or topology.json`}
            style={{ fontFamily: 'monospace', fontSize: 12 }}
          />
        </div>
      </Modal>

      <Drawer
        title="Path & Policy Verification Suite"
        open={testsOpen}
        onClose={() => setTestsOpen(false)}
        mask={!testsPinned}
        maskClosable={!testsPinned}
        rootStyle={testsPinned ? { pointerEvents: 'none' } : undefined}
        styles={testsPinned ? { wrapper: { pointerEvents: 'auto' } } : undefined}
        extra={
          <Tooltip title={testsPinned ? 'Unpin drawer' : 'Pin drawer open while interacting with canvas'}>
            <Button
              size="small"
              type={testsPinned ? 'primary' : 'text'}
              icon={testsPinned ? <PushpinFilled /> : <PushpinOutlined />}
              onClick={() => setTestsPinned((v) => !v)}
            >
              {testsPinned ? 'Pinned' : 'Pin'}
            </Button>
          </Tooltip>
        }
        width={520}
      >
        <div className="space-y-4">
          <div className="rounded border border-slate-800 bg-[#0b1120] p-3">
            <div className="mb-2 text-xs font-semibold text-slate-300">
              Save Current Trace as Assertion
            </div>
            <div className="mb-2 font-mono text-[11px] text-slate-400">
              From: {srcNode?.hostname ?? '-'}
              {traceSrcInterfaceId
                ? ` (${srcNode?.interfaces.find((i) => i.id === traceSrcInterfaceId)?.name})`
                : ''}{' '}
              → {traceDstIp} ({traceProto}
              {tracePort ? `/${tracePort}` : ''})
            </div>
            <Space>
              <Select
                size="small"
                value={newTestExpected}
                onChange={setNewTestExpected}
                style={{ width: 150 }}
                options={[
                  { value: 'delivered', label: 'Expect DELIVERED' },
                  { value: 'blocked', label: 'Expect BLOCKED' },
                  { value: 'dropped', label: 'Expect DROPPED' },
                ]}
              />
              <Button
                size="small"
                type="primary"
                icon={<PlusOutlined />}
                onClick={() => {
                  addPathTest({
                    id: `pt-${Date.now()}`,
                    name: `${srcNode?.hostname ?? 'Src'} → ${traceDstIp}`,
                    srcNodeId: traceSrcNodeId,
                    srcInterfaceId: traceSrcInterfaceId,
                    srcIp: useSimStore.getState().traceSrcIp,
                    dstIp: traceDstIp,
                    vrf: traceVrf,
                    protocol: traceProto,
                    dstPort: tracePort,
                    expectedOutcome: newTestExpected,
                  });
                  msgApi.success('Path test assertion added');
                }}
              >
                Add Assertion
              </Button>
            </Space>
          </div>

          <div className="flex items-center justify-between">
            <Space>
              <Tag color="green">Passed: {suiteSummary.passed}</Tag>
              <Tag color={suiteSummary.failed > 0 ? 'red' : 'default'}>
                Failed: {suiteSummary.failed}
              </Tag>
            </Space>
            <Button
              size="small"
              disabled={pathTests.length === 0}
              onClick={() => setShowFailoverMatrix(true)}
            >
              Run N-1 Failover
            </Button>
          </div>

          {failoverMatrix && (
            <div className="space-y-1 rounded border border-slate-800 bg-[#0b1120] p-2.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">
                  N-1 Link Failover Matrix ({failoverMatrix.filter((f) => f.failed > 0).length} SPOF link(s))
                </span>
                <Button size="small" type="text" onClick={() => setShowFailoverMatrix(false)}>
                  Clear
                </Button>
              </div>
              {failoverMatrix.map((entry) => (
                <div key={entry.linkId} className="flex items-center justify-between font-mono text-[11px]">
                  <span className="text-slate-300">{entry.linkLabel}</span>
                  {entry.failed === 0 ? (
                    <Tag color="green" className="!m-0">RESILIENT</Tag>
                  ) : (
                    <Tag color="red" className="!m-0">
                      -{entry.failed} ({entry.brokenTests.join(', ')})
                    </Tag>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="space-y-2">
            {suiteSummary.results.map(({ test, trace, passed, message: msg }) => (
              <div
                key={test.id}
                className={`rounded border p-2.5 text-xs ${passed
                    ? 'border-emerald-500/30 bg-emerald-950/20'
                    : 'border-rose-500/40 bg-rose-950/30'
                  }`}
              >
                <div className="flex items-center justify-between">
                  <Space>
                    <Tag color={passed ? 'green' : 'red'} className="!m-0">
                      {passed ? 'PASS' : 'FAIL'}
                    </Tag>
                    {trace.asymmetricPath && (
                      <Tag color="gold" className="!m-0">
                        ASYMMETRIC
                      </Tag>
                    )}
                    {trace.returnTrace && trace.returnTrace.outcome !== 'delivered' && (
                      <Tag color="volcano" className="!m-0">
                        RET {trace.returnTrace.outcome.toUpperCase()}
                      </Tag>
                    )}
                    <span className="font-semibold text-slate-200">{test.name}</span>
                  </Space>
                  <Space size="small">
                    <Button
                      size="small"
                      onClick={() => {
                        setTraceParams(
                          test.srcNodeId,
                          test.dstIp,
                          test.vrf,
                          test.protocol ?? 'any',
                          test.dstPort ?? null,
                          test.srcInterfaceId ?? null,
                          test.srcIp ?? null
                        );
                        setTraceResult(trace);
                        if (!testsPinned) setTestsOpen(false);
                      }}
                    >
                      Show on Canvas
                    </Button>
                    <Button
                      size="small"
                      danger
                      type="text"
                      icon={<DeleteOutlined />}
                      onClick={() => deletePathTest(test.id)}
                    />
                  </Space>
                </div>
                <div className="mt-1 font-mono text-[11px] text-slate-400">{msg}</div>
                {trace.hops.length > 0 && (
                    <div className="mt-0.5 truncate font-mono text-[10px] text-slate-400">
                      Fwd: {trace.hops.map((h) => h.hostname).join(' → ')}
                    </div>
                )}
                    {trace.returnTrace && trace.returnTrace.hops.length > 0 && (
                      <div
                        className={`mt-0.5 truncate font-mono text-[10px] ${trace.returnTrace.outcome !== 'delivered'
                            ? 'text-rose-400'
                            : trace.asymmetricPath
                              ? 'text-amber-300'
                              : 'text-sky-400/80'
                          }`}
                      >
                        Ret ({trace.returnTrace.outcome}): {trace.returnTrace.hops.map((h) => h.hostname).join(' → ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
        </div>
      </Drawer>

      <Drawer
        title={`Control-Plane Diagnostics (${simResult.warnings.length})`}
        open={diagOpen}
        onClose={() => setDiagOpen(false)}
        width={480}
      >
        {traceResult && (traceResult.totalLatencyMs || traceResult.totalJitterMs || traceResult.combinedLossPct || traceResult.mtuWarning) && (
          <Alert
            className="!mb-3"
            type={traceResult.mtuWarning || (traceResult.combinedLossPct ?? 0) >= 5 ? 'warning' : 'info'}
            showIcon
            message={`Path SLA: ${traceResult.totalLatencyMs ?? 0}ms latency · ±${traceResult.totalJitterMs ?? 0}ms jitter · ${traceResult.combinedLossPct ?? 0}% loss${traceResult.pathMtu ? ` · Min MTU ${traceResult.pathMtu}B` : ''}${traceResult.asymmetricPath ? ' · Asymmetric Return Path' : ''}${traceResult.ipfixRecord ? ` · IPFIX→${traceResult.ipfixRecord.exporterIp}` : ''}`}
            description={traceResult.mtuWarning}
          />
        )}
        {traceResult?.returnTrace && (
          <Alert
            className="!mb-3"
            type={traceResult.returnTrace.outcome === 'delivered' ? 'success' : 'warning'}
            showIcon
            message={`Last Trace Return Path: ${traceResult.returnTrace.outcome.toUpperCase()} (${traceResult.returnTrace.hops.length} hops)`}
            description={traceResult.returnTrace.failureReason}
          />
        )}
        {simResult.warnings.length === 0 ? (
          <Alert
            type="success"
            showIcon
            message="No control-plane warnings detected"
            description="All adjacencies, router IDs, VLANs, OSPF areas, and underlays look healthy."
          />
        ) : (
          <div className="space-y-2">
            {simResult.warnings.map((w, idx) => (
              <Alert key={idx} type="warning" showIcon message={w} />
            ))}
          </div>
        )}
      </Drawer>

      <Modal
        title="Quick Jump Search (Ctrl+K)"
        open={searchOpen}
        onCancel={() => setSearchOpen(false)}
        footer={null}
        width={560}
      >
        <Input
          autoFocus
          placeholder="Search hostname, router-id, BGP ASN, interface IP, or RIB prefix..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="!mb-3"
        />
        <div className="max-h-72 space-y-1.5 overflow-y-auto">
          {topology.nodes
            .filter((n) => {
              const q = searchQuery.trim().toLowerCase();
              if (!q) return true;
              const rib = simResult.nodes[n.id]?.rib ?? [];
              return (
                n.hostname.toLowerCase().includes(q) ||
                n.routerId.includes(q) ||
                String(n.bgp.asn).includes(q) ||
                n.interfaces.some(
                  (i) => i.name.toLowerCase().includes(q) || i.cidr.includes(q)
                ) ||
                rib.some((r) => `${r.prefix}/${r.prefixLen}`.includes(q))
              );
            })
            .map((n) => {
              const q = searchQuery.trim().toLowerCase();
              const matchedRoute = q
                ? (simResult.nodes[n.id]?.rib ?? []).find((r) =>
                  `${r.prefix}/${r.prefixLen}`.includes(q)
                )
                : undefined;
              return (
                <button
                  key={n.id}
                  type="button"
                  onClick={() => {
                    selectNode(n.id);
                    setSearchOpen(false);
                  }}
                  className="flex w-full items-center justify-between rounded border border-slate-700/70 bg-slate-900/70 px-3 py-2 text-left text-xs hover:border-sky-500"
                >
                  <div>
                    <span className="font-semibold text-slate-100">{n.hostname}</span>{' '}
                    <span className="text-slate-400">({n.vendor})</span>
                    {matchedRoute && (
                      <div className="mt-0.5 font-mono text-[11px] text-emerald-300">
                        RIB: {matchedRoute.prefix}/{matchedRoute.prefixLen} via {matchedRoute.nextHop} ({matchedRoute.protocol.toUpperCase()})
                      </div>
                    )}
                  </div>
                  <span className="font-mono text-[11px] text-sky-300">RID {n.routerId}</span>
                </button>
              );
            })}
        </div>
      </Modal>

      <Modal
        title="RPKI ROA Table (RFC 6811)"
        open={roaOpen}
        onCancel={() => setRoaOpen(false)}
        footer={null}
        width={560}
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Input
            size="small"
            className="!w-40"
            placeholder="Prefix (e.g. 203.0.113.0/24)"
            value={newRoaPrefix}
            onChange={(e) => setNewRoaPrefix(e.target.value)}
          />
          <InputNumber
            size="small"
            className="!w-24"
            min={1}
            max={128}
            placeholder="MaxLen"
            value={newRoaMaxLen}
            onChange={(v) => setNewRoaMaxLen(v ?? 24)}
          />
          <InputNumber
            size="small"
            className="!w-28"
            min={1}
            placeholder="Origin ASN"
            value={newRoaAsn}
            onChange={(v) => setNewRoaAsn(v ?? 65100)}
          />
          <Button
            size="small"
            type="primary"
            onClick={() => {
              if (!newRoaPrefix.trim()) return;
              setRoaTable([
                ...(topology.roaTable ?? []),
                {
                  id: `roa-${Date.now()}`,
                  prefix: newRoaPrefix.trim(),
                  maxLength: newRoaMaxLen,
                  originAsn: newRoaAsn,
                },
              ]);
            }}
          >
            Add ROA
          </Button>
        </div>
        <div className="max-h-64 space-y-1.5 overflow-y-auto">
          {(topology.roaTable ?? []).length === 0 ? (
            <div className="text-xs text-slate-400">No ROA entries configured.</div>
          ) : (
            (topology.roaTable ?? []).map((roa) => (
              <div
                key={roa.id}
                className="flex items-center justify-between rounded border border-slate-700/70 bg-slate-900/70 px-3 py-1.5 text-xs"
              >
                <span className="font-mono text-slate-200">
                  {roa.prefix} (max /{roa.maxLength}) → AS {roa.originAsn}
                </span>
                <Button
                  size="small"
                  danger
                  type="text"
                  icon={<DeleteOutlined />}
                  onClick={() =>
                    setRoaTable((topology.roaTable ?? []).filter((r) => r.id !== roa.id))
                  }
                />
              </div>
            ))
          )}
        </div>
      </Modal>

      <Modal
        title="Export Topology & Artifacts"
        open={exportOpen}
        onCancel={() => setExportOpen(false)}
        footer={null}
        width={440}
      >
        <div className="space-y-2.5 text-xs">
          <div className="flex items-center justify-between rounded-lg border border-white/[0.08] bg-white/[0.035] p-3">
            <div>
              <div className="font-semibold text-slate-100">Automation Bundle (.zip)</div>
              <div className="text-[11px] text-slate-400">All device running-configs, RIBs, and topology YAML/JSON</div>
            </div>
            <Button size="small" type="primary" onClick={() => { handleExportBundle(); setExportOpen(false); }}>
              Download .zip
            </Button>
          </div>
          <div className="flex items-center justify-between rounded-lg border border-white/[0.08] bg-white/[0.035] p-3">
            <div>
              <div className="font-semibold text-slate-100">Vector Diagram (.svg)</div>
              <div className="text-[11px] text-slate-400">Scalable topology diagram of all nodes and links</div>
            </div>
            <Button size="small" onClick={() => { handleExportSvg(); setExportOpen(false); }}>
              Download .svg
            </Button>
          </div>
          <div className="flex items-center justify-between rounded-lg border border-white/[0.08] bg-white/[0.035] p-3">
            <div>
              <div className="font-semibold text-slate-100">Topology State (.json)</div>
              <div className="text-[11px] text-slate-400">Raw JSON topology state for re-import or version control</div>
            </div>
            <Button size="small" onClick={() => { handleExportJson(); setExportOpen(false); }}>
              Download .json
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        title="Keyboard Shortcuts"
        open={shortcutsOpen}
        onCancel={() => setShortcutsOpen(false)}
        footer={null}
        width={420}
      >
        <div className="space-y-2 text-xs text-slate-300">
          <div className="flex justify-between"><span>Quick Jump Search (Nodes / IPs / RIB)</span><kbd className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">Ctrl+K</kbd></div>
          <div className="flex justify-between"><span>Undo Topology Edit</span><kbd className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">Ctrl+Z</kbd></div>
          <div className="flex justify-between"><span>Redo Topology Edit</span><kbd className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">Ctrl+Y</kbd></div>
          <div className="flex justify-between"><span>Auto-Layout Canvas</span><kbd className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">Shift+L</kbd></div>
          <div className="flex justify-between"><span>Delete Selected Node</span><kbd className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">Del / Backspace</kbd></div>
          <div className="flex justify-between"><span>Clear Active Packet Trace</span><kbd className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">Esc</kbd></div>
          <div className="flex justify-between"><span>Toggle This Help</span><kbd className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">?</kbd></div>
        </div>
      </Modal>
    </>
  );
};
