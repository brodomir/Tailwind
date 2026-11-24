import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  CheckOutlined,
  CopyOutlined,
  DownloadOutlined,
  SaveOutlined,
  UndoOutlined,
} from '@ant-design/icons';
import { Alert, Button, Empty, Input, Space, Switch, Table, Tabs, Tag } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { computeRibDiff } from '../engine/diff';
import {
  formatPrimaryCli,
  formatRunningConfig,
  formatSecondaryCli,
} from '../engine/formatters';
import { importTopologyFromText, validateRunningConfig } from '../engine/importer';
import { VENDOR_METADATA } from '../engine/vendorProfiles';
import { useSimStore } from '../store/useSimStore';
import { LfibEntry, MrouteEntry, NeighborStatus, RibEntry } from '../types/network';

function downloadFile(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const DEFAULT_RIB_COL_WIDTHS: Record<string, number> = {
  state: 82,
  af: 54,
  vrf: 85,
  prefix: 150,
  proto: 105,
  ad: 96,
  nextHop: 135,
  iface: 120,
  asPath: 130,
  notes: 220,
};

interface ResizableHeaderCellProps extends React.ThHTMLAttributes<HTMLTableCellElement> {
  onResizeWidth?: (width: number) => void;
  colWidth?: number;
}

const ResizableHeaderCell: React.FC<ResizableHeaderCellProps> = ({
  onResizeWidth,
  colWidth,
  children,
  style,
  ...restProps
}) => {
  const handleMouseDown = (e: React.MouseEvent<HTMLSpanElement>) => {
    if (!onResizeWidth) return;
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startWidth = colWidth ?? (e.currentTarget.parentElement?.getBoundingClientRect().width || 100);

    const onMouseMove = (moveEv: MouseEvent) => {
      const next = Math.max(48, Math.round(startWidth + (moveEv.clientX - startX)));
      onResizeWidth(next);
    };
    const onMouseUp = () => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
    };
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
  };

  if (!onResizeWidth) {
    return (
      <th {...restProps} style={style}>
        {children}
      </th>
    );
  }

  return (
    <th {...restProps} style={{ ...style, position: 'relative', userSelect: 'none' }}>
      {children}
      <span
        onMouseDown={handleMouseDown}
        title="Drag to resize column"
        className="absolute top-0 right-0 bottom-0 z-10 w-1.5 cursor-col-resize hover:bg-sky-400/70"
      />
    </th>
  );
};

export const CliOutputPanel: React.FC<{ headerExtra?: React.ReactNode }> = ({ headerExtra }) => {
  const {
    topology,
    simResult,
    baselineSimResult,
    selectedNodeId,
    traceSrcNodeId,
    setTraceParams,
    runTrace,
    applyParsedNodeConfig,
  } = useSimStore();
  const [activeKey, setActiveKey] = useState('primary');
  const [copied, setCopied] = useState(false);
  const [ribFilter, setRibFilter] = useState('');
  const [ribActiveOnly, setRibActiveOnly] = useState(false);
  const [ribColWidths, setRibColWidths] = useState<Record<string, number>>(DEFAULT_RIB_COL_WIDTHS);
  const [draftConfig, setDraftConfig] = useState('');
  const [configDirty, setConfigDirty] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [configSaved, setConfigSaved] = useState(false);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
    };
  }, []);

  const node = topology.nodes.find((n) => n.id === selectedNodeId);
  const result = node ? simResult.nodes[node.id] : undefined;
  const formattedConfig = node ? formatRunningConfig(node) : '';

  useEffect(() => {
    setDraftConfig(formattedConfig);
    setConfigDirty(false);
    setConfigError(null);
  }, [selectedNodeId, formattedConfig]);

  const secondaryText = node && result ? formatSecondaryCli(node, result) : '';
  const effectiveActiveKey =
    activeKey === 'secondary' && !secondaryText ? 'primary' : activeKey;
  const configIssues = useMemo(
    () => (node && result && effectiveActiveKey === 'config' ? validateRunningConfig(draftConfig) : []),
    [node, result, effectiveActiveKey, draftConfig]
  );

  if (!node || !result) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <Empty description="Select an appliance to inspect its routing table and CLI" />
      </div>
    );
  }

  const meta = VENDOR_METADATA[node.vendor] ?? VENDOR_METADATA['cisco-ios-xe'];
  const primaryText = formatPrimaryCli(node, result);
  const runningConfigText = configDirty ? draftConfig : formattedConfig;
  const configErrors = configIssues.filter((i) => i.severity === 'error');
  const configWarnings = configIssues.filter((i) => i.severity === 'warning');
  const jsonText = JSON.stringify(result, null, 2);

  const handleSaveRunningConfig = () => {
    if (configErrors.length > 0) {
      setConfigError(`Fix ${configErrors.length} error(s) before applying.`);
      return;
    }
    try {
      setConfigError(null);
      const parsed = importTopologyFromText(draftConfig);
      if (!parsed.nodes.length) {
        setConfigError('Could not parse any device configuration from the text.');
        return;
      }
      applyParsedNodeConfig(node.id, parsed.nodes[0]);
      setConfigDirty(false);
      setConfigSaved(true);
      window.setTimeout(() => setConfigSaved(false), 1800);
    } catch (err) {
      setConfigError(err instanceof Error ? err.message : 'Failed to parse running config');
    }
  };

  const diffSummary = baselineSimResult
    ? computeRibDiff(baselineSimResult, simResult)
    : null;
  const diffCount = diffSummary
    ? diffSummary.added + diffSummary.removed + diffSummary.modified
    : 0;

  const activeText =
    effectiveActiveKey === 'secondary' && secondaryText
      ? secondaryText
      : effectiveActiveKey === 'config'
        ? runningConfigText
        : effectiveActiveKey === 'json'
          ? jsonText
          : primaryText;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(activeText);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
      if (copyTimerRef.current !== null) window.clearTimeout(copyTimerRef.current);
      copyTimerRef.current = window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard API unavailable
    }
  };

  const makeResizable = (key: string) => ({
    width: ribColWidths[key],
    ellipsis: true,
    onHeaderCell: () =>
      ({
        colWidth: ribColWidths[key],
        onResizeWidth: (w: number) =>
          setRibColWidths((prev) => ({ ...prev, [key]: w })),
      }) as React.HTMLAttributes<HTMLElement>,
  });

  const ribColumns: ColumnsType<RibEntry> = [
    {
      title: 'State',
      key: 'state',
      ...makeResizable('state'),
      render: (_, r) =>
        r.active ? (
          <Tag color={r.ecmp ? 'cyan' : 'green'} className="!m-0 !text-[10px]">
            {r.ecmp ? 'ECMP' : 'ACTIVE'}
          </Tag>
        ) : (
          <Tag
            color={r.feasibleSuccessor ? 'blue' : 'default'}
            className="!m-0 !text-[10px]"
          >
            {r.feasibleSuccessor ? 'FS-BKP' : 'INACT'}
          </Tag>
        ),
    },
    {
      title: 'AF',
      key: 'af',
      ...makeResizable('af'),
      render: (_, r) => (
        <Tag className="!m-0 !text-[10px]">IPv{r.af ?? 4}</Tag>
      ),
    },
    {
      title: 'VRF',
      dataIndex: 'vrf',
      key: 'vrf',
      ...makeResizable('vrf'),
    },
    {
      title: 'Prefix',
      key: 'prefix',
      ...makeResizable('prefix'),
      render: (_, r) => (
        <Space size={4}>
          <span className="font-mono text-sky-300">
            {r.prefix}/{r.prefixLen}
          </span>
          <Button
            size="small"
            type="link"
            className="!h-auto !px-1 !py-0 !text-[10px]"
            onClick={() => {
              setTraceParams(traceSrcNodeId || node.id, r.prefix, r.vrf);
              runTrace();
            }}
          >
            Trace
          </Button>
        </Space>
      ),
    },
    {
      title: 'Proto',
      key: 'proto',
      ...makeResizable('proto'),
      render: (_, r) => (
        <span className="font-mono uppercase">
          {r.protocol}
          {r.ospfType ? `(${r.ospfType})` : r.isisLevel ? `(${r.isisLevel})` : ''}
        </span>
      ),
    },
    {
      title: 'AD/Metric',
      key: 'ad',
      ...makeResizable('ad'),
      render: (_, r) => (
        <span className="font-mono">
          [{r.ad}/{r.metric}]
          {r.tag !== undefined && (
            <Tag color="gold" className="!ml-1 !mr-0 !text-[10px]">
              tag:{r.tag}
            </Tag>
          )}
        </span>
      ),
    },
    {
      title: 'Next-Hop',
      dataIndex: 'nextHop',
      key: 'nextHop',
      ...makeResizable('nextHop'),
      render: (val: string) => <span className="font-mono">{val}</span>,
    },
    {
      title: 'Interface',
      dataIndex: 'egressInterface',
      key: 'iface',
      ...makeResizable('iface'),
      render: (val: string) => <span className="font-mono">{val || '-'}</span>,
    },
    {
      title: 'AS-Path',
      key: 'asPath',
      ...makeResizable('asPath'),
      render: (_, r) =>
        r.bgpAttrs ? (
          <span className="font-mono text-violet-300">
            {r.bgpAttrs.asPath.length > 0 ? r.bgpAttrs.asPath.join(' ') : 'local'}
            {r.bgpAttrs.localPref !== 100 ? ` (LP ${r.bgpAttrs.localPref})` : ''}
          </span>
        ) : (
          <span className="text-slate-600">-</span>
        ),
    },
    {
      title: 'Notes',
      key: 'notes',
      ...makeResizable('notes'),
      render: (_, r) => (
        <span className="text-[11px] text-amber-400">
          {r.leakedFromVrf ? `Leaked from ${r.leakedFromVrf}` : (r.reason ?? '')}
        </span>
      ),
    },
  ];

  const totalRibWidth = Object.values(ribColWidths).reduce((sum, w) => sum + w, 0);

  const tabItems = [
    {
      key: 'primary',
      label: meta.primaryCliCmd,
      children: (
        <pre className="m-0 whitespace-pre font-mono text-xs leading-relaxed text-emerald-300">
          {primaryText}
        </pre>
      ),
    },
    ...(secondaryText && meta.secondaryCliCmd
      ? [
          {
            key: 'secondary',
            label: meta.secondaryCliCmd,
            children: (
              <pre className="m-0 whitespace-pre font-mono text-xs leading-relaxed text-emerald-300">
                {secondaryText}
              </pre>
            ),
          },
        ]
      : []),
    {
      key: 'rib',
      label: `RIB (${result.rib.length})`,
      children: (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              size="small"
              allowClear
              className="!w-64"
              placeholder="Filter prefix, VRF, proto, next-hop..."
              value={ribFilter}
              onChange={(e) => setRibFilter(e.target.value)}
            />
            <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-slate-300">
              <Switch size="small" checked={ribActiveOnly} onChange={setRibActiveOnly} />
              <span>Active Only</span>
            </label>
          </div>
          <Table
            size="small"
            tableLayout="fixed"
            pagination={false}
            components={{ header: { cell: ResizableHeaderCell } }}
            dataSource={result.rib.filter((r) => {
              if (ribActiveOnly && !r.active) return false;
              const q = ribFilter.trim().toLowerCase();
              if (!q) return true;
              return (
                `${r.prefix}/${r.prefixLen}`.toLowerCase().includes(q) ||
                r.vrf.toLowerCase().includes(q) ||
                r.protocol.toLowerCase().includes(q) ||
                r.nextHop.toLowerCase().includes(q) ||
                r.egressInterface.toLowerCase().includes(q)
              );
            })}
            columns={ribColumns}
            rowKey={(r, i) => `${r.af ?? 4}-${r.vrf}-${r.prefix}/${r.prefixLen}-${r.protocol}-${i}`}
            scroll={{ x: totalRibWidth, y: 'clamp(160px, 30vh, 480px)' }}
          />
        </div>
      ),
    },
    {
      key: 'diff',
      label: `Diff${baselineSimResult ? ` (${diffCount})` : ''}`,
      children: !diffSummary ? (
        <Empty description="Click Snapshot in the top bar, then modify AD, metrics, or links to view unified RIB diff." />
      ) : diffSummary.items.length === 0 ? (
        <Empty description="No active RIB changes compared to the baseline snapshot." />
      ) : (
        <div className="space-y-1.5 font-mono text-[11px]">
          <div className="mb-2 flex gap-3">
            <Tag color="green">+{diffSummary.added} added</Tag>
            <Tag color="red">-{diffSummary.removed} removed</Tag>
            <Tag color="orange">~{diffSummary.modified} modified</Tag>
          </div>
          {diffSummary.items.map((item, idx) => (
            <div
              key={`${item.nodeId}-${item.vrf}-${item.cidr}-${idx}`}
              className={`rounded border px-2.5 py-1.5 ${
                item.status === 'added'
                  ? 'border-emerald-500/30 bg-emerald-950/30 text-emerald-200'
                  : item.status === 'removed'
                    ? 'border-rose-500/30 bg-rose-950/30 text-rose-200'
                    : 'border-amber-500/30 bg-amber-950/30 text-amber-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <span>
                  <span className="font-bold">
                    {item.status === 'added' ? '+' : item.status === 'removed' ? '-' : '~'}
                  </span>{' '}
                  {item.hostname} [{item.vrf}] <span className="text-sky-300">{item.cidr}</span>
                </span>
                <Tag className="!m-0 !text-[10px]">{item.status.toUpperCase()}</Tag>
              </div>
              {item.before && (
                <div className="mt-0.5 text-[10px] text-rose-300">
                  - {item.before.protocol.toUpperCase()} [{item.before.ad}/{item.before.metric}] via{' '}
                  {item.before.nextHop} ({item.before.egressInterface})
                </div>
              )}
              {item.after && (
                <div className="mt-0.5 text-[10px] text-emerald-300">
                  + {item.after.protocol.toUpperCase()} [{item.after.ad}/{item.after.metric}] via{' '}
                  {item.after.nextHop} ({item.after.egressInterface})
                </div>
              )}
            </div>
          ))}
        </div>
      ),
    },
    {
      key: 'neighbors',
      label: `Neighbors (${result.neighbors?.length ?? 0})`,
      children: (
        <Table<NeighborStatus>
          size="small"
          pagination={false}
          rowKey={(r, i) => `${r.protocol}-${r.peerIp}-${r.interfaceName}-${i}`}
          dataSource={result.neighbors ?? []}
          columns={[
            {
              title: 'Proto',
              dataIndex: 'protocol',
              width: 70,
              render: (v: string) => <Tag color="blue">{v.toUpperCase()}</Tag>,
            },
            { title: 'Neighbor ID', dataIndex: 'neighborId', width: 120 },
            { title: 'Peer / VIP', dataIndex: 'peerIp', width: 120 },
            { title: 'Interface', dataIndex: 'interfaceName', width: 100 },
            {
              title: 'State',
              dataIndex: 'state',
              width: 105,
              render: (s: NeighborStatus['state']) => (
                <Tag
                  color={
                    s === 'Down'
                      ? 'red'
                      : s === 'ExStart'
                        ? 'orange'
                        : s === 'Standby' || s === '2-Way'
                          ? 'gold'
                          : 'green'
                  }
                >
                  {s}
                </Tag>
              ),
            },
            { title: 'Detail', dataIndex: 'detail' },
          ]}
        />
      ),
    },
    ...(result.lfib?.length || result.stpState || result.lldpNeighbors?.length || result.mroute?.length || result.evpnDfState?.length || result.bmpSummary
      ? [
          {
            key: 'standards',
            label: 'MPLS / L2 / Mcast',
            children: (
              <div className="space-y-3">
                {result.lfib && result.lfib.length > 0 && (
                  <div>
                    <div className="mb-1 text-[11px] font-semibold text-slate-300">
                      MPLS / SR LFIB ({result.lfib.length})
                    </div>
                    <Table<LfibEntry>
                      size="small"
                      pagination={false}
                      rowKey={(r, i) => `${r.prefix}-${r.inLabel}-${i}`}
                      dataSource={result.lfib}
                      columns={[
                        { title: 'Proto', dataIndex: 'protocol', width: 80, render: (v: string) => <Tag color="purple">{v.toUpperCase()}</Tag> },
                        { title: 'In Label', dataIndex: 'inLabel', width: 95 },
                        { title: 'Out Label', dataIndex: 'outLabel', width: 95 },
                        { title: 'Prefix', dataIndex: 'prefix', width: 130 },
                        { title: 'Next Hop', dataIndex: 'nextHop', width: 120 },
                        { title: 'Egress', dataIndex: 'egressInterface' },
                      ]}
                    />
                  </div>
                )}
                {result.stpState && (
                  <div>
                    <div className="mb-1 text-[11px] font-semibold text-slate-300">
                      RSTP Bridge (Root: {result.stpState.rootBridgeId}{result.stpState.isRoot ? ' — This Bridge is Root' : ''})
                    </div>
                    <Table
                      size="small"
                      pagination={false}
                      rowKey={(r) => r.interfaceName}
                      dataSource={result.stpState.ports}
                      columns={[
                        { title: 'Interface', dataIndex: 'interfaceName', width: 130 },
                        { title: 'Role', dataIndex: 'role', width: 110 },
                        {
                          title: 'State',
                          dataIndex: 'state',
                          render: (s: string) => <Tag color={s === 'Blocking' ? 'red' : 'green'}>{s}</Tag>,
                        },
                      ]}
                    />
                  </div>
                )}
                {result.lldpNeighbors && result.lldpNeighbors.length > 0 && (
                  <div>
                    <div className="mb-1 text-[11px] font-semibold text-slate-300">
                      LLDP Neighbors ({result.lldpNeighbors.length})
                    </div>
                    <Table
                      size="small"
                      pagination={false}
                      rowKey={(r, i) => `${r.localInterface}-${r.remoteChassisId}-${i}`}
                      dataSource={result.lldpNeighbors}
                      columns={[
                        { title: 'Local Intf', dataIndex: 'localInterface', width: 130 },
                        { title: 'Remote Device', dataIndex: 'remoteChassisId', width: 160 },
                        { title: 'Remote Port', dataIndex: 'remotePort' },
                      ]}
                    />
                  </div>
                )}
                {result.mroute && result.mroute.length > 0 && (
                  <div>
                    <div className="mb-1 text-[11px] font-semibold text-slate-300">
                      PIM-SM Multicast Table ({result.mroute.length})
                    </div>
                    <Table<MrouteEntry>
                      size="small"
                      pagination={false}
                      rowKey={(r, i) => `${r.source}-${r.group}-${i}`}
                      dataSource={result.mroute}
                      columns={[
                        { title: 'Source', dataIndex: 'source', width: 110 },
                        { title: 'Group', dataIndex: 'group', width: 120 },
                        { title: 'RPF Intf', dataIndex: 'rpfInterface', width: 110 },
                        { title: 'OIFs', dataIndex: 'oifList', render: (v: string[]) => v.join(', ') || 'Null' },
                      ]}
                    />
                  </div>
                )}
                {result.evpnDfState && result.evpnDfState.length > 0 && (
                  <div>
                    <div className="mb-1 text-[11px] font-semibold text-slate-300">
                      EVPN ESI DF Election ({result.evpnDfState.length})
                    </div>
                    <Table
                      size="small"
                      pagination={false}
                      rowKey={(r) => `${r.esi}-${r.interfaceName}`}
                      dataSource={result.evpnDfState}
                      columns={[
                        { title: 'ESI', dataIndex: 'esi', width: 190 },
                        { title: 'Interface', dataIndex: 'interfaceName', width: 110 },
                        {
                          title: 'Role',
                          dataIndex: 'role',
                          render: (role: string) => <Tag color={role === 'DF' ? 'green' : 'default'}>{role}</Tag>,
                        },
                      ]}
                    />
                  </div>
                )}
                {result.bmpSummary && (
                  <div className="rounded border border-slate-800 bg-[#0b1120] p-2 text-[11px] text-slate-300">
                    BMP Exporter → <span className="font-mono text-sky-300">{result.bmpSummary.serverIp}</span> • Peers: {result.bmpSummary.peerCount} • Adj-RIB-In Routes: {result.bmpSummary.adjRibInCount}
                  </div>
                )}
              </div>
            ),
          },
        ]
      : []),
    {
      key: 'config',
      label: configDirty ? 'Running Config *' : 'Running Config',
      children: (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-[11px] text-[#8e8e93]">
              Edit config directly and click <strong className="text-slate-200">Save &amp; Apply</strong> (or <kbd className="rounded bg-white/10 px-1">Ctrl+Enter</kbd>) to re-converge.
            </span>
            <Space size="small">
              {configErrors.length > 0 ? (
                <Tag color="red" className="!m-0">{configErrors.length} Error(s)</Tag>
              ) : configWarnings.length > 0 ? (
                <Tag color="gold" className="!m-0">{configWarnings.length} Warning(s)</Tag>
              ) : (
                <Tag color="green" className="!m-0">Valid Syntax</Tag>
              )}
              {configSaved && <Tag color="cyan" className="!m-0">Applied</Tag>}
              {configDirty && (
                <Button
                  size="small"
                  icon={<UndoOutlined />}
                  onClick={() => {
                    setDraftConfig(formattedConfig);
                    setConfigDirty(false);
                    setConfigError(null);
                  }}
                >
                  Reset
                </Button>
              )}
              <Button
                size="small"
                type="primary"
                icon={<SaveOutlined />}
                disabled={!configDirty || configErrors.length > 0}
                onClick={handleSaveRunningConfig}
              >
                Save &amp; Apply
              </Button>
            </Space>
          </div>
          {configError && (
            <Alert type="error" showIcon message={configError} className="!py-1 !text-xs" />
          )}
          {configIssues.length > 0 && (
            <Alert
              type={configErrors.length > 0 ? 'error' : 'warning'}
              showIcon
              className="!py-1.5 !text-xs"
              message={
                <div className="max-h-24 space-y-0.5 overflow-auto font-mono text-[11px]">
                  {configIssues.map((iss, i) => (
                    <div key={`${iss.line}-${i}`}>
                      Line {iss.line} [{iss.severity.toUpperCase()}]: {iss.message}
                    </div>
                  ))}
                </div>
              }
            />
          )}
          <Input.TextArea
            value={draftConfig}
            onChange={(e) => {
              setDraftConfig(e.target.value);
              setConfigDirty(e.target.value !== formattedConfig);
              setConfigError(null);
            }}
            onKeyDown={(e) => {
              if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && configDirty) {
                e.preventDefault();
                handleSaveRunningConfig();
              }
            }}
            autoSize={{ minRows: 14, maxRows: 30 }}
            spellCheck={false}
            className="!border-slate-700 !bg-[#0b1120] !font-mono !text-xs !leading-relaxed !text-amber-200"
          />
        </div>
      ),
    },
    {
      key: 'json',
      label: 'JSON',
      children: (
        <pre className="m-0 whitespace-pre font-mono text-xs leading-relaxed text-sky-300">
          {jsonText}
        </pre>
      ),
    },
  ];

  return (
    <div className="flex h-full flex-col bg-[#121214]">
      <div className="flex items-center justify-between border-b border-white/[0.08] bg-[#1c1c1e]/90 px-3.5 py-2 backdrop-blur-md">
        <span className="text-xs font-semibold tracking-tight text-[#f5f5f7]">
          Routing &amp; CLI Diagnostics <span className="text-[#8e8e93]">—</span>{' '}
          <span className="text-[#0a84ff]">{node.hostname}</span>
        </span>
        <Space size="small">
          {headerExtra}
          <Button
            size="small"
            icon={copied ? <CheckOutlined /> : <CopyOutlined />}
            onClick={handleCopy}
          >
            {copied ? 'Copied' : 'Copy'}
          </Button>
          <Button
            size="small"
            icon={<DownloadOutlined />}
            onClick={() =>
              downloadFile(`${node.hostname}-route.txt`, primaryText, 'text/plain')
            }
          >
            .txt
          </Button>
          <Button
            size="small"
            icon={<DownloadOutlined />}
            onClick={() =>
              downloadFile(`${node.hostname}-running-config.cfg`, runningConfigText, 'text/plain')
            }
          >
            .cfg
          </Button>
          <Button
            size="small"
            icon={<DownloadOutlined />}
            onClick={() =>
              downloadFile(`${node.hostname}-rib.json`, jsonText, 'application/json')
            }
          >
            .json
          </Button>
        </Space>
      </div>

      <div className="flex-1 overflow-auto px-3 pb-3">
        <Tabs
          size="small"
          activeKey={effectiveActiveKey}
          onChange={setActiveKey}
          items={tabItems}
        />
      </div>
    </div>
  );
};
