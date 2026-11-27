import React, { useCallback, useMemo, useRef, useState } from 'react';
import {
  Background,
  BackgroundVariant,
  Connection,
  ConnectionMode,
  Controls,
  Edge,
  EdgeLabelRenderer,
  EdgeProps,
  getBezierPath,
  Handle,
  InternalNode,
  Node,
  type OnNodesChange,
  NodeProps,
  Position,
  ReactFlow,
  type ReactFlowInstance,
  useInternalNode,
  useViewport,
} from '@xyflow/react';
import { Input, InputNumber, Modal, Select } from 'antd';
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  Globe,
  Lock,
  Router,
  Shield,
  XCircle,
} from 'lucide-react';
import { parseCidr } from '../engine/ipMath';
import { VENDOR_METADATA } from '../engine/vendorProfiles';
import { useSimStore } from '../store/useSimStore';
import { NodeConfig } from '../types/network';

interface DeviceNodeData extends Record<string, unknown> {
  node: NodeConfig;
  activeRouteCount: number;
  selected: boolean;
  traceState: 'none' | 'hop' | 'delivered' | 'dropped' | 'loop' | 'blocked';
  traceVrf?: string;
}

const DeviceNode: React.FC<NodeProps<Node<DeviceNodeData>>> = ({ data }) => {
  const { node, activeRouteCount, selected, traceState, traceVrf } = data;
  const themeMode = useSimStore((s) => s.themeMode);
  const vrfColors = useSimStore((s) => s.topology.vrfColors);
  const protocolOverlay = useSimStore((s) => s.protocolOverlay);
  const stpState = useSimStore((s) => s.simResult.nodes[node.id]?.stpState);
  const traceVrfColor =
    traceVrf && (traceState === 'hop' || traceState === 'delivered')
      ? vrfColors?.[traceVrf]
      : undefined;
  const meta = VENDOR_METADATA[node.vendor] ?? VENDOR_METADATA['cisco-ios-xe'];
  const isFirewall =
    node.vendor === 'pan-os' ||
    node.vendor === 'forcepoint-ngfw' ||
    node.vendor === 'fortigate' ||
    node.vendor === 'checkpoint-gaia';
  const isCloud = meta.category === 'cloud';

  const ringClass =
    traceState === 'delivered'
      ? 'ring-2 ring-emerald-400 border-emerald-400 shadow-lg shadow-emerald-500/20'
      : traceState === 'dropped' || traceState === 'loop' || traceState === 'blocked'
        ? 'ring-2 ring-rose-500 border-rose-500 bg-rose-950/60 shadow-lg shadow-rose-500/30'
        : traceState === 'hop'
          ? 'ring-2 ring-amber-400 border-amber-400 shadow-lg shadow-amber-500/20'
          : selected
            ? 'ring-2 ring-cyan-400 border-cyan-400 shadow-lg shadow-cyan-500/15'
            : isCloud
              ? 'border-dashed border-sky-500/50 hover:border-sky-400'
              : 'border-slate-700/80 hover:border-slate-500';

  const cloudStroke =
    traceState === 'dropped' || traceState === 'loop' || traceState === 'blocked'
      ? '#f43f5e'
      : traceVrfColor
        ? traceVrfColor
        : traceState === 'delivered'
          ? '#34d399'
          : traceState === 'hop'
            ? '#fbbf24'
            : selected
              ? '#22d3ee'
              : 'rgba(56, 189, 248, 0.7)';

  const cloudFill =
    traceState === 'blocked' || traceState === 'dropped' || traceState === 'loop'
      ? themeMode === 'light'
        ? 'rgba(255, 235, 238, 0.96)'
        : 'rgba(76, 5, 25, 0.78)'
      : themeMode === 'light'
        ? 'rgba(255, 255, 255, 0.95)'
        : 'rgba(15, 23, 42, 0.92)';

  return (
    <div
      style={
        !isCloud && traceVrfColor
          ? {
            borderColor: traceVrfColor,
            boxShadow: `0 0 0 2px ${traceVrfColor}, 0 10px 15px -3px ${traceVrfColor}38`,
          }
          : undefined
      }
      className={
        `${node.adminDown ? 'opacity-55 ' : ''}` +
        (isCloud
          ? 'relative min-w-[275px] px-9 pt-8 pb-5 text-slate-100 transition-all'
          : `min-w-[205px] rounded-xl border px-3.5 py-2.5 text-slate-100 backdrop-blur transition-all ${traceState === 'blocked' || traceState === 'dropped' || traceState === 'loop'
            ? ''
            : 'bg-slate-900/95'
          } ${ringClass}`)
      }
    >
      {isCloud && (
        <svg
          viewBox="0 0 280 150"
          preserveAspectRatio="none"
          className="pointer-events-none absolute inset-0 h-full w-full overflow-visible drop-shadow-lg"
        >
          <path
            d="M 46 138 C 14 138, 6 112, 16 86 C 8 54, 30 28, 66 34 C 78 10, 118 6, 142 20 C 168 6, 208 14, 218 36 C 252 32, 272 56, 264 86 C 274 112, 264 138, 232 138 Q 186 145, 140 138 Q 92 145, 46 138 Z"
            fill={cloudFill}
            stroke={cloudStroke}
            strokeWidth={selected || traceState !== 'none' ? 2.5 : 2}
            vectorEffect="non-scaling-stroke"
          />
        </svg>
      )}
      <Handle id="top" type="source" position={Position.Top} className="!h-2.5 !w-2.5 !bg-cyan-400" />
      <Handle id="right" type="source" position={Position.Right} className="!h-2.5 !w-2.5 !bg-cyan-400" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!h-2.5 !w-2.5 !bg-cyan-400" />
      <Handle id="left" type="source" position={Position.Left} className="!h-2.5 !w-2.5 !bg-cyan-400" />

      <div className="relative z-10">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            {node.vendor === 'internet-cloud' ? (
              <Globe className="h-4 w-4 text-cyan-400" />
            ) : isCloud ? (
              <Cloud className="h-4 w-4 text-sky-400" />
            ) : isFirewall ? (
              <Shield className="h-4 w-4 text-orange-400" />
            ) : (
              <Router className="h-4 w-4 text-cyan-400" />
            )}
            <span className="text-xs font-bold tracking-tight">{node.hostname}</span>
          </div>
          <span
            className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${meta.badgeClass}`}
          >
            {meta.shortLabel}
          </span>
        </div>

        <div className="mt-1.5 flex items-center justify-between text-[11px] text-slate-400">
          <span className="font-mono">RID {node.routerId}</span>
          <span className="font-mono text-slate-300">{activeRouteCount} RIB</span>
        </div>

        <div className="mt-2 flex flex-wrap gap-1">
          {(node.vrfs?.length ? node.vrfs : ['default']).map((vrf) => {
            const customColor = vrfColors?.[vrf];
            return (
              <span
                key={vrf}
                style={
                  customColor
                    ? {
                      backgroundColor: `${customColor}24`,
                      borderColor: `${customColor}66`,
                      color: customColor,
                    }
                    : undefined
                }
                className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] ${customColor
                    ? 'border'
                    : vrf === 'default'
                      ? 'bg-slate-800 text-slate-300'
                      : 'bg-cyan-500/15 text-cyan-300'
                  }`}
              >
                {customColor && (
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ backgroundColor: customColor }}
                  />
                )}
                vr:{vrf}
              </span>
            );
          })}
          {node.ospf.enabled && (
            <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] text-emerald-300">
              OSPF
            </span>
          )}
          {node.bgp.enabled && (
            <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-[10px] text-violet-300">
              AS {node.bgp.asn}
            </span>
          )}
          {protocolOverlay === 'ospf-area' && node.ospf.enabled && (
            <span className="rounded bg-emerald-600/30 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-200">
              Areas: {Array.from(new Set(node.interfaces.filter((i) => i.ospfArea !== undefined).map((i) => i.ospfArea))).join(',') || '0'}
            </span>
          )}
          {protocolOverlay === 'bgp-asn' && node.bgp.enabled && (
            <span className="rounded bg-violet-600/30 px-1.5 py-0.5 text-[10px] font-semibold text-violet-200">
              {node.bgp.confederationId ? `Confed ${node.bgp.confederationId}` : `BGP ${node.bgp.asn}`}
            </span>
          )}
          {protocolOverlay === 'stp' && stpState && (
            <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${stpState.isRoot ? 'bg-amber-500/30 text-amber-200' : 'bg-sky-500/25 text-sky-200'}`}>
              {stpState.isRoot ? 'STP ROOT' : stpState.ports.some((p) => p.state === 'Blocking') ? 'STP BLK' : 'STP FWD'}
            </span>
          )}
          {node.adminDown && (
            <span className="rounded bg-rose-600 px-1.5 py-0.5 text-[10px] font-bold uppercase text-white">
              DOWN
            </span>
          )}
          {(traceState === 'blocked' || traceState === 'dropped' || traceState === 'loop') && (
            <span className="rounded bg-rose-500 px-1.5 py-0.5 text-[10px] font-bold uppercase text-white">
              {traceState}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

interface SubnetEdgeData extends Record<string, unknown> {
  label: string;
  sublabel: string;
  traced: boolean;
  returnTraced?: boolean;
  returnReverse?: boolean;
  returnHopIndex?: number;
  returnBlocked?: boolean;
  isIpsec?: boolean;
  isLayer2?: boolean;
  adminDown?: boolean;
  onToggleDown?: () => void;
  onEditLink?: () => void;
  traceReverse?: boolean;
  traceHopIndex?: number;
  traceBlocked?: boolean;
  labelOffsetX?: number;
  labelOffsetY?: number;
  sourceSide?: 'top' | 'right' | 'bottom' | 'left';
  targetSide?: 'top' | 'right' | 'bottom' | 'left';
  controlPointOffset?: { dx: number; dy: number };
  onChangeControlPoint?: (offset: { dx: number; dy: number } | undefined) => void;
  highlighted?: boolean;
  dimmed?: boolean;
  vrfName?: string;
  vrfColor?: string;
  traceVrfColor?: string;
}

type HandleSide = 'top' | 'right' | 'bottom' | 'left';

function getSideAnchor(
  abs: { x: number; y: number },
  w: number,
  h: number,
  side: HandleSide
): { x: number; y: number; pos: Position } {
  switch (side) {
    case 'top':
      return { x: abs.x + w / 2, y: abs.y, pos: Position.Top };
    case 'right':
      return { x: abs.x + w, y: abs.y + h / 2, pos: Position.Right };
    case 'bottom':
      return { x: abs.x + w / 2, y: abs.y + h, pos: Position.Bottom };
    case 'left':
      return { x: abs.x, y: abs.y + h / 2, pos: Position.Left };
  }
}

function getFloatingEdgeParams(
  src: InternalNode,
  dst: InternalNode,
  sourceSide?: HandleSide,
  targetSide?: HandleSide
): {
  sx: number;
  sy: number;
  tx: number;
  ty: number;
  sPos: Position;
  tPos: Position;
} {
  const sw = src.measured.width ?? 210;
  const sh = src.measured.height ?? 100;
  const dw = dst.measured.width ?? 210;
  const dh = dst.measured.height ?? 100;

  const sAbs = src.internals.positionAbsolute;
  const dAbs = dst.internals.positionAbsolute;

  const scx = sAbs.x + sw / 2;
  const scy = sAbs.y + sh / 2;
  const dcx = dAbs.x + dw / 2;
  const dcy = dAbs.y + dh / 2;

  const dx = dcx - scx;
  const dy = dcy - scy;
  const horizRatio = Math.abs(dx) / Math.max((sw + dw) / 2, 1);
  const vertRatio = Math.abs(dy) / Math.max((sh + dh) / 2, 1);

  let autoSrc: HandleSide;
  let autoDst: HandleSide;
  if (horizRatio >= vertRatio) {
    autoSrc = dx >= 0 ? 'right' : 'left';
    autoDst = dx >= 0 ? 'left' : 'right';
  } else {
    autoSrc = dy >= 0 ? 'bottom' : 'top';
    autoDst = dy >= 0 ? 'top' : 'bottom';
  }

  const sAnchor = getSideAnchor(sAbs, sw, sh, sourceSide ?? autoSrc);
  const tAnchor = getSideAnchor(dAbs, dw, dh, targetSide ?? autoDst);
  return {
    sx: sAnchor.x,
    sy: sAnchor.y,
    tx: tAnchor.x,
    ty: tAnchor.y,
    sPos: sAnchor.pos,
    tPos: tAnchor.pos,
  };
}

const SubnetEdge: React.FC<EdgeProps<Edge<SubnetEdgeData>>> = ({
  id,
  source,
  target,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
}) => {
  const srcNode = useInternalNode(source);
  const dstNode = useInternalNode(target);
  const { zoom } = useViewport();
  const [dragOffset, setDragOffset] = useState<{ dx: number; dy: number } | null>(null);
  const floating =
    srcNode && dstNode
      ? getFloatingEdgeParams(srcNode, dstNode, data?.sourceSide, data?.targetSide)
      : null;

  const sx = floating?.sx ?? sourceX;
  const sy = floating?.sy ?? sourceY;
  const tx = floating?.tx ?? targetX;
  const ty = floating?.ty ?? targetY;

  const [bezierPath, rawLabelX, rawLabelY] = getBezierPath({
    sourceX: sx,
    sourceY: sy,
    sourcePosition: floating?.sPos ?? sourcePosition,
    targetX: tx,
    targetY: ty,
    targetPosition: floating?.tPos ?? targetPosition,
  });

  const manualOffset = dragOffset ?? data?.controlPointOffset;
  const labelX = rawLabelX + (manualOffset ? manualOffset.dx : (data?.labelOffsetX ?? 0));
  const labelY = rawLabelY + (manualOffset ? manualOffset.dy : (data?.labelOffsetY ?? 0));
  const edgePath = manualOffset
    ? `M ${sx},${sy} Q ${2 * labelX - 0.5 * (sx + tx)},${2 * labelY - 0.5 * (sy + ty)} ${tx},${ty}`
    : bezierPath;

  const traced = data?.traced ?? false;
  const isIpsec = data?.isIpsec ?? false;
  const isLayer2 = data?.isLayer2 ?? false;
  const adminDown = data?.adminDown ?? false;
  const reverse = data?.traceReverse ?? false;
  const hopIdx = data?.traceHopIndex ?? 0;
  const blocked = data?.traceBlocked ?? false;
  const returnTraced = data?.returnTraced ?? false;
  const returnReverse = data?.returnReverse ?? false;
  const returnHopIdx = data?.returnHopIndex ?? 0;
  const returnBlocked = data?.returnBlocked ?? false;
  const returnDotColor = returnBlocked ? '#f43f5e' : '#06b6d4';
  const highlighted = data?.highlighted ?? false;
  const dimmed = data?.dimmed ?? false;
  const vrfColor = data?.vrfColor;
  const traceVrfColor = data?.traceVrfColor;
  const dotColor = blocked ? '#f43f5e' : (traceVrfColor ?? '#38bdf8');

  return (
    <>
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={18}
        className="react-flow__edge-interaction"
      />
      <path
        id={id}
        d={edgePath}
        fill="none"
        stroke={
          adminDown
            ? '#f43f5e'
            : traced
              ? blocked
                ? '#f43f5e'
                : (traceVrfColor ?? '#f59e0b')
              : returnTraced
                ? '#06b6d4'
                : highlighted
                  ? '#22d3ee'
                  : vrfColor
                    ? vrfColor
                    : isIpsec
                      ? '#818cf8'
                      : isLayer2
                        ? '#14b8a6'
                        : '#475569'
        }
        strokeWidth={traced || returnTraced ? 3 : highlighted ? 2.75 : isIpsec ? 2.25 : 1.75}
        strokeDasharray={adminDown ? '4 4' : traced ? '6 4' : returnTraced ? '3 3' : isIpsec ? '8 4' : isLayer2 ? '5 3' : undefined}
        className={traced && !adminDown ? 'animate-pulse' : ''}
        opacity={adminDown ? (dimmed ? 0.25 : 0.65) : dimmed && !traced && !returnTraced ? 0.22 : 1}
      />
      {traced && (
        <>
          <circle r="8" fill={dotColor} opacity="0.28">
            <animateMotion
              dur="1.4s"
              begin={`${(hopIdx * 0.45).toFixed(2)}s`}
              repeatCount="indefinite"
              path={edgePath}
              keyPoints={reverse ? '1;0' : '0;1'}
              keyTimes="0;1"
              calcMode="linear"
            />
          </circle>
          <circle r="4.5" fill={dotColor} stroke="#0f172a" strokeWidth="1.5">
            <animateMotion
              dur="1.4s"
              begin={`${(hopIdx * 0.45).toFixed(2)}s`}
              repeatCount="indefinite"
              path={edgePath}
              keyPoints={reverse ? '1;0' : '0;1'}
              keyTimes="0;1"
              calcMode="linear"
            />
          </circle>
        </>
      )}
      {returnTraced && (
        <>
          <circle r="7" fill={returnDotColor} opacity="0.25">
            <animateMotion
              dur="1.4s"
              begin={`${(returnHopIdx * 0.45 + 0.25).toFixed(2)}s`}
              repeatCount="indefinite"
              path={edgePath}
              keyPoints={returnReverse ? '1;0' : '0;1'}
              keyTimes="0;1"
              calcMode="linear"
            />
          </circle>
          <circle r="4" fill={returnDotColor} stroke="#0f172a" strokeWidth="1.5">
            <animateMotion
              dur="1.4s"
              begin={`${(returnHopIdx * 0.45 + 0.25).toFixed(2)}s`}
              repeatCount="indefinite"
              path={edgePath}
              keyPoints={returnReverse ? '1;0' : '0;1'}
              keyTimes="0;1"
              calcMode="linear"
            />
          </circle>
        </>
      )}
      <EdgeLabelRenderer>
        <div
          style={{
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            ...(traced && !blocked && traceVrfColor
              ? { borderColor: traceVrfColor, boxShadow: `0 0 0 1px ${traceVrfColor}66` }
              : vrfColor && !adminDown && !traced && !highlighted
                ? { borderColor: `${vrfColor}88` }
                : {}),
          }}
          title="Drag to move link curve • Double-click to reset"
          onMouseDown={(e) => {
            if (!(e.target as HTMLElement).closest('button')) e.stopPropagation();
          }}
          onPointerDown={(e) => {
            if (e.button !== 0 || (e.target as HTMLElement).closest('button')) return;
            e.preventDefault();
            e.stopPropagation();
            const startX = e.clientX;
            const startY = e.clientY;
            const base = data?.controlPointOffset ?? {
              dx: data?.labelOffsetX ?? 0,
              dy: data?.labelOffsetY ?? 0,
            };
            let latest = base;
            const onMove = (ev: PointerEvent) => {
              latest = {
                dx: Math.round(base.dx + (ev.clientX - startX) / Math.max(zoom, 0.1)),
                dy: Math.round(base.dy + (ev.clientY - startY) / Math.max(zoom, 0.1)),
              };
              setDragOffset(latest);
            };
            const onUp = () => {
              window.removeEventListener('pointermove', onMove);
              window.removeEventListener('pointerup', onUp);
              setDragOffset(null);
              if (latest.dx !== base.dx || latest.dy !== base.dy) {
                data?.onChangeControlPoint?.(latest);
              }
            };
            window.addEventListener('pointermove', onMove);
            window.addEventListener('pointerup', onUp);
          }}
          onDoubleClick={(e) => {
            e.stopPropagation();
            data?.onChangeControlPoint?.(undefined);
          }}
          className={`nodrag nopan pointer-events-auto absolute cursor-grab rounded border px-1.5 py-0.5 text-center font-mono text-[10px] shadow select-none hover:z-50 active:cursor-grabbing ${dimmed && !traced && !returnTraced ? 'opacity-35 ' : ''
            }${adminDown
              ? 'border-rose-500/70 bg-rose-950/90 text-rose-200'
              : traced
                ? 'border-amber-500/60 bg-amber-950/90 text-amber-200'
                : highlighted
                  ? 'z-30 border-cyan-400/80 bg-slate-900/95 text-cyan-100 ring-1 ring-cyan-400/35'
                  : isIpsec
                    ? 'border-indigo-500/50 bg-indigo-950/90 text-indigo-200'
                    : 'border-slate-700 bg-slate-900/90 text-slate-300'
            }`}
        >
          <div className="flex items-center justify-center gap-1 font-semibold">
            {vrfColor && (
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: vrfColor }}
                title={data?.vrfName ? `VRF ${data.vrfName}` : undefined}
              />
            )}
            {isIpsec && <Lock className="h-2.5 w-2.5 text-indigo-300" />}
            {data?.label}
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                data?.onToggleDown?.();
              }}
              title="Toggle Link Up / Down"
              className={`ml-1 rounded px-1 text-[8px] font-bold uppercase ${adminDown
                ? 'bg-rose-500 text-white'
                : 'bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/35'
                }`}
            >
              {adminDown ? 'DOWN' : 'UP'}
            </button>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                data?.onEditLink?.();
              }}
              title="Edit Link / IPsec Underlay"
              className="rounded bg-slate-700/80 px-1 text-[8px] font-semibold text-slate-200 hover:bg-slate-600"
            >
              Edit
            </button>
          </div>
          {data?.sublabel && (
            <div className="text-[9px] text-slate-400">{data.sublabel}</div>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
};

const nodeTypes = { device: DeviceNode };
const edgeTypes = { subnet: SubnetEdge };

export const TopologyCanvas: React.FC = () => {
  const {
    topology,
    simResult,
    selectedNodeId,
    traceResult,
    selectNode,
    updateNodePosition,
    addLink,
    updateLink,
    deleteSelection,
    themeMode,
  } = useSimStore();

  const [pendingLink, setPendingLink] = useState<{
    sourceNodeId: string;
    targetNodeId: string;
    sourceInterfaceId: string;
    targetInterfaceId: string;
    linkType: 'ethernet' | 'ipsec' | 'layer2';
  } | null>(null);
  const [editingLinkId, setEditingLinkId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  const tracedNodeStatus = useMemo(() => {
    const map = new Map<string, 'hop' | 'delivered' | 'dropped' | 'loop' | 'blocked'>();
    if (!traceResult) return map;
    for (const h of traceResult.hops) {
      map.set(h.nodeId, h.status === 'forwarded' ? 'hop' : h.status);
    }
    return map;
  }, [traceResult]);

  const tracedNodeVrf = useMemo(() => {
    const map = new Map<string, string>();
    if (!traceResult) return map;
    for (const h of traceResult.hops) {
      map.set(h.nodeId, h.vrf);
    }
    return map;
  }, [traceResult]);

  const tracedEdgeMap = useMemo(() => {
    const map = new Map<
      string,
      { reverse: boolean; hopIndex: number; blocked: boolean; vrf: string; egressIf?: string }[]
    >();
    if (!traceResult) return map;
    for (let i = 0; i < traceResult.hops.length - 1; i++) {
      const a = traceResult.hops[i].nodeId;
      const b = traceResult.hops[i + 1].nodeId;
      const hopVrf = traceResult.hops[i].vrf;
      const egressIf = traceResult.hops[i].egressInterface;
      const nextStatus = traceResult.hops[i + 1].status;
      const isBlocked =
        nextStatus === 'blocked' || nextStatus === 'dropped' || nextStatus === 'loop';
      const fwd = map.get(`${a}->${b}`) ?? [];
      fwd.push({ reverse: false, hopIndex: i, blocked: isBlocked, vrf: hopVrf, egressIf });
      map.set(`${a}->${b}`, fwd);
      const rev = map.get(`${b}->${a}`) ?? [];
      rev.push({ reverse: true, hopIndex: i, blocked: isBlocked, vrf: hopVrf, egressIf });
      map.set(`${b}->${a}`, rev);
    }
    return map;
  }, [traceResult]);

  const returnEdgeMap = useMemo(() => {
    const map = new Map<
      string,
      { reverse: boolean; hopIndex: number; blocked: boolean; egressIf?: string }[]
    >();
    const hops = traceResult?.returnTrace?.hops ?? [];
    for (let i = 0; i < hops.length - 1; i++) {
      const a = hops[i].nodeId;
      const b = hops[i + 1].nodeId;
      const egressIf = hops[i].egressInterface;
      const nextStatus = hops[i + 1].status;
      const isBlocked =
        nextStatus === 'blocked' || nextStatus === 'dropped' || nextStatus === 'loop';
      const fwd = map.get(`${a}->${b}`) ?? [];
      fwd.push({ reverse: false, hopIndex: i, blocked: isBlocked, egressIf });
      map.set(`${a}->${b}`, fwd);
      const rev = map.get(`${b}->${a}`) ?? [];
      rev.push({ reverse: true, hopIndex: i, blocked: isBlocked, egressIf });
      map.set(`${b}->${a}`, rev);
    }
    return map;
  }, [traceResult]);

  const flowNodes: Node<DeviceNodeData>[] = useMemo(
    () =>
      topology.nodes.map((n) => ({
        id: n.id,
        type: 'device',
        position: n.position,
        selected: n.id === selectedNodeId,
        data: {
          node: n,
          activeRouteCount:
            simResult.nodes[n.id]?.rib.filter((r) => r.active).length ?? 0,
          selected: n.id === selectedNodeId,
          traceState: tracedNodeStatus.get(n.id) ?? 'none',
          traceVrf: tracedNodeVrf.get(n.id),
        },
      })),
    [topology.nodes, simResult.nodes, selectedNodeId, tracedNodeStatus, tracedNodeVrf]
  );

  const flowEdges: Edge<SubnetEdgeData>[] = useMemo(() => {
    const nodeById = new Map(topology.nodes.map((n) => [n.id, n]));
    const pairCounts = new Map<string, number>();
    const pairSeen = new Map<string, number>();
    for (const l of topology.links) {
      const key = [l.sourceNodeId, l.targetNodeId].sort().join('|');
      pairCounts.set(key, (pairCounts.get(key) ?? 0) + 1);
    }

    const anchors = topology.links.map((l) => {
      const s = nodeById.get(l.sourceNodeId);
      const d = nodeById.get(l.targetNodeId);
      const sx = (s?.position.x ?? 0) + 105;
      const sy = (s?.position.y ?? 0) + 45;
      const dx = (d?.position.x ?? 0) + 105;
      const dy = (d?.position.y ?? 0) + 45;
      const key = [l.sourceNodeId, l.targetNodeId].sort().join('|');
      const count = pairCounts.get(key) ?? 1;
      const idx = pairSeen.get(key) ?? 0;
      pairSeen.set(key, idx + 1);
      const spread = count > 1 ? (idx - (count - 1) / 2) * 46 : 0;
      const len = Math.hypot(dx - sx, dy - sy) || 1;
      const nx = -(dy - sy) / len;
      const ny = (dx - sx) / len;
      const rawX = (sx + dx) / 2;
      const rawY = (sy + dy) / 2;
      const mx = rawX + nx * spread;
      const my = rawY + ny * spread;
      return { id: l.id, origX: rawX, origY: rawY, x: mx, y: my };
    });

    const boxW = 195;
    const boxH = 44;
    const nodeBoxes = topology.nodes.map((n) => {
      const isCloud = (VENDOR_METADATA[n.vendor]?.category ?? 'appliance') === 'cloud';
      const w = isCloud ? 280 : 215;
      const h = isCloud ? 150 : 100;
      return {
        cx: n.position.x + w / 2,
        cy: n.position.y + h / 2,
        halfW: (w + boxW) / 2 + 8,
        halfH: (h + boxH) / 2 + 8,
      };
    });

    for (let iter = 0; iter < 28; iter++) {
      let moved = false;
      for (let i = 0; i < anchors.length; i++) {
        for (let j = i + 1; j < anchors.length; j++) {
          const a = anchors[i];
          const b = anchors[j];
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const ox = boxW - Math.abs(dx);
          const oy = boxH - Math.abs(dy);
          if (ox > 0 && oy > 0) {
            moved = true;
            if (oy <= ox * 0.65) {
              const sign = dy === 0 ? (i % 2 === 0 ? 1 : -1) : Math.sign(dy);
              const push = oy * 0.52;
              a.y -= sign * push;
              b.y += sign * push;
            } else {
              const sign = dx === 0 ? (i % 2 === 0 ? 1 : -1) : Math.sign(dx);
              const push = ox * 0.52;
              a.x -= sign * push;
              b.x += sign * push;
            }
          }
        }
      }
      for (let i = 0; i < anchors.length; i++) {
        const a = anchors[i];
        for (const nb of nodeBoxes) {
          const dx = a.x - nb.cx;
          const dy = a.y - nb.cy;
          const ox = nb.halfW - Math.abs(dx);
          const oy = nb.halfH - Math.abs(dy);
          if (ox > 0 && oy > 0) {
            moved = true;
            if (oy <= ox) {
              a.y += (dy >= 0 ? 1 : -1) * (oy + 2);
            } else {
              a.x += (dx >= 0 ? 1 : -1) * (ox + 2);
            }
          }
        }
        a.x = Math.max(a.origX - 220, Math.min(a.origX + 220, a.x));
        a.y = Math.max(a.origY - 220, Math.min(a.origY + 220, a.y));
      }
      if (!moved) break;
    }

    const offsetMap = new Map(
      anchors.map((a) => [a.id, { dx: Math.round(a.x - a.origX), dy: Math.round(a.y - a.origY) }])
    );

    return topology.links.map((l) => {
      const src = nodeById.get(l.sourceNodeId);
      const dst = nodeById.get(l.targetNodeId);
      const srcIf = src?.interfaces.find((i) => i.id === l.sourceInterfaceId);
      const dstIf = dst?.interfaces.find((i) => i.id === l.targetInterfaceId);
      const parsed = srcIf ? parseCidr(srcIf.cidr) : null;
      const subnetLabel = parsed ? `${parsed.network}/${parsed.prefixLen}` : 'link';
      const costInfo =
        srcIf?.ospfArea !== undefined ? ` • OSPF A${srcIf.ospfArea}` : '';

      const matchesHopIface = (
        seg: { reverse: boolean; egressIf?: string },
        sIf?: typeof srcIf,
        dIf?: typeof dstIf
      ): boolean => {
        if (!seg.egressIf) return true;
        const linkIf = seg.reverse ? dIf?.name : sIf?.name;
        if (!linkIf) return false;
        const h = seg.egressIf.toLowerCase();
        const lf = linkIf.toLowerCase();
        return h === lf || h.startsWith(`${lf}.`);
      };
      const pickMatchingEdge = <T extends { reverse: boolean; egressIf?: string }>(
        candidates: T[] | undefined
      ): T | undefined => {
        if (l.adminDown || !candidates || candidates.length === 0) return undefined;
        const exact = candidates.find((seg) => matchesHopIface(seg, srcIf, dstIf));
        if (exact) return exact;
        // Fallback for virtual/LAG egress interfaces (e.g. Port-Channel) when no physical link name matches
        const anyPeerLinkMatches = topology.links.some((other) => {
          if (other.adminDown) return false;
          const samePair =
            (other.sourceNodeId === l.sourceNodeId && other.targetNodeId === l.targetNodeId) ||
            (other.sourceNodeId === l.targetNodeId && other.targetNodeId === l.sourceNodeId);
          if (!samePair) return false;
          const oSrc = nodeById.get(other.sourceNodeId)?.interfaces.find((i) => i.id === other.sourceInterfaceId);
          const oDst = nodeById.get(other.targetNodeId)?.interfaces.find((i) => i.id === other.targetInterfaceId);
          const flipped = other.sourceNodeId !== l.sourceNodeId;
          return candidates.some((seg) =>
            matchesHopIface(
              flipped ? { ...seg, reverse: !seg.reverse } : seg,
              oSrc,
              oDst
            )
          );
        });
        return anyPeerLinkMatches ? undefined : candidates[0];
      };
      const traceEdge = pickMatchingEdge(tracedEdgeMap.get(`${l.sourceNodeId}->${l.targetNodeId}`));
      const retEdge = pickMatchingEdge(returnEdgeMap.get(`${l.sourceNodeId}->${l.targetNodeId}`));

      const isIpsec = l.linkType === 'ipsec';
      const isLayer2 = l.linkType === 'layer2';
      const tunnelInfo = isIpsec
        ? ` • IPsec ${l.ipsecConfig?.ikeVersion ?? 'IKEv2'}`
        : isLayer2
          ? ` • L2 ${l.l2Mode === 'access' ? `Access${l.vlanId ? ` V${l.vlanId}` : ''}` : `Trunk${l.allowedVlans ? ` (${l.allowedVlans})` : ''}`}`
          : '';

      const impParts = [
        l.latencyMs ? `${l.latencyMs}ms` : '',
        l.jitterMs ? `±${l.jitterMs}ms` : '',
        l.lossPct ? `${l.lossPct}% loss` : '',
      ].filter(Boolean);
      const impInfo = impParts.length ? ` • ${impParts.join(' / ')}` : '';

      const off = offsetMap.get(l.id);
      const linkVrf =
        (srcIf?.vrf && srcIf.vrf !== 'default' ? srcIf.vrf : dstIf?.vrf) || 'default';
      const linkVrfColor = topology.vrfColors?.[linkVrf];
      const isConnectedToSelected = Boolean(
        selectedNodeId && (l.sourceNodeId === selectedNodeId || l.targetNodeId === selectedNodeId)
      );
      const isDimmed = Boolean(selectedNodeId && !isConnectedToSelected);
      return {
        id: l.id,
        source: l.sourceNodeId,
        target: l.targetNodeId,
        type: 'subnet',
        selected: l.id === selectedEdgeId,
        zIndex: isConnectedToSelected || l.id === selectedEdgeId ? 10 : 0,
        data: {
          label:
            subnetLabel === 'link' && isLayer2
              ? `L2 ${l.l2Mode === 'access' ? 'Access' : 'Trunk'}${l.vlanId ? ` V${l.vlanId}` : ''}`
              : subnetLabel,
          sublabel: `${srcIf?.name ?? '?'} ↔ ${dstIf?.name ?? '?'}${costInfo}${tunnelInfo}${impInfo}`,
          traced: Boolean(traceEdge),
          returnTraced: Boolean(retEdge),
          returnReverse: retEdge?.reverse ?? false,
          returnHopIndex: retEdge?.hopIndex ?? 0,
          returnBlocked: retEdge?.blocked ?? false,
          isIpsec,
          isLayer2,
          adminDown: Boolean(l.adminDown),
          onToggleDown: () => updateLink(l.id, { adminDown: !l.adminDown }),
          onEditLink: () => setEditingLinkId(l.id),
          traceReverse: traceEdge?.reverse ?? false,
          traceHopIndex: traceEdge?.hopIndex ?? 0,
          traceBlocked: traceEdge?.blocked ?? false,
          labelOffsetX: off?.dx ?? 0,
          labelOffsetY: off?.dy ?? 0,
          sourceSide: l.sourceHandle,
          targetSide: l.targetHandle,
          controlPointOffset: l.controlPointOffset,
          onChangeControlPoint: (offset) => updateLink(l.id, { controlPointOffset: offset }),
          highlighted: isConnectedToSelected || l.id === selectedEdgeId,
          dimmed: isDimmed && l.id !== selectedEdgeId,
          vrfName: linkVrf,
          vrfColor: linkVrfColor,
          traceVrfColor: traceEdge?.vrf ? topology.vrfColors?.[traceEdge.vrf] : undefined,
        },
      };
    });
  }, [topology.links, topology.nodes, topology.vrfColors, tracedEdgeMap, returnEdgeMap, updateLink, selectedNodeId, selectedEdgeId]);

  const handleNodesChange: OnNodesChange<Node<DeviceNodeData>> = (changes) => {
    for (const c of changes) {
      if (c.type === 'position' && c.position) {
        updateNodePosition(c.id, c.position);
      }
    }
  };

  const handleConnect = (connection: Connection) => {
    if (!connection.source || !connection.target || connection.source === connection.target) {
      return;
    }
    const srcNode = topology.nodes.find((n) => n.id === connection.source);
    const dstNode = topology.nodes.find((n) => n.id === connection.target);
    if (!srcNode?.interfaces.length || !dstNode?.interfaces.length) return;

    const usedIfIds = new Set(
      topology.links.flatMap((l) => [l.sourceInterfaceId, l.targetInterfaceId])
    );
    const freeSrcIf =
      srcNode.interfaces.find((i) => !usedIfIds.has(i.id)) ?? srcNode.interfaces[0];
    const freeDstIf =
      dstNode.interfaces.find((i) => !usedIfIds.has(i.id)) ?? dstNode.interfaces[0];

    setPendingLink({
      sourceNodeId: srcNode.id,
      targetNodeId: dstNode.id,
      sourceInterfaceId: freeSrcIf.id,
      targetInterfaceId: freeDstIf.id,
      linkType: 'ethernet',
    });
  };

  const pendingSrcNode = pendingLink
    ? topology.nodes.find((n) => n.id === pendingLink.sourceNodeId)
    : null;
  const pendingDstNode = pendingLink
    ? topology.nodes.find((n) => n.id === pendingLink.targetNodeId)
    : null;

  const setViewportCenter = useSimStore((s) => s.setViewportCenter);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const rfInstanceRef = useRef<ReactFlowInstance<Node<DeviceNodeData>, Edge<SubnetEdgeData>> | null>(null);

  const syncViewportCenter = useCallback(() => {
    const rf = rfInstanceRef.current;
    const el = wrapperRef.current;
    if (!rf || !el) return;
    const rect = el.getBoundingClientRect();
    const center = rf.screenToFlowPosition({
      x: rect.left + rect.width / 2,
      y: rect.top + rect.height / 2,
    });
    setViewportCenter(center);
  }, [setViewportCenter]);

  return (
    <div
      ref={wrapperRef}
      className={`relative h-full w-full ${themeMode === 'light' ? 'bg-[#f2f2f7]' : 'bg-black'
        }`}
    >
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        connectionMode={ConnectionMode.Loose}
        onNodesChange={handleNodesChange}
        onConnect={handleConnect}
        onDelete={({ nodes, edges }) => {
          deleteSelection(
            nodes.map((n) => n.id),
            edges.map((e) => e.id)
          );
          setSelectedEdgeId(null);
        }}
        deleteKeyCode={['Backspace', 'Delete']}
        onNodeClick={(_, node) => {
          setSelectedEdgeId(null);
          selectNode(node.id);
        }}
        onEdgeClick={(_, edge) => {
          setSelectedEdgeId(edge.id);
          selectNode(null);
        }}
        onPaneClick={() => {
          setSelectedEdgeId(null);
          selectNode(null);
        }}
        onInit={(instance) => {
          rfInstanceRef.current = instance;
          requestAnimationFrame(syncViewportCenter);
        }}
        onMoveEnd={syncViewportCenter}
        fitView
        forceColorMode={themeMode}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={22}
          size={1}
          color={themeMode === 'light' ? '#c7c7cc' : '#242428'}
        />
        <Controls />
      </ReactFlow>

      {simResult.warnings.length > 0 && (
        <div className="absolute left-3 top-3 z-20 max-w-md rounded-lg border border-amber-500/40 bg-amber-950/90 px-3 py-2 text-xs text-amber-200 shadow-lg">
          <div className="flex items-center gap-1.5 font-semibold">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            Topology Warnings
          </div>
          <ul className="mt-1 list-disc pl-4 text-[11px] text-amber-300/90">
            {simResult.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {traceResult && (
        <div className="absolute bottom-3 left-3 right-3 z-20 rounded-xl border border-slate-700 bg-slate-900/95 p-3 shadow-xl backdrop-blur">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold">
              {traceResult.outcome === 'delivered' ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              ) : (
                <XCircle className="h-4 w-4 text-rose-400" />
              )}
              <span>
                Path Audit <code className="text-sky-300">{traceResult.srcIp}</code> →{' '}
                <code className="text-cyan-300">{traceResult.dstIp}</code>:{' '}
                <span
                  className={
                    traceResult.outcome === 'delivered'
                      ? 'text-emerald-400 uppercase'
                      : 'text-rose-400 uppercase'
                  }
                >
                  {traceResult.outcome}
                </span>
                {traceResult.failureReason && (
                  <span className="ml-2 font-normal text-rose-300">
                    ({traceResult.failureReason})
                  </span>
                )}
                {traceResult.asymmetricPath && (
                  <span className="ml-2 rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-amber-300">
                    ASYMMETRIC ROUTING
                  </span>
                )}
                {traceResult.returnTrace && !traceResult.asymmetricPath && traceResult.returnTrace.outcome === 'delivered' && (
                  <span className="ml-2 rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-300">
                    SYMMETRIC
                  </span>
                )}
                {traceResult.returnTrace && traceResult.returnTrace.outcome !== 'delivered' && (
                  <span className="ml-2 rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-rose-300">
                    RETURN {traceResult.returnTrace.outcome.toUpperCase()}
                  </span>
                )}
              </span>
            </div>
            <span className="text-[11px] text-slate-400">
              {traceResult.hops.length} hop{traceResult.hops.length === 1 ? '' : 's'}
            </span>
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
            {traceResult.hops.map((hop, idx) => (
              <React.Fragment key={`${hop.nodeId}-${idx}`}>
                <div className="rounded border border-slate-700 bg-slate-950 px-2 py-1">
                  <span className="font-semibold text-slate-100">{hop.hostname}</span>{' '}
                  <span className="text-cyan-400">[{hop.vrf}]</span>{' '}
                  <span className="font-mono text-slate-400">
                    ({hop.egressInterface}) [{hop.matchedPrefix} via {hop.protocol.toUpperCase()} AD {hop.ad}]
                  </span>
                  {hop.routeStatus && (
                    <span
                      className={`ml-1.5 rounded px-1 py-0.5 text-[10px] font-semibold ${hop.routeStatus === 'ok'
                        ? 'bg-sky-500/20 text-sky-300'
                        : 'bg-rose-500/20 text-rose-300'
                        }`}
                    >
                      Route:{hop.routeStatus.toUpperCase()}
                    </span>
                  )}
                  {hop.aclMatched && (
                    <span
                      className={`ml-1.5 rounded px-1 py-0.5 text-[10px] font-semibold ${hop.aclMatched.startsWith('DENY')
                        ? 'bg-rose-500/20 text-rose-300'
                        : 'bg-emerald-500/20 text-emerald-300'
                        }`}
                    >
                      {hop.aclMatched}
                    </span>
                  )}
                  {hop.natApplied && (
                    <span className="ml-1.5 rounded bg-violet-500/20 px-1 py-0.5 text-[10px] text-violet-300">
                      {hop.natApplied}
                    </span>
                  )}
                  {hop.mplsLabels && hop.mplsLabels.length > 0 && (
                    <span className="ml-1.5 rounded bg-purple-500/20 px-1 py-0.5 text-[10px] text-purple-300">
                      MPLS:[{hop.mplsLabels.join(',')}]
                    </span>
                  )}
                  {hop.macsecSecured && (
                    <span className="ml-1.5 rounded bg-emerald-500/20 px-1 py-0.5 text-[10px] text-emerald-300">
                      MACsec
                    </span>
                  )}
                  {hop.ecnMarked && (
                    <span className="ml-1.5 rounded bg-amber-500/20 px-1 py-0.5 text-[10px] text-amber-300">
                      ECN-CE
                    </span>
                  )}
                  {hop.urpfStatus && hop.urpfStatus !== 'pass' && (
                    <span className="ml-1.5 rounded bg-rose-500/20 px-1 py-0.5 text-[10px] text-rose-300">
                      {hop.urpfStatus.toUpperCase()}
                    </span>
                  )}
                  {hop.dscp !== undefined && (
                    <span className="ml-1.5 rounded bg-cyan-500/20 px-1 py-0.5 text-[10px] text-cyan-300">
                      DSCP:{hop.dscp}
                    </span>
                  )}
                  {hop.flowspecMatched && (
                    <span className="ml-1.5 rounded bg-rose-500/20 px-1 py-0.5 text-[10px] text-rose-300">
                      {hop.flowspecMatched}
                    </span>
                  )}
                </div>
                {idx < traceResult.hops.length - 1 && (
                  <span className="text-amber-400">→</span>
                )}
              </React.Fragment>
            ))}
          </div>

          {traceResult.returnTrace && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5 border-t border-slate-800 pt-1.5 text-[11px]">
              <span
                className={`font-semibold ${traceResult.returnTrace.outcome !== 'delivered'
                    ? 'text-rose-300'
                    : traceResult.asymmetricPath
                      ? 'text-amber-300'
                      : 'text-sky-300'
                  }`}
              >
                Return ({traceResult.returnTrace.outcome.toUpperCase()}):
              </span>
              {traceResult.returnTrace.hops.map((hop, idx) => (
                <React.Fragment key={`ret-${hop.nodeId}-${idx}`}>
                  <span className="rounded border border-slate-800 bg-slate-950/80 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">
                    {hop.hostname}
                    {hop.egressInterface && hop.egressInterface !== '-' ? ` (${hop.egressInterface})` : ''}
                  </span>
                  {idx < traceResult.returnTrace!.hops.length - 1 && (
                    <span className={traceResult.asymmetricPath ? 'text-amber-400' : 'text-sky-400'}>→</span>
                  )}
                </React.Fragment>
              ))}
              {traceResult.returnTrace.failureReason && (
                <span className="text-[10px] text-rose-300">
                  ({traceResult.returnTrace.failureReason})
                </span>
              )}
            </div>
          )}
        </div>
      )}

      <Modal
        open={Boolean(pendingLink && pendingSrcNode && pendingDstNode)}
        title="Connect Network Link"
        okText="Connect"
        onCancel={() => setPendingLink(null)}
        onOk={() => {
          if (!pendingLink || !pendingSrcNode || !pendingDstNode) return;
          addLink({
            id: `link-${Date.now()}`,
            sourceNodeId: pendingLink.sourceNodeId,
            sourceInterfaceId: pendingLink.sourceInterfaceId,
            targetNodeId: pendingLink.targetNodeId,
            targetInterfaceId: pendingLink.targetInterfaceId,
            linkType: pendingLink.linkType,
            ipsecConfig:
              pendingLink.linkType === 'ipsec'
                ? { ikeVersion: 'IKEv2', cryptoProfile: 'AES256-GCM-SHA256' }
                : undefined,
          });
          setPendingLink(null);
        }}
      >
        {pendingLink && pendingSrcNode && pendingDstNode && (
          <div className="space-y-3 pt-2 text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <div className="mb-1 text-slate-400">
                  Source ({pendingSrcNode.hostname})
                </div>
                <Select
                  size="small"
                  className="w-full"
                  value={pendingLink.sourceInterfaceId}
                  onChange={(val) =>
                    setPendingLink({ ...pendingLink, sourceInterfaceId: val })
                  }
                  options={pendingSrcNode.interfaces.map((i) => ({
                    value: i.id,
                    label: `${i.name} (${i.cidr})`,
                  }))}
                />
              </div>
              <div>
                <div className="mb-1 text-slate-400">
                  Target ({pendingDstNode.hostname})
                </div>
                <Select
                  size="small"
                  className="w-full"
                  value={pendingLink.targetInterfaceId}
                  onChange={(val) =>
                    setPendingLink({ ...pendingLink, targetInterfaceId: val })
                  }
                  options={pendingDstNode.interfaces.map((i) => ({
                    value: i.id,
                    label: `${i.name} (${i.cidr})`,
                  }))}
                />
              </div>
            </div>
            <div>
              <div className="mb-1 text-slate-400">Link Type</div>
              <Select
                size="small"
                className="w-full"
                value={pendingLink.linkType}
                onChange={(val) =>
                  setPendingLink({
                    ...pendingLink,
                    linkType: val as 'ethernet' | 'ipsec' | 'layer2',
                  })
                }
                options={[
                  { value: 'ethernet', label: 'Ethernet / L3 Link' },
                  { value: 'layer2', label: 'Layer 2 (Access / Trunk)' },
                  { value: 'ipsec', label: 'IPsec Tunnel (IKEv2)' },
                ]}
              />
            </div>
          </div>
        )}
      </Modal>

      <Modal
        title="Edit Link / Tunnel Properties"
        open={Boolean(editingLinkId && topology.links.some((l) => l.id === editingLinkId))}
        onCancel={() => setEditingLinkId(null)}
        footer={null}
        width={380}
      >
        {(() => {
          const link = topology.links.find((l) => l.id === editingLinkId);
          if (!link) return null;
          return (
            <div className="space-y-3 text-xs">
              <div>
                <div className="mb-1 text-slate-400">Link Type</div>
                <Select
                  size="small"
                  className="w-full"
                  value={link.linkType ?? 'ethernet'}
                  onChange={(val) =>
                    updateLink(link.id, {
                      linkType: val as 'ethernet' | 'ipsec' | 'layer2',
                      l2Mode: val === 'layer2' ? (link.l2Mode ?? 'trunk') : link.l2Mode,
                      ipsecConfig:
                        val === 'ipsec'
                          ? { ikeVersion: 'IKEv2', ...link.ipsecConfig }
                          : link.ipsecConfig,
                    })
                  }
                  options={[
                    { value: 'ethernet', label: 'Ethernet / L3 Link' },
                    { value: 'layer2', label: 'Layer 2 (Access / Trunk)' },
                    { value: 'ipsec', label: 'IPsec Tunnel (IKEv2)' },
                  ]}
                />
              </div>
              {link.linkType === 'layer2' && (
                <div className="grid grid-cols-12 gap-2">
                  <div className="col-span-4">
                    <div className="mb-1 text-slate-400">L2 Mode</div>
                    <Select
                      size="small"
                      className="w-full"
                      value={link.l2Mode ?? 'trunk'}
                      onChange={(val) => updateLink(link.id, { l2Mode: val })}
                      options={[
                        { value: 'trunk', label: 'Trunk' },
                        { value: 'access', label: 'Access' },
                      ]}
                    />
                  </div>
                  <div className="col-span-3">
                    <div className="mb-1 text-slate-400">VLAN ID</div>
                    <InputNumber
                      size="small"
                      className="!w-full"
                      min={1}
                      max={4094}
                      placeholder="1"
                      value={link.vlanId ?? null}
                      onChange={(val) => updateLink(link.id, { vlanId: val ?? undefined })}
                    />
                  </div>
                  <div className="col-span-5">
                    <div className="mb-1 text-slate-400">Allowed VLANs</div>
                    <Input
                      size="small"
                      placeholder="e.g. 10,20,301"
                      value={link.allowedVlans ?? ''}
                      onChange={(e) =>
                        updateLink(link.id, { allowedVlans: e.target.value || undefined })
                      }
                    />
                  </div>
                </div>
              )}
              {link.linkType === 'ipsec' && (
                <div className="space-y-2 rounded border border-slate-800 bg-slate-900/60 p-2">
                  <div>
                    <div className="mb-1 text-slate-400">Underlay Destination IP (optional)</div>
                    <Input
                      size="small"
                      placeholder="e.g. 203.0.113.2"
                      value={link.ipsecConfig?.underlayDstIp ?? ''}
                      onChange={(e) =>
                        updateLink(link.id, {
                          ipsecConfig: {
                            ...link.ipsecConfig,
                            underlayDstIp: e.target.value || undefined,
                          },
                        })
                      }
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <div className="mb-1 text-slate-400">Local IKE</div>
                      <Select
                        size="small"
                        className="w-full"
                        value={link.ipsecConfig?.ikeVersion ?? 'IKEv2'}
                        onChange={(val) =>
                          updateLink(link.id, {
                            ipsecConfig: { ...link.ipsecConfig, ikeVersion: val },
                          })
                        }
                        options={[
                          { value: 'IKEv2', label: 'IKEv2' },
                          { value: 'IKEv1', label: 'IKEv1' },
                        ]}
                      />
                    </div>
                    <div>
                      <div className="mb-1 text-slate-400">Remote IKE</div>
                      <Select
                        size="small"
                        className="w-full"
                        allowClear
                        placeholder="Match Local"
                        value={link.ipsecConfig?.remoteIkeVersion}
                        onChange={(val) =>
                          updateLink(link.id, {
                            ipsecConfig: { ...link.ipsecConfig, remoteIkeVersion: val },
                          })
                        }
                        options={[
                          { value: 'IKEv2', label: 'IKEv2' },
                          { value: 'IKEv1', label: 'IKEv1' },
                        ]}
                      />
                    </div>
                    <div>
                      <div className="mb-1 text-slate-400">Local Crypto Profile</div>
                      <Input
                        size="small"
                        placeholder="e.g. AES256-GCM"
                        value={link.ipsecConfig?.cryptoProfile ?? ''}
                        onChange={(e) =>
                          updateLink(link.id, {
                            ipsecConfig: {
                              ...link.ipsecConfig,
                              cryptoProfile: e.target.value || undefined,
                            },
                          })
                        }
                      />
                    </div>
                    <div>
                      <div className="mb-1 text-slate-400">Remote Crypto Profile</div>
                      <Input
                        size="small"
                        placeholder="Match Local"
                        value={link.ipsecConfig?.remoteCryptoProfile ?? ''}
                        onChange={(e) =>
                          updateLink(link.id, {
                            ipsecConfig: {
                              ...link.ipsecConfig,
                              remoteCryptoProfile: e.target.value || undefined,
                            },
                          })
                        }
                      />
                    </div>
                  </div>
                </div>
              )}
              <div className="grid grid-cols-2 gap-2 border-t border-slate-800 pt-2">
                <div>
                  <div className="mb-1 text-slate-400">Source Side</div>
                  <Select
                    size="small"
                    className="w-full"
                    value={link.sourceHandle ?? 'auto'}
                    onChange={(val) =>
                      updateLink(link.id, {
                        sourceHandle: val === 'auto' ? undefined : (val as HandleSide),
                      })
                    }
                    options={[
                      { value: 'auto', label: 'Auto' },
                      { value: 'top', label: 'Top' },
                      { value: 'right', label: 'Right' },
                      { value: 'bottom', label: 'Bottom' },
                      { value: 'left', label: 'Left' },
                    ]}
                  />
                </div>
                <div>
                  <div className="mb-1 text-slate-400">Target Side</div>
                  <Select
                    size="small"
                    className="w-full"
                    value={link.targetHandle ?? 'auto'}
                    onChange={(val) =>
                      updateLink(link.id, {
                        targetHandle: val === 'auto' ? undefined : (val as HandleSide),
                      })
                    }
                    options={[
                      { value: 'auto', label: 'Auto' },
                      { value: 'top', label: 'Top' },
                      { value: 'right', label: 'Right' },
                      { value: 'bottom', label: 'Bottom' },
                      { value: 'left', label: 'Left' },
                    ]}
                  />
                </div>
                {link.controlPointOffset && (
                  <div className="col-span-2 flex justify-end">
                    <button
                      type="button"
                      onClick={() => updateLink(link.id, { controlPointOffset: undefined })}
                      className="rounded border border-slate-700 px-2 py-0.5 text-[11px] text-slate-300 hover:bg-slate-800"
                    >
                      Reset Dragged Curve
                    </button>
                  </div>
                )}
              </div>
              <div className="grid grid-cols-3 gap-2 border-t border-slate-800 pt-2">
                <div>
                  <div className="mb-1 text-slate-400">Latency (ms)</div>
                  <InputNumber
                    size="small"
                    className="!w-full"
                    min={0}
                    max={5000}
                    placeholder="0"
                    value={link.latencyMs ?? null}
                    onChange={(val) =>
                      updateLink(link.id, { latencyMs: val ?? undefined })
                    }
                  />
                </div>
                <div>
                  <div className="mb-1 text-slate-400">Jitter (ms)</div>
                  <InputNumber
                    size="small"
                    className="!w-full"
                    min={0}
                    max={1000}
                    placeholder="0"
                    value={link.jitterMs ?? null}
                    onChange={(val) =>
                      updateLink(link.id, { jitterMs: val ?? undefined })
                    }
                  />
                </div>
                <div>
                  <div className="mb-1 text-slate-400">Loss (%)</div>
                  <InputNumber
                    size="small"
                    className="!w-full"
                    min={0}
                    max={100}
                    placeholder="0"
                    value={link.lossPct ?? null}
                    onChange={(val) =>
                      updateLink(link.id, { lossPct: val ?? undefined })
                    }
                  />
                </div>
              </div>
            </div>
          );
        })()}
      </Modal>
    </div>
  );
};

