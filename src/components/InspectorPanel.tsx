import React, { useEffect, useState } from 'react';
import { CopyOutlined, DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Collapse,
  Empty,
  Input,
  InputNumber,
  Select,
  Space,
  Switch,
  Tabs,
  Tag,
} from 'antd';
import { VENDOR_CAPABILITIES, VENDOR_DEFAULT_AD, VENDOR_METADATA } from '../engine/vendorProfiles';
import { useSimStore } from '../store/useSimStore';
import { VendorProfile } from '../types/network';

const isValidBgpAsn = (asn: number): boolean =>
  Number.isInteger(asn) && asn >= 1 && asn <= 4294967295;

export const InspectorPanel: React.FC<{ headerExtra?: React.ReactNode }> = ({ headerExtra }) => {
  const {
    topology,
    selectedNodeId,
    updateNode,
    duplicateNode,
    deleteNode,
    addInterface,
    updateInterface,
    deleteInterface,
    addLink,
    deleteLink,
    setVrfColor,
  } = useSimStore();

  const [newVrfName, setNewVrfName] = useState('');
  const [newVrfColor, setNewVrfColor] = useState('#06b6d4');
  const [newBgpPeerVrf, setNewBgpPeerVrf] = useState('default');
  const [newLinkTargetId, setNewLinkTargetId] = useState('');
  const [newLinkSrcIf, setNewLinkSrcIf] = useState('');
  const [newLinkDstIf, setNewLinkDstIf] = useState('');
  const [newLinkType, setNewLinkType] = useState<'ethernet' | 'ipsec'>('ethernet');
  const [advProtoExpanded, setAdvProtoExpanded] = useState(false);
  const [inputResetNonce, setInputResetNonce] = useState(0);

  useEffect(() => {
    setNewLinkTargetId('');
    setNewLinkSrcIf('');
    setNewLinkDstIf('');
    setAdvProtoExpanded(false);
  }, [selectedNodeId]);

  const node = topology.nodes.find((n) => n.id === selectedNodeId);
  if (!node) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <Empty description="Select an appliance on the canvas to configure control-plane settings" />
      </div>
    );
  }

  const caps = VENDOR_CAPABILITIES[node.vendor] ?? VENDOR_CAPABILITIES['cisco-ios-xe'];
  const vrfs = node.vrfs?.length ? node.vrfs : ['default'];
  const workspaceVrfs = Array.from(
    new Set([
      ...topology.nodes.flatMap((n) => [
        ...(n.vrfs ?? []),
        ...n.interfaces.map((i) => i.vrf).filter(Boolean),
      ]),
      ...Object.keys(topology.vrfColors ?? {}),
    ])
  ).filter((v) => v && v !== 'default');
  const availableVrfs = Array.from(
    new Set([
      ...vrfs,
      ...node.interfaces.map((i) => i.vrf).filter(Boolean),
      ...(node.vendor === 'forcepoint-ngfw' ? [] : workspaceVrfs),
    ])
  );
  const prefixLists = node.prefixLists ?? [];
  const routeMaps = node.routeMaps ?? [];
  const vrfLeaks = node.vrfLeaks ?? [];
  const pbrRules = node.pbrRules ?? [];
  const aclRules = node.aclRules ?? [];
  const natRules = node.natRules ?? [];
  const otherNodes = topology.nodes.filter((n) => n.id !== node.id);
  const targetNode = otherNodes.find((n) => n.id === newLinkTargetId) ?? otherNodes[0];
  const nodeLinks = topology.links.filter(
    (l) => l.sourceNodeId === node.id || l.targetNodeId === node.id
  );

  const tabItems = [
    {
      key: 'general',
      label: 'Device & AD',
      children: (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-2.5">
            <div>
              <div className="mb-1 text-[11px] text-slate-400">Hostname</div>
              <Input
                size="small"
                value={node.hostname}
                onChange={(e) => updateNode(node.id, { hostname: e.target.value })}
              />
            </div>
            <div>
              <div className="mb-1 text-[11px] text-slate-400">Vendor Profile</div>
              <Select
                size="small"
                className="w-full"
                value={node.vendor}
                onChange={(v) => updateNode(node.id, { vendor: v as VendorProfile })}
                options={(Object.keys(VENDOR_METADATA) as VendorProfile[]).map((v) => ({
                  value: v,
                  label: VENDOR_METADATA[v].label,
                }))}
              />
            </div>
            <div>
              <div className="mb-1 text-[11px] text-slate-400">Router ID</div>
              <Input
                size="small"
                value={node.routerId}
                onChange={(e) => updateNode(node.id, { routerId: e.target.value })}
                style={{ fontFamily: 'monospace' }}
              />
            </div>
            <div>
              <div className="mb-1 text-[11px] text-slate-400">ECMP Max-Paths</div>
              <InputNumber
                size="small"
                min={1}
                max={16}
                className="!w-full"
                value={node.maxPaths}
                onChange={(val) => updateNode(node.id, { maxPaths: val ?? 1 })}
              />
            </div>
            <div className="col-span-2 flex items-center justify-between rounded border border-slate-700/60 px-2.5 py-1.5">
              <div>
                <div className="text-[11px] font-medium text-slate-300">Node Admin Down (Simulate Failover)</div>
                <div className="text-[10px] text-slate-400">Shuts down all links and triggers HA Standby promotion</div>
              </div>
              <Switch
                size="small"
                checked={!!node.adminDown}
                onChange={(checked) => updateNode(node.id, { adminDown: checked })}
              />
            </div>
          </div>

          <Card size="small" title={`AD Overrides (${(VENDOR_METADATA[node.vendor] ?? VENDOR_METADATA['cisco-ios-xe']).shortLabel} defaults)`}>
            <div className="grid grid-cols-3 gap-2">
              {caps.adProtocols.map((proto) => (
                <div key={proto} className="flex items-center justify-between gap-1">
                  <span className="text-[11px] uppercase text-slate-400">{proto}</span>
                  <InputNumber
                    size="small"
                    placeholder={String((VENDOR_DEFAULT_AD[node.vendor] ?? VENDOR_DEFAULT_AD['cisco-ios-xe'])[proto])}
                    value={node.adOverrides[proto] ?? null}
                    onChange={(val) => {
                      const nextOverrides = { ...node.adOverrides };
                      if (val === null || val === undefined) delete nextOverrides[proto];
                      else nextOverrides[proto] = val;
                      updateNode(node.id, { adOverrides: nextOverrides });
                    }}
                    style={{ width: 64 }}
                  />
                </div>
              )
              )}
            </div>
          </Card>

          {(node.vendor === 'aws-cloud' ||
            node.vendor === 'aws-cloudwan' ||
            node.vendor === 'azure-cloud' ||
            node.vendor === 'gcp-cloud' ||
            node.vendor === 'oci-cloud' ||
            node.vendor === 'cloudflare-mwan') && (
              <Card size="small" title="Cloud Routing Policy">
                <div className="space-y-2">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <div className="mb-1 text-[11px] text-slate-400">Region / Edge</div>
                      <Input
                        size="small"
                        placeholder={
                          node.vendor === 'azure-cloud'
                            ? 'eastus'
                            : node.vendor === 'gcp-cloud'
                              ? 'us-central1'
                              : node.vendor === 'oci-cloud'
                                ? 'us-ashburn-1'
                                : node.vendor === 'cloudflare-mwan'
                                  ? 'global-anycast'
                                  : 'us-east-1'
                        }
                        value={node.cloudConfig?.region ?? ''}
                        onChange={(e) =>
                          updateNode(node.id, {
                            cloudConfig: { ...node.cloudConfig, region: e.target.value || undefined },
                          })
                        }
                      />
                    </div>
                    {node.vendor === 'gcp-cloud' && (
                      <div>
                        <div className="mb-1 text-[11px] text-slate-400">Dynamic Routing Mode</div>
                        <Select
                          size="small"
                          className="w-full"
                          value={node.cloudConfig?.dynamicRoutingMode ?? 'global'}
                          onChange={(val: 'regional' | 'global') =>
                            updateNode(node.id, {
                              cloudConfig: { ...node.cloudConfig, dynamicRoutingMode: val },
                            })
                          }
                          options={[
                            { label: 'GLOBAL', value: 'global' },
                            { label: 'REGIONAL', value: 'regional' },
                          ]}
                        />
                      </div>
                    )}
                    {node.vendor === 'gcp-cloud' && (
                      <div>
                        <div className="mb-1 text-[11px] text-slate-400">Default Route Priority</div>
                        <InputNumber
                          size="small"
                          min={0}
                          max={65535}
                          className="!w-full"
                          value={node.cloudConfig?.defaultRoutePriority ?? 1000}
                          onChange={(val) =>
                            updateNode(node.id, {
                              cloudConfig: { ...node.cloudConfig, defaultRoutePriority: val ?? 1000 },
                            })
                          }
                        />
                      </div>
                    )}
                  </div>

                  {node.vendor !== 'cloudflare-mwan' && (
                    <div className="flex items-center justify-between rounded border border-slate-700/60 px-2.5 py-1.5">
                      <div>
                        <div className="text-[11px] font-medium text-slate-300">
                          Prefer Private Circuit over IPsec VPN
                        </div>
                        <div className="text-[10px] text-slate-400">
                          DX / ExpressRoute / Interconnect / FastConnect beats IPsec BGP
                        </div>
                      </div>
                      <Switch
                        size="small"
                        checked={node.cloudConfig?.preferPrivateCircuit !== false}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            cloudConfig: { ...node.cloudConfig, preferPrivateCircuit: checked },
                          })
                        }
                      />
                    </div>
                  )}

                  {(node.vendor === 'aws-cloud' || node.vendor === 'aws-cloudwan') && (
                    <div className="flex items-center justify-between rounded border border-slate-700/60 px-2.5 py-1.5">
                      <div>
                        <div className="text-[11px] font-medium text-slate-300">Appliance Mode Support</div>
                        <div className="text-[10px] text-slate-400">Symmetric AZ flow pinning for inspection firewalls</div>
                      </div>
                      <Switch
                        size="small"
                        checked={!!node.cloudConfig?.applianceMode}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            cloudConfig: { ...node.cloudConfig, applianceMode: checked },
                          })
                        }
                      />
                    </div>
                  )}

                  {node.vendor === 'azure-cloud' && (
                    <>
                      <div className="flex items-center justify-between rounded border border-slate-700/60 px-2.5 py-1.5">
                        <div>
                          <div className="text-[11px] font-medium text-slate-300">UDR Overrides BGP Routes</div>
                          <div className="text-[10px] text-slate-400">Static User-Defined Routes take priority over BGP</div>
                        </div>
                        <Switch
                          size="small"
                          checked={node.cloudConfig?.udrOverridesBgp !== false}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              cloudConfig: { ...node.cloudConfig, udrOverridesBgp: checked },
                            })
                          }
                        />
                      </div>
                      <div className="flex items-center justify-between rounded border border-slate-700/60 px-2.5 py-1.5">
                        <div>
                          <div className="text-[11px] font-medium text-slate-300">Disable BGP Route Propagation</div>
                          <div className="text-[10px] text-slate-400">Suppresses ExpressRoute/VPN BGP routes on this route table</div>
                        </div>
                        <Switch
                          size="small"
                          checked={!!node.cloudConfig?.disableBgpPropagation}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              cloudConfig: { ...node.cloudConfig, disableBgpPropagation: checked },
                            })
                          }
                        />
                      </div>
                    </>
                  )}

                  {node.vendor === 'gcp-cloud' && (
                    <>
                      <div className="flex items-center justify-between rounded border border-slate-700/60 px-2.5 py-1.5">
                        <div>
                          <div className="text-[11px] font-medium text-slate-300">Private Google Access (PGA)</div>
                          <div className="text-[10px] text-slate-400">Private routes to 199.36.153.8/30 & 199.36.153.4/30</div>
                        </div>
                        <Switch
                          size="small"
                          checked={!!node.cloudConfig?.privateGoogleAccess}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              cloudConfig: { ...node.cloudConfig, privateGoogleAccess: checked },
                            })
                          }
                        />
                      </div>
                      <div className="flex items-center justify-between rounded border border-slate-700/60 px-2.5 py-1.5">
                        <div>
                          <div className="text-[11px] font-medium text-slate-300">Advertise PGA to On-Prem (BGP)</div>
                          <div className="text-[10px] text-slate-400">Advertises Google API VIPs over Interconnect / VPN</div>
                        </div>
                        <Switch
                          size="small"
                          checked={!!node.cloudConfig?.pgaOnPremAdvertise}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              cloudConfig: {
                                ...node.cloudConfig,
                                pgaOnPremAdvertise: checked,
                                ...(checked ? { privateGoogleAccess: true } : {}),
                              },
                            })
                          }
                        />
                      </div>
                      <div className="flex items-center justify-between rounded border border-slate-700/60 px-2.5 py-1.5">
                        <div>
                          <div className="text-[11px] font-medium text-slate-300">Network Connectivity Center (NCC) Hub</div>
                          <div className="text-[10px] text-slate-400">Transitive hub-and-spoke across VPC & hybrid spokes</div>
                        </div>
                        <Switch
                          size="small"
                          checked={!!node.cloudConfig?.nccHubEnabled}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              cloudConfig: { ...node.cloudConfig, nccHubEnabled: checked },
                            })
                          }
                        />
                      </div>
                      <div>
                        <div className="mb-1 text-[11px] text-slate-400">
                          Private Service Connect (PSC) / PSA CIDRs
                        </div>
                        <Select
                          mode="tags"
                          size="small"
                          className="w-full"
                          tokenSeparators={[',', ' ']}
                          placeholder="Type CIDR and press Enter (e.g. 10.240.0.10/32)"
                          value={node.cloudConfig?.pscEndpoints ?? []}
                          onChange={(vals: string[]) =>
                            updateNode(node.id, {
                              cloudConfig: {
                                ...node.cloudConfig,
                                pscEndpoints: vals.map((s) => s.trim()).filter(Boolean),
                              },
                            })
                          }
                        />
                      </div>
                    </>
                  )}

                  <div>
                    <div className="mb-1 text-[11px] text-slate-400">Blackhole CIDRs</div>
                    <Select
                      mode="tags"
                      size="small"
                      className="w-full"
                      tokenSeparators={[',', ' ']}
                      placeholder="Type CIDR and press Enter (e.g. 192.0.2.0/24)"
                      value={node.cloudConfig?.blackholeCidrs ?? []}
                      onChange={(vals: string[]) =>
                        updateNode(node.id, {
                          cloudConfig: {
                            ...node.cloudConfig,
                            blackholeCidrs: vals.map((s) => s.trim()).filter(Boolean),
                          },
                        })
                      }
                    />
                  </div>
                </div>
              </Card>
            )}
        </div>
      ),
    },
    {
      key: 'interfaces',
      label: `Interfaces (${node.interfaces.length})`,
      children: (
        <div className="space-y-2">
          {node.interfaces.map((iface) => (
            <div
              key={iface.id}
              className="space-y-1.5 rounded border border-slate-800 bg-[#0b1120] p-2"
            >
              <div className="grid grid-cols-12 items-center gap-1.5">
                <Input
                  size="small"
                  className="col-span-3"
                  value={iface.name}
                  onChange={(e) => updateInterface(node.id, iface.id, { name: e.target.value })}
                  placeholder="eth0"
                  style={{ fontFamily: 'monospace' }}
                />
                <Input
                  size="small"
                  className="col-span-4"
                  value={iface.cidr}
                  onChange={(e) => updateInterface(node.id, iface.id, { cidr: e.target.value })}
                  placeholder="10.0.0.1/30"
                  style={{ fontFamily: 'monospace' }}
                />
                <Select
                  size="small"
                  className="col-span-2"
                  title="Assign VRF to interface (create additional VRFs in the VRFs tab)"
                  value={iface.vrf || 'default'}
                  onChange={(val) => {
                    const needsVrf = !vrfs.includes(val) && node.vendor !== 'forcepoint-ngfw';
                    if (needsVrf) {
                      updateNode(node.id, {
                        vrfs: [...vrfs, val],
                        interfaces: node.interfaces.map((i) =>
                          i.id === iface.id ? { ...i, vrf: val } : i
                        ),
                      });
                    } else {
                      updateInterface(node.id, iface.id, { vrf: val });
                    }
                  }}
                  options={Array.from(
                    new Set([
                      ...vrfs,
                      ...(node.vendor === 'forcepoint-ngfw'
                        ? []
                        : Object.keys(topology.vrfColors ?? {})),
                    ])
                  ).map((v) => {
                    const vc = topology.vrfColors?.[v];
                    return {
                      value: v,
                      label: (
                        <span className="inline-flex items-center gap-1">
                          {vc && (
                            <span
                              className="inline-block h-2 w-2 rounded-full"
                              style={{ backgroundColor: vc }}
                            />
                          )}
                          <span>VRF: {v}</span>
                        </span>
                      ),
                    };
                  })}
                />
                {node.ospf.enabled && (
                  <InputNumber
                    size="small"
                    className="col-span-2 !w-full"
                    placeholder="Area"
                    value={iface.ospfArea ?? null}
                    onChange={(val) =>
                      updateInterface(node.id, iface.id, {
                        ospfArea: val === null ? undefined : val,
                      })
                    }
                  />
                )}
                <Button
                  size="small"
                  danger
                  type="text"
                  className={node.ospf.enabled ? 'col-span-1' : 'col-span-3 justify-end'}
                  icon={<DeleteOutlined />}
                  onClick={() => deleteInterface(node.id, iface.id)}
                />
              </div>
              <div className="grid grid-cols-12 items-center gap-1.5 pt-0.5 text-[11px]">
                <InputNumber
                  size="small"
                  className="col-span-2 !w-full"
                  placeholder="VLAN"
                  min={1}
                  max={4094}
                  value={iface.vlanId ?? null}
                  onChange={(val) =>
                    updateInterface(node.id, iface.id, { vlanId: val ?? undefined })
                  }
                />
                {(caps.zones || Boolean(iface.zone)) && (
                  <Input
                    size="small"
                    className="col-span-4"
                    placeholder={`${caps.zoneLabel} (Trust, DMZ, Untrust)`}
                    value={iface.zone ?? ''}
                    onChange={(e) =>
                      updateInterface(node.id, iface.id, { zone: e.target.value || undefined })
                    }
                  />
                )}
                {(node.ospf.enabled || iface.ospfArea !== undefined) && (
                  <>
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="OSPF Cost"
                      value={iface.ospfCost ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, {
                          ospfCost: val === null ? undefined : val,
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-3"
                      placeholder="OSPF Auth Key"
                      value={iface.ospfAuthKey ?? ''}
                      onChange={(e) =>
                        updateInterface(node.id, iface.id, { ospfAuthKey: e.target.value || undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="OSPF Hello (10s)"
                      min={1}
                      max={65535}
                      value={iface.ospfHelloInterval ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { ospfHelloInterval: val ?? undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="OSPF Dead (40s)"
                      min={1}
                      max={65535}
                      value={iface.ospfDeadInterval ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { ospfDeadInterval: val ?? undefined })
                      }
                    />
                    <Select
                      size="small"
                      className="col-span-2"
                      allowClear
                      placeholder="OSPF Net"
                      value={iface.ospfNetworkType}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { ospfNetworkType: val })
                      }
                      options={[
                        { value: 'broadcast', label: 'Broadcast' },
                        { value: 'point-to-point', label: 'Point-to-Point' },
                        { value: 'non-broadcast', label: 'Non-Broadcast' },
                        { value: 'point-to-multipoint', label: 'P2MP' },
                      ]}
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="OSPF Prio (1)"
                      min={0}
                      max={255}
                      value={iface.ospfPriority ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { ospfPriority: val ?? undefined })
                      }
                    />
                  </>
                )}
                {node.eigrp?.enabled && (
                  <>
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="EIGRP Hello (5s)"
                      min={1}
                      max={65535}
                      value={iface.eigrpHelloInterval ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { eigrpHelloInterval: val ?? undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="EIGRP Hold (15s)"
                      min={1}
                      max={65535}
                      value={iface.eigrpHoldTime ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { eigrpHoldTime: val ?? undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="BW (kbps)"
                      min={1}
                      value={iface.eigrpBw ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { eigrpBw: val ?? undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="Delay (us)"
                      min={1}
                      value={iface.eigrpDelay ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { eigrpDelay: val ?? undefined })
                      }
                    />
                  </>
                )}
                {node.isis?.enabled && (
                  <>
                    <Select
                      size="small"
                      className="col-span-2"
                      allowClear
                      placeholder="IS-IS"
                      value={iface.isisLevel}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { isisLevel: val })
                      }
                      options={[
                        { value: 'L1', label: 'IS-IS L1' },
                        { value: 'L2', label: 'IS-IS L2' },
                      ]}
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="IS-IS Hello (10s)"
                      min={1}
                      max={65535}
                      value={iface.isisHelloInterval ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { isisHelloInterval: val ?? undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="IS-IS Mult (3x)"
                      min={1}
                      max={100}
                      value={iface.isisHelloMultiplier ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { isisHelloMultiplier: val ?? undefined })
                      }
                    />
                    <Select
                      size="small"
                      className="col-span-2"
                      allowClear
                      placeholder="IS-IS Net"
                      value={iface.isisNetworkType}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { isisNetworkType: val })
                      }
                      options={[
                        { value: 'broadcast', label: 'Broadcast' },
                        { value: 'point-to-point', label: 'Point-to-Point' },
                      ]}
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="IS-IS Met (10)"
                      min={1}
                      max={16777215}
                      value={iface.isisMetric ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { isisMetric: val ?? undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="IS-IS Prio (64)"
                      min={0}
                      max={127}
                      value={iface.isisPriority ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { isisPriority: val ?? undefined })
                      }
                    />
                  </>
                )}
                {(node.ospf.bfd || node.eigrp?.bfd || node.isis?.bfd || node.lisp?.bfd || node.bgp.peers.some((p) => p.bfd)) && (
                  <>
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="BFD Tx (50ms)"
                      min={5}
                      max={60000}
                      value={iface.bfdIntervalMs ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { bfdIntervalMs: val ?? undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="BFD Rx (50ms)"
                      min={5}
                      max={60000}
                      value={iface.bfdMinRxMs ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { bfdMinRxMs: val ?? undefined })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="BFD Mult (3x)"
                      min={1}
                      max={50}
                      value={iface.bfdMultiplier ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { bfdMultiplier: val ?? undefined })
                      }
                    />
                  </>
                )}
                {node.evpn?.enabled && (
                  <Input
                    size="small"
                    className="col-span-3"
                    placeholder="EVPN ESI"
                    value={iface.evpnEsi ?? ''}
                    style={{ fontFamily: 'monospace' }}
                    onChange={(e) =>
                      updateInterface(node.id, iface.id, { evpnEsi: e.target.value || undefined })
                    }
                  />
                )}
                {(node.vendor === 'cisco-nx-os' || Boolean(node.vpc?.enabled)) && (
                  <InputNumber
                    size="small"
                    className="col-span-2 !w-full"
                    placeholder="vPC"
                    min={1}
                    max={4096}
                    value={iface.vpcId ?? null}
                    onChange={(val) =>
                      updateInterface(node.id, iface.id, { vpcId: val ?? undefined })
                    }
                  />
                )}
                {(node.vendor === 'arista-eos' || Boolean(node.mlag?.enabled)) && (
                  <InputNumber
                    size="small"
                    className="col-span-2 !w-full"
                    placeholder="MLAG"
                    min={1}
                    max={4096}
                    value={iface.mlagId ?? null}
                    onChange={(val) =>
                      updateInterface(node.id, iface.id, { mlagId: val ?? undefined })
                    }
                  />
                )}
                {(caps.lag.supported || iface.lacpGroup !== undefined) && (
                  <>
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="LAG / Po#"
                      min={1}
                      max={4096}
                      value={iface.lacpGroup ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, {
                          lacpGroup: val ?? undefined,
                          lacpMode: val ? iface.lacpMode ?? 'active' : undefined,
                          lagProtocol: val ? iface.lagProtocol ?? 'lacp' : undefined,
                        })
                      }
                    />
                    {iface.lacpGroup !== undefined && (
                      <Select
                        size="small"
                        className="col-span-3"
                        placeholder={caps.lag.label}
                        value={iface.lacpMode ?? 'active'}
                        onChange={(val) =>
                          updateInterface(node.id, iface.id, {
                            lacpMode: val,
                            lagProtocol:
                              val === 'desirable' || val === 'auto'
                                ? 'pagp'
                                : val === 'on'
                                  ? 'static'
                                  : 'lacp',
                          })
                        }
                        options={[
                          { value: 'active', label: 'LACP Active' },
                          { value: 'passive', label: 'LACP Passive' },
                          { value: 'desirable', label: 'PAgP Desirable' },
                          { value: 'auto', label: 'PAgP Auto' },
                          { value: 'on', label: 'Static On' },
                        ].filter((opt) => caps.lag.modes.includes(opt.value as any))}
                      />
                    )}
                  </>
                )}
                {(node.vendor === 'cisco-sdwan' || Boolean(node.sdwan?.enabled)) && (
                  <>
                    <Select
                      size="small"
                      className="col-span-3"
                      allowClear
                      placeholder="TLOC Color"
                      value={iface.tlocColor ?? null}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { tlocColor: val ?? undefined })
                      }
                      options={[
                        { value: 'mpls', label: 'mpls' },
                        { value: 'biz-internet', label: 'biz-internet' },
                        { value: 'public-internet', label: 'public-internet' },
                        { value: 'lte', label: 'lte' },
                      ]}
                    />
                    <Select
                      size="small"
                      className="col-span-2"
                      value={iface.tlocEncap ?? 'ipsec'}
                      onChange={(val) =>
                        updateInterface(node.id, iface.id, { tlocEncap: val })
                      }
                      options={[
                        { value: 'ipsec', label: 'IPsec' },
                        { value: 'gre', label: 'GRE' },
                      ]}
                    />
                    <Input
                      size="small"
                      className="col-span-3"
                      placeholder="TLOC-Ext (e.g. ge0/0)"
                      value={iface.tlocExtension ?? ''}
                      onChange={(e) =>
                        updateInterface(node.id, iface.id, {
                          tlocExtension: e.target.value || undefined,
                        })
                      }
                    />
                  </>
                )}
                <InputNumber
                  size="small"
                  className="col-span-2 !w-full"
                  placeholder="MTU"
                  min={576}
                  max={9216}
                  value={iface.mtu ?? null}
                  onChange={(val) =>
                    updateInterface(node.id, iface.id, { mtu: val ?? undefined })
                  }
                />
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5 text-[11px] text-slate-300">
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-400">Speed</span>
                  <Select
                    size="small"
                    allowClear
                    placeholder="Auto (1G)"
                    style={{ width: 96 }}
                    value={iface.speedMbps}
                    onChange={(val) =>
                      updateInterface(node.id, iface.id, { speedMbps: val })
                    }
                    options={[
                      { value: 10, label: '10 Mbps' },
                      { value: 100, label: '100 Mbps' },
                      { value: 1000, label: '1 Gbps' },
                      { value: 10000, label: '10 Gbps' },
                      { value: 25000, label: '25 Gbps' },
                      { value: 40000, label: '40 Gbps' },
                      { value: 100000, label: '100 Gbps' },
                    ]}
                  />
                </div>
                <div className="flex items-center gap-3">
                  <label className="flex cursor-pointer items-center gap-1.5">
                    <Switch
                      size="small"
                      checked={Boolean(iface.passive)}
                      onChange={(checked) =>
                        updateInterface(node.id, iface.id, { passive: checked })
                      }
                    />
                    <span>Passive</span>
                  </label>
                  <label className="flex cursor-pointer items-center gap-1.5">
                    <Switch
                      size="small"
                      checked={Boolean(iface.shutdown)}
                      onChange={(checked) =>
                        updateInterface(node.id, iface.id, { shutdown: checked })
                      }
                    />
                    <span>Shutdown</span>
                  </label>
                </div>
              </div>
              <Collapse
                size="small"
                ghost
                items={[
                  {
                    key: 'adv',
                    label: (
                      <span className="text-[11px] text-slate-400">
                        IPv6 / Security / QoS
                        {(iface.cidr6 || iface.urpfMode || iface.qosPolicy?.dscpMark !== undefined || iface.dot1xState || iface.macsecEnabled || iface.pimSparse)
                          ? ' (Configured)'
                          : ''}
                      </span>
                    ),
                    children: (
                      <div className="grid grid-cols-12 items-center gap-1.5 text-[11px]">
                        <Input
                          size="small"
                          className="col-span-6"
                          value={iface.cidr6 ?? ''}
                          onChange={(e) =>
                            updateInterface(node.id, iface.id, {
                              cidr6: e.target.value || undefined,
                            })
                          }
                          placeholder="IPv6 CIDR (e.g. 2001:db8:1::1/64)"
                          style={{ fontFamily: 'monospace', fontSize: 11 }}
                        />
                        <Select
                          size="small"
                          className="col-span-3"
                          allowClear
                          placeholder="uRPF (Off)"
                          value={iface.urpfMode}
                          onChange={(val) =>
                            updateInterface(node.id, iface.id, { urpfMode: val })
                          }
                          options={[
                            { value: 'strict', label: 'uRPF Strict' },
                            { value: 'loose', label: 'uRPF Loose' },
                          ]}
                        />
                        <InputNumber
                          size="small"
                          className="col-span-3 !w-full"
                          placeholder="DSCP (0-63)"
                          min={0}
                          max={63}
                          value={iface.qosPolicy?.dscpMark ?? null}
                          onChange={(val) => {
                            if (val !== null) {
                              updateInterface(node.id, iface.id, {
                                qosPolicy: { ...iface.qosPolicy, dscpMark: val },
                              });
                            } else {
                              const { dscpMark: _removed, ...restQos } = iface.qosPolicy ?? {};
                              void _removed;
                              updateInterface(node.id, iface.id, {
                                qosPolicy: Object.keys(restQos).length > 0 ? restQos : undefined,
                              });
                            }
                          }}
                        />
                        <Select
                          size="small"
                          className="col-span-4"
                          allowClear
                          placeholder="802.1X"
                          value={iface.dot1xState}
                          onChange={(val) =>
                            updateInterface(node.id, iface.id, { dot1xState: val })
                          }
                          options={[
                            { value: 'authorized', label: '802.1X Auth' },
                            { value: 'unauthorized', label: '802.1X Unauth' },
                            { value: 'force-authorized', label: '802.1X Force' },
                          ]}
                        />
                        <label className="col-span-3 flex cursor-pointer items-center gap-1.5 text-slate-300">
                          <Switch
                            size="small"
                            checked={Boolean(iface.macsecEnabled)}
                            onChange={(checked) =>
                              updateInterface(node.id, iface.id, { macsecEnabled: checked })
                            }
                          />
                          <span>MACsec</span>
                        </label>
                        {node.multicast?.pimEnabled && (
                          <label className="col-span-3 flex cursor-pointer items-center gap-1.5 text-slate-300">
                            <Switch
                              size="small"
                              checked={Boolean(iface.pimSparse)}
                              onChange={(checked) =>
                                updateInterface(node.id, iface.id, { pimSparse: checked })
                              }
                            />
                            <span>PIM Sparse</span>
                          </label>
                        )}
                      </div>
                    ),
                  },
                ]}
              />
            </div>
          ))}
          <Button
            size="small"
            icon={<PlusOutlined />}
            onClick={() => {
              const prefix = (VENDOR_METADATA[node.vendor] ?? VENDOR_METADATA['cisco-ios-xe']).defaultInterfacePrefix;
              let nextNum = node.interfaces.length + 1;
              while (
                node.interfaces.some(
                  (i) => i.name.toLowerCase() === `${prefix}${nextNum}`.toLowerCase()
                )
              ) {
                nextNum++;
              }
              addInterface(node.id, {
                id: `if-${Date.now()}`,
                name: `${prefix}${nextNum}`,
                cidr: `10.100.${nextNum}.1/24`,
                vrf: 'default',
              });
            }}
          >
            Add Interface
          </Button>

          {(caps.fhrp.supported || (node.fhrpGroups ?? []).length > 0) && (
            <Card
              size="small"
              title={<span className="text-cyan-300">{caps.fhrp.label}</span>}
              extra={
                <Button
                  size="small"
                  icon={<PlusOutlined />}
                  onClick={() =>
                    updateNode(node.id, {
                      fhrpGroups: [
                        ...(node.fhrpGroups ?? []),
                        {
                          id: `fhrp-${Date.now()}`,
                          protocol: caps.fhrp.protocols[0] ?? 'vrrp',
                          groupId: 10,
                          interfaceId: node.interfaces[0]?.id ?? '',
                          virtualIp: '10.10.10.254',
                          priority: 110,
                        },
                      ],
                    })
                  }
                >
                  Add VIP
                </Button>
              }
            >
              <div className="space-y-1.5">
                {(node.fhrpGroups ?? []).map((grp) => (
                  <div key={grp.id} className="grid grid-cols-12 items-center gap-1">
                    <Select
                      size="small"
                      className="col-span-2"
                      value={grp.protocol}
                      onChange={(val) =>
                        updateNode(node.id, {
                          fhrpGroups: (node.fhrpGroups ?? []).map((x) =>
                            x.id === grp.id ? { ...x, protocol: val } : x
                          ),
                        })
                      }
                      options={[
                        ...(caps.fhrp.protocols.includes('hsrp') ? [{ value: 'hsrp', label: 'HSRP' }] : []),
                        { value: 'vrrp', label: caps.fhrp.vrrpLabel },
                      ]}
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      value={grp.groupId}
                      onChange={(val) =>
                        updateNode(node.id, {
                          fhrpGroups: (node.fhrpGroups ?? []).map((x) =>
                            x.id === grp.id ? { ...x, groupId: val ?? 10 } : x
                          ),
                        })
                      }
                    />
                    <Select
                      size="small"
                      className="col-span-3"
                      value={grp.interfaceId}
                      onChange={(val) =>
                        updateNode(node.id, {
                          fhrpGroups: (node.fhrpGroups ?? []).map((x) =>
                            x.id === grp.id ? { ...x, interfaceId: val } : x
                          ),
                        })
                      }
                      options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                    />
                    <Input
                      size="small"
                      className="col-span-3"
                      value={grp.virtualIp}
                      style={{ fontFamily: 'monospace' }}
                      onChange={(e) =>
                        updateNode(node.id, {
                          fhrpGroups: (node.fhrpGroups ?? []).map((x) =>
                            x.id === grp.id ? { ...x, virtualIp: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-1 !w-full"
                      value={grp.priority}
                      onChange={(val) =>
                        updateNode(node.id, {
                          fhrpGroups: (node.fhrpGroups ?? []).map((x) =>
                            x.id === grp.id ? { ...x, priority: val ?? 100 } : x
                          ),
                        })
                      }
                    />
                    <Button
                      size="small"
                      danger
                      type="text"
                      className="col-span-1"
                      icon={<DeleteOutlined />}
                      onClick={() =>
                        updateNode(node.id, {
                          fhrpGroups: (node.fhrpGroups ?? []).filter((x) => x.id !== grp.id),
                        })
                      }
                    />
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      ),
    },
    {
      key: 'static',
      label: node.vendor === 'azure-cloud'
        ? `Azure UDRs (${node.staticRoutes.length})`
        : node.vendor === 'aws-cloud' || node.vendor === 'aws-cloudwan'
          ? `AWS Route Tables (${node.staticRoutes.length})`
          : node.vendor === 'gcp-cloud'
            ? `GCP VPC Routes (${node.staticRoutes.length})`
            : `Static & PBR (${node.staticRoutes.length + pbrRules.length})`,
      children: (
        <div className="space-y-3">
          <div className="space-y-1.5">
            <div className="text-[11px] font-semibold text-slate-300">
              {node.vendor === 'azure-cloud'
                ? 'Azure User Defined Routes (UDRs)'
                : node.vendor === 'aws-cloud' || node.vendor === 'aws-cloudwan'
                  ? 'AWS VPC / TGW Route Table Entries'
                  : node.vendor === 'gcp-cloud'
                    ? 'GCP VPC Custom & System Routes (Priority 0–65535)'
                    : 'Static Routes (IPv4 / IPv6)'}
            </div>
            {node.staticRoutes.map((sr) => (
              <div key={sr.id} className="grid grid-cols-12 items-center gap-1.5">
                <Select
                  size="small"
                  className="col-span-2"
                  value={sr.vrf || 'default'}
                  onChange={(val) =>
                    updateNode(node.id, {
                      staticRoutes: node.staticRoutes.map((x) =>
                        x.id === sr.id ? { ...x, vrf: val } : x
                      ),
                    })
                  }
                  options={vrfs.map((v) => ({ value: v, label: v }))}
                />
                <Input
                  size="small"
                  className="col-span-4"
                  value={sr.prefix}
                  onChange={(e) =>
                    updateNode(node.id, {
                      staticRoutes: node.staticRoutes.map((x) =>
                        x.id === sr.id ? { ...x, prefix: e.target.value } : x
                      ),
                    })
                  }
                  style={{ fontFamily: 'monospace' }}
                />
                <Input
                  size="small"
                  className="col-span-3"
                  value={sr.nextHop}
                  onChange={(e) =>
                    updateNode(node.id, {
                      staticRoutes: node.staticRoutes.map((x) =>
                        x.id === sr.id ? { ...x, nextHop: e.target.value } : x
                      ),
                    })
                  }
                  style={{ fontFamily: 'monospace' }}
                />
                <InputNumber
                  size="small"
                  className="col-span-2 !w-full"
                  placeholder="AD"
                  value={sr.ad ?? null}
                  onChange={(val) =>
                    updateNode(node.id, {
                      staticRoutes: node.staticRoutes.map((x) =>
                        x.id === sr.id ? { ...x, ad: val ?? undefined } : x
                      ),
                    })
                  }
                />
                <Button
                  size="small"
                  danger
                  type="text"
                  className="col-span-1"
                  icon={<DeleteOutlined />}
                  onClick={() =>
                    updateNode(node.id, {
                      staticRoutes: node.staticRoutes.filter((x) => x.id !== sr.id),
                    })
                  }
                />
                {node.vendor === 'azure-cloud' ? (
                  <Select
                    size="small"
                    className="col-span-5"
                    placeholder="Next-Hop Type"
                    value={sr.azureNextHopType ?? 'VirtualAppliance'}
                    onChange={(val) =>
                      updateNode(node.id, {
                        staticRoutes: node.staticRoutes.map((x) =>
                          x.id === sr.id
                            ? {
                              ...x,
                              azureNextHopType: val,
                              nextHop:
                                val === 'None'
                                  ? 'blackhole'
                                  : val === 'Internet'
                                    ? 'internet'
                                    : val === 'VnetLocal'
                                      ? '0.0.0.0'
                                      : x.nextHop,
                            }
                            : x
                        ),
                      })
                    }
                    options={[
                      { value: 'VirtualAppliance', label: 'VirtualAppliance (NVA)' },
                      { value: 'None', label: 'None (Drop / Blackhole)' },
                      { value: 'Internet', label: 'Internet (Direct Breakout)' },
                      { value: 'VnetLocal', label: 'VnetLocal' },
                      { value: 'VirtualNetworkGateway', label: 'VirtualNetworkGateway' },
                    ]}
                  />
                ) : node.vendor === 'aws-cloud' || node.vendor === 'aws-cloudwan' ? (
                  <Select
                    size="small"
                    className="col-span-5"
                    placeholder="AWS Target"
                    value={sr.awsTargetType ?? 'tgw'}
                    onChange={(val) =>
                      updateNode(node.id, {
                        staticRoutes: node.staticRoutes.map((x) =>
                          x.id === sr.id
                            ? {
                              ...x,
                              awsTargetType: val,
                              nextHop:
                                val === 'igw'
                                  ? 'igw'
                                  : val === 'nat'
                                    ? 'nat-gw'
                                    : val === 'blackhole'
                                      ? 'blackhole'
                                      : val === 'local'
                                        ? '0.0.0.0'
                                        : x.nextHop,
                            }
                            : x
                        ),
                      })
                    }
                    options={[
                      { value: 'igw', label: 'Internet Gateway (igw)' },
                      { value: 'nat', label: 'NAT Gateway (nat-gw)' },
                      { value: 'tgw', label: 'Transit Gateway (tgw)' },
                      { value: 'pcx', label: 'VPC Peering (pcx)' },
                      { value: 'vgw', label: 'VGW — DX / VPN (vgw)' },
                      { value: 'vpce', label: 'VPC Endpoint / NFW (vpce)' },
                      { value: 'blackhole', label: 'Blackhole (Drop)' },
                      { value: 'local', label: 'Local (Intra-VPC)' },
                    ]}
                  />
                ) : node.vendor === 'gcp-cloud' ? (
                  <Select
                    size="small"
                    className="col-span-5"
                    placeholder="GCP Next-Hop Type"
                    value={sr.gcpNextHopType ?? 'next-hop-address'}
                    onChange={(val) =>
                      updateNode(node.id, {
                        staticRoutes: node.staticRoutes.map((x) =>
                          x.id === sr.id
                            ? {
                              ...x,
                              gcpNextHopType: val,
                              nextHop:
                                val === 'default-internet-gateway'
                                  ? 'gcp-igw'
                                  : val === 'cloud-nat'
                                    ? 'gcp-nat'
                                    : x.nextHop,
                            }
                            : x
                        ),
                      })
                    }
                    options={[
                      { value: 'default-internet-gateway', label: 'Default Internet Gateway' },
                      { value: 'cloud-nat', label: 'Cloud NAT (Outbound SNAT)' },
                      { value: 'ilb', label: 'Internal Load Balancer (ILB)' },
                      { value: 'next-hop-address', label: 'Next-Hop IP (NVA)' },
                      { value: 'vpn-tunnel', label: 'Cloud VPN Tunnel' },
                      { value: 'interconnect', label: 'Cloud Interconnect' },
                      { value: 'vpc-peering', label: 'VPC Network Peering' },
                    ]}
                  />
                ) : (
                  <Select
                    size="small"
                    allowClear
                    className="col-span-5"
                    placeholder="Track Object (optional)"
                    value={sr.trackId}
                    onChange={(val) =>
                      updateNode(node.id, {
                        staticRoutes: node.staticRoutes.map((x) =>
                          x.id === sr.id ? { ...x, trackId: val || undefined } : x
                        ),
                      })
                    }
                    options={(node.tracks ?? []).map((t) => ({
                      value: t.id,
                      label: `Track ${t.id}: ${t.targetIp}`,
                    }))}
                  />
                )}
                <InputNumber
                  size="small"
                  className="col-span-2 !w-full"
                  placeholder="Tag"
                  min={0}
                  value={sr.tag ?? null}
                  onChange={(val) =>
                    updateNode(node.id, {
                      staticRoutes: node.staticRoutes.map((x) =>
                        x.id === sr.id ? { ...x, tag: val ?? undefined } : x
                      ),
                    })
                  }
                />
                <Input
                  size="small"
                  className="col-span-3"
                  placeholder="Out If / Null0"
                  value={sr.interfaceName ?? ''}
                  onChange={(e) =>
                    updateNode(node.id, {
                      staticRoutes: node.staticRoutes.map((x) =>
                        x.id === sr.id ? { ...x, interfaceName: e.target.value || undefined } : x
                      ),
                    })
                  }
                  style={{ fontFamily: 'monospace' }}
                />
                <label className="col-span-2 flex cursor-pointer items-center justify-end gap-1 text-[10px] text-slate-400" title="Global Next-Hop (VRF-to-Global leak)">
                  <Switch
                    size="small"
                    checked={Boolean(sr.globalNextHop)}
                    onChange={(checked) =>
                      updateNode(node.id, {
                        staticRoutes: node.staticRoutes.map((x) =>
                          x.id === sr.id ? { ...x, globalNextHop: checked || undefined } : x
                        ),
                      })
                    }
                  />
                  <span>Global</span>
                </label>
              </div>
            ))}
            <Button
              size="small"
              icon={<PlusOutlined />}
              onClick={() =>
                updateNode(node.id, {
                  staticRoutes: [
                    ...node.staticRoutes,
                    {
                      id: `sr-${Date.now()}`,
                      vrf: 'default',
                      prefix: '0.0.0.0/0',
                      nextHop: '10.0.0.1',
                    },
                  ],
                })
              }
            >
              Add Static Route
            </Button>
          </div>

          <div className="space-y-1.5 border-t border-slate-800 pt-2">
            <div className="text-[11px] font-semibold text-slate-300">
              IP SLA / Track Objects
            </div>
            {(node.tracks ?? []).map((t, idx) => (
              <div key={idx} className="grid grid-cols-12 items-center gap-1.5">
                <Input
                  key={`${node.id}-track-${idx}-${t.id}-${inputResetNonce}`}
                  size="small"
                  className="col-span-3"
                  placeholder="ID"
                  defaultValue={t.id}
                  onBlur={(e) => {
                    const nextTrackId = e.target.value.trim();
                    if (!nextTrackId) {
                      setInputResetNonce((n) => n + 1);
                      return;
                    }
                    if (nextTrackId === t.id) return;
                    if ((node.tracks ?? []).some((x, i) => i !== idx && x.id === nextTrackId)) {
                      setInputResetNonce((n) => n + 1);
                      return;
                    }
                    updateNode(node.id, {
                      tracks: (node.tracks ?? []).map((x, i) =>
                        i === idx ? { ...x, id: nextTrackId } : x
                      ),
                      staticRoutes: node.staticRoutes.map((sr) =>
                        sr.trackId === t.id ? { ...sr, trackId: nextTrackId } : sr
                      ),
                    });
                  }}
                  onPressEnter={(e) => (e.target as HTMLInputElement).blur()}
                />
                <Input
                  size="small"
                  className="col-span-5"
                  placeholder="Target IP"
                  value={t.targetIp}
                  onChange={(e) =>
                    updateNode(node.id, {
                      tracks: (node.tracks ?? []).map((x, i) =>
                        i === idx ? { ...x, targetIp: e.target.value } : x
                      ),
                    })
                  }
                />
                <Select
                  size="small"
                  className="col-span-3"
                  placeholder="VRF"
                  value={t.vrf ?? 'default'}
                  onChange={(val) =>
                    updateNode(node.id, {
                      tracks: (node.tracks ?? []).map((x, i) =>
                        i === idx ? { ...x, vrf: val || 'default' } : x
                      ),
                    })
                  }
                  options={Array.from(new Set([...vrfs, t.vrf ?? 'default'])).map((v) => ({
                    value: v,
                    label: v,
                  }))}
                />
                <Button
                  size="small"
                  danger
                  type="text"
                  className="col-span-1"
                  icon={<DeleteOutlined />}
                  onClick={() =>
                    updateNode(node.id, {
                      tracks: (node.tracks ?? []).filter((_, i) => i !== idx),
                      staticRoutes: node.staticRoutes.map((sr) =>
                        sr.trackId === t.id ? { ...sr, trackId: undefined } : sr
                      ),
                    })
                  }
                />
              </div>
            ))}
            <Button
              size="small"
              icon={<PlusOutlined />}
              onClick={() =>
                updateNode(node.id, {
                  tracks: [
                    ...(node.tracks ?? []),
                    {
                      id: String(Math.max(0, ...(node.tracks ?? []).map((t) => Number(t.id) || 0)) + 1),
                      targetIp: '8.8.8.8',
                      vrf: 'default',
                    },
                  ],
                })
              }
            >
              Add Track Object
            </Button>
          </div>

          <div className="space-y-1.5 border-t border-slate-800 pt-2">
            <div className="text-[11px] font-semibold text-emerald-300">
              {caps.pbrTitle}
            </div>
            {pbrRules.map((p) => (
              <div key={p.id} className="space-y-1 rounded border border-slate-800/80 bg-[#0b1120]/60 p-1.5">
                <div className="grid grid-cols-12 items-center gap-1">
                  <Input
                    size="small"
                    className="col-span-3"
                    value={p.name}
                    placeholder="Rule"
                    onChange={(e) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, name: e.target.value } : x
                        ),
                      })
                    }
                  />
                  <Input
                    size="small"
                    className="col-span-3"
                    value={p.srcCidr ?? ''}
                    placeholder="Src CIDR (any)"
                    style={{ fontFamily: 'monospace' }}
                    onChange={(e) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, srcCidr: e.target.value || undefined } : x
                        ),
                      })
                    }
                  />
                  <Input
                    size="small"
                    className="col-span-3"
                    value={p.matchPrefix}
                    placeholder="Dst CIDR"
                    style={{ fontFamily: 'monospace' }}
                    onChange={(e) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, matchPrefix: e.target.value } : x
                        ),
                      })
                    }
                  />
                  <Input
                    size="small"
                    className="col-span-2"
                    value={p.nextHop}
                    placeholder="Gateway"
                    style={{ fontFamily: 'monospace' }}
                    onChange={(e) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, nextHop: e.target.value } : x
                        ),
                      })
                    }
                  />
                  <Button
                    size="small"
                    danger
                    type="text"
                    className="col-span-1"
                    icon={<DeleteOutlined />}
                    onClick={() =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.filter((x) => x.id !== p.id),
                      })
                    }
                  />
                </div>
                <div className="grid grid-cols-12 items-center gap-1">
                  <Select
                    size="small"
                    allowClear
                    className="col-span-3"
                    placeholder="In If"
                    value={p.ingressInterface}
                    onChange={(val) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, ingressInterface: val || undefined } : x
                        ),
                      })
                    }
                    options={node.interfaces.map((i) => ({ value: i.name, label: `in: ${i.name}` }))}
                  />
                  <Select
                    size="small"
                    allowClear
                    className="col-span-3"
                    placeholder="Out If"
                    value={p.interfaceName}
                    onChange={(val) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, interfaceName: val || undefined } : x
                        ),
                      })
                    }
                    options={node.interfaces.map((i) => ({ value: i.name, label: `out: ${i.name}` }))}
                  />
                  <Select
                    size="small"
                    className="col-span-2"
                    value={p.protocol ?? 'any'}
                    onChange={(val) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, protocol: val } : x
                        ),
                      })
                    }
                    options={[
                      { value: 'any', label: 'any' },
                      { value: 'tcp', label: 'tcp' },
                      { value: 'udp', label: 'udp' },
                      { value: 'icmp', label: 'icmp' },
                    ]}
                  />
                  <InputNumber
                    size="small"
                    className="col-span-2 !w-full"
                    placeholder="Port"
                    min={1}
                    max={65535}
                    value={p.dstPort ?? null}
                    onChange={(val) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, dstPort: val ?? undefined } : x
                        ),
                      })
                    }
                  />
                  <Input
                    size="small"
                    className="col-span-2"
                    value={p.multiLinkPool ?? ''}
                    placeholder="Pool"
                    onChange={(e) =>
                      updateNode(node.id, {
                        pbrRules: pbrRules.map((x) =>
                          x.id === p.id ? { ...x, multiLinkPool: e.target.value || undefined } : x
                        ),
                      })
                    }
                  />
                </div>
              </div>
            ))}
            <Button
              size="small"
              icon={<PlusOutlined />}
              onClick={() =>
                updateNode(node.id, {
                  pbrRules: [
                    ...pbrRules,
                    {
                      id: `pbr-${Date.now()}`,
                      name: `PBR-${pbrRules.length + 1}`,
                      matchPrefix: '0.0.0.0/0',
                      nextHop: '10.1.13.1',
                      multiLinkPool: 'WAN-MULTI-LINK',
                    },
                  ],
                })
              }
            >
              Add PBR Rule
            </Button>
          </div>
        </div>
      ),
    },
    {
      key: 'protocols',
      label: 'Protocols',
      children: (
        <div className="space-y-2.5">
          {(caps.igps.ospf ||
            caps.igps.eigrp ||
            caps.igps.isis ||
            caps.igps.rip ||
            node.ospf.enabled ||
            node.eigrp?.enabled ||
            node.isis?.enabled ||
            node.rip?.enabled) && (
            <Card size="small">
              <div className="flex flex-wrap items-center justify-between gap-2">
                {(caps.igps.ospf || node.ospf.enabled) && (
                  <Space>
                    <span className="font-semibold text-emerald-300">OSPF</span>
                    <Switch
                      size="small"
                      checked={node.ospf.enabled}
                      onChange={(checked) =>
                        updateNode(node.id, { ospf: { ...node.ospf, enabled: checked } })
                      }
                    />
                  </Space>
                )}
                {(caps.igps.eigrp || node.eigrp?.enabled) && (
                  <Space>
                    <span className="font-semibold text-sky-300">EIGRP</span>
                    <InputNumber
                      size="small"
                      style={{ width: 68 }}
                      value={node.eigrp?.asn ?? 100}
                      onChange={(val) =>
                        updateNode(node.id, {
                          eigrp: {
                            ...(node.eigrp ?? {}),
                            enabled: node.eigrp?.enabled ?? false,
                            asn: val ?? 100,
                            networks: node.eigrp?.networks ?? [],
                          },
                        })
                      }
                    />
                    <Switch
                      size="small"
                      checked={node.eigrp?.enabled ?? false}
                      onChange={(checked) =>
                        updateNode(node.id, {
                          eigrp: {
                            ...(node.eigrp ?? {}),
                            enabled: checked,
                            asn: node.eigrp?.asn ?? 100,
                            networks: node.eigrp?.networks ?? [],
                          },
                        })
                      }
                    />
                  </Space>
                )}
                {(caps.igps.isis || node.isis?.enabled) && (
                  <Space>
                    <span className="font-semibold text-amber-300">IS-IS</span>
                    <Select
                      size="small"
                      style={{ width: 78 }}
                      value={node.isis?.level ?? 'L1-L2'}
                      onChange={(val) =>
                        updateNode(node.id, {
                          isis: {
                            ...(node.isis ?? {}),
                            enabled: node.isis?.enabled ?? false,
                            level: val,
                            networks: node.isis?.networks ?? [],
                          },
                        })
                      }
                      options={[
                        { value: 'L1', label: 'L1' },
                        { value: 'L2', label: 'L2' },
                        { value: 'L1-L2', label: 'L1-L2' },
                      ]}
                    />
                    <Switch
                      size="small"
                      checked={node.isis?.enabled ?? false}
                      onChange={(checked) =>
                        updateNode(node.id, {
                          isis: {
                            ...(node.isis ?? {}),
                            enabled: checked,
                            net: node.isis?.net,
                            level: node.isis?.level ?? 'L1-L2',
                            networks: node.isis?.networks ?? [],
                          },
                        })
                      }
                    />
                  </Space>
                )}
                {(caps.igps.rip || node.rip?.enabled) && (
                  <Space>
                    <span className="font-semibold text-teal-300">RIP</span>
                    <Switch
                      size="small"
                      checked={node.rip?.enabled ?? false}
                      onChange={(checked) =>
                        updateNode(node.id, {
                          rip: {
                            enabled: checked,
                            version: node.rip?.version ?? 2,
                            defaultOriginate: node.rip?.defaultOriginate,
                            networks: node.rip?.networks ?? [],
                          },
                        })
                      }
                    />
                  </Space>
                )}
              </div>
              {node.ospf.enabled && (
                <div className="mt-2.5 space-y-2 border-t border-slate-800 pt-2">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                    <label className="flex cursor-pointer items-center gap-1.5 text-slate-300">
                      <Switch
                        size="small"
                        checked={Boolean(node.ospf.defaultOriginate)}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            ospf: { ...node.ospf, defaultOriginate: checked },
                          })
                        }
                      />
                      <span>default-information originate</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1.5 text-slate-300">
                      <Switch
                        size="small"
                        checked={Boolean(node.ospf.bfd)}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            ospf: { ...node.ospf, bfd: checked },
                          })
                        }
                      />
                      <span>BFD</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1.5 text-slate-300">
                      <Switch
                        size="small"
                        checked={Boolean(node.ospf.maxMetricRouterLsa)}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            ospf: { ...node.ospf, maxMetricRouterLsa: checked },
                          })
                        }
                      />
                      <span>max-metric</span>
                    </label>
                    {['cisco-ios-xe', 'cisco-nx-os', 'cisco-ios-xr', 'arista-eos', 'aruba-aos-cx', 'juniper-junos', 'mikrotik-routeros', 'forcepoint-ngfw', 'fortigate', 'checkpoint-gaia', 'vyos'].includes(
                      node.vendor
                    ) && (
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-400">Ref BW (Mbps)</span>
                          <InputNumber
                            size="small"
                            min={1}
                            placeholder="100"
                            style={{ width: 78 }}
                            value={node.ospf.referenceBandwidth ?? null}
                            onChange={(val) =>
                              updateNode(node.id, {
                                ospf: { ...node.ospf, referenceBandwidth: val ?? undefined },
                              })
                            }
                          />
                        </div>
                      )}
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <div className="mb-0.5 text-slate-400">OSPF Auth Key</div>
                      <Input
                        size="small"
                        placeholder="Optional process auth key"
                        value={node.ospf.authKey ?? ''}
                        onChange={(e) =>
                          updateNode(node.id, {
                            ospf: { ...node.ospf, authKey: e.target.value || undefined },
                          })
                        }
                      />
                    </div>
                    <div className="space-y-1.5">
                      {(() => {
                        const nonBackboneAreas = Array.from(
                          new Set([
                            ...node.interfaces
                              .map((i) => i.ospfArea)
                              .filter((a): a is number => a !== undefined && a !== 0),
                            ...node.ospf.networks
                              .map((n) => n.area)
                              .filter((a) => a !== 0),
                            ...Object.keys(node.ospf.areaTypes ?? {})
                              .map(Number)
                              .filter((a) => Number.isFinite(a) && a !== 0),
                          ])
                        ).sort((a, b) => a - b);
                        const areasToShow = nonBackboneAreas.length ? nonBackboneAreas : [1];
                        return areasToShow.map((areaId) => (
                          <div key={areaId}>
                            <div className="mb-0.5 text-slate-400">Area {areaId} Type</div>
                            <Select
                              size="small"
                              className="w-full"
                              value={node.ospf.areaTypes?.[areaId] ?? 'normal'}
                              onChange={(val) =>
                                updateNode(node.id, {
                                  ospf: {
                                    ...node.ospf,
                                    areaTypes: { ...(node.ospf.areaTypes ?? {}), [areaId]: val },
                                  },
                                })
                              }
                              options={[
                                { value: 'normal', label: 'Normal' },
                                { value: 'stub', label: 'Stub' },
                                { value: 'totally-stubby', label: 'Totally Stubby' },
                                { value: 'nssa', label: 'NSSA' },
                              ]}
                            />
                            {node.ospf.areaTypes?.[areaId] === 'nssa' && (
                              <label className="mt-1 flex cursor-pointer items-center gap-1.5 text-[10px] text-slate-300">
                                <Switch
                                  size="small"
                                  checked={Boolean(node.ospf.nssaNoSummary?.[areaId])}
                                  onChange={(checked) =>
                                    updateNode(node.id, {
                                      ospf: {
                                        ...node.ospf,
                                        nssaNoSummary: { ...(node.ospf.nssaNoSummary ?? {}), [areaId]: checked },
                                      },
                                    })
                                  }
                                />
                                <span>Area {areaId} NSSA no-summary</span>
                              </label>
                            )}
                          </div>
                        ));
                      })()}
                    </div>
                  </div>
                  <div>
                    <div className="mb-1 text-[11px] text-slate-400">
                      OSPF Area Ranges &amp; Virtual Links
                    </div>
                    <div className="space-y-1.5">
                      {(node.ospf.areaRanges ?? []).map((ar) => (
                        <div key={ar.id} className="grid grid-cols-12 gap-1">
                          <InputNumber
                            size="small"
                            className="col-span-3 !w-full"
                            placeholder="Area"
                            value={ar.area}
                            onChange={(val) =>
                              updateNode(node.id, {
                                ospf: {
                                  ...node.ospf,
                                  areaRanges: (node.ospf.areaRanges ?? []).map((x) =>
                                    x.id === ar.id ? { ...x, area: Number(val ?? 0) } : x
                                  ),
                                },
                              })
                            }
                          />
                          <Input
                            size="small"
                            className="col-span-8"
                            placeholder="Summary CIDR"
                            value={ar.prefix}
                            onChange={(e) =>
                              updateNode(node.id, {
                                ospf: {
                                  ...node.ospf,
                                  areaRanges: (node.ospf.areaRanges ?? []).map((x) =>
                                    x.id === ar.id ? { ...x, prefix: e.target.value } : x
                                  ),
                                },
                              })
                            }
                          />
                          <Button
                            size="small"
                            danger
                            type="text"
                            className="col-span-1"
                            icon={<DeleteOutlined />}
                            onClick={() =>
                              updateNode(node.id, {
                                ospf: {
                                  ...node.ospf,
                                  areaRanges: (node.ospf.areaRanges ?? []).filter((x) => x.id !== ar.id),
                                },
                              })
                            }
                          />
                        </div>
                      ))}
                      <Button
                        size="small"
                        icon={<PlusOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            ospf: {
                              ...node.ospf,
                              areaRanges: [
                                ...(node.ospf.areaRanges ?? []),
                                { id: `oar-${Date.now()}`, area: 1, prefix: '10.1.0.0/16' },
                              ],
                            },
                          })
                        }
                      >
                        Add Area Range
                      </Button>
                      {(node.ospf.virtualLinks ?? []).map((vl) => (
                        <div key={vl.id} className="grid grid-cols-12 gap-1">
                          <InputNumber
                            size="small"
                            className="col-span-3 !w-full"
                            placeholder="Transit"
                            value={vl.transitArea}
                            onChange={(val) =>
                              updateNode(node.id, {
                                ospf: {
                                  ...node.ospf,
                                  virtualLinks: (node.ospf.virtualLinks ?? []).map((x) =>
                                    x.id === vl.id ? { ...x, transitArea: Number(val ?? 1) } : x
                                  ),
                                },
                              })
                            }
                          />
                          <Input
                            size="small"
                            className="col-span-8"
                            placeholder="Peer Router-ID"
                            value={vl.peerRouterId}
                            onChange={(e) =>
                              updateNode(node.id, {
                                ospf: {
                                  ...node.ospf,
                                  virtualLinks: (node.ospf.virtualLinks ?? []).map((x) =>
                                    x.id === vl.id ? { ...x, peerRouterId: e.target.value } : x
                                  ),
                                },
                              })
                            }
                          />
                          <Button
                            size="small"
                            danger
                            type="text"
                            className="col-span-1"
                            icon={<DeleteOutlined />}
                            onClick={() =>
                              updateNode(node.id, {
                                ospf: {
                                  ...node.ospf,
                                  virtualLinks: (node.ospf.virtualLinks ?? []).filter((x) => x.id !== vl.id),
                                },
                              })
                            }
                          />
                        </div>
                      ))}
                      <Button
                        size="small"
                        icon={<PlusOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            ospf: {
                              ...node.ospf,
                              virtualLinks: [
                                ...(node.ospf.virtualLinks ?? []),
                                { id: `ovl-${Date.now()}`, transitArea: 1, peerRouterId: '2.2.2.2' },
                              ],
                            },
                          })
                        }
                      >
                        Add Virtual Link
                      </Button>
                    </div>
                  </div>
                  <div>
                    <div className="mb-1 text-[11px] text-slate-400">
                      OSPF Passive Interfaces
                    </div>
                    <Select
                      mode="multiple"
                      size="small"
                      className="w-full"
                      placeholder="Select passive interfaces (suppresses OSPF hello)"
                      value={node.interfaces.filter((i) => i.passive).map((i) => i.id)}
                      onChange={(selectedIds: string[]) => {
                        const set = new Set(selectedIds);
                        updateNode(node.id, {
                          interfaces: node.interfaces.map((i) => ({
                            ...i,
                            passive: set.has(i.id),
                          })),
                        });
                      }}
                      options={node.interfaces.map((i) => ({
                        value: i.id,
                        label: `${i.name} (${i.cidr})`,
                      }))}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-semibold text-emerald-300">
                    <span>OSPF Network Advertisements</span>
                    <Button
                      size="small"
                      icon={<PlusOutlined />}
                      onClick={() =>
                        updateNode(node.id, {
                          ospf: {
                            ...node.ospf,
                            networks: [
                              ...node.ospf.networks,
                              {
                                id: `ospf-net-${Date.now()}`,
                                prefix: '10.0.0.0/24',
                                area: 0,
                                vrf: 'default',
                              },
                            ],
                          },
                        })
                      }
                    >
                      Add Network
                    </Button>
                  </div>
                  {node.ospf.networks.map((on) => (
                    <div key={on.id} className="grid grid-cols-12 items-center gap-1">
                      <Input
                        size="small"
                        className="col-span-5"
                        value={on.prefix}
                        placeholder="10.0.0.0/24"
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            ospf: {
                              ...node.ospf,
                              networks: node.ospf.networks.map((x) =>
                                x.id === on.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        min={0}
                        placeholder="Area"
                        value={on.area}
                        onChange={(val) =>
                          updateNode(node.id, {
                            ospf: {
                              ...node.ospf,
                              networks: node.ospf.networks.map((x) =>
                                x.id === on.id ? { ...x, area: val ?? 0 } : x
                              ),
                            },
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        min={1}
                        placeholder="Cost"
                        value={on.cost ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            ospf: {
                              ...node.ospf,
                              networks: node.ospf.networks.map((x) =>
                                x.id === on.id ? { ...x, cost: val ?? undefined } : x
                              ),
                            },
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-2"
                        value={on.vrf || 'default'}
                        onChange={(val) =>
                          updateNode(node.id, {
                            ospf: {
                              ...node.ospf,
                              networks: node.ospf.networks.map((x) =>
                                x.id === on.id ? { ...x, vrf: val } : x
                              ),
                            },
                          })
                        }
                        options={vrfs.map((v) => ({ value: v, label: v }))}
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            ospf: {
                              ...node.ospf,
                              networks: node.ospf.networks.filter((x) => x.id !== on.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                </div>
              )}

              {node.eigrp?.enabled && (
                <div className="mt-2.5 space-y-1.5 border-t border-slate-800 pt-2">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-semibold text-sky-300">EIGRP Network Advertisements</span>
                    <div className="flex items-center gap-2">
                      <div className="flex items-center gap-1 text-[11px]">
                        <span className="text-slate-400">Var</span>
                        <InputNumber
                          size="small"
                          min={1}
                          max={128}
                          style={{ width: 52 }}
                          value={node.eigrp?.variance ?? 1}
                          onChange={(val) =>
                            updateNode(node.id, {
                              eigrp: {
                                ...(node.eigrp ?? {}),
                                enabled: true,
                                asn: node.eigrp?.asn ?? 100,
                                networks: node.eigrp?.networks ?? [],
                                variance: val ?? 1,
                              },
                            })
                          }
                        />
                      </div>
                      <div className="flex items-center gap-1 text-[11px]" title="EIGRP K-values (K1,K2,K3,K4,K5)">
                        <span className="text-slate-400">K:</span>
                        <Input
                          key={`${node.id}-${(node.eigrp?.kValues ?? [1, 0, 1, 0, 0]).join(',')}-${inputResetNonce}`}
                          size="small"
                          style={{ width: 84, fontFamily: 'monospace' }}
                          placeholder="1,0,1,0,0"
                          defaultValue={(node.eigrp?.kValues ?? [1, 0, 1, 0, 0]).join(',')}
                          onBlur={(e) => {
                            const parts = e.target.value.split(/[,\s]+/).filter(Boolean).map(Number);
                            if (parts.length === 5 && parts.every((n) => Number.isFinite(n) && n >= 0 && n <= 255)) {
                              updateNode(node.id, {
                                eigrp: {
                                  ...(node.eigrp ?? {}),
                                  enabled: true,
                                  asn: node.eigrp?.asn ?? 100,
                                  networks: node.eigrp?.networks ?? [],
                                  kValues: parts as [number, number, number, number, number],
                                },
                              });
                            } else {
                              setInputResetNonce((n) => n + 1);
                            }
                          }}
                          onPressEnter={(e) => (e.target as HTMLInputElement).blur()}
                        />
                      </div>
                      <label className="flex cursor-pointer items-center gap-1 text-slate-300">
                        <Switch
                          size="small"
                          checked={Boolean(node.eigrp?.bfd)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              eigrp: {
                                ...(node.eigrp ?? {}),
                                enabled: true,
                                asn: node.eigrp?.asn ?? 100,
                                networks: node.eigrp?.networks ?? [],
                                bfd: checked,
                              },
                            })
                          }
                        />
                        <span>BFD</span>
                      </label>
                      <Button
                        size="small"
                        icon={<PlusOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            eigrp: {
                              ...(node.eigrp ?? {}),
                              enabled: true,
                              asn: node.eigrp?.asn ?? 100,
                              networks: [
                                ...(node.eigrp?.networks ?? []),
                                {
                                  id: `eigrp-net-${Date.now()}`,
                                  prefix: '10.20.0.0/24',
                                  vrf: 'default',
                                },
                              ],
                            },
                          })
                        }
                      >
                        Add Network
                      </Button>
                    </div>
                  </div>
                  {(node.eigrp?.networks ?? []).map((en) => (
                    <div key={en.id} className="grid grid-cols-12 items-center gap-1">
                      <Input
                        size="small"
                        className="col-span-5"
                        value={en.prefix}
                        placeholder="10.20.0.0/24"
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            eigrp: {
                              ...(node.eigrp ?? {}),
                              enabled: true,
                              asn: node.eigrp?.asn ?? 100,
                              networks: (node.eigrp?.networks ?? []).map((x) =>
                                x.id === en.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        min={1}
                        placeholder="BW"
                        value={en.bandwidth ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            eigrp: {
                              ...(node.eigrp ?? {}),
                              enabled: true,
                              asn: node.eigrp?.asn ?? 100,
                              networks: (node.eigrp?.networks ?? []).map((x) =>
                                x.id === en.id ? { ...x, bandwidth: val ?? undefined } : x
                              ),
                            },
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        min={1}
                        placeholder="Dly"
                        value={en.delay ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            eigrp: {
                              ...(node.eigrp ?? {}),
                              enabled: true,
                              asn: node.eigrp?.asn ?? 100,
                              networks: (node.eigrp?.networks ?? []).map((x) =>
                                x.id === en.id ? { ...x, delay: val ?? undefined } : x
                              ),
                            },
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-2"
                        value={en.vrf || 'default'}
                        onChange={(val) =>
                          updateNode(node.id, {
                            eigrp: {
                              ...(node.eigrp ?? {}),
                              enabled: true,
                              asn: node.eigrp?.asn ?? 100,
                              networks: (node.eigrp?.networks ?? []).map((x) =>
                                x.id === en.id ? { ...x, vrf: val } : x
                              ),
                            },
                          })
                        }
                        options={vrfs.map((v) => ({ value: v, label: v }))}
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            eigrp: {
                              ...(node.eigrp ?? { enabled: true, asn: 100 }),
                              enabled: true,
                              asn: node.eigrp?.asn ?? 100,
                              networks: (node.eigrp?.networks ?? []).filter((x) => x.id !== en.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                  {(node.eigrp?.summaries ?? []).map((s) => (
                    <div key={s.id} className="flex items-center gap-1">
                      <Input
                        size="small"
                        placeholder="EIGRP Summary CIDR"
                        value={s.prefix}
                        onChange={(e) =>
                          updateNode(node.id, {
                            eigrp: {
                              ...node.eigrp!,
                              summaries: (node.eigrp?.summaries ?? []).map((x) =>
                                x.id === s.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            eigrp: {
                              ...node.eigrp!,
                              summaries: (node.eigrp?.summaries ?? []).filter((x) => x.id !== s.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                  <Button
                    size="small"
                    icon={<PlusOutlined />}
                    onClick={() =>
                      updateNode(node.id, {
                        eigrp: {
                          ...node.eigrp!,
                          summaries: [
                            ...(node.eigrp?.summaries ?? []),
                            { id: `esum-${Date.now()}`, prefix: '10.10.0.0/16' },
                          ],
                        },
                      })
                    }
                  >
                    Add EIGRP Summary
                  </Button>
                </div>
              )}

              {node.isis?.enabled && (
                <div className="mt-2.5 space-y-1.5 border-t border-slate-800 pt-2">
                  <div className="flex items-center gap-2 text-[11px]">
                    <span className="text-slate-400">IS-IS NET</span>
                    <Input
                      size="small"
                      className="flex-1"
                      placeholder="49.0001.0000.0000.0001.00"
                      style={{ fontFamily: 'monospace' }}
                      value={node.isis?.net ?? ''}
                      onChange={(e) =>
                        updateNode(node.id, {
                          isis: {
                            ...(node.isis ?? { level: 'L1-L2', networks: [] }),
                            enabled: true,
                            net: e.target.value,
                          },
                        })
                      }
                    />
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-[11px]">
                    <label className="flex cursor-pointer items-center gap-1 text-slate-300">
                      <Switch
                        size="small"
                        checked={Boolean(node.isis?.overloadBit)}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            isis: { ...(node.isis ?? { level: 'L1-L2', networks: [] }), enabled: true, overloadBit: checked },
                          })
                        }
                      />
                      <span>Overload Bit</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1 text-slate-300">
                      <Switch
                        size="small"
                        checked={Boolean(node.isis?.multiTopologyV6)}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            isis: { ...(node.isis ?? { level: 'L1-L2', networks: [] }), enabled: true, multiTopologyV6: checked },
                          })
                        }
                      />
                      <span>IPv6 MT</span>
                    </label>
                    <Select
                      size="small"
                      style={{ width: 96 }}
                      value={node.isis?.metricStyle ?? 'wide'}
                      onChange={(val) =>
                        updateNode(node.id, {
                          isis: { ...(node.isis ?? { level: 'L1-L2', networks: [] }), enabled: true, metricStyle: val },
                        })
                      }
                      options={[
                        { value: 'wide', label: 'Wide Met' },
                        { value: 'narrow', label: 'Narrow' },
                      ]}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-semibold text-amber-300">IS-IS Network Advertisements</span>
                    <div className="flex items-center gap-2">
                      <label className="flex cursor-pointer items-center gap-1 text-slate-300">
                        <Switch
                          size="small"
                          checked={Boolean(node.isis?.bfd)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              isis: {
                                enabled: true,
                                level: node.isis?.level ?? 'L1-L2',
                                networks: node.isis?.networks ?? [],
                                ...node.isis,
                                bfd: checked,
                              },
                            })
                          }
                        />
                        <span>BFD</span>
                      </label>
                      <Button
                        size="small"
                        icon={<PlusOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            isis: {
                              ...(node.isis ?? { level: 'L1-L2' }),
                              enabled: true,
                              networks: [
                                ...(node.isis?.networks ?? []),
                                {
                                  id: `isis-net-${Date.now()}`,
                                  prefix: '10.30.0.0/24',
                                  level: node.isis?.level === 'L1' ? 'L1' : 'L2',
                                  vrf: 'default',
                                },
                              ],
                            },
                          })
                        }
                      >
                        Add Network
                      </Button>
                    </div>
                  </div>
                  {(node.isis?.networks ?? []).map((inw) => (
                    <div key={inw.id} className="grid grid-cols-12 items-center gap-1">
                      <Input
                        size="small"
                        className="col-span-5"
                        value={inw.prefix}
                        placeholder="10.30.0.0/24"
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            isis: {
                              ...(node.isis ?? { level: 'L1-L2' }),
                              enabled: true,
                              networks: (node.isis?.networks ?? []).map((x) =>
                                x.id === inw.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-2"
                        value={inw.level ?? 'L2'}
                        onChange={(val) =>
                          updateNode(node.id, {
                            isis: {
                              ...(node.isis ?? { level: 'L1-L2' }),
                              enabled: true,
                              networks: (node.isis?.networks ?? []).map((x) =>
                                x.id === inw.id ? { ...x, level: val } : x
                              ),
                            },
                          })
                        }
                        options={[
                          { value: 'L1', label: 'L1' },
                          { value: 'L2', label: 'L2' },
                        ]}
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        min={1}
                        placeholder="Met"
                        value={inw.metric ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            isis: {
                              ...(node.isis ?? { level: 'L1-L2' }),
                              enabled: true,
                              networks: (node.isis?.networks ?? []).map((x) =>
                                x.id === inw.id ? { ...x, metric: val ?? undefined } : x
                              ),
                            },
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-2"
                        value={inw.vrf || 'default'}
                        onChange={(val) =>
                          updateNode(node.id, {
                            isis: {
                              ...(node.isis ?? { level: 'L1-L2' }),
                              enabled: true,
                              networks: (node.isis?.networks ?? []).map((x) =>
                                x.id === inw.id ? { ...x, vrf: val } : x
                              ),
                            },
                          })
                        }
                        options={vrfs.map((v) => ({ value: v, label: v }))}
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            isis: {
                              ...(node.isis ?? { level: 'L1-L2' }),
                              enabled: true,
                              networks: (node.isis?.networks ?? []).filter((x) => x.id !== inw.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                  {(node.isis?.summaries ?? []).map((s) => (
                    <div key={s.id} className="flex items-center gap-1">
                      <Input
                        size="small"
                        placeholder="IS-IS Summary CIDR"
                        value={s.prefix}
                        onChange={(e) =>
                          updateNode(node.id, {
                            isis: {
                              ...node.isis!,
                              summaries: (node.isis?.summaries ?? []).map((x) =>
                                x.id === s.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            isis: {
                              ...node.isis!,
                              summaries: (node.isis?.summaries ?? []).filter((x) => x.id !== s.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                  <Button
                    size="small"
                    icon={<PlusOutlined />}
                    onClick={() =>
                      updateNode(node.id, {
                        isis: {
                          ...node.isis!,
                          summaries: [
                            ...(node.isis?.summaries ?? []),
                            { id: `isum-${Date.now()}`, prefix: '10.20.0.0/16' },
                          ],
                        },
                      })
                    }
                  >
                    Add IS-IS Summary
                  </Button>
                  {node.isis?.level === 'L1-L2' && (
                    <div className="space-y-1 pt-1">
                      {(node.isis?.leakL2ToL1 ?? []).map((lk) => (
                        <div key={lk.id} className="flex items-center gap-1">
                          <Input
                            size="small"
                            placeholder="L2→L1 Leak CIDR"
                            value={lk.prefix}
                            style={{ fontFamily: 'monospace' }}
                            onChange={(e) =>
                              updateNode(node.id, {
                                isis: {
                                  ...node.isis!,
                                  leakL2ToL1: (node.isis?.leakL2ToL1 ?? []).map((x) =>
                                    x.id === lk.id ? { ...x, prefix: e.target.value } : x
                                  ),
                                },
                              })
                            }
                          />
                          <Button
                            size="small"
                            danger
                            type="text"
                            icon={<DeleteOutlined />}
                            onClick={() =>
                              updateNode(node.id, {
                                isis: {
                                  ...node.isis!,
                                  leakL2ToL1: (node.isis?.leakL2ToL1 ?? []).filter((x) => x.id !== lk.id),
                                },
                              })
                            }
                          />
                        </div>
                      ))}
                      <Button
                        size="small"
                        icon={<PlusOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            isis: {
                              ...node.isis!,
                              leakL2ToL1: [
                                ...(node.isis?.leakL2ToL1 ?? []),
                                { id: `ileak-${Date.now()}`, prefix: '10.0.0.0/8' },
                              ],
                            },
                          })
                        }
                      >
                        Add L2→L1 Leak
                      </Button>
                    </div>
                  )}
                </div>
              )}

              {node.rip?.enabled && (
                <div className="mt-2.5 space-y-1.5 border-t border-slate-800 pt-2">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                    <label className="flex cursor-pointer items-center gap-1.5 text-slate-300">
                      <Switch
                        size="small"
                        checked={Boolean(node.rip.defaultOriginate)}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            rip: {
                              enabled: true,
                              version: node.rip?.version ?? 2,
                              defaultOriginate: checked,
                              networks: node.rip?.networks ?? [],
                            },
                          })
                        }
                      />
                      <span>default-information originate</span>
                    </label>
                    <Select
                      size="small"
                      style={{ width: 82 }}
                      value={node.rip?.version ?? 2}
                      onChange={(val) =>
                        updateNode(node.id, {
                          rip: {
                            enabled: true,
                            version: val,
                            defaultOriginate: node.rip?.defaultOriginate,
                            networks: node.rip?.networks ?? [],
                          },
                        })
                      }
                      options={[
                        { value: 1, label: 'RIPv1' },
                        { value: 2, label: 'RIPv2' },
                      ]}
                    />
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-semibold text-teal-300">
                    <span>RIPv{node.rip?.version ?? 2} Network Advertisements</span>
                    <Button
                      size="small"
                      icon={<PlusOutlined />}
                      onClick={() =>
                        updateNode(node.id, {
                          rip: {
                            enabled: true,
                            version: node.rip?.version ?? 2,
                            defaultOriginate: node.rip?.defaultOriginate,
                            networks: [
                              ...(node.rip?.networks ?? []),
                              {
                                id: `rip-net-${Date.now()}`,
                                prefix: '10.40.0.0/24',
                                vrf: 'default',
                              },
                            ],
                          },
                        })
                      }
                    >
                      Add Network
                    </Button>
                  </div>
                  {(node.rip?.networks ?? []).map((rn) => (
                    <div key={rn.id} className="grid grid-cols-12 items-center gap-1">
                      <Input
                        size="small"
                        className="col-span-7"
                        value={rn.prefix}
                        placeholder="10.40.0.0/24"
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            rip: {
                              enabled: true,
                              version: node.rip?.version ?? 2,
                              defaultOriginate: node.rip?.defaultOriginate,
                              networks: (node.rip?.networks ?? []).map((x) =>
                                x.id === rn.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-4"
                        value={rn.vrf || 'default'}
                        onChange={(val) =>
                          updateNode(node.id, {
                            rip: {
                              enabled: true,
                              version: node.rip?.version ?? 2,
                              defaultOriginate: node.rip?.defaultOriginate,
                              networks: (node.rip?.networks ?? []).map((x) =>
                                x.id === rn.id ? { ...x, vrf: val } : x
                              ),
                            },
                          })
                        }
                        options={vrfs.map((v) => ({ value: v, label: v }))}
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            rip: {
                              enabled: true,
                              version: node.rip?.version ?? 2,
                              defaultOriginate: node.rip?.defaultOriginate,
                              networks: (node.rip?.networks ?? []).filter((x) => x.id !== rn.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}

          {(node.vendor === 'cisco-nx-os' || Boolean(node.vpc?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-cyan-300">NX-OS vPC Domain</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.vpc?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      vpc: {
                        domainId: node.vpc?.domainId ?? 1,
                        ...node.vpc,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.vpc?.enabled && (
                <div className="space-y-2 text-[11px]">
                  <div className="grid grid-cols-3 gap-1.5">
                    <div>
                      <div className="mb-0.5 text-slate-400">Domain ID</div>
                      <InputNumber
                        size="small"
                        className="!w-full"
                        min={1}
                        max={1000}
                        value={node.vpc.domainId}
                        onChange={(val) =>
                          updateNode(node.id, { vpc: { ...node.vpc!, domainId: val ?? 1 } })
                        }
                      />
                    </div>
                    <div>
                      <div className="mb-0.5 text-slate-400">Role Prio</div>
                      <InputNumber
                        size="small"
                        className="!w-full"
                        placeholder="32667"
                        value={node.vpc.rolePriority ?? null}
                        onChange={(val) =>
                          updateNode(node.id, { vpc: { ...node.vpc!, rolePriority: val ?? undefined } })
                        }
                      />
                    </div>
                    <div>
                      <div className="mb-0.5 text-slate-400">Sys Prio</div>
                      <InputNumber
                        size="small"
                        className="!w-full"
                        placeholder="32667"
                        value={node.vpc.systemPriority ?? null}
                        onChange={(val) =>
                          updateNode(node.id, { vpc: { ...node.vpc!, systemPriority: val ?? undefined } })
                        }
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-12 gap-1.5">
                    <Input
                      size="small"
                      className="col-span-5"
                      placeholder="Keepalive Dst IP"
                      value={node.vpc.peerKeepaliveDst ?? ''}
                      onChange={(e) =>
                        updateNode(node.id, {
                          vpc: { ...node.vpc!, peerKeepaliveDst: e.target.value || undefined },
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-4"
                      placeholder="Keepalive Src"
                      value={node.vpc.peerKeepaliveSrc ?? ''}
                      onChange={(e) =>
                        updateNode(node.id, {
                          vpc: { ...node.vpc!, peerKeepaliveSrc: e.target.value || undefined },
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-3"
                      placeholder="VRF (mgmt)"
                      value={node.vpc.peerKeepaliveVrf ?? ''}
                      onChange={(e) =>
                        updateNode(node.id, {
                          vpc: { ...node.vpc!, peerKeepaliveVrf: e.target.value || undefined },
                        })
                      }
                    />
                  </div>
                  <div className="grid grid-cols-12 gap-1.5">
                    <Select
                      size="small"
                      allowClear
                      className="col-span-8"
                      placeholder="Select vPC Peer-Link Interface"
                      value={node.vpc.peerLinkInterfaceId}
                      onChange={(val) =>
                        updateNode(node.id, {
                          vpc: { ...node.vpc!, peerLinkInterfaceId: val || undefined },
                        })
                      }
                      options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                    />
                    <InputNumber
                      size="small"
                      className="col-span-4 !w-full"
                      placeholder="Delay Restore (s)"
                      value={node.vpc.delayRestore ?? null}
                      onChange={(val) =>
                        updateNode(node.id, {
                          vpc: { ...node.vpc!, delayRestore: val ?? undefined },
                        })
                      }
                    />
                  </div>
                  <div className="flex flex-wrap gap-x-3 gap-y-1.5 pt-1 text-slate-300">
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.vpc.peerGateway)}
                        onChange={(checked) =>
                          updateNode(node.id, { vpc: { ...node.vpc!, peerGateway: checked } })
                        }
                      />
                      <span>peer-gateway</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.vpc.peerSwitch)}
                        onChange={(checked) =>
                          updateNode(node.id, { vpc: { ...node.vpc!, peerSwitch: checked } })
                        }
                      />
                      <span>peer-switch</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.vpc.layer3PeerRouter)}
                        onChange={(checked) =>
                          updateNode(node.id, { vpc: { ...node.vpc!, layer3PeerRouter: checked } })
                        }
                      />
                      <span>layer3 peer-router</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.vpc.autoRecovery)}
                        onChange={(checked) =>
                          updateNode(node.id, { vpc: { ...node.vpc!, autoRecovery: checked } })
                        }
                      />
                      <span>auto-recovery</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.vpc.ipArpSynchronize)}
                        onChange={(checked) =>
                          updateNode(node.id, { vpc: { ...node.vpc!, ipArpSynchronize: checked } })
                        }
                      />
                      <span>ip arp synchronize</span>
                    </label>
                  </div>
                </div>
              )}
            </Card>
          )}

          {(node.vendor === 'pan-os' || Boolean(node.panHa?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-amber-300">PAN-OS HA &amp; HSCI Session Peering</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.panHa?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      panHa: {
                        mode: node.panHa?.mode ?? 'active-passive',
                        groupId: node.panHa?.groupId ?? 1,
                        sessionSync: node.panHa?.sessionSync ?? true,
                        ...node.panHa,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.panHa?.enabled && (
                <div className="space-y-2 text-[11px]">
                  <div className="grid grid-cols-3 gap-1.5">
                    <Select
                      size="small"
                      value={node.panHa.mode}
                      onChange={(val) =>
                        updateNode(node.id, { panHa: { ...node.panHa!, mode: val } })
                      }
                      options={[
                        { value: 'active-passive', label: 'Active-Passive' },
                        { value: 'active-active', label: 'Active-Active' },
                      ]}
                    />
                    <InputNumber
                      size="small"
                      className="!w-full"
                      placeholder="Grp ID"
                      min={1}
                      max={63}
                      value={node.panHa.groupId}
                      onChange={(val) =>
                        updateNode(node.id, { panHa: { ...node.panHa!, groupId: val ?? 1 } })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="!w-full"
                      placeholder="Prio (100)"
                      value={node.panHa.devicePriority ?? null}
                      onChange={(val) =>
                        updateNode(node.id, { panHa: { ...node.panHa!, devicePriority: val ?? undefined } })
                      }
                    />
                  </div>
                  <div className="grid grid-cols-3 gap-1.5">
                    <Select
                      size="small"
                      allowClear
                      placeholder="HA1 (Control)"
                      value={node.panHa.ha1InterfaceId}
                      onChange={(val) =>
                        updateNode(node.id, { panHa: { ...node.panHa!, ha1InterfaceId: val || undefined } })
                      }
                      options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                    />
                    <Select
                      size="small"
                      allowClear
                      placeholder="HA2 (Session)"
                      value={node.panHa.ha2InterfaceId}
                      onChange={(val) =>
                        updateNode(node.id, { panHa: { ...node.panHa!, ha2InterfaceId: val || undefined } })
                      }
                      options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                    />
                    <Select
                      size="small"
                      allowClear
                      placeholder="HA3 / HSCI"
                      value={node.panHa.ha3HsciInterfaceId}
                      onChange={(val) =>
                        updateNode(node.id, { panHa: { ...node.panHa!, ha3HsciInterfaceId: val || undefined } })
                      }
                      options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                    />
                  </div>
                  <div className="flex flex-wrap gap-3 text-slate-300">
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.panHa.sessionSync)}
                        onChange={(checked) =>
                          updateNode(node.id, { panHa: { ...node.panHa!, sessionSync: checked } })
                        }
                      />
                      <span>Session Sync</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.panHa.preempt)}
                        onChange={(checked) =>
                          updateNode(node.id, { panHa: { ...node.panHa!, preempt: checked } })
                        }
                      />
                      <span>Preempt</span>
                    </label>
                  </div>
                </div>
              )}
            </Card>
          )}

          {(node.vendor === 'fortigate' || Boolean(node.fortiHa?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-rose-300">FortiGate FGCP HA Cluster</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.fortiHa?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      fortiHa: {
                        mode: node.fortiHa?.mode ?? 'a-p',
                        groupId: node.fortiHa?.groupId ?? 1,
                        sessionPickup: node.fortiHa?.sessionPickup ?? true,
                        ...node.fortiHa,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.fortiHa?.enabled && (
                <div className="space-y-2 text-[11px]">
                  <div className="grid grid-cols-3 gap-1.5">
                    <Select
                      size="small"
                      value={node.fortiHa.mode}
                      onChange={(val) =>
                        updateNode(node.id, { fortiHa: { ...node.fortiHa!, mode: val } })
                      }
                      options={[
                        { value: 'a-p', label: 'Active-Passive' },
                        { value: 'a-a', label: 'Active-Active' },
                      ]}
                    />
                    <InputNumber
                      size="small"
                      className="!w-full"
                      placeholder="Grp ID"
                      value={node.fortiHa.groupId}
                      onChange={(val) =>
                        updateNode(node.id, { fortiHa: { ...node.fortiHa!, groupId: val ?? 1 } })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="!w-full"
                      placeholder="Prio (128)"
                      value={node.fortiHa.priority ?? null}
                      onChange={(val) =>
                        updateNode(node.id, { fortiHa: { ...node.fortiHa!, priority: val ?? undefined } })
                      }
                    />
                  </div>
                  <Select
                    size="small"
                    allowClear
                    className="w-full"
                    placeholder="Heartbeat / Session-Sync Interface (hbdev)"
                    value={node.fortiHa.hbInterfaceId}
                    onChange={(val) =>
                      updateNode(node.id, { fortiHa: { ...node.fortiHa!, hbInterfaceId: val || undefined } })
                    }
                    options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                  />
                  <div className="flex flex-wrap gap-3 text-slate-300">
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.fortiHa.sessionPickup)}
                        onChange={(checked) =>
                          updateNode(node.id, { fortiHa: { ...node.fortiHa!, sessionPickup: checked } })
                        }
                      />
                      <span>session-pickup</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-1.5">
                      <Switch
                        size="small"
                        checked={Boolean(node.fortiHa.override)}
                        onChange={(checked) =>
                          updateNode(node.id, { fortiHa: { ...node.fortiHa!, override: checked } })
                        }
                      />
                      <span>override</span>
                    </label>
                  </div>
                </div>
              )}
            </Card>
          )}

          {(caps.lisp || Boolean(node.lisp?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-sky-300">LISP (EID / RLOC Overlay)</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.lisp?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      lisp: {
                        role: node.lisp?.role ?? 'xtr',
                        rlocIp: node.lisp?.rlocIp || node.routerId,
                        instanceId: node.lisp?.instanceId ?? 0,
                        eidPrefixes: node.lisp?.eidPrefixes ?? [],
                        ...node.lisp,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.lisp?.enabled && (
                <div className="space-y-2 text-[11px]">
                  <div className="grid grid-cols-12 gap-1.5">
                    <Select
                      size="small"
                      className="col-span-4"
                      value={node.lisp.role}
                      onChange={(val) =>
                        updateNode(node.id, { lisp: { ...node.lisp!, role: val } })
                      }
                      options={[
                        { value: 'xtr', label: 'xTR (ITR/ETR)' },
                        { value: 'pxtr', label: 'PxTR' },
                        { value: 'pitr', label: 'PiTR' },
                        { value: 'petr', label: 'PeTR' },
                        { value: 'ms-mr', label: 'MS/MR' },
                      ]}
                    />
                    <Input
                      size="small"
                      className="col-span-5"
                      placeholder="RLOC IP"
                      value={node.lisp.rlocIp}
                      onChange={(e) =>
                        updateNode(node.id, { lisp: { ...node.lisp!, rlocIp: e.target.value } })
                      }
                      style={{ fontFamily: 'monospace' }}
                    />
                    <InputNumber
                      size="small"
                      className="col-span-3 !w-full"
                      placeholder="IID"
                      value={node.lisp.instanceId ?? 0}
                      onChange={(val) =>
                        updateNode(node.id, { lisp: { ...node.lisp!, instanceId: val ?? 0 } })
                      }
                    />
                  </div>
                  {node.lisp.role !== 'ms-mr' && (
                    <div className="flex items-center gap-1.5">
                      <span className="shrink-0 text-slate-400">Map-Server/Resolver</span>
                      <Input
                        size="small"
                        placeholder="e.g. 10.0.0.100"
                        value={node.lisp.mapServerIp ?? ''}
                        onChange={(e) =>
                          updateNode(node.id, { lisp: { ...node.lisp!, mapServerIp: e.target.value || undefined } })
                        }
                        style={{ fontFamily: 'monospace' }}
                      />
                    </div>
                  )}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <label className="flex cursor-pointer items-center gap-1.5 text-slate-300">
                      <Switch
                        size="small"
                        checked={Boolean(node.lisp.bfd)}
                        onChange={(checked) =>
                          updateNode(node.id, { lisp: { ...node.lisp!, bfd: checked } })
                        }
                      />
                      <span>RLOC BFD Probing</span>
                    </label>
                    {node.lisp.bfd && (
                      <div className="flex items-center gap-1">
                        <InputNumber
                          size="small"
                          className="!w-14"
                          placeholder="Tx 50"
                          min={5}
                          max={60000}
                          value={node.lisp.bfdIntervalMs ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              lisp: { ...node.lisp!, bfdIntervalMs: val ?? undefined },
                            })
                          }
                        />
                        <InputNumber
                          size="small"
                          className="!w-14"
                          placeholder="Rx 50"
                          min={5}
                          max={60000}
                          value={node.lisp.bfdMinRxMs ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              lisp: { ...node.lisp!, bfdMinRxMs: val ?? undefined },
                            })
                          }
                        />
                        <InputNumber
                          size="small"
                          className="!w-12"
                          placeholder="x3"
                          min={1}
                          max={50}
                          value={node.lisp.bfdMultiplier ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              lisp: { ...node.lisp!, bfdMultiplier: val ?? undefined },
                            })
                          }
                        />
                      </div>
                    )}
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Database-Mapping EID Prefixes</span>
                    <Button
                      size="small"
                      icon={<PlusOutlined />}
                      onClick={() =>
                        updateNode(node.id, {
                          lisp: {
                            ...node.lisp!,
                            eidPrefixes: [
                              ...(node.lisp?.eidPrefixes ?? []),
                              {
                                id: `eid-${Date.now()}`,
                                prefix: '10.80.1.0/24',
                                vrf: 'default',
                                priority: 1,
                                weight: 100,
                              },
                            ],
                          },
                        })
                      }
                    >
                      Add EID
                    </Button>
                  </div>
                  {(node.lisp.eidPrefixes ?? []).map((eid) => (
                    <div key={eid.id} className="grid grid-cols-12 items-center gap-1">
                      <Input
                        size="small"
                        className="col-span-5"
                        value={eid.prefix}
                        onChange={(e) =>
                          updateNode(node.id, {
                            lisp: {
                              ...node.lisp!,
                              eidPrefixes: node.lisp!.eidPrefixes.map((x) =>
                                x.id === eid.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                        style={{ fontFamily: 'monospace' }}
                      />
                      <InputNumber
                        size="small"
                        className="col-span-3 !w-full"
                        placeholder="Prio"
                        value={eid.priority ?? 1}
                        onChange={(val) =>
                          updateNode(node.id, {
                            lisp: {
                              ...node.lisp!,
                              eidPrefixes: node.lisp!.eidPrefixes.map((x) =>
                                x.id === eid.id ? { ...x, priority: val ?? 1 } : x
                              ),
                            },
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-3 !w-full"
                        placeholder="Wt"
                        value={eid.weight ?? 100}
                        onChange={(val) =>
                          updateNode(node.id, {
                            lisp: {
                              ...node.lisp!,
                              eidPrefixes: node.lisp!.eidPrefixes.map((x) =>
                                x.id === eid.id ? { ...x, weight: val ?? 100 } : x
                              ),
                            },
                          })
                        }
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            lisp: {
                              ...node.lisp!,
                              eidPrefixes: node.lisp!.eidPrefixes.filter((x) => x.id !== eid.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}

          {(caps.evpn || Boolean(node.evpn?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-violet-300">VXLAN / BGP EVPN (VTEP)</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.evpn?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      evpn: {
                        vtepIp: node.evpn?.vtepIp || node.routerId,
                        l3Vni: node.evpn?.l3Vni ?? 50000,
                        vrf: node.evpn?.vrf ?? 'default',
                        advertiseConnected: node.evpn?.advertiseConnected ?? true,
                        ...node.evpn,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.evpn?.enabled && (
                <div className="grid grid-cols-12 gap-1.5 text-[11px]">
                  <Input
                    size="small"
                    className="col-span-5"
                    placeholder="VTEP IP"
                    value={node.evpn.vtepIp}
                    onChange={(e) =>
                      updateNode(node.id, { evpn: { ...node.evpn!, vtepIp: e.target.value } })
                    }
                    style={{ fontFamily: 'monospace' }}
                  />
                  <InputNumber
                    size="small"
                    className="col-span-4 !w-full"
                    placeholder="L3 VNI"
                    value={node.evpn.l3Vni ?? null}
                    onChange={(val) =>
                      updateNode(node.id, { evpn: { ...node.evpn!, l3Vni: val ?? undefined } })
                    }
                  />
                  <Select
                    size="small"
                    className="col-span-3"
                    value={node.evpn.vrf || 'default'}
                    onChange={(val) =>
                      updateNode(node.id, { evpn: { ...node.evpn!, vrf: val } })
                    }
                    options={vrfs.map((v) => ({ value: v, label: v }))}
                  />
                </div>
              )}
            </Card>
          )}

          {(caps.mpls || Boolean(node.mplsVpn?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-amber-300">MPLS L3VPN (RD / Route Targets)</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.mplsVpn?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      mplsVpn: {
                        vrfTargets: node.mplsVpn?.vrfTargets ?? [],
                        ...node.mplsVpn,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.mplsVpn?.enabled && (
                <div className="space-y-1.5 text-[11px]">
                  <Button
                    size="small"
                    icon={<PlusOutlined />}
                    onClick={() =>
                      updateNode(node.id, {
                        mplsVpn: {
                          ...node.mplsVpn!,
                          vrfTargets: [
                            ...(node.mplsVpn?.vrfTargets ?? []),
                            {
                              id: `rt-${Date.now()}`,
                              vrf: vrfs[0] || 'default',
                              rd: '65000:100',
                              importRt: '65000:100',
                              exportRt: '65000:100',
                            },
                          ],
                        },
                      })
                    }
                  >
                    Add VRF Route Target
                  </Button>
                  {(node.mplsVpn.vrfTargets ?? []).map((vt) => (
                    <div key={vt.id} className="grid grid-cols-12 items-center gap-1">
                      <Select
                        size="small"
                        className="col-span-3"
                        value={vt.vrf}
                        onChange={(val) =>
                          updateNode(node.id, {
                            mplsVpn: {
                              ...node.mplsVpn!,
                              vrfTargets: node.mplsVpn!.vrfTargets.map((x) =>
                                x.id === vt.id ? { ...x, vrf: val } : x
                              ),
                            },
                          })
                        }
                        options={vrfs.map((v) => ({ value: v, label: v }))}
                      />
                      <Input
                        size="small"
                        className="col-span-3"
                        placeholder="RD"
                        value={vt.rd}
                        onChange={(e) =>
                          updateNode(node.id, {
                            mplsVpn: {
                              ...node.mplsVpn!,
                              vrfTargets: node.mplsVpn!.vrfTargets.map((x) =>
                                x.id === vt.id ? { ...x, rd: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Input
                        size="small"
                        className="col-span-2"
                        placeholder="Imp RT"
                        value={vt.importRt}
                        onChange={(e) =>
                          updateNode(node.id, {
                            mplsVpn: {
                              ...node.mplsVpn!,
                              vrfTargets: node.mplsVpn!.vrfTargets.map((x) =>
                                x.id === vt.id ? { ...x, importRt: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Input
                        size="small"
                        className="col-span-3"
                        placeholder="Exp RT"
                        value={vt.exportRt}
                        onChange={(e) =>
                          updateNode(node.id, {
                            mplsVpn: {
                              ...node.mplsVpn!,
                              vrfTargets: node.mplsVpn!.vrfTargets.map((x) =>
                                x.id === vt.id ? { ...x, exportRt: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            mplsVpn: {
                              ...node.mplsVpn!,
                              vrfTargets: node.mplsVpn!.vrfTargets.filter((x) => x.id !== vt.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}

          {(node.vendor === 'forcepoint-ngfw' || Boolean(node.forcepointCluster?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-emerald-300">Forcepoint NGFW Cluster</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.forcepointCluster?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      forcepointCluster: {
                        mode: node.forcepointCluster?.mode ?? 'standby',
                        clusterId: node.forcepointCluster?.clusterId ?? 1,
                        stateSync: node.forcepointCluster?.stateSync ?? true,
                        ...node.forcepointCluster,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.forcepointCluster?.enabled && (
                <div className="space-y-2 text-[11px]">
                  <div className="grid grid-cols-3 gap-1.5">
                    <Select
                      size="small"
                      value={node.forcepointCluster.mode}
                      onChange={(val) =>
                        updateNode(node.id, { forcepointCluster: { ...node.forcepointCluster!, mode: val } })
                      }
                      options={[
                        { value: 'standby', label: 'Standby' },
                        { value: 'load-balancing', label: 'Load-Balancing' },
                      ]}
                    />
                    <InputNumber
                      size="small"
                      className="!w-full"
                      placeholder="Cluster ID"
                      value={node.forcepointCluster.clusterId}
                      onChange={(val) =>
                        updateNode(node.id, { forcepointCluster: { ...node.forcepointCluster!, clusterId: val ?? 1 } })
                      }
                    />
                    <Input
                      size="small"
                      placeholder="CVI (Cluster Virtual IP)"
                      value={node.forcepointCluster.cviIp ?? ''}
                      onChange={(e) =>
                        updateNode(node.id, {
                          forcepointCluster: { ...node.forcepointCluster!, cviIp: e.target.value || undefined },
                        })
                      }
                    />
                  </div>
                  <Select
                    size="small"
                    allowClear
                    className="w-full"
                    placeholder="Heartbeat / State-Sync Interface"
                    value={node.forcepointCluster.heartbeatInterfaceId}
                    onChange={(val) =>
                      updateNode(node.id, {
                        forcepointCluster: { ...node.forcepointCluster!, heartbeatInterfaceId: val || undefined },
                      })
                    }
                    options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                  />
                </div>
              )}
            </Card>
          )}

          {(node.vendor === 'arista-eos' || Boolean(node.mlag?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-sky-300">Arista EOS MLAG</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.mlag?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      mlag: {
                        domainId: node.mlag?.domainId ?? 'MLAG-DOMAIN',
                        ...node.mlag,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.mlag?.enabled && (
                <div className="space-y-2 text-[11px]">
                  <div className="grid grid-cols-2 gap-1.5">
                    <Input
                      size="small"
                      placeholder="Domain ID"
                      value={node.mlag.domainId}
                      onChange={(e) =>
                        updateNode(node.id, { mlag: { ...node.mlag!, domainId: e.target.value } })
                      }
                    />
                    <Input
                      size="small"
                      placeholder="Peer Address (e.g. 10.255.0.2)"
                      value={node.mlag.peerAddress ?? ''}
                      onChange={(e) =>
                        updateNode(node.id, { mlag: { ...node.mlag!, peerAddress: e.target.value || undefined } })
                      }
                    />
                  </div>
                  <div className="grid grid-cols-12 gap-1.5">
                    <Select
                      size="small"
                      allowClear
                      className="col-span-8"
                      placeholder="MLAG Peer-Link Interface"
                      value={node.mlag.peerLinkInterfaceId}
                      onChange={(val) =>
                        updateNode(node.id, { mlag: { ...node.mlag!, peerLinkInterfaceId: val || undefined } })
                      }
                      options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                    />
                    <InputNumber
                      size="small"
                      className="col-span-4 !w-full"
                      placeholder="Reload Delay"
                      value={node.mlag.reloadDelay ?? null}
                      onChange={(val) =>
                        updateNode(node.id, { mlag: { ...node.mlag!, reloadDelay: val ?? undefined } })
                      }
                    />
                  </div>
                </div>
              )}
            </Card>
          )}

          {(node.vendor === 'cisco-sdwan' || Boolean(node.sdwan?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-cyan-300">Cisco SD-WAN (OMP & TLOC Overlay)</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.sdwan?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      sdwan: {
                        systemIp: node.sdwan?.systemIp ?? node.routerId,
                        siteId: node.sdwan?.siteId ?? 100,
                        vSmartPeers: node.sdwan?.vSmartPeers ?? ['10.255.0.100'],
                        advertiseConnected: node.sdwan?.advertiseConnected ?? true,
                        advertiseStatic: node.sdwan?.advertiseStatic ?? true,
                        ...node.sdwan,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.sdwan?.enabled && (
                <div className="space-y-2 text-[11px]">
                  <div className="grid grid-cols-3 gap-1.5">
                    <Input
                      size="small"
                      addonBefore="Sys-IP"
                      value={node.sdwan.systemIp}
                      onChange={(e) =>
                        updateNode(node.id, {
                          sdwan: { ...node.sdwan!, systemIp: e.target.value },
                        })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="!w-full"
                      addonBefore="Site"
                      min={1}
                      value={node.sdwan.siteId}
                      onChange={(val) =>
                        updateNode(node.id, {
                          sdwan: { ...node.sdwan!, siteId: val ?? 100 },
                        })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="!w-full"
                      addonBefore="AD"
                      min={1}
                      max={255}
                      value={node.sdwan.ompAdminDistance ?? 251}
                      onChange={(val) =>
                        updateNode(node.id, {
                          sdwan: { ...node.sdwan!, ompAdminDistance: val ?? 251 },
                        })
                      }
                    />
                  </div>
                  <div className="flex flex-wrap gap-3 text-[11px] text-slate-300">
                    <Checkbox
                      checked={node.sdwan.advertiseConnected !== false}
                      onChange={(e) =>
                        updateNode(node.id, {
                          sdwan: { ...node.sdwan!, advertiseConnected: e.target.checked },
                        })
                      }
                    >
                      OMP Adv Connected
                    </Checkbox>
                    <Checkbox
                      checked={node.sdwan.advertiseStatic !== false}
                      onChange={(e) =>
                        updateNode(node.id, {
                          sdwan: { ...node.sdwan!, advertiseStatic: e.target.checked },
                        })
                      }
                    >
                      OMP Adv Static
                    </Checkbox>
                    <Checkbox
                      checked={Boolean(node.sdwan.advertiseOspf)}
                      onChange={(e) =>
                        updateNode(node.id, {
                          sdwan: { ...node.sdwan!, advertiseOspf: e.target.checked },
                        })
                      }
                    >
                      OMP Adv OSPF
                    </Checkbox>
                    <Checkbox
                      checked={Boolean(node.sdwan.advertiseBgp)}
                      onChange={(e) =>
                        updateNode(node.id, {
                          sdwan: { ...node.sdwan!, advertiseBgp: e.target.checked },
                        })
                      }
                    >
                      OMP Adv BGP
                    </Checkbox>
                  </div>
                </div>
              )}
            </Card>
          )}

          {(['fortigate', 'pan-os', 'prisma-sdwan', 'cisco-sdwan'].includes(node.vendor) ||
            Boolean(node.sdwanSla?.enabled)) && (
            <Card
              size="small"
              title={<span className="text-emerald-300">SD-WAN Performance SLA &amp; Path Steering</span>}
              extra={
                <Switch
                  size="small"
                  checked={Boolean(node.sdwanSla?.enabled)}
                  onChange={(checked) =>
                    updateNode(node.id, {
                      sdwanSla: {
                        rules: node.sdwanSla?.rules ?? [],
                        ...node.sdwanSla,
                        enabled: checked,
                      },
                    })
                  }
                />
              }
            >
              {node.sdwanSla?.enabled && (
                <div className="space-y-2 text-[11px]">
                  {node.sdwanSla.rules.map((rule) => (
                    <div
                      key={rule.id}
                      className="space-y-1.5 rounded border border-slate-800 bg-[#0b1120] p-2"
                    >
                      <div className="grid grid-cols-12 gap-1.5">
                        <Input
                          size="small"
                          className="col-span-4"
                          placeholder="Rule Name"
                          value={rule.name}
                          onChange={(e) =>
                            updateNode(node.id, {
                              sdwanSla: {
                                ...node.sdwanSla!,
                                rules: node.sdwanSla!.rules.map((r) =>
                                  r.id === rule.id ? { ...r, name: e.target.value } : r
                                ),
                              },
                            })
                          }
                        />
                        <Select
                          size="small"
                          className="col-span-4"
                          value={rule.mode}
                          onChange={(val) =>
                            updateNode(node.id, {
                              sdwanSla: {
                                ...node.sdwanSla!,
                                rules: node.sdwanSla!.rules.map((r) =>
                                  r.id === rule.id ? { ...r, mode: val } : r
                                ),
                              },
                            })
                          }
                          options={[
                            { value: 'sla-failover', label: 'SLA Failover' },
                            { value: 'best-quality', label: 'Best Quality' },
                            { value: 'priority', label: 'Priority Order' },
                          ]}
                        />
                        <Input
                          size="small"
                          className="col-span-3"
                          placeholder="Dst CIDR"
                          value={rule.dstCidr ?? ''}
                          onChange={(e) =>
                            updateNode(node.id, {
                              sdwanSla: {
                                ...node.sdwanSla!,
                                rules: node.sdwanSla!.rules.map((r) =>
                                  r.id === rule.id
                                    ? { ...r, dstCidr: e.target.value || undefined }
                                    : r
                                ),
                              },
                            })
                          }
                        />
                        <Button
                          size="small"
                          type="text"
                          danger
                          icon={<DeleteOutlined />}
                          onClick={() =>
                            updateNode(node.id, {
                              sdwanSla: {
                                ...node.sdwanSla!,
                                rules: node.sdwanSla!.rules.filter((r) => r.id !== rule.id),
                              },
                            })
                          }
                        />
                      </div>
                      <div className="grid grid-cols-12 gap-1.5">
                        <Select
                          mode="tags"
                          size="small"
                          className="col-span-6"
                          tokenSeparators={[',', ' ']}
                          placeholder="Members (e.g. port1, port2)"
                          value={rule.preferredMembers}
                          options={node.interfaces.map((i) => ({ value: i.name, label: i.name }))}
                          onChange={(vals) =>
                            updateNode(node.id, {
                              sdwanSla: {
                                ...node.sdwanSla!,
                                rules: node.sdwanSla!.rules.map((r) =>
                                  r.id === rule.id
                                    ? {
                                      ...r,
                                      preferredMembers: vals.map((s) => s.trim()).filter(Boolean),
                                    }
                                    : r
                                ),
                              },
                            })
                          }
                        />
                        <InputNumber
                          size="small"
                          className="col-span-2 !w-full"
                          placeholder="Max ms"
                          min={1}
                          value={rule.maxLatencyMs ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              sdwanSla: {
                                ...node.sdwanSla!,
                                rules: node.sdwanSla!.rules.map((r) =>
                                  r.id === rule.id
                                    ? { ...r, maxLatencyMs: val ?? undefined }
                                    : r
                                ),
                              },
                            })
                          }
                        />
                        <InputNumber
                          size="small"
                          className="col-span-2 !w-full"
                          placeholder="Jitter"
                          min={0}
                          value={rule.maxJitterMs ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              sdwanSla: {
                                ...node.sdwanSla!,
                                rules: node.sdwanSla!.rules.map((r) =>
                                  r.id === rule.id
                                    ? { ...r, maxJitterMs: val ?? undefined }
                                    : r
                                ),
                              },
                            })
                          }
                        />
                        <InputNumber
                          size="small"
                          className="col-span-2 !w-full"
                          placeholder="Loss%"
                          min={0}
                          max={100}
                          value={rule.maxLossPct ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              sdwanSla: {
                                ...node.sdwanSla!,
                                rules: node.sdwanSla!.rules.map((r) =>
                                  r.id === rule.id
                                    ? { ...r, maxLossPct: val ?? undefined }
                                    : r
                                ),
                              },
                            })
                          }
                        />
                      </div>
                    </div>
                  ))}
                  <Button
                    size="small"
                    type="dashed"
                    block
                    icon={<PlusOutlined />}
                    onClick={() =>
                      updateNode(node.id, {
                        sdwanSla: {
                          ...node.sdwanSla!,
                          rules: [
                            ...node.sdwanSla!.rules,
                            {
                              id: `sla-${Date.now()}`,
                              name: `SDWAN-RULE-${node.sdwanSla!.rules.length + 1}`,
                              mode: 'sla-failover',
                              preferredMembers: node.interfaces.slice(0, 2).map((i) => i.name),
                              maxLatencyMs: 50,
                              maxLossPct: 1,
                            },
                          ],
                        },
                      })
                    }
                  >
                    Add SD-WAN SLA Rule
                  </Button>
                </div>
              )}
            </Card>
          )}

          {(() => {
            const hasAdvProtoActive = Boolean(
              node.mpls?.ldpEnabled ||
              node.mpls?.segmentRouting?.enabled ||
              node.switching?.stpEnabled ||
              node.switching?.lldpEnabled ||
              node.multicast?.pimEnabled ||
              node.timing?.ptpMode ||
              node.timing?.ntpServer ||
              node.telemetry?.bmpServerIp ||
              node.telemetry?.ipfixCollectorIp ||
              (node.bgp.flowspecRules?.length ?? 0) > 0 ||
              (node.nat64Rules?.length ?? 0) > 0
            );
            if (!(caps.mpls || caps.switching || caps.multicast || hasAdvProtoActive)) return null;
            const showAdvProtoBody = hasAdvProtoActive || advProtoExpanded;
            const advTitle =
              [
                caps.mpls ? 'MPLS / SR' : null,
                caps.switching ? 'Switching' : null,
                caps.multicast ? 'Multicast' : null,
              ]
                .filter(Boolean)
                .join(' / ') || 'Advanced Protocols & Telemetry';
            return (
              <Card
                size="small"
                title={<span className="text-teal-300">{advTitle}</span>}
                extra={
                  <Switch
                    size="small"
                    checked={showAdvProtoBody}
                    onChange={(checked) => {
                      setAdvProtoExpanded(checked);
                      if (!checked) {
                        updateNode(node.id, {
                          mpls: node.mpls ? { ...node.mpls, ldpEnabled: false, segmentRouting: node.mpls.segmentRouting ? { ...node.mpls.segmentRouting, enabled: false } : undefined } : undefined,
                          switching: node.switching ? { ...node.switching, stpEnabled: false, lldpEnabled: false } : undefined,
                          multicast: node.multicast ? { ...node.multicast, pimEnabled: false } : undefined,
                          timing: undefined,
                          telemetry: undefined,
                          nat64Rules: undefined,
                          bgp: node.bgp.flowspecRules?.length ? { ...node.bgp, flowspecRules: undefined } : node.bgp,
                        });
                      }
                    }}
                  />
                }
              >
                {showAdvProtoBody && (
                  <div className="space-y-2 text-[11px]">
                    {(caps.mpls || node.mpls?.ldpEnabled || node.mpls?.segmentRouting?.enabled) && (
                      <div className="flex flex-wrap items-center gap-3">
                        <label className="flex cursor-pointer items-center gap-1.5">
                          <Switch
                            size="small"
                            checked={Boolean(node.mpls?.ldpEnabled)}
                            onChange={(checked) =>
                              updateNode(node.id, { mpls: { ...node.mpls, ldpEnabled: checked } })
                            }
                          />
                          <span>MPLS LDP</span>
                        </label>
                        <label className="flex cursor-pointer items-center gap-1.5">
                          <Switch
                            size="small"
                            checked={Boolean(node.mpls?.segmentRouting?.enabled)}
                            onChange={(checked) =>
                              updateNode(node.id, {
                                mpls: {
                                  ...node.mpls,
                                  segmentRouting: { ...node.mpls?.segmentRouting, enabled: checked },
                                },
                              })
                            }
                          />
                          <span>SR-MPLS</span>
                        </label>
                        {node.mpls?.segmentRouting?.enabled && (
                          <InputNumber
                            size="small"
                            className="!w-24"
                            placeholder="Prefix-SID"
                            min={1}
                            value={node.mpls.segmentRouting.prefixSid ?? null}
                            onChange={(val) =>
                              updateNode(node.id, {
                                mpls: {
                                  ...node.mpls,
                                  segmentRouting: {
                                    ...node.mpls!.segmentRouting!,
                                    prefixSid: val ?? undefined,
                                  },
                                },
                              })
                            }
                          />
                        )}
                      </div>
                    )}
                    {(caps.switching || node.switching?.stpEnabled || node.switching?.lldpEnabled) && (
                      <div className="flex flex-wrap items-center gap-3">
                        <label className="flex cursor-pointer items-center gap-1.5">
                          <Switch
                            size="small"
                            checked={Boolean(node.switching?.stpEnabled)}
                            onChange={(checked) =>
                              updateNode(node.id, {
                                switching: { ...node.switching, stpEnabled: checked, stpMode: node.switching?.stpMode ?? 'rstp' },
                              })
                            }
                          />
                          <span>RSTP</span>
                        </label>
                        {node.switching?.stpEnabled && (
                          <InputNumber
                            size="small"
                            className="!w-24"
                            placeholder="Prio (32768)"
                            min={0}
                            max={61440}
                            step={4096}
                            value={node.switching.stpPriority ?? null}
                            onChange={(val) =>
                              updateNode(node.id, {
                                switching: { ...node.switching, stpPriority: val ?? undefined },
                              })
                            }
                          />
                        )}
                        <label className="flex cursor-pointer items-center gap-1.5">
                          <Switch
                            size="small"
                            checked={Boolean(node.switching?.lldpEnabled)}
                            onChange={(checked) =>
                              updateNode(node.id, { switching: { ...node.switching, lldpEnabled: checked } })
                            }
                          />
                          <span>LLDP</span>
                        </label>
                      </div>
                    )}
                    {(caps.multicast || node.multicast?.pimEnabled) && (
                      <div className="flex flex-wrap items-center gap-2">
                        <label className="flex cursor-pointer items-center gap-1.5">
                          <Switch
                            size="small"
                            checked={Boolean(node.multicast?.pimEnabled)}
                            onChange={(checked) =>
                              updateNode(node.id, { multicast: { ...node.multicast, pimEnabled: checked } })
                            }
                          />
                          <span>PIM-SM</span>
                        </label>
                        {node.multicast?.pimEnabled && (
                          <Input
                            size="small"
                            className="!w-32"
                            placeholder="RP IP (e.g. 10.0.0.1)"
                            value={node.multicast.rpAddress ?? ''}
                            style={{ fontFamily: 'monospace' }}
                            onChange={(e) =>
                              updateNode(node.id, {
                                multicast: { ...node.multicast, rpAddress: e.target.value || undefined },
                              })
                            }
                          />
                        )}
                      </div>
                    )}
                    <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-2">
                      <Select
                        size="small"
                        className="!w-32"
                        allowClear
                        placeholder="PTP Mode"
                        value={node.timing?.ptpMode}
                        onChange={(val) =>
                          updateNode(node.id, { timing: { ...node.timing, ptpMode: val } })
                        }
                        options={[
                          { value: 'grandmaster', label: 'PTP GM' },
                          { value: 'boundary', label: 'PTP Boundary' },
                          { value: 'transparent', label: 'PTP Transp' },
                        ]}
                      />
                      <Input
                        size="small"
                        className="!w-28"
                        placeholder="NTP Server"
                        value={node.timing?.ntpServer ?? ''}
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            timing: { ...node.timing, ntpServer: e.target.value || undefined },
                          })
                        }
                      />
                      <Input
                        size="small"
                        className="!w-28"
                        placeholder="BMP Server"
                        value={node.telemetry?.bmpServerIp ?? ''}
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            telemetry: { ...node.telemetry, bmpServerIp: e.target.value || undefined },
                          })
                        }
                      />
                      <Input
                        size="small"
                        className="!w-28"
                        placeholder="IPFIX Collector"
                        value={node.telemetry?.ipfixCollectorIp ?? ''}
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            telemetry: { ...node.telemetry, ipfixCollectorIp: e.target.value || undefined },
                          })
                        }
                      />
                    </div>
                    <div className="space-y-1.5 border-t border-slate-800 pt-2">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">BGP FlowSpec ({node.bgp.flowspecRules?.length ?? 0}) &amp; NAT64 ({node.nat64Rules?.length ?? 0})</span>
                        <Space size="small">
                          <Button
                            size="small"
                            icon={<PlusOutlined />}
                            onClick={() =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  flowspecRules: [
                                    ...(node.bgp.flowspecRules ?? []),
                                    { id: `fs-${Date.now()}`, dstCidr: '198.51.100.0/24', protocol: 'tcp', dstPort: 23, action: 'drop' },
                                  ],
                                },
                              })
                            }
                          >
                            FlowSpec
                          </Button>
                          <Button
                            size="small"
                            icon={<PlusOutlined />}
                            onClick={() =>
                              updateNode(node.id, {
                                nat64Rules: [
                                  ...(node.nat64Rules ?? []),
                                  { id: `n64-${Date.now()}`, prefix6: '64:ff9b::/96', pool4Cidr: '10.0.0.0/24' },
                                ],
                              })
                            }
                          >
                            NAT64
                          </Button>
                        </Space>
                      </div>
                      {(node.bgp.flowspecRules ?? []).map((fs) => (
                        <div key={fs.id} className="flex flex-wrap items-center gap-1">
                          <Input
                            size="small"
                            className="!w-28"
                            value={fs.srcCidr ?? ''}
                            placeholder="Src CIDR"
                            onChange={(e) =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  flowspecRules: node.bgp.flowspecRules?.map((x) =>
                                    x.id === fs.id ? { ...x, srcCidr: e.target.value || undefined } : x
                                  ),
                                },
                              })
                            }
                          />
                          <Input
                            size="small"
                            className="!w-28"
                            value={fs.dstCidr ?? ''}
                            placeholder="Dst CIDR"
                            onChange={(e) =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  flowspecRules: node.bgp.flowspecRules?.map((x) =>
                                    x.id === fs.id ? { ...x, dstCidr: e.target.value || undefined } : x
                                  ),
                                },
                              })
                            }
                          />
                          <Select
                            size="small"
                            className="!w-16"
                            value={fs.protocol ?? 'any'}
                            onChange={(val) =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  flowspecRules: node.bgp.flowspecRules?.map((x) =>
                                    x.id === fs.id ? { ...x, protocol: val } : x
                                  ),
                                },
                              })
                            }
                            options={[
                              { value: 'any', label: 'any' },
                              { value: 'tcp', label: 'tcp' },
                              { value: 'udp', label: 'udp' },
                              { value: 'icmp', label: 'icmp' },
                            ]}
                          />
                          <InputNumber
                            size="small"
                            className="!w-16"
                            value={fs.dstPort ?? null}
                            placeholder="Port"
                            onChange={(v) =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  flowspecRules: node.bgp.flowspecRules?.map((x) =>
                                    x.id === fs.id ? { ...x, dstPort: v ?? undefined } : x
                                  ),
                                },
                              })
                            }
                          />
                          <Select
                            size="small"
                            className="!w-24"
                            value={fs.action}
                            onChange={(val) =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  flowspecRules: node.bgp.flowspecRules?.map((x) =>
                                    x.id === fs.id ? { ...x, action: val } : x
                                  ),
                                },
                              })
                            }
                            options={[
                              { value: 'drop', label: 'Drop' },
                              { value: 'rate-limit', label: 'Rate-Lim' },
                              { value: 'redirect', label: 'Redirect' },
                            ]}
                          />
                          {fs.action === 'rate-limit' && (
                            <InputNumber
                              size="small"
                              className="!w-20"
                              min={1}
                              placeholder="Mbps"
                              value={fs.rateMbps ?? null}
                              onChange={(v) =>
                                updateNode(node.id, {
                                  bgp: {
                                    ...node.bgp,
                                    flowspecRules: node.bgp.flowspecRules?.map((x) =>
                                      x.id === fs.id ? { ...x, rateMbps: v ?? undefined } : x
                                    ),
                                  },
                                })
                              }
                            />
                          )}
                          {fs.action === 'redirect' && (
                            <Input
                              size="small"
                              className="!w-28"
                              placeholder="Redirect NH"
                              value={fs.redirectNextHop ?? ''}
                              onChange={(e) =>
                                updateNode(node.id, {
                                  bgp: {
                                    ...node.bgp,
                                    flowspecRules: node.bgp.flowspecRules?.map((x) =>
                                      x.id === fs.id ? { ...x, redirectNextHop: e.target.value || undefined } : x
                                    ),
                                  },
                                })
                              }
                            />
                          )}
                          <Button
                            size="small"
                            danger
                            type="text"
                            icon={<DeleteOutlined />}
                            onClick={() =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  flowspecRules: node.bgp.flowspecRules?.filter((x) => x.id !== fs.id),
                                },
                              })
                            }
                          />
                        </div>
                      ))}
                      {(node.nat64Rules ?? []).map((n64) => (
                        <div key={n64.id} className="flex items-center gap-1">
                          <Input
                            size="small"
                            className="!w-32"
                            value={n64.prefix6}
                            placeholder="NAT64 Prefix6"
                            onChange={(e) =>
                              updateNode(node.id, {
                                nat64Rules: node.nat64Rules?.map((x) =>
                                  x.id === n64.id ? { ...x, prefix6: e.target.value } : x
                                ),
                              })
                            }
                          />
                          <Input
                            size="small"
                            className="!w-32"
                            value={n64.pool4Cidr}
                            placeholder="IPv4 Pool"
                            onChange={(e) =>
                              updateNode(node.id, {
                                nat64Rules: node.nat64Rules?.map((x) =>
                                  x.id === n64.id ? { ...x, pool4Cidr: e.target.value } : x
                                ),
                              })
                            }
                          />
                          <Button
                            size="small"
                            danger
                            type="text"
                            icon={<DeleteOutlined />}
                            onClick={() =>
                              updateNode(node.id, {
                                nat64Rules: node.nat64Rules?.filter((x) => x.id !== n64.id),
                              })
                            }
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </Card>
            );
          })()}

          <Card
            size="small"
            title={<span className="text-violet-300">BGP Process</span>}
            extra={
              <Space>
                {!isValidBgpAsn(node.bgp.asn) && (
                  <span className="text-[11px] font-medium text-rose-400">Invalid ASN</span>
                )}
                <InputNumber
                  size="small"
                  style={{ width: 112 }}
                  status={isValidBgpAsn(node.bgp.asn) ? undefined : 'error'}
                  placeholder="1–4294967295"
                  value={node.bgp.asn}
                  onChange={(val) =>
                    updateNode(node.id, { bgp: { ...node.bgp, asn: val ?? 0 } })
                  }
                />
                <Switch
                  size="small"
                  checked={node.bgp.enabled}
                  onChange={(checked) =>
                    updateNode(node.id, { bgp: { ...node.bgp, enabled: checked } })
                  }
                />
              </Space>
            }
          >
            {node.bgp.enabled && (
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className="shrink-0 text-slate-400">RR Cluster ID</span>
                  <Input
                    size="small"
                    className="!w-28"
                    placeholder="e.g. 10.0.0.1"
                    value={node.bgp.clusterId ?? ''}
                    style={{ fontFamily: 'monospace' }}
                    onChange={(e) =>
                      updateNode(node.id, {
                        bgp: { ...node.bgp, clusterId: e.target.value || undefined },
                      })
                    }
                  />
                  <span className="shrink-0 text-slate-400">Confed ID</span>
                  <InputNumber
                    size="small"
                    className="!w-20"
                    placeholder="Off"
                    min={1}
                    value={node.bgp.confederationId ?? null}
                    onChange={(val) =>
                      updateNode(node.id, {
                        bgp: { ...node.bgp, confederationId: val ?? undefined },
                      })
                    }
                  />
                  {node.bgp.confederationId && (
                    <Select
                      mode="tags"
                      size="small"
                      className="!min-w-32"
                      tokenSeparators={[',', ' ']}
                      placeholder="Confed Peers (65001, 65002)"
                      value={(node.bgp.confederationPeers ?? []).map(String)}
                      onChange={(vals) => {
                        const peers = vals
                          .map((v) => Number(v.trim()))
                          .filter((n) => Number.isFinite(n) && n > 0);
                        updateNode(node.id, {
                          bgp: { ...node.bgp, confederationPeers: peers.length ? peers : undefined },
                        });
                      }}
                    />
                  )}
                  <label className="flex cursor-pointer items-center gap-1">
                    <Switch
                      size="small"
                      checked={Boolean(node.bgp.alwaysCompareMed)}
                      onChange={(checked) =>
                        updateNode(node.id, { bgp: { ...node.bgp, alwaysCompareMed: checked } })
                      }
                    />
                    <span>always-compare-med</span>
                  </label>
                  <label className="flex cursor-pointer items-center gap-1">
                    <Switch
                      size="small"
                      checked={Boolean(node.bgp.deterministicMed)}
                      onChange={(checked) =>
                        updateNode(node.id, { bgp: { ...node.bgp, deterministicMed: checked } })
                      }
                    />
                    <span>deterministic-med</span>
                  </label>
                  <label className="flex cursor-pointer items-center gap-1">
                    <Switch
                      size="small"
                      checked={Boolean(node.bgp.rpkiRejectInvalid)}
                      onChange={(checked) =>
                        updateNode(node.id, { bgp: { ...node.bgp, rpkiRejectInvalid: checked } })
                      }
                    />
                    <span>RPKI Drop Invalid</span>
                  </label>
                  <label className="flex cursor-pointer items-center gap-1">
                    <Switch
                      size="small"
                      checked={Boolean(node.bgp.bestpathAsPathIgnore)}
                      onChange={(checked) =>
                        updateNode(node.id, { bgp: { ...node.bgp, bestpathAsPathIgnore: checked } })
                      }
                    />
                    <span>as-path ignore</span>
                  </label>
                  <label className="flex cursor-pointer items-center gap-1">
                    <Switch
                      size="small"
                      checked={Boolean(node.bgp.medMissingAsWorst)}
                      onChange={(checked) =>
                        updateNode(node.id, { bgp: { ...node.bgp, medMissingAsWorst: checked } })
                      }
                    />
                    <span>missing-as-worst</span>
                  </label>
                  <label className="flex cursor-pointer items-center gap-1">
                    <Switch
                      size="small"
                      checked={Boolean(node.bgp.gracefulRestart)}
                      onChange={(checked) =>
                        updateNode(node.id, { bgp: { ...node.bgp, gracefulRestart: checked } })
                      }
                    />
                    <span>Graceful Restart</span>
                  </label>
                </div>
                {node.bgp.peers.map((p) => (
                  <div
                    key={p.id}
                    className="space-y-1.5 rounded border border-slate-800 bg-[#0b1120] p-2"
                  >
                    <div className="grid grid-cols-12 gap-1">
                      <Input
                        size="small"
                        className="col-span-4"
                        value={p.peerIp}
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, peerIp: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-3 !w-full"
                        status={isValidBgpAsn(p.remoteAs) ? undefined : 'error'}
                        placeholder="Remote AS"
                        value={p.remoteAs}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, remoteAs: val ?? 0 } : x
                              ),
                            },
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        placeholder="LP"
                        value={p.localPref ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, localPref: val ?? undefined } : x
                              ),
                            },
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        placeholder="Wt"
                        value={p.weight ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, weight: val ?? undefined } : x
                              ),
                            },
                          })
                        }
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.filter((x) => x.id !== p.id),
                            },
                          })
                        }
                      />
                    </div>
                    {!isValidBgpAsn(p.remoteAs) && (
                      <div className="text-[10px] font-medium text-rose-400">
                        Invalid ASN (must be a 2-byte/4-byte integer: 1–4294967295)
                      </div>
                    )}
                    <div className="grid grid-cols-3 gap-1">
                      <Select
                        size="small"
                        value={p.vrf || 'default'}
                        onChange={(val) =>
                          updateNode(node.id, {
                            ...(vrfs.includes(val) || node.vendor === 'forcepoint-ngfw'
                              ? {}
                              : { vrfs: [...vrfs, val] }),
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, vrf: val } : x
                              ),
                            },
                          })
                        }
                        options={availableVrfs.map((v) => {
                          const vc = topology.vrfColors?.[v];
                          return {
                            value: v,
                            label: (
                              <span className="inline-flex items-center gap-1">
                                {vc && (
                                  <span
                                    className="inline-block h-2 w-2 rounded-full"
                                    style={{ backgroundColor: vc }}
                                  />
                                )}
                                <span>VRF: {v}</span>
                              </span>
                            ),
                          };
                        })}
                      />
                      <Select
                        size="small"
                        allowClear
                        placeholder={routeMaps.length ? 'Route-Map IN (Import)' : 'No Route-Maps (Policy tab)'}
                        value={p.routeMapInId}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, routeMapInId: val } : x
                              ),
                            },
                          })
                        }
                        options={routeMaps.map((rm) => ({ value: rm.id, label: `IN: ${rm.name}` }))}
                      />
                      <Select
                        size="small"
                        allowClear
                        placeholder={routeMaps.length ? 'Route-Map OUT (Export)' : 'No Route-Maps (Policy tab)'}
                        value={p.routeMapOutId}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, routeMapOutId: val } : x
                              ),
                            },
                          })
                        }
                        options={routeMaps.map((rm) => ({
                          value: rm.id,
                          label: `OUT: ${rm.name}`,
                        }))}
                      />
                    </div>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 pt-0.5 text-[11px] text-slate-300">
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.nextHopSelf)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, nextHopSelf: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>next-hop-self</span>
                      </label>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.shutdown)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, shutdown: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>Shutdown</span>
                      </label>
                      <Select
                        size="small"
                        allowClear
                        placeholder="Update-Source"
                        style={{ minWidth: 115 }}
                        value={p.updateSource}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, updateSource: val } : x
                              ),
                            },
                          })
                        }
                        options={node.interfaces.map((i) => ({
                          value: i.name,
                          label: `Src: ${i.name}`,
                        }))}
                      />
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.allowAsIn)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, allowAsIn: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>allowas-in</span>
                      </label>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.asOverride)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, asOverride: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>as-override</span>
                      </label>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.removePrivateAs)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, removePrivateAs: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>remove-private-AS</span>
                      </label>
                      <Select
                        size="small"
                        allowClear
                        placeholder="send-comm"
                        style={{ minWidth: 112 }}
                        value={p.sendCommunity}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((x) =>
                                x.id === p.id ? { ...x, sendCommunity: val } : x
                              ),
                            },
                          })
                        }
                        options={[
                          { value: 'both', label: 'comm: both' },
                          { value: 'standard', label: 'comm: std' },
                          { value: 'extended', label: 'comm: ext' },
                          { value: 'none', label: 'comm: strip' },
                        ]}
                      />
                      <div className="flex items-center gap-1">
                        <span className="text-slate-400">Max-Pfx:</span>
                        <InputNumber
                          size="small"
                          className="!w-16"
                          placeholder="∞"
                          min={1}
                          max={1000000}
                          value={p.maxPrefixes ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, maxPrefixes: val ?? undefined } : x
                                ),
                              },
                            })
                          }
                        />
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="text-slate-400">MED:</span>
                        <InputNumber
                          size="small"
                          className="!w-16"
                          placeholder="0"
                          min={0}
                          value={p.med ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, med: val ?? undefined } : x
                                ),
                              },
                            })
                          }
                        />
                      </div>
                      <label className="flex cursor-pointer items-center gap-1" title="disable-connected-check">
                        <Switch
                          size="small"
                          checked={Boolean(p.disableConnectedCheck)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, disableConnectedCheck: checked || undefined } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>no-conn-chk</span>
                      </label>
                      <div className="flex items-center gap-1">
                        <span className="text-slate-400">Local-AS:</span>
                        <InputNumber
                          size="small"
                          className="!w-16"
                          placeholder="Off"
                          min={1}
                          value={p.localAs ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, localAs: val ?? undefined } : x
                                ),
                              },
                            })
                          }
                        />
                      </div>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.defaultOriginate)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, defaultOriginate: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>default-originate</span>
                      </label>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.routeReflectorClient)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, routeReflectorClient: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>RR-client</span>
                      </label>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.ebgpMultihop)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, ebgpMultihop: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>eBGP Multihop</span>
                      </label>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.bfd)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, bfd: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>BFD</span>
                      </label>
                      {p.bfd && (
                        <div className="flex items-center gap-1">
                          <InputNumber
                            size="small"
                            className="!w-14"
                            placeholder="Tx 50"
                            min={5}
                            max={60000}
                            value={p.bfdIntervalMs ?? null}
                            onChange={(val) =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  peers: node.bgp.peers.map((x) =>
                                    x.id === p.id ? { ...x, bfdIntervalMs: val ?? undefined } : x
                                  ),
                                },
                              })
                            }
                          />
                          <InputNumber
                            size="small"
                            className="!w-14"
                            placeholder="Rx 50"
                            min={5}
                            max={60000}
                            value={p.bfdMinRxMs ?? null}
                            onChange={(val) =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  peers: node.bgp.peers.map((x) =>
                                    x.id === p.id ? { ...x, bfdMinRxMs: val ?? undefined } : x
                                  ),
                                },
                              })
                            }
                          />
                          <InputNumber
                            size="small"
                            className="!w-12"
                            placeholder="x3"
                            min={1}
                            max={50}
                            value={p.bfdMultiplier ?? null}
                            onChange={(val) =>
                              updateNode(node.id, {
                                bgp: {
                                  ...node.bgp,
                                  peers: node.bgp.peers.map((x) =>
                                    x.id === p.id ? { ...x, bfdMultiplier: val ?? undefined } : x
                                  ),
                                },
                              })
                            }
                          />
                        </div>
                      )}
                      <div className="flex items-center gap-1">
                        <span className="text-slate-400">Keepalive:</span>
                        <InputNumber
                          size="small"
                          className="!w-16"
                          placeholder="60"
                          min={0}
                          max={65535}
                          value={p.keepaliveTime ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, keepaliveTime: val ?? undefined } : x
                                ),
                              },
                            })
                          }
                        />
                        <span className="text-slate-400">Hold:</span>
                        <InputNumber
                          size="small"
                          className="!w-16"
                          placeholder="180"
                          min={0}
                          max={65535}
                          value={p.holdTime ?? null}
                          onChange={(val) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, holdTime: val ?? undefined } : x
                                ),
                              },
                            })
                          }
                        />
                      </div>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.softReconfigurationInbound)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, softReconfigurationInbound: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>Soft-Reconfig</span>
                      </label>
                      <label className="flex cursor-pointer items-center gap-1.5">
                        <Switch
                          size="small"
                          checked={Boolean(p.gracefulRestart)}
                          onChange={(checked) =>
                            updateNode(node.id, {
                              bgp: {
                                ...node.bgp,
                                peers: node.bgp.peers.map((x) =>
                                  x.id === p.id ? { ...x, gracefulRestart: checked } : x
                                ),
                              },
                            })
                          }
                        />
                        <span>Graceful Restart</span>
                      </label>
                    </div>
                  </div>
                ))}
                <Space.Compact size="small">
                  <Select
                    value={availableVrfs.includes(newBgpPeerVrf) ? newBgpPeerVrf : 'default'}
                    onChange={(val) => setNewBgpPeerVrf(val)}
                    style={{ width: 120 }}
                    options={availableVrfs.map((v) => {
                      const vc = topology.vrfColors?.[v];
                      return {
                        value: v,
                        label: (
                          <span className="inline-flex items-center gap-1">
                            {vc && (
                              <span
                                className="inline-block h-2 w-2 rounded-full"
                                style={{ backgroundColor: vc }}
                              />
                            )}
                            <span>VRF: {v}</span>
                          </span>
                        ),
                      };
                    })}
                  />
                  <Button
                    icon={<PlusOutlined />}
                    onClick={() => {
                      const targetVrf = availableVrfs.includes(newBgpPeerVrf)
                        ? newBgpPeerVrf
                        : 'default';
                      updateNode(node.id, {
                        ...(vrfs.includes(targetVrf) || node.vendor === 'forcepoint-ngfw'
                          ? {}
                          : { vrfs: [...vrfs, targetVrf] }),
                        bgp: {
                          ...node.bgp,
                          peers: [
                            ...node.bgp.peers,
                            {
                              id: `peer-${Date.now()}`,
                              peerIp: '10.0.0.2',
                              remoteAs: 65001,
                              vrf: targetVrf,
                            },
                          ],
                        },
                      });
                    }}
                  >
                    Add BGP Peer
                  </Button>
                </Space.Compact>
                <div className="mt-2 space-y-1.5 border-t border-slate-800 pt-2">
                  <div className="text-[11px] text-slate-400">BGP Aggregate Addresses</div>
                  {(node.bgp.aggregates ?? []).map((agg) => (
                    <div key={agg.id} className="flex items-center gap-1.5">
                      <Input
                        size="small"
                        className="flex-1"
                        placeholder="10.0.0.0/8"
                        value={agg.prefix}
                        onChange={(e) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              aggregates: (node.bgp.aggregates ?? []).map((x) =>
                                x.id === agg.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Switch
                        size="small"
                        checked={Boolean(agg.summaryOnly)}
                        onChange={(checked) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              aggregates: (node.bgp.aggregates ?? []).map((x) =>
                                x.id === agg.id ? { ...x, summaryOnly: checked } : x
                              ),
                            },
                          })
                        }
                      />
                      <span className="text-[10px] text-slate-400">summary-only</span>
                      <Button
                        size="small"
                        danger
                        type="text"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              aggregates: (node.bgp.aggregates ?? []).filter((x) => x.id !== agg.id),
                            },
                          })
                        }
                      />
                    </div>
                  ))}
                  <Button
                    size="small"
                    icon={<PlusOutlined />}
                    onClick={() =>
                      updateNode(node.id, {
                        bgp: {
                          ...node.bgp,
                          aggregates: [
                            ...(node.bgp.aggregates ?? []),
                            { id: `agg-${Date.now()}`, prefix: '10.1.0.0/16', summaryOnly: true },
                          ],
                        },
                      })
                    }
                  >
                    Add Aggregate
                  </Button>
                </div>

                <div className="mt-2 space-y-1.5 border-t border-slate-800 pt-2">
                  <div className="flex items-center justify-between text-[11px] font-semibold text-violet-300">
                    <span>BGP Network Advertisements</span>
                    <Button
                      size="small"
                      icon={<PlusOutlined />}
                      onClick={() =>
                        updateNode(node.id, {
                          bgp: {
                            ...node.bgp,
                            networks: [
                              ...node.bgp.networks,
                              {
                                id: `bgp-net-${Date.now()}`,
                                prefix: '198.51.100.0/24',
                                origin: 'igp',
                                vrf: 'default',
                              },
                            ],
                          },
                        })
                      }
                    >
                      Add Network
                    </Button>
                  </div>
                  {node.bgp.networks.map((bn) => (
                    <div key={bn.id} className="grid grid-cols-12 items-center gap-1">
                      <Input
                        size="small"
                        className="col-span-5"
                        value={bn.prefix}
                        placeholder="198.51.100.0/24"
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              networks: node.bgp.networks.map((x) =>
                                x.id === bn.id ? { ...x, prefix: e.target.value } : x
                              ),
                            },
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-2"
                        value={bn.origin ?? 'igp'}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              networks: node.bgp.networks.map((x) =>
                                x.id === bn.id ? { ...x, origin: val } : x
                              ),
                            },
                          })
                        }
                        options={[
                          { value: 'igp', label: 'IGP' },
                          { value: 'egp', label: 'EGP' },
                          { value: 'incomplete', label: '?' },
                        ]}
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        min={0}
                        placeholder="MED"
                        value={bn.med ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              networks: node.bgp.networks.map((x) =>
                                x.id === bn.id ? { ...x, med: val ?? undefined } : x
                              ),
                            },
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-2"
                        value={bn.vrf || 'default'}
                        onChange={(val) =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              networks: node.bgp.networks.map((x) =>
                                x.id === bn.id ? { ...x, vrf: val } : x
                              ),
                            },
                          })
                        }
                        options={vrfs.map((v) => ({ value: v, label: v }))}
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              networks: node.bgp.networks.filter((x) => x.id !== bn.id),
                            },
                          })
                        }
                      />
                      <Select
                        mode="tags"
                        size="small"
                        className="col-span-12 mt-1"
                        tokenSeparators={[',', ' ']}
                        placeholder="Communities (e.g. 65100:100, no-export)"
                        value={bn.communities ?? []}
                        onChange={(vals) => {
                          const list = vals.map((s) => s.trim()).filter(Boolean);
                          updateNode(node.id, {
                            bgp: {
                              ...node.bgp,
                              networks: node.bgp.networks.map((x) =>
                                x.id === bn.id
                                  ? { ...x, communities: list.length ? list : undefined }
                                  : x
                              ),
                            },
                          });
                        }}
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>

          <Card
            size="small"
            title={<span className="text-amber-300">Redistribution</span>}
            extra={
              <Button
                size="small"
                icon={<PlusOutlined />}
                onClick={() =>
                  updateNode(node.id, {
                    redistributions: [
                      ...node.redistributions,
                      {
                        id: `red-${Date.now()}`,
                        vrf: 'default',
                        from: 'bgp',
                        to: 'ospf',
                        metric: 20,
                        metricType: 'E2',
                      },
                    ],
                  })
                }
              >
                Add
              </Button>
            }
          >
            <div className="space-y-1.5">
              {node.redistributions.map((r) => (
                <div key={r.id} className="grid grid-cols-12 items-center gap-1">
                  <Select
                    size="small"
                    className="col-span-3"
                    value={r.from}
                    onChange={(val) =>
                      updateNode(node.id, {
                        redistributions: node.redistributions.map((x) =>
                          x.id === r.id ? { ...x, from: val } : x
                        ),
                      })
                    }
                    options={[
                      { value: 'connected', label: 'Connected' },
                      { value: 'static', label: 'Static' },
                      { value: 'ospf', label: 'OSPF' },
                      { value: 'eigrp', label: 'EIGRP' },
                      { value: 'isis', label: 'IS-IS' },
                      { value: 'rip', label: 'RIP' },
                      { value: 'bgp', label: 'BGP' },
                    ]}
                  />
                  <Select
                    size="small"
                    className="col-span-3"
                    value={r.to}
                    onChange={(val) =>
                      updateNode(node.id, {
                        redistributions: node.redistributions.map((x) =>
                          x.id === r.id ? { ...x, to: val } : x
                        ),
                      })
                    }
                    options={[
                      { value: 'ospf', label: 'To OSPF' },
                      { value: 'eigrp', label: 'To EIGRP' },
                      { value: 'isis', label: 'To IS-IS' },
                      { value: 'rip', label: 'To RIP' },
                      { value: 'bgp', label: 'To BGP' },
                    ]}
                  />
                  <InputNumber
                    size="small"
                    className="col-span-2 !w-full"
                    value={r.metric ?? 20}
                    onChange={(val) =>
                      updateNode(node.id, {
                        redistributions: node.redistributions.map((x) =>
                          x.id === r.id ? { ...x, metric: val ?? 20 } : x
                        ),
                      })
                    }
                  />
                  {r.to === 'ospf' && (
                    <Select
                      size="small"
                      className="col-span-2"
                      value={r.metricType ?? 'E2'}
                      onChange={(val) =>
                        updateNode(node.id, {
                          redistributions: node.redistributions.map((x) =>
                            x.id === r.id ? { ...x, metricType: val } : x
                          ),
                        })
                      }
                      options={[
                        { value: 'E1', label: 'E1' },
                        { value: 'E2', label: 'E2' },
                      ]}
                    />
                  )}
                  <Select
                    size="small"
                    className={r.to === 'ospf' ? 'col-span-2' : 'col-span-3'}
                    allowClear
                    placeholder="Route-Map"
                    value={r.routeMapId}
                    onChange={(val) =>
                      updateNode(node.id, {
                        redistributions: node.redistributions.map((x) =>
                          x.id === r.id ? { ...x, routeMapId: val } : x
                        ),
                      })
                    }
                    options={routeMaps.map((rm) => ({ value: rm.id, label: rm.name }))}
                  />
                  <Button
                    size="small"
                    danger
                    type="text"
                    className="col-span-1"
                    icon={<DeleteOutlined />}
                    onClick={() =>
                      updateNode(node.id, {
                        redistributions: node.redistributions.filter((x) => x.id !== r.id),
                      })
                    }
                  />
                </div>
              ))}
            </div>
          </Card>
        </div>
      ),
    },
    {
      key: 'vrfs',
      label: `${caps.vrfTabLabel} (${vrfs.length})`,
      children: (
        <div className="space-y-3">
          <Card size="small" title={caps.vrfLabel}>
            {(node.vendor === 'forcepoint-ngfw' || Boolean(node.forcepointCluster?.enabled)) && (
              <Alert
                type="info"
                showIcon
                className="!mb-2.5 !py-1.5 !text-[11px]"
                message="Forcepoint NGFW supports 1 VRF per virtual engine (even though underlying FRR/VRR supports multiple VRFs)."
              />
            )}
            <div className="mb-2 flex flex-wrap gap-1.5">
              {vrfs.map((v) => {
                const vColor = topology.vrfColors?.[v];
                return (
                  <Tag
                    key={v}
                    color={vColor ? undefined : v === 'default' ? 'default' : 'cyan'}
                    style={
                      vColor
                        ? {
                          backgroundColor: `${vColor}22`,
                          borderColor: `${vColor}77`,
                          color: vColor,
                        }
                        : undefined
                    }
                    closable={v !== 'default'}
                    onClose={() => {
                      const nextVrfRouterIds = node.vrfRouterIds ? { ...node.vrfRouterIds } : undefined;
                      if (nextVrfRouterIds) delete nextVrfRouterIds[v];
                      updateNode(node.id, {
                        vrfs: vrfs.filter((x) => x !== v),
                        vrfLeaks: vrfLeaks.filter((l) => l.fromVrf !== v && l.toVrf !== v),
                        interfaces: node.interfaces.map((i) => (i.vrf === v ? { ...i, vrf: 'default' } : i)),
                        staticRoutes: node.staticRoutes.map((sr) => (sr.vrf === v ? { ...sr, vrf: 'default' } : sr)),
                        redistributions: node.redistributions.map((r) => (r.vrf === v ? { ...r, vrf: 'default' } : r)),
                        ospf: {
                          ...node.ospf,
                          networks: node.ospf.networks.map((n) => (n.vrf === v ? { ...n, vrf: 'default' } : n)),
                          shamLinks: node.ospf.shamLinks?.filter((sl) => sl.vrf !== v),
                        },
                        bgp: {
                          ...node.bgp,
                          peers: node.bgp.peers.map((p) => (p.vrf === v ? { ...p, vrf: 'default' } : p)),
                          networks: node.bgp.networks.map((n) => (n.vrf === v ? { ...n, vrf: 'default' } : n)),
                          aggregates: node.bgp.aggregates?.map((a) => (a.vrf === v ? { ...a, vrf: 'default' } : a)),
                        },
                        lisp: node.lisp
                          ? {
                            ...node.lisp,
                            eidPrefixes: node.lisp.eidPrefixes?.map((e) =>
                              e.vrf === v ? { ...e, vrf: 'default' } : e
                            ),
                          }
                          : undefined,
                        eigrp: node.eigrp
                          ? {
                            ...node.eigrp,
                            networks: node.eigrp.networks.map((n) => (n.vrf === v ? { ...n, vrf: 'default' } : n)),
                          }
                          : undefined,
                        isis: node.isis
                          ? {
                            ...node.isis,
                            networks: node.isis.networks.map((n) => (n.vrf === v ? { ...n, vrf: 'default' } : n)),
                          }
                          : undefined,
                        rip: node.rip
                          ? {
                            ...node.rip,
                            networks: node.rip.networks.map((n) => (n.vrf === v ? { ...n, vrf: 'default' } : n)),
                          }
                          : undefined,
                        tracks: node.tracks?.map((tr) => (tr.vrf === v ? { ...tr, vrf: 'default' } : tr)),
                        evpn: node.evpn && node.evpn.vrf === v ? { ...node.evpn, vrf: 'default' } : node.evpn,
                        mplsVpn: node.mplsVpn
                          ? {
                            ...node.mplsVpn,
                            vrfTargets: node.mplsVpn.vrfTargets.filter((vt) => vt.vrf !== v),
                          }
                          : undefined,
                        vrfRouterIds:
                          nextVrfRouterIds && Object.keys(nextVrfRouterIds).length > 0
                            ? nextVrfRouterIds
                            : undefined,
                      });
                    }}
                  >
                    <span className="inline-flex items-center gap-1.5">
                      <input
                        type="color"
                        title={`Set color for VRF ${v}`}
                        value={vColor ?? (v === 'default' ? '#64748b' : '#06b6d4')}
                        onChange={(e) => setVrfColor(v, e.target.value)}
                        className="h-3 w-3 cursor-pointer border-0 bg-transparent p-0"
                      />
                      <span>{v}</span>
                    </span>
                  </Tag>
                );
              })}
            </div>
            {workspaceVrfs.some((v) => !vrfs.includes(v)) && (
              <Select
                size="small"
                className="!mb-2 w-full"
                value={null}
                disabled={node.vendor === 'forcepoint-ngfw' && vrfs.length >= 1}
                placeholder="Add existing workspace VRF..."
                onChange={(val: string) => {
                  if (!val || vrfs.includes(val)) return;
                  if (node.vendor === 'forcepoint-ngfw' && vrfs.length >= 1) return;
                  updateNode(node.id, { vrfs: [...vrfs, val] });
                }}
                options={workspaceVrfs
                  .filter((v) => !vrfs.includes(v))
                  .map((v) => ({
                    value: v,
                    label: (
                      <span className="inline-flex items-center gap-1.5">
                        <span
                          className="inline-block h-2 w-2 rounded-full"
                          style={{ backgroundColor: topology.vrfColors?.[v] ?? '#06b6d4' }}
                        />
                        <span>{v}</span>
                      </span>
                    ),
                  }))}
              />
            )}
            <Space.Compact size="small" className="w-full">
              <input
                type="color"
                title="Pick VRF color"
                value={newVrfColor}
                onChange={(e) => setNewVrfColor(e.target.value)}
                className="h-6 w-7 cursor-pointer rounded-l border border-slate-700 bg-transparent p-0.5"
              />
              <Input
                value={newVrfName}
                onChange={(e) => setNewVrfName(e.target.value)}
                placeholder="New VRF name (e.g. DMZ)"
              />
              <Button
                type="primary"
                icon={<PlusOutlined />}
                disabled={node.vendor === 'forcepoint-ngfw' && vrfs.length >= 1}
                onClick={() => {
                  const trimmed = newVrfName.trim();
                  if (!trimmed || vrfs.includes(trimmed)) return;
                  if (node.vendor === 'forcepoint-ngfw' && vrfs.length >= 1) return;
                  updateNode(node.id, { vrfs: [...vrfs, trimmed] });
                  setVrfColor(trimmed, newVrfColor);
                  setNewVrfName('');
                }}
              >
                Add
              </Button>
            </Space.Compact>
            {vrfs.some((v) => v !== 'default') && (
              <div className="mt-3 space-y-1.5 border-t border-slate-800 pt-2">
                <div className="text-[11px] font-medium text-slate-400">
                  Per-VRF Router IDs (optional)
                </div>
                {vrfs
                  .filter((v) => v !== 'default')
                  .map((v) => (
                    <div key={v} className="flex items-center gap-2 text-[11px]">
                      <span className="w-24 truncate text-slate-300">{v}</span>
                      <Input
                        size="small"
                        placeholder={node.routerId}
                        value={node.vrfRouterIds?.[v] ?? ''}
                        style={{ fontFamily: 'monospace' }}
                        onChange={(e) => {
                          const next = { ...(node.vrfRouterIds ?? {}) };
                          if (e.target.value) next[v] = e.target.value;
                          else delete next[v];
                          updateNode(node.id, { vrfRouterIds: next });
                        }}
                      />
                    </div>
                  ))}
              </div>
            )}
          </Card>

          <Card
            size="small"
            title="VRF Route-Leaking"
            extra={
              <Button
                size="small"
                icon={<PlusOutlined />}
                onClick={() =>
                  updateNode(node.id, {
                    vrfLeaks: [
                      ...vrfLeaks,
                      {
                        id: `leak-${Date.now()}`,
                        fromVrf: vrfs[0],
                        toVrf: vrfs[1] ?? vrfs[0],
                      },
                    ],
                  })
                }
              >
                Add Leak
              </Button>
            }
          >
            <div className="space-y-1.5">
              {vrfLeaks.map((l) => (
                <div key={l.id} className="grid grid-cols-12 items-center gap-1.5">
                  <Select
                    size="small"
                    className="col-span-3"
                    value={l.fromVrf}
                    onChange={(val) =>
                      updateNode(node.id, {
                        vrfLeaks: vrfLeaks.map((x) =>
                          x.id === l.id ? { ...x, fromVrf: val } : x
                        ),
                      })
                    }
                    options={vrfs.map((v) => ({ value: v, label: `From: ${v}` }))}
                  />
                  <Select
                    size="small"
                    className="col-span-3"
                    value={l.toVrf}
                    onChange={(val) =>
                      updateNode(node.id, {
                        vrfLeaks: vrfLeaks.map((x) =>
                          x.id === l.id ? { ...x, toVrf: val } : x
                        ),
                      })
                    }
                    options={vrfs.map((v) => ({ value: v, label: `To: ${v}` }))}
                  />
                  <Select
                    size="small"
                    className="col-span-5"
                    allowClear
                    placeholder="All Prefixes"
                    value={l.matchPrefixListId}
                    onChange={(val) =>
                      updateNode(node.id, {
                        vrfLeaks: vrfLeaks.map((x) =>
                          x.id === l.id ? { ...x, matchPrefixListId: val } : x
                        ),
                      })
                    }
                    options={prefixLists.map((pl) => ({ value: pl.id, label: `PL: ${pl.name}` }))}
                  />
                  <Button
                    size="small"
                    danger
                    type="text"
                    className="col-span-1"
                    icon={<DeleteOutlined />}
                    onClick={() =>
                      updateNode(node.id, {
                        vrfLeaks: vrfLeaks.filter((x) => x.id !== l.id),
                      })
                    }
                  />
                </div>
              ))}
            </div>
          </Card>
        </div>
      ),
    },
    {
      key: 'policy',
      label: `Policy (${routeMaps.length})`,
      children: (
        <div className="space-y-3">
          <Card
            size="small"
            title="Prefix-Lists"
            extra={
              <Button
                size="small"
                icon={<PlusOutlined />}
                onClick={() =>
                  updateNode(node.id, {
                    prefixLists: [
                      ...prefixLists,
                      {
                        id: `pl-${Date.now()}`,
                        name: `PL-${prefixLists.length + 1}`,
                        entries: [
                          {
                            id: `ple-${Date.now()}`,
                            seq: 10,
                            action: 'permit',
                            prefix: '0.0.0.0/0',
                          },
                        ],
                      },
                    ],
                  })
                }
              >
                Add
              </Button>
            }
          >
            <div className="space-y-2">
              {prefixLists.map((pl) => (
                <div key={pl.id} className="space-y-1.5 rounded border border-slate-800 p-2">
                  <div className="flex items-center justify-between gap-2">
                    <Input
                      size="small"
                      value={pl.name}
                      style={{ fontFamily: 'monospace', width: 160 }}
                      onChange={(e) =>
                        updateNode(node.id, {
                          prefixLists: prefixLists.map((x) =>
                            x.id === pl.id ? { ...x, name: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <Space size="small">
                      <Button
                        size="small"
                        onClick={() =>
                          updateNode(node.id, {
                            prefixLists: prefixLists.map((x) =>
                              x.id === pl.id
                                ? {
                                  ...x,
                                  entries: [
                                    ...x.entries,
                                    {
                                      id: `ple-${Date.now()}`,
                                      seq: (x.entries.length + 1) * 10,
                                      action: 'permit',
                                      prefix: '10.0.0.0/8',
                                    },
                                  ],
                                }
                                : x
                            ),
                          })
                        }
                      >
                        + Entry
                      </Button>
                      <Button
                        size="small"
                        danger
                        type="text"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            prefixLists: prefixLists.filter((x) => x.id !== pl.id),
                            routeMaps: routeMaps.map((rm) => ({
                              ...rm,
                              entries: rm.entries.map((entry) =>
                                entry.matchPrefixListId === pl.id
                                  ? { ...entry, matchPrefixListId: undefined }
                                  : entry
                              ),
                            })),
                            vrfLeaks: node.vrfLeaks.map((vl) =>
                              vl.matchPrefixListId === pl.id ? { ...vl, matchPrefixListId: undefined } : vl
                            ),
                          })
                        }
                      />
                    </Space>
                  </div>
                  {pl.entries.map((e) => (
                    <div key={e.id} className="grid grid-cols-12 items-center gap-1">
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        value={e.seq}
                        onChange={(val) =>
                          updateNode(node.id, {
                            prefixLists: prefixLists.map((x) =>
                              x.id === pl.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, seq: val ?? 10 } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-3"
                        value={e.action}
                        onChange={(val) =>
                          updateNode(node.id, {
                            prefixLists: prefixLists.map((x) =>
                              x.id === pl.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, action: val } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                        options={[
                          { value: 'permit', label: 'permit' },
                          { value: 'deny', label: 'deny' },
                        ]}
                      />
                      <Input
                        size="small"
                        className="col-span-4"
                        value={e.prefix}
                        style={{ fontFamily: 'monospace' }}
                        onChange={(ev) =>
                          updateNode(node.id, {
                            prefixLists: prefixLists.map((x) =>
                              x.id === pl.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, prefix: ev.target.value } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        placeholder="le"
                        value={e.le ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            prefixLists: prefixLists.map((x) =>
                              x.id === pl.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, le: val ?? undefined } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            prefixLists: prefixLists.map((x) =>
                              x.id === pl.id
                                ? { ...x, entries: x.entries.filter((en) => en.id !== e.id) }
                                : x
                            ),
                          })
                        }
                      />
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </Card>

          <Card
            size="small"
            title="Route-Maps"
            extra={
              <Button
                size="small"
                icon={<PlusOutlined />}
                onClick={() =>
                  updateNode(node.id, {
                    routeMaps: [
                      ...routeMaps,
                      {
                        id: `rm-${Date.now()}`,
                        name: `RM-${routeMaps.length + 1}`,
                        entries: [
                          {
                            id: `rme-${Date.now()}`,
                            seq: 10,
                            action: 'permit',
                            set: { setLocalPref: 200 },
                          },
                        ],
                      },
                    ],
                  })
                }
              >
                Add
              </Button>
            }
          >
            <div className="space-y-2">
              {routeMaps.map((rm) => (
                <div key={rm.id} className="space-y-1.5 rounded border border-slate-800 p-2">
                  <div className="flex items-center justify-between">
                    <Input
                      size="small"
                      value={rm.name}
                      style={{ fontFamily: 'monospace', width: 160 }}
                      onChange={(e) =>
                        updateNode(node.id, {
                          routeMaps: routeMaps.map((x) =>
                            x.id === rm.id ? { ...x, name: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <Space size="small">
                      <Button
                        size="small"
                        onClick={() =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? {
                                  ...x,
                                  entries: [
                                    ...x.entries,
                                    {
                                      id: `rme-${Date.now()}`,
                                      seq: (Math.max(0, ...x.entries.map((e) => e.seq)) || 0) + 10,
                                      action: 'permit',
                                      set: {},
                                    },
                                  ],
                                }
                                : x
                            ),
                          })
                        }
                      >
                        + Entry
                      </Button>
                      <Button
                        size="small"
                        danger
                        type="text"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.filter((x) => x.id !== rm.id),
                            bgp: {
                              ...node.bgp,
                              peers: node.bgp.peers.map((p) => ({
                                ...p,
                                routeMapInId: p.routeMapInId === rm.id ? undefined : p.routeMapInId,
                                routeMapOutId: p.routeMapOutId === rm.id ? undefined : p.routeMapOutId,
                              })),
                            },
                            redistributions: node.redistributions.map((rd) =>
                              rd.routeMapId === rm.id ? { ...rd, routeMapId: undefined } : rd
                            ),
                          })
                        }
                      />
                    </Space>
                  </div>
                  {node.bgp.enabled && node.bgp.peers.length > 0 && (
                    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.035] px-2.5 py-1.5 text-[10px] text-slate-300">
                      <span className="text-slate-400">Apply to BGP Peers:</span>
                      {node.bgp.peers.map((peer) => {
                        const isIn = peer.routeMapInId === rm.id;
                        const isOut = peer.routeMapOutId === rm.id;
                        return (
                          <span key={peer.id} className="inline-flex items-center gap-1 rounded-md border border-white/[0.08] bg-white/[0.03] px-1.5 py-0.5 font-mono">
                            <span>{peer.peerIp}</span>
                            <Button
                              size="small"
                              type={isIn ? 'primary' : 'default'}
                              className="!h-4 !px-1 !text-[9px]"
                              onClick={() =>
                                updateNode(node.id, {
                                  bgp: {
                                    ...node.bgp,
                                    peers: node.bgp.peers.map((x) =>
                                      x.id === peer.id
                                        ? { ...x, routeMapInId: isIn ? undefined : rm.id }
                                        : x
                                    ),
                                  },
                                })
                              }
                            >
                              IN
                            </Button>
                            <Button
                              size="small"
                              type={isOut ? 'primary' : 'default'}
                              className="!h-4 !px-1 !text-[9px]"
                              onClick={() =>
                                updateNode(node.id, {
                                  bgp: {
                                    ...node.bgp,
                                    peers: node.bgp.peers.map((x) =>
                                      x.id === peer.id
                                        ? { ...x, routeMapOutId: isOut ? undefined : rm.id }
                                        : x
                                    ),
                                  },
                                })
                              }
                            >
                              OUT
                            </Button>
                          </span>
                        );
                      })}
                    </div>
                  )}
                  {rm.entries.map((e) => (
                    <div key={e.id} className="grid grid-cols-12 items-center gap-1">
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        value={e.seq}
                        onChange={(val) =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, seq: val ?? 10 } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                      />
                      <Select
                        size="small"
                        className="col-span-3"
                        value={e.action}
                        onChange={(val) =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, action: val } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                        options={[
                          { value: 'permit', label: 'permit' },
                          { value: 'deny', label: 'deny' },
                        ]}
                      />
                      <Select
                        size="small"
                        className="col-span-4"
                        allowClear
                        placeholder="Match Any"
                        value={e.matchPrefixListId}
                        onChange={(val) =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, matchPrefixListId: val } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                        options={prefixLists.map((pl) => ({ value: pl.id, label: pl.name }))}
                      />
                      <Input
                        size="small"
                        className="col-span-4"
                        placeholder="Match Comm (65000:100)"
                        value={e.matchCommunity ?? ''}
                        onChange={(ev) =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, matchCommunity: ev.target.value || undefined } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                      />
                      <Input
                        size="small"
                        className="col-span-4"
                        placeholder="Match AS-Path (^64501)"
                        value={e.matchAsPathRegex ?? ''}
                        onChange={(ev) =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id ? { ...en, matchAsPathRegex: ev.target.value || undefined } : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                      />
                      <Input
                        size="small"
                        className="col-span-4"
                        placeholder="Set Comm (65000:200)"
                        value={e.set.setCommunity ?? ''}
                        onChange={(ev) =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id
                                      ? { ...en, set: { ...en.set, setCommunity: ev.target.value || undefined } }
                                      : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                      />
                      <InputNumber
                        size="small"
                        className="col-span-2 !w-full"
                        placeholder="LP"
                        value={e.set.setLocalPref ?? null}
                        onChange={(val) =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? {
                                  ...x,
                                  entries: x.entries.map((en) =>
                                    en.id === e.id
                                      ? {
                                        ...en,
                                        set: { ...en.set, setLocalPref: val ?? undefined },
                                      }
                                      : en
                                  ),
                                }
                                : x
                            ),
                          })
                        }
                      />
                      <Button
                        size="small"
                        danger
                        type="text"
                        className="col-span-1"
                        icon={<DeleteOutlined />}
                        onClick={() =>
                          updateNode(node.id, {
                            routeMaps: routeMaps.map((x) =>
                              x.id === rm.id
                                ? { ...x, entries: x.entries.filter((en) => en.id !== e.id) }
                                : x
                            ),
                          })
                        }
                      />
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </Card>
        </div>
      ),
    },
    {
      key: 'security',
      label: `${caps.securityTabLabel} (${aclRules.length + natRules.length})`,
      children: (
        <div className="space-y-3">
          <Card
            size="small"
            title={caps.aclCardTitle}
            extra={
              <Button
                size="small"
                icon={<PlusOutlined />}
                onClick={() =>
                  updateNode(node.id, {
                    aclRules: [
                      ...aclRules,
                      {
                        id: `acl-${Date.now()}`,
                        seq: (aclRules.length + 1) * 10,
                        name: `RULE-${aclRules.length + 1}`,
                        action: 'allow',
                        srcCidr: 'any',
                        dstCidr: 'any',
                        protocol: 'any',
                      },
                    ],
                  })
                }
              >
                Add Rule
              </Button>
            }
          >
            <div className="space-y-1.5">
              {aclRules.map((r) => (
                <div key={r.id} className="space-y-1 rounded border border-slate-800 p-1.5">
                  <div className="grid grid-cols-12 items-center gap-1">
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      value={r.seq}
                      onChange={(val) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, seq: val ?? 10 } : x
                          ),
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-4"
                      value={r.name}
                      placeholder="Rule name"
                      onChange={(e) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, name: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <Select
                      size="small"
                      className="col-span-3"
                      value={r.action}
                      onChange={(val) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, action: val } : x
                          ),
                        })
                      }
                      options={[
                        { value: 'allow', label: 'ALLOW' },
                        { value: 'deny', label: 'DENY' },
                      ]}
                    />
                    <Select
                      size="small"
                      className="col-span-2"
                      value={r.protocol}
                      onChange={(val) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, protocol: val } : x
                          ),
                        })
                      }
                      options={[
                        { value: 'any', label: 'any' },
                        { value: 'tcp', label: 'tcp' },
                        { value: 'udp', label: 'udp' },
                        { value: 'icmp', label: 'icmp' },
                      ]}
                    />
                    <Button
                      size="small"
                      danger
                      type="text"
                      className="col-span-1"
                      icon={<DeleteOutlined />}
                      onClick={() =>
                        updateNode(node.id, {
                          aclRules: aclRules.filter((x) => x.id !== r.id),
                        })
                      }
                    />
                  </div>
                  <div className="grid grid-cols-12 items-center gap-1">
                    <Input
                      size="small"
                      className="col-span-6"
                      value={r.srcZone ?? ''}
                      placeholder="Src Zone (any)"
                      onChange={(e) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, srcZone: e.target.value || undefined } : x
                          ),
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-6"
                      value={r.dstZone ?? ''}
                      placeholder="Dst Zone (any)"
                      onChange={(e) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, dstZone: e.target.value || undefined } : x
                          ),
                        })
                      }
                    />
                  </div>
                  <div className="grid grid-cols-12 items-center gap-1">
                    <Input
                      size="small"
                      className="col-span-5"
                      value={r.srcCidr}
                      placeholder="Src CIDR / any"
                      style={{ fontFamily: 'monospace' }}
                      onChange={(e) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, srcCidr: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-5"
                      value={r.dstCidr}
                      placeholder="Dst CIDR / any"
                      style={{ fontFamily: 'monospace' }}
                      onChange={(e) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, dstCidr: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      placeholder="Port"
                      value={r.dstPort ?? null}
                      onChange={(val) =>
                        updateNode(node.id, {
                          aclRules: aclRules.map((x) =>
                            x.id === r.id ? { ...x, dstPort: val ?? undefined } : x
                          ),
                        })
                      }
                    />
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card
            size="small"
            title={caps.natCardTitle}
            extra={
              <Button
                size="small"
                icon={<PlusOutlined />}
                onClick={() =>
                  updateNode(node.id, {
                    natRules: [
                      ...natRules,
                      {
                        id: `nat-${Date.now()}`,
                        seq: (natRules.length + 1) * 10,
                        name: `NAT-${natRules.length + 1}`,
                        type: 'snat',
                        srcCidr: '10.0.0.0/8',
                        dstCidr: 'any',
                        translatedIp: '203.0.113.2',
                      },
                    ],
                  })
                }
              >
                Add NAT
              </Button>
            }
          >
            <div className="space-y-1.5">
              {natRules.map((n) => (
                <div key={n.id} className="space-y-1 rounded border border-slate-800 p-1.5">
                  <div className="grid grid-cols-12 items-center gap-1">
                    <InputNumber
                      size="small"
                      className="col-span-2 !w-full"
                      value={n.seq}
                      onChange={(val) =>
                        updateNode(node.id, {
                          natRules: natRules.map((x) =>
                            x.id === n.id ? { ...x, seq: val ?? 10 } : x
                          ),
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-5"
                      value={n.name}
                      placeholder="NAT name"
                      onChange={(e) =>
                        updateNode(node.id, {
                          natRules: natRules.map((x) =>
                            x.id === n.id ? { ...x, name: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <Select
                      size="small"
                      className="col-span-4"
                      value={n.type}
                      onChange={(val) =>
                        updateNode(node.id, {
                          natRules: natRules.map((x) =>
                            x.id === n.id ? { ...x, type: val } : x
                          ),
                        })
                      }
                      options={[
                        { value: 'snat', label: 'SNAT (Src)' },
                        { value: 'dnat', label: 'DNAT (Dst)' },
                      ]}
                    />
                    <Button
                      size="small"
                      danger
                      type="text"
                      className="col-span-1"
                      icon={<DeleteOutlined />}
                      onClick={() =>
                        updateNode(node.id, {
                          natRules: natRules.filter((x) => x.id !== n.id),
                        })
                      }
                    />
                  </div>
                  <div className="grid grid-cols-12 items-center gap-1">
                    <Input
                      size="small"
                      className="col-span-4"
                      value={n.srcCidr}
                      placeholder="Src CIDR"
                      style={{ fontFamily: 'monospace' }}
                      onChange={(e) =>
                        updateNode(node.id, {
                          natRules: natRules.map((x) =>
                            x.id === n.id ? { ...x, srcCidr: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-4"
                      value={n.dstCidr}
                      placeholder="Dst CIDR"
                      style={{ fontFamily: 'monospace' }}
                      onChange={(e) =>
                        updateNode(node.id, {
                          natRules: natRules.map((x) =>
                            x.id === n.id ? { ...x, dstCidr: e.target.value } : x
                          ),
                        })
                      }
                    />
                    <Input
                      size="small"
                      className="col-span-4"
                      value={n.translatedIp}
                      placeholder="Translated IP"
                      style={{ fontFamily: 'monospace' }}
                      onChange={(e) =>
                        updateNode(node.id, {
                          natRules: natRules.map((x) =>
                            x.id === n.id ? { ...x, translatedIp: e.target.value } : x
                          ),
                        })
                      }
                    />
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      ),
    },
    {
      key: 'links',
      label: `Links (${nodeLinks.length})`,
      children: (
        <div className="space-y-3">
          <div className="space-y-1.5">
            {nodeLinks.map((l) => {
              const src = topology.nodes.find((n) => n.id === l.sourceNodeId);
              const dst = topology.nodes.find((n) => n.id === l.targetNodeId);
              const sIf = src?.interfaces.find((i) => i.id === l.sourceInterfaceId);
              const dIf = dst?.interfaces.find((i) => i.id === l.targetInterfaceId);
              return (
                <div
                  key={l.id}
                  className="flex items-center justify-between rounded border border-slate-800 bg-[#0b1120] px-2.5 py-1.5 text-xs"
                >
                  <span>
                    <strong>{src?.hostname}</strong>:
                    <span className="font-mono text-sky-300">{sIf?.name}</span> ↔{' '}
                    <strong>{dst?.hostname}</strong>:
                    <span className="font-mono text-sky-300">{dIf?.name}</span>
                    {l.linkType === 'ipsec' && (
                      <Tag color="purple" className="!ml-1.5 !text-[9px]">
                        IPsec {l.ipsecConfig?.ikeVersion ?? 'IKEv2'}
                      </Tag>
                    )}
                  </span>
                  <Button
                    size="small"
                    danger
                    type="text"
                    icon={<DeleteOutlined />}
                    onClick={() => deleteLink(l.id)}
                  />
                </div>
              );
            })}
          </div>

          {targetNode && (() => {
            const validSrcIf = node.interfaces.some((i) => i.id === newLinkSrcIf)
              ? newLinkSrcIf
              : node.interfaces[0]?.id;
            const validDstIf = targetNode.interfaces.some((i) => i.id === newLinkDstIf)
              ? newLinkDstIf
              : targetNode.interfaces[0]?.id;
            return (
              <Card size="small" title="Connect Interface Link">
                <div className="grid grid-cols-3 gap-1.5">
                  <Select
                    size="small"
                    value={validSrcIf}
                    onChange={setNewLinkSrcIf}
                    options={node.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                  />
                  <Select
                    size="small"
                    value={targetNode.id}
                    onChange={(val) => {
                      setNewLinkTargetId(val);
                      setNewLinkDstIf('');
                    }}
                    options={otherNodes.map((n) => ({ value: n.id, label: n.hostname }))}
                  />
                  <Select
                    size="small"
                    value={validDstIf}
                    onChange={setNewLinkDstIf}
                    options={targetNode.interfaces.map((i) => ({ value: i.id, label: i.name }))}
                  />
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <Select
                    size="small"
                    className="flex-1"
                    value={newLinkType}
                    onChange={(v) => setNewLinkType(v as 'ethernet' | 'ipsec')}
                    options={[
                      { value: 'ethernet', label: 'Ethernet / L3 Link' },
                      { value: 'ipsec', label: 'IPsec Tunnel (IKEv2)' },
                    ]}
                  />
                  <Button
                    size="small"
                    type="primary"
                    icon={<PlusOutlined />}
                    onClick={() => {
                      if (!validSrcIf || !validDstIf) return;
                      addLink({
                        id: `link-${Date.now()}`,
                        sourceNodeId: node.id,
                        sourceInterfaceId: validSrcIf,
                        targetNodeId: targetNode.id,
                        targetInterfaceId: validDstIf,
                        linkType: newLinkType,
                        ipsecConfig:
                          newLinkType === 'ipsec'
                            ? { ikeVersion: 'IKEv2', cryptoProfile: 'AES256-GCM-SHA256' }
                            : undefined,
                      });
                    }}
                  >
                    Create Link
                  </Button>
                </div>
              </Card>
            );
          })()}
        </div>
      ),
    },
  ];

  return (
    <div className="flex h-full flex-col bg-[#121214]">
      <div className="flex items-center justify-between border-b border-white/[0.08] bg-[#1c1c1e]/90 px-3.5 py-2 backdrop-blur-md">
        <Space size="small">
          <span className="text-xs font-semibold tracking-tight text-[#f5f5f7]">{node.hostname}</span>
          <Tag color="blue" className="!m-0 !rounded-full !text-[10px]">
            {(VENDOR_METADATA[node.vendor] ?? VENDOR_METADATA['cisco-ios-xe']).label}
          </Tag>
        </Space>
        <Space size="small">
          {headerExtra}
          <Button
            size="small"
            type="text"
            icon={<CopyOutlined />}
            onClick={() => duplicateNode(node.id)}
          >
            Clone
          </Button>
          <Button
            size="small"
            danger
            type="text"
            icon={<DeleteOutlined />}
            onClick={() => deleteNode(node.id)}
          >
            Delete
          </Button>
        </Space>
      </div>

      <div className="flex-1 overflow-y-auto px-3 pb-3">
        <Tabs size="small" items={tabItems} />
      </div>
    </div>
  );
};
