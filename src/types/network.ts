export type VendorProfile =
  | 'cisco-ios-xe'
  | 'cisco-nx-os'
  | 'cisco-ios-xr'
  | 'cisco-sdwan'
  | 'prisma-sdwan'
  | 'pan-os'
  | 'forcepoint-ngfw'
  | 'arista-eos'
  | 'aruba-aos-cx'
  | 'juniper-junos'
  | 'mikrotik-routeros'
  | 'fortigate'
  | 'checkpoint-gaia'
  | 'vyos'
  | 'mpls-cloud'
  | 'internet-cloud'
  | 'aws-cloud'
  | 'aws-cloudwan'
  | 'azure-cloud'
  | 'gcp-cloud'
  | 'oci-cloud'
  | 'cloudflare-mwan';

export type ProtocolType =
  | 'connected'
  | 'local'
  | 'static'
  | 'omp'
  | 'lisp'
  | 'ospf'
  | 'eigrp'
  | 'isis'
  | 'rip'
  | 'ebgp'
  | 'ibgp';

export type OspfRouteType = 'intra' | 'inter' | 'ext1' | 'ext2';
export type BgpOriginType = 'igp' | 'egp' | 'incomplete';

export interface PrefixListEntry {
  id: string;
  seq: number;
  action: 'permit' | 'deny';
  prefix: string;
  ge?: number;
  le?: number;
}

export interface PrefixListConfig {
  id: string;
  name: string;
  entries: PrefixListEntry[];
}

export interface RouteMapAction {
  setLocalPref?: number;
  setMed?: number;
  prependAsPath?: number[];
  setAd?: number;
  setOspfMetricType?: 'E1' | 'E2';
  setCommunity?: string;
  setCommunityAdditive?: boolean;
  deleteCommunity?: string;
  setLargeCommunity?: string;
  setLargeCommunityAdditive?: boolean;
  deleteLargeCommunity?: string;
  setTag?: number;
}

export interface RouteMapEntry {
  id: string;
  seq: number;
  action: 'permit' | 'deny';
  matchPrefixListId?: string;
  matchCommunity?: string;
  matchLargeCommunity?: string;
  matchAsPathRegex?: string;
  matchRpki?: 'valid' | 'invalid' | 'not-found';
  matchTag?: number;
  set: RouteMapAction;
}

export interface RouteMapConfig {
  id: string;
  name: string;
  entries: RouteMapEntry[];
}

export interface VrfLeakRule {
  id: string;
  fromVrf: string;
  toVrf: string;
  matchPrefixListId?: string;
}

export interface InterfaceConfig {
  id: string;
  name: string;
  cidr: string;
  cidr6?: string;
  vrf: string;
  ospfArea?: number;
  ospfCost?: number;
  ospfPriority?: number;
  ospfNetworkType?: 'broadcast' | 'point-to-point' | 'non-broadcast' | 'point-to-multipoint';
  ospfHelloInterval?: number;
  ospfDeadInterval?: number;
  speedMbps?: number;
  eigrpBw?: number;
  eigrpDelay?: number;
  eigrpHelloInterval?: number;
  eigrpHoldTime?: number;
  isisLevel?: 'L1' | 'L2';
  isisMetric?: number;
  isisPriority?: number;
  isisNetworkType?: 'broadcast' | 'point-to-point';
  isisHelloInterval?: number;
  isisHelloMultiplier?: number;
  bfdIntervalMs?: number;
  bfdMinRxMs?: number;
  bfdMultiplier?: number;
  ospfAuthKey?: string;
  urpfMode?: 'strict' | 'loose';
  unnumberedSource?: string;
  secondaryCidrs?: string[];
  lacpGroup?: number;
  lacpMode?: 'active' | 'passive' | 'desirable' | 'auto' | 'on';
  lagProtocol?: 'lacp' | 'pagp' | 'static';
  stpCost?: number;
  pimSparse?: boolean;
  dhcpHelperIps?: string[];
  qosPolicy?: {
    dscpMark?: number;
    policeMbps?: number;
    pfcPriorities?: number[];
    etsBwPct?: number[];
    ecnEnabled?: boolean;
  };
  macsecEnabled?: boolean;
  dot1xState?: 'authorized' | 'unauthorized' | 'force-authorized';
  dhcpSnoopingTrust?: boolean;
  daiEnabled?: boolean;
  ipSourceGuard?: boolean;
  raGuard?: boolean;
  evpnEsi?: string;
  cfmMdLevel?: number;
  zone?: string;
  vlanId?: number;
  parentInterface?: string;
  mtu?: number;
  vpcId?: number;
  mlagId?: number;
  tlocColor?: string;
  tlocEncap?: 'ipsec' | 'gre';
  tlocExtension?: string;
  passive?: boolean;
  shutdown?: boolean;
}

export interface EigrpNetworkConfig {
  id: string;
  vrf?: string;
  prefix: string;
  bandwidth?: number;
  delay?: number;
  tag?: number;
}

export interface IsisNetworkConfig {
  id: string;
  vrf?: string;
  prefix: string;
  level?: 'L1' | 'L2';
  metric?: number;
  tag?: number;
}

export interface PbrRuleConfig {
  id: string;
  name: string;
  srcCidr?: string;
  matchPrefix: string;
  nextHop: string;
  multiLinkPool?: string;
  ingressInterface?: string;
  interfaceName?: string;
  protocol?: L4Protocol;
  dstPort?: number;
}

export type L4Protocol = 'any' | 'tcp' | 'udp' | 'icmp';

export interface AclRuleConfig {
  id: string;
  seq: number;
  name: string;
  action: 'allow' | 'deny';
  srcZone?: string;
  dstZone?: string;
  srcCidr: string;
  dstCidr: string;
  protocol: L4Protocol;
  dstPort?: number;
  networkTag?: string;
}

export interface NatRuleConfig {
  id: string;
  seq: number;
  name: string;
  type: 'snat' | 'dnat';
  srcCidr: string;
  dstCidr: string;
  translatedIp: string;
}

export type AzureUdrNextHopType =
  | 'VirtualAppliance'
  | 'None'
  | 'Internet'
  | 'VnetLocal'
  | 'VirtualNetworkGateway';

export type AwsRouteTargetType =
  | 'igw'
  | 'nat'
  | 'tgw'
  | 'pcx'
  | 'vgw'
  | 'vpce'
  | 'blackhole'
  | 'local';

export type GcpRouteNextHopType =
  | 'default-internet-gateway'
  | 'cloud-nat'
  | 'ilb'
  | 'next-hop-address'
  | 'vpn-tunnel'
  | 'interconnect'
  | 'vpc-peering';

export interface StaticRouteConfig {
  id: string;
  vrf: string;
  prefix: string;
  nextHop: string;
  ad?: number;
  tag?: number;
  interfaceName?: string;
  trackId?: string;
  globalNextHop?: boolean;
  azureNextHopType?: AzureUdrNextHopType;
  awsTargetType?: AwsRouteTargetType;
  gcpNextHopType?: GcpRouteNextHopType;
  gcpPriority?: number;
  networkTag?: string;
}

export interface OspfNetworkConfig {
  id: string;
  vrf?: string;
  prefix: string;
  area: number;
  routeType?: OspfRouteType;
  cost?: number;
  tag?: number;
}

export interface BgpPeerConfig {
  id: string;
  vrf?: string;
  peerIp: string;
  remoteAs: number;
  localPref?: number;
  weight?: number;
  med?: number;
  nextHopSelf?: boolean;
  defaultOriginate?: boolean;
  routeReflectorClient?: boolean;
  ebgpMultihop?: boolean;
  shutdown?: boolean;
  updateSource?: string;
  allowAsIn?: boolean;
  asOverride?: boolean;
  sendCommunity?: 'standard' | 'extended' | 'both' | 'none';
  removePrivateAs?: boolean;
  maxPrefixes?: number;
  addPath?: 'send' | 'receive' | 'both';
  localAs?: number;
  localAsNoPrepend?: boolean;
  localAsReplaceAs?: boolean;
  disableConnectedCheck?: boolean;
  confederationPeer?: boolean;
  linkBandwidthMbps?: number;
  aigp?: boolean;
  bfd?: boolean;
  bfdIntervalMs?: number;
  bfdMinRxMs?: number;
  bfdMultiplier?: number;
  keepaliveTime?: number;
  holdTime?: number;
  gracefulRestart?: boolean;
  softReconfigurationInbound?: boolean;
  routeMapInId?: string;
  routeMapOutId?: string;
}

export interface BgpNetworkConfig {
  id: string;
  vrf?: string;
  prefix: string;
  origin?: BgpOriginType;
  med?: number;
  localPref?: number;
  asPath?: number[];
  communities?: string[];
}

export interface RedistributionRule {
  id: string;
  vrf?: string;
  from: 'connected' | 'static' | 'ospf' | 'eigrp' | 'isis' | 'rip' | 'bgp';
  to: 'ospf' | 'eigrp' | 'isis' | 'rip' | 'bgp';
  metric?: number;
  metricType?: 'E1' | 'E2';
  routeMapId?: string;
}

export interface NodeConfig {
  id: string;
  hostname: string;
  vendor: VendorProfile;
  routerId: string;
  vrfRouterIds?: Record<string, string>;
  adminDown?: boolean;
  position: { x: number; y: number };
  maxPaths: number;
  vrfs: string[];
  adOverrides: Partial<Record<ProtocolType, number>>;
  interfaces: InterfaceConfig[];
  staticRoutes: StaticRouteConfig[];
  ospf: {
    enabled: boolean;
    defaultOriginate?: boolean;
    referenceBandwidth?: number;
    maxMetricRouterLsa?: boolean;
    bfd?: boolean;
    authKey?: string;
    areaTypes?: Record<number, 'normal' | 'stub' | 'totally-stubby' | 'nssa'>;
    nssaNoSummary?: Record<number, boolean>;
    areaRanges?: { id: string; area: number; prefix: string }[];
    virtualLinks?: { id: string; transitArea: number; peerRouterId: string }[];
    shamLinks?: { id: string; vrf: string; area: number; srcIp: string; dstIp: string; cost?: number }[];
    networks: OspfNetworkConfig[];
  };
  eigrp?: {
    enabled: boolean;
    asn: number;
    bfd?: boolean;
    variance?: number;
    kValues?: [number, number, number, number, number];
    summaries?: { id: string; prefix: string }[];
    networks: EigrpNetworkConfig[];
  };
  isis?: {
    enabled: boolean;
    net?: string;
    bfd?: boolean;
    overloadBit?: boolean;
    metricStyle?: 'narrow' | 'wide';
    multiTopologyV6?: boolean;
    level: 'L1' | 'L2' | 'L1-L2';
    summaries?: { id: string; prefix: string }[];
    leakL2ToL1?: { id: string; prefix: string }[];
    networks: IsisNetworkConfig[];
  };
  rip?: {
    enabled: boolean;
    version?: 1 | 2;
    defaultOriginate?: boolean;
    networks: { id: string; vrf?: string; prefix: string }[];
  };
  bgp: {
    enabled: boolean;
    asn: number;
    clusterId?: string;
    confederationId?: number;
    confederationPeers?: number[];
    alwaysCompareMed?: boolean;
    deterministicMed?: boolean;
    bestpathAsPathIgnore?: boolean;
    medMissingAsWorst?: boolean;
    rpkiRejectInvalid?: boolean;
    dampening?: boolean;
    gracefulRestart?: boolean;
    peers: BgpPeerConfig[];
    networks: BgpNetworkConfig[];
    aggregates?: { id: string; vrf?: string; prefix: string; summaryOnly?: boolean; asSet?: boolean }[];
    flowspecRules?: {
      id: string;
      srcCidr?: string;
      dstCidr?: string;
      protocol?: L4Protocol;
      dstPort?: number;
      action: 'drop' | 'rate-limit' | 'redirect';
      rateMbps?: number;
      redirectNextHop?: string;
    }[];
  };
  mpls?: {
    ldpEnabled?: boolean;
    ldpRouterId?: string;
    segmentRouting?: {
      enabled: boolean;
      srgbStart?: number;
      srgbEnd?: number;
      prefixSid?: number;
      srv6Locator?: string;
      tiLfa?: boolean;
    };
    rsvpTeTunnels?: {
      id: string;
      name: string;
      destination: string;
      ero?: string[];
      bandwidthMbps?: number;
    }[];
  };
  switching?: {
    stpEnabled?: boolean;
    stpMode?: 'rstp' | 'mstp' | 'pvst';
    stpPriority?: number;
    lldpEnabled?: boolean;
  };
  multicast?: {
    pimEnabled?: boolean;
    rpAddress?: string;
    igmpGroups?: { id: string; group: string; interfaceId: string; source?: string }[];
  };
  nat64Rules?: { id: string; prefix6: string; pool4Cidr: string }[];
  vplsInstances?: { id: string; vcId: number; peerIp: string; vlanId?: number }[];
  oam?: { cfmEnabled?: boolean; stampEnabled?: boolean };
  timing?: {
    ptpMode?: 'grandmaster' | 'boundary' | 'transparent';
    ptpDomain?: number;
    ntpServer?: string;
    ntpStratum?: number;
  };
  telemetry?: {
    bmpServerIp?: string;
    ipfixCollectorIp?: string;
  };
  redistributions: RedistributionRule[];
  prefixLists: PrefixListConfig[];
  routeMaps: RouteMapConfig[];
  vrfLeaks: VrfLeakRule[];
  pbrRules?: PbrRuleConfig[];
  aclRules?: AclRuleConfig[];
  natRules?: NatRuleConfig[];
  fhrpGroups?: {
    id: string;
    protocol: 'hsrp' | 'vrrp' | 'glbp';
    groupId: number;
    interfaceId: string;
    virtualIp: string;
    priority: number;
    preempt?: boolean;
  }[];
  tracks?: { id: string; targetIp: string; vrf?: string }[];
  sdwanSla?: {
    enabled: boolean;
    probeTargetIp?: string;
    rules: {
      id: string;
      name: string;
      dstCidr?: string;
      protocol?: L4Protocol;
      dstPort?: number;
      mode: 'best-quality' | 'sla-failover' | 'priority';
      preferredMembers: string[];
      maxLatencyMs?: number;
      maxJitterMs?: number;
      maxLossPct?: number;
    }[];
  };
  sdwan?: {
    enabled: boolean;
    systemIp: string;
    siteId: number;
    organizationName?: string;
    vSmartPeers?: string[];
    ompAdminDistance?: number;
    ompGracefulRestart?: boolean;
    advertiseConnected?: boolean;
    advertiseStatic?: boolean;
    advertiseOspf?: boolean;
    advertiseBgp?: boolean;
  };
  lisp?: {
    enabled: boolean;
    role: 'xtr' | 'ms-mr' | 'pxtr' | 'pitr' | 'petr';
    rlocIp: string;
    mapServerIp?: string;
    instanceId?: number;
    rlocProbing?: boolean;
    mapCacheTtlMin?: number;
    bfd?: boolean;
    bfdIntervalMs?: number;
    bfdMinRxMs?: number;
    bfdMultiplier?: number;
    eidPrefixes: {
      id: string;
      prefix: string;
      vrf?: string;
      instanceId?: number;
      priority?: number;
      weight?: number;
    }[];
  };
  evpn?: {
    enabled: boolean;
    vtepIp: string;
    l3Vni?: number;
    l2Vni?: number;
    vrf?: string;
    advertiseConnected?: boolean;
  };
  mplsVpn?: {
    enabled: boolean;
    vrfTargets: {
      id: string;
      vrf: string;
      rd: string;
      importRt: string;
      exportRt: string;
    }[];
  };
  vpc?: {
    enabled: boolean;
    domainId: number;
    rolePriority?: number;
    systemPriority?: number;
    peerKeepaliveDst?: string;
    peerKeepaliveSrc?: string;
    peerKeepaliveVrf?: string;
    peerLinkInterfaceId?: string;
    peerGateway?: boolean;
    peerSwitch?: boolean;
    layer3PeerRouter?: boolean;
    autoRecovery?: boolean;
    ipArpSynchronize?: boolean;
    delayRestore?: number;
  };
  panHa?: {
    enabled: boolean;
    mode: 'active-passive' | 'active-active';
    groupId: number;
    devicePriority?: number;
    preempt?: boolean;
    sessionSync?: boolean;
    ha1InterfaceId?: string;
    ha2InterfaceId?: string;
    ha3HsciInterfaceId?: string;
  };
  fortiHa?: {
    enabled: boolean;
    mode: 'a-p' | 'a-a';
    groupId: number;
    priority?: number;
    sessionPickup?: boolean;
    override?: boolean;
    hbInterfaceId?: string;
  };
  forcepointCluster?: {
    enabled: boolean;
    mode: 'standby' | 'load-balancing';
    clusterId: number;
    heartbeatInterfaceId?: string;
    stateSync?: boolean;
    cviIp?: string;
  };
  mlag?: {
    enabled: boolean;
    domainId: string;
    localInterface?: string;
    peerAddress?: string;
    peerLinkInterfaceId?: string;
    reloadDelay?: number;
  };
  cloudConfig?: {
    region?: string;
    dynamicRoutingMode?: 'regional' | 'global';
    applianceMode?: boolean;
    udrOverridesBgp?: boolean;
    disableBgpPropagation?: boolean;
    preferPrivateCircuit?: boolean;
    blackholeCidrs?: string[];
    defaultRoutePriority?: number;
    privateGoogleAccess?: boolean;
    pgaOnPremAdvertise?: boolean;
    nccHubEnabled?: boolean;
    pscEndpoints?: string[];
  };
}

export interface LinkConfig {
  id: string;
  sourceNodeId: string;
  sourceInterfaceId: string;
  targetNodeId: string;
  targetInterfaceId: string;
  adminDown?: boolean;
  sourceHandle?: 'top' | 'right' | 'bottom' | 'left';
  targetHandle?: 'top' | 'right' | 'bottom' | 'left';
  controlPointOffset?: { dx: number; dy: number };
  vlanId?: number;
  l2Mode?: 'access' | 'trunk';
  allowedVlans?: string;
  latencyMs?: number;
  lossPct?: number;
  jitterMs?: number;
  linkType?: 'ethernet' | 'ipsec' | 'layer2';
  ipsecConfig?: {
    ikeVersion?: 'IKEv2' | 'IKEv1';
    cryptoProfile?: string;
    remoteIkeVersion?: 'IKEv2' | 'IKEv1';
    remoteCryptoProfile?: string;
    underlaySrcIp?: string;
    underlayDstIp?: string;
  };
}

export interface RoaEntry {
  id: string;
  prefix: string;
  maxLength: number;
  originAsn: number;
}

export interface TopologyState {
  nodes: NodeConfig[];
  links: LinkConfig[];
  vrfColors?: Record<string, string>;
  roaTable?: RoaEntry[];
}

export interface BgpAttributes {
  weight: number;
  localPref: number;
  locallyOriginated: boolean;
  asPath: number[];
  confedAsPath?: number[];
  asSet?: number[];
  origin: BgpOriginType;
  med: number;
  medMissing?: boolean;
  isEbgp: boolean;
  igpMetric: number;
  peerRouterId: string;
  peerIp: string;
  communities?: string[];
  largeCommunities?: string[];
  clusterList?: string[];
  originatorId?: string;
  rpkiState?: 'valid' | 'invalid' | 'not-found';
  atomicAggregate?: boolean;
  aggregator?: string;
  linkBandwidthMbps?: number;
  aigpMetric?: number;
}

export interface RibEntry {
  af?: 4 | 6;
  prefix: string;
  prefixLen: number;
  vrf: string;
  protocol: ProtocolType;
  ospfType?: OspfRouteType;
  isisLevel?: 'L1' | 'L2';
  feasibleSuccessor?: boolean;
  ad: number;
  metric: number;
  nextHop: string;
  egressInterface: string;
  active: boolean;
  ecmp: boolean;
  reason?: string;
  leakedFromVrf?: string;
  overlayRemoteVrf?: string;
  isisUpDownBit?: boolean;
  tag?: number;
  bgpAttrs?: BgpAttributes;
  tloc?: {
    systemIp: string;
    color: string;
    encap: 'ipsec' | 'gre';
    preference?: number;
    viaTlocExtension?: string;
  };
  lisp?: {
    rlocIp: string;
    instanceId: number;
    priority: number;
    weight: number;
  };
  evpnVni?: number;
  azureNextHopType?: AzureUdrNextHopType;
  awsTargetType?: AwsRouteTargetType;
  gcpNextHopType?: GcpRouteNextHopType;
  gcpPriority?: number;
  networkTag?: string;
}

export interface FibEntry {
  af?: 4 | 6;
  prefix: string;
  prefixLen: number;
  vrf: string;
  nextHop: string;
  egressInterface: string;
  protocol: ProtocolType;
  flags: string;
}

export interface NeighborStatus {
  protocol: 'ospf' | 'eigrp' | 'isis' | 'rip' | 'bgp' | 'omp' | 'lisp' | 'hsrp' | 'vrrp' | 'glbp' | 'vpc' | 'ha' | 'mlag';
  neighborId: string;
  peerIp: string;
  interfaceName: string;
  state: 'FULL' | '2-Way' | 'ExStart' | 'Established' | 'Up' | 'Active' | 'Standby' | 'Down';
  ospfRole?: 'DR' | 'BDR' | 'DROther' | 'P2P';
  isisDis?: boolean;
  detail?: string;
}

export interface LfibEntry {
  inLabel: number | string;
  outLabel: number | string | 'POP';
  prefix: string;
  nextHop: string;
  egressInterface: string;
  protocol: 'ldp' | 'sr-mpls' | 'srv6' | 'rsvp-te';
}

export interface StpNodeState {
  rootBridgeId: string;
  isRoot: boolean;
  ports: {
    interfaceName: string;
    role: 'Root' | 'Designated' | 'Alternate';
    state: 'Forwarding' | 'Blocking';
  }[];
}

export interface MrouteEntry {
  source: string;
  group: string;
  rpfInterface: string;
  oifList: string[];
  rp?: string;
}

export interface NodeRoutingResult {
  nodeId: string;
  hostname: string;
  vendor: VendorProfile;
  rib: RibEntry[];
  fib: FibEntry[];
  neighbors?: NeighborStatus[];
  lfib?: LfibEntry[];
  stpState?: StpNodeState;
  lldpNeighbors?: { localInterface: string; remoteChassisId: string; remotePort: string }[];
  mroute?: MrouteEntry[];
  evpnDfState?: { esi: string; interfaceName: string; role: 'DF' | 'Backup' }[];
  bmpSummary?: { serverIp: string; peerCount: number; adjRibInCount: number };
  warnings: string[];
}

export interface SimulationResult {
  nodes: Record<string, NodeRoutingResult>;
  computeTimeMs: number;
  convergedIterations: number;
  warnings: string[];
}

export interface PacketTraceHop {
  nodeId: string;
  hostname: string;
  vrf: string;
  ingressInterface?: string;
  egressInterface: string;
  nextHop: string;
  matchedPrefix: string;
  protocol: ProtocolType;
  ad: number;
  metric: number;
  status: 'forwarded' | 'delivered' | 'dropped' | 'loop' | 'blocked';
  routeStatus?: 'ok' | 'no-route' | 'loop';
  aclStatus?: 'allowed' | 'blocked';
  aclMatched?: string;
  natApplied?: string;
  sdwanSteered?: string;
  pbrApplied?: string;
  ecmpPaths?: string[];
  encapNote?: string;
  urpfStatus?: 'pass' | 'drop-strict' | 'drop-loose';
  mplsLabels?: (number | string)[];
  flowspecMatched?: string;
  dscp?: number;
  ecnMarked?: boolean;
  macsecSecured?: boolean;
}

export interface FailoverMatrixEntry {
  linkId: string;
  linkLabel: string;
  passed: number;
  failed: number;
  brokenTests: string[];
}

export interface PacketTraceResult {
  dstIp: string;
  srcIp?: string;
  srcNodeId: string;
  srcInterfaceId?: string;
  vrf: string;
  hops: PacketTraceHop[];
  outcome: 'delivered' | 'dropped' | 'loop' | 'blocked';
  blockedNodeId?: string;
  failureReason?: string;
  totalLatencyMs?: number;
  totalJitterMs?: number;
  combinedLossPct?: number;
  pathMtu?: number;
  mtuWarning?: string;
  asymmetricPath?: boolean;
  ipfixRecord?: {
    srcIp: string;
    dstIp: string;
    protocol: string;
    dstPort?: number;
    bytes: number;
    dscp?: number;
    exporterIp: string;
  };
  returnTrace?: {
    outcome: 'delivered' | 'dropped' | 'loop' | 'blocked';
    hops: PacketTraceHop[];
    failureReason?: string;
  };
}

export interface PathTestCase {
  id: string;
  name: string;
  srcNodeId: string;
  srcInterfaceId?: string;
  srcIp?: string;
  dstIp: string;
  vrf: string;
  protocol: L4Protocol;
  dstPort?: number;
  expectedOutcome: 'delivered' | 'blocked' | 'dropped';
  expectedBlockedNodeId?: string;
}