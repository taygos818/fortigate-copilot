export type FirewallVendor = "fortigate";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export type PublishedObjectType = "vip" | "virtual-server";

export interface FirewallPolicy {
  id: number;
  name?: string;
  srcintf: string[];
  dstintf: string[];
  srcaddr: string[];
  dstaddr: string[];
  service: string[];
  action: string;
  schedule?: string;
  status?: string;
  logtraffic?: string;
  comments?: string;
}

export interface VirtualIp {
  name: string;
  type?: string;
  extip?: string;
  extintf?: string;
  mappedip: string[];
  portforward?: boolean;
  extport?: string;
  mappedport?: string;
  protocol?: string;
  realServers: VirtualServerRealServer[];
  comments?: string;
}

export interface VirtualServerRealServer {
  ip: string;
  port?: string;
  status?: string;
}

export interface VirtualServer {
  name: string;
  interface?: string;
  ip?: string;
  port?: string;
  type?: string;
  loadBalanceMethod?: string;
  serverType?: string;
  realServers: VirtualServerRealServer[];
  comments?: string;
}

export interface LinkedPublishedService {
  objectType: PublishedObjectType;
  objectName: string;
  externalInterface?: string;
  externalIp?: string;
  externalPort?: string;
  internalTargets: string[];
  linkedPolicyIds: number[];
  linkedPolicies: FirewallPolicy[];
  /** Policy id -> groups the policy's dstaddr went through to reach this object. */
  linkedVia: Record<number, string[]>;
}

export interface Finding {
  id: string;
  severity: FindingSeverity;
  title: string;
  summary: string;
  details?: string;
  policyIds?: number[];
  relatedObjectNames?: string[];
  relatedObjectType?: PublishedObjectType;
  recommendation?: string;
}

export interface AnalysisSummary {
  vendor: FirewallVendor;
  policyCount: number;
  vipCount: number;
  virtualServerCount: number;
  linkedPublishedServiceCount: number;
  riskScore: number;
}

export interface AnalysisResult {
  summary: AnalysisSummary;
  policies: FirewallPolicy[];
  vips: VirtualIp[];
  virtualServers: VirtualServer[];
  linkedPublishedServices: LinkedPublishedService[];
  findings: Finding[];
  recommendations: {
    summary: string;
    recommendations: string[];
  };
}
