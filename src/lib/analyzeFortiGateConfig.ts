import { AnalysisResult, VirtualServer } from "../types/firewall";
import { parsePolicies } from "../parsers/parsePolicies";
import { parseVips } from "../parsers/parseVips";
import { linkPublishedServices } from "./linkPublishedServices";
import { checkVipFindings } from "../checks/checkPublishedServiceFindings";
import { calculateRiskScore } from "./riskScore";
import { parseVirtualServers } from "@/parsers/parseVirtualServers";

export function analyzeFortiGateConfig(configText: string): AnalysisResult {
  const policies = parsePolicies(configText);
  const vips = parseVips(configText);
  const virtualServers = parseVirtualServers(configText);

  const linkedPublishedServices = linkPublishedServices(policies, vips, virtualServers);
  const findings = checkVipFindings(linkedPublishedServices);
  const risk = calculateRiskScore(findings);

  return {
    summary: {
      vendor: "fortigate",
      policyCount: policies.length,
      vipCount: vips.length,
      virtualServerCount: virtualServers.length,
      linkedPublishedServiceCount: linkedPublishedServices.length,
      riskScore: risk.score,
    },
    policies,
    vips,
    virtualServers,
    linkedPublishedServices,
    findings,
    aiRecommendations: undefined,
  };
}