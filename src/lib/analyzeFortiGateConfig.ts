import { AnalysisResult } from "../types/firewall";
import { parseConfigTree } from "../parsers/configTree";
import { parsePolicies } from "../parsers/parsePolicies";
import { parseVips } from "../parsers/parseVips";
import { parseVirtualServers } from "../parsers/parseVirtualServers";
import { parseAddressGroups } from "../parsers/parseAddressGroups";
import { parseWanInterfaces } from "../parsers/parseInterfaces";
import { linkPublishedServices } from "./linkPublishedServices";
import { checkPublishedServiceFindings } from "../checks/checkPublishedServiceFindings";
import { calculateRiskScore } from "./riskScore";
import { generateRecommendations } from "./generateRecommendations";

export function analyzeFortiGateConfig(configText: string): AnalysisResult {
  const tree = parseConfigTree(configText);

  const policies = parsePolicies(tree);
  const vips = parseVips(tree);
  const virtualServers = parseVirtualServers(tree);
  const groups = parseAddressGroups(tree);
  const wanInterfaces = parseWanInterfaces(tree);

  const linkedPublishedServices = linkPublishedServices(policies, vips, virtualServers, groups);
  const findings = checkPublishedServiceFindings(linkedPublishedServices, { groups, wanInterfaces });
  const risk = calculateRiskScore(findings);
  const recommendations = generateRecommendations(findings);

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
    recommendations,
  };
}
