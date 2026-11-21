import {
  Finding,
  FirewallPolicy,
  LinkedPublishedService,
} from "../types/firewall";
import { GroupMembers, expandAddresses } from "../parsers/parseAddressGroups";
import { DEFAULT_WAN_NAMES } from "../parsers/parseInterfaces";

export interface FindingContext {
  /** Address and VIP groups, used to see whether a source group contains `all`. */
  groups?: GroupMembers;
  /** Lower-case interface and zone names treated as internet-facing. */
  wanInterfaces?: Set<string>;
}

export function checkPublishedServiceFindings(
  linkedPublishedServices: LinkedPublishedService[],
  context: FindingContext = {}
): Finding[] {
  const groups = context.groups ?? new Map();
  const wanInterfaces = context.wanInterfaces ?? new Set(DEFAULT_WAN_NAMES);
  const findings: Finding[] = [];

  for (const service of linkedPublishedServices) {
    const relatedObjectNames = [service.objectName];
    const linkedPolicies = service.linkedPolicies;
    const objectLabel =
      service.objectType === "vip" ? "VIP" : "Virtual Server";

    if (linkedPolicies.length === 0) {
      findings.push({
        id: `unlinked-${service.objectType}-${service.objectName}`,
        severity: "info",
        title: `${objectLabel} ${service.objectName} has no linked accepting policy`,
        summary: `No enabled accepting policy names this ${service.objectType}, directly or through an address or VIP group in this configuration.`,
        relatedObjectNames,
        relatedObjectType: service.objectType,
        recommendation:
          "Confirm the object is unused (for example, not referenced from another VDOM or a central NAT rule) before removing it.",
      });
    }

    for (const policy of linkedPolicies) {
      if (policy.status?.toLowerCase() === "disable" || policy.action.toLowerCase() !== "accept") {
        continue;
      }
      const anySourceVia = anySourceGroupChain(policy, groups);
      if (anySourceVia) {
        findings.push({
          id: `${service.objectType}-any-source-${service.objectName}-${policy.id}`,
          severity: "high",
          title: `${objectLabel} ${service.objectName} is exposed to any source`,
          summary:
            anySourceVia.length > 0
              ? `Policy ${policy.id} allows traffic from 'all' sources (through group ${anySourceVia.join(" > ")}) to this ${service.objectType}.`
              : `Policy ${policy.id} allows traffic from 'all' sources to this ${service.objectType}.`,
          details: buildPolicyDetails(policy, service),
          policyIds: [policy.id],
          relatedObjectNames,
          relatedObjectType: service.objectType,
          recommendation:
            "Restrict source addresses to only trusted networks or known partner/public IP ranges.",
        });
      }

      if (isBroadServicePolicy(policy)) {
        findings.push({
          id: `${service.objectType}-broad-service-${service.objectName}-${policy.id}`,
          severity: "medium",
          title: `${objectLabel} ${service.objectName} uses broad service exposure`,
          summary: `Policy ${policy.id} uses broad service definitions such as ALL.`,
          details: buildPolicyDetails(policy, service),
          policyIds: [policy.id],
          relatedObjectNames,
          relatedObjectType: service.objectType,
          recommendation:
            "Restrict the allowed services to the minimum required ports and protocols.",
        });
      }

      if (isWanPublished(service, policy, wanInterfaces)) {
        findings.push({
          id: `${service.objectType}-wan-published-${service.objectName}-${policy.id}`,
          severity: "info",
          title: `${objectLabel} ${service.objectName} is published from a WAN-facing interface`,
          summary: `Policy ${policy.id} and/or published object interface indicates internet-facing publication.`,
          details: buildPolicyDetails(policy, service),
          policyIds: [policy.id],
          relatedObjectNames,
          relatedObjectType: service.objectType,
          recommendation:
            "Review whether internet exposure is intended and confirm the source and service restrictions are appropriate.",
        });
      }
    }
  }

  return dedupeFindings(findings);
}

/**
 * The group chain through which a policy's source reaches `all`: an empty list
 * for a direct `all`, a list of group names for an indirect one, or undefined
 * when the source never resolves to `all`.
 */
function anySourceGroupChain(policy: FirewallPolicy, groups: GroupMembers): string[] | undefined {
  const matches = expandAddresses(policy.srcaddr, groups).filter(
    (address) => address.name.toLowerCase() === "all"
  );

  if (matches.length === 0) {
    return undefined;
  }

  return matches.reduce((best, match) => (match.via.length < best.via.length ? match : best)).via;
}

function isBroadServicePolicy(policy: FirewallPolicy): boolean {
  return policy.service.some((svc) => svc.toUpperCase() === "ALL");
}

function isWanPublished(
  service: LinkedPublishedService,
  policy: FirewallPolicy,
  wanInterfaces: Set<string>
): boolean {
  const interfaceNames = [
    ...(service.externalInterface ? [service.externalInterface] : []),
    ...policy.srcintf,
  ].map((name) => name.toLowerCase());

  // `any` as a policy source interface includes every WAN interface.
  const anySourceInterface = policy.srcintf.some((name) => name.toLowerCase() === "any");

  return anySourceInterface || interfaceNames.some((name) => wanInterfaces.has(name));
}

function buildPolicyDetails(
  policy: FirewallPolicy,
  service?: LinkedPublishedService
): string {
  const parts = [
    `Policy ID: ${policy.id}`,
    `Source Interfaces: ${policy.srcintf.join(", ") || "none"}`,
    `Destination Interfaces: ${policy.dstintf.join(", ") || "none"}`,
    `Source Addresses: ${policy.srcaddr.join(", ") || "none"}`,
    `Destination Addresses: ${policy.dstaddr.join(", ") || "none"}`,
    `Services: ${policy.service.join(", ") || "none"}`,
  ];

  if (service) {
    parts.push(
      `Published Object: ${service.objectName}`,
      `Object Type: ${service.objectType}`,
      `External Interface: ${service.externalInterface ?? "unknown"}`,
      `External IP: ${service.externalIp ?? "unknown"}`,
      `External Port: ${service.externalPort ?? "unknown"}`,
      `Internal Targets: ${service.internalTargets.join(", ") || "none"}`
    );

    const via = service.linkedVia[policy.id];
    if (via && via.length > 0) {
      parts.push(`Linked Through Group: ${via.join(" > ")}`);
    }
  }

  return parts.join(" | ");
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];

  for (const finding of findings) {
    if (seen.has(finding.id)) {
      continue;
    }

    seen.add(finding.id);
    result.push(finding);
  }

  return result;
}
