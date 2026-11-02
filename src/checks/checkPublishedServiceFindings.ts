import {
  Finding,
  FirewallPolicy,
  LinkedPublishedService,
} from "../types/firewall";

export function checkVipFindings(
  linkedPublishedServices: LinkedPublishedService[]
): Finding[] {
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
        title: `${objectLabel} ${service.objectName} has no directly linked accepting policy`,
        summary: `No enabled accepting policy directly names this ${service.objectType}. Address groups and other indirect references are not resolved.`,
        relatedObjectNames,
        relatedObjectType: service.objectType,
        recommendation:
          "Check address groups and other indirect references before deciding whether this object is unused.",
      });
    }

    for (const policy of linkedPolicies) {
      if (policy.status?.toLowerCase() === "disable" || policy.action.toLowerCase() !== "accept") {
        continue;
      }
      if (isAnySourcePolicy(policy)) {
        findings.push({
          id: `${service.objectType}-any-source-${service.objectName}-${policy.id}`,
          severity: "high",
          title: `${objectLabel} ${service.objectName} is exposed to any source`,
          summary: `Policy ${policy.id} allows traffic from 'all' sources to this ${service.objectType}.`,
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

      if (isWanPublished(service, policy)) {
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

function isAnySourcePolicy(policy: FirewallPolicy): boolean {
  return policy.srcaddr.some((addr) => addr.toLowerCase() === "all");
}

function isBroadServicePolicy(policy: FirewallPolicy): boolean {
  return policy.service.some((svc) => svc.toUpperCase() === "ALL");
}

function isWanPublished(
  service: LinkedPublishedService,
  policy: FirewallPolicy
): boolean {
  const interfaceNames = [
    ...(service.externalInterface ? [service.externalInterface] : []),
    ...policy.srcintf,
  ].map((name) => name.toLowerCase());

  return interfaceNames.some((name) =>
    ["wan", "wan1", "wan2", "internet", "external", "outside"].includes(name)
  );
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
