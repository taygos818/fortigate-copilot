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
      if (service.objectType !== "vip") {
        continue;
      }
  
      const relatedObjectNames = [service.objectName];
      const linkedPolicies = service.linkedPolicies;
  
      if (linkedPolicies.length === 0) {
        findings.push({
          id: `unused-vip-${service.objectName}`,
          severity: "medium",
          title: `VIP ${service.objectName} has no linked policy`,
          summary:
            "This VIP exists in configuration but is not directly referenced by any firewall policy.",
          relatedObjectNames,
          relatedObjectType: "vip",
          recommendation:
            "Confirm whether this VIP is still needed. Remove it if it is stale or unused.",
        });
      }
  
      for (const policy of linkedPolicies) {
        if (isAnySourcePolicy(policy)) {
          findings.push({
            id: `vip-any-source-${service.objectName}-${policy.id}`,
            severity: "high",
            title: `VIP ${service.objectName} is exposed to any source`,
            summary: `Policy ${policy.id} allows traffic from 'all' sources to this VIP.`,
            details: buildPolicyDetails(policy),
            policyIds: [policy.id],
            relatedObjectNames,
            relatedObjectType: "vip",
            recommendation:
              "Restrict source addresses to only trusted networks or known partner/public IP ranges.",
          });
        }
  
        if (isBroadServicePolicy(policy)) {
          findings.push({
            id: `vip-broad-service-${service.objectName}-${policy.id}`,
            severity: "medium",
            title: `VIP ${service.objectName} uses broad service exposure`,
            summary: `Policy ${policy.id} uses broad service definitions such as ALL.`,
            details: buildPolicyDetails(policy),
            policyIds: [policy.id],
            relatedObjectNames,
            relatedObjectType: "vip",
            recommendation:
              "Restrict the allowed services to the minimum required ports/protocols.",
          });
        }
  
        if (isWanPublished(service, policy)) {
          findings.push({
            id: `vip-wan-published-${service.objectName}-${policy.id}`,
            severity: "info",
            title: `VIP ${service.objectName} is published from a WAN-facing interface`,
            summary: `Policy ${policy.id} and/or VIP interface indicates internet-facing publication.`,
            details: buildPolicyDetails(policy, service),
            policyIds: [policy.id],
            relatedObjectNames,
            relatedObjectType: "vip",
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