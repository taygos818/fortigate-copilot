import { FirewallPolicy } from "../types/firewall";

/**
 * Parse a FortiGate `config firewall policy` section into FirewallPolicy[].
 */
export function parsePolicies(configText: string): FirewallPolicy[] {
  const lines = configText.split(/\r?\n/);

  const policies: FirewallPolicy[] = [];

  let inPolicySection = false;
  let currentPolicy: Partial<FirewallPolicy> | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!inPolicySection) {
      if (line === "config firewall policy") {
        inPolicySection = true;
      }
      continue;
    }

    if (line === "end") {
      if (currentPolicy) {
        policies.push(finalizePolicy(currentPolicy));
        currentPolicy = null;
      }
      break;
    }

    if (line.startsWith("edit ")) {
      if (currentPolicy) {
        policies.push(finalizePolicy(currentPolicy));
      }

      const idText = line.slice("edit ".length).trim().replace(/^"|"$/g, "");
      const id = Number.parseInt(idText, 10);

      currentPolicy = {
        id: Number.isNaN(id) ? -1 : id,
        srcintf: [],
        dstintf: [],
        srcaddr: [],
        dstaddr: [],
        service: [],
        action: "deny",
      };

      continue;
    }

    if (line === "next") {
      if (currentPolicy) {
        policies.push(finalizePolicy(currentPolicy));
        currentPolicy = null;
      }
      continue;
    }

    if (!currentPolicy || !line.startsWith("set ")) {
      continue;
    }

    const setLine = line.slice(4).trim();
    const spaceIndex = setLine.indexOf(" ");

    if (spaceIndex === -1) {
      continue;
    }

    const key = setLine.slice(0, spaceIndex).trim();
    const value = setLine.slice(spaceIndex + 1).trim();

    switch (key) {
      case "name":
        currentPolicy.name = stripOuterQuotes(value);
        break;

      case "srcintf":
        currentPolicy.srcintf = parseQuotedList(value);
        break;

      case "dstintf":
        currentPolicy.dstintf = parseQuotedList(value);
        break;

      case "srcaddr":
        currentPolicy.srcaddr = parseQuotedList(value);
        break;

      case "dstaddr":
        currentPolicy.dstaddr = parseQuotedList(value);
        break;

      case "service":
        currentPolicy.service = parseQuotedList(value);
        break;

      case "action":
        currentPolicy.action = stripOuterQuotes(value);
        break;

      case "schedule":
        currentPolicy.schedule = stripOuterQuotes(value);
        break;

      case "status":
        currentPolicy.status = stripOuterQuotes(value);
        break;

      case "logtraffic":
        currentPolicy.logtraffic = stripOuterQuotes(value);
        break;

      case "comments":
        currentPolicy.comments = stripOuterQuotes(value);
        break;

      default:
        break;
    }
  }

  return policies;
}

function finalizePolicy(policy: Partial<FirewallPolicy>): FirewallPolicy {
  return {
    id: policy.id ?? -1,
    name: policy.name,
    srcintf: policy.srcintf ?? [],
    dstintf: policy.dstintf ?? [],
    srcaddr: policy.srcaddr ?? [],
    dstaddr: policy.dstaddr ?? [],
    service: policy.service ?? [],
    action: policy.action ?? "deny",
    schedule: policy.schedule,
    status: policy.status,
    logtraffic: policy.logtraffic,
    comments: policy.comments,
  };
}

function parseQuotedList(value: string): string[] {
  return [...value.matchAll(/"([^"]*)"|(\S+)/g)].map((match) => match[1] ?? match[2]);
}

function stripOuterQuotes(value: string): string {
  return value.replace(/^"(.*)"$/, "$1").trim();
}
