import { VirtualIp } from "../types/firewall";

/**
 * Parse a FortiGate `config firewall vip` section into VirtualIp[].
 *
 * Supported pattern:
 *
 * config firewall vip
 *   edit "WEB-443"
 *     set extip 203.0.113.10
 *     set extintf "wan1"
 *     set mappedip "10.10.10.25"
 *     set portforward enable
 *     set extport 443
 *     set mappedport 443
 *   next
 * end
 */
export function parseVips(configText: string): VirtualIp[] {
  const lines = configText.split(/\r?\n/);

  const vips: VirtualIp[] = [];

  let inVipSection = false;
  let currentVip: Partial<VirtualIp> | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!inVipSection) {
      if (line === "config firewall vip") {
        inVipSection = true;
      }
      continue;
    }

    if (line === "end") {
      if (currentVip) {
        vips.push(finalizeVip(currentVip));
        currentVip = null;
      }
      break;
    }

    if (line.startsWith("edit ")) {
      if (currentVip) {
        vips.push(finalizeVip(currentVip));
      }

      const name = stripOuterQuotes(line.slice("edit ".length).trim());

      currentVip = {
        name,
        mappedip: [],
      };

      continue;
    }

    if (line === "next") {
      if (currentVip) {
        vips.push(finalizeVip(currentVip));
        currentVip = null;
      }
      continue;
    }

    if (!currentVip || !line.startsWith("set ")) {
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
      case "extip":
        currentVip.extip = stripOuterQuotes(value);
        break;

      case "extintf":
        currentVip.extintf = stripOuterQuotes(value);
        break;

      case "mappedip":
        currentVip.mappedip = parseQuotedList(value);
        break;

      case "portforward":
        currentVip.portforward = stripOuterQuotes(value).toLowerCase() === "enable";
        break;

      case "extport":
        currentVip.extport = stripOuterQuotes(value);
        break;

      case "mappedport":
        currentVip.mappedport = stripOuterQuotes(value);
        break;

      case "protocol":
        currentVip.protocol = stripOuterQuotes(value);
        break;

      case "comments":
        currentVip.comments = stripOuterQuotes(value);
        break;

      default:
        break;
    }
  }

  return vips;
}

function finalizeVip(vip: Partial<VirtualIp>): VirtualIp {
  return {
    name: vip.name ?? "unknown",
    extip: vip.extip,
    extintf: vip.extintf,
    mappedip: vip.mappedip ?? [],
    portforward: vip.portforward,
    extport: vip.extport,
    mappedport: vip.mappedport,
    protocol: vip.protocol,
    comments: vip.comments,
  };
}

function parseQuotedList(value: string): string[] {
  return [...value.matchAll(/"([^"]*)"|(\S+)/g)].map((match) => match[1] ?? match[2]);
}

function stripOuterQuotes(value: string): string {
  return value.replace(/^"(.*)"$/, "$1").trim();
}
