import { VirtualServer } from "../types/firewall";

export function parseVirtualServers(configText: string): VirtualServer[] {
  const lines = configText.split(/\r?\n/);

  const virtualServers: VirtualServer[] = [];

  let inVirtualServerSection = false;
  let currentVirtualServer: Partial<VirtualServer> | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!inVirtualServerSection) {
      if (line === "config firewall virtual-server") {
        inVirtualServerSection = true;
      }
      continue;
    }

    if (line === "end") {
      if (currentVirtualServer) {
        virtualServers.push(finalizeVirtualServer(currentVirtualServer));
        currentVirtualServer = null;
      }
      break;
    }

    if (line.startsWith("edit ")) {
      if (currentVirtualServer) {
        virtualServers.push(finalizeVirtualServer(currentVirtualServer));
      }

      const name = stripOuterQuotes(line.slice("edit ".length).trim());

      currentVirtualServer = {
        name,
        realServers: [],
      };

      continue;
    }

    if (line === "next") {
      if (currentVirtualServer) {
        virtualServers.push(finalizeVirtualServer(currentVirtualServer));
        currentVirtualServer = null;
      }
      continue;
    }

    if (!currentVirtualServer || !line.startsWith("set ")) {
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
      case "interface":
        currentVirtualServer.interface = stripOuterQuotes(value);
        break;

      case "ip":
        currentVirtualServer.ip = stripOuterQuotes(value);
        break;

      case "port":
        currentVirtualServer.port = stripOuterQuotes(value);
        break;

      case "type":
        currentVirtualServer.type = stripOuterQuotes(value);
        break;

      case "ldb-method":
        currentVirtualServer.loadBalanceMethod = stripOuterQuotes(value);
        break;

      case "server-type":
        currentVirtualServer.serverType = stripOuterQuotes(value);
        break;

      case "comments":
        currentVirtualServer.comments = stripOuterQuotes(value);
        break;

      default:
        break;
    }
  }

  return virtualServers;
}

function finalizeVirtualServer(
  virtualServer: Partial<VirtualServer>
): VirtualServer {
  return {
    name: virtualServer.name ?? "unknown",
    interface: virtualServer.interface,
    ip: virtualServer.ip,
    port: virtualServer.port,
    type: virtualServer.type,
    loadBalanceMethod: virtualServer.loadBalanceMethod,
    serverType: virtualServer.serverType,
    realServers: virtualServer.realServers ?? [],
    comments: virtualServer.comments,
  };
}

function stripOuterQuotes(value: string): string {
  return value.replace(/^"(.*)"$/, "$1").trim();
}