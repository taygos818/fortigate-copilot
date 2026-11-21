import { VirtualServer, VirtualServerRealServer } from "../types/firewall";
import { ConfigEntry, ConfigTree, findEntries, firstValue, nestedEntries, parseConfigTree } from "./configTree";

/**
 * Parse `config firewall virtual-server` sections into VirtualServer[].
 *
 * Current FortiOS releases configure load balancing as a `firewall vip` with
 * `set type server-load-balance`, which parseVips handles. This parser covers
 * configurations that use a separate virtual-server section.
 */
export function parseVirtualServers(config: string | ConfigTree): VirtualServer[] {
  const tree = typeof config === "string" ? parseConfigTree(config) : config;

  return findEntries(tree, "firewall virtual-server").map((entry) => ({
    name: entry.name || "unknown",
    interface: firstValue(entry, "interface"),
    ip: firstValue(entry, "ip"),
    port: firstValue(entry, "port"),
    type: firstValue(entry, "type"),
    loadBalanceMethod: firstValue(entry, "ldb-method"),
    serverType: firstValue(entry, "server-type"),
    realServers: realServersOf(entry),
    comments: firstValue(entry, "comment") ?? firstValue(entry, "comments"),
  }));
}

function realServersOf(entry: ConfigEntry): VirtualServerRealServer[] {
  return nestedEntries(entry, "realservers").flatMap((server) => {
    const ip = firstValue(server, "ip");
    if (!ip) return [];
    const port = firstValue(server, "port");
    const status = firstValue(server, "status");
    return [{ ip, ...(port ? { port } : {}), ...(status ? { status } : {}) }];
  });
}
