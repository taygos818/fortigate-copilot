import { VirtualIp, VirtualServerRealServer } from "../types/firewall";
import {
  ConfigEntry,
  ConfigTree,
  allValues,
  findEntries,
  firstValue,
  nestedEntries,
  parseConfigTree,
} from "./configTree";

/**
 * Parse every `config firewall vip` section into VirtualIp[].
 *
 * Supports static NAT and port-forward VIPs, plus `server-load-balance` VIPs
 * whose real servers sit in a nested `config realservers` block.
 *
 * config firewall vip
 *     edit "WEB-443"
 *         set extip 203.0.113.10
 *         set extintf "wan1"
 *         set mappedip "10.10.10.25"
 *         set portforward enable
 *         set extport 443
 *         set mappedport 443
 *     next
 * end
 */
export function parseVips(config: string | ConfigTree): VirtualIp[] {
  const tree = typeof config === "string" ? parseConfigTree(config) : config;

  return findEntries(tree, "firewall vip").map((entry) => {
    const realServers = realServersOf(entry);

    return {
      name: entry.name || "unknown",
      type: firstValue(entry, "type"),
      extip: firstValue(entry, "extip"),
      extintf: firstValue(entry, "extintf"),
      mappedip: allValues(entry, "mappedip"),
      portforward: firstValue(entry, "portforward")?.toLowerCase() === "enable",
      extport: firstValue(entry, "extport"),
      mappedport: firstValue(entry, "mappedport"),
      protocol: firstValue(entry, "protocol"),
      realServers,
      comments: firstValue(entry, "comment") ?? firstValue(entry, "comments"),
    };
  });
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
