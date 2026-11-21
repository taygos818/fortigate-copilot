import { FirewallPolicy } from "../types/firewall";
import { ConfigTree, allValues, findEntries, firstValue, parseConfigTree } from "./configTree";

/**
 * Parse every `config firewall policy` section (one per VDOM in a multi-VDOM
 * backup) into FirewallPolicy[].
 *
 * A policy with no `set action` uses the FortiOS default, `deny`.
 */
export function parsePolicies(config: string | ConfigTree): FirewallPolicy[] {
  const tree = typeof config === "string" ? parseConfigTree(config) : config;

  return findEntries(tree, "firewall policy").map((entry) => {
    const id = Number.parseInt(entry.name, 10);

    return {
      id: Number.isNaN(id) ? -1 : id,
      name: firstValue(entry, "name"),
      srcintf: allValues(entry, "srcintf"),
      dstintf: allValues(entry, "dstintf"),
      srcaddr: allValues(entry, "srcaddr"),
      dstaddr: allValues(entry, "dstaddr"),
      service: allValues(entry, "service"),
      action: firstValue(entry, "action") ?? "deny",
      schedule: firstValue(entry, "schedule"),
      status: firstValue(entry, "status"),
      logtraffic: firstValue(entry, "logtraffic"),
      comments: firstValue(entry, "comments"),
    };
  });
}
