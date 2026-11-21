import { ConfigTree, allValues, findEntries, parseConfigTree } from "./configTree";

/**
 * Group name -> member names, from address groups (`firewall addrgrp`,
 * `firewall addrgrp6`) and VIP groups (`firewall vipgrp`, `firewall vipgrp6`).
 */
export type GroupMembers = Map<string, string[]>;

const GROUP_SECTIONS = [
  "firewall addrgrp",
  "firewall addrgrp6",
  "firewall vipgrp",
  "firewall vipgrp6",
];

export function parseAddressGroups(config: string | ConfigTree): GroupMembers {
  const tree = typeof config === "string" ? parseConfigTree(config) : config;
  const groups: GroupMembers = new Map();

  for (const section of GROUP_SECTIONS) {
    for (const entry of findEntries(tree, section)) {
      const existing = groups.get(entry.name) ?? [];
      groups.set(entry.name, [...existing, ...allValues(entry, "member")]);
    }
  }

  return groups;
}

/**
 * Expand a list of address names through groups, recursively.
 *
 * Returns each resolved name with the chain of groups that led to it, so a
 * finding can say "via group WEB-GROUP". Names that are not groups resolve to
 * themselves with an empty chain. Group cycles are ignored.
 */
export function expandAddresses(
  names: string[],
  groups: GroupMembers
): { name: string; via: string[] }[] {
  const result: { name: string; via: string[] }[] = [];

  const visit = (name: string, via: string[]) => {
    result.push({ name, via });

    const members = groups.get(name);

    if (!members || via.includes(name)) {
      return;
    }

    for (const member of members) {
      visit(member, [...via, name]);
    }
  };

  for (const name of names) {
    visit(name, []);
  }

  return result;
}
