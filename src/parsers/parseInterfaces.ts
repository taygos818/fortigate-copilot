import { ConfigTree, allValues, findEntries, findSections, firstValue, nestedEntries, parseConfigTree } from "./configTree";

/**
 * Interface names commonly used for internet-facing links. They are a
 * fallback for configurations that do not include `config system interface`.
 */
export const DEFAULT_WAN_NAMES = ["wan", "wan1", "wan2", "internet", "external", "outside"];

/**
 * Names a policy or VIP can use to mean an internet-facing interface:
 * the default names above, interfaces with `set role wan`, zones that contain
 * one of those interfaces, and SD-WAN (`virtual-wan-link` and SD-WAN zones).
 */
export function parseWanInterfaces(config: string | ConfigTree): Set<string> {
  const tree = typeof config === "string" ? parseConfigTree(config) : config;
  const wan = new Set(DEFAULT_WAN_NAMES);

  for (const entry of findEntries(tree, "system interface")) {
    if (firstValue(entry, "role")?.toLowerCase() === "wan") {
      wan.add(entry.name.toLowerCase());
    }
  }

  for (const section of [...findSections(tree, "system sdwan"), ...findSections(tree, "system virtual-wan-link")]) {
    const status = section.settings.status?.[0]?.toLowerCase();

    if (status === "disable") {
      continue;
    }

    wan.add("virtual-wan-link");

    for (const sectionEntry of section.entries) {
      for (const zone of nestedEntries(sectionEntry, "zone")) {
        wan.add(zone.name.toLowerCase());
      }
    }

    // Members of an SD-WAN bundle are internet-facing even without a role.
    for (const sectionEntry of section.entries) {
      for (const member of nestedEntries(sectionEntry, "members")) {
        const name = firstValue(member, "interface");
        if (name) wan.add(name.toLowerCase());
      }
    }
  }

  for (const entry of findEntries(tree, "system zone")) {
    if (allValues(entry, "interface").some((name) => wan.has(name.toLowerCase()))) {
      wan.add(entry.name.toLowerCase());
    }
  }

  return wan;
}
