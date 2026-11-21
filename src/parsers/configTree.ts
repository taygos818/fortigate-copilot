/**
 * A small, forgiving reader for FortiOS CLI configuration text.
 *
 * FortiOS configuration is a tree of `config <path>` sections. A section holds
 * `edit <name>` entries (or, for singleton sections, `set` lines directly), and
 * an entry can hold `set` lines and further nested `config` sections. Sections
 * close with `end` and entries with `next`.
 *
 * Reading the whole tree, rather than scanning for one section and stopping at
 * the first `end`, keeps nested blocks such as a load-balancing VIP's
 * `config realservers` from cutting a section short, and finds every copy of a
 * section in a multi-VDOM backup.
 */

export interface ConfigEntry {
  name: string;
  settings: Record<string, string[]>;
  sections: ConfigSection[];
}

export interface ConfigSection {
  path: string;
  settings: Record<string, string[]>;
  entries: ConfigEntry[];
}

export interface ConfigTree {
  sections: ConfigSection[];
}

type Frame =
  | { kind: "root"; sections: ConfigSection[] }
  | { kind: "section"; section: ConfigSection }
  | { kind: "entry"; entry: ConfigEntry };

export function parseConfigTree(configText: string): ConfigTree {
  const root: ConfigTree = { sections: [] };
  const stack: Frame[] = [{ kind: "root", sections: root.sections }];

  for (const rawLine of configText.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }

    const top = stack[stack.length - 1];

    if (line.startsWith("config ")) {
      const section: ConfigSection = {
        path: normalizeSpaces(line.slice("config ".length)),
        settings: {},
        entries: [],
      };

      if (top.kind === "root") {
        top.sections.push(section);
      } else if (top.kind === "entry") {
        top.entry.sections.push(section);
      } else {
        // A nested `config` directly inside a singleton section. Keep it by
        // attaching it to an unnamed entry so it is still reachable.
        top.section.entries.push({ name: "", settings: {}, sections: [section] });
      }

      stack.push({ kind: "section", section });
      continue;
    }

    if (line.startsWith("edit ") || line === "edit") {
      // A missing `next` before a new `edit` closes the previous entry.
      if (top.kind === "entry") {
        stack.pop();
      }

      const current = stack[stack.length - 1];

      if (current.kind !== "section") {
        continue;
      }

      const entry: ConfigEntry = {
        name: splitValues(line.slice("edit".length))[0] ?? "",
        settings: {},
        sections: [],
      };

      current.section.entries.push(entry);
      stack.push({ kind: "entry", entry });
      continue;
    }

    if (line === "next") {
      if (top.kind === "entry") {
        stack.pop();
      }
      continue;
    }

    if (line === "end") {
      // A missing `next` before `end` closes the open entry as well.
      if (top.kind === "entry") {
        stack.pop();
      }

      if (stack[stack.length - 1].kind === "section") {
        stack.pop();
      }
      continue;
    }

    if (line.startsWith("set ")) {
      const rest = line.slice("set ".length).trim();
      const spaceIndex = rest.search(/\s/);
      const key = spaceIndex === -1 ? rest : rest.slice(0, spaceIndex);
      const values = spaceIndex === -1 ? [] : splitValues(rest.slice(spaceIndex + 1));

      if (top.kind === "entry") {
        top.entry.settings[key] = values;
      } else if (top.kind === "section") {
        top.section.settings[key] = values;
      }
      continue;
    }

    if (line.startsWith("unset ")) {
      const key = line.slice("unset ".length).trim();

      if (top.kind === "entry") {
        delete top.entry.settings[key];
      } else if (top.kind === "section") {
        delete top.section.settings[key];
      }
    }
  }

  return root;
}

/**
 * Every entry of every section with this path, at any depth. In a multi-VDOM
 * backup, `config firewall policy` appears once inside each `config vdom` /
 * `edit <vdom>` entry, and all of them are returned in file order.
 */
export function findEntries(tree: ConfigTree, path: string): ConfigEntry[] {
  return findSections(tree, path).flatMap((section) => section.entries);
}

export function findSections(tree: ConfigTree, path: string): ConfigSection[] {
  const wanted = normalizeSpaces(path);
  const found: ConfigSection[] = [];

  const visitSections = (sections: ConfigSection[]) => {
    for (const section of sections) {
      if (section.path === wanted) {
        found.push(section);
        // Sections of the same path are not nested inside each other, and
        // looking inside would pick up unrelated sub-blocks with the same name.
        continue;
      }

      for (const entry of section.entries) {
        visitSections(entry.sections);
      }
    }
  };

  visitSections(tree.sections);
  return found;
}

/** First value of a setting, or undefined. */
export function firstValue(entry: { settings: Record<string, string[]> }, key: string): string | undefined {
  return entry.settings[key]?.[0];
}

/** All values of a setting, or an empty list. */
export function allValues(entry: { settings: Record<string, string[]> }, key: string): string[] {
  return entry.settings[key] ?? [];
}

/** The settings of an entry's nested section, as a list of entries. */
export function nestedEntries(entry: ConfigEntry, path: string): ConfigEntry[] {
  const wanted = normalizeSpaces(path);
  return entry.sections.filter((section) => section.path === wanted).flatMap((section) => section.entries);
}

/**
 * Split a FortiOS value list. Values are either double-quoted (with `\"` and
 * `\\` escapes) or bare words: `"Partner A" "Partner B"`, `HTTP HTTPS`,
 * `203.0.113.2 255.255.255.248`.
 */
export function splitValues(text: string): string[] {
  const values: string[] = [];
  const pattern = /"((?:[^"\\]|\\.)*)"|(\S+)/g;

  for (const match of text.matchAll(pattern)) {
    if (match[1] !== undefined) {
      values.push(match[1].replace(/\\(.)/g, "$1"));
    } else {
      values.push(match[2]);
    }
  }

  return values;
}

function normalizeSpaces(text: string): string {
  return text.trim().replace(/\s+/g, " ");
}
