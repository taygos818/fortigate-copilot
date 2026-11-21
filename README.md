# FortiGate Policy Analyzer

A local review aid for FortiGate configurations. Paste or upload a sanitized configuration and it shows which VIPs and virtual servers are published, which enabled accepting policies reach them, and which of those deserve a closer look: sources of `all`, a service of `ALL`, and internet-facing interfaces. Recommendations come from fixed rules. No AI service or API key is involved.

It is a starting point for a manual review, not a verdict. A missing finding does not mean a configuration is safe.

## Run locally

Requires Node.js 20 or later.

```sh
npm ci
npm run dev
```

Open `http://localhost:3000`. To try it, upload [`sample-configs/realistic-sanitized.conf`](sample-configs/realistic-sanitized.conf), a synthetic backup-style configuration with interfaces, zones, address and VIP groups, a load-balancing VIP and a disabled policy.

To validate changes:

```sh
npm test
npm run lint
npm run build
```

## What it reads

- Every `config firewall policy`, `config firewall vip` and `config firewall virtual-server` section, including one per VDOM in a multi-VDOM backup.
- Nested blocks such as a `server-load-balance` VIP's `config realservers`.
- `config firewall addrgrp`, `addrgrp6`, `vipgrp` and `vipgrp6`, so a policy that reaches a VIP through a group is linked, and a source group that contains `all` counts as any source.
- `config system interface` (`set role wan`), `config system zone` and `config system sdwan`, to decide which interfaces face the internet. Without them it falls back to common names such as `wan1`.

## What it flags

| Finding | Severity |
| --- | --- |
| A published object reachable from source `all` | High |
| A published object reachable with service `ALL` | Medium |
| A published object on an internet-facing interface | Info |
| A published object with no enabled accepting policy | Info |

Disabled and denying policies don't count as exposure. A policy with no `set action` uses the FortiOS default, `deny`.

The score adds fixed points per finding and caps at 100. It is for sorting findings, not a measure of security.

## What it doesn't do

It does not evaluate policy order, schedules, routing, central NAT, internet-service objects, address negation, IPv6 VIP mappings, or every FortiOS syntax variant. Check the original configuration before changing a firewall.

## Your data

The browser sends the configuration to this app's own `/api/analyze` route, which analyzes it in memory and returns the result. The app does not store it. If you deploy the app somewhere, that host and its logs are outside this repository's control, so keep it local unless you have reviewed that.

Use sanitized or synthetic configurations. Don't commit real firewall configurations, credentials, customer details, or analysis of them to this repository.

## Project layout

```
app/                      Next.js UI and the /api/analyze route
src/parsers/configTree.ts Reads FortiOS CLI text into a tree of sections and entries
src/parsers/              Policies, VIPs, virtual servers, groups, WAN interfaces
src/lib/                  Linking, scoring and recommendations
src/checks/               Findings
scripts/*.test.ts         Tests (node:test)
sample-configs/           Synthetic configurations only
docs/                     Design notes and dev session logs
```

## License

MIT. See [LICENSE](LICENSE).
