# FortiGate Policy Analyzer

A local review aid for selected FortiGate configuration sections. Paste or upload a sanitized configuration, then inspect published VIPs and virtual servers, directly linked accepting policies, exposure findings, a simple score, and rule-based recommendations. No AI service or API key is involved.

## Run locally

Requires Node.js 20 or later.

```sh
npm ci
npm run dev
```

Open `http://localhost:3000`. Use the included documentation-address sample to explore the output. To validate changes, run `npm test`, `npm run lint`, and `npm run build`.

The browser sends the entered configuration to this app's `/api/analyze` server route. The app does not deliberately store it, but a hosted deployment, its infrastructure, and logs are outside this repository's control. Use sanitized or synthetic configurations. Keep the app local unless you have reviewed that data flow and added any access controls a deployment requires.

## What the analysis covers

- Top-level `config firewall policy`, `config firewall vip`, and `config firewall virtual-server` sections, including basic real-server targets.
- Direct policy `dstaddr` references to a VIP or virtual-server name. Disabled and denying policies are excluded from exposure links.
- Findings for an accepting policy with source `all`, service `ALL`, or a recognized WAN-style interface name, plus published objects without a directly linked accepting policy.
- A score based on fixed severity points, capped at 100. The score is for sorting findings, not a calibrated measure of security.

The analyzer does **not** resolve address groups, nested objects, schedules, routing, central NAT, policy order, or every FortiOS syntax variant. A missing finding is not evidence that exposure is safe. The WAN check recognizes a small list of interface names; a custom interface name may be missed. Review the original configuration before changing a firewall.

Only synthetic examples belong in this repository. Do not commit real firewall configurations, credentials, customer details, or generated analysis of them. Repository visibility is a separate decision from completing the local tool.
