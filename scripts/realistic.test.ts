import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { analyzeFortiGateConfig } from "../src/lib/analyzeFortiGateConfig";
import { parseConfigTree, findEntries, splitValues } from "../src/parsers/configTree";
import { expandAddresses } from "../src/parsers/parseAddressGroups";

const realistic = fs.readFileSync(
  path.join(process.cwd(), "sample-configs", "realistic-sanitized.conf"),
  "utf-8"
);

function service(result: ReturnType<typeof analyzeFortiGateConfig>, name: string) {
  const found = result.linkedPublishedServices.find((item) => item.objectName === name);
  assert.ok(found, `expected published object ${name}`);
  return found;
}

function titles(result: ReturnType<typeof analyzeFortiGateConfig>, name: string): string[] {
  return result.findings.filter((finding) => finding.relatedObjectNames?.includes(name)).map((finding) => finding.title);
}

test("realistic sample: a nested realservers block does not cut the VIP section short", () => {
  const result = analyzeFortiGateConfig(realistic);

  assert.deepEqual(
    result.vips.map((vip) => vip.name),
    ["VIP-WEB-HTTPS", "VIP-WEB-HTTP", "VIP-SFTP", "VIP-APP-LB", "VIP-RDP-OLD", "VIP-MGMT-ANY"]
  );
  assert.deepEqual(service(result, "VIP-APP-LB").internalTargets, ["10.30.0.31:8443", "10.30.0.32:8443"]);
});

test("realistic sample: policies reach VIPs through a VIP group", () => {
  const result = analyzeFortiGateConfig(realistic);
  const web = service(result, "VIP-WEB-HTTPS");

  assert.deepEqual(web.linkedPolicyIds, [10]);
  assert.deepEqual(web.linkedVia[10], ["VIPGRP-WEB"]);
  assert.ok(titles(result, "VIP-WEB-HTTPS").some((title) => title.includes("exposed to any source")));
});

test("realistic sample: a source group that contains all counts as any source", () => {
  const result = analyzeFortiGateConfig(realistic);
  const finding = result.findings.find((item) => item.id === "vip-any-source-VIP-APP-LB-12");

  assert.ok(finding);
  assert.match(finding.summary, /ANY-SOURCE-GRP/);
});

test("realistic sample: interfaces with role wan and zones that contain them are WAN-facing", () => {
  const result = analyzeFortiGateConfig(realistic);

  // port2 has `set role wan`; the INTERNET zone contains port1 and port2.
  assert.ok(titles(result, "VIP-SFTP").some((title) => title.includes("WAN-facing")));
  assert.ok(titles(result, "VIP-APP-LB").some((title) => title.includes("WAN-facing")));
  // A partner-only source is not flagged as any source.
  assert.equal(titles(result, "VIP-SFTP").some((title) => title.includes("any source")), false);
});

test("realistic sample: a VIP whose only policy is disabled has no linked policy", () => {
  const result = analyzeFortiGateConfig(realistic);

  assert.deepEqual(service(result, "VIP-RDP-OLD").linkedPolicyIds, []);
  assert.deepEqual(titles(result, "VIP-RDP-OLD"), ["VIP VIP-RDP-OLD has no linked accepting policy"]);
});

test("multi-VDOM backups: policies and VIPs from every VDOM are read", () => {
  const result = analyzeFortiGateConfig(`config vdom
edit root
config firewall vip
edit "VIP-A"
set extip 203.0.113.30
set mappedip "10.0.0.30"
next
end
config firewall policy
edit 1
set srcintf "wan1"
set srcaddr "all"
set dstaddr "VIP-A"
set service "HTTPS"
set action accept
next
end
next
edit customer-b
config firewall vip
edit "VIP-B"
set extip 203.0.113.31
set mappedip "10.0.0.31"
next
end
next
end`);

  assert.deepEqual(result.vips.map((vip) => vip.name), ["VIP-A", "VIP-B"]);
  assert.deepEqual(service(result, "VIP-A").linkedPolicyIds, [1]);
});

test("SD-WAN zones count as WAN-facing", () => {
  const result = analyzeFortiGateConfig(`config system sdwan
set status enable
config zone
edit "virtual-wan-link"
next
edit "underlay"
next
end
config members
edit 1
set interface "port9"
next
end
end
config firewall vip
edit "VIP-SD"
set extip 203.0.113.40
set mappedip "10.0.0.40"
next
end
config firewall policy
edit 5
set srcintf "underlay"
set srcaddr "PARTNER"
set dstaddr "VIP-SD"
set service "HTTPS"
set action accept
next
end`);

  assert.ok(titles(result, "VIP-SD").some((title) => title.includes("WAN-facing")));
});

test("value splitting handles quotes, escapes and bare words", () => {
  assert.deepEqual(splitValues(`"Partner A" "Partner B"`), ["Partner A", "Partner B"]);
  assert.deepEqual(splitValues(`HTTP HTTPS`), ["HTTP", "HTTPS"]);
  assert.deepEqual(splitValues(`"Website \\"www\\" group"`), [`Website "www" group`]);
});

test("a missing next before end still closes the entry", () => {
  const tree = parseConfigTree(`config firewall vip\nedit "A"\nset extip 203.0.113.1\nend\nconfig firewall policy\nedit 1\nset action accept\nnext\nend`);

  assert.deepEqual(findEntries(tree, "firewall vip").map((entry) => entry.name), ["A"]);
  assert.equal(findEntries(tree, "firewall policy").length, 1);
});

test("group cycles do not loop forever", () => {
  const groups = new Map([
    ["G1", ["G2", "HOST"]],
    ["G2", ["G1"]],
  ]);

  const names = expandAddresses(["G1"], groups).map((item) => item.name);
  assert.ok(names.includes("HOST"));
  assert.ok(names.length < 10);
});
