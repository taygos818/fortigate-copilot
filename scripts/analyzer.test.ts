import assert from "node:assert/strict";
import test from "node:test";
import { analyzeFortiGateConfig } from "../src/lib/analyzeFortiGateConfig";

test("active policy links a VIP, while disabled and deny policies do not create exposure", () => {
  const result = analyzeFortiGateConfig(`config firewall vip
edit "WEB"
set extip 203.0.113.10
set extintf "wan1"
set mappedip "192.0.2.10"
next
end
config firewall policy
edit 1
set srcintf "wan1"
set dstaddr "WEB"
set srcaddr "all"
set service "ALL"
set action accept
set status disable
next
edit 2
set srcintf "wan1"
set dstaddr "WEB"
set srcaddr "all"
set service "ALL"
set action deny
next
edit 3
set srcintf "wan1"
set dstaddr "WEB"
set srcaddr "all"
set service "ALL"
next
end`);

  assert.deepEqual(result.linkedPublishedServices[0].linkedPolicyIds, []);
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].title, /no linked accepting policy/);
  assert.equal(result.summary.riskScore, 0);
});

test("virtual-server real targets and multi-value policy fields survive parsing", () => {
  const result = analyzeFortiGateConfig(`config firewall virtual-server
edit "APP"
set interface "wan1"
set ip 203.0.113.20
set port 443
config realservers
edit 1
set ip 192.0.2.20
set port 8443
next
end
next
end
config firewall policy
edit 10
set srcintf "wan1"
set srcaddr "Partner A" "Partner B"
set dstaddr "APP"
set service "HTTPS"
set action accept
next
end`);

  assert.deepEqual(result.virtualServers[0].realServers, [{ ip: "192.0.2.20", port: "8443" }]);
  assert.deepEqual(result.policies[0].srcaddr, ["Partner A", "Partner B"]);
  assert.deepEqual(result.linkedPublishedServices[0].internalTargets, ["192.0.2.20"]);
  assert.equal(result.findings.some((finding) => finding.title.includes("any source")), false);
});
