import assert from "node:assert/strict";
import test from "node:test";
import { POST } from "../app/api/analyze/route";

function request(configText: unknown): Request {
  return new Request("http://localhost/api/analyze", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ configText }),
  });
}

test("rejects text without a supported section", async () => {
  const response = await POST(request("config system admin\nend"));
  assert.equal(response.status, 400);
});

test("accepts Windows line endings", async () => {
  const response = await POST(request("config firewall vip\r\nedit TEST\r\nnext\r\nend"));
  assert.equal(response.status, 200);
});

test("does not return an empty analysis as a zero-risk result", async () => {
  const response = await POST(request("config firewall vip\nend"));
  assert.equal(response.status, 422);
});

test("rejects oversized input before analysis", async () => {
  const response = await POST(request(`config firewall vip\n${"x".repeat(2 * 1024 * 1024)}`));
  assert.equal(response.status, 413);
});

test("returns rule-based recommendations for a synthetic policy", async () => {
  const response = await POST(request(`config firewall vip\nedit "TEST"\nset extip 203.0.113.1\nnext\nend\nconfig firewall policy\nedit 1\nset dstaddr "TEST"\nset srcaddr "all"\nset service "HTTPS"\nset action accept\nnext\nend`));
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(typeof result.recommendations.summary, "string");
  assert.equal("aiRecommendations" in result, false);
  assert.equal(result.findings.some((finding: { title: string }) => finding.title.includes("any source")), true);
});
