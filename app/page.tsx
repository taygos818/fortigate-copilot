"use client";

import { useState } from "react";

type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

interface FirewallPolicy {
  id: number;
  name?: string;
  srcintf: string[];
  dstintf: string[];
  srcaddr: string[];
  dstaddr: string[];
  service: string[];
  action: string;
}

interface LinkedPublishedService {
  objectType: "vip" | "virtual-server";
  objectName: string;
  externalInterface?: string;
  externalIp?: string;
  externalPort?: string;
  internalTargets: string[];
  linkedPolicyIds: number[];
  linkedPolicies: FirewallPolicy[];
}

interface Finding {
  id: string;
  severity: FindingSeverity;
  title: string;
  summary: string;
  details?: string;
  recommendation?: string;
  policyIds?: number[];
  relatedObjectNames?: string[];
}

interface AnalysisResult {
  summary: {
    vendor: string;
    policyCount: number;
    vipCount: number;
    virtualServerCount: number;
    linkedPublishedServiceCount: number;
    riskScore: number;
  };
  linkedPublishedServices: LinkedPublishedService[];
  findings: Finding[];
}

export default function HomePage() {
  const [configText, setConfigText] = useState(`config firewall vip
    edit "WEB-443"
        set extip 203.0.113.10
        set extintf "wan1"
        set mappedip "10.10.10.25"
        set portforward enable
        set extport 443
        set mappedport 443
    next
    edit "RDP-8443"
        set extip 203.0.113.11
        set extintf "wan1"
        set mappedip "10.10.10.50"
        set portforward enable
        set extport 8443
        set mappedport 3389
    next
end

config firewall policy
    edit 101
        set name "Allow-HTTPS-To-WEB"
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "WEB-443"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set logtraffic all
    next
    edit 102
        set name "Allow-RDP-Publish"
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "Branch-Offices"
        set dstaddr "RDP-8443"
        set action accept
        set schedule "always"
        set service "TCP-8443"
        set logtraffic all
    next
end`);

  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  async function handleAnalyze() {
    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ configText }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data?.error ?? "Analysis failed");
      }

      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <main style={{ padding: 24, maxWidth: 1200, margin: "0 auto" }}>
      <h1 style={{ marginBottom: 8 }}>FortiGate AI Copilot</h1>
      <p style={{ marginTop: 0, marginBottom: 24 }}>
        Paste a FortiGate config and analyze published services, linked policies,
        and risk findings.
      </p>

      <div style={{ display: "grid", gap: 16 }}>
        <textarea
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
          rows={20}
          style={{
            width: "100%",
            fontFamily: "monospace",
            fontSize: 14,
            padding: 12,
            borderRadius: 8,
          }}
        />

        <div>
          <button onClick={handleAnalyze} disabled={isLoading}>
            {isLoading ? "Analyzing..." : "Analyze"}
          </button>
        </div>

        {error && <div style={{ color: "red" }}>{error}</div>}

        {result && (
          <div style={{ display: "grid", gap: 24 }}>
            <section>
              <h2>Summary</h2>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: 12,
                }}
              >
                <SummaryCard label="Vendor" value={result.summary.vendor} />
                <SummaryCard
                  label="Risk Score"
                  value={String(result.summary.riskScore)}
                />
                <SummaryCard
                  label="Policies"
                  value={String(result.summary.policyCount)}
                />
                <SummaryCard
                  label="VIPs"
                  value={String(result.summary.vipCount)}
                />
                <SummaryCard
                  label="Virtual Servers"
                  value={String(result.summary.virtualServerCount)}
                />
                <SummaryCard
                  label="Published Services"
                  value={String(result.summary.linkedPublishedServiceCount)}
                />
              </div>
            </section>

            <section>
              <h2>Published Services</h2>
              <div style={{ display: "grid", gap: 12 }}>
                {result.linkedPublishedServices.map((service) => (
                  <div
                    key={`${service.objectType}-${service.objectName}`}
                    style={{
                      border: "1px solid #ccc",
                      borderRadius: 8,
                      padding: 12,
                    }}
                  >
                    <div>
                      <strong>{service.objectName}</strong> ({service.objectType})
                    </div>
                    <div>External Interface: {service.externalInterface ?? "unknown"}</div>
                    <div>External IP: {service.externalIp ?? "unknown"}</div>
                    <div>External Port: {service.externalPort ?? "unknown"}</div>
                    <div>
                      Internal Targets:{" "}
                      {service.internalTargets.length > 0
                        ? service.internalTargets.join(", ")
                        : "none"}
                    </div>
                    <div>
                      Linked Policies:{" "}
                      {service.linkedPolicyIds.length > 0
                        ? service.linkedPolicyIds.join(", ")
                        : "none"}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section>
              <h2>Findings</h2>
              <div style={{ display: "grid", gap: 12 }}>
                {result.findings.map((finding) => (
                  <div
                    key={finding.id}
                    style={{
                      border: "1px solid #ccc",
                      borderRadius: 8,
                      padding: 12,
                    }}
                  >
                    <div>
                      <strong>{finding.title}</strong>
                    </div>
                    <div>Severity: {finding.severity}</div>
                    <div>{finding.summary}</div>
                    {finding.details && (
                      <div style={{ marginTop: 8, fontSize: 14 }}>
                        Details: {finding.details}
                      </div>
                    )}
                    {finding.recommendation && (
                      <div style={{ marginTop: 8, fontSize: 14 }}>
                        Recommendation: {finding.recommendation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>
          </div>
        )}
      </div>
    </main>
  );
}

function SummaryCard({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        border: "1px solid #ccc",
        borderRadius: 8,
        padding: 12,
      }}
    >
      <div style={{ fontSize: 13, opacity: 0.7 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700 }}>{value}</div>
    </div>
  );
}