"use client";

import { useMemo, useState } from "react";

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

const starterConfig = `config firewall vip
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
    edit "UNUSED-VIP"
        set extip 203.0.113.12
        set extintf "wan1"
        set mappedip "10.10.10.99"
        set portforward enable
        set extport 9443
        set mappedport 9443
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
    edit 103
        set name "Internal-Outbound"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "Users"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTP" "HTTPS"
    next
end`;

export default function HomePage() {
  const [configText, setConfigText] = useState(starterConfig);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const topRisks = useMemo(() => {
    return (
      result?.findings.filter(
        (finding) =>
          finding.severity === "critical" || finding.severity === "high"
      ) ?? []
    );
  }, [result]);

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
    <main
      style={{
        minHeight: "100vh",
        background: "#0b1020",
        color: "#e5e7eb",
        padding: 24,
      }}
    >
      <div style={{ maxWidth: 1200, margin: "0 auto", display: "grid", gap: 24 }}>
        <header>
          <h1 style={{ margin: 0, fontSize: 36 }}>FortiGate AI Copilot</h1>
          <p style={{ marginTop: 8, color: "#94a3b8", maxWidth: 820 }}>
            Paste a FortiGate config and analyze published services, linked
            policies, and exposure findings.
          </p>
        </header>

        <section
          style={{
            border: "1px solid #334155",
            borderRadius: 12,
            background: "#111827",
            padding: 16,
          }}
        >
          <h2 style={{ marginTop: 0 }}>Config Input</h2>
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
              border: "1px solid #475569",
              background: "#020617",
              color: "#e2e8f0",
              resize: "vertical",
              boxSizing: "border-box",
            }}
          />

          <div style={{ marginTop: 12, display: "flex", gap: 12 }}>
            <button
              onClick={handleAnalyze}
              disabled={isLoading}
              style={{
                border: "none",
                borderRadius: 8,
                padding: "10px 16px",
                background: "#2563eb",
                color: "white",
                cursor: isLoading ? "not-allowed" : "pointer",
                fontWeight: 700,
              }}
            >
              {isLoading ? "Analyzing..." : "Analyze"}
            </button>
          </div>

          {error && (
            <div
              style={{
                marginTop: 12,
                border: "1px solid #ef4444",
                borderRadius: 8,
                padding: 12,
                color: "#fecaca",
                background: "#450a0a",
              }}
            >
              {error}
            </div>
          )}
        </section>

        {result && (
          <div style={{ display: "grid", gap: 24 }}>
            <section>
              <h2>Top Risks</h2>
              {topRisks.length === 0 ? (
                <div
                  style={{
                    border: "1px solid #334155",
                    borderRadius: 12,
                    padding: 16,
                    background: "#111827",
                    color: "#cbd5e1",
                  }}
                >
                  No critical or high-severity findings.
                </div>
              ) : (
                <div style={{ display: "grid", gap: 12 }}>
                  {topRisks.map((finding) => (
                    <div
                      key={`top-${finding.id}`}
                      style={{
                        border: `2px solid ${getSeverityColor(
                          finding.severity
                        )}`,
                        borderRadius: 12,
                        padding: 16,
                        background: "#111827",
                      }}
                    >
                      <div
                        style={{
                          color: getSeverityColor(finding.severity),
                          fontWeight: 800,
                          letterSpacing: 0.5,
                        }}
                      >
                        {finding.severity.toUpperCase()}
                      </div>
                      <div style={{ fontWeight: 700, fontSize: 18, marginTop: 6 }}>
                        {finding.title}
                      </div>
                      <div style={{ marginTop: 8, color: "#cbd5e1" }}>
                        {finding.summary}
                      </div>
                      {finding.recommendation && (
                        <div style={{ marginTop: 10, color: "#e2e8f0" }}>
                          <strong>Recommendation:</strong> {finding.recommendation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>

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
                <RiskScoreCard score={result.summary.riskScore} />
                <SummaryCard
                  label="Policies"
                  value={String(result.summary.policyCount)}
                />
                <SummaryCard label="VIPs" value={String(result.summary.vipCount)} />
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
                      border: "1px solid #334155",
                      borderRadius: 12,
                      padding: 16,
                      background: "#111827",
                    }}
                  >
                    <div style={{ fontWeight: 700, fontSize: 18 }}>
                      {service.objectName}
                    </div>
                    <div style={{ color: "#94a3b8", marginTop: 4 }}>
                      {service.objectType}
                    </div>

                    <div style={{ marginTop: 12, display: "grid", gap: 6 }}>
                      <div>
                        <strong>External Interface:</strong>{" "}
                        {service.externalInterface ?? "unknown"}
                      </div>
                      <div>
                        <strong>External IP:</strong>{" "}
                        {service.externalIp ?? "unknown"}
                      </div>
                      <div>
                        <strong>External Port:</strong>{" "}
                        {service.externalPort ?? "unknown"}
                      </div>
                      <div>
                        <strong>Internal Targets:</strong>{" "}
                        {service.internalTargets.length > 0
                          ? service.internalTargets.join(", ")
                          : "none"}
                      </div>
                      <div>
                        <strong>Linked Policies:</strong>{" "}
                        {service.linkedPolicyIds.length > 0
                          ? service.linkedPolicyIds.join(", ")
                          : "none"}
                      </div>
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
                      border: `2px solid ${getSeverityColor(finding.severity)}`,
                      borderRadius: 12,
                      padding: 16,
                      background: "#111827",
                    }}
                  >
                    <div
                      style={{
                        color: getSeverityColor(finding.severity),
                        fontWeight: 800,
                        letterSpacing: 0.5,
                      }}
                    >
                      {finding.severity.toUpperCase()}
                    </div>

                    <div style={{ fontWeight: 700, fontSize: 18, marginTop: 6 }}>
                      {finding.title}
                    </div>

                    <div style={{ marginTop: 8, color: "#cbd5e1" }}>
                      {finding.summary}
                    </div>

                    {finding.details && (
                      <div style={{ marginTop: 10, color: "#94a3b8", fontSize: 14 }}>
                        <strong>Details:</strong> {finding.details}
                      </div>
                    )}

                    {finding.recommendation && (
                      <div style={{ marginTop: 10, color: "#e2e8f0" }}>
                        <strong>Recommendation:</strong> {finding.recommendation}
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
        border: "1px solid #334155",
        borderRadius: 12,
        padding: 16,
        background: "#111827",
      }}
    >
      <div style={{ fontSize: 13, color: "#94a3b8" }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 800, marginTop: 8 }}>{value}</div>
    </div>
  );
}

function RiskScoreCard({ score }: { score: number }) {
  const color = getRiskScoreColor(score);

  return (
    <div
      style={{
        border: `2px solid ${color}`,
        borderRadius: 12,
        padding: 16,
        background: "#111827",
      }}
    >
      <div style={{ fontSize: 13, color: "#94a3b8" }}>Risk Score</div>
      <div
        style={{
          fontSize: 34,
          fontWeight: 900,
          marginTop: 8,
          color,
        }}
      >
        {score}
      </div>
    </div>
  );
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case "critical":
      return "#ef4444";
    case "high":
      return "#f97316";
    case "medium":
      return "#eab308";
    case "low":
      return "#22c55e";
    case "info":
      return "#38bdf8";
    default:
      return "#94a3b8";
  }
}

function getRiskScoreColor(score: number) {
  if (score >= 70) return "#ef4444";
  if (score >= 40) return "#f97316";
  if (score >= 20) return "#eab308";
  return "#22c55e";
}