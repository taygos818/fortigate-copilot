import { Finding, FindingSeverity } from "../types/firewall";

export interface RiskScoreResult {
  score: number;
  counts: Record<FindingSeverity, number>;
}

const SEVERITY_POINTS: Record<FindingSeverity, number> = {
  critical: 30,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

export function calculateRiskScore(findings: Finding[]): RiskScoreResult {
  const counts: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  let total = 0;

  for (const finding of findings) {
    counts[finding.severity] += 1;
    total += SEVERITY_POINTS[finding.severity];
  }

  return {
    score: Math.min(100, total),
    counts,
  };
}