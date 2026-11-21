import { Finding } from "../types/firewall";

export interface RecommendationsResult {
  summary: string;
  recommendations: string[];
}

export function generateRecommendations(
  findings: Finding[]
): RecommendationsResult {
  if (findings.length === 0) {
    return {
      summary:
        "No findings were detected. Review the configuration manually to confirm intended exposure.",
      recommendations: [
        "Validate that all published services are intentional.",
        "Confirm source and service restrictions align with policy.",
      ],
    };
  }

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;

  const anySource = findings.some((f) => f.id.includes("-any-source-"));
  const broadService = findings.some((f) => f.id.includes("-broad-service-"));
  const unused = findings.some((f) => f.id.startsWith("unlinked-"));
  const wan = findings.some((f) => f.id.includes("-wan-published-"));

  const recommendations: string[] = [];

  if (anySource) {
    recommendations.push(
      "Restrict published services that are exposed to ANY source. Limit access to trusted networks or specific external IP ranges."
    );
  }

  if (broadService) {
    recommendations.push(
      "Reduce broad service exposure. Replace ALL services with only the required ports and protocols."
    );
  }

  if (unused) {
    recommendations.push(
      "Review published objects with no linked accepting policy and remove the ones that are no longer needed."
    );
  }

  if (wan) {
    recommendations.push(
      "Review all internet-facing services to ensure exposure is intentional and properly restricted."
    );
  }

  recommendations.push(
    "Review order: check ANY-source exposure, then broad services, then objects without linked policies."
  );

  return {
    summary: `This configuration has ${findings.length} finding(s), including ${criticalCount} critical, ${highCount} high, and ${mediumCount} medium severity issues.`,
    recommendations,
  };
}
