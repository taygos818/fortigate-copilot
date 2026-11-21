import { analyzeFortiGateConfig } from "@/lib/analyzeFortiGateConfig";

const MAX_CONFIG_BYTES = 2 * 1024 * 1024;

export async function POST(req: Request) {
  try {
    if (Number(req.headers.get("content-length")) > MAX_CONFIG_BYTES) {
      return Response.json({ error: "Config exceeds the 2 MB limit" }, { status: 413 });
    }
    const body = await req.json();
    const configText = body?.configText;

    if (typeof configText !== "string" || configText.trim().length === 0) {
      return Response.json(
        { error: "configText is required" },
        { status: 400 }
      );
    }

    if (Buffer.byteLength(configText, "utf8") > MAX_CONFIG_BYTES) {
      return Response.json({ error: "Config exceeds the 2 MB limit" }, { status: 413 });
    }
    if (!/^[ \t]*config[ \t]+firewall[ \t]+(policy|vip|virtual-server)[ \t]*\r?$/m.test(configText)) {
      return Response.json(
        { error: "No supported FortiGate policy, VIP, or virtual-server section found" },
        { status: 400 }
      );
    }

    const result = analyzeFortiGateConfig(configText);

    if (result.summary.policyCount + result.summary.vipCount + result.summary.virtualServerCount === 0) {
      return Response.json(
        { error: "No supported policy, VIP, or virtual-server objects were parsed" },
        { status: 422 }
      );
    }

    return Response.json(result);
  } catch {
    return Response.json(
      { error: "Could not analyze this configuration" },
      { status: 500 }
    );
  }
}
