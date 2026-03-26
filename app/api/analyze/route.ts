import { analyzeFortiGateConfig } from "@/lib/analyzeFortiGateConfig";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const configText = body?.configText;

    if (typeof configText !== "string" || configText.trim().length === 0) {
      return Response.json(
        { error: "configText is required" },
        { status: 400 }
      );
    }

    const result = analyzeFortiGateConfig(configText);

    return Response.json(result);
  } catch (error) {
    return Response.json(
      {
        error: "Failed to analyze config",
        details: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}