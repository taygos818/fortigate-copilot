import fs from "node:fs";
import path from "node:path";
import { analyzeFortiGateConfig } from "../src/lib/analyzeFortiGateConfig";

const filePath = path.join(process.cwd(), "sample-configs", "policy-and-vip.conf");
const configText = fs.readFileSync(filePath, "utf-8");

const result = analyzeFortiGateConfig(configText);

console.log(JSON.stringify(result, null, 2));