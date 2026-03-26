import { parsePolicies } from "../src/parsers/parsePolicies";
import fs from "node:fs";
import path from "node:path";

const filePath = path.join(process.cwd(), "sample-configs", "simple.conf");
const configText = fs.readFileSync(filePath, "utf-8");

const policies = parsePolicies(configText);

console.log(JSON.stringify(policies, null, 2));