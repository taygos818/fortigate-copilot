import { parseVips } from "../src/parsers/parseVips";
import fs from "node:fs";
import path from "node:path";

const filePath = path.join(process.cwd(), "sample-configs", "vip-test.conf");
const configText = fs.readFileSync(filePath, "utf-8");

const vips = parseVips(configText);

console.log(JSON.stringify(vips, null, 2));