import fs from "node:fs";
import path from "node:path";
import { parseVirtualServers } from "../src/parsers/parseVirtualServers";

const filePath = path.join(
  process.cwd(),
  "sample-configs",
  "virtual-server-test.conf"
);
const configText = fs.readFileSync(filePath, "utf-8");

const virtualServers = parseVirtualServers(configText);

console.log(JSON.stringify(virtualServers, null, 2));