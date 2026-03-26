import fs from "node:fs";
import path from "node:path";
import { parsePolicies } from "../src/parsers/parsePolicies";
import { parseVips } from "../src/parsers/parseVips";
import { linkPublishedServices } from "../src/lib/linkPublishedServices";

const filePath = path.join(process.cwd(), "sample-configs", "policy-and-vip.conf");
const configText = fs.readFileSync(filePath, "utf-8");

const policies = parsePolicies(configText);
const vips = parseVips(configText);
const linkedPublishedServices = linkPublishedServices(policies, vips);

console.log(JSON.stringify(linkedPublishedServices, null, 2));