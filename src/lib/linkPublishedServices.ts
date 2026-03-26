import { FirewallPolicy, LinkedPublishedService, VirtualIp } from "../types/firewall";

export function linkPublishedServices(
  policies: FirewallPolicy[],
  vips: VirtualIp[]
): LinkedPublishedService[] {
  return vips.map((vip) => {
    const linkedPolicies = policies.filter((policy) =>
      policy.dstaddr.includes(vip.name)
    );

    return {
      objectType: "vip",
      objectName: vip.name,
      externalInterface: vip.extintf,
      externalIp: vip.extip,
      externalPort: vip.extport,
      internalTargets: vip.mappedip,
      linkedPolicyIds: linkedPolicies.map((policy) => policy.id),
      linkedPolicies,
    };
  });
}