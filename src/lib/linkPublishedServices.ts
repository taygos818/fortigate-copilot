import {
  FirewallPolicy,
  LinkedPublishedService,
  VirtualIp,
  VirtualServer,
} from "../types/firewall";

export function linkPublishedServices(
  policies: FirewallPolicy[],
  vips: VirtualIp[],
  virtualServers: VirtualServer[]
): LinkedPublishedService[] {
  const activePolicies = policies.filter(
    (policy) => policy.action.toLowerCase() === "accept" && policy.status?.toLowerCase() !== "disable"
  );
  const vipServices: LinkedPublishedService[] = vips.map((vip) => {
    const linkedPolicies = activePolicies.filter((policy) =>
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

  const virtualServerServices: LinkedPublishedService[] = virtualServers.map(
    (virtualServer) => {
      const linkedPolicies = activePolicies.filter((policy) =>
        policy.dstaddr.includes(virtualServer.name)
      );

      return {
        objectType: "virtual-server",
        objectName: virtualServer.name,
        externalInterface: virtualServer.interface,
        externalIp: virtualServer.ip,
        externalPort: virtualServer.port,
        internalTargets: virtualServer.realServers.map((server) => server.ip),
        linkedPolicyIds: linkedPolicies.map((policy) => policy.id),
        linkedPolicies,
      };
    }
  );

  return [...vipServices, ...virtualServerServices];
}
