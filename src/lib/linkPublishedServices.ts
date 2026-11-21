import {
  FirewallPolicy,
  LinkedPublishedService,
  VirtualIp,
  VirtualServer,
} from "../types/firewall";
import { GroupMembers, expandAddresses } from "../parsers/parseAddressGroups";

/**
 * Link VIPs and virtual servers to the enabled accepting policies that name
 * them in `dstaddr`, either directly or through address and VIP groups.
 */
export function linkPublishedServices(
  policies: FirewallPolicy[],
  vips: VirtualIp[],
  virtualServers: VirtualServer[],
  groups: GroupMembers = new Map()
): LinkedPublishedService[] {
  const activePolicies = policies.filter(
    (policy) => policy.action.toLowerCase() === "accept" && policy.status?.toLowerCase() !== "disable"
  );

  // Policy -> resolved destination names, each with the group chain that led there.
  const resolvedDestinations = activePolicies.map((policy) => ({
    policy,
    destinations: expandAddresses(policy.dstaddr, groups),
  }));

  const link = (objectName: string) => {
    const linkedPolicies: FirewallPolicy[] = [];
    const linkedVia: Record<number, string[]> = {};

    for (const { policy, destinations } of resolvedDestinations) {
      const matches = destinations.filter((destination) => destination.name === objectName);

      if (matches.length === 0) {
        continue;
      }

      linkedPolicies.push(policy);

      // Prefer a direct reference; otherwise report the shortest group chain.
      const shortest = matches.reduce((best, match) => (match.via.length < best.via.length ? match : best));

      if (shortest.via.length > 0) {
        linkedVia[policy.id] = shortest.via;
      }
    }

    return { linkedPolicies, linkedVia };
  };

  const vipServices: LinkedPublishedService[] = vips.map((vip) => {
    const { linkedPolicies, linkedVia } = link(vip.name);

    return {
      objectType: "vip",
      objectName: vip.name,
      externalInterface: vip.extintf,
      externalIp: vip.extip,
      externalPort: vip.extport,
      internalTargets:
        vip.realServers.length > 0
          ? vip.realServers.map((server) => (server.port ? `${server.ip}:${server.port}` : server.ip))
          : vip.mappedip,
      linkedPolicyIds: linkedPolicies.map((policy) => policy.id),
      linkedPolicies,
      linkedVia,
    };
  });

  const virtualServerServices: LinkedPublishedService[] = virtualServers.map((virtualServer) => {
    const { linkedPolicies, linkedVia } = link(virtualServer.name);

    return {
      objectType: "virtual-server",
      objectName: virtualServer.name,
      externalInterface: virtualServer.interface,
      externalIp: virtualServer.ip,
      externalPort: virtualServer.port,
      internalTargets: virtualServer.realServers.map((server) => server.ip),
      linkedPolicyIds: linkedPolicies.map((policy) => policy.id),
      linkedPolicies,
      linkedVia,
    };
  });

  return [...vipServices, ...virtualServerServices];
}
