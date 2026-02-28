// Shodan Agent Enrichment — IP / host reconnaissance
// Docs: https://developer.shodan.io/api

interface AgentEnrichmentResult {
  key: string;
  key_type: "ip" | "domain" | "hash" | "url";
  risk_score?: number;
  tags?: string[];
  data: Record<string, unknown>;
}

async function enrich(
  artifact: string,
  artifactType: string,
  credentials: Record<string, string>,
): Promise<AgentEnrichmentResult> {
  const url =
    artifactType === "domain"
      ? `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(artifact)}&key=${credentials.API_KEY}`
      : `https://api.shodan.io/shodan/host/${encodeURIComponent(artifact)}?key=${credentials.API_KEY}`;

  const res = await fetch(url);
  if (res.status === 404) {
    return { key: artifact, key_type: artifactType as any, data: { found: false } };
  }
  if (!res.ok) throw new Error(`Shodan API error: ${res.status}`);
  const data = await res.json();

  // For domain lookups, resolve IP first then fetch host
  if (artifactType === "domain") {
    const ip = data[artifact];
    if (!ip) return { key: artifact, key_type: "domain", data: { found: false } };
    const hostRes = await fetch(
      `https://api.shodan.io/shodan/host/${ip}?key=${credentials.API_KEY}`,
    );
    if (!hostRes.ok)
      return { key: artifact, key_type: "domain", data: { resolved_ip: ip, found: false } };
    const hostData = await hostRes.json();
    return buildResult(artifact, "domain", hostData);
  }

  return buildResult(artifact, "ip", data);
}

function buildResult(
  artifact: string,
  keyType: string,
  data: any,
): AgentEnrichmentResult {
  const tags: string[] = [];
  const ports = data.ports ?? [];
  if (ports.includes(22)) tags.push("ssh");
  if (ports.includes(3389)) tags.push("rdp");
  if (data.vulns && data.vulns.length > 0) tags.push("vulnerable");
  if (data.tags) tags.push(...data.tags);

  const vulnCount = data.vulns?.length ?? 0;
  const risk = Math.min(20 + ports.length * 3 + vulnCount * 15, 100);

  return {
    key: artifact,
    key_type: keyType as any,
    risk_score: risk,
    tags,
    data: {
      ip: data.ip_str,
      hostnames: data.hostnames,
      country_code: data.country_code,
      city: data.city,
      org: data.org,
      isp: data.isp,
      os: data.os,
      ports,
      vulns: data.vulns,
      last_update: data.last_update,
    },
  };
}

export { enrich };
