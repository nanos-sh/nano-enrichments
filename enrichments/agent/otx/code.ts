// OTX AlienVault Agent Enrichment — IOC correlation
// Docs: https://otx.alienvault.com/api

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
  const typePath = getTypePath(artifactType);

  const res = await fetch(
    `https://otx.alienvault.com/api/v1/indicators/${typePath}/${encodeURIComponent(artifact)}/general`,
    { headers: { "X-OTX-API-KEY": credentials.API_KEY } },
  );
  if (res.status === 404) {
    return {
      key: artifact,
      key_type: artifactType as any,
      data: { found: false, pulse_count: 0 },
    };
  }
  if (!res.ok) throw new Error(`OTX API error: ${res.status}`);
  const data = await res.json();

  const pulseCount = data.pulse_info?.count ?? data.count ?? 0;
  const tags: string[] = [];
  if (pulseCount > 0) tags.push("in-pulse");
  if (pulseCount >= 5) tags.push("multi-pulse");

  const risk = Math.min(pulseCount * 15, 100);

  return {
    key: artifact,
    key_type: artifactType as any,
    risk_score: risk,
    tags,
    data: {
      pulse_count: pulseCount,
      reputation: data.reputation,
      country: data.country_code ?? data.country,
      pulses: (data.pulse_info?.pulses ?? []).slice(0, 5).map((p: any) => ({
        name: p.name,
        created: p.created,
        tags: p.tags,
      })),
    },
  };
}

function getTypePath(t: string): string {
  switch (t) {
    case "ip":
      return "IPv4";
    case "domain":
      return "domain";
    case "hash":
      return "file";
    case "url":
      return "url";
    default:
      return "IPv4";
  }
}

export { enrich };
