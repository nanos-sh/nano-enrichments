// URLhaus Agent Enrichment — Malicious URL lookup
// Docs: https://urlhaus-api.abuse.ch/

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
  const endpoint =
    artifactType === "domain"
      ? "https://urlhaus-api.abuse.ch/v1/host/"
      : "https://urlhaus-api.abuse.ch/v1/url/";

  const body =
    artifactType === "domain"
      ? `host=${encodeURIComponent(artifact)}`
      : `url=${encodeURIComponent(artifact)}`;

  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error(`URLhaus API error: ${res.status}`);
  const data = await res.json();

  if (data.query_status === "no_results") {
    return { key: artifact, key_type: artifactType as any, data: { found: false } };
  }

  const tags: string[] = [];
  if (data.threat) tags.push(data.threat);
  if (data.tags) tags.push(...data.tags);
  if (data.url_status === "online") tags.push("online");
  if (data.blacklists?.spamhaus_dbl) tags.push("spamhaus-listed");

  const risk =
    data.threat === "malware_download" ? 90 : data.urls_online > 0 ? 70 : 30;

  return {
    key: artifact,
    key_type: artifactType as any,
    risk_score: Math.min(risk, 100),
    tags,
    data: {
      threat: data.threat,
      url_status: data.url_status,
      url_count: data.url_count,
      urls_online: data.urls_online,
      blacklists: data.blacklists,
      date_added: data.date_added,
      host: data.host,
    },
  };
}

export { enrich };
