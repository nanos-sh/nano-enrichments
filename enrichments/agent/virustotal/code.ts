// VirusTotal Agent Enrichment — Multi-engine scanning
// Docs: https://docs.virustotal.com/reference/overview

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
  const endpoint = getEndpoint(artifact, artifactType);

  const res = await fetch(endpoint, {
    headers: { "x-apikey": credentials.API_KEY },
  });

  if (res.status === 404) {
    return {
      key: artifact,
      key_type: artifactType as any,
      data: { found: false },
    };
  }
  if (!res.ok) throw new Error(`VirusTotal API error: ${res.status}`);

  const { data } = await res.json();
  const attrs = data.attributes ?? {};
  const stats = attrs.last_analysis_stats ?? {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const total = malicious + suspicious + (stats.undetected ?? 0) + (stats.harmless ?? 0);

  const tags: string[] = [];
  if (malicious > 0) tags.push("malicious");
  if (suspicious > 0) tags.push("suspicious");
  if (attrs.tags) tags.push(...attrs.tags);
  if (attrs.popular_threat_classification?.suggested_threat_label) {
    tags.push(attrs.popular_threat_classification.suggested_threat_label);
  }

  const risk = total > 0 ? Math.min(Math.round(((malicious + suspicious * 0.5) / total) * 100), 100) : 0;

  return {
    key: artifact,
    key_type: artifactType as any,
    risk_score: risk,
    tags,
    data: {
      malicious_count: malicious,
      suspicious_count: suspicious,
      total_engines: total,
      reputation: attrs.reputation,
      threat_label: attrs.popular_threat_classification?.suggested_threat_label,
      categories: attrs.categories,
      last_analysis_date: attrs.last_analysis_date,
      ...(artifactType === "hash" && {
        file_type: attrs.type_description,
        file_size: attrs.size,
        names: attrs.names?.slice(0, 5),
      }),
      ...(artifactType === "domain" && {
        registrar: attrs.registrar,
        creation_date: attrs.creation_date,
        whois: attrs.whois?.slice(0, 500),
      }),
      ...(artifactType === "ip" && {
        country: attrs.country,
        as_owner: attrs.as_owner,
        network: attrs.network,
      }),
    },
  };
}

function getEndpoint(artifact: string, artifactType: string): string {
  const base = "https://www.virustotal.com/api/v3";
  switch (artifactType) {
    case "hash":
      return `${base}/files/${artifact}`;
    case "domain":
      return `${base}/domains/${artifact}`;
    case "ip":
      return `${base}/ip_addresses/${artifact}`;
    case "url": {
      const urlId = btoa(artifact).replace(/=+$/, "");
      return `${base}/urls/${urlId}`;
    }
    default:
      return `${base}/files/${artifact}`;
  }
}

export { enrich };
