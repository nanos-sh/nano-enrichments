// AbuseIPDB Agent Enrichment — IP reputation lookup
// Docs: https://docs.abuseipdb.com/#check-endpoint

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
  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(artifact)}&maxAgeInDays=90&verbose`,
    { headers: { Key: credentials.API_KEY, Accept: "application/json" } },
  );
  if (!res.ok) throw new Error(`AbuseIPDB API error: ${res.status}`);
  const { data } = await res.json();

  const tags: string[] = [];
  if (data.isTor) tags.push("tor");
  if (data.isWhitelisted) tags.push("whitelisted");
  if (data.totalReports > 0) tags.push("reported");
  if (data.abuseConfidenceScore >= 80) tags.push("high-abuse");

  return {
    key: artifact,
    key_type: "ip",
    risk_score: Math.min(data.abuseConfidenceScore ?? 0, 100),
    tags,
    data: {
      abuse_confidence: data.abuseConfidenceScore,
      total_reports: data.totalReports,
      country_code: data.countryCode,
      isp: data.isp,
      domain: data.domain,
      usage_type: data.usageType,
      is_tor: data.isTor,
      is_whitelisted: data.isWhitelisted,
      last_reported_at: data.lastReportedAt,
    },
  };
}

export { enrich };
