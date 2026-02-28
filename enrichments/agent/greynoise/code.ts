// GreyNoise Agent Enrichment — IP noise classification
// Docs: https://docs.greynoise.io/reference/get_v3-community-ip

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
    `https://api.greynoise.io/v3/community/${encodeURIComponent(artifact)}`,
    { headers: { key: credentials.API_KEY, Accept: "application/json" } },
  );
  if (res.status === 404) {
    return {
      key: artifact,
      key_type: "ip",
      data: { found: false, noise: false, riot: false },
    };
  }
  if (!res.ok) throw new Error(`GreyNoise API error: ${res.status}`);
  const data = await res.json();

  const tags: string[] = [];
  if (data.noise) tags.push("internet-noise");
  if (data.riot) tags.push("benign-service");
  if (data.classification === "malicious") tags.push("malicious");
  if (data.classification === "benign") tags.push("benign");

  let risk = 0;
  if (data.classification === "malicious") risk = 80;
  else if (data.classification === "unknown" && data.noise) risk = 40;
  else if (data.classification === "benign") risk = 5;

  return {
    key: artifact,
    key_type: "ip",
    risk_score: risk,
    tags,
    data: {
      noise: data.noise,
      riot: data.riot,
      classification: data.classification,
      name: data.name,
      link: data.link,
      last_seen: data.last_seen,
      message: data.message,
    },
  };
}

export { enrich };
