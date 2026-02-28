// Tor Exit Nodes — Bulk data enrichment
// Source: https://check.torproject.org/torbulkexitlist

interface EnrichmentRecord {
  key: string;
  risk_score?: number;
  tags?: string[];
  data: Record<string, unknown>;
}

interface DataEnrichmentResult {
  records: EnrichmentRecord[];
  watermark?: string;
}

async function enrich(context: {
  lastWatermark?: string;
  credentials: Record<string, string>;
}): Promise<DataEnrichmentResult> {
  const res = await fetch(
    "https://check.torproject.org/torbulkexitlist?ip=1.1.1.1",
  );
  if (!res.ok) throw new Error(`Tor exit list error: ${res.status}`);

  const text = await res.text();
  const ips = text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));

  const records: EnrichmentRecord[] = ips.map((ip) => ({
    key: ip,
    risk_score: 40,
    tags: ["tor", "exit-node"],
    data: {
      source: "torproject.org",
      node_type: "exit",
      fetched_at: new Date().toISOString(),
    },
  }));

  return {
    records,
    watermark: new Date().toISOString(),
  };
}

export { enrich };
