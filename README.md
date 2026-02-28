# NanoSIEM Enrichments

Official enrichment catalog for [NanoSIEM](https://github.com/nanos-sh/nanosiem). Add this repository in **Settings > Marketplace > Repositories** to browse and install enrichments.

## Structure

```
enrichments/
  agent/          # On-demand artifact lookups (IP, domain, hash, URL)
    abuseipdb/
    greynoise/
    malwarebazaar/
    otx/
    shodan/
    urlhaus/
    virustotal/
  data/           # Bulk data feeds synced on schedule
    threatfox/
    tor-exit-nodes/
```

Each enrichment directory contains:
- `manifest.yaml` — metadata, credential requirements, config
- `code.ts` — TypeScript code executed in the Deno sandbox

## Writing Custom Enrichments

See the [NanoSIEM docs](https://docs.nanosiem.io/enrichments/custom) for the full guide. The basic pattern:

### Agent enrichment (on-demand lookup)

```typescript
async function enrich(
  artifact: string,
  artifactType: string,
  credentials: Record<string, string>,
): Promise<AgentEnrichmentResult> {
  // Call external API, return structured result
}
export { enrich };
```

### Data enrichment (bulk feed)

```typescript
async function enrich(context: {
  lastWatermark?: string;
  credentials: Record<string, string>;
}): Promise<DataEnrichmentResult> {
  // Fetch bulk data, return records array
}
export { enrich };
```

## License

MIT
