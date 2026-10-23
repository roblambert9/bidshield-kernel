# BidShield Kernel — Open-Source Document Defense Schema

> **Make institutional complexity survivable for ordinary people.**

A domain-general document defense kernel that extracts mandatory requirements, deadlines, and referenced documents from procurement, insurance, and benefits paperwork. Produces scope-honest, source-cited preliminary risk previews.

## Status

**Research preview.** Not production-ready. No paid service. No compliance ruling.

## What This Is

A Python dataclass schema and validation layer for structured document defense. The kernel represents:

- **ReviewScope** — notice triage, partial package, full package, or denial packet
- **DocumentCriticality** — critical, supporting, contextual, unknown
- **DependencyCriticality** — blocking, high, medium, low
- **InterpretationConfidence** — high, medium, low, ambiguous
- **OutputClassification** — preliminary preview, human-reviewed draft, client-ready report, rejected sensitive input, insufficient documents
- **IntakeConsent** — PHI/PII/privileged legal/confidential pricing/credential/government-protected confirmation gates
- **DocumentSensitivity** — sensitivity classification for safe public preview
- **ProcessingLocation** — client browser, local machine, secure server, third-party processor
- **Fatal language gate** — preliminary outputs cannot use "Fatal", "non-responsive", "disqualified", "will be rejected"

## Key Design Principles

1. **Scope honesty** — every report declares what was reviewed and what was not
2. **Consequence verification** — Fatal items require a verbatim consequence quote from source
3. **Human verification gate** — only client-ready reports may contain verified Fatal/High findings
4. **Sensitivity gates** — public preview refuses PHI, PII, privileged legal, confidential pricing, credentials, government-protected material
5. **Processing location transparency** — local-first claims only when technically enforced
6. **Fatal language gate** — preliminary outputs use "potential high-attention clause" not "Fatal"

## Moonshot Metric

Return 1,000,000 administrative hours to independent operators, clinics, and families by 2028.

## Current Baseline

- Outside paying customer count: 0
- Verified human hours returned: 0
- Live document pilots: 0

## License

MIT

## Contributing

This is a research preview. Contributions welcome. Please open an issue before submitting a PR.

## Disclaimer

This is not legal, insurance, medical, procurement, or financial advice. This kernel produces preliminary previews only. Human verification is required before acting on any output.