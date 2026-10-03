# sdd-canon-data

Daily, signed security data for the SDD kit: known-vulnerability records (OSV and its origin
databases, enriched with CISA KEV and FIRST EPSS) and the distributable SAST rules curated by
the ArchGenerator platform.

## How it works

1. The platform builds the package after each successful sync, signs `MANIFEST.json` with an
   ed25519 key that never leaves its secret store, and exposes it at
   `https://app.archgenerator.com/api/public/security-data/latest`.
2. Once a day (05:30 UTC) and on demand, the `publish` workflow downloads it, checks sizes,
   hashes, schema, tag and the signature against the public key pinned in `keys.json`, refuses a
   package whose sync times are older than the current release (anti-rollback), and publishes
   the release `data-YYYYMMDD-HHMM` as `latest` only when the content changed. The 14 most recent
   `data-*` releases are kept.
3. The SDD kit (3.2.6+) reads the `latest` release and verifies the signature again with its own
   copy of the public key (`canon-data.keys`) before installing anything.

## Release assets

| Asset | Content |
|-------|---------|
| `MANIFEST.json` | schema `archgen-security-data/1`, file hashes, `contentSha256`, sync times, counts |
| `MANIFEST.json.sig` | `{"alg":"ed25519","keyId","signature"}` over the exact bytes of `MANIFEST.json` |
| `advisories.ndjson.gz` | vulnerability records, one JSON object per line |
| `sast-rules.ndjson.gz` | SAST rules with a permissive license, one per line |
| `LICENSES.md` | license of every origin database (informative, not signed) |

## Workflow hardening

Only `contents: write`; triggers are `schedule` and `workflow_dispatch` without inputs; no
`pull_request` trigger; no expression inside `run:`; no secret besides the repository's own
`GITHUB_TOKEN`; `actions/checkout` pinned by commit SHA; one run at a time. The workflow also
commits `status.json` when it publishes, and at least every 30 days, so that GitHub keeps the
schedule enabled.

## Data licenses

Each record keeps the license of its origin database (CC-BY-4.0, CC0-1.0, Apache-2.0, MIT —
see `LICENSES.md` in each release). The scripts in this repository are under the MIT License.
