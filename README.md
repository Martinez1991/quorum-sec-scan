# Quorum

**English** · [Português](README.pt-BR.md)

> Consensus security scanning. Run a pool of open-source scanners, correlate the
> findings they agree on, and get one report that tells you **how many and which**
> tools detected each issue — plus a confidence score derived from that consensus.

Quorum is **not another scanner**. It is the lightweight correlation + consensus
layer on top of the scanners you already trust (Trivy, Grype, Checkov, KICS,
Dockle, Kubescape). It is **CLI/Docker only — no panel, no daemon** — built to
run inside a CI/CD pipeline and gate a build via exit code.

```
target ─▶ orchestrator ─▶ [trivy|grype|checkov|kics|dockle|kubescape]
                          └▶ normalize ▶ resolve aliases ▶ correlate ▶ score ▶ report (SARIF/JSON/XML)
```

See [DESIGN.md](DESIGN.md) for the full data model, correlation matrix, and
consensus math.

---

## Why

Different scanners find overlapping-but-not-identical issues and report them in
incompatible shapes. Run three tools and you get three reports, duplicate
findings, and no signal about which findings are *corroborated*. Quorum
normalizes everything to one canonical model, merges equivalent findings across
tools, and surfaces consensus:

```json
{
  "title": "S3 bucket sem bloqueio de acesso público",
  "severity": "HIGH",
  "detectedBy": ["checkov", "trivy"],
  "detectionCount": 2,
  "confidence": 0.81
}
```

Guiding principle: **false split > false merge.** When in doubt, Quorum keeps
findings separate and flags them `unmapped` — a wrong merge hides risk.

---

## Install

### Docker (recommended)

```bash
# Self-contained image with every scanner bundled:
docker run --rm -v "$PWD:/work" ghcr.io/martinez1991/quorum-sec-scan:full \
  scan . --type repo --format sarif --output /work/quorum.sarif --fail-on high

# Slim image (orchestrator only — bring your own scanners on PATH):
docker run --rm -v "$PWD:/work" ghcr.io/martinez1991/quorum-sec-scan:slim scan . --type repo
```

Published tags (built and pushed to GHCR by the [release workflow](.github/workflows/release.yml) on every `v*` tag):

| Tag | Image | Platforms |
|-----|-------|-----------|
| `:latest`, `:full`, `:<version>` | all scanners bundled (self-contained CI image) | `linux/amd64` |
| `:slim`, `:<version>-slim` | orchestrator only | `linux/amd64`, `linux/arm64` |

All images are **signed keylessly with [cosign](https://github.com/sigstore/cosign)**
via the GitHub OIDC identity (no keys to manage). Verify before use:

```bash
cosign verify ghcr.io/martinez1991/quorum-sec-scan:slim \
  --certificate-identity-regexp \
    "https://github.com/Martinez1991/quorum-sec-scan/.github/workflows/release.yml@.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### From source

```bash
go build -o quorum ./cmd/quorum     # or: make build
./quorum list-scanners
```

Go 1.26+. The orchestrator shells out to whichever scanner binaries are on
`PATH`; missing ones are reported as `unavailable` and skipped (the scan never
fails just because a tool is absent).

---

## Usage

```
quorum scan <target> \
  --type image|repo|k8s \          # inferred if omitted (existing path → repo, else image)
  --scanners trivy,grype,checkov \ # default: all that support the target
  --format sarif|json|xml \        # default: sarif
  --output report.sarif \          # default: stdout
  --fail-on high \                 # exit 1 if any finding is >= this severity
  --crosswalk ./crosswalk \        # directory of rule→control mappings
  --cache ~/.cache/quorum/aliases.json \
  --timeout 5m \                   # per-scanner timeout
  --offline \                      # skip OSV alias lookups
  --quiet
```

Examples:

```bash
# SCA consensus over a container image, gate on CRITICAL:
quorum scan myimage:1.2.3 --type image --scanners trivy,grype --fail-on critical

# IaC consensus over a Terraform repo, SARIF for GitHub code scanning:
quorum scan . --type repo --format sarif -o quorum.sarif

# Kubernetes posture, JSON for further processing:
quorum scan ./k8s --type k8s --format json -o quorum.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success (or no finding met `--fail-on`) |
| `1`  | A finding met or exceeded `--fail-on` (build gate) |
| `2`  | Usage or runtime error |

---

## What it does, stage by stage

1. **Scan** — supported adapters run in parallel with a per-scanner timeout.
2. **Normalize** — every tool's output becomes a canonical `Finding` (one
   severity scale, PURLs for packages, AVD/CIS/category for controls).
3. **Resolve aliases** (VULN only) — Grype's `GHSA-…` and Trivy's `CVE-…` for
   the same bug are unified via finding-local aliases → local cache → OSV.dev
   (CVE preferred). Network failures degrade gracefully.
4. **Correlate** — findings are grouped by a deterministic, per-type
   `correlationKey` (`DESIGN §6`). Unresolvable controls stay isolated.
5. **Score** — each group gets a `detectionCount` and a `confidence` 0..1 that
   weighs engine diversity, severity, and authoritative confirmation — not raw
   count (three linters on one line ≠ strong signal).
6. **Report** — SARIF (primary), JSON, or XML.

---

## Scanners

| Adapter | Type | Targets | Notes |
|---------|------|---------|-------|
| `trivy` | VULN, MISCONFIG, SECRET | image, repo, k8s | speaks AVD natively |
| `grype` | VULN | image, repo | aliases via `relatedVulnerabilities` |
| `checkov` | MISCONFIG | repo, k8s | crosswalked to AVD |
| `kics` | MISCONFIG | repo, k8s | crosswalked to AVD |
| `dockle` | IMG_HARDENING | image | CIS-DI controls |
| `kubescape` | K8S_POSTURE | k8s | control posture |

`quorum list-scanners` prints what is registered.

---

## Output formats

- **SARIF** (primary) — uses `partialFingerprints` (`quorum/v1` = `sha256(correlationKey)`)
  so GitHub code scanning / DefectDojo dedupe the same finding across runs for
  free. `properties.detectedBy/detectionCount/confidence` carry the consensus.
- **JSON** — a direct dump of merged findings plus a per-scanner run summary and
  severity rollup.
- **XML** — same structure serialized for legacy/JUnit-like pipelines.

Every report includes per-scanner **status** (`ran`/`skipped`/`unavailable`/
`error`/`timeout`). *"0 findings" is not proof of safety* — it could mean no
scanner ran. Quorum makes that explicit.

---

## Customizing the crosswalk

IaC/K8s misconfigs only correlate when each engine's rule id maps to a shared
canonical control. Mappings live in YAML under `--crosswalk` (default
`./crosswalk`, bundled at `/opt/quorum/crosswalk` in the Docker images):

```yaml
- canonicalControl: AVD-AWS-0086
  category: public-access
  cwe: CWE-732
  title: "S3 bucket without public-access block"
  ids:
    checkov: [CKV_AWS_53, CKV_AWS_54]
    kics:    ["a2c... (S3 Bucket Allows Public ACL)"]
    trivy:   [AVD-AWS-0086]
```

Add files for more clouds/controls; everything under the directory is merged.
A rule with no mapping is **not guessed** — its finding stays isolated and is
flagged `unmapped`.

> The AVD/CKV numbers and KICS UUIDs shipped in `crosswalk/aws.yaml` are
> illustrative of the format — verify them against the official catalogs before
> production use.

---

## CI/CD

Ready-to-copy pipelines in [examples/ci/](examples/ci/):

- [GitHub Actions](examples/ci/github-actions.yml) — scan + upload SARIF to code scanning.
- [GitLab CI](examples/ci/gitlab-ci.yml) — SARIF/JSON artifacts + gate on exit code.

---

## Roadmap

| Phase | Delivery |
|-------|----------|
| MVP   | Trivy + Grype (SCA), consensus by `vulnId+purl`, SARIF+JSON, `:full` image |
| v0.2  | Checkov + KICS (IaC), crosswalk top-50 S3/IAM, category fallback |
| v0.3  | Kubescape + Polaris (K8s), Dockle, XML |
| v1.0  | OPA/Conftest policy-as-code layer, persistent alias cache, image profiles |
| future| separate runtime module (Falco/Tetragon stream model) |

---

## Development

```bash
make test     # unit + adapter contract tests (fixtures in internal/adapter/testdata)
make vet
make build
make docker-full
```

Each adapter ships a contract test against a versioned fixture of the tool's
real output, so a format change breaks a test before it breaks production.

---

## Security of the chain itself

Bundled scanner binaries are part of your trust boundary. The `:full` image
pins each tool by version; for production, convert those to immutable
`@sha256:<digest>` references and verify release checksums (`DESIGN §12`).

## License

[Apache-2.0](LICENSE).
