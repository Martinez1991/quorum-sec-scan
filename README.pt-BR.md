<p align="center">
  <img src="docs/assets/logo.svg" width="120" alt="Logo do Quorum">
</p>

# Quorum

[English](README.md) · **Português**

[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-7b42bc?logo=materialformkdocs&logoColor=white)](https://martinez1991.github.io/quorum-sec-scan/)
[![Deploy docs](https://github.com/Martinez1991/quorum-sec-scan/actions/workflows/docs.yml/badge.svg)](https://github.com/Martinez1991/quorum-sec-scan/actions/workflows/docs.yml)

📚 **Documentação completa:** <https://martinez1991.github.io/quorum-sec-scan/> (fonte em [`docs/`](docs/)).

> Scanning de segurança por consenso. Rode um pool de scanners open-source,
> correlacione os achados em que eles concordam e obtenha um único relatório que
> diz **quantas e quais** ferramentas detectaram cada problema — mais um score de
> confiança derivado desse consenso.

Quorum **não é mais um scanner**. É a camada leve de correlação + consenso por
cima dos scanners que você já confia (Trivy, Grype, Checkov, KICS, Dockle,
Kubescape). É **somente CLI/Docker — sem painel, sem daemon** — feito para rodar
dentro de um pipeline CI/CD e barrar um build via exit code.

```
alvo ─▶ orquestrador ─▶ [trivy|grype|checkov|kics|dockle|kubescape]
                        └▶ normaliza ▶ resolve aliases ▶ correlaciona ▶ score ▶ relatório (SARIF/JSON/XML)
```

Veja o [DESIGN.md](DESIGN.md) para o modelo de dados completo, a matriz de
correlação e a matemática do consenso.

---

## Por quê

Scanners diferentes encontram problemas sobrepostos — mas não idênticos — e os
reportam em formatos incompatíveis. Rode três ferramentas e você terá três
relatórios, achados duplicados e nenhum sinal sobre quais achados estão
*corroborados*. O Quorum normaliza tudo para um modelo canônico, funde achados
equivalentes entre as ferramentas e revela o consenso:

```json
{
  "title": "S3 bucket sem bloqueio de acesso público",
  "severity": "HIGH",
  "detectedBy": ["checkov", "trivy"],
  "detectionCount": 2,
  "confidence": 0.81
}
```

Princípio condutor: **falso split > falso merge.** Na dúvida, o Quorum mantém os
achados separados e os marca como `unmapped` — um merge errado esconde risco.

---

## Instalação

### Docker (recomendado)

```bash
# Imagem self-contained com todos os scanners embutidos:
docker run --rm -v "$PWD:/work" ghcr.io/martinez1991/quorum-sec-scan:full \
  scan . --type repo --format sarif --output /work/quorum.sarif --fail-on high

# Imagem slim (só o orquestrador — traga seus scanners no PATH):
docker run --rm -v "$PWD:/work" ghcr.io/martinez1991/quorum-sec-scan:slim scan . --type repo
```

Tags publicadas (buildadas e enviadas ao GHCR pelo [workflow de release](.github/workflows/release.yml) a cada tag `v*`):

| Tag | Imagem | Plataformas |
|-----|--------|-------------|
| `:latest`, `:full`, `:<versão>` | todos os scanners embutidos (imagem CI self-contained) | `linux/amd64` |
| `:slim`, `:<versão>-slim` | só o orquestrador | `linux/amd64`, `linux/arm64` |

Todas as imagens são **assinadas com [cosign](https://github.com/sigstore/cosign)
em modo keyless** via a identidade OIDC do GitHub (sem chaves para gerenciar).
Verifique antes de usar:

```bash
cosign verify ghcr.io/martinez1991/quorum-sec-scan:slim \
  --certificate-identity-regexp \
    "https://github.com/Martinez1991/quorum-sec-scan/.github/workflows/release.yml@.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Binário nativo

Baixe o arquivo para seu OS/arch na página de [Releases](https://github.com/Martinez1991/quorum-sec-scan/releases)
(gerado pelo GoReleaser; já inclui o crosswalk padrão). Cada release traz um
`checksums.txt` e uma assinatura cosign keyless (`checksums.txt.sig` / `.pem`)
que você verifica com `cosign verify-blob`.

### A partir do código

```bash
go build -o quorum ./cmd/quorum     # ou: make build
./quorum list-scanners
```

Go 1.26+. O orquestrador chama os binários de scanner que estiverem no `PATH`;
os ausentes são reportados como `unavailable` e pulados (o scan nunca falha só
porque uma ferramenta não está instalada).

---

## Uso

```
quorum scan <alvo> \
  --type image|repo|k8s \          # inferido se omitido (caminho existente → repo, senão image)
  --scanners trivy,grype,checkov \ # padrão: todos que suportam o alvo
  --format sarif|json|xml \        # padrão: sarif
  --output report.sarif \          # padrão: stdout
  --fail-on high \                 # exit 1 se algum achado for >= esta severidade
  --min-severity medium \          # descarta achados abaixo desta severidade
  --baseline .quorumignore \       # suprime achados aceitos (por fingerprint/chave)
  --crosswalk ./crosswalk \        # diretório de mapeamentos rule→control
  --cache ~/.cache/quorum/aliases.json \
  --timeout 5m \                   # timeout por scanner
  --offline \                      # pular lookups de alias na OSV
  --quiet
```

Exemplos:

```bash
# Consenso de SCA sobre uma imagem, barrar em CRITICAL:
quorum scan minhaimagem:1.2.3 --type image --scanners trivy,grype --fail-on critical

# Consenso de IaC sobre um repo Terraform, SARIF para o GitHub code scanning:
quorum scan . --type repo --format sarif -o quorum.sarif

# Postura Kubernetes, JSON para processamento posterior:
quorum scan ./k8s --type k8s --format json -o quorum.json
```

### Baseline (aceitar achados conhecidos)

Para adotar `--fail-on` no CI é preciso poder aceitar achados já triados.
Coloque um fingerprint ou correlationKey por linha num arquivo de baseline
(padrão `.quorumignore`); achados correspondentes são suprimidos do relatório e
do gate. `#` inicia comentário. Os fingerprints vêm direto do relatório
(`fingerprint` no JSON, `partialFingerprints["quorum/v1"]` no SARIF). As
contagens de supressão são sempre logadas — nada é descartado silenciosamente.

### Exit codes

| Código | Significado |
|--------|-------------|
| `0`    | Sucesso (ou nenhum achado atingiu `--fail-on`) |
| `1`    | Um achado atingiu ou excedeu `--fail-on` (gate de build) |
| `2`    | Erro de uso ou de execução |

---

## O que ele faz, etapa por etapa

1. **Scan** — os adapters suportados rodam em paralelo, com timeout por scanner.
2. **Normalize** — a saída de cada ferramenta vira um `Finding` canônico (uma
   escala única de severidade, PURLs para pacotes, AVD/CIS/categoria para controles).
3. **Resolve aliases** (só VULN) — o `GHSA-…` do Grype e o `CVE-…` do Trivy para
   o mesmo bug são unificados via aliases locais → cache local → OSV.dev (CVE
   preferido). Falhas de rede degradam graciosamente.
4. **Correlate** — achados são agrupados por uma `correlationKey` determinística
   por tipo (`DESIGN §6`). Controles não resolvíveis ficam isolados.
5. **Score** — cada grupo recebe um `detectionCount` e uma `confidence` 0..1 que
   pesa diversidade de engine, severidade e confirmação autoritativa — não a
   contagem bruta (três linters numa linha ≠ sinal forte).
6. **Report** — SARIF (primário), JSON ou XML.

---

## Scanners

| Adapter | Tipo | Alvos | Notas |
|---------|------|-------|-------|
| `trivy` | VULN, MISCONFIG, SECRET | image, repo, k8s | fala AVD nativamente |
| `grype` | VULN | image, repo | aliases via `relatedVulnerabilities` |
| `checkov` | MISCONFIG | repo, k8s | crosswalk para AVD |
| `kics` | MISCONFIG | repo, k8s | crosswalk para AVD |
| `dockle` | IMG_HARDENING | image | controles CIS-DI |
| `kubescape` | K8S_POSTURE | k8s | postura por controle |

`quorum list-scanners` imprime o que está registrado.

---

## Formatos de saída

- **SARIF** (primário) — usa `partialFingerprints` (`quorum/v1` =
  `sha256(correlationKey)`) para que GitHub code scanning / DefectDojo deduplicam
  o mesmo achado entre execuções de graça. `properties.detectedBy/detectionCount/
  confidence` carregam o consenso.
- **JSON** — dump direto dos achados fundidos mais um resumo de execução por
  scanner e rollup de severidade.
- **XML** — mesma estrutura serializada para pipelines legados/JUnit-like.

Todo relatório inclui o **status** por scanner (`ran`/`skipped`/`unavailable`/
`error`/`timeout`). *"0 achados" não é prova de segurança* — pode significar que
nenhum scanner rodou. O Quorum deixa isso explícito.

---

## Customizando o crosswalk

Misconfigs de IaC/K8s só correlacionam quando o rule id de cada engine mapeia
para um controle canônico compartilhado. Os mapeamentos vivem em YAML sob
`--crosswalk` (padrão `./crosswalk`, embutido em `/opt/quorum/crosswalk` nas
imagens Docker):

```yaml
- canonicalControl: AVD-AWS-0086
  category: public-access
  cwe: CWE-732
  title: "S3 bucket sem bloqueio de acesso público"
  ids:
    checkov: [CKV_AWS_53, CKV_AWS_54]
    kics:    ["a2c... (S3 Bucket Allows Public ACL)"]
    trivy:   [AVD-AWS-0086]
```

Adicione arquivos para mais nuvens/controles; tudo dentro do diretório é
mesclado. Um rule sem mapeamento **não é adivinhado** — seu achado fica isolado e
recebe a flag `unmapped`.

> Os números AVD/CKV e UUIDs de KICS em `crosswalk/aws.yaml` são ilustrativos do
> formato — confira contra os catálogos oficiais antes de usar em produção.

---

## CI/CD

Pipelines prontos para copiar em [examples/ci/](examples/ci/):

- [GitHub Actions](examples/ci/github-actions.yml) — scan + upload do SARIF para o code scanning.
- [GitLab CI](examples/ci/gitlab-ci.yml) — artefatos SARIF/JSON + gate por exit code.

---

## Roadmap

| Fase  | Entrega |
|-------|---------|
| MVP   | Trivy + Grype (SCA), consenso por `vulnId+purl`, SARIF+JSON, imagem `:full` |
| v0.2  | Checkov + KICS (IaC), crosswalk top-50 S3/IAM, fallback por categoria |
| v0.3  | Kubescape + Polaris (K8s), Dockle, XML |
| v1.0  | Camada policy-as-code OPA/Conftest, cache de aliases persistente, perfis de imagem |
| futuro| módulo runtime separado (modelo de stream Falco/Tetragon) |

---

## Desenvolvimento

```bash
make test     # testes unitários + de contrato (fixtures em internal/adapter/testdata)
make vet
make build
make docker-full
```

Cada adapter traz um teste de contrato contra uma fixture versionada da saída
real da ferramenta, então uma mudança de formato quebra um teste antes de quebrar
a produção.

---

## Limitações conhecidas

- **Granularidade da correlação de MISCONFIG.** Os scanners divergem no caminho
  do arquivo e na identidade do recurso (Trivy/Checkov usam o endereço Terraform
  `aws_s3_bucket.data`, enquanto o KICS costuma usar o nome literal do recurso).
  Para o consenso entre engines funcionar, achados de MISCONFIG correlacionam por
  `basename(arquivo) + tipoDoRecurso + controleCanônico`. Trade-off: dois
  recursos distintos do *mesmo tipo* com o *mesmo* controle no *mesmo* arquivo
  podem se fundir indevidamente. Identidade por recurso fica para uma versão
  futura.
- **Cobertura do crosswalk.** O `crosswalk/aws.yaml` cobre controles comuns de
  S3/IAM (derivados de saída real dos scanners); controles sem mapeamento ficam
  isolados e marcados como `unmapped`, em vez de adivinhados.

## Segurança da própria cadeia

Os binários de scanner embutidos fazem parte do seu trust boundary. A imagem
`:full` pina cada ferramenta por versão; para produção, converta essas tags para
referências imutáveis `@sha256:<digest>` e valide os checksums dos releases
(`DESIGN §12`).

## Licença

[Apache-2.0](LICENSE).
