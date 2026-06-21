# Quorum — Documento de Design

> **Nome de trabalho:** Quorum (consenso entre scanners). Trocável.
> **Status:** Draft v0.1 — base para implementação do MVP.
> **Escopo deste doc:** modelo de dados, correlação/dedup, consenso, saída SARIF, CLI/Docker.

---

## 1. Visão

Orquestrador CLI leve que roda um *pool* de scanners de segurança open source sobre um
alvo (repositório, imagem, manifests), normaliza todos os achados para um modelo
canônico, **correlaciona findings equivalentes entre ferramentas** e produz um relatório
unificado (SARIF / JSON / XML) onde cada finding carrega *quantos e quais* scanners o
detectaram, mais um score de confiança derivado desse consenso.

**Diferencial:** não é "mais um scanner". É a camada de correlação + consenso que
ninguém entrega de forma leve e plugável.

### Princípios

1. **Modelo canônico primeiro.** Nenhuma lógica opera sobre o JSON cru de um scanner.
2. **Adapters plugáveis.** Adicionar scanner = adicionar um adapter, sem tocar no core.
3. **Falso split > falso merge.** Na dúvida, não una findings. Um merge errado esconde risco.
4. **Tudo determinístico.** `correlationKey` é função pura dos dados normalizados.

---

## 2. Escopo

### Dentro (MVP → v1)
- SCA / vuln de imagem: **Trivy + Grype** (Syft p/ SBOM)
- IaC / misconfig: **Checkov + KICS**
- Postura K8s: **Kubescape** (+ Polaris na v1)
- Hardening de imagem: **Dockle**
- Saídas: SARIF (primária), JSON, XML

### Fora (por enquanto)
- Runtime (Falco/Tetragon/Inspektor Gadget) — modelo de *stream*, não cabe em scan estático. Produto separado futuro.
- OPA/Conftest como "scanner" — entram só como camada de policy-as-code opcional (usuário traz regras).
- Ferramentas mortas/redundantes: **tfsec** (absorvido pelo Trivy), **Terrascan** (arquivado nov/2025).

---

## 3. Arquitetura

```
            ┌──────────────┐
  target →  │  Orchestrator│  (resolve quais adapters rodar p/ o alvo)
            └──────┬───────┘
                   │ fan-out (paralelo, com timeout por scanner)
      ┌────────────┼─────────────┬───────────────┐
      ▼            ▼             ▼               ▼
  ┌────────┐  ┌────────┐   ┌─────────┐     ┌─────────┐
  │ trivy  │  │ grype  │   │ checkov │ ...  │ dockle  │   ← Adapters
  │adapter │  │adapter │   │ adapter │     │ adapter │
  └───┬────┘  └───┬────┘   └────┬────┘     └────┬────┘
      │ []Finding (canônico)    │               │
      └───────────┬─────────────┴───────────────┘
                  ▼
         ┌─────────────────┐
         │ Alias Resolver  │  (GHSA↔CVE, OSV árbitro) — só p/ type=VULN
         └────────┬────────┘
                  ▼
         ┌─────────────────┐
         │  Correlator     │  (agrupa por correlationKey)
         └────────┬────────┘
                  ▼
         ┌─────────────────┐
         │ Consensus Engine│  (detectionCount + confidence)
         └────────┬────────┘
                  ▼
         ┌─────────────────┐
         │   Reporters     │  → SARIF / JSON / XML
         └─────────────────┘
```

Pipeline: `scan → normalize → resolve aliases → correlate → score → report`.

---

## 4. Modelo de dados canônico (Go)

```go
package model

type FindingType string

const (
	TypeVuln         FindingType = "VULN"
	TypeMisconfig    FindingType = "MISCONFIG"
	TypeSecret       FindingType = "SECRET"
	TypeK8sPosture   FindingType = "K8S_POSTURE"
	TypeImgHardening FindingType = "IMG_HARDENING"
)

type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
)

type Resource struct {
	Kind      string // ex: aws_s3_bucket | Deployment
	Name      string
	Namespace string // k8s
	Address   string // canonizado: "<type>.<name>"
}

type Location struct {
	File       string
	StartLine  int
	EndLine    int
	ImageLayer string // SCA
}

// Finding é a unidade canônica. Todo adapter emite isto.
type Finding struct {
	Type           FindingType
	Scanner        string // "trivy"
	ScannerVersion string

	// Identidade (preenchida conforme Type)
	VulnID           string // CVE/GHSA já canônico
	PURL             string // pkg:type/ns/name@version
	CanonicalControl string // resultado do crosswalk (AVD/CWE/CIS/categoria)
	Resource         Resource
	Location         Location

	// Normalizado
	Severity Severity
	CVSS     float64 // 0 = ausente

	// Computados pelo pipeline
	CorrelationKey string
	Fingerprint    string // sha256(CorrelationKey)

	Title string
	Raw   map[string]any // payload original preservado
}

// MergedFinding é o resultado pós-correlação.
type MergedFinding struct {
	CorrelationKey string
	Type           FindingType
	Title          string
	Severity       Severity // agregada
	DetectedBy     []string // scanners distintos
	DetectionCount int
	Confidence     float64 // 0..1
	Members        []Finding
	Fingerprint    string
}
```

---

## 5. Interface de Adapter

```go
package adapter

import "context"

type Capability struct {
	Type    model.FindingType
	Targets []string // "image", "repo", "k8s-manifests"
}

type Adapter interface {
	Name() string
	Version(ctx context.Context) (string, error)
	Supports(target Target) bool
	// Run invoca a ferramenta e traduz a saída p/ findings canônicos.
	Run(ctx context.Context, target Target) ([]model.Finding, error)
}
```

Cada adapter encapsula: (a) como invocar a CLI da ferramenta (preferir output SARIF/JSON
nativo), (b) como mapear cada campo para `Finding`. Adapters NÃO calculam
`CorrelationKey` — isso é responsabilidade centralizada do Correlator, para garantir
consistência.

> **Teste de contrato obrigatório por adapter:** fixtures com a saída real de cada
> ferramenta, versionadas. Quando o scanner muda o formato, o teste quebra antes da prod.

---

## 6. Matriz de correlação

A chave muda por `Type`. **Não existe chave única.**

| Type | Chave de correlação | Normalização antes | Dificuldade |
|------|---------------------|--------------------|-------------|
| `VULN` | `vulnId⁺ + purl(name@version)` | resolver aliases; derivar PURL; ignorar layer/path na chave | 🟢 |
| `MISCONFIG` | `file + resourceAddr + canonicalControl` | crosswalk rule→control; normalizar path e resource address | 🔴 |
| `K8S_POSTURE` | `objectRef + container + canonicalControl` | crosswalk check→categoria; identidade do objeto | 🟡 |
| `IMG_HARDENING` | `cis-di-id` | — (quase sempre count=1) | 🟢 |

⁺ após o Alias Resolver.

Construção da chave (determinística):

```go
func BuildKey(f model.Finding) string {
	switch f.Type {
	case model.TypeVuln:
		return "VULN|" + f.VulnID + "|" + purlSemVersion(f.PURL)
	case model.TypeMisconfig:
		return "MISCONFIG|" + normPath(f.Location.File) + "|" +
			f.Resource.Address + "|" + f.CanonicalControl
	case model.TypeK8sPosture:
		return "K8S|" + objectRef(f.Resource) + "|" +
			f.Resource.Address /*container*/ + "|" + f.CanonicalControl
	case model.TypeImgHardening:
		return "IMGH|" + f.CanonicalControl
	default:
		return "OTHER|" + f.Scanner + "|" + f.Title
	}
}
```

> **Regra do não-match:** se `CanonicalControl` não pôde ser resolvido pelo crosswalk,
> o finding fica isolado (`DetectionCount=1`) e recebe flag `unmapped`. Nunca chutar match.

---

## 7. Alias Resolver (apenas `VULN`)

Problema: Grype pode reportar só `GHSA-xxxx`; Trivy só `CVE-…`. Sem resolução, o mesmo
bug vira dois findings e o consenso quebra.

```go
package alias

// Resolver mapeia qualquer ID de vuln para a forma canônica (preferir CVE).
type Resolver interface {
	Canonical(ctx context.Context, id string) (string, error)
}

// Estratégia em camadas, parando no primeiro acerto:
//  1. aliases já presentes no próprio finding (Grype: relatedVulnerabilities)
//  2. cache local (bolt/sqlite) — evita rede em re-scans
//  3. OSV.dev como árbitro (id -> aliases[]) ; escolher CVE se existir
type chainResolver struct {
	local *cache.Store
	osv   *osv.Client
}

func (r *chainResolver) Canonical(ctx context.Context, id string) (string, error) {
	if v, ok := r.local.Get(id); ok {
		return v, nil
	}
	aliases, err := r.osv.Aliases(ctx, id) // GET https://api.osv.dev/v1/vulns/{id}
	if err != nil {
		return id, nil // degrada graciosamente: usa o próprio id
	}
	canon := preferCVE(append(aliases, id)) // CVE > GHSA > demais
	r.local.Put(id, canon)
	return canon, nil
}
```

Regras:
- Priorizar `CVE-*`; cair para `GHSA-*`; senão manter o id original.
- Degradação graciosa: rede indisponível ⇒ usar o id como veio (nunca falhar o scan inteiro).
- Cache persistente para idempotência e velocidade em CI.

---

## 8. Crosswalk de exemplo (IaC — S3 e IAM)

Hub canônico escolhido: **AVD** (Aqua Vuln DB) — Trivy já fala AVD nativamente; basta
mapear Checkov→AVD e KICS→AVD. Onde não houver AVD, usar uma `category` semântica como
fallback (Estratégia B).

```yaml
# crosswalk/aws.yaml — formato: canonicalControl agrupa rule-ids equivalentes
- canonicalControl: AVD-AWS-0086        # S3 bucket public access block
  category: public-access
  cwe: CWE-732
  title: "S3 bucket sem bloqueio de acesso público"
  ids:
    checkov: [CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56]
    kics:    ["a2c... (S3 Bucket Allows Public ACL)"]
    trivy:   [AVD-AWS-0086]

- canonicalControl: AVD-AWS-0088        # S3 server-side encryption
  category: encryption
  cwe: CWE-311
  title: "S3 bucket sem criptografia em repouso"
  ids:
    checkov: [CKV_AWS_19]
    kics:    ["bd0... (S3 Bucket Without Encryption)"]
    trivy:   [AVD-AWS-0088]

- canonicalControl: AVD-AWS-0132        # S3 encryption with CMK
  category: encryption
  ids:
    checkov: [CKV_AWS_145]
    trivy:   [AVD-AWS-0132]

- canonicalControl: AVD-AWS-0089        # S3 access logging
  category: logging
  ids:
    checkov: [CKV_AWS_18]
    kics:    ["f87... (S3 Bucket Logging Disabled)"]
    trivy:   [AVD-AWS-0089]

- canonicalControl: AVD-AWS-0090        # S3 versioning
  category: data-protection
  ids:
    checkov: [CKV_AWS_21]
    trivy:   [AVD-AWS-0090]

- canonicalControl: AVD-AWS-0091        # S3 block public ACLs (account)
  category: public-access
  ids:
    checkov: [CKV_AWS_20]
    trivy:   [AVD-AWS-0091]

- canonicalControl: AVD-AWS-0057        # IAM policy wildcard actions
  category: iam
  cwe: CWE-269
  title: "Política IAM com ações curinga (*)"
  ids:
    checkov: [CKV_AWS_1, CKV_AWS_49]
    kics:    ["2f3... (IAM Policy Grants Full Admin)"]
    trivy:   [AVD-AWS-0057]

- canonicalControl: AVD-AWS-0345        # IAM no inline policies
  category: iam
  ids:
    checkov: [CKV_AWS_40]
    trivy:   [AVD-AWS-0345]

- canonicalControl: AVD-AWS-0123        # IAM password policy length
  category: iam
  ids:
    checkov: [CKV_AWS_10, CKV_AWS_11]
    trivy:   [AVD-AWS-0123]

- canonicalControl: AVD-AWS-0167        # IAM no user-attached policies
  category: iam
  ids:
    checkov: [CKV_AWS_273]
    trivy:   [AVD-AWS-0167]
```

> Os IDs do KICS são UUIDs de query; acima estão representados pelo nome para
> legibilidade — preencher o UUID real no arquivo final. Os números AVD devem ser
> conferidos contra o catálogo público AVD antes de uso em produção; aqui são
> ilustrativos do *formato*, não uma referência autoritativa.

Carregamento:

```go
type Crosswalk map[string]string // ruleID -> canonicalControl

func (c Crosswalk) Resolve(scanner, ruleID string) (control string, ok bool) {
	control, ok = c[scanner+"|"+ruleID]
	return
}
```

---

## 9. Motor de consenso

```go
func Merge(findings []model.Finding) []model.MergedFinding {
	groups := map[string][]model.Finding{}
	for _, f := range findings {
		groups[f.CorrelationKey] = append(groups[f.CorrelationKey], f)
	}
	out := make([]model.MergedFinding, 0, len(groups))
	for key, members := range groups {
		scanners := distinctScanners(members)
		m := model.MergedFinding{
			CorrelationKey: key,
			Type:           members[0].Type,
			Title:          members[0].Title,
			Severity:       aggregateSeverity(members), // max
			DetectedBy:     scanners,
			DetectionCount: len(scanners),
			Members:        members,
			Fingerprint:    sha256Hex(key),
			Confidence:     confidence(members, scanners),
		}
		out = append(out, m)
	}
	return out
}
```

### Fórmula de confiança

Contagem bruta **não** é confiança (3 linters na mesma linha ≠ forte). Pesa-se
diversidade de engine + severidade + confirmação autoritativa:

```go
func confidence(members []model.Finding, scanners []string) float64 {
	w1, w2, w3, w4 := 0.35, 0.25, 0.25, 0.15

	count := math.Log(1+float64(len(scanners))) / math.Log(5) // ~normalizado
	diversity := categoryDiversity(scanners)                  // SCA+IaC > 2x SCA, 0..1
	sev := severityWeight(members)                            // CRIT=1 .. INFO=0.1
	authoritative := 0.0
	if confirmedByNVDorOSV(members) {
		authoritative = 1.0
	}
	return clamp01(w1*count + w2*diversity + w3*sev + w4*authoritative)
}
```

| Sinal | Peso | Racional |
|-------|------|----------|
| nº scanners distintos (log) | 0.35 | mais detecções = mais sinal, com retorno decrescente |
| diversidade de categoria | 0.25 | duas engines diferentes valem mais que duas iguais |
| severidade normalizada | 0.25 | risco alto pesa mais na priorização |
| confirmado por NVD/OSV | 0.15 | fonte autoritativa reduz falso positivo |

---

## 10. Normalização de severidade

Tabela única para onde tudo converge:

| Origem | Mapeamento |
|--------|-----------|
| CVSS score | ≥9.0→CRITICAL, ≥7.0→HIGH, ≥4.0→MEDIUM, >0→LOW |
| Trivy / Grype label | já alinhado a CVSS — usar direto |
| Checkov / KICS / Kubescape enum | mapear enum próprio → {CRIT,HIGH,MED,LOW,INFO} |
| Dockle | FATAL→HIGH, WARN→MEDIUM, INFO→LOW |

`aggregateSeverity` = a maior severidade entre os membros do grupo.

---

## 11. Saída SARIF

Usar `partialFingerprints` para dedup portável (GitHub code scanning, DefectDojo
reconhecem o mesmo finding entre execuções → dedup temporal de graça):

```json
{
  "ruleId": "AVD-AWS-0086",
  "level": "error",
  "message": { "text": "S3 bucket sem bloqueio de acesso público" },
  "partialFingerprints": { "quorum/v1": "<sha256(correlationKey)>" },
  "properties": {
    "detectedBy": ["checkov", "trivy"],
    "detectionCount": 2,
    "confidence": 0.81
  },
  "locations": [ /* uma por membro, deduplicadas */ ]
}
```

JSON: dump direto de `[]MergedFinding`. XML: mesma estrutura serializada (p/ pipelines legados/JUnit-like).

---

## 12. CLI & Docker

```
quorum scan <target> \
  --type image|repo|k8s \
  --scanners trivy,grype,checkov,kics,dockle,kubescape \
  --format sarif|json|xml \
  --output report.sarif \
  --fail-on high \           # exit code != 0 p/ gating em CI
  --crosswalk ./crosswalk/   # diretório de mapeamentos customizados
```

Docker — evitar a imagem-monstro de 4 GB:
- **`quorum:full`** — todas as ferramentas embutidas (conveniência, CI self-contained).
- **`quorum:slim`** — só o orquestrador; chama scanners já presentes no PATH.
- Considerar imagens por perfil (`:sca`, `:iac`, `:k8s`) se o tamanho incomodar.

Segurança da própria cadeia: pinar cada ferramenta por **digest/SHA**, não por tag
mutável, e validar checksum no build (houve incidente de supply chain em Actions de
scanners em 2026).

---

## 13. Roadmap

| Fase | Entrega | Critério de pronto |
|------|---------|--------------------|
| **MVP** | Trivy + Grype (SCA), consenso por `vulnId+purl`, SARIF+JSON, Docker `:full` | dois scanners concordam num CVE e o relatório mostra `detectionCount:2` |
| **v0.2** | Checkov + KICS (IaC), crosswalk top-50 S3/IAM, Estratégia B de fallback | misconfig de S3 correlacionado entre as duas engines |
| **v0.3** | Kubescape + Polaris (K8s), Dockle, XML | postura k8s com consenso |
| **v1.0** | Conftest/OPA como camada opcional, cache de aliases persistente, perfis de imagem | policy-as-code do usuário integrada ao mesmo relatório |
| **futuro** | módulo runtime separado (Falco *ou* Tetragon), OpenSCAP host | produto à parte, modelo de stream |

---

## 14. Riscos e mitigações

| Risco | Mitigação |
|-------|-----------|
| Scanners mudam formato de saída | testes de contrato com fixtures versionadas por adapter |
| Crosswalk vira dívida de manutenção | começar pelo top-50 controles (cobrem maioria dos findings); fallback por categoria |
| Falso merge esconde risco | regra "na dúvida, não una"; flag `unmapped` |
| Licenças das ferramentas embutidas | auditar licença de cada binário distribuído na imagem |
| Imagem gigante | perfis de imagem + modo `:slim` |
| "0 vulns" = falsa sensação de segurança | deixar explícito no relatório e na doc |

---

*Os números AVD/CKV e UUIDs de KICS neste documento são ilustrativos do formato e
devem ser conferidos contra os catálogos oficiais antes de irem para produção.*
