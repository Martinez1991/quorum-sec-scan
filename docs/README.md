# Documentação do Quorum

Bem-vindo à documentação **enterprise** do **Quorum** (`quorum-sec-scan`) — uma ferramenta de
**consensus security scanning** entregue como **CLI + imagens Docker**. Esta pasta descreve o produto
**AS-IS na versão v0.2.3** (branch `main` como fonte de verdade), em português (pt-BR).

> 📖 **O índice mestre completo é [`00-index.md`](00-index.md)** — lá estão as trilhas de leitura por
> papel, o **Registro de Premissas** (A-01…A-21), o **Registro de Lacunas** (G-01…G-19), as
> **Perguntas em aberto** para stakeholders e os metadados. Este `README.md` é apenas o atalho que o
> GitHub renderiza ao abrir a pasta `docs/`.

## Escopo (importante)

O Quorum é **CLI/Docker only**. Os domínios abaixo são **N/A por arquitetura** e estão documentados
como tal (com justificativa e, quando útil, "proposta futura" separada):

| Domínio | Status | Onde |
|---------|--------|------|
| Frontend web / UI | **N/A** (UX é terminal) | [08-frontend](08-frontend.md) |
| Banco de dados relacional | **N/A** (só caches de arquivo reconstruíveis) | [07-persistencia-e-artefatos](07-persistencia-e-artefatos.md) |
| API REST HTTP | **N/A** (interface é a CLI + imagem) | [06-interfaces-cli-e-formatos](06-interfaces-cli-e-formatos.md) |
| Autenticação / contas | **N/A** | [12-seguranca](12-seguranca.md) |
| IA / LLM / ML | **N/A** (OSV.dev é lookup determinístico) | [13-ia](13-ia.md) |

## Sumário

| # | Documento | Descrição |
|---|-----------|-----------|
| 00 | [Índice mestre](00-index.md) | Landing, trilhas, premissas, lacunas, perguntas, metadados. |
| 01 | [Visão Geral](01-visao-geral.md) | O que é o Quorum, escopo, princípios e fronteiras N/A. |
| 02 | [Requisitos Funcionais](02-requisitos-funcionais.md) | Comandos, flags, exit codes, scanners e matriz de targets. |
| 03 | [Requisitos Não Funcionais](03-requisitos-nao-funcionais.md) | Performance, SLO/SLI, supply chain, conformidade. |
| 04 | [Arquitetura](04-arquitetura.md) | Pipeline, pacotes `internal/*`, fan-out e diagrama de sequência. |
| 05 | [Modelagem de Dados](05-modelo-de-dados.md) | `model.Finding`, MergedFinding, fingerprints, JSON/XML. |
| 06 | [Interfaces (CLI) e Formatos](06-interfaces-cli-e-formatos.md) | Contrato da CLI, `list-scanners`, SARIF/JSON/XML. |
| 07 | [Persistência e Artefatos](07-persistencia-e-artefatos.md) | Cache de aliases, Grype DB, crosswalk, baseline, relatórios. |
| 08 | [Frontend / Terminal](08-frontend.md) | UX de terminal: stdout/stderr, summary, cor/TTY. |
| 09 | [Backend](09-backend.md) | `cmd/quorum` + `internal/*` como backend CLI. |
| 10 | [Infraestrutura](10-infraestrutura.md) | Build, distribuição GHCR (`:full`/`:slim`), cosign + SLSA. |
| 11 | [DevOps](11-devops.md) | Workflows CI/e2e/release, fluxo de PR, tag móvel `v0`. |
| 12 | [Segurança](12-seguranca.md) | Modelo de ameaças, riscos, supply chain, frameworks. |
| 13 | [IA](13-ia.md) | Ausência de IA/LLM/ML (N/A + proposta futura). |
| 14 | [Observabilidade](14-observabilidade.md) | Logs `[quorum]`, campos SARIF/JSON, telemetria proposta. |
| 15 | [Testes](15-testes.md) | Estratégia, contract tests, e2e de consenso, cobertura. |
| 16 | [Roadmap](16-roadmap.md) | Fases V1/V2/V3 e gates de release SemVer. |
| 17 | [Backlog](17-backlog.md) | Epics/Stories priorizados (MoSCoW, story points). |
| 18 | [Matriz de Riscos](18-riscos.md) | Riscos técnicos/supply-chain/operacionais. |
| 19 | [Custos](19-custos.md) | Actions/GHCR/headcount, licenças, câmbio. |
| 20 | [Melhorias](20-melhorias.md) | Oportunidades priorizadas (impacto × esforço). |
| 99 | [Checklists](99-checklists.md) | Adoção, QA, segurança, deploy e produção. |

## Trilhas rápidas por papel

- **Primeiro contato:** [01](01-visao-geral.md) → [06](06-interfaces-cli-e-formatos.md) → [99](99-checklists.md)
- **Como funciona:** [04](04-arquitetura.md) → [05](05-modelo-de-dados.md) → [09](09-backend.md)
- **Adotar em pipeline:** [06](06-interfaces-cli-e-formatos.md) → [10](10-infraestrutura.md) → [11](11-devops.md) → [14](14-observabilidade.md)
- **Postura de segurança:** [12](12-seguranca.md) → [18](18-riscos.md) → [13](13-ia.md)
- **Planejar evolução:** [16](16-roadmap.md) → [17](17-backlog.md) → [20](20-melhorias.md)

---

Convenção: arquivos seguem `NN-arquivo.md` (`00` índice, `99` checklists); cross-links são relativos
dentro de `docs/`. Documentação descritiva do produto na v0.2.3 — para o produto em si, veja o
[README principal](https://github.com/Martinez1991/quorum-sec-scan/blob/main/README.md).
