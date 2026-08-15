# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This repository is a toolbox of Claude Code **skills** (stored as `SKILL.md` files under `.claude/skills/`) designed to assist with AI-aided secure code reviews. The skills are the deliverable — there is no application to build or test suite to run.

## Skills overview

All skills live in `.claude/skills/<skill-name>/SKILL.md`. They use Claude Code's skill format with frontmatter (`description`, `argument-hint`, `allowed-tools`, `disable-model-invocation`).

| Skill | Invocation | Purpose |
| --- | --- | --- |
| `codebase-overview` | `/codebase-overview [path]` | Generates a Mermaid flowchart mapping entry points → landing points (custom code or third-party libs), colored by risk tier |
| `codebase-hotspotsv1` | `/codebase-hotspotsv1 [path]` | Taint-traces each entry point to risky sinks; outputs a structured findings report saved as `Findings-YYYY-MM-DD.md` and a companion test file `SecurityFindingsTest-YYYY-MM-DD.<ext>` |
| `codebase-hotspotsv2` | `/codebase-hotspotsv2 [path]` | Evolution of v1: spawns dedicated agents per vulnerability class to enforce complete, class-specific detection rules that a general model tends to miss or apply inconsistently; same output format as v1 |
| `codebase-semgrep-findings-review` | `/codebase-semgrep-findings-review <sarif-or-json> [source-root] [CONFIRMED\|PARTIAL]` | Reads a Semgrep SARIF/JSON output, applies semantic reasoning to each finding, and saves a filtered report as `Semgrep-Review-YYYY-MM-DD.md` |

## Recommended review workflow

Apply these steps **at the root of the codebase under review**, starting a fresh Claude Code session for each step to keep contexts isolated:

1. Run `/codebase-overview` for a global visual map of risky sinks.
2. Scan the codebase with Semgrep (via [toolbox-codescan](https://github.com/righettod/toolbox-codescan)).
3. Run `/codebase-semgrep-findings-review` on the Semgrep output to filter false positives.
4. Run `/codebase-hotspotsv2` (preferred) or `/codebase-hotspotsv1` to trace entry-point → sink paths.
5. Manually validate the combined output of steps 3 and 4.

A **module-by-module** approach is recommended for large codebases — run steps 2–5 per module from that module's root folder.

## Installing skills into a target project

Copy `.claude/skills/` into the target project's `.claude/` folder, or use the one-liner:

```powershell
irm https://raw.githubusercontent.com/righettod/toolbox-ai-assisted-secure-code-review/main/install.ps1 | iex
```

## Skill authoring conventions

- `disable-model-invocation: true` is set on all skills — they run as pure prompt instructions, not model calls.
- Skills use `TaskCreate` to spawn subagents for parallelizing analysis across large entry-point sets.
- Output files are always written to the **current working directory** (the codebase root) using the `Write` tool.
- Mermaid diagrams must pass the validation checklist in `codebase-overview/SKILL.md` before being emitted (unique IDs, quoted labels, no bare `-->` inside labels, node count ≤ 40).
- Risk coloring: `classDef high fill:#fdd,stroke:#c00,color:#900` (red) for code-execution/direct-compromise sinks; `classDef med fill:#ffe9c7,stroke:#e08e00` (amber) for auth/crypto/session sinks.
- `codebase-hotspotsv1` generates a companion test file (`SecurityFindingsTest-YYYY-MM-DD.<ext>`) alongside the markdown report. Only Confidence: YES findings with self-contained sink types (SQL injection, weak RNG, ReDoS, hash input ambiguity, prototype pollution, CSV injection) get a test. Each test method carries a header comment cross-referencing its finding number, the markdown report filename, the source location, and the CWE — so the two artifacts are mutually traceable. Tests assert the **vulnerable behavior** (green on unpatched code).
- `codebase-hotspotsv2` uses a two-tier detection architecture:
  - **Dedicated agents** (`.claude/skills/codebase-hotspotsv2/agent-*/SKILL.md`) — spawned via `TaskCreate` for specific vulnerability classes: ReDoS, hash input ambiguity, log forging/viewer XSS, archive decompression, open redirect, CSV injection, email validation, image validation, PDF validation, DOCX validation (DDE + OLE/ActiveX), XLSX validation (VBA macros + OLE/ActiveX + external connections + external links). Each agent enforces a complete, class-specific rule set.
  - **Generic agent** (`agent-generic/`) — fallback spawned via `TaskCreate` for all sink types not covered by a dedicated agent (XXE, SSRF, XSS, command injection, SQL injection, path traversal, authentication/authorization bypass, CORS, template injection, code injection, deserialization, prototype pollution, weak RNG, uncontrolled resource allocation). Serves as the single authoritative source for the Risky processing list.
  - The shared output contract (Confidence, Severity, finding format) lives in `.claude/skills/codebase-hotspotsv2/shared-rules.md` and is referenced by all agents and the orchestrator.
  - All analysis runs in parallel via `TaskCreate`; the orchestrator is a pure dispatcher and aggregator — it never analyses inline.
  - When adding a new weakness: always create a dedicated agent. The orchestrator contains no detection logic.
  - The companion `SecurityFindingsTest-YYYY-MM-DD.<ext>` file is a **manual validation sandbox**, not an automated CI test. It covers all Confidence YES and PARTIAL findings (including those requiring external state such as a running server, a file, or a database) and is designed to let the reviewer reproduce the vulnerable condition locally and confirm exploitability. Setup prerequisites are documented inline as comments or fixture blocks.
