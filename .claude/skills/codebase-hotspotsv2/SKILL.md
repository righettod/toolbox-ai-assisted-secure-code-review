---
description: Generate a list of locations in the codebase where risky processing is performed from a security perspective.
argument-hint: <entry-point-or-package>
allowed-tools: Read, Glob, Grep, Bash, TaskCreate, Write
disable-model-invocation: true
---

Analyse all the source file located in the location specified by `$ARGUMENTS` in order to identify where risky processing is performed from a security perspective.

## Scope

If an argument is provided in `$ARGUMENTS`, restrict the analysis to that entry point or package. Otherwise, analyze all entry points in the codebase.

## Definition

* **Entry point**: Is where information enters the codebase: `main()` functions, HTTP route definitions, CLI command handlers, message/queue consumers, exported public API functions.
* **Source**: Is the entry point form which the information start is journey into the codebase.
* **Sink**: Is the final location where the information is processed or exit the codebase.
* **Data validation**: Input information is considered **validated** when there is **effective** check for the specific sink it reaches. The **effectiveness** is described in the section **effective validation reference** of the file  `.claude/skills/codebase-hotspotsv2/shared-rules.md`.
* **Risky processing**: A risky processing is a processing that uses the information to perform any of the actions listed in the **`Risky processing`** section of the file `.claude/skills/codebase-hotspotsv2/agent-generic/SKILL.md`, without performing *data validation* against the information prior to use.

## Methodology

You must follow all these steps in the defined sequence order.

### Step 1: Cartography of all the entry points

* You **enumerate all entry points** using Glob/Grep (route definitions, `main()`, CLI handlers, queue consumers, exported public API functions) present into the codebase.
* You must restrict codebase to `$ARGUMENTS` if provided.

### Step 2: Analysis of every entry points

* An agent is dedicated to single class of vulnerability.
* You must analyze all the identified entry points.
* The analyze of an every entry point consist to follow the information from its **source** location to its **sink** location.
* You trace the data flow, if during the flow the information reach the sink without being **validated** then you must:
  * Identify the corresponding dedicated agent using the **Dedicated agents registry** section below, then spawn it via `TaskCreate`. Each `TaskCreate` prompt must:
    1. Instruct the subagent to read the agent SKILL.md: `"Read the file .claude/skills/codebase-hotspotsv2/<agent-path>/SKILL.md and apply its instructions to the following source code."` (replace `<agent-path>` with the path from the registry).
    2. Append the full source code of every function involved in the taint path from source to sink.
    3. Declare: `"You may use: Read, Glob, Grep."`.
  * If no dedicated agent is available, spawn the generic agent (`agent-generic/`) via `TaskCreate` using the same 3-point prompt template, replacing `<agent-path>` with `agent-generic/`. Do not analyse the sink inline — always delegate to the generic agent so all analysis runs in parallel.
* An agent goal is to identify, based on the source code provided in its prompt, every risky processing performed from a security perspective.
* An agent output format is defined in the section `Output rules` of the file `.claude/skills/codebase-hotspotsv2/shared-rules.md`.

### Step 3: Gather feedback from all agents

* Wait for all `TaskCreate` subagents spawned in Step 2 to complete before proceeding.
* Collect the output of every subagent and apply the following transformations to produce the **findings file**:
  * **Renumber globally**: agents each number findings starting at 1; assign a single sequence of identifiers (1, 2, 3, …) across all agent outputs in the order they are processed.
  * **Deduplicate**: collapse findings with the same (entry point, sink location) pair produced by different agents or runs into a single finding.
  * **Group by entry point**: order findings by entry point, then within each group by Severity (CRITICAL first) then Confidence (YES first).
  * **Build the summary table**: count findings per entry point per severity level; include entry points with zero findings (confirming they were analysed). Follow the summary table format defined in the `Output rules` section of `.claude/skills/codebase-hotspotsv2/shared-rules.md`.
  * **Format each finding** using the structure defined in the `Output rules` section of `.claude/skills/codebase-hotspotsv2/shared-rules.md`.
* Save the assembled output to a file named `SecurityFindings-$DATE.md` where `$DATE` is today's date in `YYYY-MM-DD` format, written to the current working directory using the `Write` tool.

### Step 4: Generation of the sandbox validation script

Using the findings collected in Step 3, generate a single sandbox script or test class that
contains one test per finding with Confidence **YES** or **PARTIAL**, then save it to the
current working directory.

**Purpose**: the generated file is a **manual validation sandbox**, not an automated CI
test. Its goal is to let the reviewer reproduce the vulnerable condition, observe the
behaviour, and confirm exploitability by running the code locally. Tests do not need to be
self-contained or free of external I/O — they should be as realistic as needed to demonstrate
the finding.

**Eligibility rule**: include every finding where Confidence is **YES** or **PARTIAL**.
Exclude only findings where Confidence is **NO**.

**Framework detection**: inspect the project's dependency manifests and existing test files
(e.g. `pom.xml`, `build.gradle`, `package.json`, `requirements.txt`, `go.mod`, `*.test.*`,
`*Test.*`, `spec/**`) to identify the test framework in use. Use the first match from this
priority list:

| Language | Framework (priority order) |
| --- | --- |
| Java / Kotlin | JUnit 5, JUnit 4, TestNG |
| JavaScript / TypeScript | Jest, Mocha, Vitest |
| Python | pytest, unittest |
| Go | `testing` (standard library) |
| C# | xUnit, NUnit, MSTest |
| Ruby | RSpec, Minitest |
| PHP | PHPUnit |
| Rust | `#[test]` (standard library) |

If no framework can be detected, default to the idiomatic built-in test mechanism for the
detected language.

**Output rules for the sandbox file**:

- All tests go into a **single** class or script; do not create one file per finding.
- Name the file `SecurityFindingsTest-$DATE.<ext>` where `$DATE` is today's date in
  `YYYY-MM-DD` format and `<ext>` matches the project language.
- Each test method is named after its finding identifier and sink type,
  e.g. `test_finding_3_sqli` / `testFinding3Sqli`.
- Each test must contain a header comment block with the following fields, so the sandbox
  file and the markdown report cross-reference each other:
  - `Finding`: the finding identifier number (e.g. `3`).
  - `Report`: the filename of the markdown findings file generated in the same run
    (e.g. `SecurityFindings-2026-08-12.md`).
  - `Location`: the processing location from the finding (e.g. `src/dao/UserDao.java:87`).
  - `Category`: the sink type / CWE (e.g. `SQL injection — CWE-89`).
  Use the comment syntax of the target language (`//`, `#`, `--`, etc.). Keep the block
  compact — four lines maximum.
- Each test reproduces the **vulnerable behaviour** on the unpatched code, confirming the
  condition is present and observable. For findings that require external state (a running
  server, a file, a database, a network endpoint), include the setup steps as inline
  comments or `@BeforeEach` / fixture blocks so the reviewer knows exactly what to
  prepare before running the test.
- For Confidence **PARTIAL** findings, add a comment flagging the uncertainty:
  `// PARTIAL — manual inspection required: <reason from finding>`.
- Keep each test focused on a single finding; avoid shared state between tests.

## Dedicated agents registry

Use this table during Step 2 to identify which agent to invoke. Match the sink type detected
in the taint path against the **Vulnerability class** column. The **Source** column records
the reference material used to design the agent's detection rules — consult it when the
agent's rules need to be updated or a new version of the upstream skill is available.

| Agent path | Vulnerability class | Source |
|---|---|---|
| `agent-redos/` | ReDoS — user-controlled regex pattern or catastrophic static pattern matched against user input | Internal analysis — model knowledge |
| `agent-hash-input-ambiguity/` | Hash input ambiguity — multiple variable-length values concatenated without unambiguous separator before hashing | [secure-message-digest-generation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-message-digest-generation/SKILL.md) |
| `agent-log-forging/` | Log injection / log forging (newline injection) and log viewer XSS (HTML/JS injection into log entries rendered in a web UI) | [secure-log-entry-generation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-log-entry-generation/SKILL.md) |
| `agent-archive-decompression/` | Zip-slip, decompression bomb, symbolic/hard link attacks in archive extraction | [secure-archive-decompression](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-archive-decompression/SKILL.md) |
| `agent-relative-url-validation/` | Open redirect via insufficient relative URL validation (missing recursive decoding, scheme rejection, protocol-relative URL rejection, path traversal rejection, allowed character check) | [secure-relative-url-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-relative-url-validation/SKILL.md) |
| `agent-csv-injection/` | CSV / formula injection — user-controlled values written to CSV output without single-quote prefix guard on formula-trigger characters | [secure-csv-generation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-csv-generation/SKILL.md) |
| `agent-email-validation/` | Insufficient email address validation — missing RFC parsing, encoded-word/comment/Punycode/UUCP/address-literal/source-route/percent-hack rejection, length limits, CRLF prevention, single-label domain rejection, quoted local-part rejection | [secure-email-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-email-validation/SKILL.md) |
| `agent-image-validation/` | Insufficient image file validation — missing magic-number type verification, trailing-content (polyglot/concatenation) detection, and pixel stripping | [secure-image-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-image-validation/SKILL.md) |
| `agent-pdf-validation/` | Insufficient PDF file validation — missing magic-number verification, file size limit, embedded attachment detection, XFA form detection, JavaScript detection across all four document locations, forbidden action detection (Launch/GoToR/ImportData) with recursive Next-chain traversal, and trailing-content detection after the final %%EOF | [secure-pdf-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-pdf-validation/SKILL.md) |
| `agent-docx-validation/` | Insufficient Microsoft Word / DOCX file validation — DDE field injection detection and OLE/ActiveX embedded object detection (ZIP-level checks delegated to agent-archive-decompression) | [secure-microsoft-word-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-microsoft-word-validation/SKILL.md) |
| `agent-xlsx-validation/` | Insufficient Microsoft Excel / XLSX file validation — VBA macro detection, OLE/ActiveX embedded object detection, external data connection detection, and external workbook link detection (ZIP-level checks delegated to agent-archive-decompression) | [secure-microsoft-excel-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-microsoft-excel-validation/SKILL.md) |
| `agent-generic/` | Fallback for all sink types not covered by a dedicated agent above — XXE, SSRF, XSS, command injection, SQL/NoSQL/ORM/LDAP/XPath/GraphQL injection, path traversal, authentication bypass, authorization bypass / IDOR, CORS bypass, server-side template injection, code injection, insecure deserialization, prototype pollution, weak RNG, uncontrolled resource allocation | Internal — rules defined in [agent-generic/SKILL.md#risky-processing](agent-generic/SKILL.md#risky-processing) |


