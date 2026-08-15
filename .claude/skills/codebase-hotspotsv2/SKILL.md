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
* **Risky processing**: A risky processing is a processing that uses the information to perform any of the actions listed in the **`Risky processing`** section of this file, without performing *data validation* against the information prior to use.

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
  * If no dedicated agent is available then you use your knowledge to identify if the processing performed is risky from a security perspective based on the **`Risky processing`** section of this file and produce **the same output format defined in the `Output rules` section of `.claude/skills/codebase-hotspotsv2/shared-rules.md`**.
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
* Save the assembled output to a file named `Findings-$DATE.md` where `$DATE` is today's date in `YYYY-MM-DD` format, written to the current working directory using the `Write` tool.

### Step 4: Generation of the test class or script

Using the findings collected in Step 3, generate a single test class or script that contains one test per eligible finding, then save it to the current working directory.

**Eligibility rule**: include a finding only when **both** conditions hold:

- Confidence is **YES**.
- The sink type is testable without external I/O or network access: SQL/NoSQL injection, weak RNG, ReDoS, hash input ambiguity, prototype pollution, CSV/formula injection.

Exclude: SSRF, path traversal, command injection, XXE, open redirect, deserialization, XSS, CORS, zip-slip, uncontrolled resource allocation — these require live I/O, a running server, or filesystem state that makes a self-contained unit test unreliable.

**Framework detection**: inspect the project's dependency manifests and existing test files (e.g. `pom.xml`, `build.gradle`, `package.json`, `requirements.txt`, `go.mod`, `*.test.*`, `*Test.*`, `spec/**`) to identify the test framework in use. Use the first match from this priority list:

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

If no framework can be detected, default to the idiomatic built-in test mechanism for the detected language.

**Output rules for the test file**:

- All tests go into a **single** class or script; do not create one file per finding.
- Name the file `SecurityFindingsTest-$DATE.<ext>` where `$DATE` is today's date in `YYYY-MM-DD` format and `<ext>` matches the project language.
- Each test method is named after its finding identifier and sink type, e.g. `test_finding_3_sqli` / `testFinding3Sqli`.
- Each test must contain a header comment block with the following fields, so the test file and the markdown report cross-reference each other:
  - `Finding`: the finding identifier number (e.g. `3`).
  - `Report`: the filename of the markdown findings file generated in the same run (e.g. `Findings-2026-08-12.md`).
  - `Location`: the processing location from the finding (e.g. `src/dao/UserDao.java:87`).
  - `Category`: the sink type / CWE (e.g. `SQL injection — CWE-89`).
  Use the comment syntax of the target language (`//`, `#`, `--`, etc.). Keep the block compact — four lines maximum.
- Each test asserts the **vulnerable behavior** — it must **pass** (green) on the unpatched code, confirming the issue is present. Do not assert the fixed behavior; the test's purpose is detection, not regression.
- Keep tests minimal and self-contained: inline all fixtures, avoid shared state between tests, import only what the framework provides plus the class under test.
- If no eligible findings exist, skip the file and note this in the console output.

## Dedicated agents registry

Use this table during Step 2 to identify which agent to invoke. Match the sink type detected
in the taint path against the **Vulnerability class** column. The **Source** column records
the reference material used to design the agent's detection rules — consult it when the
agent's rules need to be updated or a new version of the upstream skill is available.

| Agent path | Vulnerability class | Source |
|---|---|---|
| `agent-redos/` | ReDoS — user-controlled regex pattern or catastrophic static pattern matched against user input | Internal analysis |
| `agent-hash-input-ambiguity/` | Hash input ambiguity — multiple variable-length values concatenated without unambiguous separator before hashing | [secure-message-digest-generation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-message-digest-generation/SKILL.md) |
| `agent-log-forging/` | Log injection / log forging (newline injection) and log viewer XSS (HTML/JS injection into log entries rendered in a web UI) | [secure-log-entry-generation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-log-entry-generation/SKILL.md) |
| `agent-archive-decompression/` | Zip-slip, decompression bomb, symbolic/hard link attacks in archive extraction | [secure-archive-decompression](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-archive-decompression/SKILL.md) |
| `agent-relative-url-validation/` | Open redirect via insufficient relative URL validation (missing recursive decoding, scheme rejection, protocol-relative URL rejection, path traversal rejection, allowed character check) | [secure-relative-url-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-relative-url-validation/SKILL.md) |
| `agent-csv-injection/` | CSV / formula injection — user-controlled values written to CSV output without single-quote prefix guard on formula-trigger characters | [secure-csv-generation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-csv-generation/SKILL.md) |
| `agent-email-validation/` | Insufficient email address validation — missing RFC parsing, encoded-word/comment/Punycode/UUCP/address-literal/source-route/percent-hack rejection, length limits, CRLF prevention, single-label domain rejection, quoted local-part rejection | [secure-email-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-email-validation/SKILL.md) |
| `agent-image-validation/` | Insufficient image file validation — missing magic-number type verification, trailing-content (polyglot/concatenation) detection, and pixel stripping | [secure-image-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-image-validation/SKILL.md) |
| `agent-pdf-validation/` | Insufficient PDF file validation — missing magic-number verification, file size limit, embedded attachment detection, XFA form detection, JavaScript detection across all four document locations, forbidden action detection (Launch/GoToR/ImportData) with recursive Next-chain traversal, and trailing-content detection after the final %%EOF | [secure-pdf-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-pdf-validation/SKILL.md) |

## Inline detection guidance for file types without a dedicated agent

When no dedicated agent exists for a file type encountered during Step 2, apply your general
knowledge and the rules in `.claude/skills/codebase-hotspotsv2/shared-rules.md`. For the file types listed below, also apply
the additional checks described here — these are non-obvious patterns that model knowledge
alone tends to miss.

### Microsoft Word / DOCX files

DOCX is a ZIP archive containing XML parts. When user-supplied DOCX files are processed
without a dedicated agent, apply the archive decompression agent (`agent-archive-decompression/`)
for ZIP-level checks (size limits, zip-slip, zip-bomb), then additionally check for the
following two Word-specific risky patterns that models consistently miss:

**DDE field injection** (CWE-20, severity MEDIUM):
- Open the `word/document.xml` part inside the ZIP.
- Scan its content for the strings `DDEAUTO` or ` DDE ` (with surrounding whitespace, to
  avoid matching unrelated substrings).
- A match means the document contains a Dynamic Data Exchange field that executes an
  arbitrary system command when opened in Microsoft Word with field updates enabled.
- Report as a finding if the uploaded file is stored or forwarded without this scan.
- Effective guard: reject the file if either string is found; no sanitisation alternative exists.

**OLE / ActiveX embedded objects** (CWE-434, severity HIGH):
- Open the `word/_rels/document.xml.rels` relationship file inside the ZIP.
- Scan for relationship entries whose `Type` URI contains `oleObject` or `control`
  (case-insensitive). Example:
  `Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"`
- A match means the document embeds an OLE object or ActiveX control that can execute
  arbitrary code when the document is opened.
- Report as a finding if the uploaded file is stored or forwarded without this scan.
- Effective guard: reject the file if any such relationship is found.

Source: [secure-microsoft-word-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-microsoft-word-validation/SKILL.md)

### Microsoft Excel / XLSX files

XLSX is a ZIP archive containing XML parts (Office Open XML). When user-supplied XLSX files
are processed without a dedicated agent, apply the archive decompression agent
(`agent-archive-decompression/`) for ZIP-level checks (size limits, zip-slip, zip-bomb),
then additionally check for the following three Excel-specific risky patterns that models
consistently miss:

**VBA macro detection** (CWE-434, severity HIGH):
- Scan the ZIP entry list for the presence of `vbaProject.bin`.
- A match means the workbook contains compiled VBA macros that execute arbitrary code when
  the file is opened with macros enabled.
- Report as a finding if the uploaded file is stored or forwarded without this scan.
- Effective guard: reject the file if `vbaProject.bin` is present; no sanitisation alternative exists.

**External data connections** (CWE-611 / SSRF-adjacent, severity MEDIUM):
- Scan the ZIP entry list for the presence of `xl/connections.xml`.
- A match means the workbook contains external data connection definitions (database queries,
  web queries, OData feeds) that may trigger outbound network requests or credential exposure
  when the file is opened.
- Report as a finding if the uploaded file is stored or forwarded without this scan.
- Effective guard: reject the file if `xl/connections.xml` is present.

**External workbook links** (CWE-20, severity MEDIUM):
- Scan the ZIP entry list for any entry whose path begins with `xl/externalLinks/`.
- A match means the workbook references external workbook files. These links can point to
  attacker-controlled UNC paths (`\\attacker\share\file.xlsx`), triggering NTLM credential
  capture when the file is opened on Windows, or can be used to exfiltrate data via formula
  evaluation against a remote workbook.
- Report as a finding if the uploaded file is stored or forwarded without this scan.
- Effective guard: reject the file if any `xl/externalLinks/` entry is present.

Note: OLE/ActiveX embedded objects use the same detection pattern as DOCX — scan the
relationship file `xl/_rels/workbook.xml.rels` for `Type` URIs containing `oleObject` or
`control` (case-insensitive), severity HIGH (CWE-434).

Source: [secure-microsoft-excel-validation](https://raw.githubusercontent.com/righettod/code-assistant-skills-security-utils/refs/heads/main/.claude/skills/secure-microsoft-excel-validation/SKILL.md)

## Risky processing

The following processing must be considered **risky** from a security perspective. Use this
list during Step 2 when no dedicated agent is available for the sink type detected.

- Input information not validated and used within an XML/XSD parser (XXE).
- Input information not validated and used to create a message written into a logging function (log injection/forging).
- Input information not validated and used to perform a network request (SSRF, including DNS-rebinding and redirect-based variants).
- Input information not validated and used to create an HTTP response (response splitting, header injection, open redirect via `Location`/`Set-Cookie`).
- Input information not validated and used to render HTML or write to the DOM — `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, unescaped template output, or equivalent — (XSS).
- Input information not validated and used to generate Comma-Separated Values (CSV) content (CSV/formula injection).
- Input information not validated and used for authentication decisions (authentication bypass).
- Input information not validated and used for authorization decisions (including IDOR / object reference, mass assignment / object binding).
- Input information not validated and used for Cross-Origin Resource Sharing (CORS) decisions (CORS validation bypass).
- Input information not validated and used to decompress an archive (zip-slip, decompression bomb).
- Input information not validated and used to access a filesystem (path traversal, file upload with input-controlled filename/extension/content-type).
- Input information not validated and used for a shell or process execution (command injection, tainted format string).
- Input information not validated and used to create a regular expression that is evaluated (ReDoS).
- Input information not validated and used to construct a SQL/NoSQL/ORM/LDAP/XPath/GraphQL query (injection).
- Input information not validated and used in a template engine (server-side template injection).
- Input information not validated and passed to a dynamic code evaluation function such as `eval()`, `Function()`, `exec()`, `compile()`, or equivalent (code injection).
- Input information not validated and used for a deserialization processing using another format than JSON (insecure deserialization).
- Input information not validated and used to merge into or assign properties of an object in a way that can overwrite inherited properties such as `__proto__`, `constructor`, or `prototype` — e.g. `_.merge`, `Object.assign`, recursive merge with user-controlled keys — (prototype pollution).
- Input information not validated and used to generate random values for a security-sensitive purpose (weak RNG, e.g. a predictable or input-derived seed, or a non-CSPRNG such as `Math.random`).
- Input information not validated and used to compute a cryptographic digest without a values separator (hash input ambiguity).
- Input information not validated and used to control a resource allocation size, loop iteration count, or similar bound — resulting in memory exhaustion, CPU exhaustion, or excessive I/O — (uncontrolled resource allocation / DoS).
