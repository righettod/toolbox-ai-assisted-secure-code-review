
# Definition

* **Entry point**: Is where information enters the codebase: `main()` functions, HTTP route
  definitions, CLI command handlers, message/queue consumers, exported public API functions.
* **Source**: Is the user-controlled value that enters the codebase at an entry point — for
  example an HTTP request parameter, request body field, HTTP header, path segment, CLI
  argument, environment variable supplied at runtime by an external caller, or message/queue
  payload. The following are **never** sources, even if they flow to a risky sink:
  server-side configuration values (e.g. `app.config`, `application.properties`,
  `appsettings.json`), hardcoded constants, values loaded from a secrets manager at startup,
  and data fetched from a trusted internal store with no user influence over the fetched
  value. If the only values reaching a sink originate from this list, return: `NO FINDINGS`.
* **Sink**: Is the final location where the information is processed or exits the codebase.
* **Data validation**: Input information is considered **validated** when there is an
  **effective** check for the specific sink it reaches. Effectiveness is defined in the
  **Effective validation reference** section of this file.
* **Risky processing**: A processing that uses user-controlled information to perform any
  action listed in the `## Risky processing` section of
  `.claude/skills/codebase-hotspotsv2/agent-generic/SKILL.md`, without performing data
  validation against that information prior to use.

# Confidence

Use the following value for the **Confidence** indicator:

- **YES**: You traced the full taint path in code and can provide a proof-of-concept input that reaches the sink.
- **PARTIAL**: The taint path is plausible but you could not confirm that upstream validation (middleware, decorator, framework binding, or another layer not read) is absent. The sink is real; the absence of a guard is uncertain.
- **NO**: The finding is theoretical — no concrete code evidence of a reachable path exists.

Report findings of all three confidence levels. Never silently drop a PARTIAL or NO finding.

# Severity

Assign **Severity** from the weakness category, then apply the adjustment rules below. Use this default mapping:

- **CRITICAL**: command injection, code injection, SQL/NoSQL/ORM/LDAP/XPath/GraphQL injection, insecure deserialization, server-side template injection, authentication bypass.
- **HIGH**: SSRF, path traversal / unsafe file access, zip-slip / decompression bomb, authorization bypass (including IDOR / mass assignment), XXE, XSS (stored), prototype pollution.
- **MEDIUM**: XSS (reflected / DOM), response splitting / header injection / open redirect, CORS validation bypass, log injection, ReDoS, weak RNG for a security-sensitive purpose, uncontrolled resource allocation.
- **LOW**: CSV / formula injection, cryptographic digest without a values separator.

**Adjustment rules** (apply in order; each rule moves the severity by one level at most):

- **Downgrade** by one level if exploiting the finding requires prior authentication (i.e. the entry point is behind a login gate with no known bypass): CRITICAL → HIGH, HIGH → MEDIUM, MEDIUM → LOW. Do not downgrade LOW findings.
- **Upgrade** by one level if the entry point is unauthenticated, internet-facing, and processes sensitive data (PII, credentials, financial data, session tokens): LOW → MEDIUM, MEDIUM → HIGH, HIGH → CRITICAL. Do not upgrade CRITICAL findings.

If both rules apply to the same finding, they cancel and the base severity stands.

# Output rules

Group findings by entry point. For each finding, use this structure:

- **Finding identifier**: Unique identifier of the finding, it is a number starting at 1 and incremented for each finding.
- **Confidence**: YES / PARTIAL / NO.
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW, assigned per the Severity mapping above.
- **Category**: The specific weakness class for the finding, taken from the parenthetical label of the matched item above (e.g. SSRF, XXE, ReDoS, path traversal, command injection), plus the corresponding CWE ID (e.g. CWE-89, CWE-79).
- **Processing location**: `path/to/file.go:42`.
- **Processing summary**: The risky processing identified as a single line summary.
- **Taint path**: `file.ext:method:line → file.ext:method:line → file.ext:method:line` — prefix **every** node with its filename and the enclosing method/function name using the format `filename:method:line` (e.g. `JwtConsumer.java:process:290`) so steps that cross files and functions are unambiguous. The first node is the entry-point input (the source); the last is the sink. For second-order paths, show the write path and the read-then-sink path on separate lines prefixed `[write]` and `[read→sink]`.
- **Proof of concept** (required when Confidence is YES; omit otherwise): Use the format that matches the sink type:

  | Sink type | Required format |
  | --- | --- |
  | HTTP endpoint (SSRF, XSS, SQLi, header injection, open redirect) | Minimal `curl` command or raw HTTP request reproducing the payload |
  | XXE | The minimal XML document containing the external entity declaration and the injected entity reference |
  | CORS bypass | `curl` command with `Origin: <attacker-origin>` header, showing the permissive `Access-Control-Allow-Origin` in the response |
  | CLI / shell (command injection) | Exact argument string passed to the binary |
  | Library call (eval, deserialization, template injection, prototype pollution, weak RNG, hash input ambiguity) | Minimal code snippet showing the tainted value reaching the call |
  | Filesystem (path traversal, zip-slip) | The exact filename or archive entry name that triggers the traversal |
  | ReDoS | The input string and the regex pattern that causes catastrophic backtracking |
  | Authentication / authorization bypass (IDOR) | The HTTP request showing the bypassed credential or the substituted resource identifier |
  | CSV / formula injection | The cell value (e.g. `=cmd\|' /C calc'!A0`) that triggers formula execution when opened in a spreadsheet |
  | Log injection | The input string containing a newline followed by a forged log line |
  | Uncontrolled resource allocation / DoS | The input value or payload size that triggers the excessive allocation or iteration |

# Effective validation reference

Use this table to decide whether a guard constitutes *effective* validation for a given sink.

| Sink | Effective | NOT effective |
| --- | --- | --- |
| SSRF | Exact-match allow-list of hosts/IPs | Regex on URL string, prefix check, URL parsing then domain check |
| Path traversal | `realpath()` / canonical path compared against allowed base | Blocking `..`, string contains check |
| Command injection | Parameterized exec (no shell invocation), allow-list of values | Escaping or quoting user input inside a shell string |
| SQL / NoSQL injection | Parameterized queries / prepared statements | String escaping, regex replacement |
| ReDoS | Static regex with no user-controlled characters | Any user input present anywhere in the pattern |
| XSS | Context-aware output encoding, strict CSP | HTML entity encoding applied once to the whole string |
| Open redirect | Exact-match allow-list of redirect targets | Checking that URL starts with `/`, domain regex |
| Deserialization | Allow-list of expected types enforced before deserializing | Blocking known gadget class names |
| XXE | External entity processing disabled in parser config | Filtering `<!DOCTYPE` or `<!ENTITY` from the input string |
| CORS bypass | Exact-match allow-list of origins | Wildcard `*`, regex on origin string, checking that origin ends with a domain suffix |
| Zip-slip / decompression bomb | Canonical path check before extraction, enforced entry count and decompressed-size limits | Blocking `..` in entry names, trusting archive metadata for size |
| Authentication bypass | Verified signed token (JWT RS256/ES256) or server-side session; signature verified before any claim is trusted | Trusting user-supplied role or identity fields, HS256 with an exposed or weak secret |
| Authorization bypass / IDOR | Server-side ownership check on every resource access, re-fetched from the authoritative store | Trusting client-supplied resource ID without re-checking ownership |
| Server-side template injection | Logic-less templates (Mustache, Handlebars in escape-only mode) or sandboxed engine with no access to dangerous globals | Escaping user input before inserting it into a template string |
| Code injection | No dynamic evaluation of user input; input never reaches `eval`/`exec`/`compile` | Sanitizing or escaping input before passing it to an eval function |
| Prototype pollution | `Object.create(null)` for merged objects; JSON schema validation rejecting `__proto__`, `constructor`, `prototype` keys before merge | Deleting `__proto__` from input after the merge has already occurred |
| Weak RNG | CSPRNG (`crypto.randomBytes`, `SecureRandom`, `os.urandom`) with no user-controlled seed | `Math.random()`, `rand()`, seeding with any user-controllable value |
| Log injection | Strip or encode newline characters (`\n`, `\r`) before the value reaches a log call | General HTML encoding, which does not neutralize log-format newlines |
| CSV / formula injection | Prefix any cell starting with `=`, `+`, `-`, `@`, `\t`, or `\r` with a single quote `'` | Quoting values with `"` without prefixing formula-trigger characters |
| Hash input ambiguity | Fixed-length inputs, length-prefixed fields, or HMAC | Simple concatenation with a separator character that could appear in user input |
| Uncontrolled resource allocation | Enforced server-side hard limit on size, entry count, or iteration bound before processing begins | Trusting a client-supplied limit value, no limit at all |
