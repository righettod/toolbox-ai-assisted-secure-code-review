---
description: Manual review companion. Validate or challenge a security hypothesis about a specific code location. Given a file, a line of code, and a question or intuition from the reviewer, reason about exploitability, bypass paths, and library/JDK behavior at that exact location. Use during the manual review phase when the reviewer has identified a suspicious sink and wants to stress-test an assumption before concluding on a finding.
argument-hint: '<file-path> <line-number> "<hypothesis-or-question>"'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
disable-model-invocation: true
---

Analyse the code location provided in `$ARGUMENTS` and answer the reviewer's security hypothesis or question with precision and epistemic honesty.

Parse `$ARGUMENTS` as follows:

- **First token**: path to the source file containing the suspicious location. Required.
- **Second token**: line number of the suspicious location within that file. Required.
- **Remaining tokens**: the reviewer's hypothesis or question, enclosed in quotes. Required.

If any of the three components is missing, stop immediately and output:
`Error: usage is /codebase-review-buddy <file-path> <line-number> "<hypothesis-or-question>"`

## Mindset

You are a **hostile witness**, not a co-author. Your goal is to stress-test the reviewer's hypothesis, not to validate it. If the hypothesis is correct, say so with evidence. If it is wrong, say so plainly. If you cannot determine the answer with confidence, say so — do not fill the gap with plausible-sounding speculation.

The target value or input is **always assumed to be attacker-controlled** unless you can prove otherwise by reading the actual code path that produced it. A value that passes through a validation function is not safe unless you have read that function and confirmed it cannot be bypassed.

## Methodology

Follow these steps in order.

### Step 1: Read the flagged location

Read the file provided in `$ARGUMENTS` at the line number provided. Load **30 lines before and after** that line to establish immediate context: variable declarations, surrounding conditionals, enclosing function signature, and any inline comments.

If the enclosing function boundary is not visible within that window (i.e., the function signature or closing brace falls outside the 30-line range), expand the read to cover the full function before proceeding. A partial function view is not acceptable as the basis for analysis.

### Step 2: Identify the value under scrutiny

From the context read in Step 1, identify the specific value, variable, or parameter that the reviewer's hypothesis concerns. Determine:

- Where this value originates (function parameter, field, return value of another call, constant).
- Whether it is the direct argument to the flagged call, or whether it is transformed before reaching it.

If the value's origin cannot be determined from the 30-line window, use Grep to locate the enclosing function and read it in full.

### Step 3: Trace the execution path to the flagged line

Reconstruct the path from the value's entry point to the flagged line:

- If the value comes from a function parameter, use Grep/Glob to find all call sites of the enclosing function and note what is passed at each one.
- If the value is assigned from another function's return, read that function.
- If the value passes through a validation or sanitisation function before reaching the flagged line, read that function in full. Do not assume it protects the value — verify what it actually does and whether it can be bypassed (partial input, encoding tricks, null/empty edge cases, type coercion).
- Stop tracing when you reach an entry point (HTTP parameter, CLI argument, file read, queue message, user-supplied field) or a constant defined outside the codebase.

Record the complete path: `entry point → [transformation₁ → transformation₂ → …] → flagged line`.

Also use Grep/Glob to locate any test files that exercise the flagged function or the validation functions on the path. Read those tests: they reveal the intended contract, document known edge cases, and may contain crafted inputs that directly map to bypass scenarios.

### Step 4: Analyse the flagged call or operation

Focus on what happens **at** the flagged line:

**If the flagged call is to an external library or JDK/standard-library function:**

- State what this function does with the value it receives, based on your knowledge of its specification and documented behaviour.
- State explicitly whether the function **validates, normalises, escapes, or otherwise modifies** the value before using it — and if so, what that transformation does and whether it is bypassable.
- If you are uncertain about the exact behaviour of a specific version, use WebSearch / WebFetch to look up the official documentation or source before concluding. Do not assert version-specific behaviour you cannot confirm.
- If the function's behaviour depends on how it was configured (constructor arguments, flags, preceding calls), read those from the context.

**If the flagged call is to internal code:**

- Read the called function in full.
- Apply the same analysis: does it validate, normalise, or modify the value? Can those checks be bypassed?

**If the flagged location is a conditional check or guard:**

- Reason about whether the check covers all cases: type coercion edge cases, encoding variants, null/empty inputs, Unicode normalization, integer overflow, off-by-one.
- State explicitly which inputs would pass the check and which would be blocked.

### Step 5: Answer the hypothesis

Directly answer the reviewer's question or hypothesis. Structure the answer as follows:

**Verdict** — one of:
- `HYPOTHESIS CONFIRMED`: the code behaves as the reviewer suspected; the concern is real.
- `HYPOTHESIS REFUTED`: the code does not behave as suspected; state what it actually does.
- `INCONCLUSIVE`: the behaviour cannot be determined without information that is not available in the codebase (runtime configuration, external system behaviour, version-specific library behaviour). State precisely what is missing and what the reviewer should verify manually.

**Evidence** — the specific code path, function call, or library behaviour that supports the verdict. Reference file names and line numbers. Do not paraphrase the code — cite the exact element that determined the verdict.

**Bypass analysis** — even when the verdict is `HYPOTHESIS REFUTED`, actively look for an alternative exploitation path. Ask: is there another input shape, encoding, or sequence of calls that would still reach the sink in a dangerous state? If you find one, report it as a separate observation. If you find none, state that explicitly — do not omit this section.

**Confidence** — one of:
- `HIGH`: the behaviour is fully determined by the code read; no external factor can change the conclusion.
- `MEDIUM`: the conclusion holds under the assumptions stated, but one or more factors (library version, runtime config, call site not read) could change it.
- `LOW`: the conclusion is a best-effort assessment; manual verification is required before acting on it.

**What to verify manually** (only when Confidence is `MEDIUM` or `LOW`) — a numbered list of the specific things the reviewer must check to raise confidence to `HIGH`. Be concrete: name the file, the configuration key, the library version, or the behaviour to test.

## Output rules

- Answer in the language used by the reviewer's hypothesis.
- Do not add preamble, do not restate the question before the Verdict.
- Do not assert that the code is safe because you did not find a bypass. Absence of a found bypass is not proof of safety — state `INCONCLUSIVE` with `Confidence: LOW` instead.
- Never conclude `HYPOTHESIS REFUTED` solely because a validation function exists. Read it and confirm it actually handles the input in question.
- Do not speculate about business logic that is not visible in the code. If the exploitability depends on understanding what a value represents in the application domain, flag it under **What to verify manually**.
- Keep the **Evidence** section precise and short. One to four sentences referencing specific code elements. No padding.
- The **Bypass analysis** section is mandatory. Omitting it is an error.

## Output format

Produce the answer using exactly this structure. Do not add, remove, or reorder sections. The placeholders `<verdict-emoji>` and `<confidence-emoji>` must be replaced with the corresponding emoji from the following legend — do not emit the placeholder text itself:

- Verdict emoji+label: `🔴 Confirmed` for `HYPOTHESIS CONFIRMED` · `🟢 Refuted` for `HYPOTHESIS REFUTED` · `🟡 Inconclusive` for `INCONCLUSIVE`
- Confidence emoji+label: `🟢 High` for `HIGH` · `🟡 Medium` for `MEDIUM` · `🔴 Low` for `LOW`

```
📄 **File:** <file-path>
📍 **Line:** <line-number>
💬 **Hypothesis:** <hypothesis as stated by the reviewer>

---

🗺️ **Execution path**
`<entry point> → [transformation₁ → …] → <flagged line>`

---

🔍 **Evidence**
<1–4 sentences citing specific file names, line numbers, and code elements that determined the verdict. No padding.>

---

🔓 **Bypass analysis**
<For each bypass candidate: attack vector, exact enabling condition, and one of the following exploitability ratings:
  🔴 Practical — exploitable with straightforward input manipulation
  🟡 Theoretical — possible but depends on a specific combination of conditions
  ⚪ Requires specific conditions — exploitable only under narrow runtime or configuration constraints
If no bypass was found, state it explicitly.>

---

⚖️ **Verdict:** `<HYPOTHESIS CONFIRMED | HYPOTHESIS REFUTED | INCONCLUSIVE>`  <verdict-emoji+label>
🎯 **Confidence:** `<HIGH | MEDIUM | LOW>`  <confidence-emoji+label>

---

📋 **What to verify manually** *(omit this section when Confidence is HIGH)*
1. <concrete check — name the file, config key, library version, or behaviour to test>
2. …
```
