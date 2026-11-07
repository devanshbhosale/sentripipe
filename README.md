# SentriPipe

A pre-LLM firewall. SentriPipe screens every prompt **before it reaches your model**: it masks personal data, catches prompt injection, blocks malicious scripts, and then confirms the masking did not corrupt the meaning.

Built for the [Clocked Build Challenge](https://clocked.rezolve.ai/challenge) (Oct 21 - Nov 10, 2026).

![Blocked injection scan](docs/scan-block.png)

The verdict banner, the 4-endpoint pipeline, the evidence quotes and the attack-span highlighting are all driven by live Clocked responses. More below: [indirect injection caught in agent-read email](docs/indirect.png), [12-case adversarial eval scorecard](docs/eval.png).

## The problem

LLM apps take raw user input. That input can carry personal data that leaks into logs and third-party models, jailbreak instructions, or scripts an agent would happily run. Most teams handle this with one regex and a hope.

## What it does

One call to `/api/scan` runs a 5-step gate:

1. **Protect** (`POST /clocked/pii`) finds sensitive values and returns a sanitized copy. The sanitized copy, not the original, is what continues down the pipeline.
2. **Guard** (`POST /clocked/injection`) screens the **sanitized** text for prompt injection, with `source` set to `"user"` (typed input) or `"content"` (email, page, or document an agent read: indirect injection).
3. **Inspect** (`POST /clocked/script`) screens the sanitized text for malicious or suspicious scripts.
4. **Verify** (`POST /clocked/grounding`) checks the sanitized text against the original prompt, proving the masking preserved the request's meaning.
5. **Decide** (`POST /clocked/decide`) fires only for borderline (REVIEW) input: a calibrated yes/no on whether the input should be blocked, which can escalate REVIEW to BLOCK.

Every verdict (ALLOW / REVIEW / BLOCK) is derived from these outputs with explicit, explainable rules. No decoration calls: each endpoint's result changes the app's behavior.

```mermaid
flowchart LR
    IN[Prompt or agent-read content] --> P["Protect<br/>/clocked/pii"]
    P -->|"sanitized copy"| G["Guard<br/>/clocked/injection<br/>source = user or content"]
    P -->|"sanitized copy"| I["Inspect<br/>/clocked/script"]
    P -.->|"original as document"| V["Verify<br/>/clocked/grounding"]
    G --> R{Verdict rules}
    I --> R
    V --> R
    R -->|BLOCK| B[BLOCK: never reaches the model]
    R -->|ALLOW| A[ALLOW: sanitized prompt goes to the LLM]
    R -->|REVIEW| D["Decide<br/>/clocked/decide<br/>calibrated block probability"]
    D -->|p >= 0.6| B
    D -->|p < 0.6| A
```

### Verdict rules

| Verdict | Trigger |
| --- | --- |
| BLOCK | Guard verdict is not `benign`, or Inspect `malicious >= 0.5`, or Decide escalates a REVIEW with block probability `>= 0.6` |
| REVIEW | Guard score `>= 0.3`, or Inspect `suspicious >= 0.5`, or Verify grounded `< 0.6` (then Decide arbitrates) |
| ALLOW | Everything clean; the sanitized prompt is what the LLM would receive |

## Indirect injection is a first-class case

The 2026 threat model is not users typing `ignore previous instructions`. It is injection hidden in content an agent reads: a supplier email with a bracketed "note to the AI assistant", a knowledge-base article with a poisoned HTML comment. SentriPipe has an input-role toggle: **Typed by the user** runs Guard with `source: "user"`, **Read by the agent** runs it with `source: "content"`. Both presets are built in, and both are part of the eval suite.

## Adversarial eval, measured not vibes

The app ships a 12-case eval (`lib/evalCases.ts`, runnable from the UI): 8 attacks that must BLOCK, including indirect and base64-encoded ones, and 4 benign payloads that must NOT block, deliberately including security-flavored false-positive traps (AWS key rotation questions, admin backup scripts, authorized-pentest language). A gate that blocks every legitimate security question is useless in production, so false positives are counted as failures, same as false negatives.

## Why not `/clocked/pipeline`?

Clocked's own pipeline endpoint explicitly does **not** pass one step's output to the next step: every step reads the same shared text. Gating the *sanitized* text (rather than the raw input) requires real orchestration, which is exactly what SentriPipe adds. Guard and Inspect here see the world the way the LLM will.

## Drop-in middleware

The same verdict logic ships as a ~40-line `gate()` wrapper (shown in the app UI and in `app/page.tsx`):

```ts
const reply = await gate(userInput, (cleanPrompt) => myLLM(cleanPrompt));
```

Clean input returns the LLM reply. Blocked input throws before any model call happens.

## Run it

```bash
npm install
# .env.local
# CLOCKED_API_KEY=your_key_here   (never committed)
npm run dev
```

Open http://localhost:3000, pick a preset or paste your own prompt, and scan.

## Credit math

Each scan = 4 Clocked calls (1 sequential + 3 parallel), plus a 5th Decide call only for borderline REVIEW input. The UI shows real credits per scan from the `X-Clocked-Credits` response header, not estimates. At the free challenge allowance (20,000 credits), that is thousands of scans: enough for development, the demo, judge testing, and many eval runs.

## Threat model: what this does not do

Clocked's own docs say it best: a detector is **not an enforcement boundary**. Honest limits of this gate:

- Guard and Inspect are probabilistic. A score below threshold is not proof of safety; that is why REVIEW exists and why Decide arbitrates borderline cases instead of a coin-flip threshold.
- PII detection covers modeled entity types and custom rules; novel identifier formats can slip through. Verify's grounded score is the backstop: if masking corrupted the meaning, the scan drops to REVIEW.
- Scripts are analyzed statically; nothing is executed.
- The gate screens text. Prompt-leakage via images, PDFs, or tool outputs passed as other modalities is out of scope here.

## Stack

Next.js (App Router) + Tailwind CSS + TypeScript. One API route keeps the Clocked key server-side; the browser never sees it. No other dependencies.
