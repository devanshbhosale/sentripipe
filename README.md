# SentriPipe

A pre-LLM firewall. SentriPipe screens every prompt **before it reaches your model**: it masks personal data, catches prompt injection, blocks malicious scripts, and then confirms the masking did not corrupt the meaning.

Built for the [Clocked Build Challenge](https://clocked.rezolve.ai/challenge) (Oct 21 - Nov 10, 2026).

## The problem

LLM apps take raw user input. That input can carry personal data that leaks into logs and third-party models, jailbreak instructions, or scripts an agent would happily run. Most teams handle this with one regex and a hope.

## What it does

One call to `/api/scan` runs a 4-step gate:

1. **Protect** (`POST /clocked/pii`) finds sensitive values and returns a sanitized copy. The sanitized copy, not the original, is what continues down the pipeline.
2. **Guard** (`POST /clocked/injection`) screens the **sanitized** text for prompt injection.
3. **Inspect** (`POST /clocked/script`) screens the sanitized text for malicious or suspicious scripts.
4. **Verify** (`POST /clocked/grounding`) checks the sanitized text against the original prompt, proving the masking preserved the request's meaning.

Every verdict (ALLOW / REVIEW / BLOCK) is derived from these outputs with explicit, explainable rules. No decoration calls: each endpoint's result changes the app's behavior.

### Verdict rules

| Verdict | Trigger |
| --- | --- |
| BLOCK | Guard verdict is not `benign`, or Inspect `malicious >= 0.5` |
| REVIEW | Guard score `>= 0.3`, or Inspect `suspicious >= 0.5`, or Verify grounded `< 0.6` |
| ALLOW | Everything clean; the sanitized prompt is what the LLM would receive |

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

Each scan = 4 Clocked calls (1 sequential + 3 parallel). At the free challenge allowance (20,000 credits), that is thousands of scans: enough for development, the demo, and judge testing combined.

## Stack

Next.js (App Router) + Tailwind CSS + TypeScript. One API route keeps the Clocked key server-side; the browser never sees it. No other dependencies.
