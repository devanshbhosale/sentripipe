import { NextResponse } from "next/server";

const BASE = "https://clocked.rezolve.ai/clocked";

export const maxDuration = 60;

type PiiEntity = {
  type: string;
  value: string;
  start: number;
  end: number;
  confidence: number;
};

type PiiResult = {
  entities: PiiEntity[];
  counts: Record<string, number>;
  anonymized_text?: string;
  timing?: { total_ms?: number };
};

type InjectionResult = {
  injection: number;
  verdict: string;
  category?: string;
  severity?: string;
  evidence?: Array<{ quote: string; start: number; end: number; confidence: number }>;
  timing?: { total_ms?: number };
};

type ScriptResult = {
  malicious: number;
  suspicious: number;
  verdict: string;
  category?: string;
  severity?: string;
  evidence?: Array<{ line: string; start: number; end: number; confidence: number }>;
  timing?: { total_ms?: number };
};

type GroundingResult = {
  grounded: number;
  ungrounded: number;
  verdict: string;
  claims?: Array<{ claim: string; verdict: string; supported: number }>;
  timing?: { total_ms?: number };
};

async function clocked<T>(endpoint: string, body: unknown): Promise<T> {
  const key = process.env.CLOCKED_API_KEY;
  if (!key || key.startsWith("paste_")) {
    throw new Error("CLOCKED_API_KEY missing in .env.local");
  }
  const res = await fetch(`${BASE}/${endpoint}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      "Idempotency-Key": crypto.randomUUID(),
    },
    body: JSON.stringify(body),
  });
  const json: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail =
      json && typeof json === "object" && "error" in json
        ? String((json as { error: unknown }).error)
        : res.statusText;
    throw new Error(`${endpoint}: ${res.status} ${detail}`);
  }
  return json as T;
}

export async function POST(req: Request) {
  let text = "";
  try {
    const body = await req.json();
    text = String(body?.text ?? "").trim();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  if (!text) {
    return NextResponse.json({ error: "text is required" }, { status: 400 });
  }
  if (text.length > 20000) {
    return NextResponse.json({ error: "text too long (20000 char max)" }, { status: 400 });
  }

  const t0 = Date.now();
  const reasons: string[] = [];
  const errors: string[] = [];

  // Step 1: Protect masks PII on the original input.
  let pii: PiiResult | null = null;
  let sanitized = text;
  try {
    pii = await clocked<PiiResult>("pii", {
      text,
      anonymize: "replace",
      threshold: 0.5,
    });
    if (pii.anonymized_text) sanitized = pii.anonymized_text;
  } catch (e) {
    errors.push(e instanceof Error ? e.message : String(e));
  }

  // Steps 2-4: Guard, Inspect and Verify run on the sanitized text,
  // i.e. exactly what the LLM would receive. This fan-out needs real
  // orchestration because /clocked/pipeline cannot pass one step's
  // output to the next step's input.
  const [injR, scrR, grdR] = await Promise.allSettled([
    clocked<InjectionResult>("injection", {
      text: sanitized,
      source: "user",
      evidence: true,
      threshold: 0.5,
    }),
    clocked<ScriptResult>("script", {
      script: sanitized,
      threshold: 0.5,
      evidence: true,
    }),
    clocked<GroundingResult>("grounding", {
      answer: sanitized,
      documents: [{ id: "original-prompt", text }],
      question: "Does the sanitized prompt preserve the meaning of the original prompt?",
      threshold: 0.5,
      evidence: "flagged",
    }),
  ]);

  const injection = injR.status === "fulfilled" ? injR.value : null;
  const script = scrR.status === "fulfilled" ? scrR.value : null;
  const grounding = grdR.status === "fulfilled" ? grdR.value : null;
  for (const r of [injR, scrR, grdR]) {
    if (r.status === "rejected") {
      errors.push(r.reason instanceof Error ? r.reason.message : String(r.reason));
    }
  }

  // Verdict: explainable rules driven only by endpoint outputs.
  let verdict: "BLOCK" | "REVIEW" | "ALLOW" = "ALLOW";

  if (injection && injection.verdict !== "benign") {
    verdict = "BLOCK";
    reasons.push(
      `Guard flagged "${injection.category ?? injection.verdict}" (p=${injection.injection.toFixed(2)}, severity ${injection.severity ?? "n/a"})`
    );
  }
  if (script && script.malicious >= 0.5) {
    verdict = "BLOCK";
    reasons.push(
      `Inspect flagged "${script.category ?? script.verdict}" (malicious p=${script.malicious.toFixed(2)})`
    );
  }
  if (verdict === "ALLOW") {
    if (injection && injection.injection >= 0.3) {
      verdict = "REVIEW";
      reasons.push(
        `Guard score ${injection.injection.toFixed(2)} below threshold but above 0.3 watch band`
      );
    }
    if (script && script.suspicious >= 0.5) {
      verdict = "REVIEW";
      reasons.push(
        `Inspect suspicious score ${script.suspicious.toFixed(2)}`
      );
    }
  }
  if (verdict === "ALLOW" && grounding && grounding.grounded < 0.6) {
    verdict = "REVIEW";
    reasons.push(
      `Verify grounded score ${grounding.grounded.toFixed(2)}: masking may have altered meaning`
    );
  }
  if (verdict === "ALLOW") {
    reasons.push(
      pii && pii.entities.length > 0
        ? `Masked ${pii.entities.length} sensitive value(s) before any model call, Guard and Inspect found no threat`
        : "No PII, no injection, no malicious script"
    );
  }

  return NextResponse.json({
    verdict,
    reasons,
    errors,
    sanitizedText: pii?.anonymized_text ?? null,
    piiMasked: pii ? pii.entities.length : 0,
    totalMs: Date.now() - t0,
    pii,
    injection,
    script,
    grounding,
  });
}
