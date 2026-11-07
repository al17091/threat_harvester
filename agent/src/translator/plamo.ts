import { request } from "undici";

export interface TranslateOptions {
  plamoBaseUrl?: string;
  timeoutMs?: number;
}

export class PLaMoTranslator {
  private baseUrl: string;
  private timeoutMs: number;

  constructor(options?: TranslateOptions) {
    this.baseUrl = (options?.plamoBaseUrl || process.env.PLAMO_BASE_URL || "http://plamo-translator-service.litellm.svc.cluster.local:8080").replace(/\/+$/, "");
    this.timeoutMs = options?.timeoutMs || 60000;
  }

  /**
   * Translates English text to professional Japanese using PLaMo 3 Translate (llama-server /completion).
   * Utilizes native PFML3 prompt format with glossary support to preserve CTI entities and enforce canonical names.
   */
  async translateToJapanese(text: string, glossary: Record<string, string> | string[] = {}): Promise<string> {
    if (!text || text.trim() === "") return "";

    // Normalize glossary entries
    const glossaryEntries: [string, string][] = [];
    if (Array.isArray(glossary)) {
      for (const term of glossary) {
        if (term && term.trim()) {
          glossaryEntries.push([term.trim(), term.trim()]);
        }
      }
    } else if (typeof glossary === "object" && glossary !== null) {
      for (const [k, v] of Object.entries(glossary)) {
        if (k && k.trim() && v && v.trim()) {
          glossaryEntries.push([k.trim(), v.trim()]);
        }
      }
    }

    // Sort glossary entries by length descending so longer phrases match first
    glossaryEntries.sort((a, b) => b[0].length - a[0].length);

    // Construct PFML3 prompt
    let glossaryTag = "";
    if (glossaryEntries.length > 0) {
      glossaryTag = "<|plamo:tag|>glossary" + glossaryEntries
        .map(([src, tgt]) => `<|plamo:index|>${src}<|plamo:item|>${tgt}`)
        .join("");
    }

    const prompt = `<|plamo:tag|>dataset<|plamo:msg|>translation${glossaryTag}<|plamo:tag|>input<|plamo:msg|>${text.trim()}<|plamo:tag|>output<|plamo:key|>lang<|plamo:val|>ja<|plamo:key|>form<|plamo:val|>plain<|plamo:msg|>`;

    try {
      const res = await request(`${this.baseUrl}/completion`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        headersTimeout: this.timeoutMs,
        bodyTimeout: this.timeoutMs,
        body: JSON.stringify({
          prompt: prompt,
          n_predict: 512,
          temperature: 0.1,
          stop: ["<|plamo:tag|>", "<|plamo:bos|>"]
        })
      });

      if (res.statusCode !== 200) {
        throw new Error(`llama-server returned status ${res.statusCode}`);
      }

      const body = (await res.body.json()) as any;
      const translated = (body.content || "").trim();
      return translated || text;
    } catch (err: any) {
      console.warn(`[PLaMoTranslator] Translation call failed: ${err.message}. Returning original text.`);
      return text;
    }
  }
}
