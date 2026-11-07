import { request } from "undici";

export interface TranslateOptions {
  ollamaBaseUrl?: string;
  model?: string;
  glossary?: Record<string, string>;
}

export class PLaMoTranslator {
  private baseUrl: string;
  private model: string;

  constructor(options?: TranslateOptions) {
    this.baseUrl = options?.ollamaBaseUrl || process.env.OLLAMA_BASE_URL || "http://ollama-service.litellm.svc.cluster.local:11434";
    this.model = options?.model || process.env.PLAMO_MODEL || "plamo-3-translate:2b";
  }

  /**
   * Translates English text to professional Japanese, safeguarding designated CTI terms.
   */
  async translateToJapanese(text: string, preservedTerms: string[] = []): Promise<string> {
    if (!text || text.trim() === "") return "";

    // 1. Replace preserved terms (CVEs, Victim Org names, Actor names) with placeholder tokens
    const placeholders = new Map<string, string>();
    let maskedText = text;

    // Sort terms by length descending to prevent sub-string collision
    const sortedTerms = Array.from(new Set(preservedTerms.filter(t => t && t.trim().length > 1)))
      .sort((a, b) => b.length - a.length);

    sortedTerms.forEach((term, index) => {
      const token = `__CTI_TERM_${index}__`;
      placeholders.set(token, term);
      // Case-insensitive boundary or exact match
      const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      maskedText = maskedText.replace(new RegExp(escaped, "gi"), token);
    });

    const prompt = `Translate the following English cyber threat intelligence text into concise, professional Japanese.
Rules:
- Translate into natural Japanese (da/dearu style).
- Do NOT translate or modify placeholder tokens like __CTI_TERM_0__.
- Strictly output ONLY the Japanese translation. No commentary.

Text to translate:
${maskedText}`;

    try {
      const res = await request(`${this.baseUrl}/api/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: this.model,
          prompt: prompt,
          stream: false,
          options: {
            temperature: 0.1
          }
        })
      });

      if (res.statusCode !== 200) {
        throw new Error(`Ollama translator returned status ${res.statusCode}`);
      }

      const body = (await res.body.json()) as any;
      let translated = (body.response || "").trim();

      // 2. Restore placeholder tokens with original preserved strings
      for (const [token, original] of placeholders.entries()) {
        translated = translated.replaceAll(token, original);
      }

      return translated;
    } catch (err: any) {
      console.warn(`[PLaMoTranslator] Translation call failed: ${err.message}. Returning original text.`);
      return text;
    }
  }
}

