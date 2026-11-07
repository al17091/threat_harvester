import Fastify from "fastify";
import { CTIAgentService } from "./agent.js";
import { ThreatItemSchema } from "./types.js";
import { z } from "zod";

const fastify = Fastify({
  logger: true
});

const agentService = new CTIAgentService();

fastify.get("/healthz", async () => {
  return { status: "ok", service: "threat-harvester-agent" };
});

fastify.post("/analyze", async (request, reply) => {
  const parseResult = ThreatItemSchema.safeParse(request.body);
  if (!parseResult.success) {
    return reply.status(400).send({
      error: "Invalid ThreatItem payload",
      details: parseResult.error.format()
    });
  }

  try {
    const result = await agentService.analyze(parseResult.data);
    return reply.status(200).send(result);
  } catch (err: any) {
    fastify.log.error(err);
    return reply.status(500).send({ error: "Analysis failed", message: err.message });
  }
});

fastify.post("/analyze/batch", async (request, reply) => {
  const BatchSchema = z.object({
    items: z.array(ThreatItemSchema)
  });

  const parseResult = BatchSchema.safeParse(request.body);
  if (!parseResult.success) {
    return reply.status(400).send({
      error: "Invalid batch payload",
      details: parseResult.error.format()
    });
  }

  const results = [];
  for (const item of parseResult.data.items) {
    try {
      const res = await agentService.analyze(item);
      results.push(res);
    } catch (err: any) {
      fastify.log.error(`Batch item failed: ${err.message}`);
      results.push(null);
    }
  }

  return reply.status(200).send({ results });
});

const port = Number(process.env.AGENT_PORT || 8002);
const host = process.env.AGENT_HOST || "0.0.0.0";

try {
  await fastify.listen({ port, host });
  console.log(`[threat-harvester-agent] Listening on http://${host}:${port}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}

