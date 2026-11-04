import { handleTelegramUpdate, telegram } from "./telegram.js";
import { handleShortLink } from "./short.js";

export { UsageGuard } from "./usage.js";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/s/") && request.method === "GET") {
      return handleShortLink(url.pathname.slice(3), env);
    }

    if (url.pathname === "/health") {
      return Response.json({ ok: true, service: "telegram-subscription-parser" });
    }

    if (url.pathname === "/webhook" && request.method === "POST") {
      const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
      if (!env.WEBHOOK_SECRET || secret !== env.WEBHOOK_SECRET) {
        return new Response("Forbidden", { status: 403 });
      }
      let update;
      try { update = await request.json(); } catch {
        return new Response("Bad Request", { status: 400 });
      }
      ctx.waitUntil(handleTelegramUpdate(update, env).catch(async e => {
        console.error("update failed", e?.stack || e);
      }));
      return Response.json({ ok: true });
    }

    if (url.pathname === "/set-webhook" && request.method === "POST") {
      const key = url.searchParams.get("key");
      if (!key || key !== env.WEBHOOK_SECRET) return new Response("Forbidden", { status: 403 });
      const result = await telegram(env, "setWebhook", {
        url: `${url.origin}/webhook`,
        secret_token: env.WEBHOOK_SECRET,
        allowed_updates: ["message", "callback_query"]
      });
      return Response.json(result);
    }

    return new Response("Telegram subscription parser is running.", { status: 200 });
  }
};
