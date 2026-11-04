export async function makeShort(env, userId, content) {
  const id=crypto.randomUUID().replaceAll("-","");
  await env.BOT_KV.put(`short:${id}`, content, {expirationTtl:60*60*24*30, metadata:{userId}});
  return `${env.SHORT_BASE_URL.replace(/\/$/,"")}/s/${id}`;
}
export async function saveSubscription(env,userId,value) {
  const id=crypto.randomUUID();
  await env.BOT_KV.put(`saved:${userId}:${id}`, JSON.stringify({value,createdAt:Date.now()}));
}
export async function handleShortLink(id,env) {
  if(!/^[a-f0-9]{32}$/.test(id)) return new Response("Not found",{status:404});
  const item=await env.BOT_KV.get(`short:${id}`);
  if(item === null) return new Response("Expired",{status:404});
  return new Response(item,{headers:{"content-type":"text/plain; charset=utf-8","cache-control":"private, no-store"}});
}
