export async function claimUsage(env, opKey, action) {
  const id=env.USAGE_GUARD.idFromName(opKey);
  const stub=env.USAGE_GUARD.get(id);
  return stub.fetch("https://usage/claim",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({opKey,action,mode:"claim"})}).then(r=>r.json());
}
export async function finishUsage(env, opKey, action, success) {
  const id=env.USAGE_GUARD.idFromName(opKey);
  const stub=env.USAGE_GUARD.get(id);
  return stub.fetch("https://usage/finish",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({opKey,action,mode:"finish",success})});
}
