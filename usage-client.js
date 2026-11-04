
const ACTIONS = new Set([
  "refresh",
  "base64",
  "yaml",
  "short",
  "save"
]);

async function requestUsage(env, opKey, body) {
  if (!env.USAGE_GUARD) {
    throw new Error("USAGE_GUARD 未配置。");
  }

  if (
    typeof opKey !== "string" ||
    opKey.length < 1 ||
    opKey.length > 256
  ) {
    throw new Error("限次操作标识不正确。");
  }

  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    throw new Error("限次请求参数不正确。");
  }

  if (!ACTIONS.has(body.action)) {
    throw new Error("不支持的限次操作类型。");
  }

  const id = env.USAGE_GUARD.idFromName(opKey);
  const stub = env.USAGE_GUARD.get(id);

  let response;

  try {
    response = await stub.fetch("https://usage/", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        ...body,
        opKey
      })
    });
  } catch {
    throw new Error("限次服务连接失败，请稍后重试。");
  }

  let result;

  try {
    result = await response.json();
  } catch {
    throw new Error("限次服务返回了无效数据。");
  }

  if (!response.ok) {
    throw new Error(
      result?.error ||
      `限次服务异常：HTTP ${response.status}`
    );
  }

  if (
    !result ||
    typeof result !== "object" ||
    typeof result.ok !== "boolean"
  ) {
    throw new Error("限次服务返回的数据格式不正确。");
  }

  return result;
}

// ======================================
// 领取操作次数
// ======================================

export async function claimUsage(env, opKey, action) {
  if (!ACTIONS.has(action)) {
    throw new Error("不支持的限次操作类型。");
  }

  const result = await requestUsage(env, opKey, {
    action,
    mode: "claim"
  });

  if (!result.ok) {
    return {
      ok: false,
      error: result.error || "already_used_or_processing"
    };
  }

  if (
    typeof result.token !== "string" ||
    result.token.length < 1 ||
    result.token.length > 128
  ) {
    throw new Error("限次服务没有返回有效操作凭证。");
  }

  return {
    ok: true,
    token: result.token
  };
}

// ======================================
// 完成操作或释放失败操作
// ======================================

export async function finishUsage(
  env,
  opKey,
  action,
  token,
  success
) {
  if (!ACTIONS.has(action)) {
    throw new Error("不支持的限次操作类型。");
  }

  if (
    typeof token !== "string" ||
    token.length < 1 ||
    token.length > 128
  ) {
    throw new Error("操作凭证不正确。");
  }

  if (typeof success !== "boolean") {
    throw new Error("操作结果参数不正确。");
  }

  const result = await requestUsage(env, opKey, {
    action,
    mode: "finish",
    token,
    success
  });

  if (!result.ok) {
    throw new Error(
      success
        ? "操作已经执行，但限次状态更新失败，请检查操作记录。"
        : "失败操作的额度释放失败，请检查限次状态。"
    );
  }

  return {
    ok: true
  };
}
