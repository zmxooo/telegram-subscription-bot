
async function requestUsage(env, opKey, body) {
  if (!env.USAGE_GUARD) {
    throw new Error("USAGE_GUARD 未配置。");
  }

  const id = env.USAGE_GUARD.idFromName(opKey);
  const stub = env.USAGE_GUARD.get(id);

  const response = await stub.fetch("https://usage/", {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({
      opKey,
      ...body
    })
  });

  let result;

  try {
    result = await response.json();
  } catch {
    throw new Error("限次服务返回了无效数据。");
  }

  if (!response.ok) {
    throw new Error(
      result?.error || `限次服务异常：HTTP ${response.status}`
    );
  }

  return result;
}

// 领取操作次数
export async function claimUsage(env, opKey, action) {
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

  if (!result.token) {
    throw new Error("限次服务没有返回操作凭证。");
  }

  return {
    ok: true,
    token: result.token
  };
}

// 完成操作或释放失败操作
export async function finishUsage(
  env,
  opKey,
  action,
  token,
  success
) {
  if (typeof token !== "string" || !token) {
    throw new Error("缺少操作凭证，无法完成限次操作。");
  }

  if (typeof success !== "boolean") {
    throw new Error("操作结果参数不正确。");
  }

  return requestUsage(env, opKey, {
    action,
    mode: "finish",
    token,
    success
  });
}
