
const ACTIONS = new Set([
  "refresh",
  "base64",
  "yaml",
  "short",
  "save"
]);

// ======================================
// 基础配置
// ======================================

// 处理中超过30分钟，允许重新领取
const PROCESSING_TTL = 30 * 60 * 1000;

// 参数限制
const MAX_OP_KEY_LENGTH = 256;
const MAX_TOKEN_LENGTH = 128;
const MAX_BODY_BYTES = 4096;

// ======================================
// 通用响应
// ======================================

function jsonResponse(data, status = 200) {
  return Response.json(
    data,
    {
      status,
      headers: {
        "cache-control": "no-store"
      }
    }
  );
}

function jsonError(message, status = 400) {
  return jsonResponse(
    {
      ok: false,
      error: message
    },
    status
  );
}

// ======================================
// Durable Object
// ======================================

export class UsageGuard {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;

    // ==================================
    // 创建额度表
    // ==================================

    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS usage (
        op_key TEXT NOT NULL,
        action TEXT NOT NULL,
        status TEXT NOT NULL,
        token TEXT,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (op_key, action)
      )
    `);

    // ==================================
    // 兼容旧数据库
    // ==================================

    const columns = this.sql
      .exec("PRAGMA table_info(usage)")
      .toArray();

    if (
      !columns.some(
        column => column.name === "token"
      )
    ) {
      this.sql.exec(
        "ALTER TABLE usage ADD COLUMN token TEXT"
      );
    }
  }

  // ======================================
  // 请求入口
  // ======================================

  async fetch(request) {
    if (request.method !== "POST") {
      return jsonResponse(
        {
          ok: false,
          error: "Method not allowed"
        },
        405
      );
    }

    // ==================================
    // 检查 Content-Length
    // ==================================

    const contentLength =
      request.headers.get("content-length");

    if (contentLength !== null) {
      if (!/^\d+$/.test(contentLength)) {
        return jsonError(
          "Invalid Content-Length",
          400
        );
      }

      if (Number(contentLength) > MAX_BODY_BYTES) {
        return jsonError(
          "Request too large",
          413
        );
      }
    }

    // ==================================
    // 读取请求体
    // ==================================

    let body;

    try {
      const raw = await this.readBody(
        request,
        MAX_BODY_BYTES
      );

      body = JSON.parse(raw);

    } catch (error) {
      if (error.message === "BODY_TOO_LARGE") {
        return jsonError(
          "Request too large",
          413
        );
      }

      if (error.message === "INVALID_UTF8") {
        return jsonError(
          "Invalid UTF-8",
          400
        );
      }

      if (error instanceof SyntaxError) {
        return jsonError(
          "Invalid JSON",
          400
        );
      }

      console.error(
        "Usage request body error:",
        error?.stack || error
      );

      return jsonError(
        "Invalid request body",
        400
      );
    }

    // ==================================
    // 检查 JSON 结构
    // ==================================

    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body)
    ) {
      return jsonError(
        "Invalid request body",
        400
      );
    }

    const {
      opKey,
      action,
      mode
    } = body;

    // ==================================
    // 检查参数
    // ==================================

    if (
      typeof opKey !== "string" ||
      opKey.length < 1 ||
      opKey.length > MAX_OP_KEY_LENGTH ||
      typeof action !== "string" ||
      !ACTIONS.has(action)
    ) {
      return jsonError(
        "Invalid parameters",
        400
      );
    }

    // ==================================
    // 领取额度
    // ==================================

    if (mode === "claim") {
      return this.claim(
        opKey,
        action
      );
    }

    // ==================================
    // 完成额度操作
    // ==================================

    if (mode === "finish") {
      return this.finish(
        body,
        opKey,
        action
      );
    }

    return jsonError(
      "Invalid mode",
      400
    );
  }

  // ======================================
  // 限制请求体实际字节数
  // ======================================

  async readBody(request, maxBytes) {
    if (!request.body) {
      throw new Error("EMPTY_BODY");
    }

    const reader = request.body.getReader();

    const chunks = [];
    let totalBytes = 0;

    try {
      while (true) {
        const {
          done,
          value
        } = await reader.read();

        if (done) break;

        totalBytes += value.byteLength;

        if (totalBytes > maxBytes) {
          await reader.cancel();

          throw new Error("BODY_TOO_LARGE");
        }

        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }

    const buffer = new Uint8Array(totalBytes);

    let offset = 0;

    for (const chunk of chunks) {
      buffer.set(chunk, offset);
      offset += chunk.byteLength;
    }

    try {
      return new TextDecoder(
        "utf-8",
        { fatal: true }
      ).decode(buffer);
    } catch {
      throw new Error("INVALID_UTF8");
    }
  }

  // ======================================
  // 原子领取额度
  // ======================================

  claim(opKey, action) {
    const now = Date.now();

    const token = crypto.randomUUID();

    const result = this.ctx.storage.transactionSync(() => {
      const row = this.sql.exec(
        `SELECT
           status,
           token,
           updated_at
         FROM usage
         WHERE op_key = ?
           AND action = ?`,
        opKey,
        action
      ).toArray()[0];

      // ==================================
      // 已经成功使用
      // 永久禁止再次领取
      // ==================================

      if (
        row &&
        row.status === "done"
      ) {
        return "already_used";
      }

      // ==================================
      // 仍在处理中
      // 暂时禁止重复领取
      // ==================================

      if (
        row &&
        row.status === "processing" &&
        now - row.updated_at < PROCESSING_TTL
      ) {
        return "processing";
      }

      // ==================================
      // 不存在记录或处理锁已经过期
      // 重新领取
      // ==================================

      this.sql.exec(
        `INSERT OR REPLACE INTO usage (
           op_key,
           action,
           status,
           token,
           updated_at
         )
         VALUES (?, ?, 'processing', ?, ?)`,
        opKey,
        action,
        token,
        now
      );

      return "claimed";
    });

    if (result !== "claimed") {
      return jsonResponse({
        ok: false,
        error: result
      });
    }

    return jsonResponse({
      ok: true,
      token
    });
  }

  // ======================================
  // 完成额度操作
  // ======================================

  finish(body, opKey, action) {
    const {
      token,
      success
    } = body;

    // ==================================
    // 检查 Token 和状态
    // ==================================

    if (
      typeof token !== "string" ||
      token.length < 1 ||
      token.length > MAX_TOKEN_LENGTH ||
      typeof success !== "boolean"
    ) {
      return jsonError(
        "Invalid finish parameters",
        400
      );
    }

    // ==================================
    // 原子完成操作
    // ==================================

    const result = this.ctx.storage.transactionSync(() => {
      const row = this.sql.exec(
        `SELECT
           status,
           token
         FROM usage
         WHERE op_key = ?
           AND action = ?`,
        opKey,
        action
      ).toArray()[0];

      // ==================================
      // 只能由当前领取者完成
      // ==================================

      if (
        !row ||
        row.status !== "processing" ||
        row.token !== token
      ) {
        return false;
      }

      // ==================================
      // 成功：永久记录已使用
      // ==================================

      if (success) {
        this.sql.exec(
          `UPDATE usage
           SET status = 'done',
               token = NULL,
               updated_at = ?
           WHERE op_key = ?
             AND action = ?
             AND status = 'processing'
             AND token = ?`,
          Date.now(),
          opKey,
          action,
          token
        );

        return true;
      }

      // ==================================
      // 失败：只释放当前领取者的额度
      // ==================================

      this.sql.exec(
        `DELETE FROM usage
         WHERE op_key = ?
           AND action = ?
           AND status = 'processing'
           AND token = ?`,
        opKey,
        action,
        token
      );

      return true;
    });

    return jsonResponse({
      ok: result
    });
  }
}
