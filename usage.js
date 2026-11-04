
const ACTIONS = new Set([
  "refresh",
  "base64",
  "yaml",
  "short",
  "save"
]);

// 处理中超过10分钟，允许重新领取
const PROCESSING_TTL = 10 * 60 * 1000;

const MAX_OP_KEY_LENGTH = 256;

export class UsageGuard {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;

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

    // 兼容旧版本数据库：为旧表增加 token 字段
    const columns = this.sql.exec(
      "PRAGMA table_info(usage)"
    ).toArray();

    if (!columns.some(column => column.name === "token")) {
      this.sql.exec(
        "ALTER TABLE usage ADD COLUMN token TEXT"
      );
    }
  }

  async fetch(request) {
    if (request.method !== "POST") {
      return Response.json(
        { ok: false, error: "Method not allowed" },
        { status: 405 }
      );
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        { ok: false, error: "Invalid JSON" },
        { status: 400 }
      );
    }

    const { opKey, action, mode } = body || {};

    if (
      typeof opKey !== "string" ||
      opKey.length < 1 ||
      opKey.length > MAX_OP_KEY_LENGTH ||
      typeof action !== "string" ||
      !ACTIONS.has(action)
    ) {
      return Response.json(
        { ok: false, error: "Invalid parameters" },
        { status: 400 }
      );
    }

    if (mode === "claim") {
      return this.claim(opKey, action);
    }

    if (mode === "finish") {
      return this.finish(body, opKey, action);
    }

    return Response.json(
      { ok: false, error: "Invalid mode" },
      { status: 400 }
    );
  }

  claim(opKey, action) {
    const now = Date.now();
    const token = crypto.randomUUID();

    const result = this.ctx.storage.transactionSync(() => {
      const row = this.sql.exec(
        `SELECT status, updated_at
         FROM usage
         WHERE op_key = ? AND action = ?`,
        opKey,
        action
      ).toArray()[0];

      // 已经成功使用过，不允许再次领取
      if (row && row.status === "done") {
        return false;
      }

      // 仍在处理中，暂时不允许重复领取
      if (
        row &&
        row.status === "processing" &&
        now - row.updated_at < PROCESSING_TTL
      ) {
        return false;
      }

      // 不存在记录，或旧操作已经超时，允许领取
      this.sql.exec(
        `INSERT OR REPLACE INTO usage
         (op_key, action, status, token, updated_at)
         VALUES (?, ?, 'processing', ?, ?)`,
        opKey,
        action,
        token,
        now
      );

      return true;
    });

    if (!result) {
      return Response.json({
        ok: false,
        error: "already_used_or_processing"
      });
    }

    return Response.json({
      ok: true,
      token
    });
  }

  finish(body, opKey, action) {
    const token = body.token;
    const success = body.success;

    if (
      typeof token !== "string" ||
      token.length < 1 ||
      token.length > 128 ||
      typeof success !== "boolean"
    ) {
      return Response.json(
        { ok: false, error: "Invalid finish parameters" },
        { status: 400 }
      );
    }

    const result = this.ctx.storage.transactionSync(() => {
      const row = this.sql.exec(
        `SELECT status, token
         FROM usage
         WHERE op_key = ? AND action = ?`,
        opKey,
        action
      ).toArray()[0];

      // 必须是当前领取成功的操作才能完成
      if (
        !row ||
        row.status !== "processing" ||
        row.token !== token
      ) {
        return false;
      }

      if (success) {
        this.sql.exec(
          `UPDATE usage
           SET status = 'done',
               updated_at = ?,
               token = NULL
           WHERE op_key = ? AND action = ?`,
          Date.now(),
          opKey,
          action
        );
      } else {
        // 失败释放额度
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
      }

      return true;
    });

    return Response.json({
      ok: result
    });
  }
}
