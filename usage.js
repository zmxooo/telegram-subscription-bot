export class UsageGuard {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS usage (
      op_key TEXT NOT NULL,
      action TEXT NOT NULL,
      status TEXT NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (op_key, action)
    )`);
  }
  async fetch(request) {
    const body = await request.json();
    const { opKey, action, mode } = body;
    if (!opKey || !action) return Response.json({ok:false}, {status:400});
    if (mode === "claim") {
      const result = this.ctx.storage.transactionSync(() => {
        const row = this.sql.exec("SELECT status FROM usage WHERE op_key=? AND action=?", opKey, action).one();
        if (row && (row.status === "done" || row.status === "processing")) return false;
        this.sql.exec("INSERT OR REPLACE INTO usage(op_key,action,status,updated_at) VALUES(?,?,?,?)", opKey, action, "processing", Date.now());
        return true;
      });
      return Response.json({ok:result});
    }
    if (mode === "finish") {
      this.ctx.storage.transactionSync(() => {
        if (body.success) this.sql.exec("UPDATE usage SET status='done',updated_at=? WHERE op_key=? AND action=?", Date.now(), opKey, action);
        else this.sql.exec("DELETE FROM usage WHERE op_key=? AND action=? AND status='processing'", opKey, action);
      });
      return Response.json({ok:true});
    }
    return Response.json({ok:false}, {status:400});
  }
}
