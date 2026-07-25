# 0050 — Rollback plan

## Triggers

- Layer returns wrong CWE for a class of findings → fix the JSON; no
  code change required.
- Router-layer integration produces zero findings where 0049
  produced >0 → switch `server.New` to pass nil layer; identical to
  0049.
- Per-plugin manifest mapping causes panics → wrap Layer.Normalize
  in a `defer recover` and return empty. Forward fix.
- Full revert: `git revert <0050-merge-sha>` — no DB migration to
  undo; no embedded data persisted.

## Confidence

Strict-addition design (router built without a layer == 0049) means
the blast radius is small. The system-data JSON is the only piece
that needs upstream care, and it's data, not code.
