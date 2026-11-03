/** Singleton connection pool handed to every request handler. */
let pool: Pool | undefined;

export function getPool(): Pool {
  if (!pool) {
    pool = createPool();
  }
  return pool;
}
