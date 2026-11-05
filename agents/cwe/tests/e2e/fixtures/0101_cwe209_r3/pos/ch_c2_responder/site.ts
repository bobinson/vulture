export const ledgerHandlers = {
  "ledger.read": async ({ params, respond }: any) => {
    try {
      respond(true, await store.read(params.id));
    } catch (err) {
      respond(false, undefined, { code: "UNAVAILABLE", message: String(err) }); // EXPECT: finding tp-C2
    }
  },
};
