// Known gap: a `.name` test against a library's validation class. Its message names model
// columns and constraints, but the vendor prefix is not a word the role lexicon can read, so the
// branch is excused like a project's own validation class. Pinned to the observed verdict.
export async function show(req: any, res: any) {
  try {
    await orm.query(req.body.sql);
  } catch (err) {
    if (err.name === "OrmValidationError") {
      res.status(400).json({ error: err.message }); // EXPECT: clean gap-library-validation-class
    }
  }
}
