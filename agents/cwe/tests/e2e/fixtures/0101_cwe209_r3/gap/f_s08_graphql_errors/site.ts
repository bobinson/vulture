export async function graphqlHandler(req, res) {
  const result = await execute({ schema, document: parse(req.body.query) });
  res.json({ data: result.data, errors: result.errors }); // EXPECT: clean ambiguous-graphql
}
