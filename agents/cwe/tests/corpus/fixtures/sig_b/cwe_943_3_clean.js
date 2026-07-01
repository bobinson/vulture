// Analytics aggregation route.
// Safe: field name resolved through a fixed whitelist before building the pipeline.
function aggregate(req, collection) {
  const allowed = { day: "$day", region: "$region" };
  const groupBy = allowed[req.params.field] || "$day";
  return collection.aggregate([{ $group: { _id: groupBy, count: { $sum: 1 } } }]);
}
