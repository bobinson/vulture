// Analytics aggregation route.
// CWE-943: mapReduce map function assembled from untrusted input.
function aggregate(req, collection) {
  const groupBy = req.params.field;
  return collection.mapReduce("function(){ emit(this." + groupBy + ", 1); }", reducer, {});
}
