// pins: a destructured parameter leaf named with a request word ({ params }) is a request source by its own name (R-E)
export async function GET(_, { params }) {
  return fs.promises.readFile("/srv/docs/" + params.slug);
}
