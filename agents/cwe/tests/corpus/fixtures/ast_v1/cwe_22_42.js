// pins: a fetch-API request object - new URL(req.url).searchParams.get("f") stays external through rule 15 and reaches fs.readFile
export async function handler(req) {
  const name = new URL(req.url).searchParams.get("f");
  return fs.promises.readFile("/srv/docs/" + name);
}
