const unzipper = require('unzipper')

async function unpackArchive (buffer) {
  const directory = await unzipper.Open.buffer(buffer)
  for (const entry of directory.files) {
    const fileName = path.basename(entry.path)
    await pipeline(entry.stream(), fs.createWriteStream('storage/incoming/' + fileName))
  }
}

module.exports = { unpackArchive }
