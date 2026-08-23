const FileType = require('file-type')
const store = multer({ dest: '/var/tmp/incoming' })

async function accept (file, reject) {
  const sniffed = await FileType.fromBuffer(file.buffer)
  if (sniffed.mime !== 'image/png') { return reject(new Error('unsupported type')) }
  return store.write(file)
}

module.exports = { accept }
