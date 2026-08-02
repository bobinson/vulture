const store = multer({ dest: '/var/tmp/incoming' })

function accept (file, reject) {
  const ext = file.originalname.split('.').pop()
  if (ext !== 'png') { return reject(new Error('unsupported type')) }
  return store.write(file)
}

module.exports = { accept }
