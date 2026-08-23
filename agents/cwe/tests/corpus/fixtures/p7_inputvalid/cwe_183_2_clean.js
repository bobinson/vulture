const store = multer({ dest: '/var/tmp/avatars' })

const allowedMimeTypes = ['image/png', 'image/webp']

function accept (mime) {
  return allowedMimeTypes.indexOf(mime) !== -1
}

module.exports = { store, accept }
