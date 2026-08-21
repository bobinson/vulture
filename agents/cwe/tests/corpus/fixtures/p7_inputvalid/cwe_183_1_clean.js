const store = multer({ dest: '/var/tmp/incoming' })

const allowedExtensions = ['.png', '.jpg', '.gif']

function accept (name) {
  return allowedExtensions.some((e) => name.endsWith(e))
}

module.exports = { store, accept }
