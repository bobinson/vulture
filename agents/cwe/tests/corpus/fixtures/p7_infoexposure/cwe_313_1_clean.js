const fs = require('fs')

function persistPreferences (theme) {
  fs.writeFileSync('/etc/app/state.json', JSON.stringify({ theme: theme }))
}

module.exports = { persistPreferences }
