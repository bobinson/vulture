const winston = require('winston')

const auditLogger = winston.createLogger({
  transports: [new winston.transports.File({ filename: 'var/log/audit.log' })]
})

module.exports = { auditLogger }
