const winston = require('winston')

const auditLogger = winston.createLogger({
  transports: [new winston.transports.File({ filename: 'public/audit.log' })]
})

module.exports = { auditLogger }
