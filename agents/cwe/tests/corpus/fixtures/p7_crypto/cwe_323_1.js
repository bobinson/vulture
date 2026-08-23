const crypto = require('crypto');

function sealPayload(key, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, Buffer.alloc(12));
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}
