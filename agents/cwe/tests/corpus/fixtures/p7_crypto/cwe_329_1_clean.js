const crypto = require('crypto');

function encryptRecord(keyHex, plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);
  return Buffer.concat([iv, cipher.update(plaintext, 'utf8'), cipher.final()]);
}
