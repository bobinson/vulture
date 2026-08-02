const crypto = require('crypto');

function encryptRecord(key, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16));
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
}
