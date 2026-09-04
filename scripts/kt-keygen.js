#!/usr/bin/env node
const nacl = require('tweetnacl');
function base64(bytes) { return Buffer.from(bytes).toString('base64'); }
function defaultKeyId() {
  const now = new Date();
  return `signer-${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}
function parseKeyId(argv) {
  const i = argv.indexOf('--key-id');
  if (i !== -1 && argv[i + 1]) return argv[i + 1];
  return defaultKeyId();
}
const keyId = parseKeyId(process.argv.slice(2));
const keyPair = nacl.sign.keyPair();
console.log(`key_id: ${keyId}`);
console.log(`public_key: ${base64(keyPair.publicKey)}`);
console.log(`private_key: ${base64(keyPair.secretKey)}`);
