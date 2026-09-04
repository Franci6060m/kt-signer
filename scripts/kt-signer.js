#!/usr/bin/env node
/**
 * Key Transparency signer — the ONE trusted process allowed to write to
 * key_transparency_heads (see schema.sql's big comment above
 * key_transparency_log / key_transparency_heads for the full design).
 *
 * ENV VARS REQUIRED
 *   SUPABASE_DB_URL        — direct Postgres connection string (Supabase
 *                            dashboard → Project Settings → Database →
 *                            Connection string → "URI", NOT the REST URL).
 *   KT_SIGNER_KEY_ID        — must match a key_id already present in
 *                            key_transparency_signer_meta.
 *   KT_SIGNER_PRIVATE_KEY   — base64, the 64-byte tweetnacl secret key.
 *                            Never log this, never let it end up in CI output.
 *
 * Usage:
 *   SUPABASE_DB_URL=... KT_SIGNER_KEY_ID=... KT_SIGNER_PRIVATE_KEY=... \
 *     node scripts/kt-signer.js
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');
const { Client } = require('pg');

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha512(buf) {
  return crypto.createHash('sha512').update(buf).digest();
}

function leafHash(dataBuf) {
  return sha512(Buffer.concat([LEAF_PREFIX, dataBuf]));
}

function nodeHash(left, right) {
  return sha512(Buffer.concat([NODE_PREFIX, left, right]));
}

function splitPoint(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function merkleRoot(leafHashes) {
  const n = leafHashes.length;
  if (n === 0) return sha512(Buffer.alloc(0));
  if (n === 1) return leafHashes[0];
  const k = splitPoint(n);
  const left = merkleRoot(leafHashes.slice(0, k));
  const right = merkleRoot(leafHashes.slice(k, n));
  return nodeHash(left, right);
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n, 0);
  return b;
}

function lengthPrefixed(str) {
  const bytes = Buffer.from(str, 'utf8');
  return Buffer.concat([u32be(bytes.length), bytes]);
}

function deviceLeafBytes({ userId, deviceId, identityKey }) {
  return Buffer.concat([lengthPrefixed(userId), lengthPrefixed(deviceId), lengthPrefixed(identityKey)]);
}

function signedMessageBytes(treeSize, rootHashBuf) {
  const sizeBytes = Buffer.alloc(8);
  sizeBytes.writeBigUInt64BE(BigInt(treeSize));
  return Buffer.concat([sizeBytes, rootHashBuf]);
}

async function runSelfCheck(client) {
  const testVector = { userId: 'kt-selfcheck-user', deviceId: 'kt-selfcheck-device', identityKey: 'kt-selfcheck-identity-key' };
  const localHash = leafHash(deviceLeafBytes(testVector));

  const { rows } = await client.query(
    'select public.kt_leaf_hash($1, $2, $3) as h',
    [testVector.userId, testVector.deviceId, testVector.identityKey],
  );
  const sqlHash = rows[0]?.h;

  if (!sqlHash || Buffer.compare(localHash, sqlHash) !== 0) {
    throw new Error(
      'Self-check failed: local leaf-hash does not match Postgres kt_leaf_hash(). Refusing to sign.',
    );
  }
}

async function main() {
  const dbUrl = process.env.SUPABASE_DB_URL;
  const keyId = process.env.KT_SIGNER_KEY_ID;
  const privateKeyB64 = process.env.KT_SIGNER_PRIVATE_KEY;

  const missing = [];
  if (!dbUrl) missing.push('SUPABASE_DB_URL');
  if (!keyId) missing.push('KT_SIGNER_KEY_ID');
  if (!privateKeyB64) missing.push('KT_SIGNER_PRIVATE_KEY');
  if (missing.length > 0) {
    console.error(`[kt-signer] Missing required env var(s): ${missing.join(', ')}`);
    process.exit(1);
  }

  const secretKey = Buffer.from(privateKeyB64, 'base64');
  if (secretKey.length !== 64) {
    console.error(`[kt-signer] KT_SIGNER_PRIVATE_KEY decoded to ${secretKey.length} bytes, expected 64.`);
    process.exit(1);
  }

  const client = new Client({ connectionString: dbUrl });
  await client.connect();

  try {
    await runSelfCheck(client);
    console.log('[kt-signer] Self-check passed.');

    const { rows: leafRows } = await client.query(
      'select leaf_index, leaf_hash from key_transparency_log order by leaf_index asc',
    );

    if (leafRows.length === 0) {
      console.log('[kt-signer] No leaves yet — nothing to sign.');
      return;
    }

    leafRows.forEach((row, i) => {
      if (Number(row.leaf_index) !== i) {
        throw new Error(`[kt-signer] Gap detected: expected leaf_index ${i}, found ${row.leaf_index}.`);
      }
    });

    const leafHashes = leafRows.map((row) => row.leaf_hash);
    const treeSize = leafHashes.length;
    const rootHash = merkleRoot(leafHashes);

    const { rows: lastHeadRows } = await client.query(
      'select tree_size, root_hash from key_transparency_heads order by tree_size desc limit 1',
    );
    const lastHead = lastHeadRows[0];
    if (lastHead && Number(lastHead.tree_size) === treeSize && Buffer.compare(lastHead.root_hash, rootHash) === 0) {
      console.log(`[kt-signer] Tree unchanged (size ${treeSize}) — nothing new to sign.`);
      return;
    }

    const message = signedMessageBytes(treeSize, rootHash);
    const signature = Buffer.from(nacl.sign.detached(message, secretKey));

    await client.query(
      'insert into key_transparency_heads (tree_size, root_hash, signature, signer_key_id) values ($1, $2, $3, $4)',
      [treeSize, rootHash, signature, keyId],
    );

    console.log(`[kt-signer] Signed head — tree_size=${treeSize}, signer_key_id=${keyId}`);
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('[kt-signer] Failed:', err.message || err);
  process.exit(1);
});
