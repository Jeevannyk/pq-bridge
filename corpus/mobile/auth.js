const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// device binding keys
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

function sessionToken(user) {
  return jwt.sign({ sub: user }, privateKey, { algorithm: 'ES256', expiresIn: '5m' });
}

function deviceDigest(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function handshake() {
  const ecdh = crypto.createECDH('prime256v1');
  return ecdh.generateKeys();
}

module.exports = { sessionToken, deviceDigest, handshake, publicKey };
