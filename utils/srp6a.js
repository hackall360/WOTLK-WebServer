const crypto = require('crypto');

function generateVerifier(username, password) {
  const N_hex = '894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7';
  const g = 7;

  // Salt generation
  const salt = crypto.randomBytes(32).toString('hex');

  // Username/password hashing
  const hash = crypto.createHash('sha1').update(username.toUpperCase() + ':' + password).digest('hex');

  // Use external bigint-mod-arith to bypass Node/OpenSSL restriction:
  const bigintModArith = require('bigint-mod-arith');

  const N = BigInt('0x' + N_hex);
  const x = BigInt('0x' + hash);

  // SRP6 verifier = g^x mod N
  const verifier = bigintModArith.modPow(g, x, N).toString(16);

  return {
    salt,
    verifier
  };
}

module.exports = { generateVerifier };
