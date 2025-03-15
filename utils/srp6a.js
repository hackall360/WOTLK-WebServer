/********************************************************************
 * utils/srp6a.js
 *
 * SRP6a Implementation in plain JavaScript using Node.js native
 * BigInt and crypto. This version uses an iterative modular 
 * exponentiation algorithm (exponentiation by squaring) to prevent
 * "Maximum BigInt size exceeded" errors by never computing base^exp
 * in full.
 ********************************************************************/

const crypto = require('crypto');

/**
 * TrinityCore 3.3.5 default SRP6 parameters (256-bit N, g=7).
 * k is precomputed as k = SHA1(N || g).
 */
const N_HEX = '894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7';
const G_HEX = '07';
const K_HEX = '3C297A37A70AFD45A68C8F4E25A831BCBC8BB9F5'; // SHA1(N||g)

const N = BigInt('0x' + N_HEX);
const g = BigInt('0x' + G_HEX);
const k = BigInt('0x' + K_HEX);

/**
 * Convert between Buffer and BigInt.
 */
function bufToBigInt(buf) {
  return BigInt('0x' + buf.toString('hex'));
}

function bigIntToBuf(bi) {
  let hex = bi.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

/**
 * Constant-time comparison of two Buffers.
 */
function constantTimeEq(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * SHA1 hash of concatenated Buffers.
 */
function sha1(...buffers) {
  const hash = crypto.createHash('sha1');
  for (const buf of buffers) {
    hash.update(buf);
  }
  return hash.digest();
}

/**
 * Reduce an exponent modulo (N - 1) to keep it small.
 */
function safeExponent(x) {
  return x % (N - 1n);
}

/**
 * Iterative modular exponentiation: computes (base^exp) mod m 
 * without ever constructing base^exp in full.
 */
function modPow(base, exp, m) {
  let e = safeExponent(exp);
  let result = 1n;
  base = base % m;
  while (e > 0n) {
    if (e % 2n === 1n) {
      result = (result * base) % m;
    }
    e = e / 2n;
    base = (base * base) % m;
  }
  return result;
}

/**
 * SRPEngine: Core math for SRP6a.
 */
class SRPEngine {
  /**
   * computeX(username, password, salt):
   *   x = SHA1( salt || SHA1( upper(username:password) ) )
   */
  static computeX(username, password, salt) {
    const I = Buffer.from(`${username.toUpperCase()}:${password.toUpperCase()}`, 'utf8');
    const inner = sha1(I);
    return bufToBigInt(sha1(salt, inner));
  }

  /**
   * computeV(x): v = g^(x mod (N−1)) mod N.
   */
  static computeV(x) {
    return modPow(g, x, N);
  }

  /**
   * computeA(a): A = g^(a mod (N−1)) mod N.
   */
  static computeA(a) {
    return modPow(g, a, N);
  }

  /**
   * computeB(b, v): B = (k*v + g^(b mod (N−1))) mod N.
   */
  static computeB(b, v) {
    const term1 = (k * v) % N;
    const term2 = modPow(g, b, N);
    return (term1 + term2) % N;
  }

  /**
   * computeU(A, B): u = SHA1( A || B ).
   */
  static computeU(A, B) {
    return bufToBigInt(sha1(bigIntToBuf(A), bigIntToBuf(B))) % N;
  }

  /**
   * computeClientS(a, B, x, u):
   *   S = (B - k*g^x)^(a + u*x) mod N.
   */
  static computeClientS(a, B, x, u) {
    const gx = modPow(g, x, N);
    const kgx = (k * gx) % N;
    const base = (B + N - kgx) % N; // (B - k*g^x) mod N
    return modPow(base, a + u * x, N);
  }

  /**
   * computeServerS(b, A, v, u):
   *   S = (A * v^u)^b mod N.
   */
  static computeServerS(b, A, v, u) {
    const term = (A * modPow(v, u, N)) % N;
    return modPow(term, b, N);
  }

  /**
   * computeK(S): K = SHA1( S ) as a Buffer.
   */
  static computeK(S) {
    return sha1(bigIntToBuf(S));
  }

  /**
   * computeClientProof(username, salt, A, B, K):
   *   M1 = SHA1( (H(N) XOR H(g)), H(username), salt, A, B, K ).
   */
  static computeClientProof(username, salt, A, B, K) {
    const HN = sha1(bigIntToBuf(N));
    const Hg = sha1(bigIntToBuf(g));
    const HU = sha1(Buffer.from(username.toUpperCase(), 'utf8'));
    const xor = Buffer.alloc(20);
    for (let i = 0; i < 20; i++) {
      xor[i] = HN[i] ^ Hg[i];
    }
    return sha1(xor, HU, salt, bigIntToBuf(A), bigIntToBuf(B), K);
  }

  /**
   * computeServerProof(A, M1, K): M2 = SHA1(A, M1, K).
   */
  static computeServerProof(A, M1, K) {
    return sha1(bigIntToBuf(A), M1, K);
  }
}

/**
 * SRPClient class.
 * For registration, computing the verifier;
 * For login, computing ephemeral values and client proof.
 */
class SRPClient {
  constructor() {
    this.state = 'init';
  }

  /**
   * generateSalt – produces a random salt.
   */
  generateSalt(len = 16) {
    return crypto.randomBytes(len);
  }

  /**
   * computeVerifier – returns a Buffer verifier.
   */
  computeVerifier(username, password, salt) {
    const x = SRPEngine.computeX(username, password, salt);
    const v = SRPEngine.computeV(x);
    return bigIntToBuf(v);
  }

  /**
   * setCredentials – sets username, password and salt,
   * and computes ephemeral A.
   */
  setCredentials(username, password, saltBuf) {
    this.username = username;
    this.saltBuf = saltBuf;
    this.xVal = SRPEngine.computeX(username, password, saltBuf);
    this.aVal = bufToBigInt(crypto.randomBytes(32)); // 32-byte random exponent
    this.AVal = SRPEngine.computeA(this.aVal);
    this.state = 'credentials';
  }

  /**
   * setServerKey – accepts server's B (as a Buffer) and computes session key and proof.
   */
  setServerKey(BBuf) {
    if (this.state !== 'credentials') throw new Error("SRPClient state must be 'credentials'");
    this.BVal = bufToBigInt(BBuf);
    const A = this.AVal;
    const u = SRPEngine.computeU(A, this.BVal);
    if (this.BVal % N === 0n) {
      throw new Error("Invalid server public key (B is 0 mod N)");
    }
    if (u === 0n) {
      throw new Error("Computed u is zero; aborting");
    }
    const S = SRPEngine.computeClientS(this.aVal, this.BVal, this.xVal, u);
    this.KBuf = SRPEngine.computeK(S);
    this.M1Buf = SRPEngine.computeClientProof(this.username, this.saltBuf, A, this.BVal, this.KBuf);
    this.serverProof = SRPEngine.computeServerProof(A, this.M1Buf, this.KBuf);
    this.state = 'computed';
  }

  /**
   * getPublicKey – returns A as a Buffer.
   */
  getPublicKey() {
    if (this.state !== 'credentials' && this.state !== 'computed') {
      throw new Error("SRPClient not ready for public key");
    }
    return bigIntToBuf(this.AVal);
  }

  /**
   * getProof – returns client proof M1 as a Buffer.
   */
  getProof() {
    if (this.state !== 'computed') throw new Error("SRPClient proof not computed");
    return this.M1Buf;
  }

  /**
   * validateProof – compares server's M2 proof with expected value.
   */
  validateProof(M2Buf) {
    return constantTimeEq(M2Buf, this.serverProof);
  }
}

/**
 * SRPServer class.
 * Used to verify client proofs during login.
 */
class SRPServer {
  constructor() {
    this.state = 'init';
  }

  /**
   * setCredentials – sets username, verifier and salt.
   */
  setCredentials(username, verifierBuf, saltBuf) {
    this.username = username;
    this.saltBuf = saltBuf;
    this.verifier = bufToBigInt(verifierBuf);
    this.b = bufToBigInt(crypto.randomBytes(32)); // server secret exponent
    this.B = SRPEngine.computeB(this.b, this.verifier);
    this.state = 'ready';
  }

  /**
   * getPublicKey – returns B as a Buffer.
   */
  getPublicKey() {
    if (this.state !== 'ready') throw new Error("SRPServer not ready");
    return bigIntToBuf(this.B);
  }

  /**
   * checkClientProof – validates client's M1 given A and M1 (as hex strings).
   * Returns an object { ok, M2 } on success.
   */
  checkClientProof(A_hex, M1_hex) {
    if (this.state !== 'ready') {
      return { ok: false, error: "SRPServer not ready" };
    }
    const A = BigInt('0x' + A_hex);
    const M1 = Buffer.from(M1_hex, 'hex');
    const u = SRPEngine.computeU(A, this.B);
    if (A % N === 0n) {
      return { ok: false, error: "Invalid client public key (A is 0 mod N)" };
    }
    if (u === 0n) {
      return { ok: false, error: "Computed u is 0" };
    }
    const S = SRPEngine.computeServerS(this.b, A, this.verifier, u);
    const K = SRPEngine.computeK(S);
    const M1_expected = SRPEngine.computeClientProof(this.username, this.saltBuf, A, this.B, K);
    if (!constantTimeEq(M1_expected, M1)) {
      return { ok: false, error: "Client proof mismatch" };
    }
    const M2 = SRPEngine.computeServerProof(A, M1, K);
    return { ok: true, M2 };
  }
}

module.exports = {
  SRPClient,
  SRPServer,
  constantTimeEq
};

if (typeof window !== 'undefined') {
    window.SRPClient = SRPClient;
    window.SRPServer = SRPServer;
  }