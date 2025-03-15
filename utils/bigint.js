// utils/bigint.js
class BigInt {
    constructor(value) {
      this.value = global.BigInt(value);
    }
  
    static fromBuffer(buf) {
      return new BigInt('0x' + buf.toString('hex'));
    }
  
    toBuffer() {
      let hex = this.value.toString(16);
      if (hex.length % 2) hex = '0' + hex;
      return Buffer.from(hex, 'hex');
    }
  
    mod(n) {
      return new BigInt(this.value % n.value);
    }
  
    modPow(exp, n) {
      return new BigInt(this.value ** exp.value % n.value);
    }
  
    add(n) {
      return new BigInt(this.value + n.value);
    }
  
    subtract(n) {
      return new BigInt(this.value - n.value);
    }
  
    multiply(n) {
      return new BigInt(this.value * n.value);
    }
  
    eq(n) {
      return this.value === n.value;
    }
  }
  
  module.exports = { BigInt };