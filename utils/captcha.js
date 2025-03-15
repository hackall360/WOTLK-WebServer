const hcaptcha = require('hcaptcha');
const config = require('../config');

async function verifyCaptcha(token) {
  const verification = await hcaptcha.verify(config.captcha.secret, token);
  return verification.success;
}

module.exports = { verifyCaptcha };
