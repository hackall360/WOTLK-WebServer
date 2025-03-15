/********************************************************************
 * public/js/login.js
 *
 * Example: an extremely simplified or “mock” SRP client flow in the
 * browser. For real SRP in the browser, you must bundle `srp6a.js`
 * or use a separate SRP library (like `srp6a-client`) so you can
 * compute A and M1 correctly. This stub is only to show how the
 * request structure works.
 ********************************************************************/

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('loginForm');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    if (!username || !password) {
      alert('Please enter username & password');
      return;
    }

    try {
      // Stage 1: /login/init
      const initResp = await fetch('/login/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });
      const initData = await initResp.json();
      if (!initData.success) {
        alert('Login init error: ' + initData.error);
        return;
      }

      // In a real SRP client, we’d now compute A and M1 from salt, B, username, password
      // For demonstration, we'll just send dummy data:
      // A = "deadbeef", M1 = "cafebabe"
      // 
      // In reality, you must do:
      //   A = g^a mod N
      //   M1 = SHA1( (H(N) ^ H(g)), H(username), salt, A, B, K )
      // … using the same logic as srp6a.js
      const Ahex = 'deadbeef';
      const M1hex = 'cafebabe';

      // Stage 2: /login/proof
      const proofResp = await fetch('/login/proof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          A: Ahex,
          M1: M1hex
        })
      });
      const proofData = await proofResp.json();
      if (proofData.success) {
        // Logged in!
        window.location.href = '/account';
      } else {
        alert('Login failed: ' + proofData.error);
      }

    } catch (err) {
      console.error('Login error:', err);
      alert('Login error, see console');
    }
  });
});
