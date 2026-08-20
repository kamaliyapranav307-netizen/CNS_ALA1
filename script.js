(() => {
  const $ = id => document.getElementById(id);
  const stages = document.querySelectorAll('.stage');
  const setStage = (i, state) => {
    stages.forEach((s, idx) => {
      s.classList.remove('active','rsa-stage');
      if (idx < i) s.classList.add('done');
    });
    if (state !== 'done-all') {
      stages[i].classList.add('active');
      if (i === 0 || i === 2 || i === 4) stages[i].classList.add('rsa-stage');
    }
  };

  let publicKey, privateKey;
  let aesKey; // CryptoKey, sender-side, ephemeral per message
  let cipherBytes, ivBytes, encryptedKeyBytes;

  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const b64ToBuf = str => Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;

  function setStatus(el, msg, cls) {
    el.textContent = msg;
    el.className = 'status' + (cls ? ' ' + cls : '');
  }
  function setOut(el, text, glowClass) {
    el.textContent = text;
    el.classList.remove('empty');
    if (glowClass) el.classList.add(glowClass);
  }

  // STEP 1 — Generate RSA-OAEP keypair for the recipient
  $('genKeysBtn').addEventListener('click', async () => {
    setStage(0);
    setStatus($('keyStatus'), 'Generating RSA-2048 keypair…');
    $('genKeysBtn').disabled = true;
    try {
      const pair = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048,
          publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
        true,
        ['encrypt','decrypt']
      );
      publicKey = pair.publicKey;
      privateKey = pair.privateKey;

      const pubRaw = await crypto.subtle.exportKey('spki', publicKey);
      const privRaw = await crypto.subtle.exportKey('pkcs8', privateKey);

      setOut($('pubKeyOut'), b64(pubRaw), 'rsa-glow');
      setOut($('privKeyOut'), b64(privRaw), 'rsa-glow');
      setStatus($('keyStatus'), '✓ RSA-2048 keypair generated. Public key can now be shared to seal messages.', 'ok');

      $('encryptBtn').disabled = false;
    } catch (err) {
      setStatus($('keyStatus'), 'Error generating keys: ' + err.message, 'err');
    } finally {
      $('genKeysBtn').disabled = false;
    }
  });

  // STEP 2 — AES-encrypt the message, then RSA-encrypt the AES key
  $('encryptBtn').addEventListener('click', async () => {
    const text = $('plaintext').value;
    if (!text.trim()) {
      setStatus($('encryptStatus'), 'Type a message first.', 'err');
      return;
    }
    setStage(1);
    setStatus($('encryptStatus'), 'Generating one-time AES-256 key…');
    $('encryptBtn').disabled = true;
    try {
      aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt','decrypt']);

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(text);
      const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);

      cipherBytes = cipherBuf;
      ivBytes = iv;

      setOut($('cipherOut'), b64(cipherBuf), 'aes-glow');
      setOut($('ivOut'), b64(iv), 'aes-glow');
      setStatus($('encryptStatus'), '✓ Message sealed with AES-GCM. Now sealing the AES key with RSA…');

      setStage(2);
      const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
      const encKeyBuf = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawAesKey);
      encryptedKeyBytes = encKeyBuf;

      setOut($('encKeyOut'), b64(encKeyBuf), 'rsa-glow');
      setStage(3);
      setStatus($('encryptStatus'), '✓ Bundle ready to transmit: ciphertext + IV + RSA-sealed AES key. Only the private key holder can open it.', 'ok');

      $('decryptBtn').disabled = false;
    } catch (err) {
      setStatus($('encryptStatus'), 'Error during encryption: ' + err.message, 'err');
    } finally {
      $('encryptBtn').disabled = false;
    }
  });

  // STEP 3 — RSA-decrypt the AES key, then AES-decrypt the message
  $('decryptBtn').addEventListener('click', async () => {
    setStage(4);
    setStatus($('decryptStatus'), 'Unsealing AES key with RSA private key…');
    $('decryptBtn').disabled = true;
    try {
      const rawAesKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedKeyBytes);
      const recoveredAesKey = await crypto.subtle.importKey('raw', rawAesKey, { name: 'AES-GCM' }, false, ['decrypt']);

      const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, recoveredAesKey, cipherBytes);
      const plainText = new TextDecoder().decode(plainBuf);

      setOut($('plainOut'), plainText, 'ok-glow');
      setStatus($('decryptStatus'), '✓ AES key unsealed via RSA, message decrypted via AES. Integrity verified by GCM.', 'ok');
      setStage(5, 'done-all');
      stages.forEach(s => s.classList.add('done'));
    } catch (err) {
      setStatus($('decryptStatus'), 'Decryption failed: ' + err.message, 'err');
    } finally {
      $('decryptBtn').disabled = false;
    }
  });
})();
