// ── auth.js — client-side account manager ────────────────────────────────────
// Passwords are never stored. A PBKDF2-derived AES-GCM key encrypts all user
// data at rest in localStorage. The derived key (not the password) is cached
// in sessionStorage for the lifetime of the browser tab.

const Auth = (() => {

  // ── Helpers ────────────────────────────────────────────────────────────────

  function bufToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  function b64ToBuf(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  // ── Crypto ─────────────────────────────────────────────────────────────────

  async function deriveKey(password, saltB64, extractable = false) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64ToBuf(saltB64), iterations: 120000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      extractable,
      ['encrypt', 'decrypt']
    );
  }

  async function hashPassword(password, saltB64) {
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest('SHA-256', enc.encode(password + saltB64));
    return bufToB64(buf);
  }

  async function encryptData(obj, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const cipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))
    );
    return { iv: bufToB64(iv), data: bufToB64(cipher) };
  }

  async function decryptData(ivB64, dataB64, key) {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(ivB64) }, key, b64ToBuf(dataB64)
    );
    return JSON.parse(new TextDecoder().decode(plain));
  }

  // ── Session (tab-scoped, stores key bytes not password) ────────────────────

  async function cacheSession(username, key) {
    const keyBytes = await crypto.subtle.exportKey('raw', key);
    sessionStorage.setItem('pt_session', JSON.stringify({
      username,
      keyB64: bufToB64(keyBytes)
    }));
  }

  async function sessionKey() {
    const s = sessionStorage.getItem('pt_session');
    if (!s) return null;
    const { keyB64 } = JSON.parse(s);
    return crypto.subtle.importKey(
      'raw', b64ToBuf(keyB64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  function getSession() {
    const s = sessionStorage.getItem('pt_session');
    return s ? JSON.parse(s) : null;
  }

  function logout() {
    sessionStorage.removeItem('pt_session');
  }

  async function createAccount(username, password) {
    const key = `pt_acct_${username}`;
    if (localStorage.getItem(key)) throw new Error('Username already taken');

    const salt         = bufToB64(crypto.getRandomValues(new Uint8Array(16)));
    const passwordHash = await hashPassword(password, salt);
    const aesKey       = await deriveKey(password, salt, true);
    const userData     = { highScore: 0, createdAt: new Date().toISOString() };
    const { iv, data } = await encryptData(userData, aesKey);

    localStorage.setItem(key, JSON.stringify({ salt, passwordHash, iv, data }));
    await cacheSession(username, aesKey);
    return userData;
  }

  async function login(username, password) {
    const stored = localStorage.getItem(`pt_acct_${username}`);
    if (!stored) throw new Error('Account not found');

    const acct = JSON.parse(stored);
    const hash = await hashPassword(password, acct.salt);
    if (hash !== acct.passwordHash) throw new Error('Incorrect password');

    const aesKey   = await deriveKey(password, acct.salt, true);
    const userData = await decryptData(acct.iv, acct.data, aesKey);
    await cacheSession(username, aesKey);
    return userData;
  }

  async function getUserData() {
    const session = getSession();
    if (!session) return null;
    const stored = localStorage.getItem(`pt_acct_${session.username}`);
    if (!stored) return null;
    const acct = JSON.parse(stored);
    const key  = await sessionKey();
    return decryptData(acct.iv, acct.data, key);
  }

  async function saveUserData(data) {
    const session = getSession();
    if (!session) return false;
    const storeKey = `pt_acct_${session.username}`;
    const acct     = JSON.parse(localStorage.getItem(storeKey));
    if (!acct) return false;
    const key      = await sessionKey();
    const enc      = await encryptData(data, key);
    localStorage.setItem(storeKey, JSON.stringify({ ...acct, ...enc }));
    return true;
  }

  return { getSession, logout, createAccount, login, getUserData, saveUserData };
})();
