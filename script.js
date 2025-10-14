

/* script.js */
const $ = id => document.getElementById(id);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const themeToggle = document.querySelector('.theme-toggle');
const root = document.body;

function blockExternalRequests() {
    const localOnlyMessage = 'Network requests are disabled for this local-only tool.';

    if (window.fetch) {
        window.fetch = async () => {
            throw new Error(localOnlyMessage);
        };
    }

    if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
        const originalXhrOpen = window.XMLHttpRequest.prototype.open;
        window.XMLHttpRequest.prototype.open = function (method, url) {
            if (typeof url === 'string' && /^(https?:|\/\/)/i.test(url)) {
                throw new Error(localOnlyMessage);
            }
            return originalXhrOpen.apply(this, arguments);
        };
    }

    if (window.navigator && window.navigator.sendBeacon) {
        window.navigator.sendBeacon = () => false;
    }
}

blockExternalRequests();

function applyTheme(isDark) {
    root.classList.toggle('dark-theme', isDark);
    root.classList.toggle('light-theme', !isDark);
    themeToggle.classList.toggle('is-dark', isDark);

    const label = themeToggle.querySelector('.theme-toggle__label');
    const icon = themeToggle.querySelector('.theme-toggle__icon');
    label.textContent = isDark ? 'Dark' : 'Light';
    icon.textContent = isDark ? '🌙' : '☀️';
    themeToggle.setAttribute('aria-checked', String(isDark));
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
}

function triggerToggleAnimation() {
    themeToggle.classList.remove('is-changing');
    void themeToggle.offsetWidth;
    themeToggle.classList.add('is-changing');
    window.setTimeout(() => themeToggle.classList.remove('is-changing'), 350);
}

const savedTheme = localStorage.getItem('theme');
applyTheme(savedTheme === 'dark');

themeToggle.addEventListener('click', () => {
    const isDark = !root.classList.contains('dark-theme');
    triggerToggleAnimation();
    applyTheme(isDark);
});

const toBase64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromBase64 = b64 => {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
};

function setStatus(elementId, message, isError = false) {
    const el = $(elementId);
    el.textContent = message;
    el.className = `status${isError ? ' error' : ' success'}`;
}

async function deriveKey(passphrase, salt) {
    const passKey = await crypto.subtle.importKey(
        'raw', textEncoder.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: textEncoder.encode(salt),
            iterations: 250000,
            hash: 'SHA-256'
        },
        passKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptText(plain, passphrase, salt) {
    const key = await deriveKey(passphrase, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        textEncoder.encode(plain)
    );
    const combined = new Uint8Array(iv.length + cipher.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipher), iv.length);
    return toBase64(combined.buffer);
}

async function decryptText(b64, passphrase, salt) {
    const combined = new Uint8Array(fromBase64(b64));
    const iv = combined.slice(0, 12);
    const cipher = combined.slice(12);
    const key = await deriveKey(passphrase, salt);
    const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        cipher
    );
    return textDecoder.decode(plain);
}

async function copyText(textareaId) {
    const value = $(textareaId).value;
    if (!value) return;
    await navigator.clipboard.writeText(value);
}

$('encryptBtn').onclick = async () => {
    const text = $('plaintext').value.trim();
    const pass = $('passphrase').value;
    const salt = $('salt').value.trim();

    if (!text || !pass || !salt) {
        setStatus('encryptStatus', 'Please complete all fields before encrypting.', true);
        return;
    }

    try {
        const encrypted = await encryptText(text, pass, salt);
        $('ciphertext').value = encrypted;
        setStatus('encryptStatus', 'Encryption completed successfully.');
    } catch (error) {
        console.error(error);
        setStatus('encryptStatus', 'Encryption failed. Please try again.', true);
    }
};

$('decryptBtn').onclick = async () => {
    const cipher = $('cipherToDecrypt').value.trim();
    const pass = $('passphrase2').value;
    const salt = $('salt2').value.trim();

    if (!cipher || !pass || !salt) {
        setStatus('decryptStatus', 'Please complete all fields before decrypting.', true);
        return;
    }

    try {
        const decrypted = await decryptText(cipher, pass, salt);
        $('decrypted').value = decrypted;
        setStatus('decryptStatus', 'Decryption completed successfully.');
    } catch (error) {
        console.error(error);
        setStatus('decryptStatus', 'Decryption failed. Check your passphrase and salt.', true);
    }
};

$('generateSalt').onclick = () => {
    const s = crypto.getRandomValues(new Uint8Array(12));
    const hex = Array.from(s).map(b => b.toString(16).padStart(2, '0')).join('');
    $('salt').value = hex;
    $('salt2').value = hex;
    setStatus('encryptStatus', 'A new salt was generated.');
};

$('clearEncryptBtn').onclick = () => {
    $('plaintext').value = '';
    $('passphrase').value = '';
    $('salt').value = '';
    $('ciphertext').value = '';
    setStatus('encryptStatus', '');
};

$('clearDecryptBtn').onclick = () => {
    $('cipherToDecrypt').value = '';
    $('passphrase2').value = '';
    $('salt2').value = '';
    $('decrypted').value = '';
    setStatus('decryptStatus', '');
};

$('copyEncryptBtn').onclick = async () => {
    await copyText('ciphertext');
    setStatus('encryptStatus', 'Ciphertext copied to clipboard.');
};

$('copyDecryptBtn').onclick = async () => {
    await copyText('decrypted');
    setStatus('decryptStatus', 'Decrypted text copied to clipboard.');
};