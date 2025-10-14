

/* script.js */
const $ = id => document.getElementById(id);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();


const toBase64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromBase64 = b64 => {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
};


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


$('encryptBtn').onclick = async () => {
    const text = $('plaintext').value;
    const pass = $('passphrase').value;
    const salt = $('salt').value;
    if (!text || !pass || !salt) return alert('Please fill in all fields');
    $('ciphertext').value = await encryptText(text, pass, salt);
};


$('decryptBtn').onclick = async () => {
    const cipher = $('cipherToDecrypt').value;
    const pass = $('passphrase2').value;
    const salt = $('salt2').value;
    if (!cipher || !pass || !salt) return alert('Please fill in all fields');
    try {
        $('decrypted').value = await decryptText(cipher, pass, salt);
    } catch {
        alert('Decryption failed. Check your passphrase/salt.');
    }
};


$('generateSalt').onclick = () => {
    const s = crypto.getRandomValues(new Uint8Array(12));
    const hex = Array.from(s).map(b => b.toString(16).padStart(2, '0')).join('');
    $('salt').value = hex;
    $('salt2').value = hex;
};