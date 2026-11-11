// cifra.js — núcleo de criptografia compartilhado entre o mod (Claude Code) e a
// página de resposta (celular). Só usa JavaScript puro: o ambiente dos mods não
// tem AES nem ECDH, então tudo é construído sobre SHA-256:
//
//   chave mestra = PBKDF2-HMAC-SHA256(código de pareamento, sal fixo, 100 000)
//   chaves       = HMAC(mestra, "enc") / HMAC(mestra, "mac") / HMAC(mestra, "topico")
//   cifra        = fluxo em modo contador: bloco_i = HMAC(k_enc, nonce || i)
//   autenticação = HMAC(k_mac, contexto || nonce || cifrado)   (encrypt-then-MAC)
//
// Envelope (base64url): versão(1) || nonce(16) || cifrado || tag(32).
// O "contexto" amarra a mensagem ao seu propósito ("q:<id>" pergunta, "r:<id>" resposta).

const VERSAO = 1
const SAL = 'claude-celular-v1'
export const ITERACOES = 100000
const ALFABETO = '0123456789ABCDEFGHJKMNPQRSTVWXYZ' // base32 sem I, L, O, U

// ---------- SHA-256 ----------

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

function compress(state, block, off, w) {
  for (let i = 0; i < 16; i++) {
    const j = off + i * 4
    w[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]
  }
  for (let i = 16; i < 64; i++) {
    const a = w[i - 15]
    const b = w[i - 2]
    const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)
    const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10)
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0
  }
  let a = state[0], b = state[1], c = state[2], d = state[3]
  let e = state[4], f = state[5], g = state[6], h = state[7]
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))
    const ch = (e & f) ^ (~e & g)
    const t1 = (h + S1 + ch + K[i] + w[i]) | 0
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
    const maj = (a & b) ^ (a & c) ^ (b & c)
    const t2 = (S0 + maj) | 0
    h = g; g = f; f = e; e = (d + t1) | 0
    d = c; c = b; b = a; a = (t1 + t2) | 0
  }
  state[0] = (state[0] + a) | 0; state[1] = (state[1] + b) | 0
  state[2] = (state[2] + c) | 0; state[3] = (state[3] + d) | 0
  state[4] = (state[4] + e) | 0; state[5] = (state[5] + f) | 0
  state[6] = (state[6] + g) | 0; state[7] = (state[7] + h) | 0
}

export function sha256(data) {
  const state = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ])
  const w = new Int32Array(64)
  const len = data.length
  const full = Math.floor(len / 64) * 64
  for (let off = 0; off < full; off += 64) compress(state, data, off, w)
  const restLen = len - full
  const tailLen = restLen < 56 ? 64 : 128
  const tail = new Uint8Array(tailLen)
  tail.set(data.subarray(full))
  tail[restLen] = 0x80
  const bits = len * 8
  const hi = Math.floor(bits / 0x100000000)
  const lo = bits >>> 0
  tail[tailLen - 8] = (hi >>> 24) & 0xff
  tail[tailLen - 7] = (hi >>> 16) & 0xff
  tail[tailLen - 6] = (hi >>> 8) & 0xff
  tail[tailLen - 5] = hi & 0xff
  tail[tailLen - 4] = (lo >>> 24) & 0xff
  tail[tailLen - 3] = (lo >>> 16) & 0xff
  tail[tailLen - 2] = (lo >>> 8) & 0xff
  tail[tailLen - 1] = lo & 0xff
  for (let off = 0; off < tailLen; off += 64) compress(state, tail, off, w)
  const out = new Uint8Array(32)
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (state[i] >>> 24) & 0xff
    out[i * 4 + 1] = (state[i] >>> 16) & 0xff
    out[i * 4 + 2] = (state[i] >>> 8) & 0xff
    out[i * 4 + 3] = state[i] & 0xff
  }
  return out
}

// ---------- HMAC / PBKDF2 ----------

export function hmac(key, msg) {
  let k = key.length > 64 ? sha256(key) : key
  const ipad = new Uint8Array(64 + msg.length)
  const opad = new Uint8Array(64 + 32)
  for (let i = 0; i < 64; i++) {
    const b = i < k.length ? k[i] : 0
    ipad[i] = b ^ 0x36
    opad[i] = b ^ 0x5c
  }
  ipad.set(msg, 64)
  opad.set(sha256(ipad), 64)
  return sha256(opad)
}

export function pbkdf2(password, salt, iterations) {
  const s = new Uint8Array(salt.length + 4)
  s.set(salt)
  s[salt.length + 3] = 1 // bloco 1: basta para 32 bytes
  let u = hmac(password, s)
  const out = u.slice()
  for (let i = 1; i < iterations; i++) {
    u = hmac(password, u)
    for (let j = 0; j < 32; j++) out[j] ^= u[j]
  }
  return out
}

// ---------- utilitários ----------

const enc = new TextEncoder()
const dec = new TextDecoder()
export const utf8 = s => enc.encode(s)
export const fromUtf8 = b => dec.decode(b)

export function concat(...parts) {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export function toHex(b) {
  let s = ''
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0')
  return s
}

export function fromHex(s) {
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16)
  return out
}

export function toB64url(b) {
  let bin = ''
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fromB64url(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function iguais(a, b) {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]
  return d === 0
}

export function aleatorio(n) {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

// ---------- código de pareamento ----------

/** 12 caracteres (60 bits), exibido como XXXX-XXXX-XXXX. */
export function novoCodigo() {
  const b = aleatorio(12)
  let s = ''
  for (let i = 0; i < 12; i++) s += ALFABETO[b[i] & 31]
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`
}

/** Normaliza o que a pessoa digitou: maiúsculas, sem traços/espaços, O→0, I/L→1. */
export function normalizarCodigo(c) {
  const s = String(c || '')
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V')
  if (s.length !== 12) return undefined
  for (const ch of s) if (!ALFABETO.includes(ch)) return undefined
  return s
}

/** Deriva a chave mestra do código (lento de propósito: ~0,5 s). */
export function mestraDoCodigo(codigo) {
  const c = normalizarCodigo(codigo)
  if (!c) throw new Error('código inválido')
  return pbkdf2(utf8(c), utf8(SAL), ITERACOES)
}

/** Chaves e tópico a partir da mestra. */
export function chaves(mestra) {
  return {
    enc: hmac(mestra, utf8('enc')),
    mac: hmac(mestra, utf8('mac')),
    topico: `cc-${toHex(hmac(mestra, utf8('topico'))).slice(0, 24)}`,
  }
}

// ---------- envelope ----------

function fluxo(kEnc, nonce, n) {
  const out = new Uint8Array(n)
  const ctr = new Uint8Array(4)
  for (let i = 0, o = 0; o < n; i++, o += 32) {
    ctr[0] = (i >>> 24) & 0xff
    ctr[1] = (i >>> 16) & 0xff
    ctr[2] = (i >>> 8) & 0xff
    ctr[3] = i & 0xff
    const blk = hmac(kEnc, concat(nonce, ctr))
    out.set(blk.subarray(0, Math.min(32, n - o)), o)
  }
  return out
}

/** Cifra e assina bytes; devolve o envelope binário (versão || nonce || cifrado || tag). */
export function selarCru(k, contexto, claro) {
  const nonce = aleatorio(16)
  const ks = fluxo(k.enc, nonce, claro.length)
  const cifrado = new Uint8Array(claro.length)
  for (let i = 0; i < claro.length; i++) cifrado[i] = claro[i] ^ ks[i]
  const tag = hmac(k.mac, concat(utf8(contexto), new Uint8Array([0]), nonce, cifrado))
  return concat(new Uint8Array([VERSAO]), nonce, cifrado, tag)
}

/** Cifra e assina bytes (uma imagem, por exemplo) para o `contexto`; envelope em base64url. */
export function selarBytes(k, contexto, claro) {
  return toB64url(selarCru(k, contexto, claro))
}

/**
 * Confere e decifra bytes; aceita o envelope em base64url (texto) ou binário
 * (Uint8Array). Devolve undefined se a assinatura ou o contexto não baterem.
 */
export function abrirBytes(k, contexto, envelope) {
  let b
  if (envelope instanceof Uint8Array) {
    b = envelope[0] === VERSAO ? envelope : undefined
    // binário que na verdade é texto base64url (anexos antigos)
    if (!b) envelope = fromUtf8(envelope)
  }
  if (!b) {
    try {
      b = fromB64url(String(envelope || '').trim())
    } catch {
      return undefined
    }
  }
  if (b.length < 1 + 16 + 32 || b[0] !== VERSAO) return undefined
  const nonce = b.subarray(1, 17)
  const cifrado = b.subarray(17, b.length - 32)
  const tag = b.subarray(b.length - 32)
  const esperado = hmac(k.mac, concat(utf8(contexto), new Uint8Array([0]), nonce, cifrado))
  if (!iguais(tag, esperado)) return undefined
  const ks = fluxo(k.enc, nonce, cifrado.length)
  const claro = new Uint8Array(cifrado.length)
  for (let i = 0; i < cifrado.length; i++) claro[i] = cifrado[i] ^ ks[i]
  return claro
}

/** Cifra e assina `obj` (JSON) para o `contexto`. */
export function selar(k, contexto, obj) {
  return selarBytes(k, contexto, utf8(JSON.stringify(obj)))
}

/** Confere e decifra JSON; devolve undefined se a assinatura ou o contexto não baterem. */
export function abrir(k, contexto, envelope) {
  const claro = abrirBytes(k, contexto, envelope)
  if (!claro) return undefined
  try {
    return JSON.parse(fromUtf8(claro))
  } catch {
    return undefined
  }
}

/** Tipo da imagem pelos primeiros bytes (não confia na extensão). */
export function tipoImagem(b) {
  if (b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'image/png'
  if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg'
  if (b.length > 6 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return 'image/gif'
  if (b.length > 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'image/webp'
  return undefined
}
