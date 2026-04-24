import { Buffer } from 'buffer'
import {
  PqHandshake,
  pqHandshakePatterns,
  MLKEM512,
  MLKEM768,
  MLKEM1024,
  chachaPoly,
  aesGcm,
  sha256H,
  sha512H,
  blake2bH,
  blake2sH
} from '@lukeburns/clatterjs'

const DEFAULT_KEM = MLKEM512
const DEFAULT_CIPHER = chachaPoly
const DEFAULT_HASH = blake2bH

function defaultRng (n) {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

let PATTERNS = null
function resolvePattern (name) {
  if (PATTERNS === null) {
    PATTERNS = new Map()
    for (const p of pqHandshakePatterns()) PATTERNS.set(p.getName(), p)
  }
  const p = PATTERNS.get(name)
  if (!p) throw new Error(`Unknown post-quantum handshake pattern: ${name}`)
  return p
}

function normalizeKem (k) {
  if (!k) return null
  if (typeof k === 'object' && k.name && k.kem) return k
  if (k.default && k.default.name && k.default.kem) return k.default
  throw new Error('Invalid KEM module: expected { name, kem }')
}

function normalizeBuf (b) {
  if (b == null) return null
  return b instanceof Uint8Array ? b : Uint8Array.from(b)
}

export class PqNoise {
  constructor (pattern, initiator, staticKeypair = null, opts = {}) {
    const kem = normalizeKem(opts.kem) || DEFAULT_KEM
    this._ekem = normalizeKem(opts.ekem) || kem
    this._skem = normalizeKem(opts.skem) || kem
    this._cipher = opts.cipher || DEFAULT_CIPHER
    this._hash = opts.hash || DEFAULT_HASH
    this._rng = opts.rng || defaultRng

    this.pattern = pattern
    this._pattern = resolvePattern(pattern)
    this.initiator = initiator

    if (opts.psks) {
      this._psks = opts.psks.map((p) => Uint8Array.from(p))
    } else if (opts.psk) {
      this._psks = [Uint8Array.from(opts.psk)]
    } else {
      this._psks = []
    }

    if (staticKeypair) {
      this.s = {
        publicKey: Buffer.from(staticKeypair.publicKey),
        secretKey: Buffer.from(staticKeypair.secretKey)
      }
    } else {
      const k = this._skem.kem
      const seedLen = k.lengths.seed ?? 64
      const kp = k.keygen(this._rng(seedLen))
      this.s = {
        publicKey: Buffer.from(kp.publicKey),
        secretKey: Buffer.from(kp.secretKey)
      }
    }

    this._hs = null
    this.complete = false
    this.rx = null
    this.tx = null
    this.rs = null
    this.hash = null
  }

  initialise (prologue, remoteStatic) {
    const rsN = normalizeBuf(remoteStatic)
    this._hs = new PqHandshake(this._pattern, {
      prologue: normalizeBuf(prologue) || new Uint8Array(0),
      initiator: this.initiator,
      s: {
        publicKey: Uint8Array.from(this.s.publicKey),
        secretKey: Uint8Array.from(this.s.secretKey)
      },
      rs: rsN || undefined,
      ekem: this._ekem,
      skem: this._skem,
      cipher: this._cipher,
      hash: this._hash,
      rng: this._rng
    })

    for (const p of this._psks) this._hs.pushPsk(p)

    if (rsN) this.rs = Buffer.from(rsN)
  }

  send (payload) {
    if (!this._hs) throw new Error('Handshake not initialised')
    const pl = payload ? normalizeBuf(payload) : new Uint8Array(0)
    const overhead = this._hs.getNextMessageOverhead()
    const out = new Uint8Array(pl.length + overhead)
    const n = this._hs.writeMessage(pl, out)
    const result = Buffer.from(out.subarray(0, n))
    this._finalizeIfReady()
    return result
  }

  recv (buf) {
    if (!this._hs) throw new Error('Handshake not initialised')
    const bu = normalizeBuf(buf)
    const overhead = this._hs.getNextMessageOverhead()
    const payloadLen = bu.length - overhead
    if (payloadLen < 0) throw new Error('Noise message shorter than overhead')
    const out = new Uint8Array(payloadLen)
    this._hs.readMessage(bu, out)
    const result = Buffer.from(out)
    this._finalizeIfReady()
    return result
  }

  getProtocolName () {
    if (!this._hs) {
      // Construct the name without initialising (mirrors clatterjs buildProtocolName).
      const e = this._ekem.name
      const s = this._skem.name
      const k = e === s ? e : `${e}+${s}`
      return `Noise_${this.pattern}_${k}_${this._cipher.name}_${this._hash.name}`
    }
    return this._hs.getName()
  }

  _finalizeIfReady () {
    if (this.complete) return
    if (!this._hs.isFinished()) return

    const cs = this._hs.getCiphers()
    const k1 = cs.initiatorToResponder.getKey()
    const k2 = cs.responderToInitiator.getKey()
    this.tx = Buffer.from(this.initiator ? k1 : k2)
    this.rx = Buffer.from(this.initiator ? k2 : k1)
    this.hash = Buffer.from(this._hs.getHash())
    const rs = this._hs.getRemoteStatic()
    if (rs) this.rs = Buffer.from(rs)
    this.complete = true
  }
}

export {
  pqHandshakePatterns,
  MLKEM512,
  MLKEM768,
  MLKEM1024,
  chachaPoly,
  aesGcm,
  sha256H,
  sha512H,
  blake2bH,
  blake2sH
}

export default PqNoise
