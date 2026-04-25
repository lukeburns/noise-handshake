const { test } = require('brittle')
const Cipher = require('../cipher.js')

const NEEDS_RESPONDER_S = new Set([
  'pqNK', 'pqKK', 'pqXK', 'pqIK',
  'pqNKpsk2', 'pqKKpsk2', 'pqXKpsk3', 'pqIKpsk1', 'pqIKpsk2'
])
const NEEDS_INITIATOR_S = new Set([
  'pqKN', 'pqKK', 'pqKX',
  'pqKNpsk2', 'pqKKpsk2', 'pqKXpsk2'
])

async function makePair (name, opts = {}) {
  const { PqNoise } = await import('../pq.mjs')
  const initiator = new PqNoise(name, true, null, opts)
  const responder = new PqNoise(name, false, null, opts)

  const prologue = Buffer.alloc(0)

  if (NEEDS_RESPONDER_S.has(name)) initiator.initialise(prologue, responder.s.publicKey)
  else initiator.initialise(prologue)

  if (NEEDS_INITIATOR_S.has(name)) responder.initialise(prologue, initiator.s.publicKey)
  else responder.initialise(prologue)

  return { initiator, responder }
}

async function makeBoundPair (name, outerHandshakeHash, opts = {}) {
  const { BoundPqNoise } = await import('../pq.mjs')
  const initiator = new BoundPqNoise(name, true, null, outerHandshakeHash, opts)
  const responder = new BoundPqNoise(name, false, null, outerHandshakeHash, opts)

  const prologue = Buffer.alloc(0)

  if (NEEDS_RESPONDER_S.has(name)) initiator.initialise(prologue, responder.s.publicKey)
  else initiator.initialise(prologue)

  if (NEEDS_INITIATOR_S.has(name)) responder.initialise(prologue, initiator.s.publicKey)
  else responder.initialise(prologue)

  return { initiator, responder }
}

function completeHandshake (initiator, responder) {
  let safety = 0
  while (!(initiator.complete && responder.complete)) {
    if (safety++ > 8) throw new Error('Handshake loop did not complete')
    const m = initiator.send()
    responder.recv(m)
    if (initiator.complete && responder.complete) break
    const reply = responder.send()
    initiator.recv(reply)
  }
}

test('pq: all patterns complete and agree on session keys', async t => {
  const { pqHandshakePatterns } = await import('../pq.mjs')
  const psk = Buffer.alloc(32, 7)

  for (const p of pqHandshakePatterns()) {
    const name = p.getName()
    const opts = name.includes('psk') ? { psk } : {}
    const { initiator, responder } = await makePair(name, opts)
    completeHandshake(initiator, responder)

    t.is(initiator.complete, true, `${name}: initiator complete`)
    t.is(responder.complete, true, `${name}: responder complete`)
    t.alike(initiator.tx, responder.rx, `${name}: initiator.tx === responder.rx`)
    t.alike(initiator.rx, responder.tx, `${name}: initiator.rx === responder.tx`)
    t.alike(initiator.hash, responder.hash, `${name}: handshake hashes match`)
  }
})

test('pq: transport interop via classical Cipher', async t => {
  const { initiator, responder } = await makePair('pqIK')
  completeHandshake(initiator, responder)

  const send = new Cipher(initiator.tx)
  const recv = new Cipher(responder.rx)

  const plaintext = Buffer.from('post-quantum hello')
  const ciphertext = send.encrypt(plaintext)
  const decoded = recv.decrypt(ciphertext)

  t.alike(decoded, plaintext)
})

test('pqIK: handshake payload round-trips', async t => {
  const { initiator, responder } = await makePair('pqIK')

  const greeting = Buffer.from('hello responder')
  const reply = Buffer.from('hello initiator')

  const m1 = initiator.send(greeting)
  const r1 = responder.recv(m1)
  t.alike(r1, greeting)

  const m2 = responder.send(reply)
  const r2 = initiator.recv(m2)
  t.alike(r2, reply)

  t.is(initiator.complete, true)
  t.is(responder.complete, true)
  t.alike(initiator.rs, responder.s.publicKey)
})

test('pqNNpsk2: bad psk fails to decrypt', async t => {
  t.plan(1)
  const psk1 = Buffer.alloc(32, 1)
  const psk2 = Buffer.alloc(32, 2)
  const { initiator } = await makePair('pqNNpsk2', { psk: psk1 })
  const { responder: respBad } = await makePair('pqNNpsk2', { psk: psk2 })

  // pqNNpsk2 applies the PSK after the responder's Ekem token. With mismatched
  // PSKs the session keys diverge after the responder's reply, so the initiator
  // decryption of that reply must fail.
  const m1 = initiator.send()
  respBad.recv(m1)

  try {
    const reply = respBad.send()
    initiator.recv(reply)
    t.fail('expected decryption to fail with mismatched psk')
  } catch (err) {
    t.pass(`psk mismatch rejected: ${err.message}`)
  }
})

test('pqIK: tampered message fails', async t => {
  t.plan(1)
  // pqIK first message = (skem, e, s, payload) — the trailing bytes are an AEAD
  // tag, so flipping the last byte must cause verification to fail.
  const { initiator, responder } = await makePair('pqIK')

  const m1 = initiator.send()
  m1[m1.length - 1] ^= 1
  try {
    responder.recv(m1)
    t.fail('expected decryption to fail with tampered message')
  } catch (err) {
    t.pass(`tampered message rejected: ${err.message}`)
  }
})

test('pqIK: mismatched remote static is rejected', async t => {
  t.plan(1)
  const { PqNoise } = await import('../pq.mjs')

  const initiator = new PqNoise('pqIK', true, null)
  const responder = new PqNoise('pqIK', false, null)
  const wrongResponder = new PqNoise('pqIK', false, null)

  initiator.initialise(Buffer.alloc(0), wrongResponder.s.publicKey)
  responder.initialise(Buffer.alloc(0))

  const m1 = initiator.send()
  try {
    responder.recv(m1)
    t.fail('expected responder to reject wrong remote static')
  } catch (err) {
    t.pass(`wrong remote static rejected: ${err.message}`)
  }
})

test('pqXX: larger KEM (MLKEM1024) still completes', async t => {
  const kem = (await import('../kem-mlkem1024.mjs')).default
  const { initiator, responder } = await makePair('pqXX', { kem })
  completeHandshake(initiator, responder)

  t.alike(initiator.rx, responder.tx)
  t.alike(initiator.tx, responder.rx)
  t.is(initiator.getProtocolName(), 'Noise_pqXX_MLKEM1024_ChaChaPoly_BLAKE2b')
})

test('pq: split ekem/skem (MLKEM512 ephemeral + MLKEM768 static)', async t => {
  const ek = (await import('../kem-mlkem512.mjs')).default
  const sk = (await import('../kem-mlkem768.mjs')).default

  const { initiator, responder } = await makePair('pqXX', { ekem: ek, skem: sk })
  completeHandshake(initiator, responder)

  t.alike(initiator.rx, responder.tx)
  t.is(initiator.getProtocolName(), 'Noise_pqXX_MLKEM512+MLKEM768_ChaChaPoly_BLAKE2b')
})

test('bound pq: outer handshake hash is mixed into inner keys', async t => {
  const outerHandshakeHash = Buffer.alloc(32, 9)
  const { initiator, responder } = await makeBoundPair('pqXX', outerHandshakeHash)

  completeHandshake(initiator, responder)

  t.alike(initiator.tx, responder.rx)
  t.alike(initiator.rx, responder.tx)
  t.alike(initiator.hash, responder.hash)
})

test('bound pq: mismatched outer handshake hash fails', async t => {
  t.plan(1)
  const { BoundPqNoise } = await import('../pq.mjs')

  const initiator = new BoundPqNoise('pqXX', true, null, Buffer.alloc(32, 1))
  const responder = new BoundPqNoise('pqXX', false, null, Buffer.alloc(32, 2))

  initiator.initialise(Buffer.alloc(0))
  responder.initialise(Buffer.alloc(0))

  try {
    const m1 = initiator.send()
    responder.recv(m1)
    const reply = responder.send()
    initiator.recv(reply)
    t.fail('expected outer binding mismatch to fail')
  } catch (err) {
    t.pass(`outer binding mismatch rejected: ${err.message}`)
  }
})
