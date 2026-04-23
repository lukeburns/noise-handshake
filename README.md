# noise-handshake

Noise protocol handshakes with optional post-quantum (ML-KEM) extensions.

## Post-Quantum handshakes

`noise-handshake` can drive [PQNoise](https://doi.org/10.1145/3548606.3560577) handshakes that replace DH with an [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) key-encapsulation mechanism. The PQ entry point is published under the ESM subpath `noise-handshake/pq`, delegates to [`clatterjs`](https://www.npmjs.com/package/clatterjs) under the hood, and mirrors the classical `NoiseState` API (`initialise` / `send` / `recv` / `rx` / `tx` / `hash` / `complete`).

```js
import { PqNoise } from 'noise-handshake/pq'
import kem from 'noise-handshake/kem-mlkem512'
import Cipher from 'noise-handshake/cipher'

const initiator = new PqNoise('pqIK', true, null, { kem })
const responder = new PqNoise('pqIK', false, null, { kem })

initiator.initialise(Buffer.alloc(0), responder.s.publicKey)
responder.initialise(Buffer.alloc(0))

// -> skem, e, s
responder.recv(initiator.send())
// <- ekem, skem
initiator.recv(responder.send())

const send = new Cipher(initiator.tx)
const recv = new Cipher(responder.rx)
console.log(recv.decrypt(send.encrypt(Buffer.from('hello pq'))).toString())
```

### `new PqNoise(pattern, initiator, staticKeypair, [opts])`

Same shape as the classical constructor, with two differences:

- `pattern` must be one of the 26 PQ patterns exported by clatterjs — `pqNN`, `pqNK`, `pqNX`, `pqKN`, `pqKK`, `pqKX`, `pqXN`, `pqXK`, `pqXX`, `pqIN`, `pqIK`, `pqIX`, and their PSK variants (`pqNNpsk2`, `pqIKpsk1`, `pqIKpsk2`, `pqXXpsk3`, ...). Call `pqHandshakePatterns()` to enumerate the full list.
- `staticKeypair` is a KEM keypair (`{ publicKey, secretKey }` where the byte lengths depend on the chosen KEM), not an X25519 keypair.

`opts` may be used to pass in the following:

- `kem`: a KEM module (defaults to `MLKEM512`). Re-usable modules are shipped as `noise-handshake/kem-mlkem512`, `noise-handshake/kem-mlkem768` and `noise-handshake/kem-mlkem1024`.
- `ekem`, `skem`: override the KEM for ephemeral and static operations independently (mirrors clatter's `EKEM+SKEM` naming). Falls back to `kem` when unset.
- `cipher`, `hash`: AEAD and hash specs (defaults match the classical noise-handshake: ChaChaPoly + BLAKE2b). Use the re-exports from `noise-handshake/pq` (`chachaPoly`, `aesGcm`, `sha256H`, `sha512H`, `blake2bH`, `blake2sH`).
- `psk`: single 32-byte PSK for a `pskN` pattern. Shorthand for a one-element `psks` queue.
- `psks`: array of 32-byte PSK buffers pushed in order for multi-PSK patterns.
- `rng`: custom `(n: number) => Uint8Array` RNG (defaults to `crypto.getRandomValues`).

KEM modules export a `{ name, kem }` pair; any object with that shape can be handed to `opts.kem` / `opts.ekem` / `opts.skem`.

### Protocol naming

Protocol names follow the clatter convention. With a single KEM for both ephemeral and static operations:

```text
Noise_pqXX_MLKEM512_ChaChaPoly_BLAKE2b
```

With split ephemeral / static KEMs, joined by `+` (ephemeral first):

```text
Noise_pqXX_MLKEM512+MLKEM768_ChaChaPoly_BLAKE2b
```

Call `peer.getProtocolName()` to read the fully-qualified name.

### Interop with the classical `Cipher`

After the handshake completes, `peer.rx` and `peer.tx` are 32-byte raw AEAD keys — the same shape the classical API exposes — so the existing `noise-handshake/cipher` class can be used verbatim for transport encryption under the PQ-derived keys.

### Notes

- The PQ entry point is ESM only. CommonJS consumers can reach it via dynamic `import`: `const { PqNoise } = await import('noise-handshake/pq')`.
- The classical `require('noise-handshake')` entry is unchanged; the PQ feature is additive.

## Classical handshakes

```js
const Noise = require('noise-handshake')
const Cipher = require('noise-handshake/cipher')
const initiator = new Noise('IK', true)
const responder = new Noise('IK', false)

const prologue = Buffer.alloc(0)

// preshared key
initiator.initialise(prologue, responder.s.publicKey)
responder.initialise(prologue)

// -> e, es, s, ss
const message = initiator.send()
responder.recv(message)

// <- e, ee, se
const reply = responder.send()
initiator.recv(reply)

console.log(initiator.complete) // true

// convention is to use rx for
// sending and tx for receiving

// initiator.rx === responder.tx
// responder.rx === initiator.tx

// instantiate a cipher using shared secrets
const send = new Cipher(initiator.tx)
const recieve = new Cipher(responder.rx)

const msg = Buffer.from('hello, world')

const enc = send.encrypt(msg)
console.log(recieve.decrypt(enc)) // hello, world
```

### `const peer = new Noise(pattern, initiator, staticKeypair, [opts])`

Create a new handshake state for a given pattern. Initiator should be either `true` or `false` depending on the role. A preexisting keypair may be passed as `staticKeypair`

`opts` may be used to pass in the following:
- `curve`: module for performing Noise over other curves.
- `psk`: a 32-byte buffer containing a pre-shared key for patterns containing `psk0`. (Other psk positions are not currently supported.)

Curve modules should export the following:
```
{
  DHLEN,
  PKLEN,
  SKLEN,
  ALG,
  generateKeyPair,
  dh
}
```

See [dh.js](./dh) for an example.

### `peer.initialise(prologue, remoteStatic)`

Initialise the handshake state with a prologue and any preshared keys.

### `const buf = send([payload])`

Send the next message in the handshake, add an optional payload buffer to be included in the message, payload is a zero length buffer by default.

### `const payload = peer.recv(buf)`

Receive a handshake message from the peer and return the encrypted payload.

### `peer.complete`

`true` or `false`. Indicates whether `rx` and `tx` have been created yet.

When complete, the working handshake state shall be cleared *only* the following state shall remain on the object:

```js
{
  tx, // session key to decrypt messages from remote peer
  rx, // session key to encrypt messages to remote peer
  rs, // the remote peer's public key,
  hash, // a hash of the entire handshake state
}
```

## License

Apache-2.0
