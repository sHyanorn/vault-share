// Known-answer tests against published vectors.
import { describe, expect, it } from 'vitest'
import { decryptStream, encryptStream, recordNonce } from './ece.ts'
import { fromBase64Url, toBase64Url } from './encoding.ts'
import { deriveKeys, exportAuthKey, hkdf } from './keys.ts'
import { collect, fromHex, streamOf, toHex } from './testutil.ts'

const encoder = new TextEncoder()

describe('HKDF-SHA256 (RFC 5869 appendix A)', () => {
  it('test case 1', async () => {
    const okm = await hkdf(
      fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      fromHex('000102030405060708090a0b0c'),
      fromHex('f0f1f2f3f4f5f6f7f8f9'),
      42,
    )
    expect(toHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    )
  })

  it('test case 3: zero-length salt and info', async () => {
    const okm = await hkdf(
      fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      new Uint8Array(0),
      new Uint8Array(0),
      42,
    )
    expect(toHex(okm)).toBe(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    )
  })
})

describe('aes128gcm content encoding (RFC 8188 section 3)', () => {
  const ikm = fromBase64Url('yqdlZ-tYemfogSmv7Ws5PQ')
  const salt = fromBase64Url('I1BsxtFttlv3u_Oo94xnmw')
  const body = fromBase64Url(
    'I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg',
  )
  const plaintext = encoder.encode('I am the walrus')
  const options = { rs: 4096, keyLength: 16 as const }

  it('derives the published CEK and nonce', async () => {
    const cek = await hkdf(
      ikm,
      salt,
      encoder.encode('Content-Encoding: aes128gcm\0'),
      16,
    )
    const nonce = await hkdf(
      ikm,
      salt,
      encoder.encode('Content-Encoding: nonce\0'),
      12,
    )
    expect(toBase64Url(cek)).toBe('_wniytB-ofscZDh4tbSjHw')
    expect(toBase64Url(recordNonce(nonce, 0))).toBe('Bcs8gkIRKLI8GeI8')
  })

  it('3.1: encrypts to the published body', async () => {
    const out = await collect(
      encryptStream(streamOf(plaintext), ikm, { ...options, salt }),
    )
    expect(toBase64Url(out)).toBe(toBase64Url(body))
  })

  it('3.1: decrypts the published body', async () => {
    const out = await collect(decryptStream(streamOf(body, 7), ikm, options))
    expect(new TextDecoder().decode(out)).toBe('I am the walrus')
  })
})

describe('AES-256-GCM (NIST CAVP gcmEncryptExtIV256, count 0 of the PTlen = 128, AADlen = 0 group)', () => {
  it('matches the published ciphertext and tag', async () => {
    const key = await crypto.subtle.importKey(
      'raw',
      fromHex(
        '31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22',
      ),
      'AES-GCM',
      false,
      ['encrypt'],
    )
    const out = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: fromHex('0d18e06c7c725ac9e362e1ce'),
        tagLength: 128,
      },
      key,
      fromHex('2db5168e932556f8089a0622981d017d'),
    )
    expect(toHex(new Uint8Array(out))).toBe(
      'fa4362189661d163fcd6a56d8bf0405a' + 'd636ac1bbedd5cc3ee727dc2ab4a9489',
    )
  })
})

describe('aes128gcm with multiple records (RFC 8188 section 3.2)', () => {
  // Two 25-byte records, a zero-padded first record and the key id "a1".
  const body = fromBase64Url(
    'uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA',
  )
  const ikm = fromBase64Url('BO3ZVPxUlnLORbVGMpbT1Q')
  const options = { rs: 25, keyLength: 16 as const }

  it('rejects the published header, which carries a key id', async () => {
    const stream = decryptStream(streamOf(body), ikm, options)
    await expect(collect(stream)).rejects.toThrow('unsupported header')
  })

  it('decrypts once the key id is removed from the header', async () => {
    // The key id names the key; it is not an input to the key derivation.
    const stripped = new Uint8Array(body.length - 2)
    stripped.set(body.subarray(0, 20))
    stripped.set(body.subarray(23), 21)
    for (const chunkSize of [1, 7, 25, 71]) {
      const out = await collect(
        decryptStream(streamOf(stripped, chunkSize), ikm, options),
      )
      expect(new TextDecoder().decode(out)).toBe('I am the walrus')
    }
  })
})

describe('vault-share format (D012)', () => {
  // Generated from the reviewed implementation. Guards the key labels, the
  // aes256gcm info string and the record layout against accidental change.
  const secret = fromHex('000102030405060708090a0b0c0d0e0f')

  it('derives the recorded file and auth keys', async () => {
    const keys = await deriveKeys(secret)
    expect(toHex(keys.fileKey)).toBe(
      'fd1e0811baf46a987bdd9be4c76d1f51f21655fcfe24e1291caff295373537aa',
    )
    expect(toHex(await exportAuthKey(keys.authKey))).toBe(
      '066df9b8e3e442ba85cedc1cfd5f77f76ff7d1068af2cffb5554ef5e95a65f8b',
    )
  })

  it('encrypts a short file to the recorded body', async () => {
    const keys = await deriveKeys(secret)
    const salt = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    const plaintext = encoder.encode('vault-share')
    const body = await collect(
      encryptStream(streamOf(plaintext), keys.fileKey, { salt }),
    )
    expect(toHex(body)).toBe(
      'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff' +
        '00010000' +
        '00' +
        'b4d14b1186d9707199353fb3d115fbe362dd96edc66e93dc8bf28ba3',
    )
    expect(await collect(decryptStream(streamOf(body), keys.fileKey))).toEqual(
      plaintext,
    )
  })

  it('derives the recorded metadata key', async () => {
    const keys = await deriveKeys(secret)
    const out = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: fromHex('a0a1a2a3a4a5a6a7a8a9aaab') },
      keys.metaKey,
      encoder.encode('{"name":"a","type":"b","size":1}'),
    )
    expect(toHex(new Uint8Array(out))).toBe(
      '8c0163137552505d5352d1ead9d3b53c2af5ccf07723b039de74e11d079269f36d3fb04c41bc288c30776528a2551726',
    )
  })
})
