// Entry of vectors.html, which the browser tests in vectors/ open: runs the
// vector checks in the page's own Web Crypto and publishes the outcome.

import aesGcmJson from '../../../testdata/wycheproof/aes_gcm_test.json?raw'
import hkdfJson from '../../../testdata/wycheproof/hkdf_sha256_test.json?raw'
import hmacJson from '../../../testdata/wycheproof/hmac_sha256_test.json?raw'
import formatJson from '../../../testdata/share_format_test.json?raw'
import { shareFormat } from './shareformat.ts'
import { aesGcm, hkdfSha256, hmacSha256 } from './wycheproof.ts'

async function run() {
  return {
    aesGcm: await aesGcm(aesGcmJson),
    hkdf: await hkdfSha256(hkdfJson),
    hmac: await hmacSha256(hmacJson),
    format: await shareFormat(formatJson),
  }
}

const target = window as unknown as { vectors?: unknown }
run().then(
  (outcome) => (target.vectors = outcome),
  (error: unknown) => (target.vectors = { error: String(error) }),
)
