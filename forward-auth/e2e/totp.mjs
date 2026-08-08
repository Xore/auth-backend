import { createHmac } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input) {
  const clean = input.toUpperCase().replace(/=+$/, "");
  let bits = "";
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val < 0) throw new Error(`invalid base32 character: ${char}`);
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

// RFC 6238 TOTP: 30s step, 6 digits, HMAC-SHA1 -- matches totp.go's own
// defaults (checked against totp.go before writing this rather than
// assumed), so a code generated here is one totpValidStep() actually
// accepts.
export function totpCode(base32Secret, time = Date.now()) {
  const key = base32Decode(base32Secret);
  const counter = Math.floor(time / 1000 / 30);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binCode % 1_000_000).padStart(6, "0");
}

// users.go tracks replay protection as a monotonic "last accepted step" per
// user: "any code at or before the last accepted step is rejected" (its own
// comment, users.go). That's fine for one real login, but this spec logs
// into the *same* single admin user many times in a row across viewport
// tiers, each run taking well under 30s -- confirmed live, several
// consecutive tests landed in the same 30s step as an already-consumed one
// and got a real "Invalid code." rejection, not a flake. fullyParallel is
// false (one worker, strictly sequential), so a module-scope "last step we
// used" counter is safe here and guarantees every subsequent login always
// waits for a genuinely fresh, not-yet-consumed step before typing a code.
let lastUsedStep = -1;

export async function freshTotpCode(base32Secret) {
  for (;;) {
    const now = Date.now();
    const step = Math.floor(now / 1000 / 30);
    if (step > lastUsedStep) {
      lastUsedStep = step;
      return totpCode(base32Secret, now);
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}
