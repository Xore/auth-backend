package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// normalizeB32 cleans a user-supplied base32 TOTP secret: uppercases and
// strips whitespace (incl. stray newlines from .env files), grouping hyphens
// and '=' padding. Genuinely invalid characters (e.g. '+' '/' from a base64
// secret) are kept so decoding fails loudly instead of silently enrolling a
// different secret than the user thinks they set.
func normalizeB32(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '=', r == '-', r == ' ', r == '\t', r == '\r', r == '\n', r == '"', r == '\'':
			// dropped: padding, grouping, whitespace, stray .env quotes
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// totpValidStep validates a 6-digit code within a ±1 step window and returns
// the matched time step so callers can enforce replay protection.
func totpValidStep(secret, code string) (bool, int64) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false, 0
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalizeB32(secret))
	if err != nil {
		return false, 0
	}
	step := time.Now().Unix() / 30
	for _, s := range []int64{step - 1, step, step + 1} {
		if subtle.ConstantTimeCompare([]byte(code), []byte(hotp(key, s))) == 1 {
			return true, s
		}
	}
	return false, 0
}

func hotp(key []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	m := hmac.New(sha1.New, key)
	m.Write(buf)
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	val := (int(sum[off])&0x7f)<<24 | (int(sum[off+1])&0xff)<<16 | (int(sum[off+2])&0xff)<<8 | (int(sum[off+3]) & 0xff)
	return fmt.Sprintf("%06d", val%1000000)
}
