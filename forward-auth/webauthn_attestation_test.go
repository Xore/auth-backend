package main

import "testing"

// #64: attestationSatisfiesPolicy is the policy check that actually enforces
// WEBAUTHN_REQUIRE_ATTESTATION — go-webauthn's own FIDO Metadata Service
// validation silently no-ops for an authenticator that provided no
// attestation at all (AttestationFormatNone), so wiring MDS in alone would
// not reject the one case a "require attestation" flag most needs to catch.
func TestAttestationSatisfiesPolicy(t *testing.T) {
	cases := []struct {
		name            string
		require         bool
		attestationType string
		want            bool
	}{
		{"disabled default, no attestation, still accepted", false, "none", true},
		{"disabled default, real attestation, accepted", false, "basic_full", true},
		{"enabled, no attestation, rejected", true, "none", false},
		{"enabled, basic_full attestation, accepted", true, "basic_full", true},
		{"enabled, attca attestation, accepted", true, "attca", true},
		{"enabled, anonca attestation, accepted", true, "anonca", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := attestationSatisfiesPolicy(c.require, c.attestationType); got != c.want {
				t.Errorf("attestationSatisfiesPolicy(%v, %q) = %v, want %v", c.require, c.attestationType, got, c.want)
			}
		})
	}
}
