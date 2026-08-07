package main

// pwcheck_test.go — common-password rejection.

import (
	"strings"
	"testing"
)

// Case-insensitivity must hold for every entry in the embedded list, not
// just the ones that already happen to be lowercase. Before this fix,
// commonPwSet stored entries verbatim while isCommonPassword looked up
// strings.ToLower(pw) — since Go map lookups are case-sensitive, any entry
// containing an uppercase character could never match, silently letting
// those breached passwords through despite the doc comment's explicit
// "(case-insensitive)" claim.
func TestCommonPasswordCheckIsFullyCaseInsensitive(t *testing.T) {
	// Real entries from data/common-passwords.txt that contain an uppercase
	// character (confirmed present via grep -m5 '[A-Z]' data/common-passwords.txt).
	mixedCase := []string{"Status", "j38ifUbn"}
	for _, pw := range mixedCase {
		if !isCommonPassword(pw) {
			t.Fatalf("mixed-case breached password %q not flagged as common", pw)
		}
		if !isCommonPassword(strings.ToLower(pw)) {
			t.Fatalf("lowercased form of %q not flagged as common", pw)
		}
		if !isCommonPassword(strings.ToUpper(pw)) {
			t.Fatalf("uppercased form of %q not flagged as common", pw)
		}
	}
}
