package main

// pwcheck.go — common-password rejection. The top-100k NCSC breached/common
// password list (SecLists) is embedded and consulted when a user picks a new
// password, so the weakest choices are refused outright.
//
// Rebuild the list with:
//   curl -sfL -o data/common-passwords.txt \
//     https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt

import (
	_ "embed"
	"strings"
)

//go:embed data/common-passwords.txt
var commonPasswords string

var commonPwSet map[string]struct{}

func init() {
	commonPwSet = make(map[string]struct{})
	for _, line := range strings.Split(commonPasswords, "\n") {
		if p := strings.TrimSpace(line); p != "" {
			commonPwSet[p] = struct{}{}
		}
	}
}

// isCommonPassword reports whether pw appears in the breach list
// (case-insensitive).
func isCommonPassword(pw string) bool {
	_, ok := commonPwSet[strings.ToLower(pw)]
	return ok
}
