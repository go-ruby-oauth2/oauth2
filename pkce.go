// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
)

// PKCEMethod is a PKCE code-challenge transformation (RFC 7636).
type PKCEMethod string

const (
	// PKCES256 is the SHA-256 transformation: challenge = BASE64URL(SHA256(verifier)).
	PKCES256 PKCEMethod = "S256"
	// PKCEPlain is the identity transformation: challenge = verifier.
	PKCEPlain PKCEMethod = "plain"
)

// CodeChallenge derives the PKCE code_challenge for a code_verifier under the
// given method (RFC 7636 §4.2). For [PKCES256] it returns the base64url (no
// padding) of SHA-256(verifier); for [PKCEPlain] it returns the verifier
// unchanged. An unknown method is treated as plain.
//
// The verifier and challenge are added to the authorize URL and token request as
// the code_challenge / code_challenge_method / code_verifier params by the
// caller; this helper only performs the deterministic transformation.
func CodeChallenge(verifier string, method PKCEMethod) string {
	if method == PKCES256 {
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return verifier
}
