// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package oauth2 is a pure-Go (CGO-free) reimplementation of the deterministic
// protocol pieces of Ruby's `oauth2` gem (the OAuth2 client): building
// authorization URLs and token-request specifications, and parsing token and
// error responses. It is the interpreter-independent core the gem shares across
// grant strategies, without any Ruby runtime.
//
// # What it is — and isn't
//
// The URL/param construction (authorize-URL query encoding, per-grant token
// request bodies, basic-auth vs request-body client authentication, PKCE) and
// response parsing (JSON / form-encoded token bodies, error extraction) are
// fully deterministic and need no interpreter, so they live here as pure Go.
// The HTTP round-trip itself is a host seam: the library builds a [Request] and
// a host (wiring to go-ruby-net-http / faraday) turns it into a [Response] via a
// [RoundTripper]. This mirrors the gem, where Faraday performs the transport.
//
// # Flow
//
//	client := oauth2.NewClient("id", "secret", oauth2.Options{
//		Site:         "https://provider.example.com",
//		AuthorizeURL: "/oauth/authorize",
//		TokenURL:     "/oauth/token",
//	})
//
//	// 1. Build the authorization URL to redirect the user to.
//	url := client.AuthCode().AuthorizeURL(oauth2.Params{
//		{"redirect_uri", "https://app/cb"}, {"scope", "read"}, {"state", "xyz"},
//	})
//
//	// 2. Build the token request for the returned code, run it through the host
//	//    transport, and parse the response into an AccessToken.
//	req := client.AuthCode().GetTokenRequest("thecode", oauth2.Params{
//		{"redirect_uri", "https://app/cb"},
//	})
//	resp, _ := transport.RoundTrip(req)   // host seam
//	tok, _ := client.ParseToken(resp)
//
// # Value model
//
// Parameters and parsed bodies are carried as an ordered string→string [Map];
// residual token fields live in [AccessToken.Params]. A host (go-embedded-ruby /
// rbgo) maps its Ruby Hash/AccessToken objects to and from these shapes.
package oauth2

import (
	"errors"
	"sort"
	"strconv"
)

// Param is one ordered key/value request parameter; a []Param ([Params]) lets
// callers supply parameters with a deterministic order (the gem accepts a Ruby
// Hash — here order is explicit for reproducibility).
type Param struct {
	Key string
	Val string
}

// Params is an ordered list of request parameters.
type Params = []Param

// errNoRefreshToken is returned when a refresh is attempted without one.
var errNoRefreshToken = errors.New("oauth2: no refresh token available")

// keysOf returns the keys of h sorted, a deterministic fallback order for
// residual params when the caller does not supply the original response order.
func keysOf(h map[string]any) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// stringify renders a parsed-JSON scalar as the string the gem would carry.
// Numbers become their shortest decimal form; booleans "true"/"false"; a nil
// yields ""; strings pass through. Composite values (maps/slices) are not token
// scalars and stringify to "".
func stringify(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case bool:
		if n {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers decode to float64; render integers without a fraction.
		if n == float64(int64(n)) {
			return strconv.FormatInt(int64(n), 10)
		}
		return strconv.FormatFloat(n, 'g', -1, 64)
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case nil:
		return ""
	}
	return ""
}
