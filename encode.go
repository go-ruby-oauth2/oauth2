// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"sort"
	"strings"
)

// encodeQuery renders params as an `application/x-www-form-urlencoded` query
// string, byte-faithful to the `oauth2` gem's authorize-URL construction (which
// funnels through Faraday's default flat-params encoder): keys are emitted in
// ascending byte order, and each key and value is percent-encoded with the
// RFC 3986 unreserved set (`A-Za-z0-9-_.~`) left literal and every other byte —
// including space, which becomes %20 (not '+') — percent-escaped.
//
// The gem sorts by key; ties on key cannot occur here because a Map dedups by
// key, so a stable sort of the keys reproduces the gem exactly.
func encodeQuery(params *Map) string {
	keys := make([]string, 0, params.Len())
	for _, p := range params.pairs {
		keys = append(keys, p.Key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		v, _ := params.Get(k)
		b.WriteString(escape(k))
		b.WriteByte('=')
		b.WriteString(escape(v))
	}
	return b.String()
}

// escape percent-encodes s per the encoding described on [encodeQuery]: RFC 3986
// unreserved bytes pass through, all others (including space → %20) become %XX
// with upper-case hex, matching the gem's output.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigit(c >> 4))
		b.WriteByte(hexDigit(c & 0xf))
	}
	return b.String()
}

// unreserved reports whether c is an RFC 3986 unreserved character, which the
// encoder leaves literal.
func unreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '_', c == '.', c == '~':
		return true
	}
	return false
}

// hexDigit maps a nibble (0..15) to its upper-case hexadecimal ASCII digit.
func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'A' + (n - 10)
}
