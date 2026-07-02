// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"testing"
)

func TestAccessTokenExpiry(t *testing.T) {
	c := newTestClient(Options{})

	// expires_in derives expires_at = now + in.
	pinTime(t, 5000)
	in := AccessTokenFromHash(c, map[string]any{"access_token": "t", "expires_in": 3600}, nil)
	if in.ExpiresAt != 8600 {
		t.Errorf("derived expires_at = %d", in.ExpiresAt)
	}

	// explicit expires_at in the past → expired.
	past := AccessTokenFromHash(c, map[string]any{"access_token": "t", "expires_at": 4000}, nil)
	if !past.Expired() || !past.Expires() {
		t.Errorf("past: expired?=%v expires?=%v", past.Expired(), past.Expires())
	}

	// future expiry → not expired.
	future := AccessTokenFromHash(c, map[string]any{"access_token": "t", "expires_at": 9000}, nil)
	if future.Expired() {
		t.Error("future token should not be expired")
	}

	// exactly now → expired (<=).
	nowTok := AccessTokenFromHash(c, map[string]any{"access_token": "t", "expires_at": 5000}, nil)
	if !nowTok.Expired() {
		t.Error("token expiring exactly now should be expired")
	}

	// no expiry.
	noexp := AccessTokenFromHash(c, map[string]any{"access_token": "t"}, nil)
	if noexp.Expires() || noexp.Expired() {
		t.Errorf("noexp: expires?=%v expired?=%v", noexp.Expires(), noexp.Expired())
	}
	if noexp.ExpiresAt != 0 {
		t.Errorf("noexp expires_at = %d", noexp.ExpiresAt)
	}
}

func TestAccessTokenExpiresAtWinsOverExpiresIn(t *testing.T) {
	pinTime(t, 1000)
	c := newTestClient(Options{})
	// Both present: expires_at is authoritative, expires_in ignored.
	tok := AccessTokenFromHash(c, map[string]any{"access_token": "t", "expires_at": 12345, "expires_in": 3600}, []string{"access_token", "expires_at", "expires_in"})
	if tok.ExpiresAt != 12345 {
		t.Errorf("expires_at = %d, want 12345", tok.ExpiresAt)
	}
}

func TestAccessTokenParamsAndGet(t *testing.T) {
	c := newTestClient(Options{})
	tok := AccessTokenFromHash(c, map[string]any{"access_token": "t", "token_type": "bearer", "scope": "a b", "custom": "x"}, []string{"access_token", "token_type", "scope", "custom"})
	if v, ok := tok.Get("custom"); !ok || v != "x" {
		t.Errorf("custom = %q,%v", v, ok)
	}
	if _, ok := tok.Get("missing"); ok {
		t.Error("missing should not be present")
	}
	// Params order preserved from the response order (token_type, scope, custom).
	if !eqStrs(bodyKeys(tok.Params), []string{"token_type", "scope", "custom"}) {
		t.Errorf("params order = %v", bodyKeys(tok.Params))
	}
}

func TestAccessTokenParamsOrderFallback(t *testing.T) {
	c := newTestClient(Options{})
	// order=nil → sorted-key fallback.
	tok := AccessTokenFromHash(c, map[string]any{"access_token": "t", "zeta": "1", "alpha": "2"}, nil)
	if !eqStrs(bodyKeys(tok.Params), []string{"alpha", "zeta"}) {
		t.Errorf("fallback order = %v", bodyKeys(tok.Params))
	}
}

func TestAccessTokenFromHashSkipsAbsentOrderedKey(t *testing.T) {
	c := newTestClient(Options{})
	// An ordered key not in the hash is skipped.
	tok := AccessTokenFromHash(c, map[string]any{"access_token": "t"}, []string{"access_token", "not_present"})
	if tok.Token != "t" || tok.Params.Len() != 0 {
		t.Errorf("token=%q params=%d", tok.Token, tok.Params.Len())
	}
}

func TestAccessTokenModeAndFormatFromHash(t *testing.T) {
	c := newTestClient(Options{})
	tok := AccessTokenFromHash(c, map[string]any{
		"access_token": "t", "mode": "query", "header_format": "MAC %s", "param_name": "tok",
	}, []string{"access_token", "mode", "header_format", "param_name"})
	if tok.Mode != ModeQuery {
		t.Errorf("mode = %q", tok.Mode)
	}
	if tok.HeaderFormat != "MAC %s" {
		t.Errorf("header_format = %q", tok.HeaderFormat)
	}
	if tok.ParamName != "tok" {
		t.Errorf("param_name = %q", tok.ParamName)
	}
}

func TestAccessTokenApplyToHeader(t *testing.T) {
	c := newTestClient(Options{})
	tok := NewAccessToken(c, "abc")
	h, _, _ := tok.ApplyTo(nil, nil, nil)
	if a, _ := h.Get("Authorization"); a != "Bearer abc" {
		t.Errorf("header = %q", a)
	}
	if tok.AuthorizationHeader() != "Bearer abc" {
		t.Errorf("AuthorizationHeader = %q", tok.AuthorizationHeader())
	}
}

func TestAccessTokenApplyToCustomHeaderFormat(t *testing.T) {
	c := newTestClient(Options{})
	tok := NewAccessToken(c, "abc")
	tok.HeaderFormat = "MAC %s"
	h, _, _ := tok.ApplyTo(NewMap(), nil, nil)
	if a, _ := h.Get("Authorization"); a != "MAC abc" {
		t.Errorf("header = %q", a)
	}
}

func TestAccessTokenApplyToQuery(t *testing.T) {
	c := newTestClient(Options{})
	tok := NewAccessToken(c, "abc")
	tok.Mode = ModeQuery
	_, p, _ := tok.ApplyTo(nil, nil, nil)
	if v, _ := p.Get("access_token"); v != "abc" {
		t.Errorf("query param = %q", v)
	}
	// Custom param_name and an existing params map.
	tok.ParamName = "at"
	existing := NewMap()
	_, p2, _ := tok.ApplyTo(nil, existing, nil)
	if v, _ := p2.Get("at"); v != "abc" || p2 != existing {
		t.Errorf("query param = %q (same map: %v)", v, p2 == existing)
	}
}

func TestAccessTokenApplyToBody(t *testing.T) {
	c := newTestClient(Options{})
	tok := NewAccessToken(c, "abc")
	tok.Mode = ModeBody
	_, _, b := tok.ApplyTo(nil, nil, nil)
	if v, _ := b.Get("access_token"); v != "abc" {
		t.Errorf("body param = %q", v)
	}
	existing := NewMap()
	_, _, b2 := tok.ApplyTo(nil, nil, existing)
	if b2 != existing {
		t.Error("body mode should reuse existing map")
	}
}

func TestAccessTokenApplyToHeaderReusesMap(t *testing.T) {
	c := newTestClient(Options{})
	tok := NewAccessToken(c, "abc")
	existing := NewMap()
	h, _, _ := tok.ApplyTo(existing, nil, nil)
	if h != existing {
		t.Error("header mode should reuse existing headers map")
	}
}

func TestAccessTokenToHash(t *testing.T) {
	c := newTestClient(Options{})
	tok := AccessTokenFromHash(c, map[string]any{
		"access_token": "tok", "refresh_token": "ref", "expires_at": 1783007832,
		"token_type": "bearer", "scope": "a b", "custom": "x",
	}, []string{"access_token", "refresh_token", "expires_at", "token_type", "scope", "custom"})
	h := tok.ToHash()
	wantKeys := []string{"token_type", "scope", "custom", "access_token", "refresh_token", "expires_at", "mode", "header_format", "param_name"}
	if !eqStrs(bodyKeys(h), wantKeys) {
		t.Errorf("to_hash keys = %v\nwant %v", bodyKeys(h), wantKeys)
	}
	check := map[string]string{
		"access_token": "tok", "refresh_token": "ref", "expires_at": "1783007832",
		"token_type": "bearer", "scope": "a b", "custom": "x",
		"mode": "header", "header_format": "Bearer %s", "param_name": "access_token",
	}
	for k, want := range check {
		if got, _ := h.Get(k); got != want {
			t.Errorf("to_hash[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestAccessTokenToHashMinimal(t *testing.T) {
	c := newTestClient(Options{})
	tok := NewAccessToken(c, "tok")
	h := tok.ToHash()
	// No refresh_token, no expires_at.
	if h.Has("refresh_token") || h.Has("expires_at") {
		t.Errorf("minimal to_hash should omit refresh_token/expires_at: %v", bodyKeys(h))
	}
	if !eqStrs(bodyKeys(h), []string{"access_token", "mode", "header_format", "param_name"}) {
		t.Errorf("minimal keys = %v", bodyKeys(h))
	}
}

func TestAccessTokenDefaultsWhenZeroed(t *testing.T) {
	c := newTestClient(Options{})
	// A zero-valued token (fields left "") falls back to the gem defaults.
	tok := &AccessToken{client: c, Token: "abc", Params: NewMap()}
	if tok.AuthorizationHeader() != "Bearer abc" {
		t.Errorf("default header = %q", tok.AuthorizationHeader())
	}
	tok.Mode = ModeQuery
	_, p, _ := tok.ApplyTo(nil, nil, nil)
	if v, _ := p.Get("access_token"); v != "abc" {
		t.Errorf("default param name = %q", v)
	}
}

func TestStringify(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"s", "s"},
		{true, "true"},
		{false, "false"},
		{float64(3600), "3600"},
		{float64(1.5), "1.5"},
		{42, "42"},
		{int64(7), "7"},
		{nil, ""},
		{[]any{1}, ""},
		{map[string]any{}, ""},
	}
	for _, tc := range cases {
		if got := stringify(tc.in); got != tc.want {
			t.Errorf("stringify(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPKCE(t *testing.T) {
	// RFC 7636 appendix B vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if got := CodeChallenge(verifier, PKCES256); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("S256 challenge = %q", got)
	}
	if got := CodeChallenge(verifier, PKCEPlain); got != verifier {
		t.Errorf("plain challenge = %q", got)
	}
	// Unknown method → treated as plain.
	if got := CodeChallenge(verifier, PKCEMethod("bogus")); got != verifier {
		t.Errorf("unknown method challenge = %q", got)
	}
}

func TestPKCEInAuthorizeURL(t *testing.T) {
	c := NewClient("myid", "mysecret", Options{Site: "https://ex.com"})
	challenge := CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", PKCES256)
	got := c.AuthCode().AuthorizeURL(Params{
		{"redirect_uri", "https://cb"},
		{"code_challenge", challenge},
		{"code_challenge_method", "S256"},
	})
	want := "https://ex.com/oauth/authorize?client_id=myid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fcb&response_type=code"
	if got != want {
		t.Errorf("PKCE authorize URL:\n got %s\nwant %s", got, want)
	}
}
