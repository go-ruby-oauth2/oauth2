// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"errors"
	"testing"
)

// These tests target the remaining branches so the deterministic, ruby-free
// suite alone holds coverage at 100%.

func TestClientID(t *testing.T) {
	c := NewClient("theid", "sec", Options{Site: "https://ex.com"})
	if c.ID() != "theid" {
		t.Errorf("ID = %q", c.ID())
	}
}

func TestRoundTripFunc(t *testing.T) {
	var rt RoundTripper = RoundTripFunc(func(req *Request) (*Response, error) {
		if req.Method != "POST" {
			return nil, errors.New("bad method")
		}
		return NewResponse(200, headers("application/json"), `{"access_token":"x"}`), nil
	})
	c := NewClient("id", "sec", Options{Site: "https://ex.com"})
	req := c.ClientCredentials().GetTokenRequest(nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.ParseToken(resp)
	if err != nil || tok.Token != "x" {
		t.Fatalf("tok=%v err=%v", tok, err)
	}

	// Error propagation from the transport.
	failing := RoundTripFunc(func(*Request) (*Response, error) { return nil, errors.New("net down") })
	if _, err := failing.RoundTrip(req); err == nil {
		t.Error("want transport error")
	}
}

func TestEncodedBodyNil(t *testing.T) {
	r := &Request{}
	if r.EncodedBody() != "" {
		t.Errorf("nil body EncodedBody = %q", r.EncodedBody())
	}
}

func TestFullURLNilParams(t *testing.T) {
	r := &Request{URL: "https://ex.com/t"}
	if r.FullURL() != "https://ex.com/t" {
		t.Errorf("FullURL = %q", r.FullURL())
	}
	// Empty (but non-nil) params map → unchanged.
	r.Params = NewMap()
	if r.FullURL() != "https://ex.com/t" {
		t.Errorf("FullURL empty params = %q", r.FullURL())
	}
}

func TestFullURLExistingQuery(t *testing.T) {
	r := &Request{URL: "https://ex.com/t?a=1", Params: NewMap()}
	r.Params.Set("b", "2")
	if got := r.FullURL(); got != "https://ex.com/t?a=1&b=2" {
		t.Errorf("FullURL = %q", got)
	}
}

func TestNewResponseNilHeaders(t *testing.T) {
	r := NewResponse(200, nil, "")
	if r.Headers == nil {
		t.Error("NewResponse should default headers to an empty map")
	}
	if r.ContentType() != "" {
		t.Errorf("ContentType = %q", r.ContentType())
	}
}

func TestContentTypeLowercaseHeader(t *testing.T) {
	h := NewMap()
	h.Set("content-type", "Application/JSON; charset=utf-8")
	r := NewResponse(200, h, `{"access_token":"t"}`)
	if r.ContentType() != "application/json" {
		t.Errorf("ContentType = %q", r.ContentType())
	}
}

func TestParsedMemoised(t *testing.T) {
	r := NewResponse(200, headers("application/json"), `{"a":"1"}`)
	first := r.Parsed()
	second := r.Parsed()
	// Same map instance returned (memoised).
	if len(first) != 1 || first["a"] != "1" {
		t.Fatalf("parsed = %v", first)
	}
	first["mutated"] = "yes"
	if _, ok := second["mutated"]; !ok {
		t.Error("Parsed should be memoised (same map)")
	}
}

func TestParseBodyVariants(t *testing.T) {
	// +json structured suffix.
	r := NewResponse(200, headers("application/vnd.api+json"), `{"access_token":"t"}`)
	if r.Parsed()["access_token"] != "t" {
		t.Errorf("+json not parsed: %v", r.Parsed())
	}
	// text/json.
	r2 := NewResponse(200, headers("text/json"), `{"access_token":"t2"}`)
	if r2.Parsed()["access_token"] != "t2" {
		t.Errorf("text/json not parsed: %v", r2.Parsed())
	}
	// Malformed JSON → empty map.
	r3 := NewResponse(200, headers("application/json"), `{not json`)
	if len(r3.Parsed()) != 0 {
		t.Errorf("malformed json = %v", r3.Parsed())
	}
	// JSON null literal → empty map (nil decode).
	r4 := NewResponse(200, headers("application/json"), `null`)
	if len(r4.Parsed()) != 0 {
		t.Errorf("json null = %v", r4.Parsed())
	}
	// Unknown content type → empty map.
	r5 := NewResponse(200, headers("text/html"), "<html>")
	if len(r5.Parsed()) != 0 {
		t.Errorf("html = %v", r5.Parsed())
	}
}

func TestParseFormEdgeCases(t *testing.T) {
	// Empty body.
	if len(parseForm("")) != 0 {
		t.Error("empty form should parse to empty map")
	}
	// Trailing & yields an empty segment, skipped; '+' as space; %XX decode.
	m := parseForm("a=x+y&b=%2Fpath&&c")
	if m["a"] != "x y" {
		t.Errorf("a = %q", m["a"])
	}
	if m["b"] != "/path" {
		t.Errorf("b = %q", m["b"])
	}
	if v, ok := m["c"]; !ok || v != "" {
		t.Errorf("c = %q,%v", v, ok)
	}
}

func TestUnescapeForm(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"a+b", "a b"},
		{"%2F", "/"},
		{"%2f", "/"},   // lower-case hex
		{"%zz", "%zz"}, // invalid hex left literal
		{"%2", "%2"},   // truncated escape left literal
		{"pre%20post", "pre post"},
		{"%41%42", "AB"},
	}
	for _, c := range cases {
		if got := unescapeForm(c.in); got != c.want {
			t.Errorf("unescapeForm(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFromHex(t *testing.T) {
	for _, c := range []struct {
		in byte
		v  byte
		ok bool
	}{
		{'0', 0, true}, {'9', 9, true}, {'a', 10, true}, {'f', 15, true},
		{'A', 10, true}, {'F', 15, true}, {'g', 0, false}, {'G', 0, false}, {'/', 0, false},
	} {
		v, ok := fromHex(c.in)
		if v != c.v || ok != c.ok {
			t.Errorf("fromHex(%q) = %d,%v want %d,%v", c.in, v, ok, c.v, c.ok)
		}
	}
}

func TestJSONKeyOrderNested(t *testing.T) {
	// Nested object/array values must not leak nested keys into the order.
	body := `{"access_token":"t","obj":{"inner":1,"deep":{"x":2}},"arr":[1,{"y":3}],"scope":"a"}`
	keys := jsonKeyOrder(body)
	want := []string{"access_token", "obj", "arr", "scope"}
	if !eqStrs(keys, want) {
		t.Errorf("jsonKeyOrder = %v, want %v", keys, want)
	}
}

func TestJSONKeyOrderNonObject(t *testing.T) {
	if keys := jsonKeyOrder(`[1,2,3]`); keys != nil {
		t.Errorf("array jsonKeyOrder = %v, want nil", keys)
	}
	if keys := jsonKeyOrder(`not json`); keys != nil {
		t.Errorf("garbage jsonKeyOrder = %v, want nil", keys)
	}
	if keys := jsonKeyOrder(`"just a string"`); keys != nil {
		t.Errorf("string jsonKeyOrder = %v, want nil", keys)
	}
}

func TestJSONKeyOrderTruncated(t *testing.T) {
	// A truncated object (error mid-stream) returns the keys gathered so far.
	keys := jsonKeyOrder(`{"a":1,"b":`)
	if !eqStrs(keys, []string{"a", "b"}) {
		t.Errorf("truncated jsonKeyOrder = %v", keys)
	}
	// Truncated inside a nested value.
	keys2 := jsonKeyOrder(`{"a":{"nested":`)
	if !eqStrs(keys2, []string{"a"}) {
		t.Errorf("truncated nested jsonKeyOrder = %v", keys2)
	}
	// A malformed key position (More() true but the key token errors) returns
	// the keys gathered before it.
	keys3 := jsonKeyOrder(`{"a":1,,}`)
	if !eqStrs(keys3, []string{"a"}) {
		t.Errorf("malformed-key jsonKeyOrder = %v", keys3)
	}
}

func TestParseTokenFormOrderFallback(t *testing.T) {
	// A form-encoded (non-JSON) body uses the sorted-key fallback order and
	// still parses the token, exercising orderedKeys' nil branch.
	c := newTestClient(Options{})
	pinTime(t, 100)
	resp := NewResponse(200, headers("application/x-www-form-urlencoded"), "access_token=t&zeta=1&alpha=2")
	tok, err := c.ParseToken(resp)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Token != "t" {
		t.Errorf("token = %q", tok.Token)
	}
	if !eqStrs(bodyKeys(tok.Params), []string{"alpha", "zeta"}) {
		t.Errorf("form params order = %v", bodyKeys(tok.Params))
	}
}

func TestMapSetOverwrite(t *testing.T) {
	m := NewMap()
	m.Set("k", "1")
	m.Set("k", "2") // overwrite in place, position preserved
	m.Set("j", "3")
	if v, _ := m.Get("k"); v != "2" {
		t.Errorf("overwritten value = %q", v)
	}
	if !eqStrs(bodyKeys(m), []string{"k", "j"}) {
		t.Errorf("order after overwrite = %v", bodyKeys(m))
	}
	// Set on a zero-value Map (nil index) must initialise it.
	var z Map
	z.Set("a", "1")
	if v, ok := z.Get("a"); !ok || v != "1" {
		t.Errorf("zero-map Set = %q,%v", v, ok)
	}
	// SetDefault does not clobber an existing key.
	m.SetDefault("k", "9")
	if v, _ := m.Get("k"); v != "2" {
		t.Errorf("SetDefault clobbered: %q", v)
	}
}

func TestMapCloneIndependent(t *testing.T) {
	m := NewMap()
	m.Set("a", "1")
	c := m.clone()
	c.Set("a", "2")
	c.Set("b", "3")
	if v, _ := m.Get("a"); v != "1" {
		t.Errorf("clone mutated original: %q", v)
	}
	if m.Has("b") {
		t.Error("clone leaked a key back to original")
	}
}
