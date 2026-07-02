// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"errors"
	"testing"
	"time"
)

// pinTime pins nowFunc to a fixed instant for the duration of the test.
func pinTime(t *testing.T, unix int64) {
	t.Helper()
	old := nowFunc
	nowFunc = func() time.Time { return time.Unix(unix, 0) }
	t.Cleanup(func() { nowFunc = old })
}

// newTestClient builds a client with common defaults.
func newTestClient(opts Options) *Client {
	if opts.Site == "" {
		opts.Site = "https://example.com"
	}
	return NewClient("myid", "mysecret", opts)
}

func TestAuthorizeURL(t *testing.T) {
	c := newTestClient(Options{AuthorizeURL: "/oauth/authorize", TokenURL: "/oauth/token"})
	cases := []struct {
		name   string
		params Params
		want   string
	}{
		{
			"code+scope+state",
			Params{{"redirect_uri", "https://app.example.com/cb"}, {"scope", "read write"}, {"state", "xyz"}},
			"https://example.com/oauth/authorize?client_id=myid&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=read%20write&state=xyz",
		},
		{
			"extra+audience sorted",
			Params{{"redirect_uri", "https://app.example.com/cb"}, {"foo", "bar"}, {"audience", "https://api"}},
			"https://example.com/oauth/authorize?audience=https%3A%2F%2Fapi&client_id=myid&foo=bar&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code",
		},
		{
			"no params",
			nil,
			"https://example.com/oauth/authorize?client_id=myid&response_type=code",
		},
		{
			"reserved chars escaped",
			Params{{"state", "a+b/c=d&e"}},
			"https://example.com/oauth/authorize?client_id=myid&response_type=code&state=a%2Bb%2Fc%3Dd%26e",
		},
		{
			"unreserved passthrough",
			Params{{"t", "AZaz09-_.~!*'()@:$,;"}},
			"https://example.com/oauth/authorize?client_id=myid&response_type=code&t=AZaz09-_.~%21%2A%27%28%29%40%3A%24%2C%3B",
		},
		{
			"explicit response_type overrides",
			Params{{"zzz", "1"}, {"aaa", "2"}, {"response_type", "token"}},
			"https://example.com/oauth/authorize?aaa=2&client_id=myid&response_type=token&zzz=1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.AuthCode().AuthorizeURL(tc.params); got != tc.want {
				t.Errorf("AuthorizeURL:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestDefaultEndpoints(t *testing.T) {
	c := NewClient("id2", "sec2", Options{Site: "https://provider.test"})
	if got := c.AuthorizeURL(); got != "https://provider.test/oauth/authorize" {
		t.Errorf("AuthorizeURL = %q", got)
	}
	if got := c.TokenURL(); got != "https://provider.test/oauth/token" {
		t.Errorf("TokenURL = %q", got)
	}
	// authorize_url with no params still appends the defaults.
	if got := c.AuthCode().AuthorizeURL(nil); got != "https://provider.test/oauth/authorize?client_id=id2&response_type=code" {
		t.Errorf("AuthorizeURL(nil) = %q", got)
	}
}

func TestAbsoluteEndpoints(t *testing.T) {
	c := NewClient("id", "sec", Options{
		Site:         "https://ex.com",
		AuthorizeURL: "https://auth.other.com/authorize",
		TokenURL:     "https://token.other.com/t",
	})
	if got := c.AuthCode().AuthorizeURL(Params{{"redirect_uri", "https://cb"}}); got != "https://auth.other.com/authorize?client_id=id&redirect_uri=https%3A%2F%2Fcb&response_type=code" {
		t.Errorf("absolute authorize = %q", got)
	}
	if got := c.TokenURL(); got != "https://token.other.com/t" {
		t.Errorf("absolute token = %q", got)
	}
}

func TestResolveURLNoSite(t *testing.T) {
	c := NewClient("id", "sec", Options{AuthorizeURL: "oauth/authorize", TokenURL: "oauth/token"})
	if got := c.AuthorizeURL(); got != "oauth/authorize" {
		t.Errorf("no-site authorize = %q", got)
	}
}

// reqField collects a request's method, full url, encoded body and a header.
func TestTokenRequestBasicAuth(t *testing.T) {
	c := newTestClient(Options{TokenURL: "/oauth/token"})
	req := c.AuthCode().GetTokenRequest("thecode", Params{{"redirect_uri", "https://app/cb"}})
	if req.Method != "POST" {
		t.Errorf("method = %q", req.Method)
	}
	if req.URL != "https://example.com/oauth/token" {
		t.Errorf("url = %q", req.URL)
	}
	auth, _ := req.Headers.Get("Authorization")
	if auth != "Basic bXlpZDpteXNlY3JldA==" {
		t.Errorf("auth = %q", auth)
	}
	ct, _ := req.Headers.Get("Content-Type")
	if ct != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", ct)
	}
	if got := req.EncodedBody(); got != "code=thecode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fapp%2Fcb" {
		t.Errorf("body = %q", got)
	}
	if req.FullURL() != req.URL {
		t.Errorf("FullURL for POST should equal URL, got %q", req.FullURL())
	}
}

func TestTokenRequestRequestBodyAuth(t *testing.T) {
	c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", AuthScheme: AuthRequestBody})
	req := c.AuthCode().GetTokenRequest("code1", Params{{"redirect_uri", "https://cb"}})
	if _, ok := req.Headers.Get("Authorization"); ok {
		t.Error("request_body scheme must not set Authorization")
	}
	// client_id, client_secret prepended, then grant params in order.
	keys := bodyKeys(req.Body)
	want := []string{"client_id", "client_secret", "grant_type", "code", "redirect_uri"}
	if !eqStrs(keys, want) {
		t.Errorf("body order = %v, want %v", keys, want)
	}
	id, _ := req.Body.Get("client_id")
	sec, _ := req.Body.Get("client_secret")
	if id != "myid" || sec != "mysecret" {
		t.Errorf("creds = %q/%q", id, sec)
	}
}

func TestTokenRequestTLSClientAuth(t *testing.T) {
	c := NewClient("id", "sec", Options{Site: "https://ex.com", AuthScheme: AuthTLSClientAuth})
	req := c.ClientCredentials().GetTokenRequest(nil)
	if _, ok := req.Headers.Get("Authorization"); ok {
		t.Error("tls_client_auth must not set Authorization")
	}
	if _, ok := req.Body.Get("client_secret"); ok {
		t.Error("tls_client_auth must not send client_secret")
	}
	id, _ := req.Body.Get("client_id")
	if id != "id" {
		t.Errorf("client_id = %q", id)
	}
	keys := bodyKeys(req.Body)
	if !eqStrs(keys, []string{"client_id", "grant_type"}) {
		t.Errorf("body keys = %v", keys)
	}
}

func TestGrantBodies(t *testing.T) {
	c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", AuthScheme: AuthRequestBody})

	cc := c.ClientCredentials().GetTokenRequest(Params{{"scope", "read"}})
	if gt, _ := cc.Body.Get("grant_type"); gt != "client_credentials" {
		t.Errorf("cc grant_type = %q", gt)
	}
	if sc, _ := cc.Body.Get("scope"); sc != "read" {
		t.Errorf("cc scope = %q", sc)
	}

	pw := c.Password().GetTokenRequest("alice", "pw123", Params{{"scope", "read"}})
	if u, _ := pw.Body.Get("username"); u != "alice" {
		t.Errorf("pw username = %q", u)
	}
	if p, _ := pw.Body.Get("password"); p != "pw123" {
		t.Errorf("pw password = %q", p)
	}
	if gt, _ := pw.Body.Get("grant_type"); gt != "password" {
		t.Errorf("pw grant_type = %q", gt)
	}

	as := c.Assertion().GetTokenRequest("urn:ietf:params:oauth:grant-type:jwt-bearer", "the.jwt.assertion", nil)
	if a, _ := as.Body.Get("assertion"); a != "the.jwt.assertion" {
		t.Errorf("assertion = %q", a)
	}
	if gt, _ := as.Body.Get("grant_type"); gt != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("assertion grant_type = %q", gt)
	}

	rf := c.Refresh().GetTokenRequest("theref", nil)
	if rt, _ := rf.Body.Get("refresh_token"); rt != "theref" {
		t.Errorf("refresh refresh_token = %q", rt)
	}
	if gt, _ := rf.Body.Get("grant_type"); gt != "refresh_token" {
		t.Errorf("refresh grant_type = %q", gt)
	}
}

func TestTokenMethodGET(t *testing.T) {
	c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", TokenMethod: TokenGet, AuthScheme: AuthRequestBody})
	req := c.AuthCode().GetTokenRequest("code9", Params{{"redirect_uri", "https://cb"}})
	if req.Method != "GET" {
		t.Errorf("method = %q", req.Method)
	}
	if req.Body != nil {
		t.Errorf("GET should carry no body, got %v", req.Body)
	}
	if req.Params == nil {
		t.Fatal("GET should carry params")
	}
	// GET has no form Content-Type header.
	if _, ok := req.Headers.Get("Content-Type"); ok {
		t.Error("GET must not set form Content-Type")
	}
	want := "https://ex.com/oauth/token?client_id=myid&client_secret=mysecret&code=code9&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fcb"
	if got := req.FullURL(); got != want {
		t.Errorf("FullURL:\n got %s\nwant %s", got, want)
	}
}

func TestTokenMethodGETBasicAuth(t *testing.T) {
	c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", TokenMethod: TokenGet})
	req := c.ClientCredentials().GetTokenRequest(nil)
	auth, _ := req.Headers.Get("Authorization")
	if auth != "Basic bXlpZDpteXNlY3JldA==" {
		t.Errorf("GET basic auth = %q", auth)
	}
	want := "https://ex.com/oauth/token?grant_type=client_credentials"
	if got := req.FullURL(); got != want {
		t.Errorf("FullURL = %q, want %q", got, want)
	}
}

func TestParseTokenJSON(t *testing.T) {
	pinTime(t, 1_700_000_000)
	c := newTestClient(Options{})
	resp := NewResponse(200, headers("application/json"),
		`{"access_token":"tok123","token_type":"bearer","expires_in":3600,"refresh_token":"ref456","scope":"read write"}`)
	tok, err := c.ParseToken(resp)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Token != "tok123" {
		t.Errorf("token = %q", tok.Token)
	}
	if tok.RefreshToken != "ref456" {
		t.Errorf("refresh = %q", tok.RefreshToken)
	}
	if tok.ExpiresAt != 1_700_000_000+3600 {
		t.Errorf("expires_at = %d", tok.ExpiresAt)
	}
	if tok.TokenType() != "bearer" {
		t.Errorf("token_type = %q", tok.TokenType())
	}
	if tok.Scope() != "read write" {
		t.Errorf("scope = %q", tok.Scope())
	}
	if !tok.Expires() || tok.Expired() {
		t.Errorf("expires?=%v expired?=%v", tok.Expires(), tok.Expired())
	}
}

func TestParseTokenForm(t *testing.T) {
	c := newTestClient(Options{})
	resp := NewResponse(200, headers("application/x-www-form-urlencoded"),
		"access_token=t&expires_in=3600&scope=read")
	pinTime(t, 1000)
	tok, err := c.ParseToken(resp)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Token != "t" {
		t.Errorf("token = %q", tok.Token)
	}
	if tok.ExpiresAt != 1000+3600 {
		t.Errorf("expires_at = %d", tok.ExpiresAt)
	}
	if tok.Scope() != "read" {
		t.Errorf("scope = %q", tok.Scope())
	}
}

func TestParseTokenError(t *testing.T) {
	c := newTestClient(Options{})
	resp := NewResponse(400, headers("application/json"),
		`{"error":"invalid_grant","error_description":"bad code"}`)
	_, err := c.ParseToken(resp)
	var oe *Error
	if !errors.As(err, &oe) {
		t.Fatalf("want *Error, got %T", err)
	}
	if oe.Code != "invalid_grant" {
		t.Errorf("code = %q", oe.Code)
	}
	if oe.Description != "bad code" {
		t.Errorf("description = %q", oe.Description)
	}
	if oe.FirstLine() != "invalid_grant: bad code" {
		t.Errorf("first line = %q", oe.FirstLine())
	}
	if oe.Response != resp {
		t.Error("Error should carry the response")
	}
}

func TestErrorNoDescription(t *testing.T) {
	c := newTestClient(Options{})
	resp := NewResponse(401, headers("application/json"), `{"error":"invalid_client"}`)
	_, err := c.ParseToken(resp)
	oe := err.(*Error)
	if oe.FirstLine() != "invalid_client" {
		t.Errorf("first line = %q", oe.FirstLine())
	}
}

func TestErrorNoErrorField(t *testing.T) {
	c := newTestClient(Options{})
	resp := NewResponse(500, headers("text/plain"), "gateway boom")
	_, err := c.ParseToken(resp)
	oe := err.(*Error)
	if oe.Error() != "gateway boom" {
		t.Errorf("message = %q", oe.Error())
	}
	if oe.FirstLine() != "gateway boom" {
		t.Errorf("first line = %q", oe.FirstLine())
	}
	if oe.Code != "" {
		t.Errorf("code = %q", oe.Code)
	}
}

func TestRefreshPreservesRefreshToken(t *testing.T) {
	c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", AuthScheme: AuthRequestBody})
	tok := AccessTokenFromHash(c, map[string]any{"access_token": "old", "refresh_token": "theref", "token_type": "bearer"}, []string{"access_token", "refresh_token", "token_type"})

	req, err := tok.RefreshRequest()
	if err != nil {
		t.Fatal(err)
	}
	if rt, _ := req.Body.Get("refresh_token"); rt != "theref" {
		t.Errorf("refresh request refresh_token = %q", rt)
	}

	// The refresh response omits refresh_token; the old one is preserved.
	resp := NewResponse(200, headers("application/json"), `{"access_token":"tok2","token_type":"bearer"}`)
	newTok, err := c.ParseRefreshToken(resp, tok.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if newTok.Token != "tok2" {
		t.Errorf("new token = %q", newTok.Token)
	}
	if newTok.RefreshToken != "theref" {
		t.Errorf("preserved refresh = %q", newTok.RefreshToken)
	}
}

func TestRefreshNewTokenWins(t *testing.T) {
	c := NewClient("myid", "mysecret", Options{Site: "https://ex.com"})
	resp := NewResponse(200, headers("application/json"), `{"access_token":"tok2","refresh_token":"newref"}`)
	tok, err := c.ParseRefreshToken(resp, "oldref")
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "newref" {
		t.Errorf("refresh = %q, want newref (new wins)", tok.RefreshToken)
	}
}

func TestRefreshRequestNoRefreshToken(t *testing.T) {
	c := newTestClient(Options{})
	tok := NewAccessToken(c, "abc")
	if _, err := tok.RefreshRequest(); !errors.Is(err, errNoRefreshToken) {
		t.Errorf("err = %v, want errNoRefreshToken", err)
	}
}

func TestRefreshRequestExtraParams(t *testing.T) {
	c := NewClient("id", "sec", Options{Site: "https://ex.com", AuthScheme: AuthRequestBody})
	tok := NewAccessToken(c, "abc")
	tok.RefreshToken = "r"
	req, err := tok.RefreshRequest(Param{"scope", "read"})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := req.Body.Get("scope"); s != "read" {
		t.Errorf("scope = %q", s)
	}
}

func headers(contentType string) *Map {
	h := NewMap()
	h.Set("Content-Type", contentType)
	return h
}

func bodyKeys(m *Map) []string {
	keys := make([]string, 0, m.Len())
	for _, p := range m.Pairs() {
		keys = append(keys, p.Key)
	}
	return keys
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
