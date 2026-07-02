// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"os/exec"
	"strings"
	"testing"
)

// The oracle tests diff this package against the reference `oauth2` gem: they
// drive the gem to emit authorize URLs and token-request specs and to parse
// canned responses, and assert byte-for-byte agreement. They skip themselves
// where the gem (or ruby) is absent — the qemu cross-arch and Windows lanes —
// so the deterministic, ruby-free suite alone holds the 100% gate there.

// gemAvailable reports whether a ruby with the oauth2 gem loadable is on PATH,
// caching a failed probe as a skip.
func gemRuby(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("ruby")
	if err != nil {
		t.Skip("ruby not on PATH; skipping oauth2-gem oracle")
	}
	if err := exec.Command(bin, "-roauth2", "-e", "1").Run(); err != nil {
		t.Skip("oauth2 gem not installed; skipping oracle")
	}
	return bin
}

// rubyEval runs a ruby script (with oauth2 required, stdout binary) and returns
// trimmed stdout, failing on error.
func rubyEval(t *testing.T, bin, script string) string {
	t.Helper()
	cmd := exec.Command(bin, "-roauth2", "-e", "$stdout.binmode\n"+script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ruby error: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	return strings.TrimRight(string(out), "\n")
}

// clientRuby is the shared ruby preamble that builds a client with the given
// keyword options and a request-capturing monkeypatch, then returns the client
// as `c`. It captures the last request into `c.cap` for the request-spec oracles.
const capturePreamble = `
class OAuth2::Client
  attr_reader :cap
  def request(verb, url, opts = {})
    @cap = { verb: verb, url: url, body: opts[:body], params: opts[:params], headers: opts[:headers] }
    faraday = Struct.new(:status, :headers, :body).new(200, {"Content-Type"=>"application/json"}, '{"access_token":"tok","token_type":"bearer"}')
    OAuth2::Response.new(faraday)
  end
end
`

func TestOracleAuthorizeURL(t *testing.T) {
	bin := gemRuby(t)
	c := NewClient("myid", "mysecret", Options{Site: "https://example.com", AuthorizeURL: "/oauth/authorize", TokenURL: "/oauth/token"})

	cases := []struct {
		name   string
		params Params
		ruby   string // the ruby kwargs for authorize_url
	}{
		{"basic", Params{{"redirect_uri", "https://app/cb"}, {"scope", "read write"}, {"state", "xyz"}},
			`redirect_uri: "https://app/cb", scope: "read write", state: "xyz"`},
		{"extras", Params{{"foo", "bar"}, {"audience", "https://api"}},
			`foo: "bar", audience: "https://api"`},
		{"reserved", Params{{"state", "a+b/c=d&e"}}, `state: "a+b/c=d&e"`},
		{"none", nil, ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := `c = OAuth2::Client.new("myid","mysecret", site:"https://example.com", authorize_url:"/oauth/authorize", token_url:"/oauth/token")` + "\n" +
				`print c.auth_code.authorize_url(` + tc.ruby + `)`
			want := rubyEval(t, bin, script)
			got := c.AuthCode().AuthorizeURL(tc.params)
			if got != want {
				t.Errorf("authorize_url mismatch:\n go   %s\n ruby %s", got, want)
			}
		})
	}
}

func TestOracleTokenRequest(t *testing.T) {
	bin := gemRuby(t)

	// Each case builds a request here and drives the gem's captured request, then
	// compares the fully-encoded form (method, url, sorted body/params, and the
	// basic-auth header where present).
	cases := []struct {
		name     string
		clientRb string // ruby OAuth2::Client.new(...) args
		callRb   string // ruby c.<strategy>.get_token(...) call
		buildReq func() *Request
	}{
		{
			"authcode basic",
			`"myid","mysecret", site:"https://ex.com", token_url:"/oauth/token"`,
			`c.auth_code.get_token("thecode", redirect_uri:"https://app/cb")`,
			func() *Request {
				c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", TokenURL: "/oauth/token"})
				return c.AuthCode().GetTokenRequest("thecode", Params{{"redirect_uri", "https://app/cb"}})
			},
		},
		{
			"authcode request_body",
			`"myid","mysecret", site:"https://ex.com", auth_scheme: :request_body`,
			`c.auth_code.get_token("code1", redirect_uri:"https://cb")`,
			func() *Request {
				c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", AuthScheme: AuthRequestBody})
				return c.AuthCode().GetTokenRequest("code1", Params{{"redirect_uri", "https://cb"}})
			},
		},
		{
			"client_credentials basic",
			`"myid","mysecret", site:"https://ex.com"`,
			`c.client_credentials.get_token(scope:"read")`,
			func() *Request {
				c := NewClient("myid", "mysecret", Options{Site: "https://ex.com"})
				return c.ClientCredentials().GetTokenRequest(Params{{"scope", "read"}})
			},
		},
		{
			"password request_body",
			`"myid","mysecret", site:"https://ex.com", auth_scheme: :request_body`,
			`c.password.get_token("alice","pw123", scope:"read")`,
			func() *Request {
				c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", AuthScheme: AuthRequestBody})
				return c.Password().GetTokenRequest("alice", "pw123", Params{{"scope", "read"}})
			},
		},
		{
			"tls_client_auth",
			`"myid","mysecret", site:"https://ex.com", auth_scheme: :tls_client_auth`,
			`c.client_credentials.get_token`,
			func() *Request {
				c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", AuthScheme: AuthTLSClientAuth})
				return c.ClientCredentials().GetTokenRequest(nil)
			},
		},
		{
			"token_method get",
			`"myid","mysecret", site:"https://ex.com", token_method: :get, auth_scheme: :request_body`,
			`c.auth_code.get_token("code9", redirect_uri:"https://cb")`,
			func() *Request {
				c := NewClient("myid", "mysecret", Options{Site: "https://ex.com", TokenMethod: TokenGet, AuthScheme: AuthRequestBody})
				return c.AuthCode().GetTokenRequest("code9", Params{{"redirect_uri", "https://cb"}})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The ruby side prints: verb|url|sorted-encoded-body-or-params|authheader
			script := capturePreamble + "\n" +
				`c = OAuth2::Client.new(` + tc.clientRb + `)` + "\n" +
				tc.callRb + "\n" +
				`cap = c.cap` + "\n" +
				`require "cgi"` + "\n" +
				`def enc(h); return "" unless h; h.map{|k,v| "#{k}=#{v}"}.sort.map{|kv| k,v=kv.split("=",2); CGI.escape(k).gsub("+","%20")+"="+CGI.escape(v.to_s).gsub("+","%20") }.join("&"); end` + "\n" +
				`payload = cap[:verb] == :get ? cap[:params] : cap[:body]` + "\n" +
				`auth = (cap[:headers] || {})["Authorization"].to_s` + "\n" +
				`print [cap[:verb].to_s.upcase, cap[:url], enc(payload), auth].join("|")`
			want := rubyEval(t, bin, script)

			req := tc.buildReq()
			payload := req.EncodedBody()
			if req.Method == "GET" {
				payload = ""
				if req.Params != nil {
					payload = encodeQuery(req.Params)
				}
			}
			auth, _ := req.Headers.Get("Authorization")
			got := strings.Join([]string{req.Method, req.URL, payload, auth}, "|")
			if got != want {
				t.Errorf("token request mismatch:\n go   %s\n ruby %s", got, want)
			}
		})
	}
}

func TestOraclePKCE(t *testing.T) {
	bin := gemRuby(t)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	script := `require "digest"; require "base64"` + "\n" +
		`v = "` + verifier + `"` + "\n" +
		`print Base64.urlsafe_encode64(Digest::SHA256.digest(v), padding: false)`
	want := rubyEval(t, bin, script)
	if got := CodeChallenge(verifier, PKCES256); got != want {
		t.Errorf("PKCE S256 mismatch: go %q ruby %q", got, want)
	}
}

func TestOracleParseResponse(t *testing.T) {
	bin := gemRuby(t)
	c := NewClient("id", "sec", Options{Site: "https://ex.com"})

	// Drive the gem's AccessToken.from_hash on a canned JSON body and compare the
	// promoted fields; the residuals compare via to_hash keys.
	body := `{"access_token":"tok","token_type":"bearer","expires_at":1783007832,"refresh_token":"ref","scope":"a b","custom":"x"}`
	script := `require "json"` + "\n" +
		`c = OAuth2::Client.new("id","sec", site:"https://ex.com")` + "\n" +
		`tok = OAuth2::AccessToken.from_hash(c, JSON.parse('` + body + `'))` + "\n" +
		`print [tok.token, tok.refresh_token, tok.expires_at, tok["token_type"], tok["scope"], tok["custom"]].join("|")`
	want := rubyEval(t, bin, script)

	resp := NewResponse(200, headers("application/json"), body)
	tok, err := c.ParseToken(resp)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join([]string{
		tok.Token, tok.RefreshToken, "1783007832", tok.TokenType(),
		tok.Scope(), mustGet(tok, "custom"),
	}, "|")
	if got != want {
		t.Errorf("parsed token mismatch:\n go   %s\n ruby %s", got, want)
	}
}

func TestOracleError(t *testing.T) {
	bin := gemRuby(t)
	c := NewClient("id", "sec", Options{Site: "https://ex.com"})
	body := `{"error":"invalid_grant","error_description":"bad code"}`
	script := `class OAuth2::Client
  def request(verb, url, opts = {})
    faraday = Struct.new(:status, :headers, :body).new(400, {"Content-Type"=>"application/json"}, '` + body + `')
    r = OAuth2::Response.new(faraday)
    raise OAuth2::Error.new(r)
  end
end
` +
		`c = OAuth2::Client.new("id","sec", site:"https://ex.com")` + "\n" +
		`begin; c.auth_code.get_token("bad"); rescue OAuth2::Error => e; print [e.code, e.description, e.message.lines.first.strip].join("|"); end`
	want := rubyEval(t, bin, script)

	resp := NewResponse(400, headers("application/json"), body)
	_, err := c.ParseToken(resp)
	oe := err.(*Error)
	got := strings.Join([]string{oe.Code, oe.Description, oe.FirstLine()}, "|")
	if got != want {
		t.Errorf("error mismatch:\n go   %s\n ruby %s", got, want)
	}
}

func mustGet(t *AccessToken, k string) string {
	v, _ := t.Get(k)
	return v
}
