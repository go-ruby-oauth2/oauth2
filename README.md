<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-oauth2/brand/main/social/go-ruby-oauth2-oauth2.png" alt="go-ruby-oauth2/oauth2" width="720"></p>

# oauth2 — go-ruby-oauth2

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-oauth2.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of the deterministic protocol pieces of
Ruby's [`oauth2`](https://gitlab.com/oauth-xx/oauth2) gem** — the
interpreter-independent OAuth2 client core: building authorization URLs and
per-grant token-request specifications, and parsing token/error responses into
an `AccessToken`. It reproduces the gem's byte-level output (sorted, percent-
encoded query strings; basic-auth vs request-body vs TLS client authentication;
JSON and form-encoded response parsing) — **without any Ruby runtime**.

It is the OAuth2 client for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but a **standalone,
reusable** module — a sibling of
[go-ruby-regexp](https://github.com/go-ruby-regexp/regexp),
[go-ruby-erb](https://github.com/go-ruby-erb/erb) and
[go-ruby-yaml](https://github.com/go-ruby-yaml/yaml).

> **What it is — and isn't.** The URL/param construction and response parsing are
> fully deterministic and need **no interpreter**, so they live here as pure Go.
> The **HTTP round-trip itself is a host seam**: the library builds a `Request`
> and a host (wiring to
> [go-ruby-net-http](https://github.com/go-ruby-net-http/net-http) / faraday)
> turns it into a `Response` via a `RoundTripper`. This mirrors the gem, where
> Faraday performs the transport.

## Features

Faithful port of the `oauth2` gem's client protocol, validated against the gem
on every platform where it is installed:

- **Authorization URLs** — `AuthCode().AuthorizeURL(...)` merges the client_id
  and `response_type=code` defaults and query-encodes every param (redirect_uri,
  scope, state, PKCE, provider extras) with **keys sorted** and the RFC 3986
  unreserved set left literal (space → `%20`), byte-faithful to the gem.
- **Every grant** — authorization code, client credentials, resource-owner
  password, JWT-bearer assertion, and refresh token; each builds the token
  **request spec** (form body / query params) the gem hands to Faraday.
- **Client authentication schemes** — `basic_auth` (the default;
  `Authorization: Basic base64(id:secret)`), `request_body` (client_id +
  client_secret in the body), and `tls_client_auth` (client_id only, RFC 8705).
- **Token method** — `POST` (form body) or `GET` (query params).
- **Response parsing** — content-type dispatch (`application/json`, any
  `+json`, `text/json`, `application/x-www-form-urlencoded`) into an
  `AccessToken` with `token`, `refresh_token`, `expires_at`/`expires?`/`expired?`,
  `token_type`, `scope`, and residual provider params (in response order).
- **`AccessToken`** — expiry derivation (`expires_in` → `expires_at`), the
  refresh request builder (preserving the old refresh token when the response
  omits one), `to_hash`, and resource-request injection in header / query / body
  mode (`Bearer`/`MAC`/custom `header_format`).
- **`Error`** — extracts `error` / `error_description` from an error response and
  composes the gem's message.
- **PKCE** — `code_challenge` for the `S256` and `plain` methods (RFC 7636).

CGO-free, dependency-free, **100% test coverage**, `gofmt` + `go vet` clean, and
green across the six 64-bit Go targets (amd64, arm64, riscv64, loong64, ppc64le,
s390x).

## Install

```sh
go get github.com/go-ruby-oauth2/oauth2
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/go-ruby-oauth2/oauth2"
)

func main() {
	client := oauth2.NewClient("myid", "mysecret", oauth2.Options{
		Site:         "https://provider.example.com",
		AuthorizeURL: "/oauth/authorize",
		TokenURL:     "/oauth/token",
	})

	// 1. Authorization URL to redirect the user-agent to.
	url := client.AuthCode().AuthorizeURL(oauth2.Params{
		{"redirect_uri", "https://app/cb"},
		{"scope", "read write"},
		{"state", "xyz"},
	})
	fmt.Println(url)
	// https://provider.example.com/oauth/authorize?client_id=myid&
	//   redirect_uri=https%3A%2F%2Fapp%2Fcb&response_type=code&
	//   scope=read%20write&state=xyz

	// 2. Build the token request for the returned code; run it through the host
	//    transport (the seam), then parse the response into an AccessToken.
	req := client.AuthCode().GetTokenRequest("thecode", oauth2.Params{
		{"redirect_uri", "https://app/cb"},
	})
	// req.Method == "POST", req.URL, req.EncodedBody(),
	// req.Headers has Authorization: Basic base64(id:secret)

	resp, _ := transport.RoundTrip(req) // host seam (go-ruby-net-http / faraday)
	tok, _ := client.ParseToken(resp)
	fmt.Println(tok.Token, tok.ExpiresAt, tok.Expired())

	// 3. Inject the token into a resource request.
	headers, _, _ := tok.ApplyTo(nil, nil, nil) // Authorization: Bearer <token>
	_ = headers
}
```

The `transport` is any `oauth2.RoundTripper`:

```go
type RoundTripper interface {
	RoundTrip(req *oauth2.Request) (*oauth2.Response, error)
}
```

## PKCE

```go
verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
challenge := oauth2.CodeChallenge(verifier, oauth2.PKCES256)

url := client.AuthCode().AuthorizeURL(oauth2.Params{
	{"redirect_uri", "https://app/cb"},
	{"code_challenge", challenge},
	{"code_challenge_method", "S256"},
})
// exchange later with a code_verifier param in GetTokenRequest's extra params
```

## Value model

Parameters and parsed bodies are carried as an ordered string→string `Map`;
promoted token fields become `AccessToken` fields and the rest live in
`AccessToken.Params` (in response order). A host (go-embedded-ruby / rbgo) maps
its Ruby `OAuth2::Client` / `AccessToken` objects to and from these shapes.

| gem                                     | this package                              |
| --------------------------------------- | ----------------------------------------- |
| `OAuth2::Client.new(id, secret, ...)`   | `NewClient(id, secret, Options{...})`     |
| `client.auth_code.authorize_url(...)`   | `client.AuthCode().AuthorizeURL(params)`  |
| `client.<grant>.get_token(...)`         | `client.<Grant>().GetTokenRequest(...)` + `client.ParseToken(resp)` |
| `OAuth2::AccessToken`                    | `*AccessToken`                            |
| `OAuth2::Response#parsed`               | `(*Response).Parsed()`                    |
| `OAuth2::Error`                         | `*Error`                                  |
| Faraday transport                       | `RoundTripper` (host seam)                |

## API

```go
func NewClient(id, secret string, opts Options) *Client
func (c *Client) AuthorizeURL() string
func (c *Client) TokenURL() string
func (c *Client) ParseToken(resp *Response) (*AccessToken, error)
func (c *Client) ParseRefreshToken(resp *Response, prevRefresh string) (*AccessToken, error)

func (c *Client) AuthCode() AuthCode
func (c *Client) ClientCredentials() ClientCredentials
func (c *Client) Password() Password
func (c *Client) Assertion() Assertion
func (c *Client) Refresh() Refresh

func (s AuthCode) AuthorizeURL(params Params) string
func (s AuthCode) GetTokenRequest(code string, extra Params) *Request
// ... one GetTokenRequest per grant strategy

type AccessToken struct { Token, RefreshToken string; ExpiresAt int64; Params *Map; Mode; HeaderFormat, ParamName string }
func (t *AccessToken) Expires() bool
func (t *AccessToken) Expired() bool
func (t *AccessToken) RefreshRequest(extra ...Param) (*Request, error)
func (t *AccessToken) ApplyTo(headers, params, body *Map) (h, p, b *Map)
func (t *AccessToken) ToHash() *Map

type Request struct { Method, URL string; Params, Body, Headers *Map }
func (r *Request) EncodedBody() string
func (r *Request) FullURL() string

type Response struct { Status int; Headers *Map; Body string }
func (r *Response) Parsed() map[string]any
func (r *Response) ContentType() string

type Error struct { Response *Response; Code, Description string }
func (e *Error) Error() string
func (e *Error) FirstLine() string

func CodeChallenge(verifier string, method PKCEMethod) string // PKCE S256 / plain

type RoundTripper interface { RoundTrip(*Request) (*Response, error) }
```

## Tests & coverage

The suite pairs deterministic, ruby-free tests (which alone hold coverage at
**100%**, so the qemu cross-arch and Windows lanes pass the gate) with a
**differential oracle** against the reference `oauth2` gem: authorize URLs,
token-request specs (each grant × auth-scheme × method), PKCE challenges, and
parsed token/error responses are diffed **byte-for-byte** against the gem. The
oracle scripts `$stdout.binmode` and skip themselves where the gem is absent.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-oauth2/oauth2 authors.
