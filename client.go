// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"encoding/base64"
	"strings"
)

// AuthScheme selects how client credentials authenticate the token request,
// mirroring OAuth2::Client's :auth_scheme.
type AuthScheme string

const (
	// AuthBasic sends the credentials as an HTTP Basic Authorization header
	// (base64("id:secret")); the default.
	AuthBasic AuthScheme = "basic_auth"
	// AuthRequestBody sends client_id and client_secret as form-body params.
	AuthRequestBody AuthScheme = "request_body"
	// AuthTLSClientAuth sends only client_id in the body (the secret is carried
	// by the mutual-TLS certificate, out of band), per RFC 8705.
	AuthTLSClientAuth AuthScheme = "tls_client_auth"
)

// TokenMethod is the HTTP method used for the token request.
type TokenMethod string

const (
	// TokenPost issues the token request as a POST with a form body (default).
	TokenPost TokenMethod = "post"
	// TokenGet issues the token request as a GET with query params.
	TokenGet TokenMethod = "get"
)

// Default endpoint paths, matching OAuth2::Client's defaults.
const (
	defaultAuthorizePath = "oauth/authorize"
	defaultTokenPath     = "oauth/token"
)

// Options configures a [Client], mirroring the OAuth2::Client keyword options
// that affect URL/request construction. Empty fields take the gem's defaults.
type Options struct {
	// Site is the base URL against which relative AuthorizeURL/TokenURL resolve.
	Site string
	// AuthorizeURL is the authorization endpoint: an absolute URL, or a path
	// resolved against Site. Defaults to "oauth/authorize".
	AuthorizeURL string
	// TokenURL is the token endpoint: an absolute URL, or a path resolved against
	// Site. Defaults to "oauth/token".
	TokenURL string
	// AuthScheme selects client authentication (default AuthBasic).
	AuthScheme AuthScheme
	// TokenMethod is the token-request HTTP method (default TokenPost).
	TokenMethod TokenMethod
}

// Client is an OAuth2 client bound to a set of credentials and endpoints,
// mirroring OAuth2::Client. It builds authorization URLs and token requests and
// parses responses; the HTTP transport is a host seam (see [RoundTripper]).
type Client struct {
	id      string
	secret  string
	options Options
}

// NewClient returns a Client for the given client id and secret. opts fills in
// the site and endpoints; unset endpoint paths default to the gem's
// "oauth/authorize" and "oauth/token".
func NewClient(id, secret string, opts Options) *Client {
	if opts.AuthorizeURL == "" {
		opts.AuthorizeURL = defaultAuthorizePath
	}
	if opts.TokenURL == "" {
		opts.TokenURL = defaultTokenPath
	}
	if opts.AuthScheme == "" {
		opts.AuthScheme = AuthBasic
	}
	if opts.TokenMethod == "" {
		opts.TokenMethod = TokenPost
	}
	return &Client{id: id, secret: secret, options: opts}
}

// ID returns the client identifier.
func (c *Client) ID() string { return c.id }

// AuthorizeURL returns the fully-qualified authorization endpoint (AuthorizeURL
// resolved against Site), matching OAuth2::Client#authorize_url with no params.
func (c *Client) AuthorizeURL() string {
	return resolveURL(c.options.Site, c.options.AuthorizeURL)
}

// TokenURL returns the fully-qualified token endpoint, matching
// OAuth2::Client#token_url.
func (c *Client) TokenURL() string {
	return resolveURL(c.options.Site, c.options.TokenURL)
}

// resolveURL joins a base site and an endpoint that is either absolute (returned
// as-is) or a path (joined to site with exactly one slash), matching how the gem
// (via Faraday) builds the endpoint URL.
func resolveURL(site, endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	if site == "" {
		return endpoint
	}
	return strings.TrimRight(site, "/") + "/" + strings.TrimLeft(endpoint, "/")
}

// buildAuthorizeURL renders the authorization URL from the client defaults
// (client_id, response_type=code) merged with params, sorted+encoded query.
// Caller-supplied response_type or client_id override the defaults.
func (c *Client) buildAuthorizeURL(params *Map) string {
	q := params.clone()
	q.SetDefault("response_type", "code")
	q.SetDefault("client_id", c.id)
	return c.AuthorizeURL() + "?" + encodeQuery(q)
}

// tokenRequest wraps a grant's body params in a full [Request], applying the
// client-authentication scheme and the token method (POST body vs GET query).
// grantParams already carries grant_type and the grant-specific fields.
func (c *Client) tokenRequest(grantParams *Map) *Request {
	body := grantParams.clone()
	headers := NewMap()

	// Apply client authentication.
	switch c.options.AuthScheme {
	case AuthRequestBody:
		prependClientCreds(body, c.id, c.secret)
	case AuthTLSClientAuth:
		prependClientID(body, c.id)
	default: // AuthBasic
		headers.Set("Authorization", "Basic "+basicCredentials(c.id, c.secret))
	}

	req := &Request{Method: strings.ToUpper(string(c.options.TokenMethod)), URL: c.TokenURL(), Headers: headers}
	if c.options.TokenMethod == TokenGet {
		req.Params = body
	} else {
		req.Body = body
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return req
}

// basicCredentials returns base64("id:secret") for the Basic auth header.
func basicCredentials(id, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
}

// prependClientCreds inserts client_id then client_secret at the front of body,
// matching the gem's request_body authenticator (which prepends the credentials
// ahead of the grant params). Existing keys keep their (front) position.
func prependClientCreds(body *Map, id, secret string) {
	prepend(body, [][2]string{{"client_id", id}, {"client_secret", secret}})
}

// prependClientID inserts client_id at the front of body (tls_client_auth).
func prependClientID(body *Map, id string) {
	prepend(body, [][2]string{{"client_id", id}})
}

// prepend rebuilds body with the given key/value pairs placed first (in order),
// followed by body's existing pairs (a pair whose key is already prepended is
// skipped so it is not duplicated).
func prepend(body *Map, front [][2]string) {
	old := body.pairs
	body.pairs = nil
	body.index = map[string]int{}
	for _, kv := range front {
		body.Set(kv[0], kv[1])
	}
	for _, p := range old {
		body.Set(p.Key, p.Val)
	}
}

// ParseToken turns a token-endpoint [Response] into an [AccessToken], mirroring
// OAuth2::Client#get_token's success path: a >= 400 status becomes an [Error];
// otherwise the parsed body is promoted into an AccessToken bound to this client.
// prevRefresh, when non-empty, is retained as the refresh token if the response
// omits one (the gem's refresh behaviour, which keeps the old refresh token).
func (c *Client) ParseToken(resp *Response) (*AccessToken, error) {
	return c.parseTokenWithRefresh(resp, "")
}

// ParseRefreshToken is like [Client.ParseToken] but preserves prevRefresh when
// the response omits a new refresh_token, matching OAuth2::AccessToken#refresh.
func (c *Client) ParseRefreshToken(resp *Response, prevRefresh string) (*AccessToken, error) {
	return c.parseTokenWithRefresh(resp, prevRefresh)
}

func (c *Client) parseTokenWithRefresh(resp *Response, prevRefresh string) (*AccessToken, error) {
	if resp.Status >= 400 {
		return nil, newError(resp)
	}
	parsed := resp.Parsed()
	order := orderedKeys(resp)
	tok := AccessTokenFromHash(c, parsed, order)
	if tok.RefreshToken == "" && prevRefresh != "" {
		tok.RefreshToken = prevRefresh
	}
	return tok, nil
}

// orderedKeys recovers the token-body member order for a JSON response so
// residual params keep their original order; for a non-JSON/empty body it
// returns nil (sorted-key fallback in AccessTokenFromHash).
func orderedKeys(resp *Response) []string {
	if isJSON(resp.ContentType()) {
		return jsonKeyOrder(resp.Body)
	}
	return nil
}
