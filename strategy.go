// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

// The grant strategies mirror OAuth2::Strategy::*: each exposes the request the
// gem builds for its grant. They are lightweight views over a [Client].

// AuthCode is the authorization-code grant strategy
// (OAuth2::Strategy::AuthCode).
type AuthCode struct{ c *Client }

// AuthCode returns the authorization-code strategy for this client.
func (c *Client) AuthCode() AuthCode { return AuthCode{c} }

// AuthorizeURL builds the authorization URL to redirect the user-agent to,
// mirroring OAuth2::Strategy::AuthCode#authorize_url. The client_id and
// response_type=code defaults are merged in unless params overrides them; every
// param (redirect_uri, scope, state, PKCE code_challenge, provider extras) is
// query-encoded with keys sorted, byte-faithful to the gem.
func (s AuthCode) AuthorizeURL(params Params) string {
	return s.c.buildAuthorizeURL(paramsToMap(params))
}

// GetTokenRequest builds the token request that exchanges an authorization code
// for a token, mirroring OAuth2::Strategy::AuthCode#get_token. The body carries
// grant_type=authorization_code and the code, plus any extra params (typically
// redirect_uri and a PKCE code_verifier); client authentication is applied per
// the client's auth scheme.
func (s AuthCode) GetTokenRequest(code string, extra Params) *Request {
	body := NewMap()
	body.Set("grant_type", "authorization_code")
	body.Set("code", code)
	mergeParams(body, extra)
	return s.c.tokenRequest(body)
}

// ClientCredentials is the client-credentials grant strategy
// (OAuth2::Strategy::ClientCredentials).
type ClientCredentials struct{ c *Client }

// ClientCredentials returns the client-credentials strategy for this client.
func (c *Client) ClientCredentials() ClientCredentials { return ClientCredentials{c} }

// GetTokenRequest builds the client-credentials token request
// (grant_type=client_credentials plus any extra params such as scope).
func (s ClientCredentials) GetTokenRequest(extra Params) *Request {
	body := NewMap()
	mergeParams(body, extra)
	body.Set("grant_type", "client_credentials")
	return s.c.tokenRequest(body)
}

// Password is the resource-owner password-credentials grant strategy
// (OAuth2::Strategy::Password).
type Password struct{ c *Client }

// Password returns the password strategy for this client.
func (c *Client) Password() Password { return Password{c} }

// GetTokenRequest builds the password-grant token request
// (grant_type=password with username and password, plus any extra params).
func (s Password) GetTokenRequest(username, password string, extra Params) *Request {
	body := NewMap()
	body.Set("grant_type", "password")
	body.Set("username", username)
	body.Set("password", password)
	mergeParams(body, extra)
	return s.c.tokenRequest(body)
}

// Assertion is the assertion (JWT-bearer) grant strategy
// (OAuth2::Strategy::Assertion). The signed assertion is supplied by the caller
// (or a host binding to go-ruby-jwt) as the `assertion` param.
type Assertion struct{ c *Client }

// Assertion returns the assertion strategy for this client.
func (c *Client) Assertion() Assertion { return Assertion{c} }

// GetTokenRequest builds the assertion-grant token request. grantType is the
// grant_type URI (e.g. "urn:ietf:params:oauth:grant-type:jwt-bearer"); assertion
// is the signed JWT bearer assertion; extra carries any additional params.
func (s Assertion) GetTokenRequest(grantType, assertion string, extra Params) *Request {
	body := NewMap()
	body.Set("grant_type", grantType)
	body.Set("assertion", assertion)
	mergeParams(body, extra)
	return s.c.tokenRequest(body)
}

// Refresh is the refresh-token grant strategy. It builds the request that
// exchanges a refresh token for a new access token (the request half of
// OAuth2::AccessToken#refresh, usable independently of an AccessToken).
type Refresh struct{ c *Client }

// Refresh returns the refresh strategy for this client.
func (c *Client) Refresh() Refresh { return Refresh{c} }

// GetTokenRequest builds the refresh-token request
// (grant_type=refresh_token with the given refresh token, plus extra params).
func (s Refresh) GetTokenRequest(refreshToken string, extra Params) *Request {
	body := NewMap()
	body.Set("grant_type", "refresh_token")
	body.Set("refresh_token", refreshToken)
	mergeParams(body, extra)
	return s.c.tokenRequest(body)
}

// paramsToMap builds an ordered Map from a Params slice (later duplicates
// overwrite earlier ones, keeping the first position — Ruby Hash semantics).
func paramsToMap(params Params) *Map {
	m := NewMap()
	mergeParams(m, params)
	return m
}

// mergeParams sets each param into m in order.
func mergeParams(m *Map, params Params) {
	for _, p := range params {
		m.Set(p.Key, p.Val)
	}
}
