// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"strconv"
	"strings"
	"time"
)

// nowFunc is the clock, indirected so tests can pin "now" deterministically.
var nowFunc = time.Now

// Mode selects how [AccessToken.ApplyTo] carries the token to a resource
// request, mirroring OAuth2::AccessToken's :mode.
type Mode string

const (
	// ModeHeader carries the token in the Authorization header (the default).
	ModeHeader Mode = "header"
	// ModeQuery carries the token as a query parameter named by ParamName.
	ModeQuery Mode = "query"
	// ModeBody carries the token as a form-body parameter named by ParamName.
	ModeBody Mode = "body"
)

// AccessToken is a parsed OAuth2 access token, mirroring OAuth2::AccessToken. It
// binds the token to its issuing [Client] so [AccessToken.Refresh] can build the
// refresh request. The value model rbgo maps: Token/RefreshToken/ExpiresAt/
// TokenType plus the residual Params.
type AccessToken struct {
	client *Client

	// Token is the bearer/opaque access-token string.
	Token string
	// RefreshToken is the refresh token, or "" if none was issued.
	RefreshToken string
	// ExpiresAt is the absolute expiry as a Unix timestamp, or 0 when the token
	// does not expire (Expires reports whether it is set).
	ExpiresAt int64
	// Params holds the residual response members not promoted to a named field
	// (token_type, scope, and any provider extras), in response order.
	Params *Map

	// Mode / HeaderFormat / ParamName control resource-request injection.
	Mode         Mode
	HeaderFormat string
	ParamName    string
}

// defaultHeaderFormat and defaultParamName match OAuth2::AccessToken's defaults.
const (
	defaultHeaderFormat = "Bearer %s"
	defaultParamName    = "access_token"
)

// NewAccessToken builds a token bound to client with default injection options
// (header mode, "Bearer %s", "access_token"), like OAuth2::AccessToken.new.
func NewAccessToken(client *Client, token string) *AccessToken {
	return &AccessToken{
		client:       client,
		Token:        token,
		Params:       NewMap(),
		Mode:         ModeHeader,
		HeaderFormat: defaultHeaderFormat,
		ParamName:    defaultParamName,
	}
}

// AccessTokenFromHash builds an AccessToken from a parsed token-response map,
// mirroring OAuth2::AccessToken.from_hash. It promotes access_token,
// refresh_token, token_type, expires_at, expires_in, mode, header_format and
// param_name; every other member is retained in Params (in the given order).
// When expires_in is present and expires_at is not, ExpiresAt is derived as
// now + expires_in (the gem's behaviour).
//
// order lists the response keys in their original order so Params preserves it;
// pass nil to fall back to unspecified iteration for the residuals.
func AccessTokenFromHash(client *Client, h map[string]any, order []string) *AccessToken {
	t := NewAccessToken(client, "")
	if order == nil {
		order = keysOf(h)
	}

	var expiresIn int64
	var haveIn, haveAt bool
	for _, k := range order {
		v, ok := h[k]
		if !ok {
			continue
		}
		s := stringify(v)
		switch k {
		case "access_token":
			t.Token = s
		case "refresh_token":
			t.RefreshToken = s
		case "mode":
			t.Mode = Mode(s)
		case "header_format":
			t.HeaderFormat = s
		case "param_name":
			t.ParamName = s
		case "expires_at":
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				t.ExpiresAt = n
				haveAt = true
			}
		case "expires_in":
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				expiresIn = n
				haveIn = true
			}
		default:
			t.Params.Set(k, s)
		}
	}
	if haveIn && !haveAt {
		t.ExpiresAt = nowFunc().Unix() + expiresIn
	}
	return t
}

// TokenType returns the token_type residual param (e.g. "bearer"), or "".
func (t *AccessToken) TokenType() string {
	v, _ := t.Params.Get("token_type")
	return v
}

// Scope returns the scope residual param, or "".
func (t *AccessToken) Scope() string {
	v, _ := t.Params.Get("scope")
	return v
}

// Get returns a residual param by name (OAuth2::AccessToken#[]).
func (t *AccessToken) Get(key string) (string, bool) { return t.Params.Get(key) }

// Expires reports whether the token carries an expiry (OAuth2::AccessToken#expires?).
func (t *AccessToken) Expires() bool { return t.ExpiresAt != 0 }

// Expired reports whether the token has expired: it must have an expiry and that
// expiry must be at or before now (OAuth2::AccessToken#expired?).
func (t *AccessToken) Expired() bool {
	return t.Expires() && t.ExpiresAt <= nowFunc().Unix()
}

// RefreshRequest builds the token-endpoint [Request] that exchanges this token's
// refresh token for a new access token, mirroring OAuth2::AccessToken#refresh's
// request. extra merges additional body params. It returns an error when the
// token has no refresh token (as the gem raises).
func (t *AccessToken) RefreshRequest(extra ...Param) (*Request, error) {
	if t.RefreshToken == "" {
		return nil, errNoRefreshToken
	}
	params := NewMap()
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", t.RefreshToken)
	for _, p := range extra {
		params.Set(p.Key, p.Val)
	}
	return t.client.tokenRequest(params), nil
}

// ApplyTo injects the token into a resource request per the token's Mode. It
// mutates and returns the given headers, params and body maps (any may be nil
// and will be created on demand for its mode). This mirrors
// OAuth2::AccessToken#headers / the request-mode handling.
//
//   - ModeHeader: sets Authorization to HeaderFormat with the token substituted.
//   - ModeQuery:  sets params[ParamName] = token.
//   - ModeBody:   sets body[ParamName] = token.
func (t *AccessToken) ApplyTo(headers, params, body *Map) (h, p, b *Map) {
	switch t.Mode {
	case ModeQuery:
		if params == nil {
			params = NewMap()
		}
		params.Set(t.paramName(), t.Token)
	case ModeBody:
		if body == nil {
			body = NewMap()
		}
		body.Set(t.paramName(), t.Token)
	default: // ModeHeader and any unknown mode fall back to the header.
		if headers == nil {
			headers = NewMap()
		}
		headers.Set("Authorization", strings.Replace(t.headerFormat(), "%s", t.Token, 1))
	}
	return headers, params, body
}

// AuthorizationHeader returns the Authorization header value for the header mode
// (HeaderFormat with the token substituted), a convenience over [AccessToken.ApplyTo].
func (t *AccessToken) AuthorizationHeader() string {
	return strings.Replace(t.headerFormat(), "%s", t.Token, 1)
}

// ToHash renders the token as an ordered map matching OAuth2::AccessToken#to_hash:
// the residual params first (in order), then access_token, refresh_token,
// expires_at, mode, header_format, param_name. refresh_token and expires_at are
// omitted when unset.
func (t *AccessToken) ToHash() *Map {
	m := NewMap()
	for _, p := range t.Params.pairs {
		m.Set(p.Key, p.Val)
	}
	m.Set("access_token", t.Token)
	if t.RefreshToken != "" {
		m.Set("refresh_token", t.RefreshToken)
	}
	if t.Expires() {
		m.Set("expires_at", strconv.FormatInt(t.ExpiresAt, 10))
	}
	m.Set("mode", string(t.Mode))
	m.Set("header_format", t.headerFormat())
	m.Set("param_name", t.paramName())
	return m
}

// headerFormat / paramName supply the defaults when the field was left zero.
func (t *AccessToken) headerFormat() string {
	if t.HeaderFormat == "" {
		return defaultHeaderFormat
	}
	return t.HeaderFormat
}

func (t *AccessToken) paramName() string {
	if t.ParamName == "" {
		return defaultParamName
	}
	return t.ParamName
}
