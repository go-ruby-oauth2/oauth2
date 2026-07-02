// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import (
	"encoding/json"
	"strings"
)

// jsonKeyOrder returns the top-level object keys of a JSON document in their
// textual order, so residual token params preserve response order (Go's map
// decoding loses it). It returns nil when body is not a JSON object. It reads
// the top-level key tokens and skips over each key's value (scalar or nested
// object/array) using the decoder's depth, so nested keys are never collected.
func jsonKeyOrder(body string) []string {
	dec := json.NewDecoder(strings.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil
	}
	var keys []string
	for dec.More() {
		// Inside an object, dec.More() true guarantees the next token is a string
		// key (the decoder validates the grammar), so a type assertion is safe.
		kt, err := dec.Token()
		if err != nil {
			return keys
		}
		keys = append(keys, kt.(string))
		// Consume the value: a scalar is one token; a nested object/array is a
		// delimiter whose matching close we skip to by tracking depth.
		if err := skipValue(dec); err != nil {
			return keys
		}
	}
	return keys
}

// skipValue consumes exactly one JSON value from dec: a scalar (one token) or a
// balanced object/array. It leaves the decoder positioned after that value.
func skipValue(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := t.(json.Delim)
	if !ok || d == '}' || d == ']' {
		return nil // scalar (or an unexpected close)
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

// Request is the deterministic specification of a single HTTP round-trip the
// library builds for a token operation. The HTTP transport itself is a host
// seam: a host (wiring to go-ruby-net-http / faraday) turns a Request into a
// Response via a [RoundTripper]. All fields are byte-faithful to what the
// `oauth2` gem hands to Faraday.
//
//   - Method is "POST" or "GET" (from the client's token_method).
//   - URL is the fully-qualified token endpoint.
//   - Params carries the form fields when Method is GET (they go in the query
//     string); it is empty for POST.
//   - Body carries the form fields when Method is POST (encoded
//     application/x-www-form-urlencoded); it is empty for GET.
//   - Headers carries the request headers (Content-Type, and Authorization for
//     the basic-auth scheme).
type Request struct {
	Method  string
	URL     string
	Params  *Map
	Body    *Map
	Headers *Map
}

// EncodedBody returns the request body form-encoded (sorted keys, %-escaped),
// suitable for an application/x-www-form-urlencoded POST. It is empty for a GET
// request.
func (r *Request) EncodedBody() string {
	if r.Body == nil {
		return ""
	}
	return encodeQuery(r.Body)
}

// FullURL returns URL with the GET params appended as a query string, or URL
// unchanged for a POST request.
func (r *Request) FullURL() string {
	if r.Params == nil || r.Params.Len() == 0 {
		return r.URL
	}
	sep := "?"
	if strings.Contains(r.URL, "?") {
		sep = "&"
	}
	return r.URL + sep + encodeQuery(r.Params)
}

// RoundTripper is the host transport seam: it performs the HTTP round-trip for a
// built [Request] and returns the raw [Response]. Implementations live in the
// host (go-ruby-net-http / faraday); this package never opens a socket.
type RoundTripper interface {
	RoundTrip(req *Request) (*Response, error)
}

// RoundTripFunc adapts a function to the [RoundTripper] interface.
type RoundTripFunc func(req *Request) (*Response, error)

// RoundTrip calls f(req).
func (f RoundTripFunc) RoundTrip(req *Request) (*Response, error) { return f(req) }

// Response is the raw HTTP response from the token endpoint, as returned by a
// [RoundTripper]. It mirrors OAuth2::Response: Status, Headers and the raw Body,
// with [Response.Parsed] lazily decoding the body by content type.
type Response struct {
	Status  int
	Headers *Map
	Body    string

	parsed map[string]any
	done   bool
}

// NewResponse builds a Response from its parts.
func NewResponse(status int, headers *Map, body string) *Response {
	if headers == nil {
		headers = NewMap()
	}
	return &Response{Status: status, Headers: headers, Body: body}
}

// ContentType returns the response's Content-Type header value with any
// parameters (e.g. "; charset=utf-8") stripped and lower-cased, matching
// OAuth2::Response#content_type's effective media type.
func (r *Response) ContentType() string {
	ct, _ := r.Headers.Get("Content-Type")
	if ct == "" {
		ct, _ = r.Headers.Get("content-type")
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// Parsed decodes the body into a map keyed by string, dispatching on the
// content type exactly as OAuth2::Response does: a JSON media type
// (application/json, or any "+json") is JSON-decoded; a form media type
// (application/x-www-form-urlencoded) is form-decoded; anything else (or an
// undecodable body) yields an empty map. The result is memoised.
func (r *Response) Parsed() map[string]any {
	if r.done {
		return r.parsed
	}
	r.done = true
	r.parsed = parseBody(r.ContentType(), r.Body)
	return r.parsed
}

// parseBody decodes body according to contentType. It is the pure worker behind
// [Response.Parsed]; it never errors — an undecodable body yields an empty map,
// matching the gem's tolerant behaviour.
func parseBody(contentType, body string) map[string]any {
	switch {
	case isJSON(contentType):
		var v map[string]any
		if err := json.Unmarshal([]byte(body), &v); err != nil || v == nil {
			return map[string]any{}
		}
		return v
	case contentType == "application/x-www-form-urlencoded":
		return parseForm(body)
	default:
		return map[string]any{}
	}
}

// isJSON reports whether contentType is a JSON media type: application/json or
// any structured-suffix "+json" type (e.g. application/vnd.api+json).
func isJSON(contentType string) bool {
	return contentType == "application/json" ||
		contentType == "text/json" ||
		strings.HasSuffix(contentType, "+json")
}

// parseForm decodes an application/x-www-form-urlencoded body into a string map.
// Percent-escapes are resolved and '+' is treated as a space, matching Faraday's
// form decoder; a later duplicate key overwrites an earlier one.
func parseForm(body string) map[string]any {
	out := map[string]any{}
	if body == "" {
		return out
	}
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		out[unescapeForm(k)] = unescapeForm(v)
	}
	return out
}

// unescapeForm reverses www-form-urlencoding of s: '+' → space and %XX → byte.
// An invalid or truncated %XX is left literal, matching a tolerant decoder.
func unescapeForm(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			b.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s):
			hi, ok1 := fromHex(s[i+1])
			lo, ok2 := fromHex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
			b.WriteByte('%')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// fromHex parses a single hexadecimal ASCII digit.
func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
