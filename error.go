// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

import "strings"

// Error is raised for an unsuccessful token response, mirroring OAuth2::Error.
// It carries the originating [Response] and the extracted OAuth error fields.
// Code is the `error` member of the parsed body (or "" if absent); Description
// is `error_description`. Message reproduces the gem's assembled message.
type Error struct {
	Response    *Response
	Code        string
	Description string
	message     string
}

// Error implements the error interface.
func (e *Error) Error() string { return e.message }

// newError builds an Error from a Response, extracting the OAuth error/
// error_description fields (from a parsed JSON/form body when present) and
// composing the message the same way OAuth2::Error does:
//
//   - with a parsed `error`: "<error>: <error_description>" (the description and
//     its ": " separator omitted when the description is empty), followed by the
//     raw body on its own line;
//   - without a parsed `error`: the raw body alone.
func newError(resp *Response) *Error {
	parsed := resp.Parsed()
	code, _ := parsed["error"].(string)
	desc, _ := parsed["error_description"].(string)

	var msg string
	if code != "" {
		msg = code
		if desc != "" {
			msg += ": " + desc
		}
		if resp.Body != "" {
			msg += "\n" + resp.Body
		}
	} else {
		msg = resp.Body
	}
	return &Error{Response: resp, Code: code, Description: desc, message: msg}
}

// FirstLine returns the first line of the error message (the "code: description"
// summary), a convenience for logging without the appended raw body.
func (e *Error) FirstLine() string {
	if i := strings.IndexByte(e.message, '\n'); i >= 0 {
		return e.message[:i]
	}
	return e.message
}
