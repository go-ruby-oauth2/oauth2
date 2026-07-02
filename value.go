// Copyright (c) the go-ruby-oauth2/oauth2 authors
//
// SPDX-License-Identifier: BSD-3-Clause

package oauth2

// Pair is one entry of an ordered string-keyed map.
type Pair struct {
	Key string
	Val string
}

// Map is an insertion-ordered string→string map used for request parameters and
// parsed form bodies. Ruby's `oauth2` gem threads plain Hashes through the flow;
// this ordered map mirrors that while giving deterministic iteration for the
// (unsorted) request-body specs and stable, sorted output for URLs.
type Map struct {
	pairs []Pair
	index map[string]int
}

// NewMap returns an empty ordered Map.
func NewMap() *Map { return &Map{index: map[string]int{}} }

// Len reports the number of entries.
func (m *Map) Len() int { return len(m.pairs) }

// Pairs returns the entries in insertion order. The slice must not be mutated.
func (m *Map) Pairs() []Pair { return m.pairs }

// Set inserts or replaces the entry for key, preserving the position of an
// existing key when it is overwritten (last write wins on value, first write
// wins on order — the gem's Hash semantics).
func (m *Map) Set(key, val string) {
	if m.index == nil {
		m.index = map[string]int{}
	}
	if i, ok := m.index[key]; ok {
		m.pairs[i].Val = val
		return
	}
	m.index[key] = len(m.pairs)
	m.pairs = append(m.pairs, Pair{Key: key, Val: val})
}

// Get returns the value for key and whether it was present.
func (m *Map) Get(key string) (string, bool) {
	if i, ok := m.index[key]; ok {
		return m.pairs[i].Val, true
	}
	return "", false
}

// Has reports whether key is present.
func (m *Map) Has(key string) bool {
	_, ok := m.index[key]
	return ok
}

// SetDefault inserts key→val only if key is absent, mirroring the gem's habit of
// filling in a default (client_id, grant_type, response_type) without clobbering
// a caller-supplied override.
func (m *Map) SetDefault(key, val string) {
	if !m.Has(key) {
		m.Set(key, val)
	}
}

// clone returns a shallow copy of m.
func (m *Map) clone() *Map {
	c := NewMap()
	for _, p := range m.pairs {
		c.Set(p.Key, p.Val)
	}
	return c
}
