// Package main is an independent RFC 6962 Merkle tree oracle for Citadel's
// kt-log. It is deliberately implemented straight from the RFC 6962 §2.1
// definitions (Merkle Tree Hash, audit PATH, consistency PROOF/SUBPROOF) in a
// different language and by a different author-model than crates/kt-log/src/
// tree.rs, so that the fixtures it emits are a genuine cross-check and not a
// re-encoding of the code under test (PLAN.md §13 independent-oracle rule).
//
// It is a TEST-TIME tool only: it never ships in any product artifact, imports
// nothing from the predecessor project, and links no Citadel code. Its sole
// output is the JSON fixture corpus consumed by
// crates/kt-log/tests/go_oracle_fixtures.rs.
//
// Hashing (RFC 6962 §2.1):
//
//	leaf hash = SHA-256(0x00 || entry)
//	node hash = SHA-256(0x01 || left || right)
//	MTH({})   = SHA-256("")
package main

import "crypto/sha256"

// leafHash is RFC 6962's MTH of a single entry: SHA-256(0x00 || entry).
func leafHash(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entry)
	return h.Sum(nil)
}

// nodeHash is RFC 6962's interior node hash: SHA-256(0x01 || left || right).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less
// than n. Precondition: n >= 2 (the only context RFC 6962 uses k in).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// merkleTreeHash is RFC 6962 §2.1 MTH(D[n]) over the list of leaf entries
// (raw pre-hash bytes). The empty tree hashes to SHA-256("").
func merkleTreeHash(entries [][]byte) []byte {
	n := len(entries)
	switch n {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		return leafHash(entries[0])
	default:
		k := largestPowerOfTwoLessThan(n)
		return nodeHash(merkleTreeHash(entries[:k]), merkleTreeHash(entries[k:]))
	}
}

// auditPath is RFC 6962 §2.1.1 PATH(m, D[n]): the audit path for the leaf at
// index m within the tree over entries. Returns leaf-to-root sibling hashes.
// Precondition: 0 <= m < len(entries).
func auditPath(m int, entries [][]byte) [][]byte {
	n := len(entries)
	if n == 1 {
		// PATH(0, {d0}) = {}
		return [][]byte{}
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(auditPath(m, entries[:k]), merkleTreeHash(entries[k:]))
	}
	return append(auditPath(m-k, entries[k:]), merkleTreeHash(entries[:k]))
}

// consistencyProof is RFC 6962 §2.1.2 PROOF(m, D[n]): the consistency proof
// between the tree of the first m entries and the tree over all n entries.
// Precondition: 0 < m <= len(entries).
func consistencyProof(m int, entries [][]byte) [][]byte {
	return subProof(m, entries, true)
}

// subProof is RFC 6962 §2.1.2 SUBPROOF(m, D[n], b).
func subProof(m int, entries [][]byte, complete bool) [][]byte {
	n := len(entries)
	if m == n {
		if complete {
			return [][]byte{}
		}
		return [][]byte{merkleTreeHash(entries)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subProof(m, entries[:k], complete), merkleTreeHash(entries[k:]))
	}
	return append(subProof(m-k, entries[k:], false), merkleTreeHash(entries[:k]))
}
