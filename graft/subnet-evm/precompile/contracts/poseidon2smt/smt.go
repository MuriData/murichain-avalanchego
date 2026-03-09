// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon2smt

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/poseidon2hasher"
)

const (
	// MaxDepth is the maximum supported tree depth (covers archive trees at depth 30).
	MaxDepth = 30

	// MaxLeaves caps the number of leaves accepted by computeRoot.
	// Naturally limited by calldata gas; this prevents unbounded memory allocation.
	MaxLeaves = 16384

	// Domain tag for internal Merkle nodes, matching muri-zkproof/pkg/crypto/domain.go.
	domainTagNode = 2
)

var (
	// rOrder is the BN254 scalar field order.
	rOrder, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)

	ErrInvalidDepth  = errors.New("invalid tree depth")
	ErrTooManyLeaves = errors.New("too many leaves for given depth")
	ErrSiblingCount  = errors.New("sibling count must equal depth")
	ErrLeafIndex     = errors.New("leaf index out of range")
)

// buildZeroChain computes the zero-subtree hash chain from a given zero leaf hash.
//
//	zeroChain[0] = zeroLeafHash
//	zeroChain[k] = SpongeHash(DomainTagNode, [zeroChain[k-1], zeroChain[k-1]])
//
// Matches muri-zkproof/pkg/merkle.PrecomputeZeroHashes exactly.
func buildZeroChain(zeroLeafHash fr.Element, depth int) []fr.Element {
	chain := make([]fr.Element, depth+1)
	chain[0] = zeroLeafHash
	for i := 1; i <= depth; i++ {
		chain[i] = poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{chain[i-1], chain[i-1]})
	}
	return chain
}

// ComputeRoot builds a sparse Merkle tree root from pre-hashed leaves.
//
// Leaves occupy indices 0..len-1 at height 0. All other positions use the
// provided zeroLeafHash. Internal nodes use Poseidon2 with domain tag 2.
//
// The zeroLeafHash is circuit-specific: for PoI it is
// SpongeHash(DomainTagPadding, [528 zero elements]), not SpongeHash(0, []).
//
// Matches muri-zkproof/pkg/merkle.BuildSMTFromLeafHashes exactly.
func ComputeRoot(leafHashes []fr.Element, depth int, zeroLeafHash fr.Element) (fr.Element, error) {
	if depth < 0 || depth > MaxDepth {
		return fr.Element{}, ErrInvalidDepth
	}

	zeroChain := buildZeroChain(zeroLeafHash, depth)

	n := len(leafHashes)
	if n == 0 {
		return zeroChain[depth], nil
	}

	maxLeaves := 1 << depth
	if n > maxLeaves {
		return fr.Element{}, ErrTooManyLeaves
	}

	// Working array: only the "active" prefix (entries beyond are zero subtrees).
	current := make([]fr.Element, n)
	copy(current, leafHashes)

	// Build bottom-up from height 0 (leaves) to height depth (root).
	for h := 0; h < depth; h++ {
		activeCount := len(current)
		parentCount := (activeCount + 1) / 2
		parents := make([]fr.Element, parentCount)

		for i := 0; i < parentCount; i++ {
			left := current[2*i]
			var right fr.Element
			if 2*i+1 < activeCount {
				right = current[2*i+1]
			} else {
				right = zeroChain[h]
			}
			parents[i] = poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{left, right})
		}

		current = parents
	}

	return current[0], nil
}

// ComputeRootBigInt is a convenience wrapper that accepts and returns *big.Int.
func ComputeRootBigInt(leafHashes []*big.Int, depth int, zeroLeafHash *big.Int) (*big.Int, error) {
	elems := make([]fr.Element, len(leafHashes))
	for i, v := range leafHashes {
		elems[i].SetBigInt(v)
	}
	var zeroFr fr.Element
	zeroFr.SetBigInt(zeroLeafHash)
	root, err := ComputeRoot(elems, depth, zeroFr)
	if err != nil {
		return nil, err
	}
	out := new(big.Int)
	root.BigInt(out)
	return out, nil
}

// VerifyProof checks a sparse Merkle inclusion proof.
//
// The proof path is determined by leafIndex bits: bit i of leafIndex selects
// left (0) or right (1) at height i. This matches muri-zkproof's GetProof
// direction convention where 0 = current is left child, 1 = right child.
//
// The caller provides the siblings directly (which already contain the correct
// zero subtree hashes at the appropriate positions), so no zeroLeafHash is needed.
func VerifyProof(leafHash, root fr.Element, siblings []fr.Element, leafIndex uint64, depth int) bool {
	if depth < 0 || depth > MaxDepth {
		return false
	}
	if len(siblings) != depth {
		return false
	}
	if depth > 0 && leafIndex >= uint64(1)<<depth {
		return false
	}

	current := leafHash
	idx := leafIndex

	for i := 0; i < depth; i++ {
		if idx&1 == 0 {
			// Current is left child, sibling on right.
			current = poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{current, siblings[i]})
		} else {
			// Current is right child, sibling on left.
			current = poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{siblings[i], current})
		}
		idx >>= 1
	}

	return current.Equal(&root)
}

// VerifyProofBigInt is a convenience wrapper using *big.Int.
func VerifyProofBigInt(leafHash, root *big.Int, siblings []*big.Int, leafIndex uint64, depth int) bool {
	var leafFr, rootFr fr.Element
	leafFr.SetBigInt(leafHash)
	rootFr.SetBigInt(root)
	sibFr := make([]fr.Element, len(siblings))
	for i, s := range siblings {
		sibFr[i].SetBigInt(s)
	}
	return VerifyProof(leafFr, rootFr, sibFr, leafIndex, depth)
}
