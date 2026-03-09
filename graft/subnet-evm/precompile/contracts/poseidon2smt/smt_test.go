// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon2smt

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contracts/poseidon2hasher"
)

// hexBig parses a hex string (without 0x prefix) into a *big.Int.
func hexBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex: " + s)
	}
	return v
}

// --- Zero hash tests ---

func TestZeroHashAtHeight0(t *testing.T) {
	// zeroHashes[0] must equal the Poseidon2 hasher's empty-input hash with tag 0.
	want := hexBig("10869d2587f9881a5b769c375e383feeebc31c5ef700085cc4ff4a86c4a9ec15")
	var got big.Int
	zeroHashes[0].BigInt(&got)
	if got.Cmp(want) != 0 {
		t.Fatalf("zeroHashes[0]:\n  got  %064x\n  want %064x", &got, want)
	}
}

func TestZeroHashChain(t *testing.T) {
	// Verify zeroHashes[k] = SpongeHash(2, [zeroHashes[k-1], zeroHashes[k-1]]).
	for k := 1; k <= 5; k++ {
		expected := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{zeroHashes[k-1], zeroHashes[k-1]})
		if !expected.Equal(&zeroHashes[k]) {
			t.Fatalf("zeroHashes[%d] does not match SpongeHash(2, [zeroHashes[%d], zeroHashes[%d]])", k, k-1, k-1)
		}
	}
}

// --- ComputeRoot tests ---

func TestComputeRootEmptyTree(t *testing.T) {
	for _, depth := range []int{1, 5, 20} {
		root, err := ComputeRoot(nil, depth)
		if err != nil {
			t.Fatalf("depth=%d: unexpected error: %v", depth, err)
		}
		if !root.Equal(&zeroHashes[depth]) {
			t.Fatalf("depth=%d: empty tree root should be zeroHashes[%d]", depth, depth)
		}
	}
}

func TestComputeRootSingleLeaf(t *testing.T) {
	var leaf fr.Element
	leaf.SetInt64(42)

	// depth=1: root = Hash(leaf, zeroHashes[0])
	root, err := ComputeRoot([]fr.Element{leaf}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf, zeroHashes[0]})
	if !root.Equal(&expected) {
		t.Fatal("single leaf depth=1: root mismatch")
	}
}

func TestComputeRootTwoLeaves(t *testing.T) {
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(100)
	leaf1.SetInt64(200)

	// depth=1: root = Hash(leaf0, leaf1)
	root, err := ComputeRoot([]fr.Element{leaf0, leaf1}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	if !root.Equal(&expected) {
		t.Fatal("two leaves depth=1: root mismatch")
	}
}

func TestComputeRootThreeLeaves(t *testing.T) {
	var leaf0, leaf1, leaf2 fr.Element
	leaf0.SetInt64(10)
	leaf1.SetInt64(20)
	leaf2.SetInt64(30)

	// depth=2:
	// height 0: [leaf0, leaf1, leaf2, zeroHashes[0]]
	// height 1: [Hash(leaf0, leaf1), Hash(leaf2, zeroHashes[0])]
	// root:     Hash(height1[0], height1[1])
	h1Left := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	h1Right := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf2, zeroHashes[0]})
	expected := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{h1Left, h1Right})

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1, leaf2}, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !root.Equal(&expected) {
		t.Fatal("three leaves depth=2: root mismatch")
	}
}

func TestComputeRootDepthLargerThanNeeded(t *testing.T) {
	// 2 leaves in a depth=5 tree — should hash up with zero subtrees at higher levels.
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1}, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually compute: Hash(leaf0, leaf1) at height 1, then 4 more levels of Hash(node, zeroHashes[h]).
	current := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	for h := 1; h < 5; h++ {
		current = poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{current, zeroHashes[h]})
	}
	if !root.Equal(&current) {
		t.Fatal("2 leaves depth=5: root mismatch")
	}
}

func TestComputeRootDepthZero(t *testing.T) {
	// depth=0: tree has exactly 1 position. With 0 leaves → zeroHashes[0].
	root, err := ComputeRoot(nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !root.Equal(&zeroHashes[0]) {
		t.Fatal("depth=0 empty: should be zeroHashes[0]")
	}

	// depth=0 with 1 leaf: the leaf IS the root (no hashing levels).
	var leaf fr.Element
	leaf.SetInt64(99)
	root, err = ComputeRoot([]fr.Element{leaf}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !root.Equal(&leaf) {
		t.Fatal("depth=0 with 1 leaf: root should equal the leaf")
	}
}

func TestComputeRootTooManyLeavesForDepth(t *testing.T) {
	leaves := make([]fr.Element, 3)
	for i := range leaves {
		leaves[i].SetInt64(int64(i))
	}
	// depth=1 supports max 2 leaves.
	_, err := ComputeRoot(leaves, 1)
	if err == nil {
		t.Fatal("expected error for 3 leaves in depth=1 tree")
	}
}

func TestComputeRootInvalidDepth(t *testing.T) {
	_, err := ComputeRoot(nil, MaxDepth+1)
	if err == nil {
		t.Fatal("expected error for depth > MaxDepth")
	}
	_, err = ComputeRoot(nil, -1)
	if err == nil {
		t.Fatal("expected error for negative depth")
	}
}

// --- VerifyProof tests ---

func TestVerifyProofSimple(t *testing.T) {
	// Build a depth=2 tree with 3 leaves, then verify each leaf's proof.
	var leaf0, leaf1, leaf2 fr.Element
	leaf0.SetInt64(10)
	leaf1.SetInt64(20)
	leaf2.SetInt64(30)

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1, leaf2}, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Compute siblings manually for leaf at index 0.
	// height 0: sibling of index 0 = leaf1
	// height 1: sibling of index 0 = Hash(leaf2, zeroHashes[0])
	h1Right := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf2, zeroHashes[0]})

	if !VerifyProof(leaf0, root, []fr.Element{leaf1, h1Right}, 0, 2) {
		t.Fatal("valid proof for leaf0 rejected")
	}

	// Leaf at index 1: sibling at h=0 is leaf0, at h=1 is h1Right.
	if !VerifyProof(leaf1, root, []fr.Element{leaf0, h1Right}, 1, 2) {
		t.Fatal("valid proof for leaf1 rejected")
	}

	// Leaf at index 2: sibling at h=0 is zeroHashes[0], at h=1 is Hash(leaf0, leaf1).
	h1Left := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	if !VerifyProof(leaf2, root, []fr.Element{zeroHashes[0], h1Left}, 2, 2) {
		t.Fatal("valid proof for leaf2 rejected")
	}
}

func TestVerifyProofPaddingLeaf(t *testing.T) {
	// Verify proof for a padding (zero) leaf at index 3 in the depth=2 tree above.
	var leaf0, leaf1, leaf2 fr.Element
	leaf0.SetInt64(10)
	leaf1.SetInt64(20)
	leaf2.SetInt64(30)

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1, leaf2}, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h1Left := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	// Leaf 3 is zeroHashes[0]; sibling at h=0 is leaf2, at h=1 is h1Left.
	if !VerifyProof(zeroHashes[0], root, []fr.Element{leaf2, h1Left}, 3, 2) {
		t.Fatal("valid proof for padding leaf rejected")
	}
}

func TestVerifyProofInvalidSibling(t *testing.T) {
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Use wrong sibling.
	var wrongSibling fr.Element
	wrongSibling.SetInt64(999)
	if VerifyProof(leaf0, root, []fr.Element{wrongSibling}, 0, 1) {
		t.Fatal("invalid proof accepted")
	}
}

func TestVerifyProofWrongRoot(t *testing.T) {
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)

	var fakeRoot fr.Element
	fakeRoot.SetInt64(12345)

	if VerifyProof(leaf0, fakeRoot, []fr.Element{leaf1}, 0, 1) {
		t.Fatal("proof with wrong root accepted")
	}
}

func TestVerifyProofWrongIndex(t *testing.T) {
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)

	root, _ := ComputeRoot([]fr.Element{leaf0, leaf1}, 1)

	// Proof for leaf0 at index 0 with siblings [leaf1] — should pass.
	if !VerifyProof(leaf0, root, []fr.Element{leaf1}, 0, 1) {
		t.Fatal("correct proof rejected")
	}
	// Same proof but wrong index — should fail.
	if VerifyProof(leaf0, root, []fr.Element{leaf1}, 1, 1) {
		t.Fatal("proof with wrong index accepted")
	}
}

func TestVerifyProofSiblingCountMismatch(t *testing.T) {
	var leaf fr.Element
	leaf.SetInt64(1)
	var root fr.Element

	// depth=2 but only 1 sibling.
	if VerifyProof(leaf, root, []fr.Element{leaf}, 0, 2) {
		t.Fatal("proof with wrong sibling count accepted")
	}
}

func TestVerifyProofLeafIndexOutOfRange(t *testing.T) {
	var leaf, root fr.Element
	// depth=1: max index is 1. Index 2 should fail.
	if VerifyProof(leaf, root, []fr.Element{leaf}, 2, 1) {
		t.Fatal("proof with out-of-range leaf index accepted")
	}
}

// --- Precompile ABI tests ---

func TestComputeRootPrecompileABI(t *testing.T) {
	method := Poseidon2SMTABI.Methods["computeRoot"]
	leafHashes := []*big.Int{big.NewInt(10), big.NewInt(20), big.NewInt(30)}
	depth := uint8(2)

	packed, err := method.Inputs.Pack(leafHashes, depth)
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}

	ret, remainingGas, err := computeRootHandler(nil, [20]byte{}, [20]byte{}, packed, 100_000, true)
	if err != nil {
		t.Fatalf("handler failed: %v", err)
	}

	// Verify gas deduction.
	expectedGas := ComputeRootBaseGas + 3*ComputeRootPerLeafGas + 2*ComputeRootPerLevelGas
	if remainingGas != 100_000-expectedGas {
		t.Fatalf("gas: remaining=%d, expected=%d", remainingGas, 100_000-expectedGas)
	}

	// Verify result matches direct computation.
	results, err := method.Outputs.Unpack(ret)
	if err != nil {
		t.Fatalf("unpack failed: %v", err)
	}
	abiRoot := results[0].(*big.Int)

	directRoot, _ := ComputeRootBigInt(leafHashes, 2)
	if abiRoot.Cmp(directRoot) != 0 {
		t.Fatal("ABI result does not match direct computation")
	}
}

func TestVerifyProofPrecompileABI(t *testing.T) {
	method := Poseidon2SMTABI.Methods["verifyProof"]

	// Build tree and proof.
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)
	root, _ := ComputeRoot([]fr.Element{leaf0, leaf1}, 1)

	var rootBig, leafBig big.Int
	root.BigInt(&rootBig)
	leaf0.BigInt(&leafBig)
	var sibBig big.Int
	leaf1.BigInt(&sibBig)

	packed, err := method.Inputs.Pack(&leafBig, &rootBig, []*big.Int{&sibBig}, big.NewInt(0), uint8(1))
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}

	ret, _, err := verifyProofHandler(nil, [20]byte{}, [20]byte{}, packed, 100_000, true)
	if err != nil {
		t.Fatalf("handler failed: %v", err)
	}

	results, _ := method.Outputs.Unpack(ret)
	valid := results[0].(bool)
	if !valid {
		t.Fatal("valid proof rejected via ABI handler")
	}
}

func TestComputeRootPrecompileOutOfGas(t *testing.T) {
	method := Poseidon2SMTABI.Methods["computeRoot"]
	packed, _ := method.Inputs.Pack([]*big.Int{big.NewInt(1)}, uint8(1))

	_, _, err := computeRootHandler(nil, [20]byte{}, [20]byte{}, packed, 100, true)
	if err == nil {
		t.Fatal("expected out-of-gas error")
	}
}

func TestVerifyProofPrecompileOutOfGas(t *testing.T) {
	method := Poseidon2SMTABI.Methods["verifyProof"]
	packed, _ := method.Inputs.Pack(big.NewInt(1), big.NewInt(2), []*big.Int{big.NewInt(3)}, big.NewInt(0), uint8(1))

	_, _, err := verifyProofHandler(nil, [20]byte{}, [20]byte{}, packed, 100, true)
	if err == nil {
		t.Fatal("expected out-of-gas error")
	}
}

func TestComputeRootPrecompileFieldValidation(t *testing.T) {
	method := Poseidon2SMTABI.Methods["computeRoot"]
	bad := new(big.Int).Set(rOrder) // exactly rOrder
	packed, _ := method.Inputs.Pack([]*big.Int{bad}, uint8(1))

	_, _, err := computeRootHandler(nil, [20]byte{}, [20]byte{}, packed, 100_000, true)
	if err == nil {
		t.Fatal("expected field validation error")
	}
}

// --- Benchmarks ---

func BenchmarkComputeRoot528Leaves(b *testing.B) {
	leaves := make([]fr.Element, 528)
	for i := range leaves {
		leaves[i].SetInt64(int64(i + 1))
	}
	for i := 0; i < b.N; i++ {
		_, _ = ComputeRoot(leaves, 20)
	}
}

func BenchmarkVerifyProofDepth20(b *testing.B) {
	// Build a tree and extract a proof.
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)

	root, _ := ComputeRoot([]fr.Element{leaf0, leaf1}, 20)

	// Compute proof for leaf0: sibling at h=0 is leaf1, rest are zero hashes.
	siblings := make([]fr.Element, 20)
	siblings[0] = leaf1
	for h := 1; h < 20; h++ {
		siblings[h] = zeroHashes[h]
	}

	for i := 0; i < b.N; i++ {
		VerifyProof(leaf0, root, siblings, 0, 20)
	}
}
