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

// testZeroLeafHash computes the zero leaf hash in the same way as the PoI circuit:
// SpongeHash(DomainTagPadding=0, [numElems zero field elements]).
// This is NOT the same as SpongeHash(0, []) which has empty input.
func testPoIZeroLeafHash(numElems int) fr.Element {
	elems := make([]fr.Element, numElems)
	return poseidon2hasher.SpongeHash(0, elems) // DomainTagPadding = 0
}

// simpleZeroLeafHash returns SpongeHash(0, []) for simple test cases
// where the tree doesn't need to match PoI's circuit-specific padding.
func simpleZeroLeafHash() fr.Element {
	return poseidon2hasher.SpongeHash(0, nil)
}

// --- buildZeroChain tests ---

func TestBuildZeroChain(t *testing.T) {
	base := simpleZeroLeafHash()
	chain := buildZeroChain(base, 5)
	if !chain[0].Equal(&base) {
		t.Fatal("chain[0] should equal base")
	}
	for k := 1; k <= 5; k++ {
		expected := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{chain[k-1], chain[k-1]})
		if !expected.Equal(&chain[k]) {
			t.Fatalf("chain[%d] mismatch", k)
		}
	}
}

func TestBuildZeroChainDifferentBases(t *testing.T) {
	// Different zero leaf hashes produce different chains.
	base1 := simpleZeroLeafHash()
	base2 := testPoIZeroLeafHash(528)
	if base1.Equal(&base2) {
		t.Fatal("SpongeHash(0,[]) and SpongeHash(0,[528 zeros]) should differ")
	}
	chain1 := buildZeroChain(base1, 3)
	chain2 := buildZeroChain(base2, 3)
	for k := 0; k <= 3; k++ {
		if chain1[k].Equal(&chain2[k]) {
			t.Fatalf("chains should differ at level %d", k)
		}
	}
}

// --- ComputeRoot tests ---

func TestComputeRootEmptyTree(t *testing.T) {
	zeroLeaf := simpleZeroLeafHash()
	chain := buildZeroChain(zeroLeaf, 20)
	for _, depth := range []int{1, 5, 20} {
		root, err := ComputeRoot(nil, depth, zeroLeaf)
		if err != nil {
			t.Fatalf("depth=%d: unexpected error: %v", depth, err)
		}
		if !root.Equal(&chain[depth]) {
			t.Fatalf("depth=%d: empty tree root should be zeroChain[%d]", depth, depth)
		}
	}
}

func TestComputeRootSingleLeaf(t *testing.T) {
	var leaf fr.Element
	leaf.SetInt64(42)
	zeroLeaf := simpleZeroLeafHash()

	// depth=1: root = Hash(leaf, zeroLeaf)
	root, err := ComputeRoot([]fr.Element{leaf}, 1, zeroLeaf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf, zeroLeaf})
	if !root.Equal(&expected) {
		t.Fatal("single leaf depth=1: root mismatch")
	}
}

func TestComputeRootTwoLeaves(t *testing.T) {
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(100)
	leaf1.SetInt64(200)
	zeroLeaf := simpleZeroLeafHash()

	// depth=1: root = Hash(leaf0, leaf1)
	root, err := ComputeRoot([]fr.Element{leaf0, leaf1}, 1, zeroLeaf)
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
	zeroLeaf := simpleZeroLeafHash()

	h1Left := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	h1Right := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf2, zeroLeaf})
	expected := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{h1Left, h1Right})

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1, leaf2}, 2, zeroLeaf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !root.Equal(&expected) {
		t.Fatal("three leaves depth=2: root mismatch")
	}
}

func TestComputeRootDepthLargerThanNeeded(t *testing.T) {
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)
	zeroLeaf := simpleZeroLeafHash()
	chain := buildZeroChain(zeroLeaf, 5)

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1}, 5, zeroLeaf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Hash(leaf0, leaf1) at height 1, then 4 more levels pairing with zero subtrees.
	current := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	for h := 1; h < 5; h++ {
		current = poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{current, chain[h]})
	}
	if !root.Equal(&current) {
		t.Fatal("2 leaves depth=5: root mismatch")
	}
}

func TestComputeRootDepthZero(t *testing.T) {
	zeroLeaf := simpleZeroLeafHash()

	root, err := ComputeRoot(nil, 0, zeroLeaf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !root.Equal(&zeroLeaf) {
		t.Fatal("depth=0 empty: should be zeroLeafHash itself")
	}

	var leaf fr.Element
	leaf.SetInt64(99)
	root, err = ComputeRoot([]fr.Element{leaf}, 0, zeroLeaf)
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
	_, err := ComputeRoot(leaves, 1, simpleZeroLeafHash())
	if err == nil {
		t.Fatal("expected error for 3 leaves in depth=1 tree")
	}
}

func TestComputeRootInvalidDepth(t *testing.T) {
	_, err := ComputeRoot(nil, MaxDepth+1, simpleZeroLeafHash())
	if err == nil {
		t.Fatal("expected error for depth > MaxDepth")
	}
	_, err = ComputeRoot(nil, -1, simpleZeroLeafHash())
	if err == nil {
		t.Fatal("expected error for negative depth")
	}
}

// --- Cross-verification with muri-zkproof SMT logic ---

func TestComputeRootMatchesMuriZkproofSMT(t *testing.T) {
	// Replicate what muri-zkproof/pkg/merkle.BuildSMTFromLeafHashes does:
	// 1. Pre-hashed leaves at indices 0..n-1
	// 2. Zero subtree hashes from a circuit-specific zeroLeafHash
	// 3. Bottom-up construction with HashNodes(left, right) = SpongeHash(2, [left, right])
	//
	// Use the PoI zero leaf hash: SpongeHash(0, [528 zero elements])
	const poiNumChunks = 528
	zeroLeaf := testPoIZeroLeafHash(poiNumChunks)

	// Create 5 "real" leaf hashes (simulating pre-hashed chunks).
	numLeaves := 5
	leafHashes := make([]fr.Element, numLeaves)
	for i := range leafHashes {
		leafHashes[i].SetInt64(int64(i + 1000)) // arbitrary distinct values
	}

	depth := 4 // 2^4 = 16 positions, 5 real leaves

	// Compute root using precompile.
	precompileRoot, err := ComputeRoot(leafHashes, depth, zeroLeaf)
	if err != nil {
		t.Fatalf("ComputeRoot failed: %v", err)
	}

	// Compute root by simulating muri-zkproof's map-based algorithm:
	// levels[0] = leaf hashes, build up using parent indices.
	levels := make([]map[int]fr.Element, depth+1)
	for i := range levels {
		levels[i] = make(map[int]fr.Element)
	}
	for i, h := range leafHashes {
		levels[0][i] = h
	}
	chain := buildZeroChain(zeroLeaf, depth)
	for lvl := 0; lvl < depth; lvl++ {
		parentIndices := make(map[int]bool)
		for idx := range levels[lvl] {
			parentIndices[idx/2] = true
		}
		for parentIdx := range parentIndices {
			left, ok := levels[lvl][parentIdx*2]
			if !ok {
				left = chain[lvl]
			}
			right, ok := levels[lvl][parentIdx*2+1]
			if !ok {
				right = chain[lvl]
			}
			levels[lvl+1][parentIdx] = poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{left, right})
		}
	}
	referenceRoot, ok := levels[depth][0]
	if !ok {
		referenceRoot = chain[depth]
	}

	if !precompileRoot.Equal(&referenceRoot) {
		var pBig, rBig big.Int
		precompileRoot.BigInt(&pBig)
		referenceRoot.BigInt(&rBig)
		t.Fatalf("root mismatch:\n  precompile = %064x\n  reference  = %064x", &pBig, &rBig)
	}
}

func TestComputeRootWithPoIZeroLeafDiffersFromSimple(t *testing.T) {
	// The same leaves but different zero leaf hashes must produce different roots.
	var leaf fr.Element
	leaf.SetInt64(42)

	root1, _ := ComputeRoot([]fr.Element{leaf}, 3, simpleZeroLeafHash())
	root2, _ := ComputeRoot([]fr.Element{leaf}, 3, testPoIZeroLeafHash(528))

	if root1.Equal(&root2) {
		t.Fatal("different zero leaf hashes should produce different roots")
	}
}

// --- VerifyProof tests ---

func TestVerifyProofSimple(t *testing.T) {
	var leaf0, leaf1, leaf2 fr.Element
	leaf0.SetInt64(10)
	leaf1.SetInt64(20)
	leaf2.SetInt64(30)
	zeroLeaf := simpleZeroLeafHash()

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1, leaf2}, 2, zeroLeaf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h1Right := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf2, zeroLeaf})
	if !VerifyProof(leaf0, root, []fr.Element{leaf1, h1Right}, 0, 2) {
		t.Fatal("valid proof for leaf0 rejected")
	}

	if !VerifyProof(leaf1, root, []fr.Element{leaf0, h1Right}, 1, 2) {
		t.Fatal("valid proof for leaf1 rejected")
	}

	h1Left := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	if !VerifyProof(leaf2, root, []fr.Element{zeroLeaf, h1Left}, 2, 2) {
		t.Fatal("valid proof for leaf2 rejected")
	}
}

func TestVerifyProofPaddingLeaf(t *testing.T) {
	var leaf0, leaf1, leaf2 fr.Element
	leaf0.SetInt64(10)
	leaf1.SetInt64(20)
	leaf2.SetInt64(30)
	zeroLeaf := simpleZeroLeafHash()

	root, err := ComputeRoot([]fr.Element{leaf0, leaf1, leaf2}, 2, zeroLeaf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	h1Left := poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{leaf0, leaf1})
	if !VerifyProof(zeroLeaf, root, []fr.Element{leaf2, h1Left}, 3, 2) {
		t.Fatal("valid proof for padding leaf rejected")
	}
}

func TestVerifyProofInvalidSibling(t *testing.T) {
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)

	root, _ := ComputeRoot([]fr.Element{leaf0, leaf1}, 1, simpleZeroLeafHash())
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

	root, _ := ComputeRoot([]fr.Element{leaf0, leaf1}, 1, simpleZeroLeafHash())
	if !VerifyProof(leaf0, root, []fr.Element{leaf1}, 0, 1) {
		t.Fatal("correct proof rejected")
	}
	if VerifyProof(leaf0, root, []fr.Element{leaf1}, 1, 1) {
		t.Fatal("proof with wrong index accepted")
	}
}

func TestVerifyProofSiblingCountMismatch(t *testing.T) {
	var leaf, root fr.Element
	if VerifyProof(leaf, root, []fr.Element{leaf}, 0, 2) {
		t.Fatal("proof with wrong sibling count accepted")
	}
}

func TestVerifyProofLeafIndexOutOfRange(t *testing.T) {
	var leaf, root fr.Element
	if VerifyProof(leaf, root, []fr.Element{leaf}, 2, 1) {
		t.Fatal("proof with out-of-range leaf index accepted")
	}
}

// --- Precompile ABI tests ---

func TestComputeRootPrecompileABI(t *testing.T) {
	method := Poseidon2SMTABI.Methods["computeRoot"]
	leafHashes := []*big.Int{big.NewInt(10), big.NewInt(20), big.NewInt(30)}
	depth := uint8(2)
	zeroLeafBig := new(big.Int)
	zeroLeafFr := simpleZeroLeafHash()
	zeroLeafFr.BigInt(zeroLeafBig)

	packed, err := method.Inputs.Pack(leafHashes, depth, zeroLeafBig)
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

	directRoot, _ := ComputeRootBigInt(leafHashes, 2, zeroLeafBig)
	if abiRoot.Cmp(directRoot) != 0 {
		t.Fatal("ABI result does not match direct computation")
	}
}

func TestVerifyProofPrecompileABI(t *testing.T) {
	method := Poseidon2SMTABI.Methods["verifyProof"]

	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)
	root, _ := ComputeRoot([]fr.Element{leaf0, leaf1}, 1, simpleZeroLeafHash())

	var rootBig, leafBig, sibBig big.Int
	root.BigInt(&rootBig)
	leaf0.BigInt(&leafBig)
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
	zeroLeafBig := new(big.Int)
	zeroLeafFr := simpleZeroLeafHash()
	zeroLeafFr.BigInt(zeroLeafBig)
	packed, _ := method.Inputs.Pack([]*big.Int{big.NewInt(1)}, uint8(1), zeroLeafBig)

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
	bad := new(big.Int).Set(rOrder)
	zeroLeafBig := new(big.Int)
	zeroLeafFr := simpleZeroLeafHash()
	zeroLeafFr.BigInt(zeroLeafBig)
	packed, _ := method.Inputs.Pack([]*big.Int{bad}, uint8(1), zeroLeafBig)

	_, _, err := computeRootHandler(nil, [20]byte{}, [20]byte{}, packed, 100_000, true)
	if err == nil {
		t.Fatal("expected field validation error")
	}
}

// --- End-to-end PoI file root cross-verification ---
//
// Replicates the exact PoI pipeline from muri-zkproof:
//   file bytes → SplitIntoChunks(fileData, FileSize=16384)
//   → HashChunk(chunk) = HashWithDomainTag(DomainTagReal=1, chunk, randomness=1, elemSize=31, numChunks=528)
//   → GenerateSparseMerkleTree(leafHashes, depth=20, zeroLeafHash)
//
// This test verifies the precompile's ComputeRoot matches the muri-zkproof
// map-based SMT algorithm for the same file data.

const (
	poiFileSize    = 16 * 1024 // 16 KB per chunk
	poiElementSize = 31        // bytes per field element
	poiNumChunks   = 528       // ceil(16384 / 31)
	poiMaxDepth    = 20
)

// splitIntoChunksTest mirrors merkle.SplitIntoChunks.
func splitIntoChunksTest(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			chunk := make([]byte, chunkSize)
			copy(chunk, data[i:])
			chunks = append(chunks, chunk)
		} else {
			chunks = append(chunks, data[i:end])
		}
	}
	if len(chunks) == 0 {
		chunks = append(chunks, make([]byte, chunkSize))
	}
	return chunks
}

// hashChunkTest mirrors poi.HashChunk = crypto.HashWithDomainTag(DomainTagReal=1, chunk, randomness=1, 31, 528).
func hashChunkTest(chunk []byte) fr.Element {
	elems := make([]fr.Element, 0, poiNumChunks)
	buf := make([]byte, poiElementSize)

	for offset := 0; offset < len(chunk); offset += poiElementSize {
		for i := range buf {
			buf[i] = 0
		}
		end := offset + poiElementSize
		if end > len(chunk) {
			end = len(chunk)
		}
		copy(buf, chunk[offset:end])

		var elem fr.Element
		elem.SetBytes(buf)
		// randomness = 1, so elem * 1 = elem.
		elems = append(elems, elem)
	}
	for len(elems) < poiNumChunks {
		var zero fr.Element
		elems = append(elems, zero)
	}
	return poseidon2hasher.SpongeHash(1, elems) // DomainTagReal = 1
}

// computePoIZeroLeafHash mirrors crypto.ComputeZeroLeafHash(31, 528).
func computePoIZeroLeafHash() fr.Element {
	elems := make([]fr.Element, poiNumChunks) // all zero
	return poseidon2hasher.SpongeHash(0, elems) // DomainTagPadding = 0
}

// muriZkproofSMTRoot replicates muri-zkproof's BuildSMTFromLeafHashes map-based algorithm.
func muriZkproofSMTRoot(leafHashes []fr.Element, depth int, zeroLeafHash fr.Element) fr.Element {
	chain := buildZeroChain(zeroLeafHash, depth)

	levels := make([]map[int]fr.Element, depth+1)
	for i := range levels {
		levels[i] = make(map[int]fr.Element)
	}
	for i, h := range leafHashes {
		levels[0][i] = h
	}
	for lvl := 0; lvl < depth; lvl++ {
		parentIndices := make(map[int]bool)
		for idx := range levels[lvl] {
			parentIndices[idx/2] = true
		}
		for parentIdx := range parentIndices {
			left, ok := levels[lvl][parentIdx*2]
			if !ok {
				left = chain[lvl]
			}
			right, ok := levels[lvl][parentIdx*2+1]
			if !ok {
				right = chain[lvl]
			}
			levels[lvl+1][parentIdx] = poseidon2hasher.SpongeHash(domainTagNode, []fr.Element{left, right})
		}
	}
	root, ok := levels[depth][0]
	if !ok {
		return chain[depth]
	}
	return root
}

func TestEndToEndPoIFileRoot(t *testing.T) {
	// Create a 32KB test file (2 chunks of 16KB each).
	fileData := make([]byte, 2*poiFileSize)
	for i := range fileData {
		fileData[i] = byte(i % 256)
	}

	// Split into chunks.
	chunks := splitIntoChunksTest(fileData, poiFileSize)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}

	// Hash each chunk (PoI leaf hashing).
	leafHashes := make([]fr.Element, len(chunks))
	for i, chunk := range chunks {
		leafHashes[i] = hashChunkTest(chunk)
	}

	zeroLeaf := computePoIZeroLeafHash()

	// Compute root via precompile.
	precompileRoot, err := ComputeRoot(leafHashes, poiMaxDepth, zeroLeaf)
	if err != nil {
		t.Fatalf("ComputeRoot failed: %v", err)
	}

	// Compute root via muri-zkproof's map-based algorithm.
	referenceRoot := muriZkproofSMTRoot(leafHashes, poiMaxDepth, zeroLeaf)

	if !precompileRoot.Equal(&referenceRoot) {
		var pBig, rBig big.Int
		precompileRoot.BigInt(&pBig)
		referenceRoot.BigInt(&rBig)
		t.Fatalf("PoI file root mismatch:\n  precompile = %064x\n  reference  = %064x", &pBig, &rBig)
	}
}

func TestEndToEndPoISingleChunkFile(t *testing.T) {
	// 16KB file = exactly 1 chunk.
	fileData := make([]byte, poiFileSize)
	for i := range fileData {
		fileData[i] = byte((i * 7) % 256)
	}

	chunks := splitIntoChunksTest(fileData, poiFileSize)
	leafHashes := make([]fr.Element, len(chunks))
	for i, chunk := range chunks {
		leafHashes[i] = hashChunkTest(chunk)
	}

	zeroLeaf := computePoIZeroLeafHash()

	precompileRoot, _ := ComputeRoot(leafHashes, poiMaxDepth, zeroLeaf)
	referenceRoot := muriZkproofSMTRoot(leafHashes, poiMaxDepth, zeroLeaf)

	if !precompileRoot.Equal(&referenceRoot) {
		t.Fatal("single chunk file root mismatch")
	}
}

func TestEndToEndPoISmallFile(t *testing.T) {
	// File smaller than one chunk (100 bytes) — gets zero-padded.
	fileData := []byte("MURI Protocol test data for Poseidon2 SMT cross-verification. " +
		"This tests that the precompile matches muri-zkproof exactly.")

	chunks := splitIntoChunksTest(fileData, poiFileSize)
	leafHashes := make([]fr.Element, len(chunks))
	for i, chunk := range chunks {
		leafHashes[i] = hashChunkTest(chunk)
	}

	zeroLeaf := computePoIZeroLeafHash()

	precompileRoot, _ := ComputeRoot(leafHashes, poiMaxDepth, zeroLeaf)
	referenceRoot := muriZkproofSMTRoot(leafHashes, poiMaxDepth, zeroLeaf)

	if !precompileRoot.Equal(&referenceRoot) {
		t.Fatal("small file root mismatch")
	}
}

// --- Benchmarks ---

func BenchmarkComputeRoot528Leaves(b *testing.B) {
	leaves := make([]fr.Element, 528)
	for i := range leaves {
		leaves[i].SetInt64(int64(i + 1))
	}
	zeroLeaf := testPoIZeroLeafHash(528)
	for i := 0; i < b.N; i++ {
		_, _ = ComputeRoot(leaves, 20, zeroLeaf)
	}
}

func BenchmarkVerifyProofDepth20(b *testing.B) {
	var leaf0, leaf1 fr.Element
	leaf0.SetInt64(1)
	leaf1.SetInt64(2)
	zeroLeaf := simpleZeroLeafHash()
	chain := buildZeroChain(zeroLeaf, 20)

	root, _ := ComputeRoot([]fr.Element{leaf0, leaf1}, 20, zeroLeaf)

	siblings := make([]fr.Element, 20)
	siblings[0] = leaf1
	for h := 1; h < 20; h++ {
		siblings[h] = chain[h]
	}

	for i := 0; i < b.N; i++ {
		VerifyProof(leaf0, root, siblings, 0, 20)
	}
}
