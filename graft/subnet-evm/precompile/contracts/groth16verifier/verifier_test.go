// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package groth16verifier

import (
	"math/big"
	"testing"
)

// hexBig parses a hex string (without 0x prefix) into a *big.Int.
func hexBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex: " + s)
	}
	return v
}

// decBig parses a decimal string into a *big.Int.
func decBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid decimal: " + s)
	}
	return v
}

// PoI verification key constants from muri-artifacts/poi/poi_verifier.sol lines 56-87.
// G2 format: [x1(imaginary), x0(real), y1(imaginary), y0(real)] matching EIP-197 ordering.
var (
	poiAlpha = [2]*big.Int{
		decBig("16984406090375906538856649714891900376566808276216508035997547137095219587652"),
		decBig("4082054207606487801990297365683642323701020617307952748192280065883587978777"),
	}
	poiBetaNeg = [4]*big.Int{
		decBig("8968787828758646730824359957201541638846188769991673996554900888012189962133"),   // x1 (imaginary)
		decBig("13903557558619729110516698272555564250607281491874364155389716115918264764840"),  // x0 (real)
		decBig("7541280757538873985652591214451081479243523427343634092112386736464462838383"),   // y1 (imaginary)
		decBig("18984854107669530173045650272186764720268734203958013396524055641308854496232"),  // y0 (real)
	}
	poiGammaNeg = [4]*big.Int{
		decBig("15173908959737787370306337492897819882466825671628357605228577038145107887019"), // x1 (imaginary)
		decBig("1649298875234363572828892404338159505176047940998603639384227959288656830249"),  // x0 (real)
		decBig("11544725729975803695295104219339971252825057280897510005028260512907572989784"), // y1 (imaginary)
		decBig("8666001085288197870988633754749712755593546940921125873260794660366352980452"),  // y0 (real)
	}
	poiDeltaNeg = [4]*big.Int{
		decBig("4370569653384751069583838889696282616772705406811520793332198656431613190691"),  // x1 (imaginary)
		decBig("7134880054083676526062291671783770304098110767788316048644173821204755932635"),  // x0 (real)
		decBig("6434805825625284975823982539036470768703294823017068322041802634340239458745"),  // y1 (imaginary)
		decBig("17234867549872866186830735539185680070206806431363796558137861126293284224853"), // y0 (real)
	}
	poiIC = [][2]*big.Int{
		{ // CONSTANT
			decBig("16048201595335767932009198417871986122767654760768031453235598526006375368074"),
			decBig("4950978717326891053344708306574984558668747963430403356343830460879876278900"),
		},
		{ // PUB_0
			decBig("184197631290949916587427241782345511915246088406310822824480748270344919591"),
			decBig("21207723552402005908226478926395053469204790976572072217015561431820760113237"),
		},
		{ // PUB_1
			decBig("16557264066653923363553552711415017791327885176638119174980176533320629097844"),
			decBig("3837501704293424539842806375226114573518912439625691315885857019064950084473"),
		},
		{ // PUB_2
			decBig("9611439344809898916283370276113232371021999215794952036846764025060204916963"),
			decBig("6920078263064660029987125191849613524389330943503891550538607623354528761095"),
		},
		{ // PUB_3
			decBig("21793345983320437032870913138660142116482264029722127955819146211326514833701"),
			decBig("1863219341808331287506178581480657985934333172461886557018553759881919166091"),
		},
	}
)

// PoI proof fixture from muri-artifacts/poi/poi_proof_fixture.json.
// This is the canonical fixture used by Solidity contract tests.
var (
	poiProof = [8]*big.Int{
		hexBig("2ce6840a98b72a6e16ea2a15a9fc84a379a4f95583b4c33ce7f2a6b5d8313c48"), // A.x
		hexBig("186a0b7c204b0ec083114fab37b1e26a80ec4f2dfda73395bb36f29e94cb0ebd"), // A.y
		hexBig("2a79489d428e20937deb42b914e5c2117dd607781ee625386ee8740f57e8cbbb"), // B.x1
		hexBig("24627f3ef68a245b49e9e9ef2fa698ff562e0f82813abdbcc95b6a14037916a0"), // B.x0
		hexBig("10f6687ccb2f78f38105670a6d71f5b9f92b1f3b9af0e8e9764dece7c263cdfb"), // B.y1
		hexBig("21a3a427cb6a091ee1f184f7ebbeefb907d416ab6e169cef20d52b3c82a9e361"), // B.y0
		hexBig("19a99957d700916830a92889b9de37bca0ac76dc0f035694638979cb0004cdf5"), // C.x
		hexBig("283b3f32d65918010fb52c5baff8a75b0cc4df09b94c7e9249134276129f0236"), // C.y
	}
	// Public inputs: [commitment, randomness, publicKey, rootHash]
	poiPublicInputs = []*big.Int{
		hexBig("22e408f58658a312456c0d8b4a1a4d89a8559c34975143bd68c34b3c60d5a6a5"), // commitment
		hexBig("000000000000000000000000000000000000000000000000000000000000002a"), // randomness
		hexBig("23711d48e08f5ea81d4c9f514ff8aa889adb5cab4130e70dbfd4925c363c5054"), // publicKey
		hexBig("18b3b3b2725896132b5bc40a1046132880775d2160f1fbf5dc70ffc58a9228c7"), // rootHash
	}
)

func TestVerifyValidPoIProof(t *testing.T) {
	valid, err := Verify(poiProof, poiPublicInputs, poiAlpha, poiBetaNeg, poiGammaNeg, poiDeltaNeg, poiIC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Fatal("expected valid proof, got invalid")
	}
}

func TestVerifyInvalidProof(t *testing.T) {
	// Flip one byte of proof point A.x.
	badProof := poiProof
	badProof[0] = new(big.Int).Add(poiProof[0], big.NewInt(1))

	valid, err := Verify(badProof, poiPublicInputs, poiAlpha, poiBetaNeg, poiGammaNeg, poiDeltaNeg, poiIC)
	// The modified point may not be on the curve, causing a deserialization error,
	// or it may be on the curve but fail the pairing check.
	if err != nil {
		// Deserialization error is acceptable — proof is invalid either way.
		return
	}
	if valid {
		t.Fatal("expected invalid proof after modifying A.x")
	}
}

func TestVerifyWrongPublicInput(t *testing.T) {
	// Change one public input.
	badInputs := make([]*big.Int, len(poiPublicInputs))
	copy(badInputs, poiPublicInputs)
	badInputs[0] = new(big.Int).Add(poiPublicInputs[0], big.NewInt(1))

	valid, err := Verify(poiProof, badInputs, poiAlpha, poiBetaNeg, poiGammaNeg, poiDeltaNeg, poiIC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected invalid proof with wrong public input")
	}
}

func TestVerifyInputNotInField(t *testing.T) {
	badInputs := make([]*big.Int, len(poiPublicInputs))
	copy(badInputs, poiPublicInputs)
	// Set input[0] to R (scalar field order) — should be rejected.
	badInputs[0] = new(big.Int).Set(rOrder)

	_, err := Verify(poiProof, badInputs, poiAlpha, poiBetaNeg, poiGammaNeg, poiDeltaNeg, poiIC)
	if err == nil {
		t.Fatal("expected error for input >= R")
	}
}

func TestVerifyICLengthMismatch(t *testing.T) {
	// Pass IC with wrong length (4 instead of 5 for 4 public inputs).
	shortIC := poiIC[:4]
	_, err := Verify(poiProof, poiPublicInputs, poiAlpha, poiBetaNeg, poiGammaNeg, poiDeltaNeg, shortIC)
	if err == nil {
		t.Fatal("expected IC length mismatch error")
	}
}

func TestDeserializeG1PointAtInfinity(t *testing.T) {
	p, err := deserializeG1(big.NewInt(0), big.NewInt(0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.IsInfinity() {
		t.Fatal("expected point at infinity")
	}
}

func TestDeserializeG1OutOfRange(t *testing.T) {
	// x coordinate >= P should be rejected.
	_, err := deserializeG1(pOrder, big.NewInt(1))
	if err == nil {
		t.Fatal("expected error for x >= P")
	}
}

func TestDeserializeG2CoordinateMapping(t *testing.T) {
	// Verify that the known PoI beta point deserializes without error.
	// This confirms the [x1, x0, y1, y0] → gnark E2{A0, A1} mapping is correct.
	_, err := deserializeG2(poiBetaNeg[0], poiBetaNeg[1], poiBetaNeg[2], poiBetaNeg[3])
	if err != nil {
		t.Fatalf("failed to deserialize known G2 point: %v", err)
	}
}

func TestDeserializeG2OutOfRange(t *testing.T) {
	_, err := deserializeG2(pOrder, big.NewInt(0), big.NewInt(0), big.NewInt(0))
	if err == nil {
		t.Fatal("expected error for coordinate >= P")
	}
}

// --- Compression test helpers ---

// compressG1Test compresses a G1 point (x, y) into (x << 1) | sign_bit.
func compressG1Test(x, y *big.Int) *big.Int {
	c := new(big.Int).Lsh(x, 1)
	// Compute the default y = sqrt(x³ + 3)
	x3 := fpMul(fpMul(x, x), x)
	rhs := fpAdd(x3, big.NewInt(3))
	yDefault := fpSqrt(rhs)
	// If actual y differs from default sqrt, set sign bit to negate during decompression.
	if y.Cmp(yDefault) != 0 {
		c.SetBit(c, 0, 1)
	}
	return c
}

// compressG2Test compresses a G2 point by brute-forcing all 4 (hint, sign) combos.
// Input follows EIP-197: (x1, x0, y1, y0) where x1=imaginary, x0=real.
func compressG2Test(x1, x0, y1, y0 *big.Int) (c0, c1 *big.Int) {
	c1 = new(big.Int).Set(x1) // c1 is always x1 (imaginary part of x)
	for hintBit := uint(0); hintBit <= 1; hintBit++ {
		for signBit := uint(0); signBit <= 1; signBit++ {
			c0 = new(big.Int).Lsh(x0, 2) // real part of x
			c0.SetBit(c0, 1, hintBit)
			c0.SetBit(c0, 0, signBit)

			dx0, dx1, dy0, dy1, err := DecompressG2(c0, c1)
			if err != nil {
				continue
			}
			// DecompressG2 returns (x0, x1, y0, y1) in internal order.
			// Compare to our inputs (which are in EIP-197 order).
			if dx0.Cmp(x0) == 0 && dx1.Cmp(x1) == 0 &&
				dy0.Cmp(y0) == 0 && dy1.Cmp(y1) == 0 {
				return c0, c1
			}
		}
	}
	panic("compressG2Test: no valid (hint, sign) combination found")
}

// compressProofTest compresses an 8-element uncompressed proof into 4-element compressed format.
// Compressed format: [compressed_A, B_c1, B_c0, compressed_C]
func compressProofTest(proof [8]*big.Int) [4]*big.Int {
	compA := compressG1Test(proof[0], proof[1])
	bC0, bC1 := compressG2Test(proof[2], proof[3], proof[4], proof[5])
	compC := compressG1Test(proof[6], proof[7])
	return [4]*big.Int{compA, bC1, bC0, compC}
}

// --- Compressed proof tests ---

// Compressed proof values computed by muri-zkproof/pkg/crypto CompressProof
// from the canonical poi_proof_fixture.json above.
// Format: [compressed_A, B_c1, B_c0, compressed_C]
var poiCompressedProof = [4]*big.Int{
	hexBig("59cd0815316e54dc2dd4542b53f90946f349f2ab07698679cfe54d6bb0627890"), // compressed A
	hexBig("2a79489d428e20937deb42b914e5c2117dd607781ee625386ee8740f57e8cbbb"), // B_c1 (= B.x1)
	hexBig("9189fcfbda28916d27a7a7bcbe9a63fd58b83e0a04eaf6f3256da8500de45a81"), // B_c0
	hexBig("335332afae0122d06152511373bc6f794158edb81e06ad28c712f39600099beb"), // compressed C
}

func TestDecompressG1Roundtrip(t *testing.T) {
	x, y := poiProof[0], poiProof[1]
	c := compressG1Test(x, y)

	dx, dy, err := DecompressG1(c)
	if err != nil {
		t.Fatalf("DecompressG1 failed: %v", err)
	}
	if dx.Cmp(x) != 0 || dy.Cmp(y) != 0 {
		t.Fatal("G1 roundtrip mismatch")
	}
}

func TestDecompressG2Roundtrip(t *testing.T) {
	// B point from proof: [x1, x0, y1, y0]
	x1, x0 := poiProof[2], poiProof[3]
	y1, y0 := poiProof[4], poiProof[5]

	c0, c1 := compressG2Test(x1, x0, y1, y0)
	dx0, dx1, dy0, dy1, err := DecompressG2(c0, c1)
	if err != nil {
		t.Fatalf("DecompressG2 failed: %v", err)
	}
	if dx0.Cmp(x0) != 0 || dx1.Cmp(x1) != 0 || dy0.Cmp(y0) != 0 || dy1.Cmp(y1) != 0 {
		t.Fatal("G2 roundtrip mismatch")
	}
}

func TestDecompressRealCompressedProof(t *testing.T) {
	// Decompress the real compressed proof values produced by muri-zkproof CompressProof.
	proof, err := DecompressProof(poiCompressedProof)
	if err != nil {
		t.Fatalf("DecompressProof failed: %v", err)
	}

	// Decompressed proof must match the known uncompressed proof exactly.
	for i := 0; i < 8; i++ {
		if proof[i].Cmp(poiProof[i]) != 0 {
			t.Fatalf("proof[%d] mismatch: got %s, want %s",
				i, proof[i].Text(16), poiProof[i].Text(16))
		}
	}

	// Full Groth16 verification with the decompressed proof.
	valid, err := Verify(proof, poiPublicInputs, poiAlpha, poiBetaNeg, poiGammaNeg, poiDeltaNeg, poiIC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Fatal("expected valid proof from real compressed data")
	}
}

func TestDecompressProofRoundtrip(t *testing.T) {
	// Compress using test helpers, decompress, verify match.
	compressed := compressProofTest(poiProof)

	proof, err := DecompressProof(compressed)
	if err != nil {
		t.Fatalf("DecompressProof failed: %v", err)
	}
	for i := 0; i < 8; i++ {
		if proof[i].Cmp(poiProof[i]) != 0 {
			t.Fatalf("proof[%d] mismatch after roundtrip", i)
		}
	}
}

func TestDecompressG1PointAtInfinity(t *testing.T) {
	x, y, err := DecompressG1(big.NewInt(0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if x.Sign() != 0 || y.Sign() != 0 {
		t.Fatal("expected (0,0) for compressed zero")
	}
}

func TestDecompressG1InvalidX(t *testing.T) {
	// x >= P should fail
	c := new(big.Int).Lsh(pOrder, 1) // x = pOrder
	_, _, err := DecompressG1(c)
	if err == nil {
		t.Fatal("expected error for x >= P")
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		valid, err := Verify(poiProof, poiPublicInputs, poiAlpha, poiBetaNeg, poiGammaNeg, poiDeltaNeg, poiIC)
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("invalid proof")
		}
	}
}
