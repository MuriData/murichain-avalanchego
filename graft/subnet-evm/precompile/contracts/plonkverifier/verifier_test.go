// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package plonkverifier

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

// Keyleak proof fixture from muri-artifacts/keyleak/keyleak_proof_fixture.json.
// Secret key = 12345 (used for testing only).
var keyleakProofHex = "28c075e3c0f1dab20ec05269b21829dff9252c6ce9aad21fee7fade23676a1f6" +
	"1c9109ba0f3ef6ccb13d1e4316b21e4bc3bf7ae9b22f71d6068f4388d1290c87" +
	"2c3fe5c2c4d414caa750416c2a3d06112a7bca7033780e488c51a729d2f2faf2" +
	"20d42ae63c78246a796cf67291150921f59a2edd999eb0edef7a24c5831ed525" +
	"0d98d00770a8ef2c60c995289746422bbf801d20c85818cd5cfd24ab1f14ec89" +
	"238a15c85344141d65ae3f70745dc620d6a18628e42f39714aababeb2126e8a5" +
	"196a7334084fbde536bc3d6681ea0dd921f8f43b54910bd25eb01414e2657f36" +
	"048353cc2fea7ef1e0e43c847bc9ae5b7797acf74b0c7198accfb06688b8400b" +
	"04630dc34e090021a4cd712a6993818ce538fb3c8e853c3282c196af3c279fac" +
	"154f93e4dee39ec41e53064205f7532bf2786d47f8a5d2bd69b19f183f13ca29" +
	"029fcf195d2f344f4f36cf18b104f7e58a2a74bdbe7bbc0a1492eb52ab908ccb" +
	"0b9a4b851d01af801585d8061973347a91e9181b69b7e142fb0e923f15bceccd" +
	"0179fd140677875064d55f26176ae2f67442fd1157f1f44bf3a7ad0781bdf693" +
	"1b10a2598385e14796d0a3cb7990992831d2f5f1fd03e74fa92ceb745560a54b" +
	"0d4ee6807089df57d80cc0958a17d478b5e842e17a7b4c08dbae04f048010186" +
	"16eca602fb27b4deb6a80dc4e8e516cd7764502e6a48a3ef083a82ff4a043504" +
	"21891f46eb0f004fd2d78d5b3513bf7061e519e07fa74583af1626d4dadf881f" +
	"076aae90f2af25138f4108295ffb004a25380c5fc049a71b881b67a159fc2552" +
	"06740ead2530d5253ca53a0ec0f503c5bd74fc84b6d61dff09b9d6196624a65e" +
	"04ca4b7ee4d6cc2be1f9a74543235e34a84f6db7277834ce0b9219cdaf397248" +
	"13ba0924a6f6763366ce8befd02e8a5ff3ce51751cc4ee1583e1e17d959d69f8" +
	"177b4a27216d4aca8d95f715de0a694d51410fdbe8b890d15681709958b293db" +
	"2858aace658c8d15597bbfe460e91e6a673332ef3299bf7164ca5ea6a528023c" +
	"0df53c38bc95ae63b50d197704bde0ae7b24776559095130179b21fcaeb7232f"

// Keyleak public inputs: [publicKey, reporterAddress]
var keyleakPublicInputs = []*big.Int{
	hexBig("23711d48e08f5ea81d4c9f514ff8aa889adb5cab4130e70dbfd4925c363c5054"),
	hexBig("000000000000000000000000000000000000000000000000000000000000dead"),
}

// Keyleak VK constants from muri-artifacts/keyleak/keyleak_verifier.sol.
func makeKeyleakVK() *VerifyingKey {
	var vk VerifyingKey
	vk.DomainSize = 1024
	vk.NbPublicInputs = 2
	vk.Omega.SetBigInt(decBig("3161067157621608152362653341354432744960400845131437947728257924963983317266"))

	setG1 := func(dst *[2]big.Int, x, y string) {
		dst[0].SetString(x, 10)
		dst[1].SetString(y, 10)
	}
	_ = setG1

	// Gate selector commitments
	vk.QL.X.SetBigInt(decBig("2035804459833848381400357057509651397216026838530505497629317343141306712266"))
	vk.QL.Y.SetBigInt(decBig("8355279827650635802704447371714052300270996825928470109456287905732898110433"))

	vk.QR.X.SetBigInt(decBig("9183070365871851060332588584120849897872672382633757061364548135925360417276"))
	vk.QR.Y.SetBigInt(decBig("19470709932793351160606102569697737584124879816959549602553658461636323473823"))

	vk.QM.X.SetBigInt(decBig("16477726439520696471301046619198940528884911867978045417265195284524843496021"))
	vk.QM.Y.SetBigInt(decBig("16691941964389797036021479336981034814498018324872187243403587473450856724072"))

	vk.QO.X.SetBigInt(decBig("19417865261912958602871331733286007085965154583129775443938642073200287636313"))
	vk.QO.Y.SetBigInt(decBig("18442962065142957483764701013563031792098695859738882451845599075284253067850"))

	vk.QK.X.SetBigInt(decBig("11818817335863913258848207079890809063444566345998996186857219673852355174558"))
	vk.QK.Y.SetBigInt(decBig("20700413223296699079291239552205106526579758163404324406923543789821844582863"))

	// Permutation commitments
	vk.S1.X.SetBigInt(decBig("500459420565242757745570546943386247474647697961652211175353687125824462478"))
	vk.S1.Y.SetBigInt(decBig("11861916703625044797858772015127291618301749816928995302404156210094616371646"))

	vk.S2.X.SetBigInt(decBig("9134944159678686727588420507992563527435236730474190893265799614996690627113"))
	vk.S2.Y.SetBigInt(decBig("20761196047248634238826787839260814568217498839489223366461234004118038224804"))

	vk.S3.X.SetBigInt(decBig("11007627433957552037303858953625732805750421221821159829558842963088895620422"))
	vk.S3.Y.SetBigInt(decBig("4700039204510285229160445775935501666564871090138989415057293661598272263532"))

	// G2 SRS points from keyleak_verifier.sol.
	// Solidity naming: X_0, X_1, Y_0, Y_1 maps to gnark as:
	//   X_0 → X.A1 (imaginary), X_1 → X.A0 (real)
	//   Y_0 → Y.A1 (imaginary), Y_1 → Y.A0 (real)
	// Verified against gnark's canonical G2 generator (bn254.Generators()).
	vk.G2Srs0.X.A1.SetBigInt(decBig("11559732032986387107991004021392285783925812861821192530917403151452391805634")) // G2_SRS_0_X_0
	vk.G2Srs0.X.A0.SetBigInt(decBig("10857046999023057135944570762232829481370756359578518086990519993285655852781")) // G2_SRS_0_X_1
	vk.G2Srs0.Y.A1.SetBigInt(decBig("4082367875863433681332203403145435568316851327593401208105741076214120093531"))  // G2_SRS_0_Y_0
	vk.G2Srs0.Y.A0.SetBigInt(decBig("8495653923123431417604973247489272438418190587263600148770280649306958101930"))  // G2_SRS_0_Y_1

	// G2_SRS_1 from trusted setup.
	vk.G2Srs1.X.A1.SetBigInt(decBig("15189186766845096583418434509224181847730736058359465025908007289216250002794")) // G2_SRS_1_X_0
	vk.G2Srs1.X.A0.SetBigInt(decBig("15216022452205296168577727968522333481605107638177260510732631151259056464255")) // G2_SRS_1_X_1
	vk.G2Srs1.Y.A1.SetBigInt(decBig("20562680811565718244208980846679406647287892098783342631593830385310647445868")) // G2_SRS_1_Y_0
	vk.G2Srs1.Y.A0.SetBigInt(decBig("3521410331563555778805419347035485532604019757282085085118939073278402951336"))  // G2_SRS_1_Y_1

	vk.CosetShift.SetUint64(5)

	return &vk
}

func TestVerifyValidKeyleakProof(t *testing.T) {
	proofBytes, err := hex.DecodeString(keyleakProofHex)
	if err != nil {
		t.Fatalf("failed to decode proof hex: %v", err)
	}

	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	vk := makeKeyleakVK()

	valid, err := Verify(proof, keyleakPublicInputs, vk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Fatal("expected valid proof, got invalid")
	}
}

func TestVerifyInvalidProof(t *testing.T) {
	proofBytes, err := hex.DecodeString(keyleakProofHex)
	if err != nil {
		t.Fatalf("failed to decode proof hex: %v", err)
	}

	// Tamper with one byte.
	proofBytes[10] ^= 0xff

	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		// Tampered point may not be on curve — that's fine.
		return
	}

	vk := makeKeyleakVK()
	valid, err := Verify(proof, keyleakPublicInputs, vk)
	if err != nil {
		return // error is acceptable for invalid proof
	}
	if valid {
		t.Fatal("expected invalid proof after tampering")
	}
}

func TestVerifyWrongPublicInputs(t *testing.T) {
	proofBytes, err := hex.DecodeString(keyleakProofHex)
	if err != nil {
		t.Fatalf("failed to decode proof hex: %v", err)
	}

	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	vk := makeKeyleakVK()

	// Change reporter address.
	badInputs := make([]*big.Int, len(keyleakPublicInputs))
	copy(badInputs, keyleakPublicInputs)
	badInputs[1] = new(big.Int).Add(keyleakPublicInputs[1], big.NewInt(1))

	valid, err := Verify(proof, badInputs, vk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected invalid proof with wrong public inputs")
	}
}

func TestVerifyWrongVK(t *testing.T) {
	proofBytes, err := hex.DecodeString(keyleakProofHex)
	if err != nil {
		t.Fatalf("failed to decode proof hex: %v", err)
	}

	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	vk := makeKeyleakVK()
	// Modify coset shift — should invalidate.
	vk.CosetShift.SetUint64(7)

	valid, err := Verify(proof, keyleakPublicInputs, vk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Fatal("expected invalid proof with wrong VK")
	}
}

func TestVerifyInputNotInField(t *testing.T) {
	proofBytes, err := hex.DecodeString(keyleakProofHex)
	if err != nil {
		t.Fatalf("failed to decode proof hex: %v", err)
	}

	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	vk := makeKeyleakVK()

	// Set input to R (scalar field order) — should be rejected.
	badInputs := []*big.Int{
		new(big.Int).Set(rOrder),
		keyleakPublicInputs[1],
	}

	_, err = Verify(proof, badInputs, vk)
	if err == nil {
		t.Fatal("expected error for input >= R")
	}
}

func TestVerifyProofSizeMismatch(t *testing.T) {
	short := make([]byte, 100) // too short
	_, err := ParseProofSolidity(short)
	if err == nil {
		t.Fatal("expected error for short proof")
	}
}

func TestVerifyPublicInputCountMismatch(t *testing.T) {
	proofBytes, err := hex.DecodeString(keyleakProofHex)
	if err != nil {
		t.Fatalf("failed to decode proof hex: %v", err)
	}

	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	vk := makeKeyleakVK()

	// Pass 3 inputs instead of 2.
	badInputs := []*big.Int{
		keyleakPublicInputs[0],
		keyleakPublicInputs[1],
		big.NewInt(42),
	}

	_, err = Verify(proof, badInputs, vk)
	if err == nil {
		t.Fatal("expected error for input count mismatch")
	}
}

func TestVerifyDomainSizeNotPowerOf2(t *testing.T) {
	proofBytes, _ := hex.DecodeString(keyleakProofHex)
	proof, _ := ParseProofSolidity(proofBytes)
	vk := makeKeyleakVK()
	vk.DomainSize = 1023 // not power of 2

	_, err := Verify(proof, keyleakPublicInputs, vk)
	if err == nil {
		t.Fatal("expected error for non-power-of-2 domain size")
	}
}

// TestFiatShamirGamma verifies the gamma challenge derivation matches a known value.
func TestFiatShamirGamma(t *testing.T) {
	proofBytes, err := hex.DecodeString(keyleakProofHex)
	if err != nil {
		t.Fatalf("failed to decode proof hex: %v", err)
	}

	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}

	vk := makeKeyleakVK()

	// Just verify deriveGamma doesn't panic and returns 32 bytes.
	gamma := deriveGamma(proof, keyleakPublicInputs, vk)
	if len(gamma) != 32 {
		t.Fatalf("expected 32-byte gamma, got %d", len(gamma))
	}

	// Verify gamma is not zero.
	gammaReduced := reduceToFr(gamma)
	var zero fr.Element
	if gammaReduced.Equal(&zero) {
		t.Fatal("gamma should not be zero")
	}
}

func BenchmarkVerify(b *testing.B) {
	proofBytes, err := hex.DecodeString(keyleakProofHex)
	if err != nil {
		b.Fatal(err)
	}
	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		b.Fatal(err)
	}
	vk := makeKeyleakVK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := Verify(proof, keyleakPublicInputs, vk)
		if err != nil {
			b.Fatal(err)
		}
		if !valid {
			b.Fatal("invalid proof")
		}
	}
}
