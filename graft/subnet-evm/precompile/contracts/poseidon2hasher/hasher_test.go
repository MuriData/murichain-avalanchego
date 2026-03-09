// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon2hasher

import (
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

// --- Cross-checked test vectors (verified against muri-zkproof v0.19.0 AND gnark-crypto v0.18.1) ---

func TestSpongeHashEmptyInput(t *testing.T) {
	want := hexBig("10869d2587f9881a5b769c375e383feeebc31c5ef700085cc4ff4a86c4a9ec15")
	got, err := SpongeHashBigInt(0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("empty input (tag=0):\n  got  %064x\n  want %064x", got, want)
	}
}

func TestSpongeHashDerivePublicKey(t *testing.T) {
	want := hexBig("2092496c2e9df388bcb3b8f879f7124fcfe94d8834030e7b2e37cd37adc5e1ff")
	got, err := SpongeHashBigInt(7, []*big.Int{big.NewInt(42)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("DerivePublicKey(42) tag=7:\n  got  %064x\n  want %064x", got, want)
	}
}

func TestSpongeHashMerkleNode(t *testing.T) {
	want := hexBig("16c00244643cd64e067fa25220fa0b8cdc0f7bce32d84c5325a216d8185acb35")
	got, err := SpongeHashBigInt(2, []*big.Int{big.NewInt(1), big.NewInt(2)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("Merkle node(1,2) tag=2:\n  got  %064x\n  want %064x", got, want)
	}
}

func TestSpongeHash4Inputs(t *testing.T) {
	want := hexBig("108a3acc1ad62c1226dd95673c23781b49e27e8005f677d8e94a4b7652001d0f")
	inputs := []*big.Int{big.NewInt(10), big.NewInt(20), big.NewInt(30), big.NewInt(40)}
	got, err := SpongeHashBigInt(9, inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("4-input tag=9:\n  got  %064x\n  want %064x", got, want)
	}
}

func TestSpongeHashOddCount(t *testing.T) {
	want := hexBig("0b32162e940d89f8cf4e6d23ae800d0cb3e09ff6be49bf7e8321a9dd7628b6d9")
	inputs := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
	got, err := SpongeHashBigInt(3, inputs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("odd count(100,200,300) tag=3:\n  got  %064x\n  want %064x", got, want)
	}
}

func TestSpongeHashLargeValue(t *testing.T) {
	want := hexBig("1ea4d5864808cf4e091c275df5d81d63b93ef533288a789f6850a3514a700d00")
	input := hexBig("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	got, err := SpongeHashBigInt(7, []*big.Int{input})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("large value tag=7:\n  got  %064x\n  want %064x", got, want)
	}
}

// --- Input validation tests ---

func TestSpongeHashInputOutOfField(t *testing.T) {
	_, err := SpongeHashBigInt(0, []*big.Int{new(big.Int).Set(rOrder)})
	if err == nil {
		t.Fatal("expected error for input >= rOrder")
	}
}

func TestSpongeHashInputAboveField(t *testing.T) {
	above := new(big.Int).Add(rOrder, big.NewInt(1))
	_, err := SpongeHashBigInt(0, []*big.Int{above})
	if err == nil {
		t.Fatal("expected error for input > rOrder")
	}
}

func TestSpongeHashNegativeInput(t *testing.T) {
	_, err := SpongeHashBigInt(0, []*big.Int{big.NewInt(-1)})
	if err == nil {
		t.Fatal("expected error for negative input")
	}
}

func TestSpongeHashTooManyInputs(t *testing.T) {
	inputs := make([]*big.Int, MaxInputs+1)
	for i := range inputs {
		inputs[i] = big.NewInt(int64(i))
	}
	_, err := SpongeHashBigInt(0, inputs)
	if err == nil {
		t.Fatal("expected error for too many inputs")
	}
}

func TestSpongeHashMaxInputsOK(t *testing.T) {
	inputs := make([]*big.Int, MaxInputs)
	for i := range inputs {
		inputs[i] = big.NewInt(int64(i))
	}
	_, err := SpongeHashBigInt(0, inputs)
	if err != nil {
		t.Fatalf("unexpected error for MaxInputs: %v", err)
	}
}

// --- fr.Element level tests ---

func TestSpongeHashFrDirect(t *testing.T) {
	// Verify the fr.Element path matches the big.Int path.
	var in1, in2 fr.Element
	in1.SetInt64(1)
	in2.SetInt64(2)
	frResult := SpongeHash(2, []fr.Element{in1, in2})

	bigResult, err := SpongeHashBigInt(2, []*big.Int{big.NewInt(1), big.NewInt(2)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var frBig big.Int
	frResult.BigInt(&frBig)
	if frBig.Cmp(bigResult) != 0 {
		t.Fatal("fr.Element and big.Int paths produce different results")
	}
}

// --- Gas calculation tests ---

func TestGasCalculation(t *testing.T) {
	tests := []struct {
		name      string
		numInputs int
		wantGas   uint64
	}{
		{"empty", 0, HashBaseGas},
		{"1 input (DerivePublicKey)", 1, HashBaseGas + 1*HashPerInputGas},
		{"2 inputs (Merkle node)", 2, HashBaseGas + 2*HashPerInputGas},
		{"4 inputs (DeriveCommitment)", 4, HashBaseGas + 4*HashPerInputGas},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashBaseGas + uint64(tt.numInputs)*HashPerInputGas
			if got != tt.wantGas {
				t.Fatalf("gas for %d inputs: got %d, want %d", tt.numInputs, got, tt.wantGas)
			}
		})
	}
}

// --- Precompile-level ABI tests ---

func TestHashPrecompileABIRoundtrip(t *testing.T) {
	// Pack a hash call, then verify the handler can process it.
	method := Poseidon2HasherABI.Methods["hash"]
	domainTag := uint8(2)
	inputs := []*big.Int{big.NewInt(1), big.NewInt(2)}

	packed, err := method.Inputs.Pack(domainTag, inputs)
	if err != nil {
		t.Fatalf("failed to pack inputs: %v", err)
	}

	// Call the handler directly (AccessibleState is unused for this stateless precompile).
	suppliedGas := uint64(10_000)
	ret, remainingGas, err := hash(nil, [20]byte{}, [20]byte{}, packed, suppliedGas, true)
	if err != nil {
		t.Fatalf("hash handler failed: %v", err)
	}

	// Verify gas deduction.
	expectedGas := HashBaseGas + 2*HashPerInputGas
	if remainingGas != suppliedGas-expectedGas {
		t.Fatalf("gas: remaining=%d, expected=%d", remainingGas, suppliedGas-expectedGas)
	}

	// Unpack and verify result.
	results, err := method.Outputs.Unpack(ret)
	if err != nil {
		t.Fatalf("failed to unpack output: %v", err)
	}
	digest, ok := results[0].(*big.Int)
	if !ok {
		t.Fatalf("expected *big.Int, got %T", results[0])
	}

	want := hexBig("16c00244643cd64e067fa25220fa0b8cdc0f7bce32d84c5325a216d8185acb35")
	if digest.Cmp(want) != 0 {
		t.Fatalf("ABI roundtrip:\n  got  %064x\n  want %064x", digest, want)
	}
}

func TestHashPrecompileOutOfGas(t *testing.T) {
	method := Poseidon2HasherABI.Methods["hash"]
	packed, err := method.Inputs.Pack(uint8(0), []*big.Int{big.NewInt(1)})
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}

	// Supply less gas than required.
	_, _, err = hash(nil, [20]byte{}, [20]byte{}, packed, 100, true)
	if err == nil {
		t.Fatal("expected out-of-gas error")
	}
}

func TestHashPrecompileFieldValidation(t *testing.T) {
	method := Poseidon2HasherABI.Methods["hash"]
	badInput := new(big.Int).Set(rOrder) // exactly rOrder, should be rejected
	packed, err := method.Inputs.Pack(uint8(0), []*big.Int{badInput})
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}

	_, _, err = hash(nil, [20]byte{}, [20]byte{}, packed, 10_000, true)
	if err == nil {
		t.Fatal("expected field validation error")
	}
}

func TestHashPrecompileTooManyInputs(t *testing.T) {
	method := Poseidon2HasherABI.Methods["hash"]
	inputs := make([]*big.Int, MaxInputs+1)
	for i := range inputs {
		inputs[i] = big.NewInt(int64(i))
	}
	packed, err := method.Inputs.Pack(uint8(0), inputs)
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}

	_, _, err = hash(nil, [20]byte{}, [20]byte{}, packed, 1_000_000, true)
	if err == nil {
		t.Fatal("expected too-many-inputs error")
	}
}

// --- Benchmarks ---

func BenchmarkSpongeHash2Inputs(b *testing.B) {
	var in1, in2 fr.Element
	in1.SetInt64(1)
	in2.SetInt64(2)
	inputs := []fr.Element{in1, in2}
	for i := 0; i < b.N; i++ {
		SpongeHash(2, inputs)
	}
}

func BenchmarkSpongeHash8Inputs(b *testing.B) {
	inputs := make([]fr.Element, 8)
	for i := range inputs {
		inputs[i].SetInt64(int64(i + 1))
	}
	for i := 0; i < b.N; i++ {
		SpongeHash(0, inputs)
	}
}
