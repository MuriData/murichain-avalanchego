// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package plonkverifier

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Proof represents a deserialized PLONK BN254 proof.
type Proof struct {
	LCom, RCom, OCom          bn254.G1Affine // wire commitments
	H0Com, H1Com, H2Com       bn254.G1Affine // quotient polynomial split
	LAtZeta, RAtZeta, OAtZeta fr.Element      // wire evaluations at ζ
	S1AtZeta, S2AtZeta        fr.Element      // permutation evaluations at ζ
	ZCom                      bn254.G1Affine  // grand product commitment
	ZAtZetaOmega              fr.Element      // grand product eval at ζω
	BatchOpenZeta             bn254.G1Affine  // KZG opening proof at ζ
	BatchOpenZetaOmega        bn254.G1Affine  // KZG opening proof at ζω
}

// VerifyingKey represents a PLONK BN254 verification key.
type VerifyingKey struct {
	DomainSize     uint64
	NbPublicInputs uint64
	Omega          fr.Element
	QL, QR, QM, QO, QK bn254.G1Affine // gate selector commitments
	S1, S2, S3          bn254.G1Affine // permutation commitments
	G2Srs0, G2Srs1      bn254.G2Affine // SRS G2 points
	CosetShift           fr.Element
}

// ParseProofSolidity deserializes a PLONK proof from gnark's MarshalSolidity
// format (768 bytes for circuits with no custom gates).
//
// Layout:
//
//	0x000  L commitment (G1)
//	0x040  R commitment (G1)
//	0x080  O commitment (G1)
//	0x0c0  H₀ commitment (G1)
//	0x100  H₁ commitment (G1)
//	0x140  H₂ commitment (G1)
//	0x180  L(ζ) (scalar)
//	0x1a0  R(ζ) (scalar)
//	0x1c0  O(ζ) (scalar)
//	0x1e0  S₁(ζ) (scalar)
//	0x200  S₂(ζ) (scalar)
//	0x220  Z commitment (G1)
//	0x260  Z(ζω) (scalar)
//	0x280  W_ζ opening (G1)
//	0x2c0  W_ζω opening (G1)
func ParseProofSolidity(data []byte) (*Proof, error) {
	if len(data) < 0x300 {
		return nil, fmt.Errorf("proof too short: got %d bytes, expected at least 768", len(data))
	}

	var p Proof
	var err error

	// Helper to read a 32-byte big-endian scalar from offset.
	readScalar := func(offset int) *big.Int {
		return new(big.Int).SetBytes(data[offset : offset+32])
	}

	// Helper to deserialize a G1 point from two consecutive 32-byte words.
	readG1 := func(offset int) (bn254.G1Affine, error) {
		x := readScalar(offset)
		y := readScalar(offset + 0x20)
		return deserializeG1(x, y)
	}

	// Helper to deserialize a scalar field element, validating < R.
	readFr := func(offset int) (fr.Element, error) {
		v := readScalar(offset)
		if v.Cmp(rOrder) >= 0 {
			return fr.Element{}, fmt.Errorf("scalar at offset 0x%x >= R", offset)
		}
		var e fr.Element
		e.SetBigInt(v)
		return e, nil
	}

	// Wire commitments.
	if p.LCom, err = readG1(0x000); err != nil {
		return nil, fmt.Errorf("L commitment: %w", err)
	}
	if p.RCom, err = readG1(0x040); err != nil {
		return nil, fmt.Errorf("R commitment: %w", err)
	}
	if p.OCom, err = readG1(0x080); err != nil {
		return nil, fmt.Errorf("O commitment: %w", err)
	}

	// Quotient polynomial split.
	if p.H0Com, err = readG1(0x0c0); err != nil {
		return nil, fmt.Errorf("H0 commitment: %w", err)
	}
	if p.H1Com, err = readG1(0x100); err != nil {
		return nil, fmt.Errorf("H1 commitment: %w", err)
	}
	if p.H2Com, err = readG1(0x140); err != nil {
		return nil, fmt.Errorf("H2 commitment: %w", err)
	}

	// Wire evaluations at ζ.
	if p.LAtZeta, err = readFr(0x180); err != nil {
		return nil, fmt.Errorf("L(ζ): %w", err)
	}
	if p.RAtZeta, err = readFr(0x1a0); err != nil {
		return nil, fmt.Errorf("R(ζ): %w", err)
	}
	if p.OAtZeta, err = readFr(0x1c0); err != nil {
		return nil, fmt.Errorf("O(ζ): %w", err)
	}

	// Permutation evaluations at ζ.
	if p.S1AtZeta, err = readFr(0x1e0); err != nil {
		return nil, fmt.Errorf("S1(ζ): %w", err)
	}
	if p.S2AtZeta, err = readFr(0x200); err != nil {
		return nil, fmt.Errorf("S2(ζ): %w", err)
	}

	// Grand product commitment.
	if p.ZCom, err = readG1(0x220); err != nil {
		return nil, fmt.Errorf("Z commitment: %w", err)
	}

	// Grand product evaluation at ζω.
	if p.ZAtZetaOmega, err = readFr(0x260); err != nil {
		return nil, fmt.Errorf("Z(ζω): %w", err)
	}

	// KZG opening proofs.
	if p.BatchOpenZeta, err = readG1(0x280); err != nil {
		return nil, fmt.Errorf("batch open at ζ: %w", err)
	}
	if p.BatchOpenZetaOmega, err = readG1(0x2c0); err != nil {
		return nil, fmt.Errorf("batch open at ζω: %w", err)
	}

	return &p, nil
}
