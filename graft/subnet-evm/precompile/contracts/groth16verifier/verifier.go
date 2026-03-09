// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package groth16verifier

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// BN254 field orders and constants for point decompression.
var (
	// pOrder is the base field modulus P.
	pOrder, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)
	// rOrder is the scalar field order R.
	rOrder, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)

	// Exponent for square root: (P + 1) / 4
	expSqrt, _ = new(big.Int).SetString("0C19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52", 16)
	// Exponent for modular inverse: P - 2
	expInverse = new(big.Int).Sub(pOrder, big.NewInt(2))

	// Fp2 constants for G2 decompression.
	fraction12FP, _   = new(big.Int).SetString("183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4", 16)
	fraction2782FP, _ = new(big.Int).SetString("2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5", 16)
	fraction382FP, _  = new(big.Int).SetString("2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775", 16)
)

// Verify performs Groth16 BN254 proof verification.
//
// The verification equation:
//
//	e(A, B) · e(C, -δ) · e(α, -β) · e(L_pub, -γ) = 1
//
// where L_pub = IC[0] + Σ(input[i] * IC[i+1]).
//
// All G2 points (vkBetaNeg, vkGammaNeg, vkDeltaNeg) must be passed already negated,
// matching the convention in the Solidity verifiers (BETA_NEG_*, GAMMA_NEG_*, DELTA_NEG_*).
//
// G2 point coordinate ordering follows EIP-197: [x1, x0, y1, y0] where
// x1 is the imaginary part and x0 is the real part of the Fp2 element.
func Verify(
	proof [8]*big.Int, // [A.x, A.y, B.x1, B.x0, B.y1, B.y0, C.x, C.y]
	publicInputs []*big.Int,
	vkAlpha [2]*big.Int, // [alpha.x, alpha.y]
	vkBetaNeg [4]*big.Int, // [-beta.x1, -beta.x0, -beta.y1, -beta.y0]
	vkGammaNeg [4]*big.Int, // [-gamma.x1, -gamma.x0, -gamma.y1, -gamma.y0]
	vkDeltaNeg [4]*big.Int, // [-delta.x1, -delta.x0, -delta.y1, -delta.y0]
	vkIC [][2]*big.Int, // IC G1 points, length = len(publicInputs) + 1
) (bool, error) {
	// Validate IC length.
	if len(vkIC) != len(publicInputs)+1 {
		return false, ErrICLengthMismatch
	}

	// Validate public inputs are in the scalar field.
	for i, input := range publicInputs {
		if input == nil || input.Sign() < 0 || input.Cmp(rOrder) >= 0 {
			return false, fmt.Errorf("%w: input[%d]", ErrInputNotInField, i)
		}
	}

	// Deserialize proof points.
	A, err := deserializeG1(proof[0], proof[1])
	if err != nil {
		return false, fmt.Errorf("proof point A: %w", err)
	}
	B, err := deserializeG2(proof[2], proof[3], proof[4], proof[5])
	if err != nil {
		return false, fmt.Errorf("proof point B: %w", err)
	}
	C, err := deserializeG1(proof[6], proof[7])
	if err != nil {
		return false, fmt.Errorf("proof point C: %w", err)
	}

	// Deserialize VK points.
	alpha, err := deserializeG1(vkAlpha[0], vkAlpha[1])
	if err != nil {
		return false, fmt.Errorf("vk alpha: %w", err)
	}
	negBeta, err := deserializeG2(vkBetaNeg[0], vkBetaNeg[1], vkBetaNeg[2], vkBetaNeg[3])
	if err != nil {
		return false, fmt.Errorf("vk beta: %w", err)
	}
	negGamma, err := deserializeG2(vkGammaNeg[0], vkGammaNeg[1], vkGammaNeg[2], vkGammaNeg[3])
	if err != nil {
		return false, fmt.Errorf("vk gamma: %w", err)
	}
	negDelta, err := deserializeG2(vkDeltaNeg[0], vkDeltaNeg[1], vkDeltaNeg[2], vkDeltaNeg[3])
	if err != nil {
		return false, fmt.Errorf("vk delta: %w", err)
	}

	// Deserialize IC points.
	icPoints := make([]bn254.G1Affine, len(vkIC))
	for i, ic := range vkIC {
		pt, err := deserializeG1(ic[0], ic[1])
		if err != nil {
			return false, fmt.Errorf("vk IC[%d]: %w", i, err)
		}
		icPoints[i] = pt
	}

	// Compute L_pub = IC[0] + Σ(input[i] * IC[i+1]).
	var L bn254.G1Jac
	L.FromAffine(&icPoints[0])

	if len(publicInputs) > 0 {
		scalars := make([]fr.Element, len(publicInputs))
		points := make([]bn254.G1Affine, len(publicInputs))
		for i, input := range publicInputs {
			scalars[i].SetBigInt(input)
			points[i] = icPoints[i+1]
		}

		var msm bn254.G1Jac
		if _, err := msm.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
			return false, fmt.Errorf("MSM failed: %w", err)
		}
		L.AddAssign(&msm)
	}

	var Laffine bn254.G1Affine
	Laffine.FromJacobian(&L)

	// Pairing check: e(A, B) · e(C, -δ) · e(α, -β) · e(L_pub, -γ) = 1
	P := []bn254.G1Affine{A, C, alpha, Laffine}
	Q := []bn254.G2Affine{B, negDelta, negBeta, negGamma}

	ok, err := bn254.PairingCheck(P, Q)
	if err != nil {
		return false, fmt.Errorf("pairing check: %w", err)
	}

	return ok, nil
}

// deserializeG1 converts two big.Int values (x, y) into a BN254 G1 affine point.
// The point at infinity is encoded as (0, 0).
// Rejects coordinates >= P to prevent silent modular reduction.
func deserializeG1(x, y *big.Int) (bn254.G1Affine, error) {
	var p bn254.G1Affine

	if x == nil || y == nil {
		return p, ErrInvalidInput
	}

	// Point at infinity.
	if x.Sign() == 0 && y.Sign() == 0 {
		p.SetInfinity()
		return p, nil
	}

	// Range check: coordinates must be < P.
	if x.Sign() < 0 || x.Cmp(pOrder) >= 0 {
		return p, fmt.Errorf("%w: G1 x coordinate out of range", ErrPointNotOnCurve)
	}
	if y.Sign() < 0 || y.Cmp(pOrder) >= 0 {
		return p, fmt.Errorf("%w: G1 y coordinate out of range", ErrPointNotOnCurve)
	}

	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)

	if !p.IsOnCurve() {
		return bn254.G1Affine{}, ErrPointNotOnCurve
	}
	// BN254 G1 has cofactor 1, so IsOnCurve implies correct subgroup.
	// Check anyway for defense in depth.
	if !p.IsInSubGroup() {
		return bn254.G1Affine{}, ErrPointNotInSubgroup
	}

	return p, nil
}

// deserializeG2 converts four big.Int values into a BN254 G2 affine point.
//
// Input ordering follows EIP-197 / Solidity convention: [x1, x0, y1, y0]
// where x1 is the imaginary coefficient and x0 is the real coefficient
// of the Fp2 element x = x0 + x1·i.
//
// gnark-crypto uses E2{A0: real, A1: imaginary}, so the mapping is:
//
//	input x1 → p.X.A1 (imaginary)
//	input x0 → p.X.A0 (real)
//	input y1 → p.Y.A1 (imaginary)
//	input y0 → p.Y.A0 (real)
func deserializeG2(x1, x0, y1, y0 *big.Int) (bn254.G2Affine, error) {
	var p bn254.G2Affine

	if x0 == nil || x1 == nil || y0 == nil || y1 == nil {
		return p, ErrInvalidInput
	}

	// Point at infinity.
	if x0.Sign() == 0 && x1.Sign() == 0 && y0.Sign() == 0 && y1.Sign() == 0 {
		p.SetInfinity()
		return p, nil
	}

	// Range check: all coordinates must be < P.
	for _, v := range []*big.Int{x0, x1, y0, y1} {
		if v.Sign() < 0 || v.Cmp(pOrder) >= 0 {
			return p, fmt.Errorf("%w: G2 coordinate out of range", ErrPointNotOnCurve)
		}
	}

	p.X.A0.SetBigInt(x0) // real part
	p.X.A1.SetBigInt(x1) // imaginary part
	p.Y.A0.SetBigInt(y0) // real part
	p.Y.A1.SetBigInt(y1) // imaginary part

	if !p.IsOnCurve() {
		return bn254.G2Affine{}, ErrPointNotOnCurve
	}
	// G2 subgroup check is mandatory — BN254 G2 has cofactor != 1.
	// Without this, an attacker could craft a VK with small-order G2 points.
	if !p.IsInSubGroup() {
		return bn254.G2Affine{}, ErrPointNotInSubgroup
	}

	return p, nil
}

// --- Point decompression (matching Solidity verifier's decompress_g1 / decompress_g2) ---

// fpNegate returns (P - a) mod P.
func fpNegate(a *big.Int) *big.Int {
	r := new(big.Int).Mod(a, pOrder)
	r.Sub(pOrder, r)
	r.Mod(r, pOrder)
	return r
}

// fpSqrt computes sqrt(a) mod P using a^((P+1)/4).
func fpSqrt(a *big.Int) *big.Int {
	return new(big.Int).Exp(a, expSqrt, pOrder)
}

// fpInverse computes a^(-1) mod P via Fermat's little theorem.
func fpInverse(a *big.Int) *big.Int {
	return new(big.Int).Exp(a, expInverse, pOrder)
}

// fpMul returns (a * b) mod P.
func fpMul(a, b *big.Int) *big.Int {
	r := new(big.Int).Mul(a, b)
	r.Mod(r, pOrder)
	return r
}

// fpAdd returns (a + b) mod P.
func fpAdd(a, b *big.Int) *big.Int {
	r := new(big.Int).Add(a, b)
	r.Mod(r, pOrder)
	return r
}

// fpIsSquare returns true if x^2 == a mod P for some x.
func fpIsSquare(a *big.Int) bool {
	x := fpSqrt(a)
	return new(big.Int).Mod(new(big.Int).Mul(x, x), pOrder).Cmp(new(big.Int).Mod(a, pOrder)) == 0
}

// fp2Sqrt computes the square root in Fp2 = Fp[i]/(i²+1).
// Matches the Solidity verifier's sqrt_Fp2 function.
func fp2Sqrt(a0, a1 *big.Int, hint bool) (x0, x1 *big.Int, err error) {
	d := fpSqrt(fpAdd(fpMul(a0, a0), fpMul(a1, a1)))
	if hint {
		d = fpNegate(d)
	}
	x0 = fpSqrt(fpMul(fpAdd(a0, d), fraction12FP))
	if x0.Sign() == 0 {
		return nil, nil, fmt.Errorf("decompression failed: zero x0 in Fp2 sqrt")
	}
	x1 = fpMul(a1, fpInverse(fpMul(x0, big.NewInt(2))))

	// Validate: a0 == x0² - x1² and a1 == 2·x0·x1
	check0 := fpAdd(fpMul(x0, x0), fpNegate(fpMul(x1, x1)))
	check1 := fpMul(big.NewInt(2), fpMul(x0, x1))
	a0mod := new(big.Int).Mod(a0, pOrder)
	a1mod := new(big.Int).Mod(a1, pOrder)
	if check0.Cmp(a0mod) != 0 || check1.Cmp(a1mod) != 0 {
		return nil, nil, fmt.Errorf("Fp2 sqrt validation failed")
	}
	return x0, x1, nil
}

// DecompressG1 decompresses a compressed G1 point.
// Format: c = (x << 1) | sign_bit.
func DecompressG1(c *big.Int) (x, y *big.Int, err error) {
	if c == nil {
		return nil, nil, ErrInvalidInput
	}
	if c.Sign() == 0 {
		return new(big.Int), new(big.Int), nil
	}

	negatePoint := c.Bit(0) == 1
	x = new(big.Int).Rsh(c, 1)

	if x.Cmp(pOrder) >= 0 {
		return nil, nil, fmt.Errorf("%w: compressed G1 x >= P", ErrPointNotOnCurve)
	}

	// y² = x³ + 3
	x3 := fpMul(fpMul(x, x), x)
	rhs := fpAdd(x3, big.NewInt(3))
	y = fpSqrt(rhs)

	// Validate sqrt
	if new(big.Int).Mod(new(big.Int).Mul(y, y), pOrder).Cmp(new(big.Int).Mod(rhs, pOrder)) != 0 {
		return nil, nil, fmt.Errorf("%w: x not on G1 curve", ErrPointNotOnCurve)
	}

	if negatePoint {
		y = fpNegate(y)
	}
	return x, y, nil
}

// DecompressG2 decompresses a compressed G2 point.
// Input: c0 = (x0 << 2) | (hint ? 2 : 0) | sign_bit, c1 = x1.
// Returns (x0, x1, y0, y1) in internal Fp2 order.
func DecompressG2(c0, c1 *big.Int) (x0, x1, y0, y1 *big.Int, err error) {
	if c0 == nil || c1 == nil {
		return nil, nil, nil, nil, ErrInvalidInput
	}
	if c0.Sign() == 0 && c1.Sign() == 0 {
		return new(big.Int), new(big.Int), new(big.Int), new(big.Int), nil
	}

	negatePoint := c0.Bit(0) == 1
	hint := c0.Bit(1) == 1
	x0 = new(big.Int).Rsh(c0, 2)
	x1 = new(big.Int).Set(c1)

	if x0.Cmp(pOrder) >= 0 || x1.Cmp(pOrder) >= 0 {
		return nil, nil, nil, nil, fmt.Errorf("%w: compressed G2 coordinate >= P", ErrPointNotOnCurve)
	}

	// Compute y² components from the G2 curve equation: y² = x³ + 3/(9+i)
	pMinus3 := new(big.Int).Sub(pOrder, big.NewInt(3))
	n3ab := fpMul(fpMul(x0, x1), pMinus3)
	a3 := fpMul(fpMul(x0, x0), x0)
	b3 := fpMul(fpMul(x1, x1), x1)
	y0 = fpAdd(fraction2782FP, fpAdd(a3, fpMul(n3ab, x1)))
	y1 = fpNegate(fpAdd(fraction382FP, fpAdd(b3, fpMul(n3ab, x0))))

	y0, y1, err = fp2Sqrt(y0, y1, hint)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("%w: %w", ErrPointNotOnCurve, err)
	}

	if negatePoint {
		y0 = fpNegate(y0)
		y1 = fpNegate(y1)
	}
	return x0, x1, y0, y1, nil
}

// DecompressProof decompresses a 4-element compressed Groth16 proof into
// the 8-element uncompressed format.
//
// Compressed format: [compressed_A, B_c1, B_c0, compressed_C]
// Uncompressed format: [A.x, A.y, B.x1, B.x0, B.y1, B.y0, C.x, C.y]
func DecompressProof(compressed [4]*big.Int) ([8]*big.Int, error) {
	var proof [8]*big.Int

	// Decompress A (G1)
	ax, ay, err := DecompressG1(compressed[0])
	if err != nil {
		return proof, fmt.Errorf("decompress A: %w", err)
	}
	proof[0] = ax
	proof[1] = ay

	// Decompress B (G2): c0=compressed[2], c1=compressed[1]
	// DecompressG2 returns (x0, x1, y0, y1) in internal order
	bx0, bx1, by0, by1, err := DecompressG2(compressed[2], compressed[1])
	if err != nil {
		return proof, fmt.Errorf("decompress B: %w", err)
	}
	// Solidity uncompressed format: [B.x1, B.x0, B.y1, B.y0]
	proof[2] = bx1
	proof[3] = bx0
	proof[4] = by1
	proof[5] = by0

	// Decompress C (G1)
	cx, cy, err := DecompressG1(compressed[3])
	if err != nil {
		return proof, fmt.Errorf("decompress C: %w", err)
	}
	proof[6] = cx
	proof[7] = cy

	return proof, nil
}
