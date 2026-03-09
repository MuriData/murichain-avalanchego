// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package plonkverifier

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// BN254 field orders (same as groth16verifier).
var (
	pOrder, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)
	rOrder, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
)

// deserializeG1 converts two big.Int values (x, y) into a BN254 G1 affine point.
// Duplicated from groth16verifier to keep precompile packages independent.
func deserializeG1(x, y *big.Int) (bn254.G1Affine, error) {
	var p bn254.G1Affine

	if x == nil || y == nil {
		return p, fmt.Errorf("nil coordinate")
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		p.SetInfinity()
		return p, nil
	}

	if x.Sign() < 0 || x.Cmp(pOrder) >= 0 {
		return p, fmt.Errorf("G1 x coordinate out of range")
	}
	if y.Sign() < 0 || y.Cmp(pOrder) >= 0 {
		return p, fmt.Errorf("G1 y coordinate out of range")
	}

	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)

	if !p.IsOnCurve() {
		return bn254.G1Affine{}, fmt.Errorf("G1 point not on curve")
	}
	if !p.IsInSubGroup() {
		return bn254.G1Affine{}, fmt.Errorf("G1 point not in subgroup")
	}

	return p, nil
}

// deserializeG2 converts four big.Int values into a BN254 G2 affine point.
// EIP-197 ordering: [x1, x0, y1, y0] where x1=imaginary, x0=real.
func deserializeG2(x1, x0, y1, y0 *big.Int) (bn254.G2Affine, error) {
	var p bn254.G2Affine

	if x0 == nil || x1 == nil || y0 == nil || y1 == nil {
		return p, fmt.Errorf("nil coordinate")
	}

	if x0.Sign() == 0 && x1.Sign() == 0 && y0.Sign() == 0 && y1.Sign() == 0 {
		p.SetInfinity()
		return p, nil
	}

	for _, v := range []*big.Int{x0, x1, y0, y1} {
		if v.Sign() < 0 || v.Cmp(pOrder) >= 0 {
			return p, fmt.Errorf("G2 coordinate out of range")
		}
	}

	p.X.A0.SetBigInt(x0)
	p.X.A1.SetBigInt(x1)
	p.Y.A0.SetBigInt(y0)
	p.Y.A1.SetBigInt(y1)

	if !p.IsOnCurve() {
		return bn254.G2Affine{}, fmt.Errorf("G2 point not on curve")
	}
	if !p.IsInSubGroup() {
		return bn254.G2Affine{}, fmt.Errorf("G2 point not in subgroup")
	}

	return p, nil
}

// Verify performs full PLONK BN254 proof verification.
//
// The algorithm follows the gnark-generated Solidity verifier exactly:
//  1. Fiat-Shamir challenge derivation (SHA256): γ, β, α, ζ
//  2. Polynomial evaluation: vanishing poly, Lagrange basis, public input contribution
//  3. Linearised polynomial commitment
//  4. KZG batch verification (2-pairing check)
func Verify(proof *Proof, publicInputs []*big.Int, vk *VerifyingKey) (bool, error) {
	// Validate inputs.
	if uint64(len(publicInputs)) != vk.NbPublicInputs {
		return false, fmt.Errorf("expected %d public inputs, got %d", vk.NbPublicInputs, len(publicInputs))
	}
	for i, inp := range publicInputs {
		if inp == nil || inp.Sign() < 0 || inp.Cmp(rOrder) >= 0 {
			return false, fmt.Errorf("public input[%d] not in scalar field", i)
		}
	}
	if vk.DomainSize == 0 || (vk.DomainSize&(vk.DomainSize-1)) != 0 {
		return false, fmt.Errorf("domain size %d is not a power of 2", vk.DomainSize)
	}

	// Phase 1: Fiat-Shamir challenge derivation.
	gammaUnreduced := deriveGamma(proof, publicInputs, vk)
	gamma := reduceToFr(gammaUnreduced)

	betaUnreduced := deriveBeta(gammaUnreduced)
	beta := reduceToFr(betaUnreduced)

	alphaUnreduced := deriveAlpha(proof, betaUnreduced)
	alpha := reduceToFr(alphaUnreduced)

	zetaUnreduced := deriveZeta(proof, alphaUnreduced)
	zeta := reduceToFr(zetaUnreduced)

	// Phase 2: Polynomial evaluation.
	// ζⁿ - 1 (vanishing polynomial at ζ)
	var zetaPowerN fr.Element
	zetaPowerN.Set(&zeta)
	for i := uint64(0); i < log2(vk.DomainSize); i++ {
		zetaPowerN.Square(&zetaPowerN)
	}
	var one fr.Element
	one.SetOne()
	var zetaPowerNMinusOne fr.Element
	zetaPowerNMinusOne.Sub(&zetaPowerN, &one)

	// Lagrange bases L_i(ζ) for i = 0..nbPublicInputs-1
	lagranges := computeLagrangesAtZeta(&zeta, &zetaPowerNMinusOne, vk)

	// Public input contribution: π = Σᵢ input[i] · L_i(ζ)
	var pi fr.Element
	for i := 0; i < len(publicInputs); i++ {
		var inp fr.Element
		inp.SetBigInt(publicInputs[i])
		var tmp fr.Element
		tmp.Mul(&lagranges[i], &inp)
		pi.Add(&pi, &tmp)
	}

	// α² · L₁(ζ) for grand product check
	// L₁(ζ) = (ζⁿ-1) / (n·(ζ-1))
	var alphaSquareLag0 fr.Element
	{
		var den fr.Element
		den.Sub(&zeta, &one)
		den.Inverse(&den)
		var invDomainSize fr.Element
		invDomainSize.SetUint64(vk.DomainSize)
		invDomainSize.Inverse(&invDomainSize)
		den.Mul(&den, &invDomainSize)
		var lag0 fr.Element
		lag0.Mul(&zetaPowerNMinusOne, &den)
		alphaSquareLag0.Mul(&alpha, &alpha)
		alphaSquareLag0.Mul(&alphaSquareLag0, &lag0)
	}

	// Phase 3: Compute opening of linearised polynomial.
	openingLinearisedPoly := computeOpeningLinearisedPolynomial(
		proof, &alpha, &beta, &gamma, &pi, &alphaSquareLag0,
	)

	// Fold quotient polynomial: -z_h(ζ) * (H₀ + ζⁿ⁺²·H₁ + ζ²⁽ⁿ⁺²⁾·H₂)
	foldedH := foldH(proof, &zeta, &zetaPowerNMinusOne, vk.DomainSize)

	// Compute commitment to linearised polynomial.
	linearisedCom := computeCommitmentLinearisedPolynomial(
		proof, vk, &alpha, &beta, &gamma, &zeta, &alphaSquareLag0, &foldedH,
	)

	// Phase 4: KZG batch verification.
	// Derive γ_kzg challenge.
	gammaKzg := computeGammaKzg(proof, vk, &zeta, &linearisedCom, &openingLinearisedPoly)

	// Fold digests and evaluations.
	foldedDigest, foldedClaimedValues := foldState(
		proof, vk, &linearisedCom, &openingLinearisedPoly, &gammaKzg,
	)

	// Batch verify multi-points.
	return batchVerifyMultiPoints(
		proof, vk, &foldedDigest, &foldedClaimedValues, &zeta, &gammaKzg,
	)
}

// --- Fiat-Shamir challenge derivation ---

// sha256Transcript hashes the given transcript data and returns the raw 32-byte result.
func sha256Transcript(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// bigIntTo32Bytes returns a 32-byte big-endian representation.
func bigIntTo32Bytes(v *big.Int) [32]byte {
	var buf [32]byte
	b := v.Bytes()
	copy(buf[32-len(b):], b)
	return buf
}

// frTo32Bytes converts an fr.Element to 32-byte big-endian.
func frTo32Bytes(e *fr.Element) [32]byte {
	var bi big.Int
	e.BigInt(&bi)
	return bigIntTo32Bytes(&bi)
}

// g1To64Bytes serializes a G1 affine point as two 32-byte big-endian coordinates.
func g1To64Bytes(p *bn254.G1Affine) [64]byte {
	var buf [64]byte
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	xb := bigIntTo32Bytes(&x)
	yb := bigIntTo32Bytes(&y)
	copy(buf[:32], xb[:])
	copy(buf[32:], yb[:])
	return buf
}

// reduceToFr reduces a 32-byte SHA256 hash to a scalar field element.
func reduceToFr(hash [32]byte) fr.Element {
	v := new(big.Int).SetBytes(hash[:])
	v.Mod(v, rOrder)
	var e fr.Element
	e.SetBigInt(v)
	return e
}

// deriveGamma computes γ = SHA256("gamma" ‖ VK_S1..S3 ‖ VK_QL..QK ‖ publicInputs ‖ L,R,O commitments).
//
// The Solidity verifier places "gamma" as a uint256 with ASCII bytes right-aligned:
// FS_GAMMA = 0x67616d6d61 occupying bytes [27..31] of a 32-byte word.
// The SHA256 starts at offset 0x1b (27) of the first word, so the data fed is:
// [0x67,0x61,0x6d,0x6d,0x61] ‖ S1 ‖ S2 ‖ S3 ‖ QL ‖ QR ‖ QM ‖ QO ‖ QK ‖ pubInputs ‖ L,R,O
func deriveGamma(proof *Proof, publicInputs []*big.Int, vk *VerifyingKey) [32]byte {
	// "gamma" = 5 bytes
	tag := []byte("gamma")

	// 8 VK commitments (S1,S2,S3,QL,QR,QM,QO,QK) × 64 bytes = 512
	// + pubInputs × 32 bytes
	// + 3 wire commitments (L,R,O) × 64 bytes = 192
	size := 5 + 8*64 + len(publicInputs)*32 + 3*64
	buf := make([]byte, 0, size)

	buf = append(buf, tag...)

	// S1, S2, S3
	for _, s := range []*bn254.G1Affine{&vk.S1, &vk.S2, &vk.S3} {
		b := g1To64Bytes(s)
		buf = append(buf, b[:]...)
	}
	// QL, QR, QM, QO, QK
	for _, q := range []*bn254.G1Affine{&vk.QL, &vk.QR, &vk.QM, &vk.QO, &vk.QK} {
		b := g1To64Bytes(q)
		buf = append(buf, b[:]...)
	}
	// Public inputs
	for _, inp := range publicInputs {
		b := bigIntTo32Bytes(inp)
		buf = append(buf, b[:]...)
	}
	// L, R, O commitments from proof
	for _, c := range []*bn254.G1Affine{&proof.LCom, &proof.RCom, &proof.OCom} {
		b := g1To64Bytes(c)
		buf = append(buf, b[:]...)
	}

	return sha256Transcript(buf)
}

// deriveBeta computes β = SHA256("beta" ‖ γ_unreduced).
// Solidity: FS_BETA = 0x62657461, start at byte 28 (0x1c), total = 4 + 32 = 36 bytes.
func deriveBeta(gammaUnreduced [32]byte) [32]byte {
	tag := []byte("beta")
	buf := make([]byte, 0, 4+32)
	buf = append(buf, tag...)
	buf = append(buf, gammaUnreduced[:]...)
	return sha256Transcript(buf)
}

// deriveAlpha computes α = SHA256("alpha" ‖ β_unreduced ‖ [Z]).
// Solidity: FS_ALPHA = 0x616C706861, start at byte 27 (0x1b), total = 5 + 32 + 64 = 101 (0x65) bytes.
func deriveAlpha(proof *Proof, betaUnreduced [32]byte) [32]byte {
	tag := []byte("alpha")
	buf := make([]byte, 0, 5+32+64)
	buf = append(buf, tag...)
	buf = append(buf, betaUnreduced[:]...)
	zb := g1To64Bytes(&proof.ZCom)
	buf = append(buf, zb[:]...)
	return sha256Transcript(buf)
}

// deriveZeta computes ζ = SHA256("zeta" ‖ α_unreduced ‖ H₀ ‖ H₁ ‖ H₂).
// Solidity: FS_ZETA = 0x7a657461, start at byte 28 (0x1c), total = 4 + 32 + 3*64 = 228 (0xe4) bytes.
func deriveZeta(proof *Proof, alphaUnreduced [32]byte) [32]byte {
	tag := []byte("zeta")
	buf := make([]byte, 0, 4+32+3*64)
	buf = append(buf, tag...)
	buf = append(buf, alphaUnreduced[:]...)
	for _, h := range []*bn254.G1Affine{&proof.H0Com, &proof.H1Com, &proof.H2Com} {
		b := g1To64Bytes(h)
		buf = append(buf, b[:]...)
	}
	return sha256Transcript(buf)
}

// --- Polynomial evaluation ---

// log2 returns the binary log of n (assumes n is a power of 2).
func log2(n uint64) uint64 {
	var r uint64
	for n > 1 {
		n >>= 1
		r++
	}
	return r
}

// computeLagrangesAtZeta computes L_i(ζ) for i = 0..nbPublicInputs-1.
// L_i(ζ) = (ζⁿ-1)/(n·(ζ - ωⁱ))
func computeLagrangesAtZeta(zeta, zetaPowerNMinusOne *fr.Element, vk *VerifyingKey) []fr.Element {
	n := vk.NbPublicInputs
	if n == 0 {
		return nil
	}

	// Compute (ζⁿ-1)/n
	var invDomainSize fr.Element
	invDomainSize.SetUint64(vk.DomainSize)
	invDomainSize.Inverse(&invDomainSize)
	var zn fr.Element
	zn.Mul(zetaPowerNMinusOne, &invDomainSize)

	// Compute (ζ - ωⁱ) for each i, then batch invert.
	denoms := make([]fr.Element, n)
	var w fr.Element
	w.SetOne()
	for i := uint64(0); i < n; i++ {
		denoms[i].Sub(zeta, &w)
		w.Mul(&w, &vk.Omega)
	}

	// Batch invert using Montgomery trick.
	invs := batchInvertFr(denoms)

	// L_i(ζ) = zn * ωⁱ / (ζ - ωⁱ) = zn * ωⁱ * inv(ζ - ωⁱ)
	result := make([]fr.Element, n)
	w.SetOne()
	for i := uint64(0); i < n; i++ {
		result[i].Mul(&zn, &w)
		result[i].Mul(&result[i], &invs[i])
		w.Mul(&w, &vk.Omega)
	}

	return result
}

// batchInvertFr performs Montgomery batch inversion on a slice of field elements.
func batchInvertFr(elems []fr.Element) []fr.Element {
	n := len(elems)
	if n == 0 {
		return nil
	}

	// Build partial products.
	partials := make([]fr.Element, n)
	partials[0].Set(&elems[0])
	for i := 1; i < n; i++ {
		partials[i].Mul(&partials[i-1], &elems[i])
	}

	// Invert the accumulated product.
	var inv fr.Element
	inv.Inverse(&partials[n-1])

	// Walk backwards to recover individual inverses.
	result := make([]fr.Element, n)
	for i := n - 1; i > 0; i-- {
		result[i].Mul(&inv, &partials[i-1])
		inv.Mul(&inv, &elems[i])
	}
	result[0].Set(&inv)

	return result
}

// --- Linearised polynomial ---

// computeOpeningLinearisedPolynomial computes the expected opening of the linearised polynomial at ζ:
// r(ζ) = -[PI(ζ) - α²·L₁(ζ) + α·Z(ωζ)·(L(ζ)+β·S₁(ζ)+γ)·(R(ζ)+β·S₂(ζ)+γ)·(O(ζ)+γ)]
func computeOpeningLinearisedPolynomial(
	proof *Proof,
	alpha, beta, gamma, pi, alphaSquareLag0 *fr.Element,
) fr.Element {
	// (L(ζ) + β·S₁(ζ) + γ)
	var s1 fr.Element
	s1.Mul(beta, &proof.S1AtZeta)
	s1.Add(&s1, gamma)
	s1.Add(&s1, &proof.LAtZeta)

	// (R(ζ) + β·S₂(ζ) + γ)
	var s2 fr.Element
	s2.Mul(beta, &proof.S2AtZeta)
	s2.Add(&s2, gamma)
	s2.Add(&s2, &proof.RAtZeta)

	// (O(ζ) + γ)
	var o fr.Element
	o.Add(&proof.OAtZeta, gamma)

	// α · Z(ωζ) · (L(ζ)+β·S₁(ζ)+γ) · (R(ζ)+β·S₂(ζ)+γ) · (O(ζ)+γ)
	var result fr.Element
	result.Mul(&s1, &s2)
	result.Mul(&result, &o)
	result.Mul(&result, alpha)
	result.Mul(&result, &proof.ZAtZetaOmega)

	// PI(ζ) - α²·L₁(ζ) + above
	result.Add(&result, pi)
	result.Sub(&result, alphaSquareLag0)

	// Negate: r(ζ) = -(above)
	result.Neg(&result)

	return result
}

// foldH computes -z_h(ζ) · (H₀ + ζⁿ⁺²·H₁ + ζ²⁽ⁿ⁺²⁾·H₂) as a G1 point.
func foldH(proof *Proof, zeta, zetaPowerNMinusOne *fr.Element, domainSize uint64) bn254.G1Affine {
	// ζⁿ⁺² = ζⁿ · ζ²
	var zetaSquared fr.Element
	zetaSquared.Mul(zeta, zeta)

	var one fr.Element
	one.SetOne()
	var zetaPowerN fr.Element
	zetaPowerN.Add(zetaPowerNMinusOne, &one)

	var zetaPowerNPlus2 fr.Element
	zetaPowerNPlus2.Mul(&zetaPowerN, &zetaSquared)

	// result = [ζⁿ⁺²]H₂
	var result bn254.G1Jac
	var zetaPNP2Bi big.Int
	zetaPowerNPlus2.BigInt(&zetaPNP2Bi)
	result.ScalarMultiplication(&bn254.G1Jac{}, &zetaPNP2Bi)

	var h2Jac bn254.G1Jac
	h2Jac.FromAffine(&proof.H2Com)
	result.ScalarMultiplication(&h2Jac, &zetaPNP2Bi)

	// result = result + H₁
	var h1Jac bn254.G1Jac
	h1Jac.FromAffine(&proof.H1Com)
	result.AddAssign(&h1Jac)

	// result = [ζⁿ⁺²] * result
	result.ScalarMultiplication(&result, &zetaPNP2Bi)

	// result = result + H₀
	var h0Jac bn254.G1Jac
	h0Jac.FromAffine(&proof.H0Com)
	result.AddAssign(&h0Jac)

	// result = [ζⁿ-1] * result (multiply by vanishing polynomial evaluation)
	var zpnmoBi big.Int
	zetaPowerNMinusOne.BigInt(&zpnmoBi)
	result.ScalarMultiplication(&result, &zpnmoBi)

	// Negate Y to get -z_h(ζ) * folded_H
	var resultAff bn254.G1Affine
	resultAff.FromJacobian(&result)
	resultAff.Neg(&resultAff)

	return resultAff
}

// computeCommitmentLinearisedPolynomial computes the commitment to the linearised polynomial:
// [r(X)] = L(ζ)[QL] + R(ζ)[QR] + L(ζ)R(ζ)[QM] + O(ζ)[QO] + [QK]
//
//	+ s1·[S3] + s2·[Z] + foldedH
//
// where s1 = α·Z(ωζ)·β·(L(ζ)+β·S₁(ζ)+γ)·(R(ζ)+β·S₂(ζ)+γ)
// and s2 = -α·(L(ζ)+β·ζ+γ)·(R(ζ)+β·u·ζ+γ)·(O(ζ)+β·u²·ζ+γ) + α²·L₁(ζ)
func computeCommitmentLinearisedPolynomial(
	proof *Proof, vk *VerifyingKey,
	alpha, beta, gamma, zeta, alphaSquareLag0 *fr.Element,
	foldedH *bn254.G1Affine,
) bn254.G1Affine {
	// s1 = α · β · Z(ωζ) · (L(ζ)+β·S₁(ζ)+γ) · (R(ζ)+β·S₂(ζ)+γ)
	var s1 fr.Element
	{
		var u fr.Element
		u.Mul(&proof.ZAtZetaOmega, beta)

		var v fr.Element
		v.Mul(beta, &proof.S1AtZeta)
		v.Add(&v, &proof.LAtZeta)
		v.Add(&v, gamma)

		var w fr.Element
		w.Mul(beta, &proof.S2AtZeta)
		w.Add(&w, &proof.RAtZeta)
		w.Add(&w, gamma)

		s1.Mul(&u, &v)
		s1.Mul(&s1, &w)
		s1.Mul(&s1, alpha)
	}

	// s2 = -α·(L(ζ)+β·ζ+γ)·(R(ζ)+β·u·ζ+γ)·(O(ζ)+β·u²·ζ+γ) + α²·L₁(ζ)
	var s2 fr.Element
	{
		var cosetSquare fr.Element
		cosetSquare.Mul(&vk.CosetShift, &vk.CosetShift)

		var betaZeta fr.Element
		betaZeta.Mul(beta, zeta)

		var u fr.Element
		u.Add(&betaZeta, &proof.LAtZeta)
		u.Add(&u, gamma)

		var v fr.Element
		v.Mul(&betaZeta, &vk.CosetShift)
		v.Add(&v, &proof.RAtZeta)
		v.Add(&v, gamma)

		var w fr.Element
		w.Mul(&betaZeta, &cosetSquare)
		w.Add(&w, &proof.OAtZeta)
		w.Add(&w, gamma)

		s2.Mul(&u, &v)
		s2.Mul(&s2, &w)
		s2.Neg(&s2)
		s2.Mul(&s2, alpha)
		s2.Add(&s2, alphaSquareLag0)
	}

	// Now assemble the EC linear combination.
	var result bn254.G1Jac

	// L(ζ)·[QL]
	var scalar big.Int
	proof.LAtZeta.BigInt(&scalar)
	var qlJac bn254.G1Jac
	qlJac.FromAffine(&vk.QL)
	result.ScalarMultiplication(&qlJac, &scalar)

	// + R(ζ)·[QR]
	proof.RAtZeta.BigInt(&scalar)
	var qrJac bn254.G1Jac
	qrJac.FromAffine(&vk.QR)
	qrJac.ScalarMultiplication(&qrJac, &scalar)
	result.AddAssign(&qrJac)

	// + L(ζ)·R(ζ)·[QM]
	var lr fr.Element
	lr.Mul(&proof.LAtZeta, &proof.RAtZeta)
	lr.BigInt(&scalar)
	var qmJac bn254.G1Jac
	qmJac.FromAffine(&vk.QM)
	qmJac.ScalarMultiplication(&qmJac, &scalar)
	result.AddAssign(&qmJac)

	// + O(ζ)·[QO]
	proof.OAtZeta.BigInt(&scalar)
	var qoJac bn254.G1Jac
	qoJac.FromAffine(&vk.QO)
	qoJac.ScalarMultiplication(&qoJac, &scalar)
	result.AddAssign(&qoJac)

	// + [QK]
	var qkJac bn254.G1Jac
	qkJac.FromAffine(&vk.QK)
	result.AddAssign(&qkJac)

	// + s1·[S3]
	s1.BigInt(&scalar)
	var s3Jac bn254.G1Jac
	s3Jac.FromAffine(&vk.S3)
	s3Jac.ScalarMultiplication(&s3Jac, &scalar)
	result.AddAssign(&s3Jac)

	// + s2·[Z]
	s2.BigInt(&scalar)
	var zJac bn254.G1Jac
	zJac.FromAffine(&proof.ZCom)
	zJac.ScalarMultiplication(&zJac, &scalar)
	result.AddAssign(&zJac)

	// + foldedH
	var fhJac bn254.G1Jac
	fhJac.FromAffine(foldedH)
	result.AddAssign(&fhJac)

	var resultAff bn254.G1Affine
	resultAff.FromJacobian(&result)
	return resultAff
}

// --- KZG batch verification ---

// computeGammaKzg derives the γ_kzg challenge for folding opening proofs.
// Transcript: "gamma" ‖ ζ ‖ [linearised] ‖ [L],[R],[O] ‖ [S1],[S2] ‖
//
//	linearised(ζ) ‖ L(ζ) ‖ R(ζ) ‖ O(ζ) ‖ S1(ζ) ‖ S2(ζ) ‖ Z(ζω)
func computeGammaKzg(
	proof *Proof, vk *VerifyingKey,
	zeta *fr.Element,
	linearisedCom *bn254.G1Affine,
	openingLinearisedPoly *fr.Element,
) fr.Element {
	tag := []byte("gamma")
	// 5 + 32(ζ) + 64(linearised) + 3*64(L,R,O) + 2*64(S1,S2) + 7*32(evals) = 5+32+64+192+128+224 = 645
	buf := make([]byte, 0, 645)
	buf = append(buf, tag...)

	b := frTo32Bytes(zeta)
	buf = append(buf, b[:]...)

	lb := g1To64Bytes(linearisedCom)
	buf = append(buf, lb[:]...)

	// L, R, O commitments
	for _, c := range []*bn254.G1Affine{&proof.LCom, &proof.RCom, &proof.OCom} {
		cb := g1To64Bytes(c)
		buf = append(buf, cb[:]...)
	}

	// S1, S2 from VK
	for _, s := range []*bn254.G1Affine{&vk.S1, &vk.S2} {
		sb := g1To64Bytes(s)
		buf = append(buf, sb[:]...)
	}

	// Evaluations: linearised(ζ), L(ζ), R(ζ), O(ζ), S1(ζ), S2(ζ), Z(ζω)
	for _, e := range []*fr.Element{
		openingLinearisedPoly,
		&proof.LAtZeta, &proof.RAtZeta, &proof.OAtZeta,
		&proof.S1AtZeta, &proof.S2AtZeta,
		&proof.ZAtZetaOmega,
	} {
		eb := frTo32Bytes(e)
		buf = append(buf, eb[:]...)
	}

	hash := sha256Transcript(buf)
	return reduceToFr(hash)
}

// foldState folds the opening proofs at ζ into a single digest and claimed value.
// Returns (folded_digest, folded_claimed_value).
//
// folded_digest = [linearised] + γ_kzg·[L] + γ_kzg²·[R] + γ_kzg³·[O] + γ_kzg⁴·[S1] + γ_kzg⁵·[S2]
// folded_value = linearised(ζ) + γ_kzg·L(ζ) + γ_kzg²·R(ζ) + γ_kzg³·O(ζ) + γ_kzg⁴·S1(ζ) + γ_kzg⁵·S2(ζ)
func foldState(
	proof *Proof, vk *VerifyingKey,
	linearisedCom *bn254.G1Affine,
	openingLinearisedPoly, gammaKzg *fr.Element,
) (bn254.G1Affine, fr.Element) {
	var foldedDigest bn254.G1Jac
	foldedDigest.FromAffine(linearisedCom)

	var foldedClaimed fr.Element
	foldedClaimed.Set(openingLinearisedPoly)

	accGamma := *gammaKzg

	// Points to fold: L, R, O from proof; S1, S2 from VK
	digestPoints := []*bn254.G1Affine{
		&proof.LCom, &proof.RCom, &proof.OCom,
		&vk.S1, &vk.S2,
	}
	evalValues := []*fr.Element{
		&proof.LAtZeta, &proof.RAtZeta, &proof.OAtZeta,
		&proof.S1AtZeta, &proof.S2AtZeta,
	}

	for i := 0; i < len(digestPoints); i++ {
		var scalar big.Int
		accGamma.BigInt(&scalar)

		var ptJac bn254.G1Jac
		ptJac.FromAffine(digestPoints[i])
		ptJac.ScalarMultiplication(&ptJac, &scalar)
		foldedDigest.AddAssign(&ptJac)

		var tmp fr.Element
		tmp.Mul(&accGamma, evalValues[i])
		foldedClaimed.Add(&foldedClaimed, &tmp)

		if i < len(digestPoints)-1 {
			accGamma.Mul(&accGamma, gammaKzg)
		}
	}

	var foldedDigestAff bn254.G1Affine
	foldedDigestAff.FromJacobian(&foldedDigest)

	return foldedDigestAff, foldedClaimed
}

// batchVerifyMultiPoints performs the final KZG pairing check.
//
// Follows the Solidity verifier's batch_verify_multi_points exactly:
// 1. Derive random from SHA256(folded_digest ‖ W_ζ ‖ [Z] ‖ W_ζω ‖ ζ ‖ γ_kzg)
// 2. Fold quotient openings: folded_quotients = W_ζ + random·W_ζω
// 3. Fold digests: folded_digest += random·[Z]
// 4. Fold claimed values: folded_claimed += random·Z(ζω)
// 5. folded_digest -= [folded_claimed]·G1
// 6. folded_digest += ζ·W_ζ + random·ζω·W_ζω
// 7. Final pairing: e(folded_digest, G2_SRS_0) · e(-folded_quotients, G2_SRS_1) == 1
func batchVerifyMultiPoints(
	proof *Proof, vk *VerifyingKey,
	foldedDigest *bn254.G1Affine, foldedClaimedValues *fr.Element,
	zeta, gammaKzg *fr.Element,
) (bool, error) {
	// Derive random.
	buf := make([]byte, 0, 2*64+2*64+2*32)
	fb := g1To64Bytes(foldedDigest)
	buf = append(buf, fb[:]...)
	wb := g1To64Bytes(&proof.BatchOpenZeta)
	buf = append(buf, wb[:]...)
	zb := g1To64Bytes(&proof.ZCom)
	buf = append(buf, zb[:]...)
	wob := g1To64Bytes(&proof.BatchOpenZetaOmega)
	buf = append(buf, wob[:]...)
	zetaB := frTo32Bytes(zeta)
	buf = append(buf, zetaB[:]...)
	gkb := frTo32Bytes(gammaKzg)
	buf = append(buf, gkb[:]...)

	randomHash := sha256Transcript(buf)
	random := reduceToFr(randomHash)

	// Fold quotient openings: folded_quotients = W_ζ + random·W_ζω
	var foldedQuotients bn254.G1Jac
	var randomBi big.Int
	random.BigInt(&randomBi)
	var woJac bn254.G1Jac
	woJac.FromAffine(&proof.BatchOpenZetaOmega)
	foldedQuotients.ScalarMultiplication(&woJac, &randomBi)
	var wJac bn254.G1Jac
	wJac.FromAffine(&proof.BatchOpenZeta)
	foldedQuotients.AddAssign(&wJac)

	// Fold digests: foldedDigest += random·[Z]
	var foldedDigestJac bn254.G1Jac
	foldedDigestJac.FromAffine(foldedDigest)
	var zJac bn254.G1Jac
	zJac.FromAffine(&proof.ZCom)
	zJac.ScalarMultiplication(&zJac, &randomBi)
	foldedDigestJac.AddAssign(&zJac)

	// Fold claimed values: foldedClaimed += random·Z(ζω)
	var foldedClaimed fr.Element
	foldedClaimed.Mul(&random, &proof.ZAtZetaOmega)
	foldedClaimed.Add(&foldedClaimed, foldedClaimedValues)

	// foldedDigest -= [foldedClaimed]·G1
	var claimedBi big.Int
	foldedClaimed.BigInt(&claimedBi)
	var g1Gen bn254.G1Affine
	g1Gen.X.SetOne()
	g1Gen.Y.SetUint64(2)
	var claimedPt bn254.G1Jac
	claimedPt.FromAffine(&g1Gen)
	claimedPt.ScalarMultiplication(&claimedPt, &claimedBi)
	claimedPt.Neg(&claimedPt)
	foldedDigestJac.AddAssign(&claimedPt)

	// foldedDigest += ζ·W_ζ + random·ζω·W_ζω
	var zetaBi big.Int
	zeta.BigInt(&zetaBi)
	var wZetaJac bn254.G1Jac
	wZetaJac.FromAffine(&proof.BatchOpenZeta)
	wZetaJac.ScalarMultiplication(&wZetaJac, &zetaBi)
	foldedDigestJac.AddAssign(&wZetaJac)

	var zetaOmega fr.Element
	zetaOmega.Mul(zeta, &vk.Omega)
	var randomZetaOmega fr.Element
	randomZetaOmega.Mul(&random, &zetaOmega)
	var rzoBI big.Int
	randomZetaOmega.BigInt(&rzoBI)
	var wZetaOmegaJac bn254.G1Jac
	wZetaOmegaJac.FromAffine(&proof.BatchOpenZetaOmega)
	wZetaOmegaJac.ScalarMultiplication(&wZetaOmegaJac, &rzoBI)
	foldedDigestJac.AddAssign(&wZetaOmegaJac)

	// Final pairing: e(foldedDigest, G2_SRS_0) · e(-foldedQuotients, G2_SRS_1) == 1
	var foldedDigestAff bn254.G1Affine
	foldedDigestAff.FromJacobian(&foldedDigestJac)

	var foldedQuotientsAff bn254.G1Affine
	foldedQuotientsAff.FromJacobian(&foldedQuotients)
	foldedQuotientsAff.Neg(&foldedQuotientsAff)

	P := []bn254.G1Affine{foldedDigestAff, foldedQuotientsAff}
	Q := []bn254.G2Affine{vk.G2Srs0, vk.G2Srs1}

	ok, err := bn254.PairingCheck(P, Q)
	if err != nil {
		return false, fmt.Errorf("pairing check: %w", err)
	}

	return ok, nil
}
