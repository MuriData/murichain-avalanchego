// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package plonkverifier

import (
	_ "embed"
	"errors"
	"fmt"
	"math/big"

	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contract"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

const (
	// PlonkVerifyBaseGas covers the fixed cost of Fiat-Shamir, linearisation,
	// and 2-pairing KZG check.
	PlonkVerifyBaseGas uint64 = 180_000

	// PlonkVerifyPerInputGas covers Lagrange evaluation per public input.
	PlonkVerifyPerInputGas uint64 = 1_500
)

var (
	PlonkVerifierPrecompile contract.StatefulPrecompiledContract = createPlonkVerifierPrecompile()

	ErrInvalidInput    = errors.New("invalid input data")
	ErrInvalidProof    = errors.New("invalid plonk proof")
	ErrInputNotInField = errors.New("public input not in scalar field")

	//go:embed IPlonkVerifier.abi
	PlonkVerifierRawABI string

	PlonkVerifierABI = contract.ParseABI(PlonkVerifierRawABI)
)

// verifyProofHandler is the precompile entry point.
func verifyProofHandler(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) (ret []byte, remainingGas uint64, err error) {
	args, err := PlonkVerifierABI.Methods["verifyProof"].Inputs.Unpack(input)
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if len(args) != 16 {
		return nil, suppliedGas, fmt.Errorf("%w: expected 16 arguments, got %d", ErrInvalidInput, len(args))
	}

	// Extract proof bytes.
	proofBytes, ok := args[0].([]byte)
	if !ok {
		return nil, suppliedGas, fmt.Errorf("%w: proof must be bytes", ErrInvalidInput)
	}

	// Extract public inputs.
	publicInputs, err := extractPublicInputs(args[1])
	if err != nil {
		return nil, suppliedGas, err
	}

	// Extract VK fields.
	vk, err := extractVK(args[2:])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	// Validate public inputs count matches VK.
	if uint64(len(publicInputs)) != vk.NbPublicInputs {
		return nil, suppliedGas, fmt.Errorf("%w: expected %d public inputs, got %d",
			ErrInvalidInput, vk.NbPublicInputs, len(publicInputs))
	}

	// Calculate and deduct gas.
	requiredGas := PlonkVerifyBaseGas + uint64(len(publicInputs))*PlonkVerifyPerInputGas
	remainingGas, err = contract.DeductGas(suppliedGas, requiredGas)
	if err != nil {
		return nil, 0, err
	}

	// Parse proof from Solidity bytes format.
	proof, err := ParseProofSolidity(proofBytes)
	if err != nil {
		valid := false
		result, packErr := PlonkVerifierABI.Methods["verifyProof"].Outputs.Pack(valid)
		if packErr != nil {
			return nil, remainingGas, fmt.Errorf("failed to pack output: %w", packErr)
		}
		return result, remainingGas, nil
	}

	// Run verification.
	valid, err := Verify(proof, publicInputs, vk)
	if err != nil {
		valid = false
	}

	result, err := PlonkVerifierABI.Methods["verifyProof"].Outputs.Pack(valid)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}
	return result, remainingGas, nil
}

// createPlonkVerifierPrecompile constructs the StatefulPrecompiledContract.
func createPlonkVerifierPrecompile() contract.StatefulPrecompiledContract {
	method, ok := PlonkVerifierABI.Methods["verifyProof"]
	if !ok {
		panic("verifyProof method not found in ABI")
	}
	functions := []*contract.StatefulPrecompileFunction{
		contract.NewStatefulPrecompileFunction(method.ID, verifyProofHandler),
	}
	statefulContract, err := contract.NewStatefulPrecompileContract(nil, functions)
	if err != nil {
		panic(err)
	}
	return statefulContract
}

// --- ABI argument extraction helpers ---

func extractPublicInputs(arg interface{}) ([]*big.Int, error) {
	arr, ok := arg.([]*big.Int)
	if !ok {
		return nil, fmt.Errorf("%w: publicInputs must be uint256[]", ErrInvalidInput)
	}
	for i, v := range arr {
		if v == nil {
			return nil, fmt.Errorf("%w: publicInputs[%d] is nil", ErrInvalidInput, i)
		}
	}
	return arr, nil
}

func extractG1(arg interface{}) ([2]*big.Int, error) {
	arr, ok := arg.([2]*big.Int)
	if !ok {
		return [2]*big.Int{}, fmt.Errorf("expected [2]*big.Int, got %T", arg)
	}
	if arr[0] == nil || arr[1] == nil {
		return [2]*big.Int{}, fmt.Errorf("G1 point contains nil element")
	}
	return arr, nil
}

func extractG2(arg interface{}) ([4]*big.Int, error) {
	arr, ok := arg.([4]*big.Int)
	if !ok {
		return [4]*big.Int{}, fmt.Errorf("expected [4]*big.Int, got %T", arg)
	}
	for i, v := range arr {
		if v == nil {
			return [4]*big.Int{}, fmt.Errorf("G2 point element [%d] is nil", i)
		}
	}
	return arr, nil
}

// extractVK extracts the verification key from the remaining ABI-decoded arguments
// (args[2:] from the full argument list, i.e. indices 2..15 = 14 arguments).
func extractVK(args []interface{}) (*VerifyingKey, error) {
	if len(args) != 14 {
		return nil, fmt.Errorf("expected 14 VK arguments, got %d", len(args))
	}

	var vk VerifyingKey

	// args[0] = vkDomainSize (uint64)
	domainSize, ok := args[0].(uint64)
	if !ok {
		return nil, fmt.Errorf("vkDomainSize: expected uint64, got %T", args[0])
	}
	vk.DomainSize = domainSize

	// args[1] = vkNbPublicInputs (uint64)
	nbPub, ok := args[1].(uint64)
	if !ok {
		return nil, fmt.Errorf("vkNbPublicInputs: expected uint64, got %T", args[1])
	}
	vk.NbPublicInputs = nbPub

	// args[2] = vkOmega (uint256)
	omega, ok := args[2].(*big.Int)
	if !ok || omega == nil {
		return nil, fmt.Errorf("vkOmega: expected *big.Int")
	}
	if omega.Cmp(rOrder) >= 0 {
		return nil, fmt.Errorf("vkOmega >= R")
	}
	vk.Omega.SetBigInt(omega)

	// args[3..10] = QL, QR, QM, QO, QK, S1, S2, S3 (G1 points)
	type g1Target struct {
		name string
		idx  int
	}
	g1Targets := []g1Target{
		{"vkQL", 3}, {"vkQR", 4}, {"vkQM", 5}, {"vkQO", 6}, {"vkQK", 7},
		{"vkS1", 8}, {"vkS2", 9}, {"vkS3", 10},
	}

	g1Points := make([][2]*big.Int, len(g1Targets))
	for i, t := range g1Targets {
		pt, err := extractG1(args[t.idx])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.name, err)
		}
		g1Points[i] = pt
	}

	// Deserialize G1 points into VK.
	g1Affines := []*bn254.G1Affine{
		&vk.QL, &vk.QR, &vk.QM, &vk.QO, &vk.QK,
		&vk.S1, &vk.S2, &vk.S3,
	}
	for i, pt := range g1Points {
		p, err := deserializeG1(pt[0], pt[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g1Targets[i].name, err)
		}
		*g1Affines[i] = p
	}

	// args[11] = vkG2Srs0
	g2srs0, err := extractG2(args[11])
	if err != nil {
		return nil, fmt.Errorf("vkG2Srs0: %w", err)
	}
	vk.G2Srs0, err = deserializeG2(g2srs0[0], g2srs0[1], g2srs0[2], g2srs0[3])
	if err != nil {
		return nil, fmt.Errorf("vkG2Srs0: %w", err)
	}

	// args[12] = vkG2Srs1
	g2srs1, err := extractG2(args[12])
	if err != nil {
		return nil, fmt.Errorf("vkG2Srs1: %w", err)
	}
	vk.G2Srs1, err = deserializeG2(g2srs1[0], g2srs1[1], g2srs1[2], g2srs1[3])
	if err != nil {
		return nil, fmt.Errorf("vkG2Srs1: %w", err)
	}

	// args[13] = vkCosetShift (uint256)
	cosetShift, ok := args[13].(*big.Int)
	if !ok || cosetShift == nil {
		return nil, fmt.Errorf("vkCosetShift: expected *big.Int")
	}
	if cosetShift.Cmp(rOrder) >= 0 {
		return nil, fmt.Errorf("vkCosetShift >= R")
	}
	vk.CosetShift.SetBigInt(cosetShift)

	return &vk, nil
}
