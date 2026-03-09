// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package groth16verifier

import (
	_ "embed"
	"errors"
	"fmt"
	"math/big"

	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contract"
)

const (
	// VerifyBaseGas covers the fixed cost of the 4-pairing check.
	// EVM bn256Pairing charges 45,000 + 34,000*4 = 181,000 for 4 pairings.
	// Native Go is faster; we set a ~15% discount.
	VerifyBaseGas uint64 = 152_000

	// VerifyPerInputGas covers one EC scalar multiplication + one EC addition
	// per public input in the MSM computation.
	// EVM ECMUL = 6,000, ECADD = 150; native Go is cheaper.
	VerifyPerInputGas uint64 = 8_000

	// DecompressGas covers decompression overhead (3 field exponentiations
	// for G1 + G2 square roots and inverse, plus validation).
	DecompressGas uint64 = 12_000
)

var (
	// Groth16VerifierPrecompile is the singleton precompiled contract instance.
	Groth16VerifierPrecompile contract.StatefulPrecompiledContract = createGroth16VerifierPrecompile()

	ErrInvalidInput       = errors.New("invalid input data")
	ErrInvalidProof       = errors.New("invalid groth16 proof")
	ErrICLengthMismatch   = errors.New("IC length must equal publicInputs length + 1")
	ErrInputNotInField    = errors.New("public input not in scalar field")
	ErrPointNotOnCurve    = errors.New("point not on curve")
	ErrPointNotInSubgroup = errors.New("point not in correct subgroup")

	//go:embed IGroth16Verifier.abi
	Groth16VerifierRawABI string

	Groth16VerifierABI = contract.ParseABI(Groth16VerifierRawABI)
)

// verifyProof is the precompile entry point. It unpacks ABI-encoded input,
// computes gas, and delegates to the Verify function.
func verifyProof(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) (ret []byte, remainingGas uint64, err error) {
	// Unpack ABI-encoded arguments (selector already stripped by framework).
	args, err := Groth16VerifierABI.Methods["verifyProof"].Inputs.Unpack(input)
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if len(args) != 7 {
		return nil, suppliedGas, fmt.Errorf("%w: expected 7 arguments, got %d", ErrInvalidInput, len(args))
	}

	// Extract and convert each argument.
	proof, err := extractProof(args[0])
	if err != nil {
		return nil, suppliedGas, err
	}
	publicInputs, err := extractPublicInputs(args[1])
	if err != nil {
		return nil, suppliedGas, err
	}
	vkAlpha, err := extractG1(args[2])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: vkAlpha: %w", ErrInvalidInput, err)
	}
	vkBetaNeg, err := extractG2(args[3])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: vkBetaNeg: %w", ErrInvalidInput, err)
	}
	vkGammaNeg, err := extractG2(args[4])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: vkGammaNeg: %w", ErrInvalidInput, err)
	}
	vkDeltaNeg, err := extractG2(args[5])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: vkDeltaNeg: %w", ErrInvalidInput, err)
	}
	vkIC, err := extractICPoints(args[6])
	if err != nil {
		return nil, suppliedGas, err
	}

	// Calculate and deduct gas.
	requiredGas := VerifyBaseGas + uint64(len(publicInputs))*VerifyPerInputGas
	remainingGas, err = contract.DeductGas(suppliedGas, requiredGas)
	if err != nil {
		return nil, 0, err
	}

	// Run verification.
	valid, err := Verify(proof, publicInputs, vkAlpha, vkBetaNeg, vkGammaNeg, vkDeltaNeg, vkIC)
	if err != nil {
		// Verification errors (invalid points, etc.) return false, not an error.
		// Only return an error for truly unexpected failures.
		valid = false
	}

	// Pack the boolean result.
	result, err := Groth16VerifierABI.Methods["verifyProof"].Outputs.Pack(valid)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}
	return result, remainingGas, nil
}

// verifyCompressedProof decompresses a 4-element compressed proof, then verifies.
func verifyCompressedProof(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) (ret []byte, remainingGas uint64, err error) {
	args, err := Groth16VerifierABI.Methods["verifyCompressedProof"].Inputs.Unpack(input)
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if len(args) != 7 {
		return nil, suppliedGas, fmt.Errorf("%w: expected 7 arguments, got %d", ErrInvalidInput, len(args))
	}

	compressedProof, err := extractCompressedProof(args[0])
	if err != nil {
		return nil, suppliedGas, err
	}
	publicInputs, err := extractPublicInputs(args[1])
	if err != nil {
		return nil, suppliedGas, err
	}
	vkAlpha, err := extractG1(args[2])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: vkAlpha: %w", ErrInvalidInput, err)
	}
	vkBetaNeg, err := extractG2(args[3])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: vkBetaNeg: %w", ErrInvalidInput, err)
	}
	vkGammaNeg, err := extractG2(args[4])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: vkGammaNeg: %w", ErrInvalidInput, err)
	}
	vkDeltaNeg, err := extractG2(args[5])
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: vkDeltaNeg: %w", ErrInvalidInput, err)
	}
	vkIC, err := extractICPoints(args[6])
	if err != nil {
		return nil, suppliedGas, err
	}

	// Gas = decompression + base pairing + per-input MSM.
	requiredGas := DecompressGas + VerifyBaseGas + uint64(len(publicInputs))*VerifyPerInputGas
	remainingGas, err = contract.DeductGas(suppliedGas, requiredGas)
	if err != nil {
		return nil, 0, err
	}

	// Decompress proof.
	proof, err := DecompressProof(compressedProof)
	if err != nil {
		result, packErr := Groth16VerifierABI.Methods["verifyCompressedProof"].Outputs.Pack(false)
		if packErr != nil {
			return nil, remainingGas, fmt.Errorf("failed to pack output: %w", packErr)
		}
		return result, remainingGas, nil
	}

	// Run verification.
	valid, err := Verify(proof, publicInputs, vkAlpha, vkBetaNeg, vkGammaNeg, vkDeltaNeg, vkIC)
	if err != nil {
		valid = false
	}

	result, err := Groth16VerifierABI.Methods["verifyCompressedProof"].Outputs.Pack(valid)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}
	return result, remainingGas, nil
}

// createGroth16VerifierPrecompile constructs the StatefulPrecompiledContract.
func createGroth16VerifierPrecompile() contract.StatefulPrecompiledContract {
	verifyMethod, ok := Groth16VerifierABI.Methods["verifyProof"]
	if !ok {
		panic("verifyProof method not found in ABI")
	}
	compressedMethod, ok := Groth16VerifierABI.Methods["verifyCompressedProof"]
	if !ok {
		panic("verifyCompressedProof method not found in ABI")
	}
	functions := []*contract.StatefulPrecompileFunction{
		contract.NewStatefulPrecompileFunction(verifyMethod.ID, verifyProof),
		contract.NewStatefulPrecompileFunction(compressedMethod.ID, verifyCompressedProof),
	}
	statefulContract, err := contract.NewStatefulPrecompileContract(nil, functions)
	if err != nil {
		panic(err)
	}
	return statefulContract
}

// --- ABI argument extraction helpers ---

func extractCompressedProof(arg interface{}) ([4]*big.Int, error) {
	arr, ok := arg.([4]*big.Int)
	if !ok {
		return [4]*big.Int{}, fmt.Errorf("%w: compressedProof must be uint256[4]", ErrInvalidInput)
	}
	for i, v := range arr {
		if v == nil {
			return [4]*big.Int{}, fmt.Errorf("%w: compressedProof[%d] is nil", ErrInvalidInput, i)
		}
	}
	return arr, nil
}

func extractProof(arg interface{}) ([8]*big.Int, error) {
	arr, ok := arg.([8]*big.Int)
	if !ok {
		return [8]*big.Int{}, fmt.Errorf("%w: proof must be uint256[8]", ErrInvalidInput)
	}
	for i, v := range arr {
		if v == nil {
			return [8]*big.Int{}, fmt.Errorf("%w: proof[%d] is nil", ErrInvalidInput, i)
		}
	}
	return arr, nil
}

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

func extractICPoints(arg interface{}) ([][2]*big.Int, error) {
	arr, ok := arg.([][2]*big.Int)
	if !ok {
		return nil, fmt.Errorf("%w: vkIC must be uint256[2][]", ErrInvalidInput)
	}
	for i, ic := range arr {
		if ic[0] == nil || ic[1] == nil {
			return nil, fmt.Errorf("%w: vkIC[%d] contains nil element", ErrInvalidInput, i)
		}
	}
	return arr, nil
}
