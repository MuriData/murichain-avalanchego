// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon2hasher

import (
	_ "embed"
	"fmt"
	"math/big"

	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contract"
)

const (
	// HashBaseGas covers ABI decode + single permutation + output pack.
	HashBaseGas uint64 = 200

	// HashPerInputGas covers one permutation per 2 inputs.
	HashPerInputGas uint64 = 150
)

var (
	// Poseidon2HasherPrecompile is the singleton precompiled contract instance.
	Poseidon2HasherPrecompile contract.StatefulPrecompiledContract = createPoseidon2HasherPrecompile()

	//go:embed IPoseidon2Hasher.abi
	Poseidon2HasherRawABI string

	Poseidon2HasherABI = contract.ParseABI(Poseidon2HasherRawABI)
)

// hash is the precompile entry point for the hash(uint8,uint256[]) function.
func hash(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) (ret []byte, remainingGas uint64, err error) {
	// Unpack ABI-encoded arguments (selector already stripped by framework).
	args, err := Poseidon2HasherABI.Methods["hash"].Inputs.Unpack(input)
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if len(args) != 2 {
		return nil, suppliedGas, fmt.Errorf("%w: expected 2 arguments, got %d", ErrInvalidInput, len(args))
	}

	// Extract domain tag (uint8).
	domainTag, ok := args[0].(uint8)
	if !ok {
		return nil, suppliedGas, fmt.Errorf("%w: domainTag must be uint8", ErrInvalidInput)
	}

	// Extract inputs (uint256[]).
	inputs, err := extractInputs(args[1])
	if err != nil {
		return nil, suppliedGas, err
	}

	// Validate input count.
	if len(inputs) > MaxInputs {
		return nil, suppliedGas, fmt.Errorf("%w: %d inputs exceeds maximum %d", ErrTooManyInputs, len(inputs), MaxInputs)
	}

	// Validate all inputs are in the scalar field.
	for i, v := range inputs {
		if v.Sign() < 0 || v.Cmp(rOrder) >= 0 {
			return nil, suppliedGas, fmt.Errorf("%w: inputs[%d] >= field order", ErrInputNotInField, i)
		}
	}

	// Calculate and deduct gas.
	requiredGas := HashBaseGas + uint64(len(inputs))*HashPerInputGas
	remainingGas, err = contract.DeductGas(suppliedGas, requiredGas)
	if err != nil {
		return nil, 0, err
	}

	// Compute hash.
	digest, err := SpongeHashBigInt(int(domainTag), inputs)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("hash computation failed: %w", err)
	}

	// Pack the uint256 result.
	result, err := Poseidon2HasherABI.Methods["hash"].Outputs.Pack(digest)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}
	return result, remainingGas, nil
}

// createPoseidon2HasherPrecompile constructs the StatefulPrecompiledContract.
func createPoseidon2HasherPrecompile() contract.StatefulPrecompiledContract {
	hashMethod, ok := Poseidon2HasherABI.Methods["hash"]
	if !ok {
		panic("hash method not found in ABI")
	}
	functions := []*contract.StatefulPrecompileFunction{
		contract.NewStatefulPrecompileFunction(hashMethod.ID, hash),
	}
	statefulContract, err := contract.NewStatefulPrecompileContract(nil, functions)
	if err != nil {
		panic(err)
	}
	return statefulContract
}

// extractInputs safely converts the ABI-unpacked argument to []*big.Int.
func extractInputs(arg interface{}) ([]*big.Int, error) {
	arr, ok := arg.([]*big.Int)
	if !ok {
		return nil, fmt.Errorf("%w: inputs must be uint256[]", ErrInvalidInput)
	}
	for i, v := range arr {
		if v == nil {
			return nil, fmt.Errorf("%w: inputs[%d] is nil", ErrInvalidInput, i)
		}
	}
	return arr, nil
}

var ErrInvalidInput = fmt.Errorf("invalid input data")
