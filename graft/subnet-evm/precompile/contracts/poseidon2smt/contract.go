// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon2smt

import (
	_ "embed"
	"fmt"
	"math/big"

	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contract"
)

const (
	// computeRoot gas: base + numLeaves*perLeaf + depth*perLevel.
	ComputeRootBaseGas     uint64 = 500
	ComputeRootPerLeafGas  uint64 = 150
	ComputeRootPerLevelGas uint64 = 100

	// verifyProof gas: base + depth*perLevel.
	VerifyProofBaseGas     uint64 = 200
	VerifyProofPerLevelGas uint64 = 150
)

var (
	// Poseidon2SMTPrecompile is the singleton precompiled contract instance.
	Poseidon2SMTPrecompile contract.StatefulPrecompiledContract = createPoseidon2SMTPrecompile()

	ErrInvalidInput = fmt.Errorf("invalid input data")

	//go:embed IPoseidon2SMT.abi
	Poseidon2SMTRawABI string

	Poseidon2SMTABI = contract.ParseABI(Poseidon2SMTRawABI)
)

// computeRootHandler is the precompile entry point for computeRoot(uint256[],uint8).
func computeRootHandler(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) (ret []byte, remainingGas uint64, err error) {
	args, err := Poseidon2SMTABI.Methods["computeRoot"].Inputs.Unpack(input)
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if len(args) != 2 {
		return nil, suppliedGas, fmt.Errorf("%w: expected 2 arguments, got %d", ErrInvalidInput, len(args))
	}

	leafHashes, err := extractUint256Slice(args[0])
	if err != nil {
		return nil, suppliedGas, err
	}
	depth, ok := args[1].(uint8)
	if !ok {
		return nil, suppliedGas, fmt.Errorf("%w: depth must be uint8", ErrInvalidInput)
	}

	// Validate inputs.
	if int(depth) > MaxDepth {
		return nil, suppliedGas, fmt.Errorf("%w: depth %d exceeds maximum %d", ErrInvalidDepth, depth, MaxDepth)
	}
	if len(leafHashes) > MaxLeaves {
		return nil, suppliedGas, fmt.Errorf("%w: %d leaves exceeds maximum %d", ErrTooManyLeaves, len(leafHashes), MaxLeaves)
	}
	if depth > 0 && len(leafHashes) > (1<<depth) {
		return nil, suppliedGas, fmt.Errorf("%w: %d leaves exceeds 2^%d", ErrTooManyLeaves, len(leafHashes), depth)
	}
	for i, v := range leafHashes {
		if v.Sign() < 0 || v.Cmp(rOrder) >= 0 {
			return nil, suppliedGas, fmt.Errorf("input not in scalar field: leafHashes[%d]", i)
		}
	}

	// Calculate and deduct gas.
	requiredGas := ComputeRootBaseGas +
		uint64(len(leafHashes))*ComputeRootPerLeafGas +
		uint64(depth)*ComputeRootPerLevelGas
	remainingGas, err = contract.DeductGas(suppliedGas, requiredGas)
	if err != nil {
		return nil, 0, err
	}

	// Compute root.
	root, err := ComputeRootBigInt(leafHashes, int(depth))
	if err != nil {
		return nil, remainingGas, fmt.Errorf("compute root failed: %w", err)
	}

	result, err := Poseidon2SMTABI.Methods["computeRoot"].Outputs.Pack(root)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}
	return result, remainingGas, nil
}

// verifyProofHandler is the precompile entry point for verifyProof(uint256,uint256,uint256[],uint256,uint8).
func verifyProofHandler(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) (ret []byte, remainingGas uint64, err error) {
	args, err := Poseidon2SMTABI.Methods["verifyProof"].Inputs.Unpack(input)
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if len(args) != 5 {
		return nil, suppliedGas, fmt.Errorf("%w: expected 5 arguments, got %d", ErrInvalidInput, len(args))
	}

	leafHash, ok := args[0].(*big.Int)
	if !ok || leafHash == nil {
		return nil, suppliedGas, fmt.Errorf("%w: leafHash must be uint256", ErrInvalidInput)
	}
	root, ok := args[1].(*big.Int)
	if !ok || root == nil {
		return nil, suppliedGas, fmt.Errorf("%w: root must be uint256", ErrInvalidInput)
	}
	siblings, err := extractUint256Slice(args[2])
	if err != nil {
		return nil, suppliedGas, err
	}
	leafIndex, ok := args[3].(*big.Int)
	if !ok || leafIndex == nil {
		return nil, suppliedGas, fmt.Errorf("%w: leafIndex must be uint256", ErrInvalidInput)
	}
	depth, ok := args[4].(uint8)
	if !ok {
		return nil, suppliedGas, fmt.Errorf("%w: depth must be uint8", ErrInvalidInput)
	}

	// Validate inputs.
	if int(depth) > MaxDepth {
		return nil, suppliedGas, fmt.Errorf("%w: depth %d exceeds maximum %d", ErrInvalidDepth, depth, MaxDepth)
	}
	if len(siblings) != int(depth) {
		return nil, suppliedGas, fmt.Errorf("%w: got %d siblings for depth %d", ErrSiblingCount, len(siblings), depth)
	}
	if leafHash.Sign() < 0 || leafHash.Cmp(rOrder) >= 0 {
		return nil, suppliedGas, fmt.Errorf("leafHash not in scalar field")
	}
	if root.Sign() < 0 || root.Cmp(rOrder) >= 0 {
		return nil, suppliedGas, fmt.Errorf("root not in scalar field")
	}
	for i, s := range siblings {
		if s.Sign() < 0 || s.Cmp(rOrder) >= 0 {
			return nil, suppliedGas, fmt.Errorf("sibling[%d] not in scalar field", i)
		}
	}
	if !leafIndex.IsUint64() {
		return nil, suppliedGas, fmt.Errorf("%w: leafIndex too large", ErrLeafIndex)
	}
	idx := leafIndex.Uint64()
	if depth > 0 && idx >= uint64(1)<<depth {
		return nil, suppliedGas, fmt.Errorf("%w: leafIndex %d >= 2^%d", ErrLeafIndex, idx, depth)
	}

	// Calculate and deduct gas.
	requiredGas := VerifyProofBaseGas + uint64(depth)*VerifyProofPerLevelGas
	remainingGas, err = contract.DeductGas(suppliedGas, requiredGas)
	if err != nil {
		return nil, 0, err
	}

	// Verify proof.
	valid := VerifyProofBigInt(leafHash, root, siblings, idx, int(depth))

	result, err := Poseidon2SMTABI.Methods["verifyProof"].Outputs.Pack(valid)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("failed to pack output: %w", err)
	}
	return result, remainingGas, nil
}

// createPoseidon2SMTPrecompile constructs the StatefulPrecompiledContract.
func createPoseidon2SMTPrecompile() contract.StatefulPrecompiledContract {
	computeRootMethod, ok := Poseidon2SMTABI.Methods["computeRoot"]
	if !ok {
		panic("computeRoot method not found in ABI")
	}
	verifyProofMethod, ok := Poseidon2SMTABI.Methods["verifyProof"]
	if !ok {
		panic("verifyProof method not found in ABI")
	}
	functions := []*contract.StatefulPrecompileFunction{
		contract.NewStatefulPrecompileFunction(computeRootMethod.ID, computeRootHandler),
		contract.NewStatefulPrecompileFunction(verifyProofMethod.ID, verifyProofHandler),
	}
	statefulContract, err := contract.NewStatefulPrecompileContract(nil, functions)
	if err != nil {
		panic(err)
	}
	return statefulContract
}

// extractUint256Slice safely converts the ABI-unpacked argument to []*big.Int.
func extractUint256Slice(arg interface{}) ([]*big.Int, error) {
	arr, ok := arg.([]*big.Int)
	if !ok {
		return nil, fmt.Errorf("%w: expected uint256[]", ErrInvalidInput)
	}
	for i, v := range arr {
		if v == nil {
			return nil, fmt.Errorf("%w: element [%d] is nil", ErrInvalidInput, i)
		}
	}
	return arr, nil
}
