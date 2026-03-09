// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon2hasher

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

const (
	spongeWidth      = 3
	spongeRate       = 2
	spongeFullRounds = 6
	spongePartRounds = 50

	// MaxInputs is the protocol DoS guard — limits gas computation.
	// 127 inputs = 64 permutations.
	MaxInputs = 127
)

var (
	// rOrder is the BN254 scalar field order.
	rOrder, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)

	// spongePerm holds the immutable round keys. Each call creates its own
	// state on the stack, so concurrent use is safe.
	spongePerm *poseidon2.Permutation

	ErrInputNotInField = errors.New("input not in scalar field")
	ErrTooManyInputs   = errors.New("too many inputs")
)

func init() {
	spongePerm = poseidon2.NewPermutation(spongeWidth, spongeFullRounds, spongePartRounds)
}

// SpongeHash computes a Poseidon2 sponge hash with domain separation.
//
// The domain tag is placed in the capacity lane (state[2]) before any
// absorption. Inputs are absorbed in rate-sized blocks (2 elements per
// permutation call). An odd final input is absorbed alone into state[0]
// before permuting.
//
// Returns state[0] after all absorptions (squeeze).
func SpongeHash(domainTag int, inputs []fr.Element) fr.Element {
	var state [spongeWidth]fr.Element
	state[spongeRate].SetInt64(int64(domainTag))

	for i := 0; i < len(inputs); i += spongeRate {
		state[0].Add(&state[0], &inputs[i])
		if i+1 < len(inputs) {
			state[1].Add(&state[1], &inputs[i+1])
		}
		spongePerm.Permutation(state[:])
	}

	// Empty input: permute once so the output depends on the domain tag.
	if len(inputs) == 0 {
		spongePerm.Permutation(state[:])
	}

	return state[0]
}

// SpongeHashBigInt is a convenience wrapper that accepts and returns *big.Int.
// All inputs must be < rOrder. Returns an error if any input is out of range.
func SpongeHashBigInt(domainTag int, inputs []*big.Int) (*big.Int, error) {
	if len(inputs) > MaxInputs {
		return nil, ErrTooManyInputs
	}
	for i, v := range inputs {
		if v.Sign() < 0 || v.Cmp(rOrder) >= 0 {
			return nil, &InputError{Index: i, Err: ErrInputNotInField}
		}
	}

	elems := make([]fr.Element, len(inputs))
	for i, v := range inputs {
		elems[i].SetBigInt(v)
	}
	result := SpongeHash(domainTag, elems)
	out := new(big.Int)
	result.BigInt(out)
	return out, nil
}

// InputError wraps an error with the index of the offending input.
type InputError struct {
	Index int
	Err   error
}

func (e *InputError) Error() string {
	return e.Err.Error()
}

func (e *InputError) Unwrap() error {
	return e.Err
}
