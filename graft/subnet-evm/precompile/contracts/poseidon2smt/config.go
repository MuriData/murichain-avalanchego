// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon2smt

import "github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/precompileconfig"

var _ precompileconfig.Config = (*Config)(nil)

// Config for the Poseidon2 SMT precompile.
// No AllowList — anyone can compute roots and verify proofs.
type Config struct {
	precompileconfig.Upgrade
}

// NewConfig returns a new config instance that activates the precompile
// at the given block timestamp.
func NewConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{BlockTimestamp: blockTimestamp},
	}
}

// NewDisableConfig returns a config that disables the precompile at the given
// block timestamp.
func NewDisableConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{
			BlockTimestamp: blockTimestamp,
			Disable:        true,
		},
	}
}

func (*Config) Key() string { return ConfigKey }

func (c *Config) Verify(_ precompileconfig.ChainConfig) error {
	return nil
}

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}
