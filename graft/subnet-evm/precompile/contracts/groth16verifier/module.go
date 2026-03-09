// Copyright (C) 2024, MuriData. All rights reserved.
// See the file LICENSE for licensing terms.

package groth16verifier

import (
	"fmt"

	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contract"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/modules"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)

// ConfigKey is the key used in JSON config files to specify this precompile config.
const ConfigKey = "groth16VerifierConfig"

// ContractAddress is the precompile address.
// Custom fork precompiles start at 0x0300000000000000000000000000000000000000.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000001")

// Module is the precompile module used to register with the framework.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     Groth16VerifierPrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config {
	return new(Config)
}

// Configure is a no-op — the Groth16 verifier is stateless.
func (*configurator) Configure(_ precompileconfig.ChainConfig, cfg precompileconfig.Config, _ contract.StateDB, _ contract.ConfigurationBlockContext) error {
	if _, ok := cfg.(*Config); !ok {
		return fmt.Errorf("expected config type %T, got %T: %v", &Config{}, cfg, cfg)
	}
	return nil
}
