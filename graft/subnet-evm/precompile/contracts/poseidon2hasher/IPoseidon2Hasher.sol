//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPoseidon2Hasher {
    /// @notice Compute a Poseidon2 sponge hash with domain separation.
    /// @param domainTag Domain separation tag (uint8, placed in capacity lane)
    /// @param inputs Field elements to hash (each must be < BN254 scalar field order)
    /// @return digest The hash output (a single BN254 scalar field element)
    function hash(uint8 domainTag, uint256[] calldata inputs)
        external view returns (uint256 digest);
}
