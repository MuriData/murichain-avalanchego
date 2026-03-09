//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPoseidon2SMT {
    /// @notice Compute a sparse Merkle tree root from pre-hashed leaves.
    /// Leaves occupy indices 0..len-1; all other positions use the provided
    /// zeroLeafHash. Internal nodes use Poseidon2 with domain tag 2.
    /// @param leafHashes Pre-hashed leaf values (each must be < BN254 scalar field order)
    /// @param depth Tree depth (leaves at height 0, root at height `depth`)
    /// @param zeroLeafHash Hash value for padding leaf positions (circuit-specific)
    /// @return root The computed Merkle root
    function computeRoot(uint256[] calldata leafHashes, uint8 depth, uint256 zeroLeafHash)
        external view returns (uint256 root);

    /// @notice Verify a sparse Merkle inclusion proof.
    /// @param leafHash The leaf hash to verify
    /// @param root The expected Merkle root
    /// @param siblings Sibling hashes from leaf to root (length must equal depth)
    /// @param leafIndex Position of the leaf in the tree
    /// @param depth Tree depth
    /// @return valid True if the proof is valid
    function verifyProof(
        uint256 leafHash,
        uint256 root,
        uint256[] calldata siblings,
        uint256 leafIndex,
        uint8 depth
    ) external view returns (bool valid);
}
