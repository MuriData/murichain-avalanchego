//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IGroth16Verifier {
    /// @notice Verify a Groth16 BN254 proof with the given verification key.
    /// @param proof Uncompressed proof points [A.x, A.y, B.x1, B.x0, B.y1, B.y0, C.x, C.y]
    /// @param publicInputs The public input scalars (variable length, each must be < R)
    /// @param vkAlpha Alpha G1 point [x, y]
    /// @param vkBetaNeg Negated Beta G2 point [x1, x0, y1, y0]
    /// @param vkGammaNeg Negated Gamma G2 point [x1, x0, y1, y0]
    /// @param vkDeltaNeg Negated Delta G2 point [x1, x0, y1, y0]
    /// @param vkIC Verification key IC G1 points, length must equal publicInputs.length + 1
    /// @return valid True if the proof is valid
    function verifyProof(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs,
        uint256[2] calldata vkAlpha,
        uint256[4] calldata vkBetaNeg,
        uint256[4] calldata vkGammaNeg,
        uint256[4] calldata vkDeltaNeg,
        uint256[2][] calldata vkIC
    ) external view returns (bool valid);

    /// @notice Verify a Groth16 BN254 proof using compressed proof format.
    /// @param compressedProof Compressed proof [compressed_A, B_c1, B_c0, compressed_C]
    /// @param publicInputs The public input scalars (variable length, each must be < R)
    /// @param vkAlpha Alpha G1 point [x, y]
    /// @param vkBetaNeg Negated Beta G2 point [x1, x0, y1, y0]
    /// @param vkGammaNeg Negated Gamma G2 point [x1, x0, y1, y0]
    /// @param vkDeltaNeg Negated Delta G2 point [x1, x0, y1, y0]
    /// @param vkIC Verification key IC G1 points, length must equal publicInputs.length + 1
    /// @return valid True if the proof is valid
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[] calldata publicInputs,
        uint256[2] calldata vkAlpha,
        uint256[4] calldata vkBetaNeg,
        uint256[4] calldata vkGammaNeg,
        uint256[4] calldata vkDeltaNeg,
        uint256[2][] calldata vkIC
    ) external view returns (bool valid);
}
