//! Event and call layouts from the engine's `abi/V2.1/RailgunSmartWallet.json`
//! (an interface description, used here only for its types).

use alloy_sol_types::sol;

sol! {
    struct TokenData {
        uint8 tokenType;
        address tokenAddress;
        uint256 tokenSubID;
    }

    struct CommitmentPreimage {
        bytes32 npk;
        TokenData token;
        uint120 value;
    }

    struct ShieldCiphertext {
        bytes32[3] encryptedBundle;
        bytes32 shieldKey;
    }

    struct CommitmentCiphertext {
        bytes32[4] ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData;
        bytes memo;
    }

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    struct SnarkProof {
        G1Point a;
        G2Point b;
        G1Point c;
    }

    struct BoundParams {
        uint16 treeNumber;
        uint72 minGasPrice;
        uint8 unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        CommitmentCiphertext[] commitmentCiphertext;
    }

    struct Transaction {
        SnarkProof proof;
        bytes32 merkleRoot;
        bytes32[] nullifiers;
        bytes32[] commitments;
        BoundParams boundParams;
        CommitmentPreimage unshieldPreimage;
    }

    event Shield(
        uint256 treeNumber,
        uint256 startPosition,
        CommitmentPreimage[] commitments,
        ShieldCiphertext[] shieldCiphertext,
        uint256[] fees
    );

    event Transact(
        uint256 treeNumber,
        uint256 startPosition,
        bytes32[] hash,
        CommitmentCiphertext[] ciphertext
    );

    event Nullified(uint16 treeNumber, bytes32[] nullifier);

    event Unshield(address to, TokenData token, uint256 amount, uint256 fee);

    function transact(Transaction[] _transactions) external payable;

    function rootHistory(uint256 tree, bytes32 root) external view returns (bool);
}
