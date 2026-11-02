//! Event and call layouts from the engine's `abi/V2.1/RailgunSmartWallet.json` (an interface description, used here only for its types).

use alloy_sol_types::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct TokenData {
        uint8 tokenType;
        address tokenAddress;
        uint256 tokenSubID;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CommitmentPreimage {
        bytes32 npk;
        TokenData token;
        uint120 value;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ShieldCiphertext {
        bytes32[3] encryptedBundle;
        bytes32 shieldKey;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ShieldRequest {
        CommitmentPreimage preimage;
        ShieldCiphertext ciphertext;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CommitmentCiphertext {
        bytes32[4] ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData;
        bytes memo;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct SnarkProof {
        G1Point a;
        G2Point b;
        G1Point c;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct BoundParams {
        uint16 treeNumber;
        uint72 minGasPrice;
        uint8 unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        CommitmentCiphertext[] commitmentCiphertext;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Transaction {
        SnarkProof proof;
        bytes32 merkleRoot;
        bytes32[] nullifiers;
        bytes32[] commitments;
        BoundParams boundParams;
        CommitmentPreimage unshieldPreimage;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct VerifyingKey {
        string artifactsIPFSHash;
        G1Point alpha1;
        G2Point beta2;
        G2Point gamma2;
        G2Point delta2;
        G1Point[] ic;
    }

    event VerifyingKeySet(uint256 nullifiers, uint256 commitments, VerifyingKey verifyingKey);

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

    function shield(ShieldRequest[] _shieldRequests) external payable;

    function transact(Transaction[] _transactions) external payable;

    function rootHistory(uint256 tree, bytes32 root) external view returns (bool);

    function approve(address spender, uint256 amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);

    function balanceOf(address owner) external view returns (uint256);
}
