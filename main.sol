// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Field note: “cinder orchid protocol”
    A vault that treats actions as tickets: you stage intent, wait out a fuse, then execute.
    It’s a boring safety pattern on purpose: no mystery math, no hidden minting, no upgrade trapdoor.
*/

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IERC20PermitLike {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

library H0piuMSafeTransfer {
    error H0piuM__TokenCallFailed();
    error H0piuM__TokenBadReturn();

    function _callOptionalReturn(address token, bytes memory data) private {
        (bool ok, bytes memory ret) = token.call(data);
        if (!ok) revert H0piuM__TokenCallFailed();
        if (ret.length == 0) return;
        if (ret.length == 32) {
            uint256 v;
            assembly ("memory-safe") {
                v := mload(add(ret, 0x20))
            }
            if (v != 1) revert H0piuM__TokenBadReturn();
            return;
        }
        revert H0piuM__TokenBadReturn();
    }

    function safeTransfer(address token, address to, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(IERC20Like.transfer.selector, to, amount));
    }

    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(IERC20Like.transferFrom.selector, from, to, amount));
    }
}

library H0piuMBytes {
    function toBytes32(bytes memory b, uint256 offset) internal pure returns (bytes32 out) {
        if (b.length < offset + 32) revert();
        assembly ("memory-safe") {
            out := mload(add(add(b, 0x20), offset))
        }
    }

    function slice(bytes calldata b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ) {
            out[i] = b[start + i];
            unchecked {
                ++i;
            }
        }
    }
}

/// @title H0piuM — staged-intent vault with fuses
/// @notice Deposits/withdrawals are direct; admin actions must be staged then executed after a delay.
/// @dev No proxies, no delegatecall, no upgrades. Uses immutables, custom errors, and nonReentrant guards.
contract H0piuM {
    using H0piuMSafeTransfer for address;

    // ---------- identity anchors (not permissions; just immutable fingerprints) ----------
    bytes32 internal constant _H0P_SALT_A = 0x7a0db9a3d6f5b1a0c1c8f0a8c9b4d3f22c7b1a3e8f5d3c1a9b0e2d4c7f8a9b01;
    bytes32 internal constant _H0P_SALT_B = 0x1c6f0d8a39b2e7c4d5f6a1b3c9d0e2f45a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d;
    bytes32 internal constant _H0P_SALT_C = 0x9e2c7b1a4f6d0c3a8b5e1d9f2a7c6b0d1e4f3a8b7c6d5e0f9a1b2c3d4e5f6071;

    // Random-looking anchors (EIP-55 mixed-case). These are NOT used for access and can be ignored.
    address public immutable ORCHID_ANCHOR_0 = 0x7d0B1a3E8F5D3c1A9b0e2D4C7f8A9B01c6F0D8A3;
    address public immutable ORCHID_ANCHOR_1 = 0xA3f6D0c3A8B5E1d9F2a7C6B0D1e4F3A8B7c6D5E0;
    address public immutable ORCHID_ANCHOR_2 = 0x1E4f3A8b7C6D5E0f9A1B2c3D4E5F60717A0Db9A3;

    // ---------- accounting totals (enables safe “excess-only” rescues) ----------
    mapping(address => uint256) public totalErc20Accounted;
    uint256 public totalNativeAccounted;

    // ---------- lightweight token registry (bounded) ----------
    // Keeps a small set of tokens touched so off-chain tooling can inspect accounting without scanning logs.
    // This is not used for permissioning and does not affect balances.
    error H0piuM__TokenRegistryFull();
    uint256 internal constant _TOKEN_REGISTRY_CAP = 64;
    address[] private _touchedTokens;
    mapping(address => bool) private _touchedToken;

    // ---------- access ----------
    error H0piuM__NotOwner();
    error H0piuM__NotGuardian();
    error H0piuM__BadPendingOwner();
    error H0piuM__ZeroAddress();
    error H0piuM__Paused();
    error H0piuM__AlreadyPaused();
    error H0piuM__AlreadyUnpaused();

    event H0piuM_OwnerProposed(address indexed proposed);
    event H0piuM_OwnerAccepted(address indexed previous, address indexed next);
    event H0piuM_GuardianSet(address indexed previous, address indexed next);
    event H0piuM_PauseChanged(bool paused, address indexed by);

    address private _owner;
    address private _pendingOwner;
    address public guardian;
    bool public paused;

    // ---------- EIP-712 authorized withdrawals ----------
    // Users can sign a withdrawal so a relayer (or anyone) can submit it.
    // This does not grant new powers; it only changes who can submit the tx.
    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant _EIP712_NAME_HASH = keccak256(bytes("H0piuM-OrchidVault"));
    bytes32 internal constant _EIP712_VERSION_HASH = keccak256(bytes("v1.2.0"));

    bytes32 internal constant _AUTH_WITHDRAW_NATIVE_TYPEHASH =
        keccak256("AuthWithdrawNative(address owner,address to,uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 internal constant _AUTH_WITHDRAW_ERC20_TYPEHASH =
        keccak256("AuthWithdrawERC20(address token,address owner,address to,uint256 amount,uint256 nonce,uint256 deadline)");

    uint256 internal constant _SECP256K1_HALF_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    error H0piuM__AuthExpired();
    error H0piuM__AuthBadSig();
    error H0piuM__AuthNonce();

    event H0piuM_AuthorizedWithdrawNative(address indexed owner, address indexed to, uint256 amount, uint256 nonce);
    event H0piuM_AuthorizedWithdrawERC20(
        address indexed token,
        address indexed owner,
        address indexed to,
        uint256 amount,
        uint256 nonce
    );

    mapping(address => uint256) public authNonces;

    modifier onlyOwner() {
        if (msg.sender != _owner) revert H0piuM__NotOwner();
        _;
    }

    modifier onlyGuardianOrOwner() {
        if (msg.sender != guardian && msg.sender != _owner) revert H0piuM__NotGuardian();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert H0piuM__Paused();
