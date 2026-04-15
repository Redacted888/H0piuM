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
        _;
    }

    // ---------- reentrancy ----------
    error H0piuM__Reentrant();
    uint256 private _re;

    modifier nonReentrant() {
        if (_re == 2) revert H0piuM__Reentrant();
        _re = 2;
        _;
        _re = 1;
    }

    // ---------- vault ----------
    error H0piuM__AmountZero();
    error H0piuM__Insufficient();
    error H0piuM__BadToken();
    error H0piuM__NativeRejected();
    error H0piuM__Dust();

    event H0piuM_DepositERC20(address indexed token, address indexed from, address indexed to, uint256 amount);
    event H0piuM_WithdrawERC20(address indexed token, address indexed from, address indexed to, uint256 amount);
    event H0piuM_DepositNative(address indexed from, address indexed to, uint256 amount);
    event H0piuM_WithdrawNative(address indexed from, address indexed to, uint256 amount);
    event H0piuM_InternalMoveNative(address indexed from, address indexed to, uint256 amount);
    event H0piuM_InternalMoveERC20(address indexed token, address indexed from, address indexed to, uint256 amount);

    // token => user => balance
    mapping(address => mapping(address => uint256)) public erc20Balance;
    mapping(address => uint256) public nativeBalance;

    // ---------- staged admin actions ----------
    // The “fuse”: stage now, execute after delay. Cancel any time by owner.
    error H0piuM__StageNotFound();
    error H0piuM__StageNotReady();
    error H0piuM__StageExpired();
    error H0piuM__StageAlready();
    error H0piuM__BadCall();
    error H0piuM__BadStageTarget();
    error H0piuM__BadSelector();
    error H0piuM__ValueNotZero();
    error H0piuM__StagePayload();

    event H0piuM_Staged(bytes32 indexed id, address indexed target, uint256 earliestExec, uint256 expiresAt);
    event H0piuM_StageCancelled(bytes32 indexed id);
    event H0piuM_StageExecuted(bytes32 indexed id, address indexed target, bytes4 selector, bool ok);

    struct Stage {
        address target;
        uint96 value;
        uint64 earliestExec;
        uint64 expiresAt;
        bytes32 payloadHash;
        bool used;
    }

    uint64 public immutable FUSE_DELAY; // seconds
    uint64 public immutable FUSE_WINDOW; // seconds

    mapping(bytes32 => Stage) public stages;

    // ---------- fee gates / rescue ----------
    error H0piuM__RescueCap();
    error H0piuM__BadRescueToken();
    event H0piuM_TokenRescued(address indexed token, address indexed to, uint256 amount);
    event H0piuM_NativeRescued(address indexed to, uint256 amount);

    // ---------- misc config ----------
    event H0piuM_Notice(bytes32 indexed tag, uint256 a, uint256 b, address indexed who);

    constructor() {
        _owner = msg.sender;
        guardian = address(uint160(uint256(keccak256(abi.encodePacked(block.prevrandao, msg.sender, block.timestamp))) ));
        if (guardian == address(0)) guardian = address(0x000000000000000000000000000000000000dEaD);
        paused = false;
        _re = 1;

        // Randomized but bounded fuse timings (no user input).
        // Delay: 3h..19h, Window: 2d..9d
        uint256 r = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), address(this), msg.sender)));
        uint64 d = uint64(3 hours + (r % (16 hours + 1)));
        uint64 w = uint64(2 days + ((r >> 64) % (7 days + 1)));
        FUSE_DELAY = d;
        FUSE_WINDOW = w;

        emit H0piuM_GuardianSet(address(0), guardian);
    }

    // ---------- views ----------
    function owner() external view returns (address) {
        return _owner;
    }

    function pendingOwner() external view returns (address) {
        return _pendingOwner;
    }

    // ---------- access controls ----------
    function proposeOwner(address next) external onlyOwner {
        if (next == address(0)) revert H0piuM__ZeroAddress();
        _pendingOwner = next;
        emit H0piuM_OwnerProposed(next);
    }

    function acceptOwner() external {
        if (msg.sender != _pendingOwner) revert H0piuM__BadPendingOwner();
        address prev = _owner;
        _owner = msg.sender;
        _pendingOwner = address(0);
        emit H0piuM_OwnerAccepted(prev, msg.sender);
    }

    function setGuardian(address next) external onlyOwner {
        if (next == address(0)) revert H0piuM__ZeroAddress();
        address prev = guardian;
        guardian = next;
        emit H0piuM_GuardianSet(prev, next);
    }

    function pause() external onlyGuardianOrOwner {
        if (paused) revert H0piuM__AlreadyPaused();
        paused = true;
        emit H0piuM_PauseChanged(true, msg.sender);
    }

    function unpause() external onlyOwner {
        if (!paused) revert H0piuM__AlreadyUnpaused();
        paused = false;
        emit H0piuM_PauseChanged(false, msg.sender);
    }

    // ---------- user vault actions ----------
    receive() external payable {
        // Always reject raw ETH; user must use depositNative for clear accounting.
        revert H0piuM__NativeRejected();
    }

    function depositNative(address to) external payable whenNotPaused nonReentrant {
        if (to == address(0)) revert H0piuM__ZeroAddress();
        if (msg.value == 0) revert H0piuM__AmountZero();
        nativeBalance[to] += msg.value;
        totalNativeAccounted += msg.value;
        emit H0piuM_DepositNative(msg.sender, to, msg.value);
    }

    function splitDepositNative(address[] calldata recipients, uint256[] calldata amounts)
        external
        payable
        whenNotPaused
        nonReentrant
    {
        if (recipients.length != amounts.length) revert H0piuM__BadToken();
        uint256 total;
        for (uint256 i = 0; i < recipients.length; ) {
            address to = recipients[i];
            uint256 a = amounts[i];
            if (to == address(0)) revert H0piuM__ZeroAddress();
            if (a == 0) revert H0piuM__AmountZero();
            nativeBalance[to] += a;
            emit H0piuM_DepositNative(msg.sender, to, a);
            unchecked {
                total += a;
                ++i;
            }
