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
