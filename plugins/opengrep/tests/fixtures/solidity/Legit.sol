// SPDX-License-Identifier: MIT
// NEGATIVE fixture (0058, P2e): legitimate token/escrow/router idioms that look
// superficially similar to the scam patterns but are safe. NONE of the scam
// rules may fire here — this is the false-positive guard.
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 id) external;
    function setApprovalForAll(address operator, bool approved) external;
}

contract Legit {
    address public owner;
    bool private _initialized;
    uint256 public fee;
    mapping(address => uint256) private balances;

    // OK: fee is bounded by a require cap -> excluded by pattern-not-inside.
    function setFee(uint256 f) external {
        require(f <= 1000, "max 10%");
        fee = f;
    }

    // OK: guarded initializer -> excluded by pattern-not.
    function initialize(address o) public initializer {
        owner = o;
    }

    modifier initializer() {
        require(!_initialized, "init");
        _initialized = true;
        _;
    }

    // OK: pulls only from the caller -> excluded.
    function deposit(IERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }

    // OK: NFT escrow pulls the caller's own token to the contract -> excluded.
    function stake(IERC721 nft, uint256 id) external {
        nft.safeTransferFrom(msg.sender, address(this), id);
    }

    // OK: approves only the contract itself -> excluded by pattern-not(address(this)).
    function enableSelf(IERC721 nft) external {
        nft.setApprovalForAll(address(this), true);
    }

    // OK: no owner-bypass gate on the transfer path -> excluded.
    function _transfer(address from, address to, uint256 amount) internal {
        balances[from] -= amount;
        balances[to] += amount;
    }
}

contract LegitV2 {
    address public owner;

    // OK: reinitializer-guarded upgrade initializer -> excluded by pattern-not.
    function initialize(address o) public reinitializer(2) {
        owner = o;
    }

    modifier reinitializer(uint8 version) {
        _;
    }
}
