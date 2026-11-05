// SPDX-License-Identifier: MIT
// Scam/vuln fixture (0058, P2g): a single contract stacking MULTIPLE
// owner-omnipotence / scam markers. Individually each is a review signal;
// together they must raise the composite "scam risk" finding (>= 3 markers).
pragma solidity ^0.8.0;

contract ScamToken {
    address public owner;
    bool public tradingEnabled;
    uint256 public fee;
    bool private _initialized;
    mapping(address => uint256) private balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    // marker 1: unprotected initializer -> CWE-665
    function initialize(address o) public {
        owner = o;
    }

    modifier initializer() {
        require(!_initialized, "init");
        _initialized = true;
        _;
    }

    // marker 2: uncapped fee setter -> CWE-284
    function setFee(uint256 f) external onlyOwner {
        fee = f;
    }

    // marker 3: direct balance write -> CWE-284
    function setBalance(address account, uint256 amount) external onlyOwner {
        balances[account] = amount;
    }

    // marker 4: honeypot transfer gate -> CWE-284
    function _transfer(address from, address to, uint256 amount) internal {
        require(tradingEnabled || from == owner, "trading disabled");
        balances[from] -= amount;
        balances[to] += amount;
    }
}
