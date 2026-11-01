// SPDX-License-Identifier: MIT
// Scam/vuln fixture (0058, P2e): honeypot token. The transfer path is gated so
// that until the owner flips a flag THEY control, only the owner can move
// tokens — victims can buy but cannot sell. -> CWE-284 (Improper Access
// Control over the transfer function).
pragma solidity ^0.8.0;

contract Honeypot {
    address public owner;
    bool public tradingEnabled;
    mapping(address => uint256) private balances;

    function _transfer(address from, address to, uint256 amount) internal {
        // BAD: owner bypasses the trading gate; everyone else is frozen.
        require(tradingEnabled || from == owner, "trading disabled");
        balances[from] -= amount;
        balances[to] += amount;
    }
}
