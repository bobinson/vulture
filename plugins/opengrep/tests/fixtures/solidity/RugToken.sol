// SPDX-License-Identifier: MIT
// Scam/vuln fixture (0058, P2f): rug-pull owner-omnipotence markers.
//   * setFee()     -> owner sets the fee/tax with NO upper bound; it can be
//                     pushed to 100%, freezing every transfer. -> CWE-284.
//   * setBalance() -> owner overwrites any account's balance directly (mint
//                     from nothing, or zero a holder). -> CWE-284.
pragma solidity ^0.8.0;

contract RugToken {
    address public owner;
    uint256 public fee;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    // BAD: no `require(f <= MAX)` bound -> fee can be set to anything.
    function setFee(uint256 f) external onlyOwner {
        fee = f;
    }

    // BAD: direct, unaccounted overwrite of an arbitrary balance.
    function setBalance(address account, uint256 amount) external onlyOwner {
        balances[account] = amount;
    }
}
