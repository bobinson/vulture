// SPDX-License-Identifier: MIT
// Deliberately vulnerable Solidity fixture for the vendored rules (0058).
pragma solidity ^0.8.0;
contract Vuln {
    address owner;
    function setOwner(address n) public { require(tx.origin == owner); owner = n; }   // CWE-284
    function kill() public { selfdestruct(payable(msg.sender)); }                      // CWE-284
    function proxy(address t, bytes calldata d) public { t.delegatecall(d); }          // CWE-829
}
