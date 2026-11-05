// SPDX-License-Identifier: MIT
// Scam/vuln fixture (0058, P2e): upgradeable-proxy implementation with an
// UNPROTECTED initializer. There is an `initializer` modifier in scope but it
// is NOT applied to initialize(), so anyone can (re-)call it and seize
// ownership — the classic proxy takeover. -> CWE-665.
pragma solidity ^0.8.0;

contract Proxy {
    address public owner;
    bool private _initialized;

    // BAD: no `initializer` guard -> front-runnable / re-callable takeover.
    function initialize(address o) public {
        owner = o;
    }

    modifier initializer() {
        require(!_initialized, "init");
        _initialized = true;
        _;
    }
}
