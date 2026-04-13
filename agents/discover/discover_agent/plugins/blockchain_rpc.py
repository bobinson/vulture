"""BlockchainRPCPlugin — discover blockchain JSON-RPC and REST endpoints.

Detects Ethereum, Solana, Bitcoin, Cosmos, IPFS, and TheGraph endpoints
from source dependencies, port probing, and RPC method enumeration.
"""

import json
import logging
from pathlib import Path
from urllib.parse import urlparse

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import has_dependency, probe_endpoint, probe_port

logger = logging.getLogger(__name__)

# Chain-specific RPC methods
ETHEREUM_METHODS = [
    "eth_blockNumber", "eth_getBalance", "eth_call",
    "net_version", "web3_clientVersion",
]
SOLANA_METHODS = [
    "getAccountInfo", "getBalance", "getSlot", "getBlockHeight",
]
BITCOIN_METHODS = [
    "getblockchaininfo", "getnetworkinfo", "getmininginfo",
]

# Chain-specific REST endpoints
COSMOS_LCD_PATHS = [
    "/cosmos/bank/v1beta1/balances",
    "/cosmos/staking/v1beta1/validators",
    "/cosmos/base/tendermint/v1beta1/node_info",
]
IPFS_API_PATHS = [
    "/api/v0/id",
    "/api/v0/version",
    "/api/v0/swarm/peers",
]

CHAIN_PORTS: dict[str, list[int]] = {
    "ethereum": [8545, 8546],
    "solana": [8899],
    "bitcoin": [8332],
    "cosmos": [26657, 1317],
    "ipfs": [5001],
}

CHAIN_DEPS: dict[str, set[str]] = {
    "ethereum": {"web3", "ethers", "viem", "hardhat", "web3.py", "@ethersproject"},
    "solana": {"@solana/web3.js", "anchor-lang", "solana-sdk"},
    "bitcoin": {"bitcoinjs-lib", "python-bitcoinrpc", "btcd"},
    "cosmos": {"cosmjs", "@cosmjs/stargate", "cosmos-sdk"},
    "ipfs": {"ipfs-http-client", "kubo-rpc-client", "js-ipfs"},
    "thegraph": {"@graphprotocol/graph-cli", "@graphprotocol/graph-ts"},
}


@register_plugin
class BlockchainRPCPlugin(DiscoveryPlugin):
    """Discover blockchain JSON-RPC and REST API endpoints."""

    name = "blockchain_rpc"
    priority = 63

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        # Only run if source has blockchain dependencies or known blockchain signals
        if ctx.source_path:
            root = Path(ctx.source_path)
            for deps in CHAIN_DEPS.values():
                if has_dependency(root, deps):
                    return True
        # Also accept if prior plugins detected blockchain technologies
        blockchain_techs = [t for t in ctx.site.technologies if "blockchain" in t.lower()]
        return len(blockchain_techs) > 0

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        parsed = urlparse(ctx.staging_url)
        host = parsed.hostname or "localhost"
        base = ctx.staging_url.rstrip("/")

        # 1. Detect chain type from source dependencies
        detected_chains: list[str] = []
        if ctx.source_path:
            root = Path(ctx.source_path)
            for chain, deps in CHAIN_DEPS.items():
                if has_dependency(root, deps):
                    detected_chains.append(chain)
                    result.technologies.append(f"blockchain:{chain}")

        # 2. Probe ONLY detected chain ports (not all chains)
        await _probe_chain_ports(host, detected_chains, result)

        # 3. Try JSON-RPC methods on the staging URL
        await _probe_jsonrpc_methods(ctx.http_client, base, result)

        # 4. Probe REST endpoints (Cosmos LCD, IPFS)
        if "cosmos" in detected_chains:
            await _probe_rest_paths(ctx.http_client, base, COSMOS_LCD_PATHS, "Cosmos", result)
        if "ipfs" in detected_chains:
            await _probe_rest_paths(ctx.http_client, base, IPFS_API_PATHS, "IPFS", result)

        # 5. Probe TheGraph subgraph endpoints
        if "thegraph" in detected_chains:
            await _probe_thegraph(ctx.http_client, base, result)

        if result.metadata.get("blockchain_chain"):
            logger.info("Blockchain detected: %s", result.metadata["blockchain_chain"])
        return result


async def _probe_chain_ports(
    host: str, detected_chains: list[str], result: DiscoveryResult,
) -> None:
    """Probe chain-specific ports for detected chains only."""
    if not detected_chains:
        return
    for chain in detected_chains:
        for port in CHAIN_PORTS.get(chain, []):
            if await probe_port(host, port, timeout=3.0):
                result.metadata["blockchain_chain"] = chain
                result.metadata.setdefault("blockchain_ports", []).append(port)
                logger.info("Blockchain port open: %s:%d (%s)", host, port, chain)


async def _probe_jsonrpc_methods(
    client, base: str, result: DiscoveryResult,
) -> None:
    """Try chain-specific JSON-RPC methods on the staging URL."""
    for chain, methods in [
        ("ethereum", ETHEREUM_METHODS),
        ("solana", SOLANA_METHODS),
        ("bitcoin", BITCOIN_METHODS),
    ]:
        test_method = methods[0]
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": test_method,
            "params": [],
            "id": 1,
        }).encode()
        ok, resp = await probe_endpoint(
            client, base,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=payload,
            timeout=5.0,
        )
        if not ok or resp is None:
            continue
        try:
            data = resp.json()
        except Exception:
            continue
        if "result" in data and "error" not in data:
            result.metadata["blockchain_chain"] = chain
            result.metadata.setdefault("blockchain_methods", []).append(test_method)
            result.technologies.append(f"blockchain:{chain}")
            result.endpoints.append("/")
            logger.info("Blockchain JSON-RPC: %s via %s", chain, test_method)
            return


async def _probe_rest_paths(
    client, base: str, paths: list[str], chain: str, result: DiscoveryResult,
) -> None:
    """Probe chain-specific REST endpoints."""
    for path in paths[:3]:
        ok, resp = await probe_endpoint(client, f"{base}{path}", timeout=5.0)
        if ok and resp is not None and resp.status_code < 400:
            result.endpoints.append(path)
            result.metadata["blockchain_chain"] = chain.lower()
            logger.info("Blockchain REST: %s at %s", chain, path)
            return


async def _probe_thegraph(
    client, base: str, result: DiscoveryResult,
) -> None:
    """Probe TheGraph subgraph endpoints."""
    query = json.dumps({"query": "{ _meta { block { number } } }"}).encode()
    paths = ["/subgraphs", "/graphql"]
    for path in paths:
        ok, resp = await probe_endpoint(
            client, f"{base}{path}",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=query,
            timeout=5.0,
        )
        if ok and resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data:
                    result.endpoints.append(path)
                    result.technologies.append("TheGraph")
                    logger.info("TheGraph endpoint found: %s", path)
                    return
            except Exception:
                pass
