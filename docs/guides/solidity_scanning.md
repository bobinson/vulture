# Scanning Solidity smart contracts

Vulture scans Solidity through the **opengrep plugin**, not the CWE agent's own
skills — `.sol` is outside the CWE agent's `CODE_EXTENSIONS`, so only the plugin
sees Solidity. The plugin ships pinned, offline Solidity rules plus a composite
scam-risk correlator aimed at scammer-operated contracts (drainers, honeypots,
rug pulls, proxy takeovers).

## Enable & run (dev mode)

opengrep is **opt-in**. Unticked, it is never added to a scan.

```bash
git clone https://github.com/bobinson/vulture
cd vulture
./scripts/vulture.sh build

# Start dev mode with the opengrep plugin activated — pick a provider:
./scripts/vulture.sh dev gemini gemini-2.5-flash --pg --plugins opengrep   # Gemini
./scripts/vulture.sh dev lmstudio --pg --plugins opengrep                  # local LMStudio
```

Then run a scan selecting the opengrep tier:

```bash
vulture scan <path-or-git-url> --types cwe,opengrep
```

Or, in the UI, tick **opengrep** on the audit-config screen. Findings stream live
and land in the final result snapshot.

## Threats detected (vendored tier — hermetic, pinned, offline)

Severity shown is Vulture's (`ERROR`→high, `WARNING`→medium).

### Wallet drainers / approval theft

| Rule | Flags | CWE | Sev |
|------|-------|-----|-----|
| `arbitrary-from-transferfrom` | ERC-20 `transferFrom(arbitrary from,…)` — sweeps approved wallets | CWE-863 | med |
| `arbitrary-from-nft-transfer` | ERC-721/1155 `safeTransferFrom(arbitrary from,…)` | CWE-863 | med |
| `set-approval-for-all-untrusted` | `setApprovalForAll(operator, true)` to a non-self operator (bait step) | CWE-863 | med |

### Honeypot / rug pull

| Rule | Flags | CWE | Sev |
|------|-------|-----|-----|
| `honeypot-transfer-gate` | transfer path gated on owner — "can buy, can't sell" | CWE-284 | med |
| `uncapped-fee-setter` | owner fee/tax assigned with no `require(fee <= MAX)` bound | CWE-284 | med |
| `owner-direct-balance-write` | `balances[x] = v` overwrite (vs checked `+=`/`-=`) | CWE-284 | med |

### Takeover / backdoor

| Rule | Flags | CWE | Sev |
|------|-------|-----|-----|
| `unprotected-initializer` | `initialize()` without `initializer`/`reinitializer` guard | CWE-665 | high |
| `unprotected-selfdestruct` | `selfdestruct` — confirm it is access-controlled | CWE-284 | med |
| `delegatecall-untrusted` | `delegatecall` to a non-constant target | CWE-829 | high |
| `tx-origin-auth` | `tx.origin` used in an authorization check | CWE-284 | high |

Rule ids are prefixed `vulture-solidity-`.

## Composite scam-risk score

Any one rule above is a **review signal** — legitimate tokens sometimes share a
single shape. The scam signal is **co-occurrence**. When ≥ 3 *distinct*
drainer/owner-omnipotence markers fire in one contract, the plugin emits a
single high-severity `vulture-solidity-composite-scam-risk` finding
(CWE-284). Distinct matters: the same rule firing twice counts once. Threshold:
`SCAM_SCORE_MIN_MARKERS` in `plugins/opengrep/src/translate.py`.

## No registry tier

The plugin runs only its bundled rules, offline. The Semgrep Registry's
`r/solidity` namespace it used to add (feature 0058) was removed in plugin
0.2.0 (feature 0102): Semgrep's rules licence permits neither redistributing
those rules nor offering them as a service.

## Reading results

All plugin findings carry `provenance=opengrep` (`semgrep` in audits made before plugin 0.2.0). They are **not corpus-gated** —
they surface as ungated findings, not counted toward the CWE agent's verified N.

## Limitations

Pattern-tier only. The engine's Solidity support is experimental and has no
reliable dataflow, so these are **not** covered and need a future
Slither/Mythril tier: reentrancy (call-vs-state ordering), true honeypot
confirmation (buy/sell simulation), and backdoor reachability.

---

## Addendum: decompiling bytecode → Solidity

To audit a deployed contract with no verified source, recover approximate
Solidity from its **runtime** bytecode, then scan that.

**1. Fetch runtime bytecode** (deployed code, not creation code):

```bash
cast code <address> --rpc-url <url>          # foundry
# or JSON-RPC eth_getCode(address, "latest")
```

**2. Decompile** (pick one):

| Tool | Command / where | Output |
|------|-----------------|--------|
| Heimdall | `heimdall decompile <address\|bytecode> --rpc-url <url>` | Solidity-ish + ABI |
| Dedaub | app.dedaub.com (paste bytecode) | highest fidelity |
| Panoramix | `panoramix <address>` (powers Etherscan "Decompile Bytecode") | pseudo-Solidity |

Recover function selectors/ABI with `whatsabi` or 4byte.directory.

**3. Scan the emitted `.sol`** like any source tree — point a dev-mode scan at
the folder: `vulture scan ./decompiled --types cwe,opengrep`.

**Caveats.** Decompiled source is lossy — variable/function names are gone and
control flow is approximate. Rules that key on identifiers (`fee`, `tax`,
`balance`, `owner`) may miss or misfire, so treat pattern hits as **advisory**.
For a suspected drainer, confirm on-chain: inspect who granted the contract an
allowance (revoke.cash), and compare against verified similar contracts.
