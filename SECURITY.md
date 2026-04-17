<!--
SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
SPDX-License-Identifier: MIT
-->

# Security Policy

## Supported Versions

ZeiCoin is currently in testnet. Only the latest commit on `main` is actively maintained.

| Version | Supported |
|---------|-----------|
| testnet (main) | Yes |
| older commits | No |

## Official Sources

Only these GitHub repositories are official:

- ZeiCoin: https://github.com/ryo-zen/zeicoin
- Ocelot Wallet: https://github.com/ryo-zen/ocelot-wallet

Do not download or run node, miner, or wallet binaries from similarly named GitHub accounts. Report suspicious repositories, releases, or binaries through the private vulnerability process below.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via [GitHub Security Advisories](https://github.com/ryo-zen/zeicoin/security/advisories/new).

Include in your report:
- A description of the vulnerability and its potential impact
- The affected component (consensus, wallet, P2P, RPC, crypto)
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations, if you have them

## Response Process

1. You will receive acknowledgement within 72 hours.
2. We will investigate and keep you informed of progress.
3. A fix will be prepared and tested before any public disclosure.
4. You will be credited in the fix commit/advisory unless you prefer otherwise.

Please allow reasonable time to develop and deploy a fix before any public disclosure.

## Scope

### In Scope

- Consensus rule bypass (invalid block or transaction accepted)
- Double-spend vulnerabilities
- Wallet key exposure or decryption weaknesses
- P2P protocol attacks that crash nodes or allow remote code execution
- RPC/REST endpoint authentication or injection issues
- Memory safety bugs in critical paths

### Out of Scope

- Denial of service via resource exhaustion
- Issues only reproducible with local physical access
- Spam or rate-limiting concerns

## Security Architecture Summary

### Cryptography
- **Wallet encryption**: ChaCha20-Poly1305 AEAD with Argon2id key derivation (64MB memory, 3 iterations)
- **Transaction signing**: Ed25519 signatures, verified on mempool entry
- **Proof of Work**: RandomX (light mode on testnet, fast mode on mainnet)
- **HD Wallets**: BIP39 mnemonic (12 words) + BIP32 derivation

### Consensus
- Difficulty validated independently on every block — prevents difficulty spoofing
- Deep reorg admission policy — large reorgs require peer hash consensus before execution
- Fail-closed chain quarantine — state corruption causes the node to stop accepting blocks rather than continuing on bad state
- Coinbase maturity: 10 blocks (testnet), 100 blocks (mainnet)
- Duplicate transactions within a block are rejected

### Network
- All P2P traffic is encrypted and authenticated via Noise XX (libp2p)
- Peer block hash consensus mode configurable: `disabled`, `optional`, `enforced`
- RPC and REST interfaces bind to localhost by default — not exposed publicly

## Testnet Notice

ZeiCoin testnet has no real monetary value. The testnet may be reset at any time.
