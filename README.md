> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# C5 Blockchain Analyzer — Offline Blockchain Forensics & Consensus Attack Detection

[![License](https://img.shields.io/github/license/5h4d0wn1k/c5-blockchain)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/c5-blockchain)](https://github.com/5h4d0wn1k/c5-blockchain/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/c5-blockchain)](https://github.com/5h4d0wn1k/c5-blockchain/commits/master)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/c5-blockchain)](https://github.com/5h4d0wn1k/c5-blockchain/issues)

**C5 Blockchain Analyzer** is an offline, Python-based blockchain forensics toolkit for transaction parsing, address clustering, wallet tracking, pattern detection, and consensus attack scanning. Built for authorized security research, digital forensics education, and blockchain integrity analysis.

## Why C5 Blockchain Analyzer?

C5 Blockchain Analyzer enables security researchers and students to analyze blockchain data structures offline without connecting to live networks. The toolkit parses binary transactions and block headers using Python's standard library, performs address clustering from multi-signature inputs, tracks wallet balances and transaction histories, detects suspicious transaction patterns, and includes a SecurityScanner that identifies consensus-level anomalies against planted fixtures. All analysis runs fully offline for safe, controlled educational environments.

## Features

- **Binary Transaction Parsing** — Parse raw transaction and block header data using standard library `struct` module (see `Transaction` and `Block` classes in `blockchain_analyzer.py`).
- **Address Clustering** — Identify related addresses through multi-signature input analysis with `AddressClusterer`.
- **Wallet Tracking** — Track balances, transaction histories, and wallet-level activity with `WalletTracker`.
- **Transaction Pattern Detection** — Detect suspicious patterns like round amounts, peeling chains, and dusting transactions via `PatternDetector`.
- **Consensus Attack Detection** — `SecurityScanner` detects double-spend races, timestamp manipulation (clock rollback and far-future blocks), weak proof-of-work (hash below target), and replay attacks.
- **Planted-Attack Fixtures** — `build_fixtures()` creates a controlled ledger with planted attacks for reproducible validation and demos.
- **Offline-First Analysis** — Fully self-contained with no external network dependencies for safe educational use.

## Quickstart

### Prerequisites

- Python 3.7+

### Setup

```bash
git clone https://github.com/5h4d0wn1k/c5-blockchain
cd c5-blockchain
```

### Usage

Run the offline demo with planted fixtures:

```bash
python blockchain_analyzer.py demo
```

Scan for consensus attacks using built-in fixtures:

```bash
python blockchain_analyzer.py scan
```

Scan with custom reference timestamp for future-block detection:

```bash
python blockchain_analyzer.py scan --reference-time 1700000000
```

Output machine-readable JSON:

```bash
python blockchain_analyzer.py demo --json
python blockchain_analyzer.py demo --output report.json
```

## Project Structure

- `blockchain_analyzer.py` — Core implementation of Transaction, Block, clustering, wallet tracking, pattern detection, SecurityScanner, and CLI.
- `ETHICS.md`, `SCOPE.md` — Educational use guidelines and authorized scope.
- `SECURITY.md` — Security reporting information.

## Documentation

- [ETHICS.md](ETHICS.md) — Educational purpose and authorized use only.
- [SCOPE.md](SCOPE.md) — Scope of authorized testing and research.
- [SECURITY.md](SECURITY.md) — Security policy and reporting.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution guidelines.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Code of conduct.

## Contributing

Contributions are welcome for educational and authorized research purposes. Please review [CONTRIBUTING.md](CONTRIBUTING.md) and adhere to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
