# C5 — Blockchain Analyzer

A fully **offline**, edu-only blockchain forensics toolkit: transaction/block
parsing, address clustering, wallet tracking, pattern detection, and a
consensus-attack scanner that proves its detections against planted fixtures.

## Overview

Parses binary transactions and block headers with the standard library `struct`
module, then layers on top:

- address clustering (multi-signature input analysis),
- wallet balance + history tracking,
- transaction-pattern detection (round amounts, peeling chains, dusting),
- a `SecurityScanner` that detects **double-spend races**, **timestamp
  manipulation** (clock rollback and far-future blocks), **weak proof-of-work**
  (header hash not meeting its `bits` target), and **replay attacks**
  (identical tx hash accepted twice).

Offline fixtures (`build_fixtures()`) build a small ledger with every attack
planted in it; `demo`, `scan` and the unit tests prove the detector finds all
of them.

## Requirements

Python 3.7+, standard library only (struct, hashlib, argparse, json,
unittest). No network access, no third-party packages.

## Usage

```bash
# Offline demo: analyze the planted-attack ledger, print findings (exit 0)
python3 blockchain_analyzer.py demo

# Scan the fixture ledger and print findings to a JSON report
python3 blockchain_analyzer.py scan
python3 blockchain_analyzer.py scan --json
python3 blockchain_analyzer.py scan --output reports/scan.json

# In code
from blockchain_analyzer import BlockchainAnalyzer, build_fixtures
analyzer = BlockchainAnalyzer()
blocks, txs = build_fixtures()
for b in blocks:
    analyzer.add_block(b)
print(analyzer.analyze())
```

## How the security scanner works

- **Double-spend race**: indexes every transaction input by
  `(prev_hash, prev_idx)`; if two *distinct* transactions spend the same
  output, both are reported.
- **Timestamp manipulation**: a block whose timestamp is earlier than its
  parent (clock rollback, high severity) or more than 2 hours ahead of the
  ledger median time (future block, medium severity).
- **Weak proof-of-work**: decodes the Bitcoin compact `bits` field into a
  256-bit target and compares it against the double-SHA-256 header hash. A
  header hash greater than its target is an invalid/weak block.
- **Replay attack**: counts transactions by tx hash; a hash appearing more
  than once is a replay.

The fixture ledger mines 3 blocks against a trivial difficulty (~2^252) so
they *validate*, and deliberately plants the attacks above (mine-blocking is
fast on a laptop).

## Live Lab Test Plan

Run in any Python 3 environment (no network, no third-party deps):

1. `python3 -m py_compile blockchain_analyzer.py` — syntax check, exit 0.
2. `python3 blockchain_analyzer.py demo` — analyzes planted-attack fixtures,
   prints findings grouped by type, exit 0.
3. `python3 blockchain_analyzer.py scan --output reports/scan.json` — writes a
   JSON report with all findings and the summary, exit 0.
4. `python3 -m unittest discover -s tests` — 26 unit + subprocess tests, all
   pass, including a clean-ledger control proving no false positives.
5. `python3 blockchain_analyzer.py demo --json` — machine-readable output.

## Metrics

| Detector                 | Finding type                  | Severity | Proven in fixtures/tests |
|--------------------------|-------------------------------|----------|--------------------------|
| Double spend             | `double_spend_race`           | high     | yes (1)                  |
| Clock rollback           | `timestamp_manipulation`      | high     | yes                       |
| Future block             | `timestamp_manipulation`      | medium   | yes                       |
| Weak PoW                 | `weak_proof_of_work`          | high     | yes (1)                  |
| Replay                   | `replay_attack`               | high     | yes (1)                  |
| Low difficulty (info)    | `low_difficulty`              | low      | yes (3 mined blocks)     |

Fixture ledger: 4 blocks, 5 transactions, 8 findings. Clean-ledger control
reports zero attack findings. Tests: 26 passing.

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT