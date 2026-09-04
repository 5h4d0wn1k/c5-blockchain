# C5 — Blockchain Analyzer

Transaction parsing, address clustering, wallet balance tracking, and pattern detection tool.

## Overview

This project implements a blockchain analysis toolkit that:
- Parses raw blockchain transactions using struct
- Clusters addresses belonging to the same entity
- Tracks wallet balances across transactions
- Detects suspicious patterns (round amounts, peeling chains, dusting)

## Features

- **Transaction parsing**: Binary transaction parsing with struct
- **Address clustering**: Identify wallets using multiple addresses
- **Wallet tracking**: Monitor balances and transaction history
- **Pattern detection**: Round amounts, peeling chains, mixing patterns
- **Block parsing**: Block header and merkle root computation

## Installation

```bash
# No external dependencies required
# Uses only Python standard library
```

## Usage

```bash
# Run the analyzer
python3 blockchain_analyzer.py

# Use in code
from blockchain_analyzer import BlockchainAnalyzer, Transaction

analyzer = BlockchainAnalyzer()
tx = analyzer.create_sample_transaction()
analyzer.add_transaction(tx)
print(analyzer.analyze())
```

## Example Output

```
=== Blockchain Analyzer ===
{
  "blocks": 0,
  "transactions": 1,
  "clusters": {
    "total_clusters": 0,
    "total_addresses": 0,
    "clusters": {}
  },
  "wallets": {
    "total_addresses": 1,
    "total_balance": 50.0,
    "transactions_processed": 1,
    "top_wallets": []
  },
  "patterns": {
    "total_patterns": 0,
    "round_amount_txs": 0,
    "quick_successions": 0,
    "peeling_chains": 0,
    "unique_addresses": 1,
    "top_addresses": []
  }
}

Transaction: <hash>
```

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
