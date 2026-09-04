#!/usr/bin/env python3
"""Blockchain Analyzer - Transaction parsing, address clustering, wallet tracking."""

import struct
import hashlib
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class Transaction:
    """Parse and represent a blockchain transaction using struct."""

    MAGIC_BYTES = b'\xf9\xbe\xb4\xd9'
    TX_VERSION_SIZE = 4
    TX_INPUT_SIZE = 36  # prev_hash(32) + prev_idx(4)
    TX_OUTPUT_SIZE = 8  # value(8)
    HASH_SIZE = 32
    ADDRESS_SIZE = 20

    def __init__(self, raw_data: bytes = None):
        self.version = 0
        self.inputs: List[Dict] = []
        self.outputs: List[Dict] = []
        self.lock_time = 0
        self.tx_hash = ""
        self.timestamp = None
        if raw_data:
            self.parse(raw_data)

    def parse(self, raw_data: bytes) -> None:
        """Parse raw transaction bytes using struct."""
        offset = 0

        if len(raw_data) < 6:
            raise ValueError("Transaction data too short")

        self.version = struct.unpack_from('<I', raw_data, offset)[0]
        offset += self.TX_VERSION_SIZE

        in_count = struct.unpack_from('<B', raw_data, offset)[0]
        offset += 1

        for _ in range(in_count):
            prev_hash = raw_data[offset:offset + self.HASH_SIZE].hex()
            offset += self.HASH_SIZE
            prev_idx = struct.unpack_from('<I', raw_data, offset)[0]
            offset += 4
            script_len = struct.unpack_from('<B', raw_data, offset)[0]
            offset += 1
            script = raw_data[offset:offset + script_len].hex()
            offset += script_len
            self.inputs.append({
                'prev_hash': prev_hash,
                'prev_idx': prev_idx,
                'script': script,
                'sequence': struct.unpack_from('<I', raw_data, offset)[0]
            })
            offset += 4

        out_count = struct.unpack_from('<B', raw_data, offset)[0]
        offset += 1

        for _ in range(out_count):
            value = struct.unpack_from('<Q', raw_data, offset)[0]
            offset += self.TX_OUTPUT_SIZE
            script_len = struct.unpack_from('<B', raw_data, offset)[0]
            offset += 1
            script = raw_data[offset:offset + script_len].hex()
            offset += script_len
            self.outputs.append({
                'value': value / 1e8,
                'script': script,
                'address': self._extract_address(script)
            })

        self.lock_time = struct.unpack_from('<I', raw_data, offset)[0]
        self.tx_hash = hashlib.sha256(
            hashlib.sha256(raw_data).digest()
        ).digest()[::-1].hex()
        self.timestamp = datetime.now()

    def create(self, version: int, inputs: List[Dict],
               outputs: List[Dict], lock_time: int = 0) -> bytes:
        """Create raw transaction bytes from parameters."""
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lock_time = lock_time

        raw = struct.pack('<I', version)
        raw += struct.pack('<B', len(inputs))
        for inp in inputs:
            raw += bytes.fromhex(inp['prev_hash'])
            raw += struct.pack('<I', inp['prev_idx'])
            script = bytes.fromhex(inp.get('script', ''))
            raw += struct.pack('<B', len(script))
            raw += script
            raw += struct.pack('<I', inp.get('sequence', 0xffffffff))
        raw += struct.pack('<B', len(outputs))
        for out in outputs:
            raw += struct.pack('<Q', int(out['value'] * 1e8))
            script = bytes.fromhex(out.get('script', ''))
            raw += struct.pack('<B', len(script))
            raw += script
        raw += struct.pack('<I', lock_time)

        self.tx_hash = hashlib.sha256(
            hashlib.sha256(raw).digest()
        ).digest()[::-1].hex()
        return raw

    def _extract_address(self, script_hex: str) -> str:
        """Extract address from output script."""
        if script_hex.startswith('76a914') and script_hex.endswith('88ac'):
            return script_hex[6:46]
        if script_hex.startswith('a914') and script_hex.endswith('87'):
            return script_hex[4:-2]
        return script_hex[:40] if len(script_hex) >= 40 else script_hex

    def to_dict(self) -> Dict:
        return {
            'tx_hash': self.tx_hash,
            'version': self.version,
            'inputs': self.inputs,
            'outputs': self.outputs,
            'lock_time': self.lock_time,
            'timestamp': str(self.timestamp)
        }


class Block:
    """Parse and represent a blockchain block."""

    HEADER_SIZE = 80

    def __init__(self, raw_data: bytes = None):
        self.version = 0
        self.prev_hash = ""
        self.merkle_root = ""
        self.timestamp = 0
        self.bits = 0
        self.nonce = 0
        self.transactions: List[Transaction] = []
        self.block_hash = ""
        if raw_data:
            self.parse(raw_data)

    def parse(self, raw_data: bytes) -> None:
        """Parse raw block bytes."""
        self.version = struct.unpack_from('<I', raw_data, 0)[0]
        self.prev_hash = raw_data[4:36].hex()
        self.merkle_root = raw_data[36:68].hex()
        self.timestamp = struct.unpack_from('<I', raw_data, 68)[0]
        self.bits = struct.unpack_from('<I', raw_data, 72)[0]
        self.nonce = struct.unpack_from('<I', raw_data, 76)[0]
        self.block_hash = hashlib.sha256(
            hashlib.sha256(raw_data[:self.HEADER_SIZE]).digest()
        ).digest()[::-1].hex()

    def compute_merkle_root(self) -> str:
        """Compute merkle root from transactions."""
        if not self.transactions:
            return "0" * 64
        hashes = [bytes.fromhex(tx.tx_hash) for tx in self.transactions]
        while len(hashes) > 1:
            if len(hashes) % 2:
                hashes.append(hashes[-1])
            hashes = [
                hashlib.sha256(
                    hashlib.sha256(hashes[i] + hashes[i + 1]).digest()
                ).digest()
                for i in range(0, len(hashes), 2)
            ]
        return hashes[0].hex()

    def to_dict(self) -> Dict:
        return {
            'block_hash': self.block_hash,
            'version': self.version,
            'prev_hash': self.prev_hash,
            'merkle_root': self.merkle_root,
            'timestamp': self.timestamp,
            'bits': self.bits,
            'nonce': self.nonce,
            'tx_count': len(self.transactions)
        }


class AddressClusterer:
    """Cluster addresses belonging to the same entity."""

    def __init__(self):
        self.address_to_cluster: Dict[str, int] = {}
        self.cluster_to_addresses: Dict[int, Set[str]] = defaultdict(set)
        self.cluster_meta: Dict[int, Dict] = {}
        self._next_cluster = 0
        self.link_graph: Dict[str, Set[str]] = defaultdict(set)

    def add_link(self, addr1: str, addr2: str) -> None:
        """Link two addresses as belonging to same entity."""
        self.link_graph[addr1].add(addr2)
        self.link_graph[addr2].add(addr1)
        if addr1 in self.address_to_cluster and addr2 in self.address_to_cluster:
            c1 = self.address_to_cluster[addr1]
            c2 = self.address_to_cluster[addr2]
            if c1 != c2:
                self._merge_clusters(c1, c2)
        else:
            cluster = self._get_or_create_cluster(addr1)
            self._add_to_cluster(cluster, addr2)

    def add_transaction_inputs(self, addresses: List[str]) -> None:
        """Cluster addresses used as inputs in same transaction."""
        if len(addresses) < 2:
            return
        primary = addresses[0]
        for addr in addresses[1:]:
            self.add_link(primary, addr)

    def _get_or_create_cluster(self, addr: str) -> int:
        if addr in self.address_to_cluster:
            return self.address_to_cluster[addr]
        cluster = self._next_cluster
        self._next_cluster += 1
        self._add_to_cluster(cluster, addr)
        return cluster

    def _add_to_cluster(self, cluster: int, addr: str) -> None:
        self.address_to_cluster[addr] = cluster
        self.cluster_to_addresses[cluster].add(addr)

    def _merge_clusters(self, c1: int, c2: int) -> None:
        addrs = self.cluster_to_addresses.pop(c2, set())
        for addr in addrs:
            self.address_to_cluster[addr] = c1
            self.cluster_to_addresses[c1].add(addr)

    def get_cluster(self, addr: str) -> Optional[int]:
        return self.address_to_cluster.get(addr)

    def get_addresses(self, cluster_id: int) -> Set[str]:
        return self.cluster_to_addresses.get(cluster_id, set())

    def set_cluster_meta(self, cluster_id: int, label: str, **kwargs) -> None:
        self.cluster_meta[cluster_id] = {'label': label, **kwargs}

    def summary(self) -> Dict:
        return {
            'total_clusters': len(self.cluster_to_addresses),
            'total_addresses': len(self.address_to_cluster),
            'clusters': {
                cid: {
                    'addresses': list(addrs),
                    'meta': self.cluster_meta.get(cid, {})
                }
                for cid, addrs in self.cluster_to_addresses.items()
            }
        }


class WalletTracker:
    """Track wallet balances across transactions."""

    def __init__(self):
        self.balances: Dict[str, float] = defaultdict(float)
        self.address_history: Dict[str, List[Dict]] = defaultdict(list)
        self.tx_log: List[Dict] = []
        self.total_received: Dict[str, float] = defaultdict(float)
        self.total_sent: Dict[str, float] = defaultdict(float)

    def process_transaction(self, tx: Transaction) -> Dict:
        """Process a transaction and update balances."""
        spent = defaultdict(float)
        received = defaultdict(float)

        for inp in tx.inputs:
            spent[inp.get('address', '')] += 0

        for out in tx.outputs:
            addr = out.get('address', '')
            val = out['value']
            self.balances[addr] += val
            received[addr] += val
            self.total_received[addr] += val
            self.address_history[addr].append({
                'tx_hash': tx.tx_hash,
                'type': 'received',
                'amount': val,
                'timestamp': str(tx.timestamp)
            })

        record = {
            'tx_hash': tx.tx_hash,
            'received': dict(received),
            'spent': dict(spent),
            'total_value': sum(o['value'] for o in tx.outputs),
            'timestamp': str(tx.timestamp)
        }
        self.tx_log.append(record)
        return record

    def get_balance(self, address: str) -> float:
        return self.balances.get(address, 0.0)

    def get_history(self, address: str) -> List[Dict]:
        return self.address_history.get(address, [])

    def get_top_wallets(self, n: int = 10) -> List[Tuple[str, float]]:
        sorted_wallets = sorted(
            self.balances.items(), key=lambda x: x[1], reverse=True
        )
        return sorted_wallets[:n]

    def summary(self) -> Dict:
        return {
            'total_addresses': len(self.balances),
            'total_balance': sum(self.balances.values()),
            'transactions_processed': len(self.tx_log),
            'top_wallets': [
                {'address': a, 'balance': b}
                for a, b in self.get_top_wallets(5)
            ]
        }


class PatternDetector:
    """Detect suspicious patterns in blockchain transactions."""

    def __init__(self):
        self.patterns: List[Dict] = []
        self.address_frequency: Dict[str, int] = defaultdict(int)
        self.round_amount_txs: List[Dict] = []
        self.quick_successions: List[Dict] = []
        self.peeling_chains: List[Dict] = []

    def analyze_transaction(self, tx: Transaction) -> List[Dict]:
        """Analyze a transaction for patterns."""
        detected = []

        for out in tx.outputs:
            addr = out.get('address', '')
            self.address_frequency[addr] += 1

        round_amounts = self._detect_round_amounts(tx)
        if round_amounts:
            detected.extend(round_amounts)

        return detected

    def detect_peeling_chain(self, transactions: List[Transaction]) -> List[Dict]:
        """Detect peeling chain pattern."""
        chains = []
        for tx in transactions:
            if len(tx.inputs) == 1 and len(tx.outputs) == 2:
                remainder = max(o['value'] for o in tx.outputs)
                small = min(o['value'] for o in tx.outputs)
                if remainder > small * 10:
                    chains.append({
                        'tx_hash': tx.tx_hash,
                        'type': 'peeling_chain',
                        'remainder': remainder,
                        'peeled': small
                    })
        self.peeling_chains.extend(chains)
        return chains

    def detect_mixing_patterns(self, transactions: List[Transaction]) -> List[Dict]:
        """Detect mixing patterns."""
        patterns = []
        addr_counts = defaultdict(int)
        for tx in transactions:
            for inp in tx.inputs:
                addr_counts[inp.get('address', '')] += 1
            for out in tx.outputs:
                addr_counts[out.get('address', '')] += 1

        for addr, count in addr_counts.items():
            if count > 5:
                patterns.append({
                    'address': addr,
                    'type': 'high_activity',
                    'count': count
                })
        return patterns

    def detect_dusting(self, tx: Transaction,
                       threshold: float = 0.00001) -> List[Dict]:
        """Detect dust transactions."""
        dust = []
        for out in tx.outputs:
            if 0 < out['value'] < threshold:
                dust.append({
                    'tx_hash': tx.tx_hash,
                    'type': 'dust',
                    'amount': out['value'],
                    'address': out.get('address', '')
                })
        return dust

    def _detect_round_amounts(self, tx: Transaction) -> List[Dict]:
        """Detect round amount transactions."""
        results = []
        for out in tx.outputs:
            val = out['value']
            if val > 0 and val == int(val) and val >= 1.0:
                results.append({
                    'tx_hash': tx.tx_hash,
                    'type': 'round_amount',
                    'amount': val,
                    'address': out.get('address', '')
                })
                self.round_amount_txs.append(results[-1])
        return results

    def get_statistics(self) -> Dict:
        return {
            'total_patterns': len(self.patterns),
            'round_amount_txs': len(self.round_amount_txs),
            'quick_successions': len(self.quick_successions),
            'peeling_chains': len(self.peeling_chains),
            'unique_addresses': len(self.address_frequency),
            'top_addresses': sorted(
                self.address_frequency.items(),
                key=lambda x: x[1], reverse=True
            )[:5]
        }


class BlockchainAnalyzer:
    """Main blockchain analyzer combining all components."""

    def __init__(self):
        self.clusterer = AddressClusterer()
        self.tracker = WalletTracker()
        self.detector = PatternDetector()
        self.blocks: List[Block] = []
        self.transactions: List[Transaction] = []

    def add_block(self, block: Block) -> None:
        self.blocks.append(block)
        for tx in block.transactions:
            self.add_transaction(tx)

    def add_transaction(self, tx: Transaction) -> None:
        self.transactions.append(tx)
        self.tracker.process_transaction(tx)
        self.detector.analyze_transaction(tx)

        input_addrs = [i.get('address', '') for i in tx.inputs if i.get('address')]
        self.clusterer.add_transaction_inputs(input_addrs)

    def analyze(self) -> Dict:
        return {
            'blocks': len(self.blocks),
            'transactions': len(self.transactions),
            'clusters': self.clusterer.summary(),
            'wallets': self.tracker.summary(),
            'patterns': self.detector.get_statistics()
        }

    def create_sample_transaction(self) -> Transaction:
        """Create a sample transaction for testing."""
        raw = struct.pack('<I', 2)
        raw += struct.pack('<B', 1)
        raw += bytes(32)
        raw += struct.pack('<I', 0)
        raw += struct.pack('<B', 25)
        raw += bytes(25)
        raw += struct.pack('<I', 0xffffffff)
        raw += struct.pack('<B', 1)
        raw += struct.pack('<Q', 5000000000)
        raw += struct.pack('<B', 25)
        raw += bytes(25)
        raw += struct.pack('<I', 0)
        return Transaction(raw)


if __name__ == "__main__":
    print("=== Blockchain Analyzer ===")
    analyzer = BlockchainAnalyzer()
    tx = analyzer.create_sample_transaction()
    analyzer.add_transaction(tx)
    result = analyzer.analyze()
    print(json.dumps(result, indent=2))
    print("\nTransaction:", tx.tx_hash)
