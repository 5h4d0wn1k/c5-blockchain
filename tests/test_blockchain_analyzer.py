#!/usr/bin/env python3
"""Tests for C5 - Blockchain Analyzer."""

import os
import sys
import struct
import unittest
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from blockchain_analyzer import (
    Transaction, Block, AddressClusterer, WalletTracker, PatternDetector,
    SecurityScanner, BlockchainAnalyzer, make_tx, make_block, mine_block,
    build_fixtures,
)


def _tx(prev_hash, prev_idx, value, version=1):
    return make_tx(prev_hash, prev_idx, value, version=version)


class TestTransaction(unittest.TestCase):
    def test_create_parse_roundtrip(self):
        tx = Transaction()
        raw = tx.create(2, [{'prev_hash': 'aa' * 32, 'prev_idx': 0, 'script': ''}],
                        [{'value': 1.5, 'script': '76a914' + '11' * 20 + '88ac'}])
        parsed = Transaction(raw)
        self.assertEqual(parsed.version, 2)
        self.assertEqual(parsed.inputs[0]['prev_hash'], 'aa' * 32)
        self.assertEqual(parsed.inputs[0]['prev_idx'], 0)
        self.assertEqual(parsed.outputs[0]['value'], 1.5)

    def test_tx_hash_is_double_sha256(self):
        tx = Transaction()
        raw = tx.create(1, [{'prev_hash': 'ab' * 32, 'prev_idx': 1}],
                        [{'value': 2.0, 'script': '76a914' + '22' * 20 + '88ac'}])
        import hashlib
        expected = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
        self.assertEqual(tx.tx_hash, expected)

    def test_extract_p2pkh_address(self):
        tx = Transaction()
        raw = tx.create(1, [{'prev_hash': 'ab' * 32, 'prev_idx': 1}],
                        [{'value': 1.0, 'script': '76a914' + '33' * 20 + '88ac'}])
        parsed = Transaction(raw)
        self.assertEqual(parsed.outputs[0]['address'], '33' * 20)

    def test_identical_bytes_give_identical_hash(self):
        raw = make_tx('11' * 32, 0, 50000000)
        a = make_tx('11' * 32, 0, 50000000)
        self.assertEqual(raw.tx_hash, a.tx_hash)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            Transaction(b'\x01\x02')


class TestBlock(unittest.TestCase):
    def test_header_parse(self):
        block = make_block('33' * 32, 1666000000, 0x1d00ffff, 7)
        self.assertEqual(block.version, 1)
        self.assertEqual(block.prev_hash, '33' * 32)
        self.assertEqual(block.timestamp, 1666000000)
        self.assertEqual(block.bits, 0x1d00ffff)
        self.assertEqual(block.nonce, 7)

    def test_mine_block_meets_target(self):
        block = mine_block('33' * 32, 1666000000, (0x20 << 24) | 0x000fffff)
        scanner = SecurityScanner()
        target = scanner._target_from_bits(block.bits)
        hash_int = int.from_bytes(bytes.fromhex(block.block_hash), 'little')
        self.assertLessEqual(hash_int, target)

    def test_merkle_root_single(self):
        block = make_block('33' * 32, 1666000000, 0x1d00ffff, 1)
        tx = make_tx('11' * 32, 0, 90000000)
        block.transactions = [tx]
        root = block.compute_merkle_root()
        self.assertEqual(len(root), 64)
        self.assertNotEqual(root, '0' * 64)


class TestFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocks, cls.txs = build_fixtures()

    def test_structure(self):
        self.assertEqual(len(self.blocks), 4)
        self.assertEqual(len(self.txs), 5)

    def test_blocks_chain(self):
        for a, b in zip(self.blocks, self.blocks[1:]):
            self.assertEqual(b.prev_hash, a.block_hash)


class TestAddressClusterer(unittest.TestCase):
    def test_clustering(self):
        c = AddressClusterer()
        c.add_transaction_inputs(['A', 'B', 'C'])
        self.assertEqual(c.get_cluster('A'), c.get_cluster('B'))
        self.assertEqual(c.get_cluster('A'), c.get_cluster('C'))

    def test_merge(self):
        c = AddressClusterer()
        c.add_link('A', 'B')
        c.add_link('C', 'D')
        c.add_transaction_inputs(['A', 'C'])
        self.assertEqual(c.get_cluster('A'), c.get_cluster('D'))
        self.assertEqual(c.summary()['total_clusters'], 1)


class TestWalletTracker(unittest.TestCase):
    def test_balance_tracking(self):
        w = WalletTracker()
        tx = Transaction()
        tx.tx_hash = 'f' * 64
        tx.timestamp = None
        tx.inputs = []
        tx.outputs = [{'value': 5.0, 'address': 'addr1'}]
        w.process_transaction(tx)
        self.assertEqual(w.get_balance('addr1'), 5.0)
        self.assertEqual(w.summary()['total_balance'], 5.0)

    def test_top_wallets(self):
        w = WalletTracker()
        for i, val in enumerate([1.0, 2.0, 3.0]):
            tx = Transaction()
            tx.tx_hash = ('%x' % i).rjust(64, 'a')
            tx.timestamp = None
            tx.inputs = []
            tx.outputs = [{'value': val, 'address': 'a%d' % i}]
            w.process_transaction(tx)
        top = w.get_top_wallets(2)
        self.assertEqual([t[0] for t in top], ['a2', 'a1'])


class TestPatternDetector(unittest.TestCase):
    def test_round_amount(self):
        d = PatternDetector()
        tx = Transaction()
        tx.tx_hash = 'e' * 64
        tx.inputs = []
        tx.outputs = [{'value': 10.0, 'address': 'x'}, {'value': 0.3, 'address': 'y'}]
        found = d._detect_round_amounts(tx)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['amount'], 10.0)

    def test_peeling_chain(self):
        d = PatternDetector()
        tx = Transaction()
        tx.tx_hash = 'd' * 64
        tx.inputs = [{'address': 'z'}]
        tx.outputs = [{'value': 100.0, 'address': 'x'}, {'value': 0.01, 'address': 'y'}]
        chains = d.detect_peeling_chain([tx])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]['type'], 'peeling_chain')

    def test_dust(self):
        d = PatternDetector()
        tx = Transaction()
        tx.tx_hash = 'c' * 64
        tx.outputs = [{'value': 0.000001, 'address': 'x'}]
        dust = d.detect_dusting(tx)
        self.assertEqual(len(dust), 1)


class TestSecurityScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocks, cls.txs = build_fixtures()
        cls.scanner = SecurityScanner()
        cls.findings = cls.scanner.scan(cls.blocks, cls.txs)

    def test_double_spend_detected(self):
        types = Counter(f['type'] for f in self.findings)
        self.assertGreaterEqual(types['double_spend_race'], 1)
        ds = next(f for f in self.findings if f['type'] == 'double_spend_race')
        self.assertEqual(ds['severity'], 'high')
        self.assertGreaterEqual(len(ds['conflicting_txs']), 2)

    def test_timestamp_manipulation_detected(self):
        types = Counter(f['type'] for f in self.findings)
        self.assertGreaterEqual(types['timestamp_manipulation'], 2)

    def test_weak_pow_detected(self):
        types = Counter(f['type'] for f in self.findings)
        self.assertGreaterEqual(types['weak_proof_of_work'], 1)

    def test_replay_detected(self):
        types = Counter(f['type'] for f in self.findings)
        self.assertGreaterEqual(types['replay_attack'], 1)

    def test_clean_ledger_has_no_attacks(self):
        scanner = SecurityScanner()
        block = mine_block('33' * 32, 1666000000, (0x20 << 24) | 0x000fffff)
        tx = make_tx('22' * 32, 0, 100000000)
        findings = scanner.scan([block], [tx])
        attack_types = {'double_spend_race', 'timestamp_manipulation',
                        'weak_proof_of_work', 'replay_attack'}
        self.assertFalse(any(f['type'] in attack_types for f in findings))


class TestAnalyzer(unittest.TestCase):
    def test_analyze_structure(self):
        blocks, txs = build_fixtures()
        a = BlockchainAnalyzer()
        for b in blocks:
            a.add_block(b)
        for tx in txs:
            if tx not in a.transactions:
                a.add_transaction(tx)
        result = a.analyze()
        self.assertIn('blocks', result)
        self.assertIn('wallets', result)
        self.assertIn('security', result)
        self.assertEqual(result['blocks'], 4)


class TestCLI(unittest.TestCase):
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    SCRIPT = os.path.join(ROOT, 'blockchain_analyzer.py')

    def _run(self, *args):
        import subprocess
        return subprocess.run([sys.executable, self.SCRIPT] + list(args),
                              capture_output=True, text=True, timeout=120)

    def test_demo_exit_0(self):
        r = self._run('demo')
        self.assertEqual(r.returncode, 0)
        self.assertIn('weak_proof_of_work', r.stdout)

    def test_scan_exit_0(self):
        r = self._run('scan')
        self.assertEqual(r.returncode, 0)
        self.assertIn('Security findings', r.stdout)

    def test_scan_json(self):
        r = self._run('scan', '--json')
        self.assertEqual(r.returncode, 0)
        import json
        data = json.loads(r.stdout)
        self.assertTrue(len(data['findings']) > 0)


if __name__ == '__main__':
    unittest.main()