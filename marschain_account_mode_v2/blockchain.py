import os
import time
import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

from ecdsa import VerifyingKey, SECP256k1

from wallet_ecdsa import address_from_pubkey_bytes, verify_signature

INITIAL_BLOCK_REWARD = 50.0
HALVING_INTERVAL = 210_000

TARGET_BLOCK_TIME = 60
RETARGET_INTERVAL = 50

MAX_TARGET = int("0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
MIN_TARGET = int("0x0000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

DATA_DIR = "data"
CHAIN_FILE = os.path.join(DATA_DIR, "chain.json")

def sha256d(data: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()

@dataclass
class Transaction:
    tx_type: str
    from_address: Optional[str]
    to_address: Optional[str]
    asset: str
    amount: float
    fee: float = 0.0
    pubkey_hex: Optional[str] = None
    signature_hex: Optional[str] = None
    meta: Dict = field(default_factory=dict)

    def core_dict(self):
        return {
            "tx_type": self.tx_type,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "asset": self.asset,
            "amount": self.amount,
            "fee": self.fee,
            "meta": self.meta,
        }

    def to_dict(self):
        d = self.core_dict()
        d["pubkey_hex"] = self.pubkey_hex
        d["signature_hex"] = self.signature_hex
        return d

    def hash_for_signing(self) -> str:
        data = json.dumps(self.core_dict(), sort_keys=True).encode()
        return sha256d(data)

    def full_hash(self) -> str:
        data = json.dumps(self.to_dict(), sort_keys=True).encode()
        return sha256d(data)

@dataclass
class Block:
    height: int
    prev_hash: str
    timestamp: int
    target: int
    nonce: int = 0
    transactions: List[Transaction] = field(default_factory=list)

    def merkle_root(self) -> str:
        if not self.transactions:
            return sha256d(b"")
        hashes = [tx.full_hash() for tx in self.transactions]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            new_hashes = []
            for i in range(0, len(hashes), 2):
                new_hashes.append(sha256d((hashes[i] + hashes[i+1]).encode()))
            hashes = new_hashes
        return hashes[0]

    def header_dict(self):
        return {
            "height": self.height,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "target": str(self.target),
            "nonce": self.nonce,
            "merkle_root": self.merkle_root(),
        }

    def hash(self) -> str:
        return sha256d(json.dumps(self.header_dict(), sort_keys=True).encode())

def block_reward(height: int) -> float:
    halvings = height // HALVING_INTERVAL
    return INITIAL_BLOCK_REWARD / (2 ** halvings)

def serialize_tx(tx: Transaction) -> dict:
    return tx.to_dict()

def deserialize_tx(d: dict) -> Transaction:
    return Transaction(
        tx_type=d.get("tx_type", "TRANSFER"),
        from_address=d.get("from_address"),
        to_address=d.get("to_address"),
        asset=d.get("asset", "MARS"),
        amount=d.get("amount", 0.0),
        fee=d.get("fee", 0.0),
        pubkey_hex=d.get("pubkey_hex"),
        signature_hex=d.get("signature_hex"),
        meta=d.get("meta", {}),
    )

def serialize_block(block: Block) -> dict:
    return {
        "height": block.height,
        "prev_hash": block.prev_hash,
        "timestamp": block.timestamp,
        "target": str(block.target),
        "nonce": block.nonce,
        "transactions": [serialize_tx(tx) for tx in block.transactions],
    }

def deserialize_block(d: dict) -> Block:
    txs = [deserialize_tx(t) for t in d.get("transactions", [])]
    target_raw = d.get("target", str(MAX_TARGET))
    if isinstance(target_raw, str):
        try:
            target_val = int(target_raw, 0)
        except ValueError:
            target_val = int(target_raw, 16)
    else:
        target_val = int(target_raw)
    return Block(
        height=d["height"],
        prev_hash=d["prev_hash"],
        timestamp=d["timestamp"],
        target=target_val,
        nonce=d.get("nonce", 0),
        transactions=txs,
    )

class MarsChain:
    def __init__(self):
        self.mempool: List[Transaction] = []
        self.balances: Dict[str, float] = {}
        if os.path.exists(CHAIN_FILE):
            try:
                with open(CHAIN_FILE, "r") as f:
                    data = json.load(f)
                self.chain = [deserialize_block(b) for b in data]
            except Exception:
                self.chain = [self._create_genesis_block()]
        else:
            self.chain = [self._create_genesis_block()]
            self._save_chain()

        self.next_target = self.last_block.target
        self._recompute_state()

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def _create_genesis_block(self) -> Block:
        genesis_tx = Transaction(
            tx_type="TRANSFER",
            from_address=None,
            to_address="GENESIS",
            asset="MARS",
            amount=0.0,
        )
        return Block(
            height=0,
            prev_hash="0"*64,
            timestamp=int(time.time()),
            target=MAX_TARGET,
            transactions=[genesis_tx],
        )

    def _save_chain(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CHAIN_FILE, "w") as f:
            json.dump([serialize_block(b) for b in self.chain], f, indent=2)

    def _recompute_state(self):
        self.balances = {}
        for block in self.chain:
            for tx in block.transactions:
                self._apply_tx_to_state(tx, check_sig=False, check_balance=False)

    def _apply_tx_to_state(self, tx: Transaction, check_sig: bool = True, check_balance: bool = True) -> bool:
        if tx.from_address is None:
            if not tx.to_address:
                return False
            bal = self.balances.get(tx.to_address, 0.0)
            self.balances[tx.to_address] = bal + tx.amount
            return True

        if tx.amount <= 0:
            return False

        if check_sig:
            if not tx.pubkey_hex or not tx.signature_hex:
                return False
            msg_hash = tx.hash_for_signing()
            if not verify_signature(tx.pubkey_hex, msg_hash, tx.signature_hex):
                return False
            try:
                vk = VerifyingKey.from_string(bytes.fromhex(tx.pubkey_hex), curve=SECP256k1)
                addr = address_from_pubkey_bytes(vk.to_string())
                if addr != tx.from_address:
                    return False
            except Exception:
                return False

        from_bal = self.balances.get(tx.from_address, 0.0)
        needed = tx.amount + tx.fee
        if check_balance and from_bal < needed:
            return False

        self.balances[tx.from_address] = from_bal - needed
        self.balances[tx.to_address] = self.balances.get(tx.to_address, 0.0) + tx.amount
        return True

    def get_balance(self, address: str) -> float:
        return self.balances.get(address, 0.0)

    def validate_transaction(self, tx: Transaction) -> bool:
        if tx.from_address is None:
            return False
        if not tx.from_address or not tx.to_address:
            return False
        if tx.amount <= 0:
            return False
        if not tx.pubkey_hex or not tx.signature_hex:
            return False

        msg_hash = tx.hash_for_signing()
        if not verify_signature(tx.pubkey_hex, msg_hash, tx.signature_hex):
            return False

        try:
            vk = VerifyingKey.from_string(bytes.fromhex(tx.pubkey_hex), curve=SECP256k1)
            addr = address_from_pubkey_bytes(vk.to_string())
            if addr != tx.from_address:
                return False
        except Exception:
            return False

        if self.get_balance(tx.from_address) < tx.amount + tx.fee:
            return False

        return True

    def add_transaction(self, tx: Transaction) -> bool:
        if not self.validate_transaction(tx):
            return False
        self.mempool.append(tx)
        return True

    def _retarget_if_needed(self, new_block: Block):
        height = new_block.height
        if height == 0:
            self.next_target = MAX_TARGET
            return
        if height % RETARGET_INTERVAL != 0:
            self.next_target = new_block.target
            return
        if height < RETARGET_INTERVAL:
            self.next_target = new_block.target
            return

        last_block = new_block
        first_index = len(self.chain) - RETARGET_INTERVAL
        if first_index < 0:
            self.next_target = new_block.target
            return
        first_block = self.chain[first_index]

        actual_timespan = last_block.timestamp - first_block.timestamp
        expected_timespan = RETARGET_INTERVAL * TARGET_BLOCK_TIME

        min_ts = expected_timespan // 4
        max_ts = expected_timespan * 4
        if actual_timespan < min_ts:
            actual_ts = min_ts
        elif actual_timespan > max_ts:
            actual_ts = max_ts
        else:
            actual_ts = actual_timespan

        old_target = int(last_block.target)
        new_target = int(old_target * actual_ts / expected_timespan)

        if new_target > MAX_TARGET:
            new_target = MAX_TARGET
        if new_target < MIN_TARGET:
            new_target = MIN_TARGET

        self.next_target = new_target

    def mine_block_step(self, miner_address: str, max_tries: int = 50000) -> Tuple[Optional[Block], int]:
        height = self.last_block.height + 1
        prev_hash = self.last_block.hash()
        target = self.next_target

        reward = block_reward(height)
        coinbase = Transaction(
            tx_type="TRANSFER",
            from_address=None,
            to_address=miner_address,
            asset="MARS",
            amount=reward,
        )
        txs = [coinbase] + self.mempool
        block = Block(
            height=height,
            prev_hash=prev_hash,
            timestamp=int(time.time()),
            target=target,
            nonce=0,
            transactions=txs,
        )

        tries = 0
        while tries < max_tries:
            h = block.hash()
            if int(h, 16) < block.target:
                self.chain.append(block)
                self._recompute_state()
                self.mempool = []
                self._retarget_if_needed(block)
                self._save_chain()
                return block, tries + 1

            block.nonce += 1
            tries += 1

        return None, tries
