from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any, Dict, List, Union

from eth_abi import encode as abi_encode
from web3 import Web3

from src.bytes import compare_bytes, equals_bytes, hex_to_bytes, to_hex
from src.core import (MultiProof, get_multi_proof, get_proof,
                      is_valid_merkle_tree, make_merkle_tree,
                      process_multi_proof, process_proof, render_merkle_tree)
from src.utils import check_bounds


@dataclass
class LeafValue:
    value: Any | None
    tree_index: int


@dataclass
class StandardMerkleTreeData:
    tree: List[str]
    values: List[LeafValue]
    leaf_encoding: List[str]
    format: str = 'standard-v1'


@dataclass
class HashedValue:
    value: Any
    index: int
    hash: bytes


def standard_leaf_hash(values: Any, types: List[str]) -> bytes:
    return Web3.keccak(Web3.keccak(abi_encode(types, values)))


class StandardMerkleTree:
    _hash_lookup: Dict[str, int]
    tree: List[bytes]
    values: List[LeafValue]
    leaf_encoding: List[str]

    def __init__(self,
                 tree: List[bytes],
                 values: List[LeafValue],
                 leaf_encoding: List[str]
                 ):
        self.tree = tree
        self.values = values
        self.leaf_encoding = leaf_encoding
        self._hash_lookup = {}
        for index, leaf_value in enumerate(values):
            self._hash_lookup[to_hex(standard_leaf_hash(leaf_value.value, leaf_encoding))] = index

    @staticmethod
    def of(values: List[Any], leaf_encoding: List[str]):
        hashed_values: List[HashedValue] = []
        for index, value in enumerate(values):
            hashed_values.append(
                HashedValue(
                    value=value,
                    index=index,
                    hash=standard_leaf_hash(value, leaf_encoding)
                )
            )
        hashed_values = sorted(
            hashed_values,
            key=cmp_to_key(lambda a, b: compare_bytes(a.hash, b.hash))
        )

        tree = make_merkle_tree([x.hash for x in hashed_values])

        indexed_values = [LeafValue(value=v, tree_index=0) for v in values]

        for leaf_index, hashed_value in enumerate(hashed_values):
            indexed_values[hashed_value.index].tree_index = len(tree) - leaf_index - 1

        return StandardMerkleTree(tree, indexed_values, leaf_encoding)

    @staticmethod
    def load(data: StandardMerkleTreeData):
        if data.format != 'standard-v1':
            raise ValueError(f"Unknown format '{data.format}'")
        return StandardMerkleTree(
            [hex_to_bytes(x) for x in data.tree],
            data.values,
            data.leaf_encoding,
        )

    def dump(self) -> StandardMerkleTreeData:
        return StandardMerkleTreeData(
            format='standard-v1',
            tree=[to_hex(v) for v in self.tree],
            values=self.values,
            leaf_encoding=self.leaf_encoding
        )

    def render(self) -> str:
        return render_merkle_tree(self.tree)

    def root(self) -> str:
        return to_hex(self.tree[0])

    def validate(self) -> None:
        for i in range(len(self.values)):
            self._validate_value(i)

        if not is_valid_merkle_tree(self.tree):
            raise ValueError("Merkle tree is invalid")

    def leaf_hash(self, leaf) -> str:
        return to_hex(standard_leaf_hash(leaf, self.leaf_encoding))

    def leaf_lookup(self, leaf) -> int:
        v = self._hash_lookup[self.leaf_hash(leaf)]
        if v is None:
            raise ValueError("Leaf is not in tree")
        return v

    def get_proof(self, leaf: Union[LeafValue,int]) -> List[str]:
        # input validity

        value_index = leaf
        if not isinstance(leaf, int):
            value_index = self.leaf_lookup(leaf)
        self._validate_value(value_index)

        # rebuild tree index and generate proof
        leaf = self.values[value_index]
        # tree_index = LeafValue(value_index=self.values[value_index])

        proof = get_proof(self.tree, leaf.tree_index)
        # check proof
        thee_hash = self.tree[leaf.tree_index]
        implied_root = process_proof(thee_hash, proof)

        if not equals_bytes(implied_root, self.tree[0]):
            raise ValueError("Unable to prove value")

        return [to_hex(p) for p in proof]

    def get_multi_proof(self, leaves) -> MultiProof:
        # input validity
        value_indices = []
        for leaf in leaves:
            value_index = leaf
            if isinstance(leaf, int):
                value_indices.append(value_index)
            else:
                value_indices.append(self.leaf_lookup(leaf))

        [self._validate_value(x) for x in value_indices]

        # rebuild tree indices and generate proof
        indices = [self.values[i].tree_index for i in value_indices]
        proof = get_multi_proof(self.tree, indices)

        # check proof
        implied_root = process_multi_proof(proof)
        if not equals_bytes(implied_root, self.tree[0]):
            raise ValueError('Unable to prove values')

        # return multiproof in hex format
        return MultiProof(
            leaves=[],  # todo leaves: proof.leaves.map(hash= > this.values[this.hashLookup[hex(hash)]!]!.value),
            proof=[to_hex(x) for x in proof.proof],
            proof_flags=proof.proof_flags,
        )

    def _validate_value(self, value_index: int):
        check_bounds(self.values, value_index)
        leaf: LeafValue = self.values[value_index]
        check_bounds(self.tree, leaf.tree_index)
        leaf_hash = standard_leaf_hash(leaf.value, self.leaf_encoding)

        if not equals_bytes(leaf_hash, self.tree[leaf.tree_index]):
            raise ValueError("Merkle tree does not contain the expected value")


if __name__ == '__main__':
    ZERO_BYTES = bytearray(32)
    ZERO = to_hex(ZERO_BYTES)

    mt = StandardMerkleTree.load(StandardMerkleTreeData(
        tree=[ZERO],
        values=[LeafValue(
            value=[0],
            tree_index=0,
        )],
        leaf_encoding=['uint256'],
    ))
