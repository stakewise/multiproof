from dataclasses import asdict, dataclass
from functools import cmp_to_key
from typing import Generic, TypeVar

from eth_abi import encode as abi_encode
from eth_typing import HexStr

from multiproof.bytes import compare_bytes, equals_bytes, hex_to_bytes, to_hex
from multiproof.core import (CoreMultiProof, get_multi_proof, get_proof,
                             is_valid_merkle_tree, left_child_index,
                             make_merkle_tree, process_multi_proof,
                             process_proof, right_child_index)
from multiproof.utils import check_bounds, keccak

T = TypeVar('T')


@dataclass
class LeafValue(Generic[T]):
    value: T
    tree_index: int


@dataclass
class MultiProof(Generic[T]):
    """
    User-friendly version of multiproof, compare with CoreMultiProof
    """
    leaves: list[T]
    proof: list[HexStr]
    proof_flags: list[bool]


@dataclass
class StandardMerkleTreeData(Generic[T]):
    tree: list[HexStr]
    values: list[LeafValue[T]]
    leaf_encoding: list[str]
    format: str = 'standard-v1'


@dataclass
class HashedValue(Generic[T]):
    value: T
    index: int
    hash: bytes


def standard_leaf_hash(values: T, types: list[str]) -> bytes:
    return keccak(keccak(abi_encode(types, values)))  # type: ignore


class StandardMerkleTree(Generic[T]):
    _hash_lookup: dict[HexStr, int]
    tree: list[bytes]
    values: list[LeafValue[T]]
    leaf_encoding: list[str]

    def __init__(self, tree: list[bytes], values: list[LeafValue[T]], leaf_encoding: list[str]):
        self.tree = tree
        self.values = values
        self.leaf_encoding = leaf_encoding
        self._hash_lookup = {}
        for index, leaf_value in enumerate(values):
            self._hash_lookup[to_hex(standard_leaf_hash(leaf_value.value, leaf_encoding))] = index

    @staticmethod
    def of(
        values: list[T], leaf_encoding: list[str], sort_leaves: bool = True
    ) -> 'StandardMerkleTree[T]':
        hashed_values: list[HashedValue[T]] = []
        for index, value in enumerate(values):
            hashed_values.append(
                HashedValue(value=value, index=index, hash=standard_leaf_hash(value, leaf_encoding))
            )
        if sort_leaves:
            hashed_values = sorted(
                hashed_values,
                key=cmp_to_key(lambda a, b: compare_bytes(a.hash, b.hash)),  # type: ignore
            )

        tree = make_merkle_tree([x.hash for x in hashed_values])

        indexed_values = [LeafValue(value=v, tree_index=0) for v in values]

        for leaf_index, hashed_value in enumerate(hashed_values):
            indexed_values[hashed_value.index].tree_index = len(tree) - leaf_index - 1

        return StandardMerkleTree(tree, indexed_values, leaf_encoding)

    @staticmethod
    def load(data: StandardMerkleTreeData[T]) -> 'StandardMerkleTree[T]':
        if data.format != 'standard-v1':
            raise ValueError(f"Unknown format '{data.format}'")
        return StandardMerkleTree(
            [hex_to_bytes(x) for x in data.tree],
            data.values,
            data.leaf_encoding,
        )

    @staticmethod
    def verify(root: HexStr, leaf_encoding: list[str], leaf_value: T, proof: list[HexStr]) -> bool:
        leaf_hash = standard_leaf_hash(leaf_value, leaf_encoding)
        implied_root = process_proof(leaf_hash, [hex_to_bytes(x) for x in proof])
        return equals_bytes(implied_root, hex_to_bytes(root))

    @staticmethod
    def verify_multi_proof(root: HexStr, leaf_encoding: list[str], multiproof: MultiProof) -> bool:
        leaf_hashes = [standard_leaf_hash(value, leaf_encoding) for value in multiproof.leaves]
        proof_bytes = [hex_to_bytes(x) for x in multiproof.proof]
        implied_root = process_multi_proof(
            multiproof=CoreMultiProof(
                leaves=leaf_hashes,
                proof=proof_bytes,
                proof_flags=multiproof.proof_flags,
            )
        )

        return equals_bytes(implied_root, hex_to_bytes(root))

    def dump(self) -> StandardMerkleTreeData[T]:
        return StandardMerkleTreeData(
            format='standard-v1',
            tree=[to_hex(v) for v in self.tree],
            values=self.values,
            leaf_encoding=self.leaf_encoding,
        )

    def to_json(self) -> dict:
        return asdict(self.dump())

    @staticmethod
    def from_json(data: dict) -> 'StandardMerkleTree[T]':
        tree_data = StandardMerkleTreeData(
            tree=data['tree'],
            values=[LeafValue(**item) for item in data['values']],
            leaf_encoding=data['leaf_encoding'],
            format=data.get('format', 'standard-v1'),
        )
        return StandardMerkleTree.load(tree_data)

    @property
    def root(self) -> HexStr:
        return to_hex(self.tree[0])

    def validate(self) -> None:
        for i in range(len(self.values)):
            self._validate_value(i)

        if not is_valid_merkle_tree(self.tree):
            raise ValueError("Merkle tree is invalid")

    def leaf_hash(self, leaf: T) -> HexStr:
        return to_hex(standard_leaf_hash(leaf, self.leaf_encoding))

    def leaf_lookup(self, leaf: T) -> int:
        v = self._hash_lookup[self.leaf_hash(leaf)]
        if v is None:
            raise ValueError("Leaf is not in tree")
        return v

    def get_proof(self, leaf: T | int) -> list[HexStr]:
        # input validity
        value_index: int = leaf  # type: ignore
        if not isinstance(leaf, int):
            value_index = self.leaf_lookup(leaf)
        self._validate_value(value_index)

        # rebuild tree index and generate proof
        tree_index = self.values[value_index].tree_index
        proof = get_proof(self.tree, tree_index)

        # check proof
        thee_hash = self.tree[tree_index]
        implied_root = process_proof(thee_hash, proof)

        if not equals_bytes(implied_root, self.tree[0]):
            raise ValueError("Unable to prove value")

        return [to_hex(p) for p in proof]

    def get_multi_proof(self, leaves: list[int] | list[T]) -> MultiProof:
        # input validity
        value_indices: list[int] = []
        for leaf in leaves:
            if isinstance(leaf, int):
                value_indices.append(leaf)
            else:
                value_indices.append(self.leaf_lookup(leaf))

        for value in value_indices:
            self._validate_value(value)

        # rebuild tree indices and generate proof
        indices = [self.values[i].tree_index for i in value_indices]
        proof = get_multi_proof(self.tree, indices)

        # check proof
        implied_root = process_multi_proof(proof)
        if not equals_bytes(implied_root, self.tree[0]):
            raise ValueError('Unable to prove values')

        # return multiproof in hex format
        return MultiProof(
            leaves=[self.values[self._hash_lookup[to_hex(hash)]].value for hash in proof.leaves],
            proof=[to_hex(x) for x in proof.proof],
            proof_flags=proof.proof_flags,
        )

    def verify_leaf(self, leaf: int, proof: list[HexStr]) -> bool:
        return self._verify_leaf(self._get_leaf_hash(leaf), [hex_to_bytes(p) for p in proof])

    def _verify_leaf(self, leaf_hash: bytes, proof: list[bytes]) -> bool:
        implied_root = process_proof(leaf_hash, proof)
        return equals_bytes(implied_root, self.tree[0])

    def verify_multi_proof_leaf(self, multiproof: MultiProof) -> bool:
        return self._verify_multi_proof_leaf(
            CoreMultiProof(
                leaves=[self._get_leaf_hash(leaf) for leaf in multiproof.leaves],
                proof=[hex_to_bytes(proof) for proof in multiproof.proof],
                proof_flags=multiproof.proof_flags,
            )
        )

    def _verify_multi_proof_leaf(self, multi_proof: CoreMultiProof) -> bool:
        implied_root = process_multi_proof(multi_proof)
        return equals_bytes(implied_root, self.tree[0])

    def _validate_value(self, value_index: int) -> bytes:
        check_bounds(self.values, value_index)
        leaf = self.values[value_index]
        check_bounds(self.tree, leaf.tree_index)
        leaf_hash = standard_leaf_hash(leaf.value, self.leaf_encoding)

        if not equals_bytes(leaf_hash, self.tree[leaf.tree_index]):
            raise ValueError("Merkle tree does not contain the expected value")
        return leaf_hash

    def _get_leaf_hash(self, leaf: int) -> bytes:
        if isinstance(leaf, int):
            return self._validate_value(leaf)
        if isinstance(leaf, LeafValue):
            return standard_leaf_hash(leaf.value, self.leaf_encoding)
        return standard_leaf_hash(leaf, self.leaf_encoding)

    def __str__(self):
        if len(self.tree) == 0:
            raise ValueError("Expected non-zero number of nodes")

        stack: list = [[0, []]]
        lines: list = []

        while len(stack) > 0:
            i, path = stack.pop()
            s = ''

            if len(path):
                s += ''.join([['   ', '│  '][p] for p in path[:-1]]) + ['└─ ', '├─ '][path[-1]]
            s += str(i) + ') ' + to_hex(self.tree[i])[2:]

            lines.append(s)
            if right_child_index(i) < len(self.tree):
                stack.append([right_child_index(i), path + [0]])
                stack.append([left_child_index(i), path + [1]])

        return '\n'.join(lines)
