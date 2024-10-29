import math
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

from multiproof.bytes import compare_bytes, concat_bytes, equals_bytes
from multiproof.utils import keccak


@dataclass
class CoreMultiProof:
    leaves: list[bytes]
    proof: list[bytes]
    proof_flags: list[bool]


def hash_pair(a: bytes, b: bytes) -> bytes:
    if compare_bytes(a, b) < 0:
        return keccak(concat_bytes(a, b))
    # pylint: disable=arguments-out-of-order
    return keccak(concat_bytes(b, a))


def left_child_index(i: int) -> int:
    return 2 * i + 1


def right_child_index(i: int) -> int:
    return 2 * i + 2


def parent_index(i: int) -> int:
    if i > 0:
        return math.floor((i - 1) / 2)
    raise ValueError('Root has no parent')


def sibling_index(i: int) -> int:
    if i > 0:
        return i - (-1) ** (i % 2)
    raise ValueError('Root has no siblings')


def is_tree_node(tree: list[bytes], i: int) -> bool:
    return 0 <= i < len(tree)


def is_internal_node(tree: list[bytes], i: int) -> bool:
    return is_tree_node(tree, left_child_index(i))


def is_leaf_node(tree: list[bytes], i: int) -> bool:
    return is_tree_node(tree, i) and not is_internal_node(tree, i)


def is_valid_merkle_node(node: bytes) -> bool:
    return len(node) == 32


def check_tree_node(tree: list[bytes], i: int) -> None:
    if not is_tree_node(tree, i):
        raise ValueError("Index is not in tree")


def check_internal_node(tree: list[bytes], i: int) -> None:
    if not is_internal_node(tree, i):
        raise ValueError("Index is not an internal tree node")


def check_leaf_node(tree: list[bytes], i: int) -> None:
    if not is_leaf_node(tree, i):
        raise ValueError("Index is not a leaf")


def check_valid_merkle_node(node: bytes) -> None:
    if not is_valid_merkle_node(node):
        raise ValueError("Merkle tree nodes must be byte array of length 32")


def make_merkle_tree(leaves: list[bytes]) -> list[bytes]:
    for leaf in leaves:
        check_valid_merkle_node(leaf)

    if len(leaves) == 0:
        raise ValueError("Expected non-zero number of leaves")

    tree: list[bytes] = [b''] * (2 * len(leaves) - 1)

    for index, leaf in enumerate(leaves):
        tree[len(tree) - 1 - index] = leaf

    for i in range(len(tree) - 1 - len(leaves), -1, -1):
        tree[i] = hash_pair(
            tree[left_child_index(i)],
            tree[right_child_index(i)],
        )
    return tree


def get_proof(tree: list[bytes], index: int) -> list[bytes]:
    check_leaf_node(tree, index)

    proof = []
    while index > 0:
        proof.append(tree[sibling_index(index)])
        index = parent_index(index)

    return proof


def process_proof(leaf: bytes, proof: list[bytes]) -> bytes:
    check_valid_merkle_node(leaf)
    for item in proof:
        check_valid_merkle_node(item)
    result = leaf
    for item in proof:
        result = hash_pair(item, result)
    return result


def get_multi_proof(tree: list[bytes], indices: list[int]) -> CoreMultiProof:
    for index in indices:
        check_leaf_node(tree, index)

    indices = sorted(indices, reverse=True)

    for prev_index, next_index in pairwise(indices):
        if prev_index == next_index:
            raise ValueError("Cannot prove duplicated index")

    stack = indices[:]
    proof = []
    proof_flags = []

    while len(stack) > 0 and stack[0] > 0:
        j = stack.pop(0)  # take from the beginning
        s = sibling_index(j)
        p = parent_index(j)

        if len(stack) and s == stack[0]:
            proof_flags.append(True)
            stack.pop(0)  # consume from the stack
        else:
            proof_flags.append(False)
            proof.append(tree[s])

        stack.append(p)

    if len(indices) == 0:
        proof.append(tree[0])

    return CoreMultiProof(
        leaves=[tree[i] for i in indices],
        proof=proof,
        proof_flags=proof_flags,
    )


def process_multi_proof(multiproof: CoreMultiProof) -> bytes:
    for leaf in multiproof.leaves:
        check_valid_merkle_node(leaf)

    for p in multiproof.proof:
        check_valid_merkle_node(p)

    if len(multiproof.proof) < len([x for x in multiproof.proof_flags if not x]):
        raise ValueError("Invalid multiproof format")

    if len(multiproof.leaves) + len(multiproof.proof) != len(multiproof.proof_flags) + 1:
        raise ValueError("Provided leaves and multiproof are not compatible")

    stack = multiproof.leaves.copy()
    proof = multiproof.proof.copy()

    for flag in multiproof.proof_flags:
        a = stack.pop(0)
        if flag:
            b = stack.pop(0)
        else:
            b = proof.pop(0)

        stack.append(hash_pair(a, b))
    return pop_safe(stack) or proof.pop(0)


def is_valid_merkle_tree(tree: list[bytes]) -> bool:
    for i, node in enumerate(tree):
        if not is_valid_merkle_node(node):
            return False

        l = left_child_index(i)
        r = right_child_index(i)

        if r >= len(tree):
            if l < len(tree):
                return False
        elif not equals_bytes(node, hash_pair(tree[l], tree[r])):
            return False

    return len(tree) > 0


def pop_safe(array: list[Any]) -> Any:
    try:
        return array.pop()
    except IndexError:
        return None
