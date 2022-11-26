import math
from dataclasses import dataclass
from typing import Any, List

from web3 import Web3

from multiproof.bytes import compare_bytes, concat_bytes, equals_bytes


@dataclass
class MultiProof:
    leaves: List[Any]
    proof: List[Any]
    proof_flags: List[bool]


def hash_pair(a: bytes, b: bytes) -> bytes:
    if compare_bytes(a, b) < 0:
        return Web3.keccak(concat_bytes(a, b))
    # pylint: disable=arguments-out-of-order
    return Web3.keccak(concat_bytes(b, a))


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


def is_tree_node(tree: List[Any], i: int) -> bool:
    return 0 <= i < len(tree)


def is_internal_node(tree: List[Any], i: int) -> bool:
    return is_tree_node(tree, left_child_index(i))


def is_leaf_node(tree: List[Any], i: int) -> bool:
    return is_tree_node(tree, i) and not is_internal_node(tree, i)


def is_valid_merkle_node(node: bytes) -> bool:
    return len(node) == 32


def check_tree_node(tree: List[Any], i: int) -> None:
    if not is_tree_node(tree, i):
        raise ValueError("Index is not in tree")


def check_internal_node(tree: List[Any], i: int) -> None:
    if not is_internal_node(tree, i):
        raise ValueError("Index is not an internal tree node")


def check_leaf_node(tree: List[Any], i: int) -> None:
    if not is_leaf_node(tree, i):
        raise ValueError("Index is not a leaf")


def check_valid_merkle_node(node: bytes) -> None:
    if not is_valid_merkle_node(node):
        raise ValueError("Merkle tree nodes must be Uint8Array of length 32")


def make_merkle_tree(leaves: List[bytes]) -> List[bytes]:
    for leaf in leaves:
        check_valid_merkle_node(leaf)

    if len(leaves) == 0:
        raise ValueError("Expected non-zero number of leaves")

    tree: List[bytes] = [b''] * (2 * len(leaves) - 1)

    for index, leaf in enumerate(leaves):
        tree[len(tree) - 1 - index] = leaf

    for i in range(len(tree) - 1 - len(leaves), -1, -1):
        tree[i] = hash_pair(
            tree[left_child_index(i)],
            tree[right_child_index(i)],
        )
    return tree


def get_proof(tree: List[bytes], index: int) -> List[bytes]:
    check_leaf_node(tree, index)

    proof = []
    while index > 0:
        proof.append(tree[sibling_index(index)])
        index = parent_index(index)

    return proof


def process_proof(leaf: bytes, proof: List[bytes]) -> bytes:
    check_valid_merkle_node(leaf)
    for item in proof:
        check_valid_merkle_node(item)
    result = leaf
    for item in proof:
        result = hash_pair(item, result)
    return result


def get_multi_proof(tree: List[bytes], indices: List[int]) -> MultiProof:
    for index in indices:
        check_leaf_node(tree, index)

    indices = sorted(indices, reverse=True)

    for i, p in enumerate(indices[1:]):
        if p == indices[i]:
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

    return MultiProof(
        leaves=[tree[i] for i in indices],
        proof=proof,
        proof_flags=proof_flags,
    )


def process_multi_proof(multiproof: MultiProof) -> bytes:
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


def is_valid_merkle_tree(tree: List[bytes]) -> bool:
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


def pop_safe(array: List[Any]) -> Any:
    try:
        return array.pop()
    except IndexError:
        return None
