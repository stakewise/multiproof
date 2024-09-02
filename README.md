# Stakewise python fork of [@openzeppelin/merkle-tree](https://github.com/OpenZeppelin/merkle-tree)

A Python library to generate Merkle trees and Merkle proofs.

Well suited for airdrops and similar mechanisms in combination with OpenZeppelin Contracts MerkleProof utilities.
[`MerkleProof`]: <https://docs.openzeppelin.com/contracts/4.x/api/utils#MerkleProof>

## Quick Start

``` shell
poetry add multiproof
```

### Building a Tree

``` python
import json

from multiproof import StandardMerkleTree


# Get the values to include in the tree. (Note: Consider reading them from a file.)
values = [
    ["0x1111111111111111111111111111111111111111", 5000000000000000000],
    ["0x2222222222222222222222222222222222222222", 2500000000000000000]
]
# Build the Merkle tree. Set the encoding to match the values.
tree = StandardMerkleTree.of(values, ["address", "uint256"])
# Print the Merkle root. You will probably publish this value on chain in a smart contract.
print('Merkle Root:', tree.root)
# Write a file that describes the tree. You will distribute this to users so they can generate proofs for values in the tree.
with open('tree.json', 'w') as file:
    json.dump(tree.to_json(), file)
```

### Obtaining a Proof

Assume we're looking to generate a proof for the entry that corresponds to address `0x11...11`.

```python
import json

from multiproof import StandardMerkleTree


# Load the tree from the description that was generated previously.
with open('tree.json') as file:
    tree = StandardMerkleTree.from_json(json.load(file))

# Loop through the entries to find the one you're interested in.
for i, leaf in enumerate(tree.values):
    if leaf.value[0] == '0x1111111111111111111111111111111111111111':
        # Generate the proof using the index of the entry.
        proof = tree.get_proof(i)
        print('Value:', leaf.value)
        print('Proof:', proof)
```

In practice this might be done in a frontend application prior to submitting the proof on-chain, with the address looked up being that of the connected wallet.

### Validating a Proof in Solidity

Once the proof has been generated, it can be validated in Solidity using [`MerkleProof`] as in the following example:

```solidity
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Verifier {
    bytes32 private root;

    constructor(bytes32 _root) {
        // (1)
        root = _root;
    }

    function verify(
        bytes32[] memory proof,
        address addr,
        uint256 amount
    ) public {
        // (2)
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(addr, amount))));
        // (3)
        require(MerkleProof.verify(proof, root, leaf), "Invalid proof");
        // (4)
        // ...
    }
}
```

1. Store the tree root in your contract.
2. Compute the [leaf hash](#leaf-hash) for the provided `addr` and `amount` ABI encoded values.
3. Verify it using [`MerkleProof`]'s `verify` function.
4. Use the verification to make further operations on the contract. (Consider you may want to add a mechanism to prevent reuse of a leaf).

## Standard Merkle Trees

This library works on "standard" Merkle trees designed for Ethereum smart contracts. We have defined them with a few characteristics that make them secure and good for on-chain verification.

- The tree is shaped as a [complete binary tree](https://xlinux.nist.gov/dads/HTML/completeBinaryTree.html).
- The leaves are sorted.
- The leaves are the result of ABI encoding a series of values.
- The hash used is Keccak256.
- The leaves are double-hashed[^1] to prevent [second preimage attacks].

[second preimage attacks]: https://flawed.net.nz/2018/02/21/attacking-merkle-trees-with-a-second-preimage-attack/

## Advanced usage

### Leaf Hash

The Standard Merkle Tree uses an opinionated double leaf hashing algorithm. For example, a leaf in the tree with value `[addr, amount]` can be computed in Solidity as follows:

```solidity
bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(addr, amount))));
```

This is an opinionated design that we believe will offer the best out of the box experience for most users. However, there are advanced use case where a different leaf hashing algorithm may be needed. For those, the `SimpleMerkleTree` can be used to build a tree with custom leaf hashing.

### Leaf ordering

Each leaf of a Merkle tree can be proven individually. The relative ordering of leaves is mostly irrelevant when the only objective is to prove the inclusion of individual leaves in the tree. Proving multiple leaves at once is however a little bit more difficult.

This library proposes a mechanism to prove (and verify) that sets of leaves are included in the tree. These "multiproofs" can also be verified onchain using the implementation available in `@openzeppelin/contracts`. This mechanism requires the leaves to be ordered respective to their position in the tree. For example, if the tree leaves are (in hex form) `[ 0xAA...AA, 0xBB...BB, 0xCC...CC, 0xDD...DD]`, then you'd be able to prove `[0xBB...BB, 0xDD...DD]` as a subset of the leaves, but not `[0xDD...DD, 0xBB...BB]`.

Since this library knows the entire tree, you can generate a multiproof with the requested leaves in any order. The library will re-order them so that they appear inside the proof in the correct order. The `MultiProof` object returned by `tree.getMultiProof(...)` will have the leaves ordered according to their position in the tree, and not in the order in which you provided them.

By default, the library orders the leaves according to their hash when building the tree. This is so that a smart contract can build the hashes of a set of leaves and order them correctly without any knowledge of the tree itself. Said differently, it is simpler for a smart contract to process a multiproof for leaves that it rebuilt itself if the corresponding tree is ordered.

However, some trees are constructed iteratively from unsorted data, causing the leaves to be unsorted as well. For this library to be able to represent such trees, the call to `StandardMerkleTree.of` includes an option to disable sorting. Using that option, the leaves are kept in the order in which they were provided. Note that this option has no effect on your ability to generate and verify proofs and multiproofs in Python, but that it may introduce challenges when verifying multiproofs onchain. We recommend only using it for building a representation of trees that are built (onchain) using an iterative process.

## API & Examples

> **Note**
> Consider reading the array of elements from a CSV file for easy interoperability with spreadsheets or other data processing pipelines.
> **Note**
> By default, leaves are sorted according to their hash. This is done so that multiproof generated by the library can more easily be verified onchain. This can be disabled using the optional third argument. See the [Leaf ordering](#leaf-ordering) section for more details.

### `StandardMerkleTree`

```python3
from multiproof import StandardMerkleTree
```

#### `StandardMerkleTree.of`

```python3
tree = StandardMerkleTree.of([['alice', '100'], ['bob', '200']], ['address', 'uint'], sort_leaves=True)
```

Creates a standard Merkle tree out of an array of the elements in the tree, along with their types for ABI encoding. For documentation on the syntax of the types, including how to encode structs, refer to the documentation for Ethers.js's [`AbiCoder`](https://docs.ethers.org/v5/api/utils/abi/coder/#AbiCoder-encode).

#### `StandardMerkleTree.load`

```python3
from multiproof.standard import StandardMerkleTree, StandardMerkleTreeData, LeafValue

StandardMerkleTree.load(
    StandardMerkleTreeData(
        format='standard-v1',
        tree=['0x0000000000000000000000000000000000000000000000000000000000000000'],
        values=[LeafValue(value=['0'], tree_index=0)],
        leaf_encoding=['uint256'],
    )
)
```

Loads the tree from a description previously returned by `tree.dump`.

#### `StandardMerkleTree.verify`

```python3
verified = StandardMerkleTree.verify(root, ['address', 'uint'], ['alice', '100'], proof);
```

Returns a boolean that is `true` when the proof verifies that the value is contained in the tree given only the proof, Merkle root, and encoding.

#### `StandardMerkleTree.verify_multi_proof`

```python3
is_valid = StandardMerkleTree.verify_multi_proof(root, leaf_encoding, multiproof)
```

Returns a boolean that is `true` when the multiproof verifies that all the values are contained in the tree given only the multiproof, Merkle root, and leaf encoding.

#### Options

Allows to configure the behavior of the tree. The following options are available:

| Option        | Description                                                                       | Default |
|---------------| --------------------------------------------------------------------------------- | ------- |
| `sort_leaves` | Enable or disable sorted leaves. Sorting is strongly recommended for multiproofs. | `true`  |

#### `tree.root`

```python3
print(tree.root)
```

The root of the tree is a commitment on the values of the tree. It can be published (e.g., in a smart contract) to later prove that its values are part of the tree.

#### `tree.dump`

```python3
tree.dump()
```

Returns a description of the Merkle tree for distribution. It contains all the necessary information to reproduce the tree, find the relevant leaves, and generate proofs. You should distribute this to users in a web application or command line interface so they can generate proofs for their leaves of interest.

#### `tree.get_proof`

```python3
proof = tree.get_proof(i)
```

Returns a proof for the `i`th value in the tree. Indices refer to the position of the values in the array from which the tree was constructed.

Also accepts a value instead of an index, but this will be less efficient. It will fail if the value is not found in the tree.

```python3
proof = tree.getProof(value) # e.g. [alice, '100']
```

#### `tree.get_multi_proof`

```python3
multiproof = tree.get_multi_proof([i0, i1, ...])
print('proof:', multiproof.proof)
print('proof_flags:', multiproof.proof_flags)
print('leaves:', multiproof.leaves)
```

Returns a multiproof for the values at indices `i0, i1, ...`. Indices refer to the position of the values in the array from which the tree was constructed.

The multiproof returned contains an array with the leaves that are being proven. This array may be in a different order than that given by `i0, i1, ...`! The order returned is significant, as it is that in which the leaves must be submitted for verification (e.g., in a smart contract).

Also accepts values instead of indices, but this will be less efficient. It will fail if any of the values is not found in the tree.

```python3
multiproof = tree.get_multi_roof([value1, value2]) # e.g. [[alice, '100'], [bob, '200']]

```

#### `tree.verify`

```python3
tree.verify(i, proof)
tree.verify(value, proof)  # e.g. [alice, '100']
```

Returns a boolean that is `true` when the proof verifies that the value is contained in the tree.

#### `tree.verify_multi_proof`

```python3
from multiproof import MultiProof
multi_proof = MultiProof(proof=proof, proof_flags=proof_flags, leaves=leaves)
tree.verify_multi_proof_leaf(multi_proof)
```

Returns a boolean that is `true` when the multi-proof verifies that the values are contained in the tree.

#### `tree.leaf_hash`

```python3
leaf = tree.leaf_hash(value) # e.g. [alice, '100']
```

Returns the leaf hash of the value, defined per tree type.

It corresponds to the following expression in Solidity:

```solidity
bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(alice, 100))));
```

#### `Rendering the tree`

```python3
print(tree)
```

Returns a visual representation of the tree that can be useful for debugging.

## Testing

``` shell
poetry install
poetry run pytest multiproof/
```
