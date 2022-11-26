# Stakewise python realization of `@openzeppelin/merkle-tree`

## NB! Library is not well tested and not ready for the production use

**A Python library to generate merkle trees and merkle proofs.**
Well suited for airdrops and similar mechanisms in combination with OpenZeppelin Contracts [`MerkleProof`] utilities.

[`MerkleProof`]: https://docs.openzeppelin.com/contracts/4.x/api/utils#MerkleProof

## Quick Start

``` shell
poetry install
```

### Building a Tree

```python
from multiproof import StandardMerkleTree

values = [
    ["0x1111111111111111111111111111111111111111", 5000000000000000000],
    ["0x2222222222222222222222222222222222222222", 2500000000000000000]
]

tree = StandardMerkleTree.of(values, ["address", "uint256"])

print('Merkle Root:', tree.root)
```

# todos
- extend tests
- add docs
