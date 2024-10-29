import pytest

from multiproof.bytes import to_hex
from multiproof.standard import (LeafValue, StandardMerkleTree,
                                 StandardMerkleTreeData)
from multiproof.utils import keccak

ZERO_BYTES = bytearray(32)
ZERO = to_hex(ZERO_BYTES)


def make_tree(s: str, sort_leaves: bool = True) -> tuple[list[list[str]], StandardMerkleTree]:
    l = [[x] for x in s]
    tree = StandardMerkleTree.of(l, ['string'], sort_leaves)
    return l, tree


class TestStandartTestCase:
    @pytest.mark.parametrize('sort_leaves', (True, False))
    def test_valid_single_proofs(self, sort_leaves):
        "generates valid single proofs for all leaves"
        _, tree = make_tree('abcdef', sort_leaves)
        tree.validate()

        for index, leaf in enumerate(tree.values):
            # getProof internally validates the proof
            proof1 = tree.get_proof(index)
            proof2 = tree.get_proof(leaf.value)
            assert proof1 == proof2  # deep equal
            assert tree.verify_leaf(index, proof1)
            assert tree.verify_leaf(leaf, proof1)
            assert StandardMerkleTree.verify(tree.root, ['string'], leaf.value, proof1)

    @pytest.mark.parametrize('sort_leaves', (True, False))
    def test_invalid_single_proofs(self, sort_leaves):
        "rejects invalid proofs"
        _, tree = make_tree('abcdef', sort_leaves)
        _, other_tree = make_tree('abc', sort_leaves)
        leaf = ['a']
        invalid_proof = other_tree.get_proof(leaf)
        assert not tree.verify_leaf(leaf, invalid_proof)
        assert not StandardMerkleTree.verify(tree.root, ['string'], leaf, invalid_proof)

    @pytest.mark.parametrize('sort_leaves', (True, False))
    def test_valid_multiproofs(self, sort_leaves):
        "generates valid multiproofs"
        values, tree = make_tree('abcdef', sort_leaves)
        tree.validate()

        for ids in [[], [0, 1], [0, 1, 5], [1, 3, 4, 5], [0, 2, 4, 5], [0, 1, 2, 3, 4, 5]]:
            # getProof internally validates the proof
            proof1 = tree.get_multi_proof(ids)
            proof2 = tree.get_multi_proof([values[i] for i in ids])
            assert proof1 == proof2  # deep equal
            pf = tree.get_multi_proof(ids)
            assert tree.verify_multi_proof_leaf(proof1)
            assert StandardMerkleTree.verify_multi_proof(tree.root, ['string'], pf)

    @pytest.mark.parametrize('sort_leaves', (True, False))
    def test_invalid_multiproofs(self, sort_leaves):
        "reject invalid multiproofs"
        _, tree = make_tree('abcdef', sort_leaves)
        _, other_tree = make_tree('abc', sort_leaves)
        leaves = [['a'], ['b'], ['c']]
        multi_proof = other_tree.get_multi_proof(leaves)
        assert not tree.verify_multi_proof_leaf(multi_proof)
        assert not StandardMerkleTree.verify_multi_proof(tree.root, ['string'], multi_proof)

    @pytest.mark.parametrize('sort_leaves', (True, False))
    def test_dump_and_load(self, sort_leaves):
        _, tree = make_tree('abcdef', sort_leaves)
        tree2 = StandardMerkleTree.load(tree.dump())
        tree2.validate()

        assert tree2.leaf_encoding == tree.leaf_encoding
        assert tree2.values == tree.values
        assert tree2.tree == tree.tree

    @pytest.mark.parametrize('sort_leaves', (True, False))
    def test_out_of_bonds(self, sort_leaves):
        _, tree = make_tree('a', sort_leaves)
        with pytest.raises(Exception) as context:
            tree.get_proof(1)
            assert 'Index out of bounds' in context.exception

    def test_reject_unrecognized_tree(self):
        with pytest.raises(Exception) as context:
            StandardMerkleTree.load(
                StandardMerkleTreeData(
                    tree=[], values=[], leaf_encoding=['uint256'], format='nonstandard'
                )
            )
            assert "Unknown format 'nonstandard'" in context.exception

    def test_reject_malformed(self):
        with pytest.raises(Exception) as context:
            tree1 = StandardMerkleTree.load(
                StandardMerkleTreeData(
                    format='standard-v1',
                    tree=[ZERO],
                    values=[LeafValue(value=['0'], tree_index=0)],
                    leaf_encoding=['uint256'],
                )
            )
            tree1.get_proof(0)
            assert "Merkle tree does not contain the expected value" in context.exception

        with pytest.raises(Exception) as context:
            tree2 = StandardMerkleTree.load(
                StandardMerkleTreeData(
                    format='standard-v1',
                    tree=[ZERO, ZERO, to_hex(keccak(keccak(ZERO_BYTES)))],
                    values=[LeafValue(value=['0'], tree_index=2)],
                    leaf_encoding=['uint256'],
                )
            )
            tree2.get_proof(0)
            assert "Unable to prove value" in context.exception

    def test_render_tree(self):
        "generates valid multiproofs"
        _, tree = make_tree('a')

        expected = '''0) 9c15a6a0eaeed500fd9eed4cbeab71f797cefcc67bfd46683e4d2e6ff7f06d1c'''
        assert str(tree) == expected

        _, tree = make_tree('ab')
        expected = '''
0) fa914d99a18dc32d9725b3ef1c50426deb40ec8d0885dac8edcc5bfd6d030016
├─ 1) 9c15a6a0eaeed500fd9eed4cbeab71f797cefcc67bfd46683e4d2e6ff7f06d1c
└─ 2) 19ba6c6333e0e9a15bf67523e0676e2f23eb8e574092552d5e888c64a4bb3681
        '''.strip()
        assert str(tree) == expected

        _, tree = make_tree('abc')

        expected = '''
0) f2129b5a697531ef818f644564a6552b35c549722385bc52aa7fe46c0b5f46b1
├─ 1) fa914d99a18dc32d9725b3ef1c50426deb40ec8d0885dac8edcc5bfd6d030016
│  ├─ 3) 9c15a6a0eaeed500fd9eed4cbeab71f797cefcc67bfd46683e4d2e6ff7f06d1c
│  └─ 4) 19ba6c6333e0e9a15bf67523e0676e2f23eb8e574092552d5e888c64a4bb3681
└─ 2) 9cf5a63718145ba968a01c1d557020181c5b252f665cf7386d370eddb176517b
    '''.strip()
        assert str(tree) == expected
