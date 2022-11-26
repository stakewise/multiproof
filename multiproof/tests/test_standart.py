import unittest

from web3 import Web3

from multiproof.bytes import to_hex
from multiproof.standart import (LeafValue, StandardMerkleTree,
                                 StandardMerkleTreeData)

ZERO_BYTES = bytearray(32)
ZERO = to_hex(ZERO_BYTES)


def characters(s: str):
    l = [[x] for x in s]
    tree = StandardMerkleTree.of(l, ['string'])
    return l, tree


class StandartTestCase(unittest.TestCase):

    def test_valid_single_proofs(self):
        "generates valid single proofs for all leaves"
        _, tree = characters('abcdef')
        tree.validate()

        for index, leaf in enumerate(tree.values):
            # getProof internally validates the proof
            proof1 = tree.get_proof(index)
            proof2 = tree.get_proof(leaf.value)
            assert proof1 == proof2  # deep equal

    def test_valid_multiproofs(self):
        "generates valid multiproofs"
        values, tree = characters('abcdef')
        tree.validate()

        for ids in [[], [0, 1], [0, 1, 5], [1, 3, 4, 5], [0, 2, 4, 5], [0, 1, 2, 3, 4, 5]]:
            # getProof internally validates the proof
            proof1 = tree.get_multi_proof(ids)
            proof2 = tree.get_multi_proof([values[i] for i in ids])
            assert proof1 == proof2  # deep equal

    def test_dump_and_load(self):
        _, tree = characters('abcdef')
        tree2 = StandardMerkleTree.load(tree.dump())
        tree2.validate()

        assert tree2.leaf_encoding == tree.leaf_encoding
        assert tree2.values == tree.values
        assert tree2.tree == tree.tree

    def test_out_of_bonds(self):
        _, tree = characters('a')
        with self.assertRaises(Exception) as context:
            tree.get_proof(1)
            self.assertTrue('Index out of bounds' in context.exception)

    def test_reject_unrecognized_tree(self):
        with self.assertRaises(Exception) as context:
            StandardMerkleTree.load(
                StandardMerkleTreeData(
                    tree=[], values=[], leaf_encoding=['uint256'], format='nonstandard'
                )
            )
            self.assertTrue("Unknown format 'nonstandard'" in context.exception)

    def test_reject_malformed(self):
        with self.assertRaises(Exception) as context:
            tree1 = StandardMerkleTree.load(StandardMerkleTreeData(
                format='standard-v1',
                tree=[ZERO],
                values=[LeafValue(value=['0'], tree_index=0)],
                leaf_encoding=['uint256'],
            ))
            tree1.get_proof(0)
            self.assertTrue("Merkle tree does not contain the expected value" in context.exception)

        with self.assertRaises(Exception) as context:
            tree2 = StandardMerkleTree.load(StandardMerkleTreeData(
                format='standard-v1',
                tree=[ZERO, ZERO, to_hex(Web3.keccak(Web3.keccak(ZERO_BYTES)))],
                values=[LeafValue(value=['0'], tree_index=2)],
                leaf_encoding=['uint256'],
            ))
            tree2.get_proof(0)
            self.assertTrue("Unable to prove value" in context.exception)

    def test_render_tree(self):
        "generates valid multiproofs"
        _, tree = characters('a')

        expected = '''0) 9c15a6a0eaeed500fd9eed4cbeab71f797cefcc67bfd46683e4d2e6ff7f06d1c'''
        self.assertEqual(str(tree), expected)

        _, tree = characters('ab')
        expected = '''
0) fa914d99a18dc32d9725b3ef1c50426deb40ec8d0885dac8edcc5bfd6d030016
├─ 1) 9c15a6a0eaeed500fd9eed4cbeab71f797cefcc67bfd46683e4d2e6ff7f06d1c
└─ 2) 19ba6c6333e0e9a15bf67523e0676e2f23eb8e574092552d5e888c64a4bb3681
        '''.strip()
        self.assertEqual(str(tree), expected)

        _, tree = characters('abc')

        expected = '''
0) f2129b5a697531ef818f644564a6552b35c549722385bc52aa7fe46c0b5f46b1
├─ 1) fa914d99a18dc32d9725b3ef1c50426deb40ec8d0885dac8edcc5bfd6d030016
│  ├─ 3) 9c15a6a0eaeed500fd9eed4cbeab71f797cefcc67bfd46683e4d2e6ff7f06d1c
│  └─ 4) 19ba6c6333e0e9a15bf67523e0676e2f23eb8e574092552d5e888c64a4bb3681
└─ 2) 9cf5a63718145ba968a01c1d557020181c5b252f665cf7386d370eddb176517b
    '''.strip()
        self.assertEqual(str(tree), expected)
