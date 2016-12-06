#!/usr/bin/env python3

# testMerkleTree.py
import os
import shutil
import sys
import time
import unittest
import hashlib

from rnglib import SimpleRNG
from xlattice import (QQQ, check_using_sha,
                      SHA1_HEX_NONE, SHA2_HEX_NONE, SHA3_HEX_NONE)
from merkletree import MerkleTree, MerkleLeaf

if sys.version_info < (3, 6):
    # pylint:disable=unused-import
    import sha3                 # monkey-patches hashlib

MAX_NAME_LEN = 16


class TestMerkleTree2(unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def do_test_deepish_trees(self, using_sha):
        """
        Build a directory of random data, then its MerkleTree, then
        round trip to a serialization and back.
        """

        tree_top = os.path.join('tmp', self.rng.next_file_name(MAX_NAME_LEN))
        while os.path.exists(tree_top):
            tree_top = os.path.join(
                'tmp', self.rng.next_file_name(MAX_NAME_LEN))

        # Generate a quasi-random data directory, 7 deep, up to 5 files/dir
        self.rng.next_data_dir(tree_top, depth=7, width=5, max_len=4096)

        # Build a MerkleTree specifying the directory.
        tree = MerkleTree.create_from_file_system(tree_top, using_sha)

        # ROUND TRIP 1 ----------------------------------------------

        # Serialize it.
        ser = tree.__str__()

        # Deserialize to make another MerkleTree.
        tree2 = MerkleTree.create_from_serialization(ser, using_sha)

        self.assertTrue(tree2.__eq__(tree))
        self.assertEqual(tree2, tree)

        # ROUND TRIP 2 ----------------------------------------------
        strings = ser.split('\n')
        strings = strings[:-1]
        tree3 = MerkleTree.create_from_string_array(strings, using_sha)
        self.assertEqual(tree3, tree)

    def test_deepish_trees(self):
        for using_sha in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3]:
            self.do_test_deepish_trees(using_sha)

if __name__ == '__main__':
    unittest.main()
