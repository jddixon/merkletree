#!/usr/bin/env python3
# testMerkleTree.py

""" Test MerkleTree behavior with deeper directories. """

import os
import time
import unittest

from rnglib import SimpleRNG
from xlattice import QQQ
from merkletree import MerkleTree

MAX_NAME_LEN = 16


class TestMerkleTree2(unittest.TestCase):
    """ Test MerkleTree behavior with deeper directories. """

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
        self.assertEqual(tree2, tree)           # identical test

        # ROUND TRIP 2 ----------------------------------------------
        strings = ser.split('\n')
        strings = strings[:-1]
        tree3 = MerkleTree.create_from_string_array(strings, using_sha)
        self.assertEqual(tree3, tree)

        # ROUND TRIP 3 ----------------------------------------------
        filename = os.path.join('tmp', self.rng.next_file_name(8))
        while os.path.exists(filename):
            filename = os.path.join('tmp', self.rng.next_file_name(8))
        with open(filename, 'w') as file:
            file.write(ser)

        tree4 = MerkleTree.create_from_file(filename, using_sha)
        self.assertEqual(tree4, tree)

    def test_deepish_trees(self):
        """ Test behavior of deeper trees using various SHA hash types. """

        for using_sha in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3]:
            self.do_test_deepish_trees(using_sha)

if __name__ == '__main__':
    unittest.main()
